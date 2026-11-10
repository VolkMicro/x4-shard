"""X4 Shard server: one world, players see each other's ships, wallet and cargo live here.

The server owns what exists: static world entities per sector and one puppet per connected player.
Clients (X4 with the x4shard extension, or tools/fakepilot.py) report their ship pose; the server stamps
it with its own clock and relays it to the other players in that sector.
Each player has an account (credits, cargo of minable wares) kept in accounts.json. The server does not take a
client's word for more than its ship can do: a position is held to what the ship can fly since the last one (a jump
is cut to MAX_SPEED, and the others, selling and mining all follow the cut position); mining counts only where the
game has asteroids of that ware, up to a rate (token bucket) and what the hold takes; selling happens at a market
station the player is at; after entering a sector a ship waits a while before it mines or trades there.

Login without passwords: the client has an ECDSA P-256 key made once (kept in the game's user data, synced by
Steam Cloud), sends its Steam ID and public key, and signs this shard's random challenge together with the
fingerprint of the certificate the connection showed (p256.py checks it). The first login binds the public key to
that Steam ID; later logins must be signed by the same key. Nothing on the wire or known to a shard logs the player
in again: a shard that passes another shard's challenge to a player gets a signature bound to its own certificate,
which the other shard refuses. A shard knows the player whatever address it was reached at. A game without Steam
is known by its key alone. Plain accounts by name (the bot, test setups) are for this machine and its local
network only.

Any number of shards can run. A shard is unlisted unless it registers (--register-to) with a directory (a shard
started with --directory), under a name nobody else holds and at an address where it answers. The client asks
the directory for the list and lets the player pick a shard, or joins an address the player types. A private
shard (--invite) lets in only players it knows and newcomers who bring its invite code, x4shard://host:port/code.

Transport: TLS 1.2 or 1.3 on the shard's port, with the shard's own certificate (tlscert.py: made once next to the
accounts file). The game checks the certificate by its SHA-256 fingerprint: the directory's comes with the mod, a
listed shard's with the list (the directory checks it at REGISTER), a private shard's with its invite link
x4shard://host:port/code#fingerprint, a shard joined by a bare address is remembered by the first one it showed.
A plain-text connection is an X4 Shard older than 0.12: it is told to update.
Protocol: UTF-8 text lines, fields split by '|'.
  client -> server  LIST|proto                                   (before HELLO: the shard list)
                    HELLO|name|proto[|steam_id|public_key[|invite]]  (signed login: then CHALLENGE, PROOF)
                    PROOF|signature            (over "x4shard-login|<nonce>|<steam_id>|<certificate fingerprint>")
                    POS|sector_macro|x|y|z|yaw|pitch|roll        (sector space, metres and degrees)
                    MINED|ware|amount                            (cargo grew by mining)
                    SELL|station_eid|ware|amount                 (ware "all" / amount 0: everything the market buys)
  shard -> directory REGISTER|name|host|port|players|description|fingerprint   (answer OK or NO|reason)
  server -> client  SERVER|name|host|port|players|description|fingerprint ... END   (answer to LIST)
                    CHALLENGE|nonce                              (sign it to log in)
                    WELCOME|pid|server_time|account_name|shard_name
                    DENIED|reason                                (login refused, the server closes)
                    SPAWN|eid|kind|macro|owner|x|y|z|yaw|name|plan  (kind: station, npc, puppet)
                    MOVE|eid|server_time|x|y|z|yaw|pitch|roll
                    DESPAWN|eid
                    WALLET|credits                               (authoritative; the client mirrors it)
                    CARGO|ware|amount                            (authoritative total in the player's ship)
                    SAY|text
                    TEST|mine|ware|amount|interval|count  TEST|dock|station_eid   (scripted tests, --test-name)

usage: python3 shard_server.py [--host 0.0.0.0] [--port 47110] [--accounts accounts.json] [--name "My shard"]
                               [--public-host my.example.org] [--public-port 47110] [--lan-host 192.168.1.10]
                               [--description text] [--invite] [--directory] [--register-to host:port]
                               [--test-name Tester --test-mine ore:3:2:10 --test-dock hub1:40]
"""
import argparse
import asyncio
import hashlib
import ipaddress
import itertools
import json
import logging
import math
import os
import secrets
import socket
import ssl
import string
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # p256.py next to this file, also under python -I
import p256  # noqa: E402
import tlscert  # noqa: E402

PROTO = "4"   # 4: TLS, the login signature bound to the shard's certificate (0.12); 3: plain text (0.11)
PUPPET_MACRO = "ship_arg_s_fighter_01_a_macro"
PUPPET_OWNER = "argon"
START_CREDITS = 10000
MINABLE = ("ore", "silicon", "ice", "nividium", "hydrogen", "helium", "methane")
MINE_RATE = 5.0        # units per second a ship may report
MINE_BURST = 60.0      # units that may arrive at once
SELL_RANGE = 5000.0    # metres from the station centre; docked ships are inside the station
DIRECTORY_TTL = 90.0   # a registered shard disappears from the list after this long without REGISTER
REGISTER_EVERY = 30.0
# Limits for a shard open to the internet
MAX_CONNECTIONS = 200      # all at once
MAX_PER_IP = 8             # from one address (a household, a PC running several copies)
FIRST_LINE_TIMEOUT = 30.0  # s for a connection that has not logged in to say something
IDLE_TIMEOUT = 600.0       # s of silence before a player is dropped (the game stops sending in its pause menu)
POS_RATE, POS_BURST = 40.0, 80.0   # position reports per second a client may send (the game sends 20)
LINE_LIMIT = 8192          # bytes per line from a client
POSE_LIMIT = 1e7           # metres / degrees a reported pose may hold
# The ship every player flies, from the game's data (the X4 Shard start: ship_arg_s_miner_solid_01_a with three
# engine_arg_s_travel_01_mk1): 190 m/s, 1300 m/s boosting, 3750 m/s in travel mode; a hold of 2600 m3 for solid
# wares; a mining laser (mk2) that reaches 3 km.
MAX_SPEED = 4500.0         # m/s a ship may move; a faster report is cut to this (on a local highway, which is
                           # faster, the copy the others see lags behind and catches up when the ship slows down)
HOLD_VOLUME = 2600.0       # m3 of solid wares
WARE_VOLUME = {"ore": 10, "silicon": 10, "ice": 8, "nividium": 10}   # m3 a unit (gases need a gas miner)
MINING_RANGE = 3000.0      # m past the edge of a field the laser still reaches an asteroid
TRANSIT_LOCK = 60.0        # s after a ship enters a sector before it mines or trades there: no shortcut by hopping
START = ("cluster_13_sector001_macro", (0.0, 0.0, -7000.0))   # where the X4 Shard game start puts the ship

# Static world, sector space. Second Contact II Flashpoint: a high-yield ore field (r 2.5 km) at the sector
# centre; the clean-universe start is at (0, 0, -7000) facing it, the hub 6 km to the side of the start.
WORLD = {
    "cluster_13_sector001_macro": [
        {"eid": "hub1", "kind": "station", "macro": "station_arg_tradestation_base_01_macro", "owner": "argon",
         "pos": (6000.0, 0.0, -9000.0), "yaw": 0.0, "name": "Shard Trade Hub", "plan": "arg_tradestation",
         "market": {"ore": 50, "silicon": 120, "ice": 40, "nividium": 600}},
        {"eid": "npc1", "kind": "npc", "macro": "ship_arg_s_fighter_01_a_macro", "owner": "argon",
         "pos": (500.0, 0.0, -5500.0), "yaw": 0.0, "name": "Shard Patrol", "plan": ""},
    ],
}

# Where the game has minable asteroids, sector space (maps/xu_ep2_universe/clusters.xml places the regions,
# libraries/region_definitions.xml shapes them).
FIELDS = {
    "cluster_13_sector001_macro": [
        # region_highyield_ore at the sector centre: a cylinder r 2500 m, 2000 m high
        {"wares": ("ore",), "centre": (0.0, 0.0, 0.0), "r": 2500.0, "height": 2000.0},
        # region_cluster_13_sector_001: a tube r 8000 m along a spline through these points (here straight lines
        # between them), far from the centre
        {"wares": ("ore", "silicon"), "r": 8000.0, "spline": [
            (-171084.0, 0.0, -59219.8), (-89184.9, 0.0, -72944.6), (-14345.2, 0.0, -150607.0),
            (151426.0, 0.0, -195769.0), (44535.9, 0.0, -127229.0), (137080.0, 0.0, -61876.4),
            (-15407.8, 0.0, -17777.0), (-128579.0, 0.0, 41199.3), (-82271.9, 0.0, 72968.2),
            (-110514.0, 0.0, 132586.0), (28691.6, 0.0, 102301.0), (-7509.33, 0.0, 44851.9),
            (202433.0, 0.0, 65108.6), (86491.3, 0.0, 87838.1), (158333.0, 0.0, 175623.0),
            (35040.1, 0.0, 141392.0), (-54725.3, 0.0, 243100.0)]},
    ],
}

log = logging.getLogger("shard")
T0 = time.monotonic()
clock = time.monotonic   # the server's clock for limits (tests put a fake one here)


def now():
    return time.monotonic() - T0


def segment_distance(p, a, b):
    """Distance from point p to the segment a-b."""
    ab = [b[i] - a[i] for i in range(3)]
    n = sum(v * v for v in ab)
    k = max(0.0, min(1.0, sum((p[i] - a[i]) * ab[i] for i in range(3)) / n)) if n else 0.0
    return math.dist(p, [a[i] + ab[i] * k for i in range(3)])


def field_for(sector, pos, ware):
    """The field where a ship at pos can mine ware (its laser reaches MINING_RANGE past the edge), or None."""
    for field in FIELDS.get(sector, []):
        if ware not in field["wares"]:
            continue
        if "centre" in field:
            cx, cy, cz = field["centre"]
            if (math.hypot(pos[0] - cx, pos[2] - cz) <= field["r"] + MINING_RANGE
                    and abs(pos[1] - cy) <= field["height"] / 2 + MINING_RANGE):
                return field
        elif any(segment_distance(pos, a, b) <= field["r"] + MINING_RANGE
                 for a, b in zip(field["spline"], field["spline"][1:])):
            return field
    return None


def clean(text, limit=40):
    """Text that goes back into the line protocol: no separators, bounded length."""
    text = "".join(ch for ch in str(text) if ch not in "|\r\n\t").strip()
    return text[:limit]


def world_entity(sector, eid):
    return next((e for e in WORLD.get(sector, []) if e["eid"] == eid), None)


def is_local(ip):
    """Loopback or a private network: the directory's own machine and home network."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_private or addr.is_link_local


async def resolves_to(host, ip):
    """Does host (a name or an address) lead to ip?"""
    try:
        infos = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM), 5)
    except (OSError, asyncio.TimeoutError):
        return False
    return any(info[4][0] == ip for info in infos)


async def close_after_refusal(reader, writer):
    """Let a DENIED line reach the client: half-close, then read what it still sends until it closes. Closing with
    unread data makes the OS reset the connection, and on a reset Windows drops what the client had not read yet."""
    try:
        await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and await asyncio.wait_for(reader.read(4096), deadline - time.monotonic()):
            pass
    except (OSError, ValueError, asyncio.TimeoutError):
        pass


def invite_code(accounts_path):
    """The private shard's invite code, made once and kept next to the accounts file."""
    path = accounts_path + ".invite"
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            code = f.read().strip()
        if code.isalnum():
            return code
    code = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(10))
    with open(path, "w", encoding="utf-8") as f:
        f.write(code + "\n")
    return code


def client_tls():
    """TLS to another shard: its certificate is checked by fingerprint, not by a certificate authority."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def peer_fingerprint(writer):
    tls = writer.get_extra_info("ssl_object")
    cert = tls.getpeercert(binary_form=True) if tls else None
    return tlscert.fingerprint(cert) if cert else ""


def is_fingerprint(text):
    return len(text) == 64 and all(c in "0123456789abcdef" for c in text)


async def answers_as(host, port, name, fingerprint):
    """Does a shard called name answer at host:port, with the certificate of that fingerprint? Its LIST answer starts
    with its own row."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=client_tls()), 5)
        seen = peer_fingerprint(writer)
        writer.write(("LIST|%s\n" % PROTO).encode())
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), 5)
        writer.close()
    except (OSError, asyncio.TimeoutError, ValueError):
        return False
    fields = line.decode("utf-8", "replace").rstrip("\r\n").split("|")
    return (seen == fingerprint and len(fields) > 3 and fields[0] == "SERVER" and fields[1] == name
            and fields[3] == str(port))


async def first_byte(sock, timeout):
    """The first byte a client sent, left in the socket (MSG_PEEK): b"" when it closed, None when it says nothing."""
    loop = asyncio.get_running_loop()
    ready = loop.create_future()
    loop.add_reader(sock.fileno(), lambda: ready.done() or ready.set_result(None))
    try:
        await asyncio.wait_for(ready, timeout)
    except asyncio.TimeoutError:
        return None
    finally:
        loop.remove_reader(sock.fileno())
    try:
        return sock.recv(1, socket.MSG_PEEK)
    except (BlockingIOError, InterruptedError):
        return None
    except ConnectionError:
        return b""


async def listen(hosts, port):
    """A listening socket for each address. The shard accepts by itself: it looks at the first byte before TLS."""
    loop = asyncio.get_running_loop()
    socks = []
    for host in hosts:
        family, kind, proto, _, addr = (await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM,
                                                               flags=socket.AI_PASSIVE))[0]
        sock = socket.socket(family, kind, proto)
        if os.name == "posix":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(addr)
        sock.listen(100)
        sock.setblocking(False)
        socks.append(sock)
    return socks


class Accounts:
    """Credits and cargo per account, saved to a JSON file after every change.

    Keys: "steam:<id>" for players logged in by Steam ID and key, the plain name for the rest."""

    def __init__(self, path):
        self.path = path
        self.data = {}
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                self.data = json.load(fh)
        log.info("accounts: %d loaded from %s", len(self.data), path)

    def get(self, key, name):
        if key not in self.data:
            self.data[key] = {"name": name, "credits": START_CREDITS, "cargo": {}}
            self.save()
        return self.data[key]

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=1, sort_keys=True)
        os.replace(tmp, self.path)


class Directory:
    """This shard plus the shards that registered here recently."""

    def __init__(self, me):
        self.me = me
        self.entries = {}

    def register(self, name, host, port, players, description, fingerprint):
        self.entries["%s:%s" % (host, port)] = {"name": name, "host": host, "port": port, "players": players,
                                                "description": description, "fingerprint": fingerprint,
                                                "seen": time.monotonic()}

    def live(self):
        cutoff = time.monotonic() - DIRECTORY_TTL
        return [entry for key, entry in sorted((self.entries or {}).items())
                if entry["seen"] >= cutoff and key != "%s:%s" % (self.me["host"], self.me["port"])]

    def listing(self, my_players, peer_ip=None):
        """This shard first: to a client on the home network at its LAN address, so the long game connection does
        not go out and back through the router (its NAT hairpin breaks long flows)."""
        me = dict(self.me, players=my_players)
        if me.get("lan_host") and is_local(peer_ip):
            me["host"] = me["lan_host"]
        return [me] + self.live()

    def name_taken(self, name, host, port):
        """Names are unique in the list: this shard's own, then whoever registered it first."""
        if name.lower() == self.me["name"].lower():
            return True
        return any(e["name"].lower() == name.lower() and (e["host"], e["port"]) != (host, port) for e in self.live())

    def known(self, name, host, port, fingerprint):
        return any((e["name"], e["host"], e["port"], e["fingerprint"]) == (name, host, port, fingerprint)
                   for e in self.live())


class Player:
    def __init__(self, pid, writer, peer):
        self.pid = pid
        self.eid = "p%d" % pid
        self.writer = writer
        self.peer = peer
        self.name = "pilot%d" % pid
        self.sector = None
        self.pose = None
        self.pos_count = 0
        self.account = None
        self.tokens = MINE_BURST
        self.tokens_at = clock()
        self.pos_tokens = POS_BURST
        self.pos_at = clock()
        self.pose_at = 0.0         # clock() when the pose was taken
        self.login_at = clock()
        self.transit_until = 0.0   # mining and trading wait until then (the ship has just entered a sector)
        self.said = {}             # refusal text -> clock() when it was last said
        self.pending = None    # Steam login waiting for its signed challenge

    def send(self, *fields):
        self.writer.write(("|".join(str(f) for f in fields) + "\n").encode("utf-8"))

    def spawn_line(self):
        x, y, z, yaw, _pitch, _roll = self.pose
        return ("SPAWN", self.eid, "puppet", PUPPET_MACRO, PUPPET_OWNER, "%.2f" % x, "%.2f" % y, "%.2f" % z,
                "%.2f" % yaw, self.name, "")


class Shard:
    def __init__(self, accounts, test, me, directory, invite=None):
        self.players = {}
        self.per_ip = {}
        self.connections = 0
        self.ids = itertools.count(1)
        self.accounts = accounts
        self.test = test
        self.me = me
        self.directory = directory
        self.invite = invite   # private shard: a newcomer must bring this code (players it knows need none)

    def online(self):
        return sum(1 for p in self.players.values() if p.account is not None)

    def in_sector(self, sector, but=None):
        return [p for p in self.players.values() if p.sector == sector and p is not but]

    def enter_sector(self, player, sector):
        old = player.sector
        if old is not None:
            for other in self.in_sector(old, but=player):
                other.send("DESPAWN", player.eid)
                player.send("DESPAWN", other.eid)
            for ent in WORLD.get(old, []):
                player.send("DESPAWN", ent["eid"])
        player.sector = sector
        for ent in WORLD.get(sector, []):
            x, y, z = ent["pos"]
            player.send("SPAWN", ent["eid"], ent["kind"], ent["macro"], ent["owner"],
                        "%.2f" % x, "%.2f" % y, "%.2f" % z, "%.2f" % ent["yaw"], ent["name"], ent["plan"])
        for other in self.in_sector(sector, but=player):
            if other.pose is not None:
                player.send(*other.spawn_line())
            other.send(*player.spawn_line())
            other.send("SAY", "%s entered the sector" % player.name)
        log.info("%s (%s) entered %s, world entities %d, players there %d", player.name, player.eid, sector,
                 len(WORLD.get(sector, [])), len(self.in_sector(sector, but=player)))

    def tell(self, player, text):
        """A refusal for the player to read, at most once every 10 s per text (a client may repeat a report)."""
        t = clock()
        if t - player.said.get(text, -99.0) >= 10:
            player.said[text] = t
            player.send("SAY", text)

    def held(self, player, origin, since, pose, t):
        """pose, cut back to what a ship at origin at clock() since can have reached by t at MAX_SPEED."""
        d = math.dist(origin, pose[:3])
        reach = MAX_SPEED * max(0.0, t - since) + 1.0
        if d <= reach:
            return pose
        if t - player.said.get("held", -99.0) >= 10:
            player.said["held"] = t
            log.info("%s reported %.0f m in %.2f s, held to %.0f m/s", player.name, d, max(0.0, t - since), MAX_SPEED)
        k = reach / d
        return tuple(o + (p - o) * k for o, p in zip(origin, pose[:3])) + tuple(pose[3:])

    def first_pose(self, player, sector, pose, t):
        """Where a ship can be when it first reports: at the game start, or where it was when it last left (a game
        that reconnects), plus what it could have flown since. Anything farther is cut back."""
        refs = [(START[0], START[1], player.login_at)]
        last = player.account.get("last_pose")
        if last:
            refs.append((last[0], tuple(last[1:4]), t - max(0.0, time.time() - last[4])))
        here = [r for r in refs if r[0] == sector]
        if not here:   # a sector it was not seen entering: positions start there, mining and trading wait
            player.transit_until = t + TRANSIT_LOCK
            return pose
        origin, since = min(((r[1], r[2]) for r in here),
                            key=lambda r: math.dist(r[0], pose[:3]) - MAX_SPEED * (t - r[1]))
        return self.held(player, origin, since, pose, t)

    def on_pos(self, player, fields):
        """Relayed to the sector: at most POS_RATE a second, finite numbers only (NaN would reach every client), no
        faster than the ship flies (a jump is cut to MAX_SPEED; the copy others see, selling and mining all go by
        the cut position)."""
        t = clock()
        player.pos_tokens = min(POS_BURST, player.pos_tokens + (t - player.pos_at) * POS_RATE)
        player.pos_at = t
        if player.pos_tokens < 1:
            return
        player.pos_tokens -= 1
        sector = clean(fields[1], 64)
        pose = tuple(float(v) for v in fields[2:8])
        if not all(math.isfinite(v) and abs(v) < POSE_LIMIT for v in pose):
            return
        first = player.pose is None
        if first:
            pose = self.first_pose(player, sector, pose, t)
        elif sector == player.sector:
            pose = self.held(player, player.pose[:3], player.pose_at, pose, t)
        else:   # through a gate or a superhighway: a fresh start there, but mining and trading wait a while
            player.transit_until = t + TRANSIT_LOCK
        player.pose, player.pose_at = pose, t
        player.pos_count += 1
        if first or sector != player.sector:
            self.enter_sector(player, sector)
        t = "%.3f" % now()
        line = ("MOVE", player.eid, t) + tuple("%.2f" % v for v in pose)
        for other in self.in_sector(sector, but=player):
            other.send(*line)

    def on_hello(self, player, fields):
        """Signed login (public key, Steam ID when the game has one): remember the claim and send a challenge.
        A plain name (the bot, test setups) gets its account at once, but only from this machine or the home
        network: from the internet a name proves nothing. False means refused (DENIED sent)."""
        name = clean(fields[1] if len(fields) > 1 else "") or player.name
        steam_id = clean(fields[3], 24) if len(fields) > 4 else ""
        pubkey = fields[4].strip().lower() if len(fields) > 4 else ""
        if steam_id or pubkey:
            if fields[2] != PROTO or (steam_id and not steam_id.isdigit()) or not p256.parse_public(pubkey):
                player.send("DENIED", "update the X4 Shard extension" if fields[2] != PROTO else "bad login")
                log.info("hello pid=%d steam=%s refused: proto %s or bad key", player.pid, steam_id, fields[2])
                return False
            player.pending = {"steam_id": steam_id, "pubkey": pubkey, "name": name, "nonce": secrets.token_hex(16),
                              "invite": fields[5].strip() if len(fields) > 5 else ""}
            player.send("CHALLENGE", player.pending["nonce"])
            return True
        if not is_local(player.peer[0] if player.peer else ""):
            player.send("DENIED", "update the X4 Shard extension")
            log.info("hello pid=%d name=%s refused: login by name from %s", player.pid, name, player.peer[0])
            return False
        player.account = self.accounts.get(name, name)
        self.welcome(player, name, "-")
        return True

    def on_proof(self, player, signature):
        """The signed challenge: the first login binds the public key to the Steam ID, later ones must match it."""
        claim, player.pending = player.pending, None
        message = ("x4shard-login|%s|%s|%s" % (claim["nonce"], claim["steam_id"], self.me["fingerprint"])).encode()
        if not p256.verify(claim["pubkey"], message, signature):
            player.send("DENIED", "the login signature does not match")
            log.info("hello pid=%d steam=%s refused: bad signature", player.pid, claim["steam_id"])
            return False
        # by Steam ID; a game without Steam (GOG) is known by its key alone
        account_key = ("steam:" + claim["steam_id"] if claim["steam_id"]
                       else "key:" + hashlib.sha256(claim["pubkey"].encode()).hexdigest()[:24])
        known = self.accounts.data.get(account_key)
        if known is not None and known.get("pubkey") not in (None, claim["pubkey"]):
            player.send("DENIED", "this Steam account is bound to another key")
            log.info("hello pid=%d steam=%s refused: another key", player.pid, claim["steam_id"])
            return False
        if known is None and self.invite and not secrets.compare_digest(claim["invite"], self.invite):
            player.send("DENIED", "this server is private: ask its owner for an invite link")
            log.info("hello pid=%d steam=%s refused: no invite", player.pid, claim["steam_id"])
            return False
        player.account = self.accounts.get(account_key, claim["name"])
        if player.account.get("pubkey") != claim["pubkey"] or player.account.get("name") != claim["name"]:
            player.account["pubkey"] = claim["pubkey"]
            player.account["name"] = claim["name"]
            self.accounts.save()
        self.welcome(player, claim["name"], claim["steam_id"] or account_key)
        return True

    def welcome(self, player, name, steam_id):
        player.name = name
        player.login_at = clock()
        player.send("WELCOME", player.pid, "%.3f" % now(), name, self.me["name"])
        self.send_account(player)
        log.info("hello pid=%d name=%s steam=%s credits=%d cargo=%s", player.pid, name, steam_id,
                 player.account["credits"], player.account["cargo"])
        if self.test.get("name") == name:
            asyncio.create_task(self.run_test(player))

    def send_account(self, player):
        acc = player.account
        player.send("WALLET", acc["credits"])
        for ware in MINABLE:
            player.send("CARGO", ware, acc["cargo"].get(ware, 0))

    def on_mined(self, player, ware, amount):
        """Mining counts where the game has asteroids of that ware (FIELDS, with the laser's reach), not right after
        entering the sector, up to MINE_RATE and what the hold takes. A refused report gets the true cargo back (the
        client mirrors it)."""
        if ware not in MINABLE or amount <= 0:
            return
        cargo = player.account["cargo"]
        t = clock()
        if self.test.get("name") != player.name:   # the scripted VM test mines wherever the ship is
            why = None
            if player.pose is None or not field_for(player.sector, player.pose[:3], ware):
                why = "No %s to mine here: mining counts in the asteroid fields of the sector" % ware
            elif t < player.transit_until:
                why = "Just arrived in this sector: mining and trade count a minute after you enter it"
            if why:
                player.send("CARGO", ware, cargo.get(ware, 0))
                self.tell(player, why)
                log.info("%s mined %d %s, refused: %s", player.name, amount, ware, why)
                return
        player.tokens = min(MINE_BURST, player.tokens + (t - player.tokens_at) * MINE_RATE)
        player.tokens_at = t
        used = sum(n * WARE_VOLUME.get(w, 10) for w, n in cargo.items())
        room = max(0, int((HOLD_VOLUME - used) // WARE_VOLUME.get(ware, 10)))
        accepted = min(amount, int(player.tokens), room)
        player.tokens -= accepted
        cargo[ware] = cargo.get(ware, 0) + accepted
        self.accounts.save()
        if accepted < amount:
            player.send("CARGO", ware, cargo[ware])
            if accepted == room:
                self.tell(player, "The cargo hold is full: sell at the trade station")
            log.info("%s mined %d %s, accepted %d (%s), now %d", player.name, amount, ware, accepted,
                     "hold full" if accepted == room else "rate limit", cargo[ware])
        else:
            log.info("%s mined %d %s, now %d", player.name, amount, ware, cargo[ware])

    def on_sell(self, player, eid, ware, amount):
        station = world_entity(player.sector, eid)
        market = station.get("market") if station else None
        if not market:
            player.send("SAY", "%s does not trade" % eid)
            return
        if clock() < player.transit_until:
            self.tell(player, "Just arrived in this sector: mining and trade count a minute after you enter it")
            log.info("%s sell at %s refused: just entered the sector", player.name, eid)
            return
        dist = None
        if player.pose is not None:
            sx, sy, sz = station["pos"]
            x, y, z = player.pose[:3]
            dist = ((x - sx) ** 2 + (y - sy) ** 2 + (z - sz) ** 2) ** 0.5
        if dist is None or dist > SELL_RANGE:
            player.send("SAY", "Too far from %s to trade" % station["name"])
            log.info("%s sell at %s refused: distance %s", player.name, eid, "unknown" if dist is None else "%.0f m" % dist)
            return
        cargo = player.account["cargo"]
        wares = [w for w in market if (ware in ("all", "*") or w == ware) and cargo.get(w, 0) > 0]
        total, sold = 0, []
        for w in wares:
            n = cargo[w] if amount <= 0 else min(amount, cargo[w])
            cargo[w] -= n
            total += n * market[w]
            sold.append("%d %s" % (n, w))
            player.send("CARGO", w, cargo[w])
        if not sold:
            player.send("SAY", "Nothing to sell at %s" % station["name"])
            return
        player.account["credits"] += total
        self.accounts.save()
        player.send("WALLET", player.account["credits"])
        player.send("SAY", "Sold %s for %d Cr" % (", ".join(sold), total))
        log.info("%s sold %s at %s (%.0f m) for %d Cr, wallet %d", player.name, ", ".join(sold), eid, dist, total,
                 player.account["credits"])

    def on_list(self, player):
        for row in self.directory.listing(self.online(), player.peer[0] if player.peer else None):
            player.send("SERVER", row["name"], row["host"], row["port"], row["players"], row["description"],
                        row.get("fingerprint", ""))
        player.send("END")

    async def on_register(self, player, fields):
        """Anyone may list a shard here: under a name nobody else holds, and only if a shard of that name answers
        at the address it gives with the certificate it gives (checked when it first appears), so the list never
        sends players elsewhere, and the fingerprint in the list is the one the players will meet."""
        name, host, port = clean(fields[1]), clean(fields[2], 64), int(fields[3])
        players, description = int(fields[4] or 0), clean(fields[5] if len(fields) > 5 else "", 80)
        fingerprint = fields[6].strip().lower() if len(fields) > 6 else ""
        peer_ip = player.peer[0] if player.peer else ""
        if not is_fingerprint(fingerprint):
            player.send("NO", "update the shard server: since 0.12 it encrypts the connection")
            log.info("directory: %s at %s:%d refused, no certificate fingerprint (an old server)", name, host, port)
            return
        if not is_local(peer_ip) and not await resolves_to(host, peer_ip):
            # from the internet a shard lists only its own address: the check below connects there, and must not
            # be pointed at the home network or anyone else
            player.send("NO", "list the address this shard connects from")
            log.info("directory: %s at %s:%d refused, registered from %s", name, host, port, peer_ip)
            return
        if not name or self.directory.name_taken(name, host, port):
            player.send("NO", "name taken")
            log.info("directory: %s at %s:%d refused, name taken", name, host, port)
            return
        if (not self.directory.known(name, host, port, fingerprint)
                and not await answers_as(host, port, name, fingerprint)):
            player.send("NO", "no shard named %s answers at %s:%d with that certificate" % (name, host, port))
            log.info("directory: %s at %s:%d refused, does not answer as that shard", name, host, port)
            return
        self.directory.register(name, host, port, players, description, fingerprint)
        player.send("OK")
        log.info("directory: %s at %s:%d registered (%d players)", name, host, port, players)

    async def run_test(self, player):
        mine, dock = self.test.get("mine"), self.test.get("dock")
        await asyncio.sleep(5)
        if mine:
            ware, amount, interval, count = mine
            player.send("TEST", "mine", ware, amount, interval, count)
            log.info("test: %s mine %s x%s every %ss, %s times", player.name, ware, amount, interval, count)
        if dock:
            eid, after = dock
            await asyncio.sleep(max(0.0, after - 5))
            player.send("TEST", "dock", eid)
            log.info("test: %s dock at %s", player.name, eid)

    async def accept(self, listener, ctx):
        """Connections of one listening socket. The limits count a connection from its first moment, TLS
        handshake included."""
        loop = asyncio.get_running_loop()
        while True:
            try:
                sock, peer = await loop.sock_accept(listener)
            except OSError as err:   # out of file descriptors, say: the shard stays up
                log.info("accept failed: %s", err)
                await asyncio.sleep(1)
                continue
            ip = peer[0]
            if self.connections >= MAX_CONNECTIONS or self.per_ip.get(ip, 0) >= MAX_PER_IP:
                log.info("connection from %s refused: too many", ip)
                sock.close()
                continue
            self.connections += 1
            self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
            asyncio.create_task(self.connection(sock, peer, ctx))

    async def connection(self, sock, peer, ctx):
        """TLS from the first byte on (a TLS hello starts with 0x16); plain text is an X4 Shard older than 0.12."""
        ip = peer[0]
        loop = asyncio.get_running_loop()
        writer = None
        try:
            sock.setblocking(False)
            first = await first_byte(sock, FIRST_LINE_TIMEOUT)
            if first:
                tls = first == b"\x16"
                reader = asyncio.StreamReader(limit=LINE_LIMIT)
                protocol = asyncio.StreamReaderProtocol(reader)
                transport, _ = await loop.connect_accepted_socket(
                    lambda: protocol, sock, ssl=ctx if tls else None,
                    ssl_handshake_timeout=FIRST_LINE_TIMEOUT if tls else None)
                writer = asyncio.StreamWriter(transport, protocol, reader, loop)
                if tls:
                    await self.handle(reader, writer, peer)
                else:
                    await self.plaintext(reader, writer, ip)
        except (OSError, asyncio.TimeoutError, ValueError) as err:   # ssl.SSLError is an OSError
            log.info("connection from %s failed: %s", ip, str(err) or type(err).__name__)
        finally:
            if writer is not None:
                writer.close()
            else:
                sock.close()
            self.connections -= 1
            self.per_ip[ip] -= 1
            if not self.per_ip[ip]:
                del self.per_ip[ip]

    async def plaintext(self, reader, writer, ip):
        """An X4 Shard older than 0.12 talks without TLS: its server list gets a single row that says to update, a
        login a refusal that says so."""
        try:
            line = await asyncio.wait_for(reader.readline(), FIRST_LINE_TIMEOUT)
        except (asyncio.TimeoutError, ValueError):
            return
        if line.startswith(b"LIST"):
            writer.write(b"SERVER|Update X4 Shard (Nexus Mods) to play|0.0.0.0|1|0|\nEND\n")
        else:
            writer.write(b"DENIED|update X4 Shard: since 0.12 the servers encrypt the connection\n")
        log.info("plain-text client from %s (X4 Shard before 0.12): told to update", ip)
        await close_after_refusal(reader, writer)

    async def handle(self, reader, writer, peer):
        pid = next(self.ids)
        player = Player(pid, writer, peer)
        self.players[pid] = player
        try:
            while True:
                timeout = IDLE_TIMEOUT if player.account else FIRST_LINE_TIMEOUT
                raw = await asyncio.wait_for(reader.readline(), timeout)
                if not raw:
                    break
                fields = raw.decode("utf-8", "replace").rstrip("\r\n").split("|")
                cmd = fields[0]
                if cmd == "LIST":
                    self.on_list(player)
                elif cmd == "REGISTER" and len(fields) >= 5 and self.directory.entries is not None:
                    await self.on_register(player, fields)
                elif cmd == "HELLO" and len(fields) >= 3 and player.account is None:
                    log.info("connect pid=%d from %s", pid, peer)
                    if not self.on_hello(player, fields):
                        await close_after_refusal(reader, writer)
                        break
                elif cmd == "PROOF" and len(fields) >= 2 and player.pending:
                    if not self.on_proof(player, fields[1].strip()):
                        await close_after_refusal(reader, writer)
                        break
                elif cmd == "POS" and len(fields) >= 8 and player.account:
                    self.on_pos(player, fields)
                elif cmd == "MINED" and len(fields) >= 3 and player.account:
                    self.on_mined(player, fields[1], int(float(fields[2])))
                elif cmd == "SELL" and len(fields) >= 4 and player.account:
                    self.on_sell(player, fields[1], fields[2], int(float(fields[3] or 0)))
                elif cmd == "BYE":
                    break
                await writer.drain()
        except (OSError, ValueError, OverflowError, asyncio.TimeoutError) as err:   # ConnectionError, SSLError
            log.info("pid=%d dropped: %s", pid, str(err) or type(err).__name__)
        finally:
            del self.players[pid]
            if player.sector is not None:
                for other in self.in_sector(player.sector):
                    other.send("DESPAWN", player.eid)
                    other.send("SAY", "%s left" % player.name)
            writer.close()
            if player.account is not None:
                if player.pose is not None:   # a game that reconnects may be anywhere it could fly from here
                    player.account["last_pose"] = ([player.sector] + [round(v, 1) for v in player.pose[:3]]
                                                   + [round(time.time())])
                    self.accounts.save()
                log.info("disconnect pid=%d %s after %d positions", pid, player.name, player.pos_count)

    async def report(self):
        while True:
            await asyncio.sleep(10)
            for p in self.players.values():
                if p.account is None:
                    continue
                pose = " ".join("%.1f" % v for v in p.pose) if p.pose else "-"
                log.info("status %s %s sector=%s positions=%d pose=%s", p.eid, p.name, p.sector, p.pos_count, pose)

    async def register_loop(self, target):
        host, port = target.rsplit(":", 1)
        while True:
            listed = False
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(host, int(port), ssl=client_tls()), 10)
                writer.write(("|".join(str(f) for f in ("REGISTER", self.me["name"], self.me["host"], self.me["port"],
                                                        self.online(), self.me["description"],
                                                        self.me["fingerprint"])) + "\n").encode())
                await writer.drain()
                reply = (await asyncio.wait_for(reader.readline(), 15)).decode("utf-8", "replace").strip()
                writer.close()
                listed = reply == "OK"
                if not listed:
                    log.info("directory %s did not list this shard: %s", target, reply or "no answer")
            except (OSError, asyncio.TimeoutError) as err:
                log.info("directory %s unreachable: %s", target, err)
            # not listed yet (the directory starting up too, say): try again soon
            await asyncio.sleep(REGISTER_EVERY if listed else 3)


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0", help="addresses to listen on, comma-separated (default: all)")
    ap.add_argument("--port", type=int, default=47110)
    ap.add_argument("--accounts", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "accounts.json"))
    ap.add_argument("--name", default="X4 Shard", help="shard name in the server list and the game")
    ap.add_argument("--public-host", help="address players use to reach this shard (default: first --host)")
    ap.add_argument("--public-port", type=int, help="port players use (default: --port)")
    ap.add_argument("--lan-host", help="this shard's address on its own network, listed to clients from there")
    ap.add_argument("--description", default="", help="one line for the server list")
    ap.add_argument("--invite", action="store_true",
                    help="private: newcomers need the invite link printed at start (players it knows do not)")
    ap.add_argument("--directory", action="store_true", help="also keep the list of shards that register here")
    ap.add_argument("--register-to", help="host:port of a directory to appear in its list (default: unlisted)")
    ap.add_argument("--test-name", help="player name that gets the scripted test below")
    ap.add_argument("--test-mine", help="ware:amount:interval:count, simulated mining on the client")
    ap.add_argument("--test-dock", help="station_eid:after_seconds, autopilot to the station and dock")
    args = ap.parse_args()
    test = {}
    if args.test_name:
        test["name"] = args.test_name
        if args.test_mine:
            ware, amount, interval, count = args.test_mine.split(":")
            test["mine"] = (ware, int(amount), float(interval), int(count))
        if args.test_dock:
            eid, after = args.test_dock.split(":")
            test["dock"] = (eid, float(after))
    cert_path, key_path, fingerprint = tlscert.load_or_make(args.accounts)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert_path, key_path)
    me = {"name": clean(args.name), "host": args.public_host or args.host.split(",")[0],
          "port": args.public_port or args.port, "description": clean(args.description, 80),
          # clients on the shard's own network get its LAN address (see Directory.listing)
          "lan_host": args.lan_host, "fingerprint": fingerprint}
    directory = Directory(me)
    if not args.directory:
        directory.entries = None
    shard = Shard(Accounts(args.accounts), test, me, directory, invite_code(args.accounts) if args.invite else None)
    listeners = await listen(args.host.split(","), args.port)
    for listener in listeners:
        asyncio.create_task(shard.accept(listener, ctx))
    log.info("listening on %s as '%s' (%s:%s)%s, TLS certificate %s", ", ".join(str(s.getsockname()) for s in listeners),
             me["name"], me["host"], me["port"], ", directory" if args.directory else "", fingerprint)
    if shard.invite:
        log.info("private: invite link x4shard://%s:%s/%s#%s", me["host"], me["port"], shard.invite, fingerprint)
    elif not args.register_to and not args.directory:
        log.info("unlisted: players join by the address x4shard://%s:%s#%s", me["host"], me["port"], fingerprint)
    asyncio.create_task(shard.report())
    if args.register_to:
        asyncio.create_task(shard.register_loop(args.register_to))
    await asyncio.Event().wait()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    if sys.platform == "win32":   # the shard watches sockets for their first byte: a selector loop
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())

"""X4 Shard server: one world, players see each other's ships, wallet and cargo live here.

The server owns what exists: static world entities per sector and one puppet per connected player.
Clients (X4 with the x4shard extension, or tools/fakepilot.py) report their ship pose; the server stamps
it with its own clock and relays it to the other players in that sector.
Each player has an account (credits, cargo of minable wares) kept in accounts.json. Mining is reported by the
client and accepted up to a rate (token bucket); selling happens at a market station the player is at.

Login without passwords: the client has an ECDSA P-256 key made once (kept in the game's user data, synced by
Steam Cloud), sends its Steam ID and public key, and signs this shard's random challenge (p256.py checks it).
The first login binds the public key to that Steam ID; later logins must be signed by the same key. Nothing on
the wire or known to a shard logs the player in again, and a shard knows the player whatever address it was
reached at. A game without Steam is known by its key alone. Plain accounts by name (the bot, test setups) are
for this machine and its local network only.

Any number of shards can run. A shard is unlisted unless it registers (--register-to) with a directory (a shard
started with --directory), under a name nobody else holds and at an address where it answers. The client asks
the directory for the list and lets the player pick a shard, or joins an address the player types. A private
shard (--invite) lets in only players it knows and newcomers who bring its invite code, x4shard://host:port/code.

Protocol: UTF-8 text lines, fields split by '|'.
  client -> server  LIST|proto                                   (before HELLO: the shard list)
                    HELLO|name|proto[|steam_id|public_key[|invite]]  (signed login: then CHALLENGE, PROOF)
                    PROOF|signature                              (over "x4shard-login|<nonce>|<steam_id>")
                    POS|sector_macro|x|y|z|yaw|pitch|roll        (sector space, metres and degrees)
                    MINED|ware|amount                            (cargo grew by mining)
                    SELL|station_eid|ware|amount                 (ware "all" / amount 0: everything the market buys)
  shard -> directory REGISTER|name|host|port|players|description   (answer OK or NO|reason)
  server -> client  SERVER|name|host|port|players|description ... END   (answer to LIST)
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
import string
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # p256.py next to this file, also under python -I
import p256  # noqa: E402

PROTO = "3"
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

log = logging.getLogger("shard")
T0 = time.monotonic()


def now():
    return time.monotonic() - T0


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


async def answers_as(host, port, name):
    """Does a shard called name answer at host:port? Its LIST answer starts with its own row."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 5)
        writer.write(("LIST|%s\n" % PROTO).encode())
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), 5)
        writer.close()
    except (OSError, asyncio.TimeoutError, ValueError):
        return False
    fields = line.decode("utf-8", "replace").rstrip("\r\n").split("|")
    return len(fields) > 3 and fields[0] == "SERVER" and fields[1] == name and fields[3] == str(port)


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

    def register(self, name, host, port, players, description):
        self.entries["%s:%s" % (host, port)] = {"name": name, "host": host, "port": port, "players": players,
                                                "description": description, "seen": time.monotonic()}

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

    def known(self, name, host, port):
        return any((e["name"], e["host"], e["port"]) == (name, host, port) for e in self.live())


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
        self.tokens_at = time.monotonic()
        self.pos_tokens = POS_BURST
        self.pos_at = time.monotonic()
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

    def on_pos(self, player, fields):
        """Relayed to the sector: at most POS_RATE a second, finite numbers only (NaN would reach every client)."""
        t = time.monotonic()
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
        player.pose = pose
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
        message = ("x4shard-login|%s|%s" % (claim["nonce"], claim["steam_id"])).encode()
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
        if ware not in MINABLE or amount <= 0:
            return
        t = time.monotonic()
        player.tokens = min(MINE_BURST, player.tokens + (t - player.tokens_at) * MINE_RATE)
        player.tokens_at = t
        accepted = min(amount, int(player.tokens))
        player.tokens -= accepted
        cargo = player.account["cargo"]
        cargo[ware] = cargo.get(ware, 0) + accepted
        self.accounts.save()
        if accepted < amount:
            player.send("CARGO", ware, cargo[ware])
            log.info("%s mined %d %s, accepted %d (rate limit), now %d", player.name, amount, ware, accepted, cargo[ware])
        else:
            log.info("%s mined %d %s, now %d", player.name, amount, ware, cargo[ware])

    def on_sell(self, player, eid, ware, amount):
        station = world_entity(player.sector, eid)
        market = station.get("market") if station else None
        if not market:
            player.send("SAY", "%s does not trade" % eid)
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
            player.send("SERVER", row["name"], row["host"], row["port"], row["players"], row["description"])
        player.send("END")

    async def on_register(self, player, fields):
        """Anyone may list a shard here: under a name nobody else holds, and only if a shard of that name answers
        at the address it gives (checked when it first appears), so the list never sends players elsewhere."""
        name, host, port = clean(fields[1]), clean(fields[2], 64), int(fields[3])
        players, description = int(fields[4] or 0), clean(fields[5] if len(fields) > 5 else "", 80)
        peer_ip = player.peer[0] if player.peer else ""
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
        if not self.directory.known(name, host, port) and not await answers_as(host, port, name):
            player.send("NO", "no shard named %s answers at %s:%d" % (name, host, port))
            log.info("directory: %s at %s:%d refused, does not answer as that shard", name, host, port)
            return
        self.directory.register(name, host, port, players, description)
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

    async def handle(self, reader, writer):
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "?"
        if len(self.players) >= MAX_CONNECTIONS or self.per_ip.get(ip, 0) >= MAX_PER_IP:
            log.info("connection from %s refused: too many", ip)
            writer.close()
            return
        self.per_ip[ip] = self.per_ip.get(ip, 0) + 1
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
        except (ConnectionError, ValueError, OverflowError, asyncio.TimeoutError) as err:
            log.info("pid=%d dropped: %s", pid, str(err) or type(err).__name__)
        finally:
            del self.players[pid]
            self.per_ip[ip] -= 1
            if not self.per_ip[ip]:
                del self.per_ip[ip]
            if player.sector is not None:
                for other in self.in_sector(player.sector):
                    other.send("DESPAWN", player.eid)
                    other.send("SAY", "%s left" % player.name)
            writer.close()
            if player.account is not None:
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
                reader, writer = await asyncio.wait_for(asyncio.open_connection(host, int(port)), 10)
                writer.write(("|".join(str(f) for f in ("REGISTER", self.me["name"], self.me["host"], self.me["port"],
                                                        self.online(), self.me["description"])) + "\n").encode())
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
    me = {"name": clean(args.name), "host": args.public_host or args.host.split(",")[0],
          "port": args.public_port or args.port, "description": clean(args.description, 80),
          # clients on the shard's own network get its LAN address (see Directory.listing)
          "lan_host": args.lan_host}
    directory = Directory(me)
    if not args.directory:
        directory.entries = None
    shard = Shard(Accounts(args.accounts), test, me, directory, invite_code(args.accounts) if args.invite else None)
    server = await asyncio.start_server(shard.handle, host=args.host.split(","), port=args.port, limit=LINE_LIMIT)
    log.info("listening on %s as '%s' (%s:%s)%s", ", ".join(str(s.getsockname()) for s in server.sockets),
             me["name"], me["host"], me["port"], ", directory" if args.directory else "")
    if shard.invite:
        log.info("private: invite link x4shard://%s:%s/%s", me["host"], me["port"], shard.invite)
    elif not args.register_to and not args.directory:
        log.info("unlisted: players join by address %s:%s", me["host"], me["port"])
    asyncio.create_task(shard.report())
    if args.register_to:
        asyncio.create_task(shard.register_loop(args.register_to))
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    asyncio.run(main())

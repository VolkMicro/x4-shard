"""End-to-end check of the shard server over real sockets (no game needed).

usage: python -I tests/test_server.py
Starts a directory shard on 127.0.0.1:47199, a second shard on 47198 that registers with it and a private one on
47196 (--invite), then plays: server list, listings refused (taken name, nobody answering, another shard's
address), signed Steam login on both shards (and a stolen Steam ID with another key, a replayed signature, an old
client), the server holding a ship to what it can do (a jump to the ore field is cut back, mining counts only in
the field, within the rate limit and the hold, trade waits after entering a sector), selling too far and at the
hub, reconnect with the wallet kept, the private shard with no, a wrong and the right invite code. Everything goes
over TLS: the list carries each shard's certificate fingerprint (a shard that gives another one is not listed), and a
plain-text client (X4 Shard before 0.12) is told to update.
"""
import asyncio
import hashlib
import os
import ssl
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "server"))
import p256  # noqa: E402

PORT, PORT_B, PORT_P = 47199, 47198, 47196
PROTO = "4"
HUB = (6000.0, 0.0, -9000.0)
START_POS = (0.0, 0.0, -7000.0)   # where the game start puts the ship, 7 km from the ore field at the centre
SECTOR = "cluster_13_sector001_macro"
STEAM_ID = "76561190000000001"
KEY = p256.keygen()


TLS = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)   # the game checks the fingerprint, not a certificate authority
TLS.check_hostname, TLS.verify_mode = False, ssl.CERT_NONE


class Client:
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer

    @classmethod
    async def connect(cls, port=PORT, tls=True):
        reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=TLS if tls else None)
        return cls(reader, writer)

    def fingerprint(self):
        return hashlib.sha256(self.writer.get_extra_info("ssl_object").getpeercert(binary_form=True)).hexdigest()

    @classmethod
    async def login(cls, name, steam_id=STEAM_ID, key=KEY, port=PORT, invite=None):
        """Steam login as the game does it: public key (and the invite code it was given), then the signed
        challenge."""
        c = await cls.connect(port)
        d, pub = key
        c.send("HELLO", name, PROTO, steam_id, pub, *([invite] if invite is not None else []))
        challenge = (await asyncio.wait_for(c.reader.readline(), 5)).decode().rstrip("\n").split("|")
        assert challenge[0] == "CHALLENGE", challenge
        c.send("PROOF", p256.sign(d, ("x4shard-login|%s|%s|%s" % (challenge[1], steam_id, c.fingerprint())).encode()))
        return c

    def send(self, *fields):
        self.writer.write(("|".join(str(f) for f in fields) + "\n").encode())

    async def lines(self, seconds=0.3):
        out = []
        try:
            while True:
                raw = await asyncio.wait_for(self.reader.readline(), seconds)
                if not raw:
                    break
                out.append(raw.decode().rstrip("\n"))
        except asyncio.TimeoutError:
            pass
        return out

    async def close(self):
        self.send("BYE")
        await self.writer.drain()
        self.writer.close()


def value(lines, prefix):
    hits = [l for l in lines if l.startswith(prefix)]
    return hits[-1].split("|") if hits else None


async def scenario(tmp):
    # the second shard lists itself once both have started (a slow machine may need a retry of its REGISTER)
    for _ in range(40):
        c = await Client.connect()
        home_fp = c.fingerprint()
        c.send("LIST", PROTO)
        got = await c.lines()
        await c.close()
        rows = [l.split("|") for l in got if l.startswith("SERVER|")]
        names = [r[1] for r in rows]
        if len(names) > 1:
            break
        await asyncio.sleep(0.5)
    assert names == ["Test Home", "Test B"] and got[-1] == "END", got
    # each row carries the certificate fingerprint the players will meet there
    c = await Client.connect(PORT_B)
    b_fp = c.fingerprint()
    await c.close()
    assert [r[6] for r in rows] == [home_fp, b_fp] and home_fp != b_fp, rows

    # a plain-text client is an X4 Shard before 0.12: its list says to update, its login is refused with the reason
    c = await Client.connect(tls=False)
    c.send("LIST", PROTO)
    got = await c.lines()
    assert got[0].startswith("SERVER|Update X4 Shard") and got[-1] == "END", got
    c = await Client.connect(tls=False)
    c.send("HELLO", "Old", "3", STEAM_ID, KEY[1])
    assert "encrypt" in (value(await c.lines(), "DENIED|") or [""])[-1], "an old client must be told to update"

    # the list only takes shards under a free name that really answer at the address they give, with the
    # certificate they give
    for name, port, fp, why in (("Test B", 47197, b_fp, "name taken"), ("Test Home", 47197, b_fp, "name taken"),
                                ("Ghost", 47197, b_fp, "does not answer"), ("Fake", PORT_B, b_fp, "answers as Test B"),
                                ("Test B", PORT_B, "0" * 64, "another certificate"),
                                ("Test B", PORT_B, "", "no fingerprint: an old server")):
        c = await Client.connect()
        c.send("REGISTER", name, "127.0.0.1", port, 0, "", fp)
        got = (await asyncio.wait_for(c.reader.readline(), 12)).decode()
        assert got.startswith("NO|"), "%s at %d (%s) must be refused: %s" % (name, port, why, got)
        await c.close()

    c = await Client.login("Tester")
    got = await c.lines()
    assert value(got, "WELCOME|")[3:] == ["Tester", "Test Home"], got
    assert value(got, "WALLET|") == ["WALLET", "10000"], got
    await c.close()

    thief = await Client.login("Thief", key=p256.keygen())
    got = await thief.lines()
    assert value(got, "DENIED|"), "a stolen Steam ID with another key must be refused: %s" % got

    # a replayed or forged signature, an old client
    c = await Client.connect()
    c.send("HELLO", "Thief", PROTO, STEAM_ID, KEY[1])
    await c.lines()
    c.send("PROOF", p256.sign(KEY[0], ("x4shard-login|00|%s|%s" % (STEAM_ID, home_fp)).encode()))
    assert value(await c.lines(), "DENIED|"), "a signature over another challenge must be refused"
    # a relay: shard B passes this shard's challenge on to the player, who signs it for B's certificate
    c = await Client.connect()
    c.send("HELLO", "Relayed", PROTO, STEAM_ID, KEY[1])
    nonce = value(await c.lines(), "CHALLENGE|")[1]
    c.send("PROOF", p256.sign(KEY[0], ("x4shard-login|%s|%s|%s" % (nonce, STEAM_ID, b_fp)).encode()))
    assert value(await c.lines(), "DENIED|"), "a signature bound to another shard's certificate must be refused"
    c = await Client.connect()
    c.send("HELLO", "Old", "2", STEAM_ID, "a" * 32)
    assert value(await c.lines(), "DENIED|"), "an old client must be told to update"

    # the same key is known on another shard, which keeps its own account
    c = await Client.login("Tester", port=PORT_B)
    got = await c.lines()
    assert value(got, "WELCOME|")[3:] == ["Tester", "Test B"], got
    await c.close()

    # a game without Steam signs in by its key alone, and gets the same account the next time
    gog = p256.keygen()
    for _ in range(2):
        c = await Client.login("NoSteam", steam_id="", key=gog, port=PORT_B)
        got = await c.lines()
        assert value(got, "WELCOME|")[3:] == ["NoSteam", "Test B"], got
        await c.close()

    # the server holds the ship to what it can do: at the start, 7 km from the ore field, nothing to mine, and a jump
    # straight into the field is cut back to MAX_SPEED
    c = await Client.login("Tester")
    await c.lines()
    c.send("POS", SECTOR, *START_POS, 0, 0, 0)
    c.send("POS", SECTOR, 0, 0, 0, 0, 0, 0)
    c.send("MINED", "ore", 10)
    got = await c.lines()
    assert value(got, "CARGO|ore|") == ["CARGO", "ore", "0"] and any("No ore to mine here" in l for l in got), got
    await asyncio.sleep(1.6)   # long enough to fly the 7 km
    c.send("POS", SECTOR, 0, 0, 0, 0, 0, 0)
    c.send("MINED", "ore", 40)
    got = await c.lines()
    assert not any(l.startswith("CARGO|ore") for l in got), "40 in the field is within the burst: %s" % got
    c.send("MINED", "ore", 100)
    corr = value(await c.lines(), "CARGO|ore|")
    assert corr and int(corr[2]) < 140, "rate limit must clip"
    ore = int(corr[2])
    c.send("SELL", "hub1", "all", 0)
    assert any("Too far" in l for l in await c.lines())
    await asyncio.sleep(2.3)   # 11.5 km to the hub
    c.send("POS", SECTOR, HUB[0], HUB[1], HUB[2] - 800, 0, 0, 0)
    c.send("SELL", "hub1", "all", 0)
    got = await c.lines()
    assert value(got, "CARGO|ore|") == ["CARGO", "ore", "0"], got
    assert value(got, "WALLET|") == ["WALLET", str(10000 + ore * 50)], got
    # out through a gate and back in at once: mining and trade wait a minute after entering a sector
    c.send("POS", "cluster_14_sector001_macro", 0, 0, 0, 0, 0, 0)
    c.send("POS", SECTOR, HUB[0], HUB[1], HUB[2] - 800, 0, 0, 0)
    c.send("SELL", "hub1", "all", 0)
    assert any("Just arrived" in l for l in await c.lines()), "trade must wait after entering a sector"
    await c.close()

    c = await Client.login("Tester renamed")
    got = await c.lines()
    assert value(got, "WALLET|") == ["WALLET", str(10000 + ore * 50)], "wallet must persist: %s" % got
    assert value(got, "WELCOME|")[3] == "Tester renamed", "the Steam name may change, the account stays"

    # open to the internet: NaN poses are not relayed, a flood is cut to the rate, one address gets 8 connections
    watcher = await Client.connect()
    watcher.send("HELLO", "Watcher", PROTO)
    watcher.send("POS", SECTOR, 0, 0, 0, 0, 0, 0)
    await watcher.lines()
    c.send("POS", SECTOR, "nan", 0, 0, 0, 0, 0)
    assert not any("nan" in l for l in await watcher.lines()), "a NaN pose must not reach other players"
    for i in range(400):
        c.send("POS", SECTOR, i, 0, 0, 0, 0, 0)
    moves = [l for l in await watcher.lines(seconds=1) if l.startswith("MOVE|")]
    assert 0 < len(moves) <= 100, "a POS flood must be cut to about POS_BURST, got %d" % len(moves)
    await watcher.close()
    await c.close()
    await asyncio.sleep(0.3)
    held = [await Client.connect() for _ in range(8)]
    try:   # closed before the TLS handshake ends
        extra = await asyncio.wait_for(Client.connect(), 3)
        assert await asyncio.wait_for(extra.reader.read(), 2) == b"", "the 9th connection from one address must close"
    except (OSError, asyncio.IncompleteReadError):
        pass
    for h in held:
        await h.close()

    # a private shard: newcomers need its invite code, players it knows do not
    with open(os.path.join(tmp, "p.json.invite"), encoding="utf-8") as f:
        code = f.read().strip()
    friend = p256.keygen()
    for invite, why in ((None, "no code"), ("wrong0code", "a wrong code")):
        c = await Client.login("Friend", steam_id="76561190000000002", key=friend, port=PORT_P, invite=invite)
        assert value(await c.lines(), "DENIED|"), "a newcomer with %s must be refused" % why
    # like the 0.10 client: positions right after the proof, before any answer; the refusal must still arrive (a
    # close with unread data resets the connection, and Windows then drops the refusal on the client's side)
    c = await Client.login("Early", steam_id="76561190000000003", key=p256.keygen(), port=PORT_P)
    for i in range(20):
        c.send("POS", SECTOR, i, 0, 0, 0, 0, 0)
    await c.writer.drain()
    assert value(await c.lines(seconds=1), "DENIED|"), "a refusal must arrive while the client keeps sending"
    for invite in (code, None):
        c = await Client.login("Friend", steam_id="76561190000000002", key=friend, port=PORT_P, invite=invite)
        got = await c.lines()
        assert value(got, "WELCOME|")[3:] == ["Friend", "Test Private"], got
        await c.close()

    import shard_server
    import tlscert
    assert tlscert.load_or_make(os.path.join(tmp, "a.json"))[2] == home_fp, "the shard keeps its certificate"
    assert shard_server.is_local("127.0.0.1") and shard_server.is_local("192.168.1.10")
    assert not shard_server.is_local("8.8.8.8")
    assert await shard_server.resolves_to("localhost", "127.0.0.1")
    assert not await shard_server.resolves_to("localhost", "8.8.8.8")
    home = shard_server.Directory({"name": "H", "host": "mc.example.org", "port": 47110, "description": "",
                                   "lan_host": "192.168.1.10"})
    assert home.listing(0, "1.1.1.1")[0]["host"] == "mc.example.org", "the internet gets the public address"
    assert home.listing(0, "192.168.1.20")[0]["host"] == "192.168.1.10", "its own network gets the LAN address"

    # where mining counts: the ore field at the centre (with the laser's 3 km), the long tube far out, nowhere else
    field_for = shard_server.field_for
    assert field_for(SECTOR, (0, 0, 0), "ore") and field_for(SECTOR, (5400, 3900, 0), "ore")
    assert not field_for(SECTOR, START_POS, "ore") and not field_for(SECTOR, HUB, "ore")
    assert not field_for(SECTOR, (0, 0, 0), "silicon") and field_for(SECTOR, (-89184.9, 0, -72944.6), "silicon")
    assert not field_for(SECTOR, (0, 0, 0), "hydrogen") and not field_for("cluster_14_sector001_macro", (0, 0, 0), "ore")

    # in this process, with the server's clock in hand: a jump is held to MAX_SPEED, the hold takes 2600 m3
    class Sink:
        def __init__(self):
            self.lines = []

        def write(self, data):
            self.lines.append(data.decode().rstrip("\n"))

    clock = [1000.0]
    shard_server.clock = lambda: clock[0]
    accounts = shard_server.Accounts(os.path.join(tmp, "unit.json"))
    me = {"name": "Unit", "host": "127.0.0.1", "port": 1, "description": ""}
    shard = shard_server.Shard(accounts, {}, me, shard_server.Directory(me))
    p = shard_server.Player(1, Sink(), ("127.0.0.1", 1))
    p.account = accounts.get("unit", "Unit")
    shard.welcome(p, "Unit", "-")
    shard.on_pos(p, ["POS", SECTOR] + [str(v) for v in START_POS] + ["0", "0", "0"])
    clock[0] += 1.0
    shard.on_pos(p, ["POS", SECTOR, "0", "0", "3000", "0", "0", "0"])   # 10 km in a second
    assert abs(p.pose[2] - (START_POS[2] + shard_server.MAX_SPEED + 1)) < 1, p.pose
    clock[0] += 10.0
    shard.on_pos(p, ["POS", SECTOR, "0", "0", "0", "0", "0", "0"])
    assert p.pose[:3] == (0.0, 0.0, 0.0), "given the time, the ship is where it says: %s" % (p.pose,)
    p.account["cargo"] = {"ore": 250, "silicon": 3}
    shard.on_mined(p, "ore", 20)
    assert p.account["cargo"]["ore"] == 257 and any("hold is full" in l for l in p.writer.lines), p.account
    shard_server.clock = time.monotonic
    print("ok: TLS with fingerprints in the list, plain-text clients told to update, a relayed login refused, list of 2 shards, fake listings "
          "and a wrong certificate refused, signed Steam login on both shards, stolen ID, replayed signature and old "
          "client refused, jump to the field held back, no mining outside it, mined %d ore, sold for %d Cr, trade "
          "waits after a sector change, hold full at 2600 m3, wallet persisted, NaN and POS flood stopped, "
          "8 connections per address, key-only login, private shard by invite" % (ore, ore * 50))


def main():
    sys.stdout.reconfigure(errors="replace")   # server logs may carry localized OS messages
    tmp = tempfile.mkdtemp()
    common = [sys.executable, "-I", os.path.join(ROOT, "server", "shard_server.py"), "--host", "127.0.0.1"]
    home = subprocess.Popen(common + ["--port", str(PORT), "--name", "Test Home", "--directory",
                                      "--accounts", os.path.join(tmp, "a.json")],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    other = subprocess.Popen(common + ["--port", str(PORT_B), "--name", "Test B", "--register-to",
                                       "127.0.0.1:%d" % PORT, "--accounts", os.path.join(tmp, "b.json")],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    private = subprocess.Popen(common + ["--port", str(PORT_P), "--name", "Test Private", "--invite",
                                         "--accounts", os.path.join(tmp, "p.json")],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        asyncio.run(asyncio.sleep(1.5))
        asyncio.run(scenario(tmp))
    finally:
        shards = ((home, "home"), (other, "B"), (private, "private"))
        for proc, _ in shards:   # all of them first: a failure below must not leave a shard holding its port
            proc.terminate()
        for proc, label in shards:
            print("--- %s log" % label)
            print(proc.communicate(timeout=5)[0].decode(errors="replace"))


if __name__ == "__main__":
    main()

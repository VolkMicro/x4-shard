"""End-to-end check of the shard server over real sockets (no game needed).

usage: python -I tests/test_server.py
Starts a directory shard on 127.0.0.1:47199, a second shard on 47198 that registers with it and a private one on
47196 (--invite), then plays: server list, listings refused (taken name, nobody answering, another shard's
address), signed Steam login on both shards (and a stolen Steam ID with another key, a replayed signature, an old
client), mining within and over the rate limit, selling too far and at the hub, reconnect with the wallet kept,
the private shard with no, a wrong and the right invite code.
"""
import asyncio
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "server"))
import p256  # noqa: E402

PORT, PORT_B, PORT_P = 47199, 47198, 47196
HUB = (6000.0, 0.0, -9000.0)
SECTOR = "cluster_13_sector001_macro"
STEAM_ID = "76561190000000001"
KEY = p256.keygen()


class Client:
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer

    @classmethod
    async def connect(cls, port=PORT):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        return cls(reader, writer)

    @classmethod
    async def login(cls, name, steam_id=STEAM_ID, key=KEY, port=PORT, invite=None):
        """Steam login as the game does it: public key (and the invite code it was given), then the signed
        challenge."""
        c = await cls.connect(port)
        d, pub = key
        c.send("HELLO", name, "3", steam_id, pub, *([invite] if invite is not None else []))
        challenge = (await asyncio.wait_for(c.reader.readline(), 5)).decode().rstrip("\n").split("|")
        assert challenge[0] == "CHALLENGE", challenge
        c.send("PROOF", p256.sign(d, ("x4shard-login|%s|%s" % (challenge[1], steam_id)).encode()))
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
    c = await Client.connect()
    c.send("LIST", "2")
    got = await c.lines()
    names = [l.split("|")[1] for l in got if l.startswith("SERVER|")]
    assert names == ["Test Home", "Test B"] and got[-1] == "END", got
    await c.close()

    # the list only takes shards under a free name that really answer at the address they give
    for name, port, why in (("Test B", 47197, "name taken"), ("Test Home", 47197, "name taken"),
                            ("Ghost", 47197, "does not answer"), ("Fake", PORT_B, "answers as Test B")):
        c = await Client.connect()
        c.send("REGISTER", name, "127.0.0.1", port, 0, "")
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
    c.send("HELLO", "Thief", "3", STEAM_ID, KEY[1])
    await c.lines()
    c.send("PROOF", p256.sign(KEY[0], b"x4shard-login|00|" + STEAM_ID.encode()))
    assert value(await c.lines(), "DENIED|"), "a signature over another challenge must be refused"
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

    c = await Client.login("Tester")
    await c.lines()
    c.send("POS", SECTOR, 0, 0, 5000, 0, 0, 0)
    c.send("MINED", "ore", 40)
    got = await c.lines()
    assert not any(l.startswith("CARGO|ore") for l in got), "40 is within the burst, no correction expected"
    c.send("MINED", "ore", 100)
    corr = value(await c.lines(), "CARGO|ore|")
    assert corr and int(corr[2]) < 140, "rate limit must clip"
    ore = int(corr[2])
    c.send("SELL", "hub1", "all", 0)
    assert any("Too far" in l for l in await c.lines())
    c.send("POS", SECTOR, HUB[0], HUB[1], HUB[2] - 800, 0, 0, 0)
    c.send("SELL", "hub1", "all", 0)
    got = await c.lines()
    assert value(got, "CARGO|ore|") == ["CARGO", "ore", "0"], got
    assert value(got, "WALLET|") == ["WALLET", str(10000 + ore * 50)], got
    await c.close()

    c = await Client.login("Tester renamed")
    got = await c.lines()
    assert value(got, "WALLET|") == ["WALLET", str(10000 + ore * 50)], "wallet must persist: %s" % got
    assert value(got, "WELCOME|")[3] == "Tester renamed", "the Steam name may change, the account stays"

    # open to the internet: NaN poses are not relayed, a flood is cut to the rate, one address gets 8 connections
    watcher = await Client.connect()
    watcher.send("HELLO", "Watcher", "3")
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
    extra = await Client.connect()
    assert await asyncio.wait_for(extra.reader.read(), 2) == b"", "the 9th connection from one address must close"
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
    assert shard_server.is_local("127.0.0.1") and shard_server.is_local("192.168.1.10")
    assert not shard_server.is_local("8.8.8.8")
    assert await shard_server.resolves_to("localhost", "127.0.0.1")
    assert not await shard_server.resolves_to("localhost", "8.8.8.8")
    home = shard_server.Directory({"name": "H", "host": "mc.example.org", "port": 47110, "description": "",
                                   "lan_host": "192.168.1.10"})
    assert home.listing(0, "1.1.1.1")[0]["host"] == "mc.example.org", "the internet gets the public address"
    assert home.listing(0, "192.168.1.20")[0]["host"] == "192.168.1.10", "its own network gets the LAN address"
    print("ok: list of 2 shards, fake listings refused, signed Steam login on both shards, stolen ID, replayed "
          "signature and old client refused, mined %d ore, sold for %d Cr, wallet persisted, NaN and POS flood "
          "stopped, 8 connections per address, key-only login, private shard by invite" % (ore, ore * 50))


def main():
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
        for proc, label in ((home, "home"), (other, "B"), (private, "private")):
            proc.terminate()
            print("--- %s log" % label)
            print(proc.communicate(timeout=5)[0].decode(errors="replace"))


if __name__ == "__main__":
    main()

# X4 Shard

A shared online world for **X4: Foundations**. The world lives on a server: other players' ships fly next to
you, and the server keeps your credits and cargo. Anyone can run a server.

**Status: early alpha (0.12).** It works, but it is small:

| Works now | Not yet |
|---|---|
| One sector (Second Contact II Flashpoint) with a trade station | More sectors and content |
| Other players' ships in your sector, smoothed at 20 updates/s | Combat between players or against shared enemies |
| Mining ore and selling it at the station; credits and cargo kept by the server | Buying ships, trading between players |
| The server checks what clients report: no teleports, no mining outside a field, no overfull hold | |
| Encrypted connections (TLS), each server checked by its certificate's fingerprint | |
| A server list in the game, joining by address, private servers by invite | |
| Login by Steam account with a signed challenge bound to the server, no passwords | |

## How it works

X4 is only the client. A game started from the **X4 Shard** start has no NPC economy of its own (a clean
universe); the extension asks the server what exists and places it, and moves other players' ships where the
server says they are. The server is a small Python program (`server/`): it owns the world, the accounts and the
rules, and it does not take a client's word for more than its ship can do. Positions are held to the ship's top
speed from the game's data (190 m/s, 3750 m/s in travel mode; a jump is cut back), mining counts only in the
sector's asteroid fields (also from the game's data) and up to the hold's 2600 m³, selling only at the station,
and mining and trade wait a minute after a ship enters a sector.

What it is not: X4's own galaxy shared online. X4's economy and AI stay switched off; the shard's world is small
and lives in one server process, so there is no X4 simulation to keep in sync between players.

Combat is not synchronised yet. The plan: the server flies the shared enemies with its own simple physics and
decides what got hit from its own positions and weapon data; clients only report that they fired and show the
result.

Connections are TLS 1.2 or 1.3. Each server makes its own certificate the first time it starts, and the game checks
the certificate's SHA-256 fingerprint instead of a certificate authority: the directory's fingerprint comes with the
mod, a listed server's with the list (the directory checks it when the server registers), a private server's with
its invite link (`x4shard://host:port/code#fingerprint`), and a server joined by a bare address is remembered by
the certificate it showed the first time. The login signature covers that fingerprint too, so a server cannot pass
your login on to another one.

## Install

- **Vortex:** "Mod Manager Download" on the Nexus Mods page, then deploy.
- **By hand:** put the `x4shard` folder into `X4 Foundations\extensions\` (create the folder if it is missing):
  the result is `extensions\x4shard\content.xml`.
- **Then:** in the game, Settings → Extensions → turn **Protected UI Mode** off and restart the game. Read
  [Security](#security) first: this setting is the reason the mod can reach the network.

Requires X4: Foundations 9.00. No DLC needed.

## Play

1. New Game → **X4 Shard** (at the bottom of the list of starts).
2. The ship computer offers the servers: press the number. Login is by your Steam account; nothing to type.
3. A server that is not listed, or a private one: choose **Connect by address...** and paste the link its owner
   gives (`x4shard://203.0.113.5:47110/code#fingerprint`) or type its address (`203.0.113.5:47110`).

No saves are needed: each time, New Game → X4 Shard; your progress comes from the server.

## Run a server

Python 3.8 or newer, no extra packages, and TCP port 47110 open to the internet:

```bash
python3 server/shard_server.py --name "My shard" --public-host my.example.org
```

- **Unlisted by default:** at start the server prints its link, `x4shard://host:port#fingerprint`; players paste it.
- **Private:** add `--invite`. The server prints an invite link, `x4shard://host:port/code#fingerprint`; newcomers
  need it, players it already knows do not. Share it only with your friends.
- **Public:** add `--register-to mc.idiot-home.ru:47110` to appear in everyone's server list. The list takes a
  name nobody else holds, and only if the server really answers at the address it gives, with the certificate it
  gives.

Accounts are kept in `accounts.json` next to the server, the certificate in `accounts.json.cert.pem` and
`accounts.json.key.pem`. Keep those two: with a new certificate, players who knew the server refuse it until they
get the new link. `python3 server/shard_server.py --help` lists the options; the line protocol is described at the
top of `server/shard_server.py`.

## Security

X4's Lua cannot open network connections: the game's UI sandbox has no sockets, no `ffi.load`, no `io` or `os`.
With **Protected UI Mode off**, the game's own `package.loadlib` can load a Lua C module, and X4 Shard ships one:
[`native/x4shardnet.c`](native/x4shardnet.c), about 740 lines of C, built to `x4shardnet_64.dll`.

- It is not injected anywhere: the game loads it through its own Lua, **only when you start an X4 Shard game**. In
  any other game none of the mod's native code runs. It hooks nothing and touches no other process.
- What it can do: a TLS connection (Windows SChannel) to the server you chose, reporting the fingerprint of the
  server's certificate; make and use your login key (Windows CNG, ECDSA P-256); read your own Steam nickname from
  the game's `steam_api64.dll`; read and write files in `%LOCALAPPDATA%\X4Shard\` only (your key and recent
  servers). Nothing else. Its imports: `ws2_32`, `secur32`, `crypt32`, `bcrypt`, `kernel32`, `msvcrt` and the
  game's `lua51_64.dll`.
- What a server learns: your Steam ID, your nickname, your public key and where your ship flies in the X4 Shard
  game. Never your private key: you prove who you are by signing the server's random challenge together with the
  server's certificate fingerprint, so the signature is good for that server only.
- Protected UI Mode is a global setting: while it is off, **every** installed mod may load native code. Turn it back
  on when you play other mods you do not trust.
- The DLL is built from this source by GitHub Actions, and the build is reproducible (no timestamps, fixed image
  base): build it yourself with `native/build.sh` and compare SHA-256, or check the release's build provenance with
  `gh attestation verify x4shardnet_64.dll --repo VolkMicro/x4-shard`.

If your antivirus flags the DLL, do not just override it: check the source and the hash first, or skip the mod.
See [SECURITY.md](SECURITY.md) for details and how to report a problem.

## Build from source

```bash
sudo apt install gcc-mingw-w64-x86-64-win32
bash native/build.sh                       # -> extension/x4shard/native/x4shardnet_64.dll
python3 -I tests/test_server.py            # the server, end to end, no game needed
python3 -I tools/make_dist.py              # -> dist/X4Shard-<version>.zip, dist/X4Shard-server-<version>.zip
```

On Windows with X4 installed, `python -I tools/dlltest.py <x4shardnet_64.dll>` runs the network module against a
local server through the game's own LuaJIT, and `python -I tools/clienttest.py <x4shardnet_64.dll>` runs the
extension's client the same way, with stand-ins for the game: the server list, joining, and refusing a server whose
certificate is not the expected one.

## Layout

- `extension/x4shard/` — the X4 extension: the clean-universe start (`libraries/gamestarts.xml`), Mission Director
  script (`md/`), Lua client and the address window (`ui/`).
- `native/` — the network module's source and build script.
- `server/` — the shard server, its ECDSA check (`p256.py`) and its certificate maker (`tlscert.py`), plain Python.
- `tests/` — server tests; `tools/` — packaging, a bot player and the Windows tests of the module and the client.

## License

MIT, see [LICENSE](LICENSE). X4: Foundations is a game by Egosoft; this project is not affiliated with Egosoft.

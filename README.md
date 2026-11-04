# X4 Shard

A shared online world for **X4: Foundations**. The world lives on a server: other players' ships fly next to
you, and the server keeps your credits and cargo. Anyone can run a server.

**Status: early alpha (0.11).** It works, but it is small:

| Works now | Not yet |
|---|---|
| One sector (Second Contact II Flashpoint) with a trade station | More sectors and content |
| Other players' ships in your sector, smoothed at 20 updates/s | Combat between players or against shared enemies |
| Mining ore and selling it at the station; credits and cargo kept by the server | Buying ships, trading between players |
| A server list in the game, joining by address, private servers by invite | Encrypted traffic (TLS) |
| Login by Steam account with a signed challenge, no passwords | |

## How it works

X4 is only the client. A game started from the **X4 Shard** start has no NPC economy of its own (a clean
universe); the extension asks the server what exists and places it, and moves other players' ships where the
server says they are. The server is a small Python program (`server/`): it owns the world, the accounts and the
rules, and it checks what clients report (mining is rate-limited, selling only works at the station, poses must be
finite numbers in range).

Combat is not synchronised yet. The plan is the same server authority: the server decides what got hit, clients
only report and show it.

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
3. A server that is not listed, or a private one: choose **Connect by address...** and type or paste its address
   (`203.0.113.5:47110`) or its invite link (`x4shard://203.0.113.5:47110/code`).

No saves are needed: each time, New Game → X4 Shard; your progress comes from the server.

## Run a server

Python 3.8 or newer, no extra packages, and TCP port 47110 open to the internet:

```bash
python3 server/shard_server.py --name "My shard" --public-host my.example.org
```

- **Unlisted by default:** players join it by address.
- **Private:** add `--invite`. The server prints an invite link once; newcomers need it, players it already knows
  do not. Share it only with your friends.
- **Public:** add `--register-to mc.idiot-home.ru:47110` to appear in everyone's server list. The list takes a
  name nobody else holds, and only if the server really answers at the address it gives.

Accounts are kept in `accounts.json` next to the server. `python3 server/shard_server.py --help` lists the options;
the line protocol is described at the top of `server/shard_server.py`.

## Security

X4's Lua cannot open network connections: the game's UI sandbox has no sockets, no `ffi.load`, no `io` or `os`.
With **Protected UI Mode off**, the game's own `package.loadlib` can load a Lua C module, and X4 Shard ships one:
[`native/x4shardnet.c`](native/x4shardnet.c), about 400 lines of C, built to `x4shardnet_64.dll`.

- It is not injected anywhere: the game loads it through its own Lua, **only when you start an X4 Shard game**. In
  any other game none of the mod's native code runs. It hooks nothing and touches no other process.
- What it can do: a TCP connection to the server you chose; make and use your login key (Windows CNG, ECDSA P-256);
  read your own Steam nickname from the game's `steam_api64.dll`; read and write files in
  `%LOCALAPPDATA%\X4Shard\` only (your key and recent servers). Nothing else. Its imports: `ws2_32`, `bcrypt`,
  `kernel32`, `msvcrt` and the game's `lua51_64.dll`.
- What a server learns: your Steam ID, your nickname, your public key and where your ship flies in the X4 Shard
  game. Never your private key: you prove who you are by signing the server's random challenge.
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

## Layout

- `extension/x4shard/` — the X4 extension: the clean-universe start (`libraries/gamestarts.xml`), Mission Director
  script (`md/`), Lua client and the address window (`ui/`).
- `native/` — the network module's source and build script.
- `server/` — the shard server and its ECDSA check (`p256.py`, plain Python).
- `tests/` — server tests; `tools/` — packaging and a bot player for tests.

## License

MIT, see [LICENSE](LICENSE). X4: Foundations is a game by Egosoft; this project is not affiliated with Egosoft.

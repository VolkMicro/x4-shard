# Security

## The network module

X4's UI Lua has no way to open a network connection. X4 Shard therefore ships a small Lua C module,
`x4shardnet_64.dll`, built from [`native/x4shardnet.c`](native/x4shardnet.c). The game loads it through its own
`package.loadlib`, which exists only while **Protected UI Mode** is off (Settings → Extensions).

The extension loads the module on the first frame of an **X4 Shard** game, not before: in any other game it is
never loaded. Every call into it comes from the extension's Lua (`extension/x4shard/ui/x4shard_net.lua`).

| Function | What it does |
|---|---|
| `open`, `state`, `send`, `recv`, `close` | One non-blocking TCP connection, to the server the player chose |
| `keygen` | Makes the player's ECDSA P-256 key pair (Windows CNG, `BCryptGenerateKeyPair`) |
| `sign` | Signs a login challenge with that key: `x4shard-login|<server's random hex>|<Steam ID>` only |
| `persona` | Reads the player's own Steam nickname from the game's `steam_api64.dll` |
| `load`, `save` | Read and write files in `%LOCALAPPDATA%\X4Shard\` only; names are checked (`[A-Za-z0-9._-]`, no paths) |
| `version` | The module's version |

Imports: `ws2_32.dll`, `bcrypt.dll`, `kernel32.dll`, `msvcrt.dll` and the game's `lua51_64.dll`. No hooks, no
other processes, no registry, nothing at load time.

**Protected UI Mode off allows every installed mod to load native code**, not only this one. Turn it back on when
you play other mods you do not trust.

## Verifying the DLL

- The release DLL is built from the tagged source by GitHub Actions; the release carries `SHA256SUMS` and a
  build provenance attestation: `gh attestation verify x4shardnet_64.dll --repo VolkMicro/x4-shard`.
- The build is reproducible: `native/build.sh` writes no timestamp into the PE header and fixes the image base, so
  the same source and the same MinGW-w64 version give the same bytes. Build it yourself and compare the SHA-256.

## What a server can and cannot do

- A server learns your Steam ID, your Steam nickname, your public key and your ship's position in the X4 Shard
  game. It never sees your private key: login is a signature over its own random challenge, which is useless to
  anyone else.
- A server you join can place ships and stations in your X4 Shard game and set the credits and cargo shown there.
  It cannot run code on your PC or read your files: the client only understands the line protocol in
  `server/shard_server.py`.
- Known limits of this early version: traffic is not encrypted (TLS is planned); a shard you join could relay your
  login to another shard while you are connected to it (shard keys are planned); a Steam ID is not verified by Steam
  itself, so the first key to log in under a Steam ID owns that account on that shard.

## Reporting a problem

Open an issue, or for anything sensitive, a private report: GitHub → Security → "Report a vulnerability".

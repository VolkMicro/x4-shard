# Security

## The network module

X4's UI Lua has no way to open a network connection. X4 Shard therefore ships a small Lua C module,
`x4shardnet_64.dll`, built from [`native/x4shardnet.c`](native/x4shardnet.c). The game loads it through its own
`package.loadlib`, which exists only while **Protected UI Mode** is off (Settings → Extensions).

The extension loads the module on the first frame of an **X4 Shard** game, not before: in any other game it is
never loaded. Every call into it comes from the extension's Lua (`extension/x4shard/ui/x4shard_net.lua`).

| Function | What it does |
|---|---|
| `open`, `state`, `send`, `recv`, `close` | One non-blocking TLS 1.2 connection (Windows SChannel), to the server the player chose |
| `fingerprint` | The SHA-256 of that server's certificate, for the extension to compare with the one it expects |
| `keygen` | Makes the player's ECDSA P-256 key pair (Windows CNG, `BCryptGenerateKeyPair`) |
| `sign` | Signs a login challenge with that key: `x4shard-login|<server's random hex>|<Steam ID>|<server's certificate fingerprint>` only |
| `persona` | Reads the player's own Steam nickname from the game's `steam_api64.dll` |
| `load`, `save` | Read and write files in `%LOCALAPPDATA%\X4Shard\` only; names are checked (`[A-Za-z0-9._-]`, no paths) |
| `version` | The module's version |

Imports: `ws2_32.dll`, `secur32.dll`, `crypt32.dll`, `bcrypt.dll`, `kernel32.dll`, `msvcrt.dll` and the game's
`lua51_64.dll`. No hooks, no other processes, no registry, nothing at load time.

## Encryption and server identity

Every connection is TLS (1.2 from the game; the server takes 1.2 and 1.3). A server makes its own self-signed ECDSA
P-256 certificate the first time it starts (`server/tlscert.py`, plain Python). The module does not check it
against certificate authorities; it reports the certificate's SHA-256 fingerprint and the extension refuses the
server unless it is the expected one:

- the directory (the server list): its fingerprint is in the mod, `ui/x4shard_config.lua`;
- a listed server: the fingerprint in the list, which the directory checked by connecting to that server when it
  registered;
- a private or unlisted server: the fingerprint in the link its owner gives, `x4shard://host:port[/code]#fingerprint`;
- a server joined by a bare address: the certificate it showed on the first visit (trust on first use, as SSH does).

The login signature covers the fingerprint of the server the game is connected to, so a server that passes another
server's challenge on to a player gets a signature the other server refuses.

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
- The server holds clients to what their ship can do: positions to the ship's top speed (a jump is cut back),
  mining to the sector's asteroid fields and the hold's size, trade to the station's range. It cannot see a
  client's physics, so this limits cheating rather than making it impossible.
- Known limits of this early version: the first visit to a server by a bare address trusts the certificate it
  shows (use the owner's link to avoid that); a Steam ID is not verified by Steam itself, so the first key to log in
  under a Steam ID owns that account on that shard.

## Reporting a problem

Open an issue, or for anything sensitive, a private report: GitHub → Security → "Report a vulnerability".

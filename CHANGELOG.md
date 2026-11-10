# Changelog

## 0.12

- Encrypted connections: TLS 1.2 or 1.3 between the game and every server (Windows SChannel in the network
  module, Python's `ssl` on the server). Each server has its own certificate, made once in plain Python; the game
  checks its SHA-256 fingerprint: the directory's comes with the mod, a listed server's with the list (the directory
  checks it when the server registers), a private server's with its invite link (`x4shard://host:port/code#...`),
  and a server joined by a bare address is remembered by the certificate it showed the first time.
- The login signature now covers the certificate of the server the game is connected to: a server that passes
  another server's challenge on to a player gets a signature the other server refuses.
- The server checks what clients report: positions are held to the ship's top speed from the game's data (a jump
  is cut back), mining counts only in the sector's asteroid fields and up to the hold's 2600 m³, and mining and
  trade wait a minute after a ship enters a sector.
- Protocol 4. An X4 Shard 0.11 is told to update: its server list shows one row that says so.
- `tools/dlltest.py` and `tools/clienttest.py` run the network module and the client outside the game (Windows,
  with the game's own LuaJIT).

## 0.11

- Private servers: `--invite` lets in only players the server knows and newcomers with its invite link
  (`x4shard://host:port/code`). Servers are unlisted unless they register with a directory.
- "Connect by address..." opens a window in the game: type or paste an address or an invite link. The network
  module no longer reads the clipboard.
- The network module is loaded only when an X4 Shard game starts, never in other games.
- Reproducible build of the network module (no timestamps, fixed image base); releases are built by GitHub Actions
  with SHA256SUMS and a build provenance attestation.
- Source published under the MIT license.

## 0.10

- First public version: server list, join by address, login by Steam account with a signed challenge, one sector
  with mining and selling, other players' ships.

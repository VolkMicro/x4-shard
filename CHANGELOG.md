# Changelog

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

#!/bin/bash
# Build x4shardnet_64.dll with MinGW-w64 (Debian/Ubuntu: apt install gcc-mingw-w64-x86-64-win32).
# The import library for the game's lua51_64.dll comes from lua51_64.def, so no game files are needed.
# No timestamp goes into the PE header: the same source and compiler give the same DLL, byte for byte.
# usage: build.sh [out_dir]
set -euo pipefail
cd "$(dirname "$0")"
out=${1:-../extension/x4shard/native}
mkdir -p "$out" build
x86_64-w64-mingw32-dlltool -d lua51_64.def -l build/liblua51_64.a
# -s strips at link time: a separate strip would write a timestamp back into the header; a fixed image base, or ld
# derives one from the output path (Windows moves the DLL anyway, ASLR)
x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -shared -static-libgcc -s -Wl,--no-insert-timestamp \
  -Wl,--image-base,0x180000000 -o "$out/x4shardnet_64.dll" x4shardnet.c -Lbuild -llua51_64 -lws2_32 -lbcrypt
echo "built $out/x4shardnet_64.dll ($(stat -c %s "$out/x4shardnet_64.dll") bytes, sha256 $(sha256sum "$out/x4shardnet_64.dll" | cut -c1-64))"
echo "compiler: $(x86_64-w64-mingw32-gcc --version | head -1)"
echo "imports:"
x86_64-w64-mingw32-objdump -p "$out/x4shardnet_64.dll" | grep "DLL Name"
x86_64-w64-mingw32-objdump -p "$out/x4shardnet_64.dll" | grep -A3 "\[Ordinal/Name Pointer\]" | tail -1

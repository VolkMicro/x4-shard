"""Build the archives for players (Nexus Mods, Vortex, by hand):
  dist/X4Shard-<version>.zip         the x4shard folder at the root (content.xml inside, README.txt next to it):
                                     unpacked into <X4>/extensions/ or installed by Vortex as it is
  dist/X4Shard-server-<version>.zip  the shard server and its README, for those who host one

usage: python -I tools/make_dist.py
Refuses to pack a test client config (plain account, autopick, a home network address).
"""
import os
import re
import sys
import zipfile
from xml.etree import ElementTree

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXT = os.path.join(ROOT, "extension", "x4shard")
SERVER_FILES = ("shard_server.py", "p256.py", "tlscert.py")


def readme(name, label):
    with open(os.path.join(ROOT, "package", name), encoding="utf-8") as f:
        return "﻿" + f.read().replace("{version}", label).replace("\n", "\r\n")   # Notepad-friendly


def show(path):
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            print("%8d  %s" % (info.file_size, info.filename))
    print("%s: %d bytes" % (path, os.path.getsize(path)))


def main():
    version = int(ElementTree.parse(os.path.join(EXT, "content.xml")).getroot().get("version"))
    label = "%d.%02d" % (version // 100, version % 100)
    with open(os.path.join(EXT, "ui", "x4shard_config.lua"), encoding="utf-8") as f:
        config = "\n".join(line for line in f if not line.lstrip().startswith("--"))
    if re.search(r"\b(account|autopick)\s*=", config) or re.search(r'"(10|127|192\.168)\.', config):
        sys.exit("ui/x4shard_config.lua is a test config:\n" + config)
    os.makedirs(os.path.join(ROOT, "dist"), exist_ok=True)

    mod = os.path.join(ROOT, "dist", "X4Shard-%s.zip" % label)
    with zipfile.ZipFile(mod, "w", zipfile.ZIP_DEFLATED) as z:
        for base, dirs, files in os.walk(EXT):
            dirs.sort()
            for name in sorted(files):
                path = os.path.join(base, name)
                z.write(path, "x4shard/" + os.path.relpath(path, EXT).replace(os.sep, "/"))
        z.writestr("x4shard/README.txt", readme("README.txt", label))
    show(mod)

    server = os.path.join(ROOT, "dist", "X4Shard-server-%s.zip" % label)
    with zipfile.ZipFile(server, "w", zipfile.ZIP_DEFLATED) as z:
        for name in SERVER_FILES:
            z.write(os.path.join(ROOT, "server", name), "x4shard-server/" + name)
        z.writestr("x4shard-server/README.txt", readme("README-server.txt", label))
    show(server)


if __name__ == "__main__":
    main()

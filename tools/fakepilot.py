"""Synthetic second player for the X4 Shard server: circles the first real player it sees.

It connects like a client, enters the given sector, learns the other player's pose from MOVE lines and sends
its own POS at 20 Hz: radius 400 m around that player, 80 m/s, yaw along the circle (degrees, as X4 reports).
Until the other player shows up it holds a point near the clean-universe start (Second Contact II Flashpoint).

usage: python3 fakepilot.py [--host 127.0.0.1] [--port 47110] [--name Bot] [--sector cluster_13_sector001_macro]
                            [--seconds 900]
"""
import argparse
import asyncio
import math
import ssl
import time

RADIUS = 400.0
SPEED = 80.0
RATE = 20.0
WAIT_POINT = (0.0, 0.0, -6500.0)   # near the clean-universe start in Second Contact II Flashpoint


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=47110)
    ap.add_argument("--name", default="Bot")
    ap.add_argument("--sector", default="cluster_13_sector001_macro")
    ap.add_argument("--seconds", type=float, default=900.0)
    ap.add_argument("--radius", type=float, default=RADIUS)
    ap.add_argument("--ahead", type=float, default=0.0,
                    help="circle a point this far along +z from the other player (the clean start faces +z)")
    args = ap.parse_args()

    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)   # a test bot on the shard's own machine: no fingerprint check
    tls.check_hostname, tls.verify_mode = False, ssl.CERT_NONE
    reader, writer = await asyncio.open_connection(args.host, args.port, ssl=tls)
    writer.write(("HELLO|%s|1\n" % args.name).encode())
    state = {"target": None, "target_eid": None, "moves": 0}

    async def receive():
        while True:
            raw = await reader.readline()
            if not raw:
                print("server closed")
                return
            f = raw.decode("utf-8", "replace").rstrip("\n").split("|")
            if f[0] == "MOVE":
                if state["target_eid"] in (None, f[1]):
                    state["target_eid"] = f[1]
                    state["target"] = tuple(float(v) for v in f[3:9])
                    state["moves"] += 1
            elif f[0] in ("WELCOME", "SPAWN", "DESPAWN", "SAY"):
                print(" ".join(f), flush=True)
                if f[0] == "DESPAWN" and f[1] == state["target_eid"]:
                    state["target"], state["target_eid"] = None, None

    task = asyncio.create_task(receive())
    start = time.monotonic()
    next_report = start + 5
    sent = 0
    while time.monotonic() - start < args.seconds and not task.done():
        t = time.monotonic() - start
        target = state["target"]
        cx, cy, cz = target[:3] if target else WAIT_POINT
        cz += args.ahead
        theta = SPEED / args.radius * t
        x = cx + args.radius * math.sin(theta)
        z = cz + args.radius * math.cos(theta)
        yaw = math.degrees(theta) + 90.0
        yaw = (yaw + 180.0) % 360.0 - 180.0
        writer.write(("POS|%s|%.2f|%.2f|%.2f|%.2f|0|0\n" % (args.sector, x, cy, z, yaw)).encode())
        await writer.drain()
        sent += 1
        if time.monotonic() >= next_report:
            tgt = "none" if not target else "%s at %.0f %.0f %.0f yaw %.1f" % (
                state["target_eid"], target[0], target[1], target[2], target[3])
            print("t=%.0fs sent=%d moves_in=%d target=%s me=%.0f %.0f %.0f yaw %.1f" % (
                t, sent, state["moves"], tgt, x, cy, z, yaw), flush=True)
            next_report += 5
        await asyncio.sleep(1.0 / RATE)
    writer.write(b"BYE\n")
    await writer.drain()
    writer.close()


if __name__ == "__main__":
    asyncio.run(main())

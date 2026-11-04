"""ECDSA P-256 with SHA-256 in plain Python: checks the players' login signatures, which the client makes with
Windows BCrypt (native/x4shardnet.c), so a shard needs nothing beyond the standard library. keygen() and sign()
are for tests and tools.

Keys and signatures are hex, big-endian as BCrypt writes them: public key X||Y, signature r||s, 64 bytes each.
"""
import hashlib
import secrets

P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = P - 3
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


def _add(p, q):
    """Affine point addition; None is the point at infinity."""
    if p is None:
        return q
    if q is None:
        return p
    (x1, y1), (x2, y2) = p, q
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def _mul(k, point):
    result = None
    while k:
        if k & 1:
            result = _add(result, point)
        point = _add(point, point)
        k >>= 1
    return result


def _hash(message):
    return int.from_bytes(hashlib.sha256(message).digest(), "big")


def parse_public(hex_key):
    """(x, y) of a public key given as hex, or None when it is not a point of the curve."""
    try:
        raw = bytes.fromhex(hex_key)
    except (TypeError, ValueError):
        return None
    if len(raw) != 64:
        return None
    x, y = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    if x >= P or y >= P or (y * y - (x * x * x + A * x + B)) % P:
        return None
    return x, y


def verify(hex_key, message, hex_sig):
    """Is hex_sig an ECDSA signature of message (bytes) by the key hex_key?"""
    q = parse_public(hex_key)
    try:
        raw = bytes.fromhex(hex_sig)
    except (TypeError, ValueError):
        return False
    if q is None or len(raw) != 64:
        return False
    r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    if not (0 < r < N and 0 < s < N):
        return False
    w = pow(s, -1, N)
    point = _add(_mul(_hash(message) * w % N, G), _mul(r * w % N, q))
    return point is not None and point[0] % N == r


def keygen():
    """(private scalar, public key hex)"""
    d = secrets.randbelow(N - 1) + 1
    x, y = _mul(d, G)
    return d, "%064x%064x" % (x, y)


def sign(d, message):
    e = _hash(message)
    while True:
        k = secrets.randbelow(N - 1) + 1
        r = _mul(k, G)[0] % N
        s = pow(k, -1, N) * (e + r * d) % N
        if r and s:
            return "%064x%064x" % (r, s)

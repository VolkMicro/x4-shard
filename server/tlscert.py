"""The shard's own TLS certificate, made once in plain Python: a self-signed ECDSA P-256 certificate, signed with
p256.py, so a shard needs nothing beyond the standard library (Python's ssl loads it; nothing here talks TLS).

Players do not trust it through a certificate authority: the game pins its SHA-256 fingerprint. The directory's
fingerprint comes with the mod, a listed shard's with the directory's list (the directory checks it when the shard
registers), a private shard's with its invite link, x4shard://host:port/code#fingerprint; a shard joined by a bare
address is remembered by the fingerprint it showed the first time.

usage: python3 tlscert.py accounts.json   (prints the fingerprint, making the certificate first if needed)
"""
import base64
import datetime
import hashlib
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p256  # noqa: E402


def _len(n):
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag, body):
    return bytes([tag]) + _len(len(body)) + body


def _seq(*items):
    return _tlv(0x30, b"".join(items))


def _int(value):
    return _tlv(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def _oid(dotted):
    parts = [int(p) for p in dotted.split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7F))
            part >>= 7
        body += bytes(reversed(chunk))
    return _tlv(0x06, body)


def _bits(raw):
    return _tlv(0x03, b"\x00" + raw)


EC_PUBLIC_KEY = _oid("1.2.840.10045.2.1")
PRIME256V1 = _oid("1.2.840.10045.3.1.7")
ECDSA_SHA256 = _seq(_oid("1.2.840.10045.4.3.2"))


def _name(common_name):
    return _seq(_tlv(0x31, _seq(_oid("2.5.4.3"), _tlv(0x0C, common_name.encode("utf-8")))))


def _pem(kind, der):
    text = base64.encodebytes(der).decode().replace("\n", "")
    lines = [text[i:i + 64] for i in range(0, len(text), 64)]
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (kind, "\n".join(lines), kind)


def _unpem(text):
    body = "".join(line for line in text.splitlines() if line and not line.startswith("-----"))
    return base64.b64decode(body)


def make(common_name="X4 Shard"):
    """(certificate DER, private key DER in SEC1 form) for a new key"""
    d, public = p256.keygen()
    point = b"\x04" + bytes.fromhex(public)
    start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    validity = _seq(_tlv(0x17, start.strftime("%y%m%d%H%M%SZ").encode()),   # UTCTime
                    _tlv(0x18, b"20991231235959Z"))                         # GeneralizedTime
    tbs = _seq(_tlv(0xA0, _int(2)),                    # version 3
               _int(secrets.randbits(63) | 1),         # serial number
               ECDSA_SHA256, _name(common_name), validity, _name(common_name),
               _seq(_seq(EC_PUBLIC_KEY, PRIME256V1), _bits(point)))
    signature = bytes.fromhex(p256.sign(d, tbs))
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    cert = _seq(tbs, ECDSA_SHA256, _bits(_seq(_int(r), _int(s))))
    key = _seq(_int(1), _tlv(0x04, d.to_bytes(32, "big")), _tlv(0xA0, PRIME256V1), _tlv(0xA1, _bits(point)))
    return cert, key


def fingerprint(cert_der):
    return hashlib.sha256(cert_der).hexdigest()


def load_or_make(base, common_name="X4 Shard"):
    """The shard's certificate next to its accounts file (base.cert.pem, base.key.pem), made the first time:
    (certificate path, key path, fingerprint). Keep both files: a new certificate makes every player who knew the
    shard see another fingerprint, and the game refuses it."""
    cert_path, key_path = base + ".cert.pem", base + ".key.pem"
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        cert, key = make(common_name)
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(_pem("EC PRIVATE KEY", key))
        with open(cert_path, "w", encoding="ascii") as f:
            f.write(_pem("CERTIFICATE", cert))
    with open(cert_path, encoding="ascii") as f:
        return cert_path, key_path, fingerprint(_unpem(f.read()))


if __name__ == "__main__":
    print(load_or_make(sys.argv[1] if len(sys.argv) > 1 else "accounts.json")[2])

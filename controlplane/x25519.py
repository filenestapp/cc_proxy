"""X25519 (RFC 7748) in pure Python, for generating Reality key pairs without extra dependencies.

Speed is irrelevant here (one key pair per host), so this is the textbook Montgomery ladder.
Keys use sing-box's encoding: base64url without padding of the raw 32 bytes.
"""
import base64
import secrets

P = 2 ** 255 - 19
A24 = 121665


def _decode_scalar(k):
    b = bytearray(k)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(b, "little")


def _decode_u(u):
    b = bytearray(u)
    b[31] &= 127
    return int.from_bytes(b, "little") % P


def x25519(k, u):
    """Scalar multiplication on Curve25519: 32-byte scalar k, 32-byte u-coordinate u -> 32 bytes."""
    k, x1 = _decode_scalar(k), _decode_u(u)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + A24 * e) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


BASE = (9).to_bytes(32, "little")


def _b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def public_key(private_b64):
    return _b64(x25519(_unb64(private_b64), BASE))


def reality_keypair():
    """(private_key, public_key) in the format of `sing-box generate reality-keypair`."""
    priv = bytearray(secrets.token_bytes(32))
    priv[0] &= 248
    priv[31] &= 127
    priv[31] |= 64
    private = _b64(bytes(priv))
    return private, public_key(private)

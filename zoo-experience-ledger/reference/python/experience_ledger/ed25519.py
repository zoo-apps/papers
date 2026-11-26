# SPDX-License-Identifier: Apache-2.0
"""Pure-Python RFC 8032 Ed25519 signing and verification (zero external dependencies)."""

from __future__ import annotations

import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
K = (2 * D) % P
I = pow(2, (P - 1) // 4, P)

# Extended twisted Edwards point: (X, Y, Z, T) where x=X/Z, y=Y/Z, x*y=T/Z
IDENTITY = (0, 1, 1, 0)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= P:
        return None
    x2 = ((y * y - 1) * pow(D * y * y + 1, P - 2, P)) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = (x * I) % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


def _point_add(p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % P
    b = ((y1 + x1) * (y2 + x2)) % P
    c = (t1 * K * t2) % P
    d = (z1 * 2 * z2) % P
    e = (b - a) % P
    f = (d - c) % P
    g = (d + c) % P
    h = (b + a) % P
    return ((e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P)


def _point_mul(s: int, pt: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    q = IDENTITY
    while s > 0:
        if s & 1:
            q = _point_add(q, pt)
        pt = _point_add(pt, pt)
        s >>= 1
    return q


def _point_equal(p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]) -> bool:
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def _point_compress(pt: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = pt
    zinv = pow(z, P - 2, P)
    ax = (x * zinv) % P
    ay = (y * zinv) % P
    enc = ay | ((ax & 1) << 255)
    return enc.to_bytes(32, "little")


def _point_decompress(b: bytes) -> tuple[int, int, int, int] | None:
    if len(b) != 32:
        return None
    val = int.from_bytes(b, "little")
    sign = (val >> 255) & 1
    y = val & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % P)


_BY = (4 * pow(5, P - 2, P)) % P
_BX = _recover_x(_BY, 0)
assert _BX is not None
BASE = (_BX, _BY, 1, (_BX * _BY) % P)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _secret_expand(seed: bytes) -> tuple[int, bytes]:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed25519_public_key_from_seed(seed: bytes) -> bytes:
    """Derive 32-byte RFC 8032 Ed25519 public key from 32-byte seed."""
    a, _ = _secret_expand(seed)
    return _point_compress(_point_mul(a, BASE))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    """Sign message using 32-byte Ed25519 seed per RFC 8032."""
    a, prefix = _secret_expand(seed)
    pub = _point_compress(_point_mul(a, BASE))
    r = int.from_bytes(_sha512(prefix + message), "little") % L
    R = _point_compress(_point_mul(r, BASE))
    k = int.from_bytes(_sha512(R + pub + message), "little") % L
    s = (r + k * a) % L
    return R + s.to_bytes(32, "little")


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify 64-byte RFC 8032 Ed25519 signature against 32-byte public key."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    A = _point_decompress(public_key)
    R = _point_decompress(signature[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = int.from_bytes(_sha512(signature[:32] + public_key + message), "little") % L
    lhs = _point_mul(s, BASE)
    rhs = _point_add(R, _point_mul(k, A))
    return _point_equal(lhs, rhs)

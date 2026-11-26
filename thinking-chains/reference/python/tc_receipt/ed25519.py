# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation and Contributors

"""Pure-Python zero-dependency RFC 8032 PureEdDSA Ed25519 implementation.

Implements Ed25519 signing and verification using extended twisted Edwards
coordinates over GF(2^255 - 19) with Python standard-library hashlib (SHA-512).
"""

from __future__ import annotations

import hashlib

P = (1 << 255) - 19
L = (1 << 252) + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, -1, P)) % P
I = pow(2, (P - 1) // 4, P)

# Base point B = (Bx, By) in extended coordinates (X, Y, Z, T)
_BY = (4 * pow(5, -1, P)) % P


def _recover_x(y: int, sign: int) -> int | None:
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, -1, P) % P
    if x2 == 0:
        if sign:
            return None
        return 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = (x * I) % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_BX = _recover_x(_BY, 0)
assert _BX is not None
BASE_POINT = (_BX, _BY, 1, (_BX * _BY) % P)
IDENTITY_POINT = (0, 1, 1, 0)


def _point_add(
    p1: tuple[int, int, int, int],
    p2: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % P
    b = ((y1 + x1) * (y2 + x2)) % P
    c = (2 * D * t1 * t2) % P
    d = (2 * z1 * z2) % P
    e = (b - a) % P
    f = (d - c) % P
    g = (d + c) % P
    h = (b + a) % P
    return ((e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P)


def _point_double(p: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, _ = p
    a = (x1 * x1) % P
    b = (y1 * y1) % P
    c = (2 * z1 * z1) % P
    h = (a + b) % P
    e = (h - ((x1 + y1) * (x1 + y1)) % P) % P
    g = (a - b) % P
    f = (c + g) % P
    return ((e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P)


def _scalar_mult(s: int, pt: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    q = IDENTITY_POINT
    addend = pt
    while s > 0:
        if s & 1:
            q = _point_add(q, addend)
        addend = _point_double(addend)
        s >>= 1
    return q


def _point_equal(
    p1: tuple[int, int, int, int],
    p2: tuple[int, int, int, int],
) -> bool:
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def _point_compress(pt: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = pt
    zi = pow(z, -1, P)
    x = (x * zi) % P
    y = (y * zi) % P
    encoded = y | ((x & 1) << 255)
    return encoded.to_bytes(32, "little")


def _point_decompress(buf: bytes) -> tuple[int, int, int, int] | None:
    if len(buf) != 32:
        return None
    val = int.from_bytes(buf, "little")
    sign = (val >> 255) & 1
    y = val & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % P)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _clamp_scalar(digest_low32: bytes) -> int:
    arr = bytearray(digest_low32)
    arr[0] &= 248
    arr[31] &= 127
    arr[31] |= 64
    return int.from_bytes(arr, "little")


def ed25519_public_key_from_seed(seed: bytes) -> bytes:
    """Derive 32-byte Ed25519 public key from a 32-byte private seed (RFC 8032 §5.1.5)."""
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    h = _sha512(seed)
    a = _clamp_scalar(h[:32])
    return _point_compress(_scalar_mult(a, BASE_POINT))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    """Produce a 64-byte RFC 8032 PureEdDSA Ed25519 signature."""
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    h = _sha512(seed)
    a = _clamp_scalar(h[:32])
    prefix = h[32:]
    pub = _point_compress(_scalar_mult(a, BASE_POINT))

    r = int.from_bytes(_sha512(prefix + message), "little") % L
    r_enc = _point_compress(_scalar_mult(r, BASE_POINT))

    k = int.from_bytes(_sha512(r_enc + pub + message), "little") % L
    s = (r + k * a) % L
    return r_enc + s.to_bytes(32, "little")


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an RFC 8032 PureEdDSA Ed25519 signature (strict canonical S < L)."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a_pt = _point_decompress(public_key)
    if a_pt is None:
        return False
    r_enc = signature[:32]
    r_pt = _point_decompress(r_enc)
    if r_pt is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = int.from_bytes(_sha512(r_enc + public_key + message), "little") % L
    lhs = _scalar_mult(s, BASE_POINT)
    rhs = _point_add(r_pt, _scalar_mult(k, a_pt))
    return _point_equal(lhs, rhs)

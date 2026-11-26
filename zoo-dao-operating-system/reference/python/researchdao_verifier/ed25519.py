# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation & Open ResearchDAO Contributors.

"""Pure Python 3.12 stdlib RFC 8032 Ed25519 implementation (zero external dependencies).

Uses extended twisted Edwards coordinates (X, Y, Z, T) where x = X/Z, y = Y/Z, xy = T/Z
over F_p with p = 2^255 - 19, strictly enforcing canonical encoding and 0 <= S < L.
"""

from __future__ import annotations

import hashlib
from typing import Optional, Tuple

P = (1 << 255) - 19
L = (1 << 252) + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
K = (2 * D) % P
I = pow(2, (P - 1) // 4, P)

Point = Tuple[int, int, int, int]
IDENTITY: Point = (0, 1, 1, 0)


def _recover_x(y: int, sign: int) -> Optional[int]:
    if y >= P:
        return None
    y2 = (y * y) % P
    u = (y2 - 1) % P
    v = (D * y2 + 1) % P
    x2 = (u * pow(v, P - 2, P)) % P
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


def _make_base_point() -> Point:
    by = (4 * pow(5, P - 2, P)) % P
    bx = _recover_x(by, 0)
    assert bx is not None
    return (bx, by, 1, (bx * by) % P)


BASE_POINT: Point = _make_base_point()


def _point_add(p1: Point, p2: Point) -> Point:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % P
    b = ((y1 + x1) * (y2 + x2)) % P
    c = (t1 * K * t2) % P
    d = (2 * z1 * z2) % P
    e = (b - a) % P
    f = (d - c) % P
    g = (d + c) % P
    h = (b + a) % P
    return ((e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P)


def _point_double(pt: Point) -> Point:
    x1, y1, z1, _ = pt
    a = (x1 * x1) % P
    b = (y1 * y1) % P
    c = (2 * z1 * z1) % P
    h = (a + b) % P
    e = (h - ((x1 + y1) * (x1 + y1))) % P
    g = (a - b) % P
    f = (c + g) % P
    return ((e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P)


def _scalar_mult(s: int, pt: Point) -> Point:
    q = IDENTITY
    addend = pt
    while s > 0:
        if s & 1:
            q = _point_add(q, addend)
        addend = _point_double(addend)
        s >>= 1
    return q


def _point_equal(p1: Point, p2: Point) -> bool:
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def _encode_point(pt: Point) -> bytes:
    x, y, z, _ = pt
    z_inv = pow(z, P - 2, P)
    ax = (x * z_inv) % P
    ay = (y * z_inv) % P
    val = ay | ((ax & 1) << 255)
    return val.to_bytes(32, "little")


def _decode_point(b: bytes) -> Optional[Point]:
    if len(b) != 32:
        return None
    val = int.from_bytes(b, "little")
    y = val & ((1 << 255) - 1)
    sign = val >> 255
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % P)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _clamp_scalar(h_low: bytes) -> int:
    a = bytearray(h_low)
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return int.from_bytes(a, "little")


def public_key_from_seed(seed: bytes) -> bytes:
    """Derive 32-byte RFC 8032 Ed25519 public key from a 32-byte private seed."""
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    h = _sha512(seed)
    a = _clamp_scalar(h[:32])
    return _encode_point(_scalar_mult(a, BASE_POINT))


def sign(seed: bytes, message: bytes) -> bytes:
    """Produce a 64-byte RFC 8032 PureEd25519 signature."""
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    h = _sha512(seed)
    a = _clamp_scalar(h[:32])
    prefix = h[32:]
    pub = _encode_point(_scalar_mult(a, BASE_POINT))

    r = int.from_bytes(_sha512(prefix + message), "little") % L
    r_bytes = _encode_point(_scalar_mult(r, BASE_POINT))
    k = int.from_bytes(_sha512(r_bytes + pub + message), "little") % L
    s = (r + k * a) % L
    return r_bytes + s.to_bytes(32, "little")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a 64-byte RFC 8032 PureEd25519 signature against a 32-byte public key."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a_pt = _decode_point(public_key)
    if a_pt is None:
        return False
    r_bytes = signature[:32]
    r_pt = _decode_point(r_bytes)
    if r_pt is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = int.from_bytes(_sha512(r_bytes + public_key + message), "little") % L
    lhs = _scalar_mult(s, BASE_POINT)
    rhs = _point_add(r_pt, _scalar_mult(k, a_pt))
    return _point_equal(lhs, rhs)

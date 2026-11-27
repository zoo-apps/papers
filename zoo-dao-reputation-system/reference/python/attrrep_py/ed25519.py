# SPDX-License-Identifier: Apache-2.0
"""Clean-room pure-Python RFC 8032 Ed25519 implementation (stdlib only).

Uses extended twisted Edwards coordinates (X, Y, Z, T) for fast constant-formula
verification compatible with Go crypto/ed25519 and RFC 8032 Section 5.1.7.
"""

from __future__ import annotations

import hashlib
from typing import Optional, Tuple

P = (1 << 255) - 19
L = (1 << 252) + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
K = (2 * D) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

Point = Tuple[int, int, int, int]  # Extended coordinates (X, Y, Z, T)
IDENTITY: Point = (0, 1, 1, 0)


def _recover_x(y: int, sign: int) -> Optional[int]:
    if y >= P:
        return None
    y2 = (y * y) % P
    u = (y2 - 1) % P
    v = (D * y2 + 1) % P
    # Compute x = sqrt(u / v) via (u * v^3) * (u * v^7)^((p-5)/8) mod p
    v3 = (v * v * v) % P
    v7 = (v3 * v3 * v) % P
    x = (u * v3 * pow((u * v7) % P, (P - 5) // 8, P)) % P
    vx2 = (v * x * x) % P
    if vx2 == u:
        pass
    elif vx2 == (-u) % P:
        x = (x * SQRT_M1) % P
    else:
        return None
    if x == 0 and sign == 1:
        return None
    if (x & 1) != sign:
        x = (P - x) % P
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
    x3 = (e * f) % P
    y3 = (g * h) % P
    t3 = (e * h) % P
    z3 = (f * g) % P
    return (x3, y3, z3, t3)


def _point_double(p: Point) -> Point:
    x1, y1, z1, _ = p
    a = (x1 * x1) % P
    b = (y1 * y1) % P
    c = (2 * z1 * z1) % P
    h = (a + b) % P
    e = (h - ((x1 + y1) * (x1 + y1))) % P
    g = (a - b) % P
    f = (c + g) % P
    x3 = (e * f) % P
    y3 = (g * h) % P
    t3 = (e * h) % P
    z3 = (f * g) % P
    return (x3, y3, z3, t3)


def _point_neg(p: Point) -> Point:
    x, y, z, t = p
    return ((-x) % P, y, z, (-t) % P)


def _scalar_mult(s: int, pt: Point) -> Point:
    acc = IDENTITY
    addend = pt
    while s > 0:
        if s & 1:
            acc = _point_add(acc, addend)
        addend = _point_double(addend)
        s >>= 1
    return acc


def _point_encode(pt: Point) -> bytes:
    x, y, z, _ = pt
    zi = pow(z, P - 2, P)
    px = (x * zi) % P
    py = (y * zi) % P
    enc = py | ((px & 1) << 255)
    return enc.to_bytes(32, "little")


def _point_decode(data: bytes) -> Optional[Point]:
    if len(data) != 32:
        return None
    val = int.from_bytes(data, "little")
    sign = (val >> 255) & 1
    y = val & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % P)


def _point_is_identity(pt: Point) -> bool:
    x, y, z, _ = pt
    return (x % P) == 0 and ((y - z) % P) == 0


def public_key_from_seed(seed32: bytes) -> bytes:
    """Derives the 32-byte RFC 8032 Ed25519 public key from a 32-byte seed."""
    if len(seed32) != 32:
        raise ValueError("seed must be 32 bytes")
    h = hashlib.sha512(seed32).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _point_encode(_scalar_mult(a, BASE_POINT))


def sign(seed32: bytes, message: bytes) -> bytes:
    """Computes a 64-byte RFC 8032 Ed25519 signature over message."""
    if len(seed32) != 32:
        raise ValueError("seed must be 32 bytes")
    h = hashlib.sha512(seed32).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    prefix = h[32:]
    pub = _point_encode(_scalar_mult(a, BASE_POINT))

    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    r_bytes = _point_encode(_scalar_mult(r, BASE_POINT))
    k = int.from_bytes(hashlib.sha512(r_bytes + pub + message).digest(), "little") % L
    s = (r + k * a) % L
    return r_bytes + s.to_bytes(32, "little")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verifies an RFC 8032 Ed25519 signature (returns True iff valid)."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    pt_a = _point_decode(public_key)
    if pt_a is None:
        return False
    r_bytes = signature[:32]
    pt_r = _point_decode(r_bytes)
    if pt_r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False

    h = int.from_bytes(hashlib.sha512(r_bytes + public_key + message).digest(), "little") % L
    # Verify [8]([s]B - R - [h]A) == IDENTITY (cofactor-cleared RFC 8032 equation).
    sb = _scalar_mult(s, BASE_POINT)
    ha = _scalar_mult(h, pt_a)
    diff = _point_add(sb, _point_neg(_point_add(pt_r, ha)))
    check = _point_double(_point_double(_point_double(diff)))
    return _point_is_identity(check)

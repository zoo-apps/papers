# Copyright 2026 Zoo Labs Foundation & Hanzo Industries.
# SPDX-License-Identifier: Apache-2.0
"""Pure-Python RFC 8032 Ed25519 signature verifier (zero external dependencies).

Implements Edwards25519 curve arithmetic in extended homogeneous coordinates
(X, Y, Z, T) where x = X/Z, y = Y/Z, x*y = T/Z, following RFC 8032 Section 5.1.7.
"""

from __future__ import annotations

import hashlib
from typing import Optional, Tuple

# Field prime p = 2^255 - 19
_P = (1 << 255) - 19
# Subgroup order L = 2^252 + 27742317777372353535851937790883648493
_L = (1 << 252) + 27742317777372353535851937790883648493
# Curve constant d = -121665 / 121666 (mod p)
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
# sqrt(-1) mod p
_I = pow(2, (_P - 1) // 4, _P)

Point = Tuple[int, int, int, int]


def _xrecover(y: int) -> Optional[int]:
    """Recover x >= 0 from y on -x^2 + y^2 = 1 + d*x^2*y^2 (mod p)."""
    y2 = (y * y) % _P
    u = (y2 - 1) % _P
    v = (_D * y2 + 1) % _P
    v3 = pow(v, 3, _P)
    v7 = (v3 * v3 * v) % _P
    x = (u * v3 * pow(u * v7, (_P - 5) // 8, _P)) % _P
    vx2 = (v * x * x) % _P
    if vx2 == u:
        return x
    if vx2 == (-u) % _P:
        return (x * _I) % _P
    return None


def _point_add(p1: Point, p2: Point) -> Point:
    """RFC 8032 Section 5.1.4 complete extended twisted Edwards point addition."""
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (t1 * 2 * _D * t2) % _P
    d = (z1 * 2 * z2) % _P
    e = (b - a) % _P
    f = (d - c) % _P
    g = (d + c) % _P
    h = (b + a) % _P
    x3 = (e * f) % _P
    y3 = (g * h) % _P
    t3 = (e * h) % _P
    z3 = (f * g) % _P
    return (x3, y3, z3, t3)


def _point_mul(scalar: int, pt: Point) -> Point:
    """Double-and-add scalar multiplication on Edwards25519."""
    acc: Point = (0, 1, 1, 0)  # Identity element (0, 1)
    addend = pt
    s = scalar
    while s > 0:
        if s & 1:
            acc = _point_add(acc, addend)
        addend = _point_add(addend, addend)
        s >>= 1
    return acc


def _point_equal(p1: Point, p2: Point) -> bool:
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _decode_point(enc: bytes) -> Optional[Point]:
    """Decode a 32-byte RFC 8032 point with strict canonical range checks."""
    if len(enc) != 32:
        return None
    y_int = int.from_bytes(enc, "little")
    sign = (y_int >> 255) & 1
    y = y_int & ((1 << 255) - 1)
    if y >= _P:
        return None
    x = _xrecover(y)
    if x is None:
        return None
    if x == 0 and sign == 1:
        return None
    if (x & 1) != sign:
        x = _P - x
    return (x, y, 1, (x * y) % _P)


# Base point B (RFC 8032 Section 5.1)
_BY = (4 * pow(5, _P - 2, _P)) % _P
_BX = _xrecover(_BY)
assert _BX is not None
if _BX & 1:
    _BX = _P - _BX
_BASE: Point = (_BX, _BY, 1, (_BX * _BY) % _P)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an RFC 8032 Ed25519 signature.

    Returns True iff public_key (32 bytes) and signature (64 bytes) are valid
    and satisfy [S]B == R + [k]A with canonical 0 <= S < L.
    """
    if len(public_key) != 32 or len(signature) != 64:
        return False

    a_pt = _decode_point(public_key)
    if a_pt is None:
        return False

    r_bytes = signature[:32]
    s_bytes = signature[32:]
    r_pt = _decode_point(r_bytes)
    if r_pt is None:
        return False

    s = int.from_bytes(s_bytes, "little")
    if s >= _L:
        return False

    h = hashlib.sha512(r_bytes + public_key + message).digest()
    k = int.from_bytes(h, "little") % _L

    lhs = _point_mul(s, _BASE)
    rhs = _point_add(r_pt, _point_mul(k, a_pt))
    return _point_equal(lhs, rhs)

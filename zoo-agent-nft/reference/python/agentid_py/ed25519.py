# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.

"""Clean-room pure-Python RFC 8032 Ed25519 signature verifier (stdlib only)."""

import hashlib
from typing import Optional, Tuple

# Curve25519 / Edwards25519 field and group parameters (RFC 8032 Section 5.1).
P = (1 << 255) - 19
L = (1 << 252) + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

_BY = (4 * pow(5, P - 2, P)) % P
_BX_SQ = ((_BY * _BY - 1) * pow((D * _BY * _BY + 1) % P, P - 2, P)) % P
_BX = pow(_BX_SQ, (P + 3) // 8, P)
if (_BX * _BX - _BX_SQ) % P != 0:
    _BX = (_BX * SQRT_M1) % P
if _BX % 2 != 0:
    _BX = P - _BX

Point = Tuple[int, int, int, int]
BASE_POINT: Point = (_BX, _BY, 1, (_BX * _BY) % P)
IDENTITY: Point = (0, 1, 1, 0)


def _point_add(p1: Point, p2: Point) -> Point:
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


def _point_double(p: Point) -> Point:
    return _point_add(p, p)


def _scalar_mul(k: int, p: Point) -> Point:
    acc = IDENTITY
    cur = p
    while k > 0:
        if k & 1:
            acc = _point_add(acc, cur)
        cur = _point_double(cur)
        k >>= 1
    return acc


def _decode_point(enc: bytes) -> Optional[Point]:
    if len(enc) != 32:
        return None
    y = int.from_bytes(enc, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    if y >= P:
        return None
    y2 = (y * y) % P
    u = (y2 - 1) % P
    v = (D * y2 + 1) % P
    v3 = (v * v * v) % P
    v7 = (v3 * v3 * v) % P
    x = (u * v3 * pow((u * v7) % P, (P - 5) // 8, P)) % P
    check = (v * x * x) % P
    if check == u:
        pass
    elif check == (-u) % P:
        x = (x * SQRT_M1) % P
    else:
        return None
    if x == 0 and sign == 1:
        return None
    if (x & 1) != sign:
        x = P - x
    return (x, y, 1, (x * y) % P)


def _point_equal(p1: Point, p2: Point) -> bool:
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an RFC 8032 Ed25519 signature (strict S < L and canonical encoding)."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a_point = _decode_point(public_key)
    if a_point is None:
        return False
    r_bytes = signature[:32]
    r_point = _decode_point(r_bytes)
    if r_point is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    h = hashlib.sha512(r_bytes + public_key + message).digest()
    k = int.from_bytes(h, "little") % L
    lhs = _scalar_mul(s, BASE_POINT)
    rhs = _point_add(r_point, _scalar_mul(k, a_point))
    return _point_equal(lhs, rhs)

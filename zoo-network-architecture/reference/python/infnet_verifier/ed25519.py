# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Pure-Python RFC 8032 Ed25519 signature verification (stdlib only, 0 external packages)."""

from __future__ import annotations

import hashlib
from typing import Optional, Tuple

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)

_BY = (4 * pow(5, _P - 2, _P)) % _P


def _recover_x(y: int, sign: int) -> Optional[int]:
    if y >= _P:
        return None
    x2 = ((y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)) % _P
    if x2 == 0:
        if sign != 0:
            return None
        return 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = (x * _I) % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_BX = _recover_x(_BY, 0)
assert _BX is not None
_B = (_BX, _BY, 1, (_BX * _BY) % _P)
_ID = (0, 1, 1, 0)

Point = Tuple[int, int, int, int]


def _point_add(p1: Point, p2: Point) -> Point:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (2 * _D * t1 * t2) % _P
    d = (2 * z1 * z2) % _P
    e = (b - a) % _P
    f = (d - c) % _P
    g = (d + c) % _P
    h = (b + a) % _P
    return ((e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P)


def _point_mul(s: int, p: Point) -> Point:
    q = _ID
    addend = p
    while s > 0:
        if s & 1:
            q = _point_add(q, addend)
        addend = _point_add(addend, addend)
        s >>= 1
    return q


def _point_equal(p1: Point, p2: Point) -> bool:
    if (p1[0] * p2[2] - p2[0] * p1[2]) % _P != 0:
        return False
    if (p1[1] * p2[2] - p2[1] * p1[2]) % _P != 0:
        return False
    return True


def _decode_point(enc: bytes) -> Optional[Point]:
    if len(enc) != 32:
        return None
    y_int = int.from_bytes(enc, "little")
    sign = (y_int >> 255) & 1
    y = y_int & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % _P)


def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an RFC 8032 Ed25519 signature over message with public_key."""
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
    if s >= _L:
        return False
    k_digest = hashlib.sha512(r_bytes + public_key + message).digest()
    k = int.from_bytes(k_digest, "little") % _L
    lhs = _point_mul(s, _B)
    rhs = _point_add(r_point, _point_mul(k, a_point))
    return _point_equal(lhs, rhs)

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation
"""Pure-Python RFC 8032 Ed25519 signature verification (zero external dependencies)."""

from __future__ import annotations

import hashlib

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = (x * _I) % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_BY = (4 * pow(5, _P - 2, _P)) % _P
_BX = _recover_x(_BY, 0)
assert _BX is not None
_B = (_BX, _BY, 1, (_BX * _BY) % _P)
_IDENTITY = (0, 1, 1, 0)


def _point_add(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (2 * t1 * t2 * _D) % _P
    d = (2 * z1 * z2) % _P
    e = (b - a) % _P
    f = (d - c) % _P
    g = (d + c) % _P
    h = (b + a) % _P
    return ((e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P)


def _scalar_mult(s: int, p: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    res = _IDENTITY
    addend = p
    while s > 0:
        if s & 1:
            res = _point_add(res, addend)
        addend = _point_add(addend, addend)
        s >>= 1
    return res


def _decode_point(b: bytes) -> tuple[int, int, int, int] | None:
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % _P)


def _points_equal(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return ((x1 * z2 - x2 * z1) % _P == 0) and ((y1 * z2 - y2 * z1) % _P == 0)


def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an RFC 8032 Ed25519 signature over message using public_key."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a_pt = _decode_point(public_key)
    r_pt = _decode_point(signature[:32])
    if a_pt is None or r_pt is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = hashlib.sha512(signature[:32] + public_key + message).digest()
    k = int.from_bytes(h, "little") % _L
    lhs = _scalar_mult(s, _B)
    rhs = _point_add(r_pt, _scalar_mult(k, a_pt))
    return _points_equal(lhs, rhs)

# Copyright 2026 Zoo Labs Foundation / Hanzo Industries.
# Licensed under the Apache License, Version 2.0.
"""Clean-room pure-Python RFC 8032 Ed25519 signature verifier (zero external deps)."""

from __future__ import annotations

import hashlib

# Ed25519 curve parameters (RFC 8032 Section 5.1)
P = (1 << 255) - 19
L = (1 << 252) + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I_CONST = pow(2, (P - 1) // 4, P)

# Base point B in extended homogeneous coordinates (X, Y, Z, T)
_BY = (4 * pow(5, P - 2, P)) % P


def _recover_x(y: int, sign: int) -> int | None:
    if y >= P:
        return None
    y2 = (y * y) % P
    u = (y2 - 1) % P
    v = (D * y2 + 1) % P
    v3 = (v * v * v) % P
    v7 = (v3 * v3 * v) % P
    x = (u * v3 * pow((u * v7) % P, (P - 5) // 8, P)) % P
    if (v * x * x) % P != u:
        if (v * x * x) % P == (-u) % P:
            x = (x * I_CONST) % P
        else:
            return None
    if x == 0 and sign == 1:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_BX = _recover_x(_BY, 0)
assert _BX is not None
BASE_POINT = (_BX, _BY, 1, (_BX * _BY) % P)
IDENTITY = (0, 1, 1, 0)


def _point_add(
    p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]
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
    e = (h - ((x1 + y1) * (x1 + y1))) % P
    g = (a - b) % P
    f = (c + g) % P
    return ((e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P)


def _scalar_mult(
    point: tuple[int, int, int, int], scalar: int
) -> tuple[int, int, int, int]:
    res = IDENTITY
    addend = point
    k = scalar
    while k > 0:
        if k & 1:
            res = _point_add(res, addend)
        addend = _point_double(addend)
        k >>= 1
    return res


def _decode_point(enc: bytes) -> tuple[int, int, int, int] | None:
    if len(enc) != 32:
        return None
    y_int = int.from_bytes(enc, "little")
    sign = (y_int >> 255) & 1
    y = y_int & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % P)


def _point_equal(
    p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]
) -> bool:
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def verify(pubkey: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an RFC 8032 Ed25519 signature (strict S < L, cofactored check)."""
    if len(pubkey) != 32 or len(signature) != 64:
        return False
    a_pt = _decode_point(pubkey)
    if a_pt is None:
        return False
    r_bytes = signature[:32]
    r_pt = _decode_point(r_bytes)
    if r_pt is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False

    h_digest = hashlib.sha512(r_bytes + pubkey + message).digest()
    k = int.from_bytes(h_digest, "little") % L

    # Check [8][S]B == [8](R + [k]A) per RFC 8032 Section 5.1.7
    lhs = _scalar_mult(BASE_POINT, (8 * s) % L)
    rhs = _scalar_mult(_point_add(r_pt, _scalar_mult(a_pt, k)), 8)
    return _point_equal(lhs, rhs)

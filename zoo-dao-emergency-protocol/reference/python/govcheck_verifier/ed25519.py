# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.

"""Pure-Python RFC 8032 Ed25519 signature verification (zero external deps)."""

from __future__ import annotations

import hashlib
from typing import Optional, Tuple

_P = (1 << 255) - 19
_L = (1 << 252) + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _modinv(a: int) -> int:
    return pow(a, _P - 2, _P)


def _recover_x(y: int, sign: int) -> Optional[int]:
    if y >= _P:
        return None
    x2 = (y * y - 1) * _modinv(_D * y * y + 1) % _P
    if x2 == 0:
        if sign:
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


_BY = (4 * _modinv(5)) % _P
_BX = _recover_x(_BY, 0)
assert _BX is not None
_BASE = (_BX, _BY, 1, (_BX * _BY) % _P)
_NEUTRAL = (0, 1, 1, 0)


def _point_add(p: Tuple[int, int, int, int], q: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (2 * _D * t1 * t2) % _P
    d = (2 * z1 * z2) % _P
    e = (b - a) % _P
    f = (d - c) % _P
    g = (d + c) % _P
    h = (b + a) % _P
    return (
        (e * f) % _P,
        (g * h) % _P,
        (f * g) % _P,
        (e * h) % _P,
    )


def _point_mul(s: int, p: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    res = _NEUTRAL
    cur = p
    k = s
    while k > 0:
        if k & 1:
            res = _point_add(res, cur)
        cur = _point_add(cur, cur)
        k >>= 1
    return res


def _point_eq(p: Tuple[int, int, int, int], q: Tuple[int, int, int, int]) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    if (x1 * z2 - x2 * z1) % _P != 0:
        return False
    if (y1 * z2 - y2 * z1) % _P != 0:
        return False
    return True


def _decode_point(enc: bytes) -> Optional[Tuple[int, int, int, int]]:
    if len(enc) != 32:
        return None
    y = int.from_bytes(enc, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % _P)


def verify_ed25519(pubkey_hex: str, message: bytes, signature_hex: str) -> bool:
    """Verify an RFC 8032 Ed25519 signature over message."""
    try:
        pub = bytes.fromhex(pubkey_hex)
        sig = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    if len(pub) != 32 or len(sig) != 64:
        return False
    a_pt = _decode_point(pub)
    if a_pt is None:
        return False
    r_bytes = sig[:32]
    r_pt = _decode_point(r_bytes)
    if r_pt is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(r_bytes + pub + message).digest(), "little") % _L
    lhs = _point_mul(s, _BASE)
    rhs = _point_add(r_pt, _point_mul(k, a_pt))
    return _point_eq(lhs, rhs)

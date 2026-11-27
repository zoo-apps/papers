# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""Pure Python 3.12 stdlib RFC 8032 Ed25519 signature verification (zero external deps)."""

from __future__ import annotations

import hashlib
import re

# Ed25519 curve parameters (RFC 8032 Section 5.1)
_P = (1 << 255) - 19
_L = (1 << 252) + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)  # sqrt(-1) mod p

_BY = (4 * pow(5, _P - 2, _P)) % _P


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    y2 = (y * y) % _P
    u = (y2 - 1) % _P
    v = (_D * y2 + 1) % _P
    x2 = (u * pow(v, _P - 2, _P)) % _P
    if x2 == 0:
        if sign == 1:
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
_IDENTITY = (0, 1, 1, 0)


def _point_add(p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """Extended twisted Edwards point addition (a = -1)."""
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


def _point_double(p1: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """Extended twisted Edwards point doubling (a = -1)."""
    x1, y1, z1, _ = p1
    a = (x1 * x1) % _P
    b = (y1 * y1) % _P
    c = (2 * z1 * z1) % _P
    h = (a + b) % _P
    e = (h - ((x1 + y1) * (x1 + y1))) % _P
    g = (a - b) % _P
    f = (c + g) % _P
    x3 = (e * f) % _P
    y3 = (g * h) % _P
    t3 = (e * h) % _P
    z3 = (f * g) % _P
    return (x3, y3, z3, t3)


def _scalar_mult(s: int, pt: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    acc = _IDENTITY
    addend = pt
    while s > 0:
        if s & 1:
            acc = _point_add(acc, addend)
        addend = _point_double(addend)
        s >>= 1
    return acc


def _point_equal(p1: tuple[int, int, int, int], p2: tuple[int, int, int, int]) -> bool:
    x1, y1, z1, _ = p1
    x2, y2, z2, _ = p2
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _point_decompress(enc: bytes) -> tuple[int, int, int, int] | None:
    if len(enc) != 32:
        return None
    y = int.from_bytes(enc, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % _P)


def verify_ed25519(pub_bytes: bytes, msg_bytes: bytes, sig_bytes: bytes) -> bool:
    """Verify an RFC 8032 Ed25519 signature matching Go crypto/ed25519.Verify."""
    if len(pub_bytes) != 32 or len(sig_bytes) != 64:
        return False
    a_pt = _point_decompress(pub_bytes)
    if a_pt is None:
        return False
    r_bytes = sig_bytes[:32]
    r_pt = _point_decompress(r_bytes)
    if r_pt is None:
        return False
    s = int.from_bytes(sig_bytes[32:], "little")
    if s >= _L:
        return False
    k_digest = hashlib.sha512(r_bytes + pub_bytes + msg_bytes).digest()
    k = int.from_bytes(k_digest, "little") % _L
    lhs = _scalar_mult(s, _B)
    rhs = _point_add(r_pt, _scalar_mult(k, a_pt))
    return _point_equal(lhs, rhs)


_RE_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_RE_HEX128 = re.compile(r"^[0-9a-f]{128}$")


def verify_ed25519_hex(pub_hex: str, msg: str, sig_hex: str) -> bool:
    """Verify a lowercase hex-encoded Ed25519 signature over a UTF-8 message string."""
    if not _RE_HEX64.match(pub_hex) or not _RE_HEX128.match(sig_hex):
        return False
    return verify_ed25519(bytes.fromhex(pub_hex), msg.encode("utf-8"), bytes.fromhex(sig_hex))

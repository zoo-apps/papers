# Copyright 2026 Zoo Labs Foundation & Hanzo Industries.
# SPDX-License-Identifier: Apache-2.0
"""Exact whole-K integer GEMM and Mersenne prime F_p arithmetic (p = 2^31 - 1)."""

from __future__ import annotations

from typing import Sequence

FIELD_MODULUS = 2147483647  # 2^31 - 1
MAX_DIMENSION = 65536


def mod_p(x: int) -> int:
    """Canonical representative of x in [0, FIELD_MODULUS - 1]."""
    return x % FIELD_MODULUS


def exact_int_gemm(
    a_data: Sequence[int],
    m: int,
    d: int,
    b_data: Sequence[int],
    n: int,
) -> list[int]:
    """Exact whole-K integer matrix product C = A * B with zero floating-point rounding."""
    if m <= 0 or d <= 0 or n <= 0:
        raise ValueError(f"invalid non-positive dimensions: ({m}, {d}, {n})")
    if len(a_data) != m * d or len(b_data) != d * n:
        raise ValueError("matrix data length does not match dimensions")
    out = [0] * (m * n)
    for i in range(m):
        a_off = i * d
        c_off = i * n
        for t in range(d):
            av = a_data[a_off + t]
            if av == 0:
                continue
            b_off = t * n
            for j in range(n):
                out[c_off + j] += av * b_data[b_off + j]
    return out


def matvec_int8_mod_p(data: Sequence[int], rows: int, cols: int, r: Sequence[int]) -> list[int]:
    """Compute y = M * r (mod p) for row-major int8 matrix M and vector r in [0, p-1]^cols."""
    out = [0] * rows
    p = FIELD_MODULUS
    for i in range(rows):
        off = i * cols
        acc = 0
        for j in range(cols):
            acc += data[off + j] * r[j]
        out[i] = acc % p
    return out


def matvec_int64_mod_p(data: Sequence[int], rows: int, cols: int, r: Sequence[int]) -> list[int]:
    """Compute y = M * r (mod p) for row-major int64 matrix M and vector r in [0, p-1]^cols."""
    out = [0] * rows
    p = FIELD_MODULUS
    for i in range(rows):
        off = i * cols
        acc = 0
        for j in range(cols):
            acc += (data[off + j] % p) * r[j]
        out[i] = acc % p
    return out

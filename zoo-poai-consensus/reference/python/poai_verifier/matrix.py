# Copyright 2026 Zoo Labs Foundation & Hanzo Industries.
# SPDX-License-Identifier: Apache-2.0
"""Canonical matrix encodings, row Merkle trees, trace root, and vector SHA-256."""

from __future__ import annotations

import hashlib
import struct
from typing import Sequence

DOMAIN_MAT = b"poai:v1:mat:"
DOMAIN_ROW = b"poai:v1:row:"
DOMAIN_NODE = b"poai:v1:node:"
DOMAIN_TRACE = b"poai:v1:trace:"
DOMAIN_VEC = b"poai:v1:vec:"


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    """Domain-separated binary SHA-256 Merkle root matching Go poai.MerkleRoot."""
    if not leaves:
        return hashlib.sha256(b"poai:v1:node:empty").digest()
    level = list(leaves)
    while len(level) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            next_level.append(hashlib.sha256(DOMAIN_NODE + left + right).digest())
        level = next_level
    return level[0]


def int8_matrix_sha256(data: Sequence[int], rows: int, cols: int, role: bytes) -> bytes:
    """Canonical flat SHA-256 of an int8 matrix (width=1)."""
    h = hashlib.sha256()
    h.update(DOMAIN_MAT + role + b"\x01" + struct.pack("<II", rows, cols))
    h.update(bytes(v & 0xFF for v in data))
    return h.digest()


def int64_matrix_sha256(data: Sequence[int], rows: int, cols: int, role: bytes) -> bytes:
    """Canonical flat SHA-256 of an int64 matrix (width=8, little-endian)."""
    h = hashlib.sha256()
    h.update(DOMAIN_MAT + role + b"\x08" + struct.pack("<II", rows, cols))
    h.update(struct.pack(f"<{len(data)}q", *data))
    return h.digest()


def int8_matrix_merkle_root(data: Sequence[int], rows: int, cols: int, role: bytes) -> bytes:
    """Canonical row-Merkle root of an int8 matrix."""
    leaves: list[bytes] = []
    cols_bytes = struct.pack("<I", cols)
    for r in range(rows):
        row = data[r * cols : (r + 1) * cols]
        prefix = DOMAIN_ROW + role + struct.pack("<I", r) + cols_bytes
        leaves.append(hashlib.sha256(prefix + bytes(v & 0xFF for v in row)).digest())
    return merkle_root(leaves)


def int64_matrix_merkle_root(data: Sequence[int], rows: int, cols: int, role: bytes) -> bytes:
    """Canonical row-Merkle root of an int64 matrix."""
    leaves: list[bytes] = []
    cols_bytes = struct.pack("<I", cols)
    row_fmt = f"<{cols}q"
    for r in range(rows):
        row = data[r * cols : (r + 1) * cols]
        prefix = DOMAIN_ROW + role + struct.pack("<I", r) + cols_bytes
        leaves.append(hashlib.sha256(prefix + struct.pack(row_fmt, *row)).digest())
    return merkle_root(leaves)


def activation_trace_root(a_root: bytes, b_root: bytes, c_root: bytes) -> bytes:
    """Bind A, B, and C row-Merkle roots into the canonical activation trace root."""
    return hashlib.sha256(DOMAIN_TRACE + a_root + b_root + c_root).digest()


def vec_sha256(vec: Sequence[int]) -> bytes:
    """Canonical SHA-256 digest of a length-prefixed int64_le vector."""
    h = hashlib.sha256()
    h.update(DOMAIN_VEC + struct.pack("<I", len(vec)))
    h.update(struct.pack(f"<{len(vec)}q", *vec))
    return h.digest()

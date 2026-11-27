# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.

"""Canonical JSON, domain-separated SHA-256, RFC 6962 Merkle root, and truncating integer division."""

import hashlib
import json
from typing import Any, List


def div_trunc(a: int, b: int) -> int:
    """Integer division truncating toward zero (exact match for Go int64 a / b)."""
    q = abs(a) // abs(b)
    return -q if (a < 0) ^ (b < 0) else q


def canonical_json_bytes(obj: Any) -> bytes:
    """RFC 8259 canonical JSON: sorted keys, no whitespace, no HTML escaping."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def domain_message(domain: str, obj: Any) -> bytes:
    """Construct domain || 0x00 || canonical_json(obj)."""
    return domain.encode("utf-8") + b"\x00" + canonical_json_bytes(obj)


def hash_canonical(domain: str, obj: Any) -> str:
    """Return lowercase hex SHA-256(domain || 0x00 || canonical_json(obj))."""
    return hashlib.sha256(domain_message(domain, obj)).hexdigest()


def sha256_hex(data: bytes) -> str:
    """Return lowercase hex SHA-256 of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def _merkle_subtree(leaves: List[str]) -> bytes:
    n = len(leaves)
    if n == 1:
        return hashlib.sha256(b"\x00" + leaves[0].encode("utf-8")).digest()
    k = 1
    while (k << 1) < n:
        k <<= 1
    left = _merkle_subtree(leaves[:k])
    right = _merkle_subtree(leaves[k:])
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root_rfc6962(leaves: List[str]) -> str:
    """Compute RFC 6962 binary Merkle tree root over UTF-8 leaf strings."""
    if not leaves:
        return hashlib.sha256(b"").hexdigest()
    return _merkle_subtree(leaves).hex()

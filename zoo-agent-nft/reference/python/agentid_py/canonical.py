# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.

"""Canonical RFC 8259 JSON, domain separation, Base64URL, Base58BTC, and RFC 6962 Merkle root."""

import base64
import hashlib
import json
from typing import Any, List, Sequence

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_MAP = {ch: idx for idx, ch in enumerate(BASE58_ALPHABET)}


def canonical_json(obj: Any) -> bytes:
    """Serialize obj to deterministic RFC 8259 canonical JSON matching Go CanonicalJSON."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def domain_message(domain: str, obj: Any) -> bytes:
    """Build domain || 0x00 || CanonicalJSON(obj)."""
    return domain.encode("utf-8") + b"\x00" + canonical_json(obj)


def hash_canonical(domain: str, obj: Any) -> str:
    """Return lowercase hex SHA-256(domain || 0x00 || CanonicalJSON(obj))."""
    return hashlib.sha256(domain_message(domain, obj)).hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_base64url(s: str) -> bytes:
    """Decode unpadded URL-safe Base64 strictly."""
    if not isinstance(s, str) or "=" in s:
        raise ValueError("expected unpadded base64url string")
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad))


def base58btc_decode(s: str) -> bytes:
    """Decode a Base58BTC string to raw bytes."""
    if not s:
        raise ValueError("empty base58 string")
    zeros = 0
    for ch in s:
        if ch == "1":
            zeros += 1
        else:
            break
    n = 0
    for ch in s:
        val = _BASE58_MAP.get(ch)
        if val is None:
            raise ValueError(f"invalid base58 character {ch!r}")
        n = n * 58 + val
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""
    return (b"\x00" * zeros) + raw


def public_key_from_did_key(did: str) -> bytes:
    """Decode and validate a W3C Ed25519 did:key:z... multicodec identifier."""
    if not did.startswith("did:key:z"):
        raise ValueError("not a did:key:z multibase identifier")
    raw = base58btc_decode(did[len("did:key:z") :])
    if len(raw) != 34 or raw[0] != 0xED or raw[1] != 0x01:
        raise ValueError("invalid Ed25519 multicodec header or key length")
    return raw[2:]


def merkle_root_rfc6962(leaves: Sequence[str]) -> str:
    """Compute the RFC 6962 binary Merkle tree root over UTF-8 leaves."""
    if not leaves:
        return hashlib.sha256(b"").hexdigest()
    return _merkle_subtree(list(leaves)).hex()


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

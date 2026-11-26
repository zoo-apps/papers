# SPDX-License-Identifier: Apache-2.0
"""Domain-separated binary Merkle tree and O(log n) inclusion proofs matching Go byte-for-byte."""

from __future__ import annotations

import hashlib
from typing import Any

from .canonical import EMPTY_MERKLE_DOMAIN


def _leaf_hash(event_id_hex: str) -> bytes:
    raw = bytes.fromhex(event_id_hex)
    if len(raw) != 32:
        raise ValueError(f"invalid 32-byte event_id hex: {event_id_hex!r}")
    return hashlib.sha256(b"\x00" + raw).digest()


def _internal_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def compute_active_merkle_root(event_ids: list[str]) -> str:
    """Compute canonical binary Merkle root over sorted active event_ids."""
    if not event_ids:
        return hashlib.sha256(EMPTY_MERKLE_DOMAIN.encode("utf-8")).hexdigest()
    level = [_leaf_hash(eid) for eid in sorted(event_ids)]
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(_internal_hash(left, right))
        level = nxt
    return level[0].hex()


def generate_merkle_proof(event_ids: list[str], target_event_id: str) -> dict[str, Any]:
    """Generate O(log n) inclusion proof for target_event_id."""
    if not event_ids:
        raise ValueError("empty active set")
    ordered = sorted(event_ids)
    try:
        idx = ordered.index(target_event_id)
    except ValueError as exc:
        raise ValueError(f"event {target_event_id} not in active set") from exc

    level = [_leaf_hash(eid) for eid in ordered]
    steps: list[dict[str, str]] = []
    cur = idx
    while len(level) > 1:
        if cur % 2 == 0:
            side = "R"
            sib = level[cur + 1] if cur + 1 < len(level) else level[cur]
        else:
            side = "L"
            sib = level[cur - 1]
        steps.append({"sibling_hex": sib.hex(), "side": side})
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(_internal_hash(left, right))
        level = nxt
        cur //= 2
    return {
        "event_id": target_event_id,
        "index": idx,
        "root_hex": level[0].hex(),
        "steps": steps,
    }


def verify_merkle_proof(proof: dict[str, Any], expected_root_hex: str) -> bool:
    """Verify O(log n) Merkle inclusion proof against expected_root_hex."""
    try:
        cur = _leaf_hash(proof["event_id"])
    except Exception:
        return False
    for step in proof.get("steps", []):
        try:
            sib = bytes.fromhex(step["sibling_hex"])
        except Exception:
            return False
        if len(sib) != 32:
            return False
        side = step.get("side")
        if side == "L":
            cur = _internal_hash(sib, cur)
        elif side == "R":
            cur = _internal_hash(cur, sib)
        else:
            return False
    return cur.hex() == expected_root_hex and proof.get("root_hex") == expected_root_hex

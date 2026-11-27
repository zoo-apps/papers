# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""Domain-separated SHA-256 binary Merkle tree and inclusion proof verifier."""

from __future__ import annotations

import hashlib
import re
from typing import Any

_RE_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def empty_merkle_root() -> str:
    return sha256_hex("merkle-empty:v1")


def compute_receipt_merkle_leaf(receipt_id: str, nullifier: str, consumed_micro_zoo: int) -> str:
    return sha256_hex(f"merkle-leaf:v1|{receipt_id}|{nullifier}|{consumed_micro_zoo}")


def hash_merkle_node(left_hex: str, right_hex: str) -> str:
    return sha256_hex(f"merkle-node:v1|{left_hex}|{right_hex}")


def compute_merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return empty_merkle_root()
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level: list[str] = []
        for i in range(0, len(level), 2):
            next_level.append(hash_merkle_node(level[i], level[i + 1]))
        level = next_level
    return level[0]


def verify_merkle_proof(leaf_hex: str, proof: list[dict[str, Any]], root_hex: str) -> bool:
    if not _RE_HEX64.match(leaf_hex) or not _RE_HEX64.match(root_hex):
        return False
    cur = leaf_hex
    for step in proof:
        sib = step.get("sibling_hex", "")
        pos = step.get("position", "")
        if not isinstance(sib, str) or not _RE_HEX64.match(sib):
            return False
        if pos == "left":
            cur = hash_merkle_node(sib, cur)
        elif pos == "right":
            cur = hash_merkle_node(cur, sib)
        else:
            return False
    return cur == root_hex

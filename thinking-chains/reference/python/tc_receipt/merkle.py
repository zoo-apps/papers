# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation and Contributors

"""Domain-separated RFC 6962 binary SHA-256 Merkle tree and inclusion proofs."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

EMPTY_DOMAIN_PREFIX = b"zoo.thinking-chains.merkle.empty.v1:"


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _largest_power_of_two_less_than(n: int) -> int:
    return 1 << ((n - 1).bit_length() - 1)


def hash_leaf(domain: str, leaf_bytes: bytes) -> bytes:
    return _sha256(b"\x00" + domain.encode("ascii") + b":" + leaf_bytes)


def hash_node(domain: str, left: bytes, right: bytes) -> bytes:
    return _sha256(b"\x01" + domain.encode("ascii") + b":" + left + right)


def merkle_root(domain: str, leaves: list[bytes]) -> bytes:
    """Compute the RFC 6962 domain-separated SHA-256 Merkle root over leaves."""
    n = len(leaves)
    if n == 0:
        return _sha256(EMPTY_DOMAIN_PREFIX + domain.encode("ascii"))
    if n == 1:
        return hash_leaf(domain, leaves[0])
    k = _largest_power_of_two_less_than(n)
    left = merkle_root(domain, leaves[:k])
    right = merkle_root(domain, leaves[k:])
    return hash_node(domain, left, right)


@dataclass(frozen=True)
class ProofStep:
    sibling_hash: bytes
    is_left_sibling: bool


@dataclass(frozen=True)
class InclusionProof:
    domain: str
    leaf_index: int
    tree_size: int
    steps: tuple[ProofStep, ...]


def _build_audit_path(domain: str, leaves: list[bytes], index: int) -> list[ProofStep]:
    n = len(leaves)
    if n <= 1:
        return []
    k = _largest_power_of_two_less_than(n)
    if index < k:
        sub_steps = _build_audit_path(domain, leaves[:k], index)
        sibling = merkle_root(domain, leaves[k:])
        sub_steps.append(ProofStep(sibling_hash=sibling, is_left_sibling=False))
        return sub_steps
    sub_steps = _build_audit_path(domain, leaves[k:], index - k)
    sibling = merkle_root(domain, leaves[:k])
    sub_steps.append(ProofStep(sibling_hash=sibling, is_left_sibling=True))
    return sub_steps


def build_inclusion_proof(domain: str, leaves: list[bytes], index: int) -> InclusionProof:
    """Build an O(log n) RFC 6962 Merkle inclusion proof for leaves[index]."""
    n = len(leaves)
    if index < 0 or index >= n:
        raise IndexError(f"leaf index {index} out of bounds for tree size {n}")
    steps = _build_audit_path(domain, leaves, index)
    return InclusionProof(
        domain=domain,
        leaf_index=index,
        tree_size=n,
        steps=tuple(steps),
    )


def verify_inclusion_proof(
    proof: InclusionProof,
    leaf_bytes: bytes,
    expected_root: bytes,
) -> bool:
    """Verify an RFC 6962 Merkle inclusion proof against expected_root."""
    if proof.tree_size <= 0 or proof.leaf_index < 0 or proof.leaf_index >= proof.tree_size:
        return False
    acc = hash_leaf(proof.domain, leaf_bytes)
    for step in proof.steps:
        if step.is_left_sibling:
            acc = hash_node(proof.domain, step.sibling_hash, acc)
        else:
            acc = hash_node(proof.domain, acc, step.sibling_hash)
    return acc == expected_root

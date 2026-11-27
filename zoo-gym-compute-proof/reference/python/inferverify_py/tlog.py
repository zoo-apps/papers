# Copyright 2026 Zoo Labs Foundation / Hanzo Industries.
# Licensed under the Apache License, Version 2.0.
"""RFC 6962 SHA-256 transparency log Merkle tree and inclusion proof verifier."""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from . import ed25519

ERR_NONE = "OK"
ERR_EPOCH_MISMATCH = "ERR_EPOCH_MISMATCH"
ERR_MISSING_TLOG_PROOF = "ERR_MISSING_TLOG_PROOF"
ERR_UNTRUSTED_TLOG_KEY = "ERR_UNTRUSTED_TLOG_KEY"
ERR_INVALID_TLOG_CHECKPOINT_SIG = "ERR_INVALID_TLOG_CHECKPOINT_SIG"
ERR_INVALID_TLOG_PROOF = "ERR_INVALID_TLOG_PROOF"
ERR_TLOG_LEAF_MISMATCH = "ERR_TLOG_LEAF_MISMATCH"


def hash_leaf_rfc6962(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def hash_node_rfc6962(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_power_of_two_less_than(n: int) -> int:
    if n <= 1:
        return 0
    return 1 << ((n - 1).bit_length() - 1)


def compute_merkle_root_rfc6962(raw_leaves: list[bytes]) -> bytes:
    n = len(raw_leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hash_leaf_rfc6962(raw_leaves[0])
    k = _largest_power_of_two_less_than(n)
    left = compute_merkle_root_rfc6962(raw_leaves[:k])
    right = compute_merkle_root_rfc6962(raw_leaves[k:])
    return hash_node_rfc6962(left, right)


def _eval_inclusion_path(
    leaf_hash: bytes, index: int, tree_size: int, proof: list[bytes]
) -> tuple[bytes, int, bool]:
    if tree_size == 1:
        if index != 0:
            return b"", 0, False
        return leaf_hash, 0, True
    k = _largest_power_of_two_less_than(tree_size)
    if index < k:
        left_root, used, ok = _eval_inclusion_path(leaf_hash, index, k, proof)
        if not ok or used >= len(proof):
            return b"", 0, False
        return hash_node_rfc6962(left_root, proof[used]), used + 1, True
    right_root, used, ok = _eval_inclusion_path(
        leaf_hash, index - k, tree_size - k, proof
    )
    if not ok or used >= len(proof):
        return b"", 0, False
    return hash_node_rfc6962(proof[used], right_root), used + 1, True


def verify_inclusion_proof_rfc6962(
    raw_leaf: bytes,
    index: int,
    tree_size: int,
    proof_hex: list[str],
    expected_root_hex: str,
) -> bool:
    if tree_size <= 0 or index < 0 or index >= tree_size:
        return False
    proof: list[bytes] = []
    for h in proof_hex:
        try:
            b = bytes.fromhex(h)
        except ValueError:
            return False
        if len(b) != 32:
            return False
        proof.append(b)
    root, consumed, ok = _eval_inclusion_path(
        hash_leaf_rfc6962(raw_leaf), index, tree_size, proof
    )
    if not ok or consumed != len(proof):
        return False
    return root.hex() == expected_root_hex


def checkpoint_message(
    log_id: str, tree_size: int, root_hash: str, checkpoint_epoch: int
) -> bytes:
    s = f"rekor-checkpoint.v1\n{log_id}\n{tree_size}\n{root_hash}\n{checkpoint_epoch}"
    return s.encode("utf-8")


def verify_tlog_bundle(
    bundle: dict[str, Any] | None,
    expected_leaf_digest: str,
    expected_epoch: int,
    trust_root: dict[str, Any],
) -> str:
    if bundle is None:
        return ERR_MISSING_TLOG_PROOF
    if (
        bundle.get("log_id") != trust_root.get("tlog_id")
        or bundle.get("log_pubkey_hex") != trust_root.get("tlog_pubkey_hex")
    ):
        return ERR_UNTRUSTED_TLOG_KEY
    if bundle.get("checkpoint_epoch") != expected_epoch:
        return ERR_EPOCH_MISMATCH
    if bundle.get("leaf_entry_digest") != expected_leaf_digest:
        return ERR_TLOG_LEAF_MISMATCH

    try:
        pub_bytes = bytes.fromhex(trust_root["tlog_pubkey_hex"])
    except (ValueError, KeyError):
        return ERR_UNTRUSTED_TLOG_KEY
    if len(pub_bytes) != 32:
        return ERR_UNTRUSTED_TLOG_KEY

    try:
        sig_bytes = base64.b64decode(bundle.get("checkpoint_sig_b64", ""), validate=True)
    except Exception:
        return ERR_INVALID_TLOG_CHECKPOINT_SIG
    if len(sig_bytes) != 64:
        return ERR_INVALID_TLOG_CHECKPOINT_SIG

    msg = checkpoint_message(
        bundle["log_id"],
        int(bundle["tree_size"]),
        bundle["root_hash"],
        int(bundle["checkpoint_epoch"]),
    )
    if not ed25519.verify(pub_bytes, msg, sig_bytes):
        return ERR_INVALID_TLOG_CHECKPOINT_SIG

    if not verify_inclusion_proof_rfc6962(
        bundle["leaf_entry_digest"].encode("utf-8"),
        int(bundle["log_index"]),
        int(bundle["tree_size"]),
        list(bundle.get("hashes", [])),
        bundle["root_hash"],
    ):
        return ERR_INVALID_TLOG_PROOF

    return ERR_NONE

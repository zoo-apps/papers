# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Canonical binary encodings and SHA-256 Merkle primitives matching Go bit-for-bit."""

from __future__ import annotations

import hashlib
import struct
from typing import Any, Dict, List, Sequence

SCHEMA_VERSION = "inference-net.v1"
SPEC_VERSION = "1.0.0"

DOMAIN_NODE_ADV = b"ZOO-INFNET-V1-NODE-ADV\x00"
DOMAIN_RECEIPT = b"ZOO-INFNET-V1-RECEIPT\x00"
DOMAIN_EMPTY_MERKLE = b"ZOO-INFNET-V1-EMPTY-MERKLE"
DOMAIN_VERDICT = b"ZOO-INFNET-V1-VERDICT\x00"


def _lp_str(s: str) -> bytes:
    raw = s.encode("utf-8")
    return struct.pack(">I", len(raw)) + raw


def _lp_str_slice(xs: Sequence[str] | None) -> bytes:
    items = xs or []
    parts = [struct.pack(">I", len(items))]
    for s in items:
        parts.append(_lp_str(s))
    return b"".join(parts)


def _u32(v: int) -> bytes:
    return struct.pack(">I", int(v))


def _u64(v: int) -> bytes:
    return struct.pack(">Q", int(v))


def _bool_byte(v: bool) -> bytes:
    return b"\x01" if v else b"\x00"


def canonical_node_advertisement_bytes(ad: Dict[str, Any]) -> bytes:
    """Produce the exact RFC 8032 Ed25519 signing payload for a NodeAdvertisement."""
    return b"".join(
        [
            DOMAIN_NODE_ADV,
            _lp_str(ad["schema_version"]),
            _lp_str(ad["node_id"]),
            _lp_str(ad["public_key_hex"]),
            _lp_str(ad["hardware_profile"]),
            _lp_str(ad["model_id"]),
            _lp_str(ad["execution_role"]),
            _u32(ad["layer_start"]),
            _u32(ad["layer_end"]),
            _u32(ad["total_layers"]),
            _u64(ad["vram_total_mib"]),
            _u64(ad["vram_reserved_base_mib"]),
            _u32(ad["kv_slots_total"]),
            _u32(ad["prefill_tps"]),
            _u32(ad["decode_tps"]),
            _u64(ad["wan_rtt_us"]),
            _u64(ad["bandwidth_kbps"]),
            _lp_str(ad["privacy_tier"]),
            _lp_str(ad.get("tee_attestation_sha256", "")),
            _u64(ad["heartbeat_epoch"]),
            _u64(ad["timestamp_unix_s"]),
        ]
    )


def canonical_delivery_receipt_bytes(r: Dict[str, Any]) -> bytes:
    """Produce the exact RFC 8032 Ed25519 signing payload for a DeliveryReceipt."""
    return b"".join(
        [
            DOMAIN_RECEIPT,
            _lp_str(r["schema_version"]),
            _lp_str(r["receipt_id"]),
            _lp_str(r["request_id"]),
            _lp_str(r["topology_mode"]),
            _lp_str(r["model_id"]),
            _lp_str(r["prompt_sha256"]),
            _lp_str(r["prompt_prefix_sha256"]),
            _u32(r["prompt_tokens"]),
            _u32(r["output_tokens"]),
            _lp_str(r["output_merkle_root"]),
            _lp_str(r["privacy_requirement"]),
            _lp_str(r["effective_privacy_tier"]),
            _lp_str_slice(r.get("route_node_ids")),
            _lp_str(r["primary_provider_id"]),
            _lp_str(r["provider_public_key_hex"]),
            _lp_str(r.get("prefill_node_id", "")),
            _lp_str_slice(r.get("decode_node_ids")),
            _u32(r["kv_slots_reserved"]),
            _u64(r["vram_reserved_mib"]),
            _u64(r["network_bytes_transferred"]),
            _u64(r["ttft_us"]),
            _u64(r["tpot_us"]),
            _u64(r["total_latency_us"]),
            _u64(r["recovery_latency_us"]),
            _u32(r["failover_attempts"]),
            _lp_str_slice(r.get("failed_node_ids")),
            _u32(r["batch_size_effective"]),
            _u32(r["batch_utilization_bps"]),
            _lp_str(r["status"]),
            _bool_byte(bool(r["proves_scientific_truth"])),
            _bool_byte(bool(r["authorizes_treasury_spend"])),
        ]
    )


def _reduce_merkle(nodes: List[bytes]) -> bytes:
    cur = list(nodes)
    while len(cur) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(cur), 2):
            left = cur[i]
            right = cur[i + 1] if i + 1 < len(cur) else left
            nxt.append(hashlib.sha256(b"\x01" + left + right).digest())
        cur = nxt
    return cur[0]


def compute_output_merkle_root(chunks: Sequence[str] | None) -> str:
    """Compute SHA-256 binary Merkle root over ordered output token chunks."""
    items = chunks or []
    if not items:
        return hashlib.sha256(DOMAIN_EMPTY_MERKLE).hexdigest()
    leaves: List[bytes] = []
    for idx, ch in enumerate(items):
        leaf = hashlib.sha256(b"\x00" + struct.pack(">I", idx) + ch.encode("utf-8")).digest()
        leaves.append(leaf)
    return _reduce_merkle(leaves).hex()


def compute_merkle_root_from_hex_digests(digests: Sequence[str]) -> str:
    """Build a binary SHA-256 Merkle root from 32-byte lowercase hex digests."""
    if not digests:
        return hashlib.sha256(DOMAIN_EMPTY_MERKLE).hexdigest()
    nodes: List[bytes] = []
    for idx, d in enumerate(digests):
        raw = bytes.fromhex(d)
        if len(raw) != 32:
            raise ValueError(f"invalid 32-byte hex digest at index {idx}")
        nodes.append(raw)
    return _reduce_merkle(nodes).hex()


def compute_verdict_digest(
    case_id: str,
    valid: bool,
    error_code: str,
    signature_valid: bool,
    privacy_compliant: bool,
    capacity_conserved: bool,
    constitutional_valid: bool,
    output_merkle_root: str,
) -> str:
    """Compute canonical 32-byte hex digest of a single verification verdict."""
    payload = b"".join(
        [
            DOMAIN_VERDICT,
            _lp_str(case_id),
            _bool_byte(valid),
            _lp_str(error_code),
            _bool_byte(signature_valid),
            _bool_byte(privacy_compliant),
            _bool_byte(capacity_conserved),
            _bool_byte(constitutional_valid),
            _lp_str(output_merkle_root),
        ]
    )
    return hashlib.sha256(payload).hexdigest()

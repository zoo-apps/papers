# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Independent verifier for inference-net.v1 advertisements, receipts, capacity, and privacy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Sequence, Tuple

from .canonical import (
    SCHEMA_VERSION,
    canonical_delivery_receipt_bytes,
    canonical_node_advertisement_bytes,
    compute_merkle_root_from_hex_digests,
    compute_output_merkle_root,
    compute_verdict_digest,
)
from .ed25519 import verify_ed25519

VALID_HW_PROFILES = {"H100-80GB", "RTX-4090-24GB", "Mac-M4-Max-64GB", "Consumer-12GB"}
VALID_EXEC_ROLES = {"WHOLE_MODEL", "PREFILL", "DECODE", "PIPELINE_STAGE"}
VALID_PRIVACY_TIERS = {"TEE_ATTESTED", "LOCAL_PRIVATE", "PUBLIC_RELAY"}
VALID_PRIVACY_REQS = {"PUBLIC_OK", "PRIVACY_STRICT"}
VALID_TOPOLOGIES = {
    "centralized_datacenter_baseline",
    "decentralized_replica_dynamo",
    "decentralized_pipeline_petals",
    "decentralized_privacy_strict_tee",
}

ERR_OK = "OK"
ERR_SCHEMA_INVALID = "ERR_SCHEMA_INVALID"
ERR_INVALID_NODE_ADVERTISEMENT = "ERR_INVALID_NODE_ADVERTISEMENT"
ERR_STALE_HEARTBEAT_EPOCH = "ERR_STALE_HEARTBEAT_EPOCH"
ERR_KEY_MISMATCH = "ERR_KEY_MISMATCH"
ERR_INVALID_RECEIPT_SIGNATURE = "ERR_INVALID_RECEIPT_SIGNATURE"
ERR_OUTPUT_MERKLE_MISMATCH = "ERR_OUTPUT_MERKLE_MISMATCH"
ERR_PRIVACY_BOUNDARY_VIOLATION = "ERR_PRIVACY_BOUNDARY_VIOLATION"
ERR_CAPACITY_CONSERVATION = "ERR_CAPACITY_CONSERVATION"
ERR_CONSTITUTIONAL_VIOLATION = "ERR_CONSTITUTIONAL_VIOLATION"
ERR_MISSING_PROVIDER_NODE = "ERR_MISSING_PROVIDER_NODE"


@dataclass(frozen=True)
class VerificationResult:
    case_id: str
    valid: bool
    error_code: str
    detail: str
    signature_valid: bool
    privacy_compliant: bool
    capacity_conserved: bool
    constitutional_valid: bool
    verdict_digest: str


def _hex_bytes(h: str, expected_len: int) -> bytes | None:
    if not isinstance(h, str) or len(h) != expected_len * 2:
        return None
    try:
        raw = bytes.fromhex(h)
    except ValueError:
        return None
    return raw if len(raw) == expected_len else None


def privacy_tier_satisfies(req: str, node_tier: str) -> bool:
    if req == "PUBLIC_OK":
        return node_tier in VALID_PRIVACY_TIERS
    if req == "PRIVACY_STRICT":
        return node_tier in {"TEE_ATTESTED", "LOCAL_PRIVATE"}
    return False


def effective_tier_for_route(tiers: Sequence[str]) -> str:
    if not tiers:
        return "PUBLIC_RELAY"
    rank = {"TEE_ATTESTED": 3, "LOCAL_PRIVATE": 2, "PUBLIC_RELAY": 1}
    return min(tiers, key=lambda t: rank.get(t, 1))


def verify_node_advertisement(ad: Dict[str, Any]) -> Tuple[str, str]:
    """Validate structural bounds and RFC 8032 Ed25519 signature on a NodeAdvertisement."""
    if ad.get("schema_version") != SCHEMA_VERSION:
        return ERR_INVALID_NODE_ADVERTISEMENT, "unsupported schema_version"
    if not ad.get("node_id") or not ad.get("model_id"):
        return ERR_INVALID_NODE_ADVERTISEMENT, "node_id and model_id must be non-empty"
    if ad.get("hardware_profile") not in VALID_HW_PROFILES:
        return ERR_INVALID_NODE_ADVERTISEMENT, "invalid hardware_profile"
    if ad.get("execution_role") not in VALID_EXEC_ROLES:
        return ERR_INVALID_NODE_ADVERTISEMENT, "invalid execution_role"
    if ad.get("privacy_tier") not in VALID_PRIVACY_TIERS:
        return ERR_INVALID_NODE_ADVERTISEMENT, "invalid privacy_tier"

    l_start = int(ad.get("layer_start", -1))
    l_end = int(ad.get("layer_end", -1))
    total_layers = int(ad.get("total_layers", 0))
    if total_layers <= 0 or l_start < 0 or l_start >= l_end or l_end > total_layers:
        return ERR_INVALID_NODE_ADVERTISEMENT, "invalid layer range"
    if ad["execution_role"] == "WHOLE_MODEL" and (l_start != 0 or l_end != total_layers):
        return ERR_INVALID_NODE_ADVERTISEMENT, "WHOLE_MODEL must serve all layers"

    vram_total = int(ad.get("vram_total_mib", 0))
    vram_base = int(ad.get("vram_reserved_base_mib", -1))
    if vram_total <= 0 or vram_base < 0 or vram_base > vram_total:
        return ERR_INVALID_NODE_ADVERTISEMENT, "invalid VRAM bounds"

    if (
        int(ad.get("kv_slots_total", 0)) <= 0
        or int(ad.get("prefill_tps", 0)) <= 0
        or int(ad.get("decode_tps", 0)) <= 0
        or int(ad.get("bandwidth_kbps", 0)) <= 0
        or int(ad.get("heartbeat_epoch", 0)) <= 0
    ):
        return ERR_INVALID_NODE_ADVERTISEMENT, "capacity/throughput/epoch must be positive"

    if ad["privacy_tier"] == "TEE_ATTESTED":
        tee = ad.get("tee_attestation_sha256", "")
        if _hex_bytes(tee, 32) is None:
            return ERR_INVALID_NODE_ADVERTISEMENT, "TEE_ATTESTED requires 64-hex attestation digest"

    pub = _hex_bytes(ad.get("public_key_hex", ""), 32)
    sig = _hex_bytes(ad.get("signature_hex", ""), 64)
    if pub is None or sig is None:
        return ERR_INVALID_NODE_ADVERTISEMENT, "malformed Ed25519 key or signature"

    msg = canonical_node_advertisement_bytes(ad)
    if not verify_ed25519(pub, msg, sig):
        return ERR_INVALID_NODE_ADVERTISEMENT, f"Ed25519 signature invalid for {ad['node_id']}"
    return ERR_OK, "ok"


def verify_capacity_conservation(
    node_map: Dict[str, Dict[str, Any]],
    ledger: Sequence[Dict[str, Any]] | None,
) -> Tuple[bool, str]:
    """Replay capacity ledger and assert monotonic seq, zero oversubscription, and zero leaks."""
    vram_in_use: Dict[str, int] = {nid: 0 for nid in node_map}
    kv_in_use: Dict[str, int] = {nid: 0 for nid in node_map}
    active: Dict[str, Tuple[str, int, int]] = {}
    seen_res: set[str] = set()
    prev_seq = 0

    for ev in ledger or []:
        seq = int(ev.get("seq", 0))
        if seq <= prev_seq:
            return False, f"non-monotonic capacity event seq {seq} <= {prev_seq}"
        prev_seq = seq

        nid = ev.get("node_id", "")
        if nid not in node_map:
            return False, f"capacity event references unknown node {nid}"
        ad = node_map[nid]
        action = ev.get("action", "")
        res_id = ev.get("reservation_id", "")
        vram_mib = int(ev.get("vram_mib", 0))
        kv_slots = int(ev.get("kv_slots", 0))

        if action == "RESERVE":
            if res_id in seen_res:
                return False, f"duplicate reservation id {res_id}"
            if int(ad["vram_reserved_base_mib"]) + vram_in_use[nid] + vram_mib > int(ad["vram_total_mib"]):
                return False, f"VRAM oversubscription on {nid}"
            if kv_in_use[nid] + kv_slots > int(ad["kv_slots_total"]):
                return False, f"KV slot oversubscription on {nid}"
            vram_in_use[nid] += vram_mib
            kv_in_use[nid] += kv_slots
            active[res_id] = (nid, vram_mib, kv_slots)
            seen_res.add(res_id)
        elif action == "RELEASE":
            if res_id not in active:
                return False, f"release of non-active or already-released reservation {res_id}"
            o_nid, o_vram, o_kv = active[res_id]
            if o_nid != nid or o_vram != vram_mib or o_kv != kv_slots:
                return False, f"release mismatch for reservation {res_id}"
            vram_in_use[nid] -= vram_mib
            kv_in_use[nid] -= kv_slots
            del active[res_id]
        else:
            return False, f"unknown capacity action {action!r}"

    if active:
        return False, f"capacity leak detected: {len(active)} unreleased reservation(s)"
    for nid in node_map:
        if vram_in_use[nid] != 0 or kv_in_use[nid] != 0:
            return False, f"nonzero residual capacity on {nid}"
    return True, ERR_OK


def _verify_privacy_compliance(
    node_map: Dict[str, Dict[str, Any]],
    receipt: Dict[str, Any],
) -> Tuple[bool, str]:
    req = receipt.get("privacy_requirement", "")
    eff = receipt.get("effective_privacy_tier", "")
    if not privacy_tier_satisfies(req, eff):
        return False, f"effective_privacy_tier {eff} violates {req}"

    touched_tiers: List[str] = []

    def check_node(nid: str, role: str) -> Tuple[bool, str]:
        if nid not in node_map:
            return False, f"{role} node {nid} not found in registered advertisements"
        tier = node_map[nid]["privacy_tier"]
        if not privacy_tier_satisfies(req, tier):
            return False, f"{role} node {nid} has tier {tier} violating {req}"
        touched_tiers.append(tier)
        return True, ""

    for nid in receipt.get("route_node_ids") or []:
        ok, msg = check_node(nid, "route")
        if not ok:
            return False, msg
    prefill_nid = receipt.get("prefill_node_id") or ""
    if prefill_nid:
        ok, msg = check_node(prefill_nid, "prefill")
        if not ok:
            return False, msg
    for nid in receipt.get("decode_node_ids") or []:
        ok, msg = check_node(nid, "decode")
        if not ok:
            return False, msg
    for nid in receipt.get("failed_node_ids") or []:
        ok, msg = check_node(nid, "failed")
        if not ok:
            return False, msg

    if touched_tiers:
        expected_eff = effective_tier_for_route(touched_tiers)
        if eff != expected_eff:
            return False, f"effective_privacy_tier {eff} != weakest touched tier {expected_eff}"
    return True, ERR_OK


def verify_parity_case(case: Dict[str, Any]) -> VerificationResult:
    """Independently verify a ParityCase with exact error precedence matching Go."""
    case_id = case["case_id"]
    receipt = case["receipt"]

    constitutional_valid = (
        not bool(receipt.get("proves_scientific_truth", False))
        and not bool(receipt.get("authorizes_treasury_spend", False))
    )

    # 1. Validate & register all NodeAdvertisements in order (enforcing key pinning & monotonic epoch).
    node_map: Dict[str, Dict[str, Any]] = {}
    node_err_code = ERR_OK
    node_err_detail = ""
    for ad in case.get("nodes") or []:
        code, detail = verify_node_advertisement(ad)
        if code != ERR_OK:
            if node_err_code == ERR_OK:
                node_err_code = code
                node_err_detail = detail
            continue
        nid = ad["node_id"]
        if nid in node_map:
            existing = node_map[nid]
            if existing["public_key_hex"] != ad["public_key_hex"]:
                if node_err_code == ERR_OK:
                    node_err_code = ERR_KEY_MISMATCH
                    node_err_detail = f"node {nid} key mismatch"
                continue
            if int(ad["heartbeat_epoch"]) <= int(existing["heartbeat_epoch"]):
                if node_err_code == ERR_OK:
                    node_err_code = ERR_STALE_HEARTBEAT_EPOCH
                    node_err_detail = f"node {nid} stale heartbeat_epoch"
                continue
        node_map[nid] = ad

    # 2. Schema validation on receipt.
    schema_ok = (
        receipt.get("schema_version") == SCHEMA_VERSION
        and receipt.get("topology_mode") in VALID_TOPOLOGIES
        and receipt.get("effective_privacy_tier") in VALID_PRIVACY_TIERS
        and receipt.get("privacy_requirement") in VALID_PRIVACY_REQS
        and 0 <= int(receipt.get("batch_utilization_bps", -1)) <= 10000
    )

    # 3. Provider key binding + Ed25519 signature verification.
    primary_id = receipt.get("primary_provider_id", "")
    provider_ad = node_map.get(primary_id)
    provider_bound = (
        provider_ad is not None
        and provider_ad["public_key_hex"] == receipt.get("provider_public_key_hex")
    )
    sig_ok = False
    if provider_bound:
        pub = _hex_bytes(receipt.get("provider_public_key_hex", ""), 32)
        sig = _hex_bytes(receipt.get("signature_hex", ""), 64)
        if pub is not None and sig is not None:
            sig_ok = verify_ed25519(pub, canonical_delivery_receipt_bytes(receipt), sig)

    # 4. Output token Merkle root verification.
    output_chunks = case.get("output_chunks") or []
    recomputed_root = compute_output_merkle_root(output_chunks)
    merkle_ok = (
        recomputed_root == receipt.get("output_merkle_root")
        and len(output_chunks) == int(receipt.get("output_tokens", -1))
    )

    # 5. Privacy-boundary verification.
    privacy_ok, privacy_detail = _verify_privacy_compliance(node_map, receipt)

    # 6. Capacity conservation replay.
    cap_ok, cap_detail = verify_capacity_conservation(node_map, case.get("capacity_ledger") or [])

    valid = False
    if not schema_ok:
        err_code, detail = ERR_SCHEMA_INVALID, "receipt failed schema_version or enum validation"
    elif not constitutional_valid:
        err_code, detail = ERR_CONSTITUTIONAL_VIOLATION, "constitutional lock violated"
    elif node_err_code != ERR_OK:
        err_code, detail = node_err_code, node_err_detail
    elif not provider_bound:
        err_code, detail = ERR_MISSING_PROVIDER_NODE, f"primary provider {primary_id!r} missing or key mismatch"
    elif not sig_ok:
        err_code, detail = ERR_INVALID_RECEIPT_SIGNATURE, "delivery receipt Ed25519 signature invalid"
    elif not merkle_ok:
        err_code, detail = ERR_OUTPUT_MERKLE_MISMATCH, "output Merkle root or token count mismatch"
    elif not privacy_ok:
        err_code, detail = ERR_PRIVACY_BOUNDARY_VIOLATION, privacy_detail
    elif not cap_ok:
        err_code, detail = ERR_CAPACITY_CONSERVATION, cap_detail
    else:
        valid = True
        err_code, detail = ERR_OK, "verified"

    verdict_digest = compute_verdict_digest(
        case_id=case_id,
        valid=valid,
        error_code=err_code,
        signature_valid=sig_ok,
        privacy_compliant=privacy_ok,
        capacity_conserved=cap_ok,
        constitutional_valid=constitutional_valid,
        output_merkle_root=receipt.get("output_merkle_root", ""),
    )

    return VerificationResult(
        case_id=case_id,
        valid=valid,
        error_code=err_code,
        detail=detail,
        signature_valid=sig_ok,
        privacy_compliant=privacy_ok,
        capacity_conserved=cap_ok,
        constitutional_valid=constitutional_valid,
        verdict_digest=verdict_digest,
    )


def verify_parity_suite(suite: Dict[str, Any]) -> Tuple[List[VerificationResult], str]:
    """Verify every case in a ParitySuite and compute the canonical audit_merkle_root."""
    results: List[VerificationResult] = []
    digests: List[str] = []
    for case in suite.get("cases") or []:
        vr = verify_parity_case(case)
        results.append(vr)
        digests.append(vr.verdict_digest)
    audit_root = compute_merkle_root_from_hex_digests(digests)
    return results, audit_root

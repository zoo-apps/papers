# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.

"""Normative pure-Python verifier for forkable-org.v1 (bit-exact parity with Go)."""

from typing import Any, Dict, List, Optional, Tuple

from .canonical import domain_message, hash_canonical, merkle_root_rfc6962
from .ed25519 import verify_ed25519
from .model import (
    apply_bitdelta,
    compress_bitdelta,
    evaluate_model,
    merge_cross_fork_weights,
)

SCHEMA_VERSION = "forkable-org.v1"
SPEC_VERSION = "1.0.0"

DOMAIN_MODEL_BASE = "forkable-org.v1:base-model"
DOMAIN_BITDELTA = "forkable-org.v1:bitdelta"
DOMAIN_DELTASOUP = "forkable-org.v1:deltasoup"
DOMAIN_RESEARCH_RECORD = "forkable-org.v1:research-record"
DOMAIN_POLICY_MANIFEST = "forkable-org.v1:policy-manifest"
DOMAIN_ACL_POLICY = "forkable-org.v1:acl-policy"
DOMAIN_GOVERNANCE_ACTION = "forkable-org.v1:governance-action"
DOMAIN_ADVISORY_PROPOSAL = "forkable-org.v1:advisory-proposal"
DOMAIN_EVAL_RECEIPT = "forkable-org.v1:eval-receipt"
DOMAIN_ORG_SNAPSHOT = "forkable-org.v1:org-snapshot"
DOMAIN_FORK_ATTESTATION = "forkable-org.v1:fork-attestation"
DOMAIN_EXCHANGE_BUNDLE = "forkable-org.v1:exchange-bundle"
DOMAIN_AUDIT_LEAF = "forkable-org.v1:audit-leaf"

ROLE_HUMAN_COUNCIL = "HUMAN_COUNCIL"
ROLE_EVALUATOR = "EVALUATOR"
ROLE_TRAINER = "TRAINER"
ROLE_AI_AGENT = "AI_AGENT"

TIER_PUBLIC = "public"
TIER_INTERNAL = "org_internal"
TIER_RESTRICTED = "restricted_pii_or_partner"

ACTION_UPDATE_VOTING_RULES = "update_voting_rules"
ACTION_AUTHORIZE_TREASURY_SPEND = "authorize_treasury_spend"

ERR_OK = "OK"
ERR_LINEAGE_BROKEN = "ERR_LINEAGE_BROKEN"
ERR_DELTA_HASH_MISMATCH = "ERR_DELTA_HASH_MISMATCH"
ERR_HISTORY_CHAIN_BROKEN = "ERR_HISTORY_CHAIN_BROKEN"
ERR_MERKLE_ROOT_MISMATCH = "ERR_MERKLE_ROOT_MISMATCH"
ERR_ACL_LEAK_RESTRICTED = "ERR_ACL_LEAK_RESTRICTED"
ERR_ACL_LEAK_GRANT = "ERR_ACL_LEAK_GRANT"
ERR_ACL_TAINT_RESTRICTED = "ERR_ACL_TAINT_RESTRICTED"
ERR_KEY_ROTATION_REQUIRED = "ERR_KEY_ROTATION_REQUIRED"
ERR_CROSS_ORG_REPLAY = "ERR_CROSS_ORG_REPLAY"
ERR_UNAUTHORIZED_SIGNER = "ERR_UNAUTHORIZED_SIGNER"
ERR_INVALID_SIGNATURE = "ERR_INVALID_SIGNATURE"
ERR_AI_VOTING_RULE_FORBIDDEN = "ERR_AI_VOTING_RULE_FORBIDDEN"
ERR_AI_TREASURY_FORBIDDEN = "ERR_AI_TREASURY_FORBIDDEN"
ERR_AI_SELF_CERTIFY_FORBIDDEN = "ERR_AI_SELF_CERTIFY_FORBIDDEN"
ERR_AI_BINDING_PROPOSAL_FORBIDDEN = "ERR_AI_BINDING_PROPOSAL_FORBIDDEN"
ERR_EVAL_REPLAY_MISMATCH = "ERR_EVAL_REPLAY_MISMATCH"
ERR_QUALITY_REGRESSION = "ERR_QUALITY_REGRESSION"
ERR_SAFETY_FLOOR_VIOLATION = "ERR_SAFETY_FLOOR_VIOLATION"
ERR_LICENSE_INCOMPATIBLE = "ERR_LICENSE_INCOMPATIBLE"
ERR_REDACTION_PROOF_INVALID = "ERR_REDACTION_PROOF_INVALID"
ERR_INSUFFICIENT_QUORUM = "ERR_INSUFFICIENT_QUORUM"
ERR_SNAPSHOT_HASH_MISMATCH = "ERR_SNAPSHOT_HASH_MISMATCH"
ERR_POLICY_HASH_MISMATCH = "ERR_POLICY_HASH_MISMATCH"
ERR_BUNDLE_HASH_MISMATCH = "ERR_BUNDLE_HASH_MISMATCH"


def _verify_canonical_sig(pub_hex: str, sig_hex: str, domain: str, payload: Any) -> bool:
    try:
        pub = bytes.fromhex(pub_hex)
        sig = bytes.fromhex(sig_hex)
    except ValueError:
        return False
    return verify_ed25519(pub, domain_message(domain, payload), sig)


def _find_principal(policy: Dict[str, Any], pid: str) -> Optional[Dict[str, Any]]:
    for p in policy.get("authorized_principals", []):
        if p["id"] == pid:
            return p
    return None


def _is_license_allowed(policy: Dict[str, Any], license_id: str) -> bool:
    return license_id in policy.get("allowed_licenses", [])


def compute_base_model_hash(b: Dict[str, Any]) -> str:
    return hash_canonical(
        DOMAIN_MODEL_BASE,
        {
            "dim": b["dim"],
            "license_id": b["license_id"],
            "license_reviewed": b["license_reviewed"],
            "model_id": b["model_id"],
            "num_classes": b["num_classes"],
            "num_features": b["num_features"],
            "weights_micro": b["weights_micro"] or [],
        },
    )


def bitdelta_signing_payload(d: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "acl_tier": d["acl_tier"],
        "base_checkpoint_hash": d["base_checkpoint_hash"],
        "base_model_id": d["base_model_id"],
        "contributor_id": d["contributor_id"],
        "delta_id": d["delta_id"],
        "dim": d["dim"],
        "license_id": d["license_id"],
        "license_reviewed": d["license_reviewed"],
        "org_id": d["org_id"],
        "parent_delta_id": d["parent_delta_id"],
        "scale_micro": d["scale_micro"],
        "sign_bits_hex": d["sign_bits_hex"],
        "training_record_ids": d.get("training_record_ids") or [],
    }


def compute_bitdelta_hash(d: Dict[str, Any]) -> str:
    return hash_canonical(DOMAIN_BITDELTA, bitdelta_signing_payload(d))


def compute_deltasoup_hash(s: Dict[str, Any]) -> str:
    return hash_canonical(
        DOMAIN_DELTASOUP,
        {
            "accepted_contributor_ids": s.get("accepted_contributor_ids") or [],
            "base_checkpoint_hash": s["base_checkpoint_hash"],
            "base_model_id": s["base_model_id"],
            "contributor_delta_ids": s.get("contributor_delta_ids") or [],
            "org_id": s["org_id"],
            "result_delta_hash": s["result_delta"]["delta_hash"],
            "royalty_shares": s.get("royalty_shares") or [],
            "soup_id": s["soup_id"],
            "step_bps": s["step_bps"],
            "trim_bps": s["trim_bps"],
        },
    )


def compute_model_registry_root(m: Dict[str, Any]) -> str:
    leaves = ["base:" + m["base_model"]["weights_hash"]]
    for d in m.get("deltas") or []:
        leaves.append("delta:" + d["delta_hash"])
    for s in m.get("soups") or []:
        leaves.append("soup:" + s["soup_hash"])
    return merkle_root_rfc6962(leaves)


def research_record_signing_payload(r: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "acl_tier": r["acl_tier"],
        "author_id": r["author_id"],
        "kind": r["kind"],
        "license_id": r["license_id"],
        "license_reviewed": r["license_reviewed"],
        "org_id": r["org_id"],
        "payload_hash": r["payload_hash"],
        "payload_summary": r["payload_summary"],
        "prev_hash": r["prev_hash"],
        "record_id": r["record_id"],
        "seq": r["seq"],
    }


def compute_research_record_hash(r: Dict[str, Any]) -> str:
    return hash_canonical(DOMAIN_RESEARCH_RECORD, research_record_signing_payload(r))


def compute_research_history_root(records: List[Dict[str, Any]]) -> str:
    return merkle_root_rfc6962([r["record_hash"] for r in records])


def compute_policy_hash(p: Dict[str, Any]) -> str:
    return hash_canonical(
        DOMAIN_POLICY_MANIFEST,
        {
            "ai_agent_boundaries": p["ai_agent_boundaries"],
            "allowed_licenses": p.get("allowed_licenses") or [],
            "authorized_principals": p.get("authorized_principals") or [],
            "conservation_tithe_bps": p["conservation_tithe_bps"],
            "min_accuracy_gain_bps": p["min_accuracy_gain_bps"],
            "min_council_approvals": p["min_council_approvals"],
            "min_safety_bps": p["min_safety_bps"],
            "org_id": p["org_id"],
            "policy_version": p["policy_version"],
            "treasury_spend_limit_micro": p["treasury_spend_limit_micro"],
            "voting_quorum_bps": p["voting_quorum_bps"],
        },
    )


def compute_acl_policy_hash(a: Dict[str, Any]) -> str:
    return hash_canonical(
        DOMAIN_ACL_POLICY,
        {
            "cross_org_delegations": a.get("cross_org_delegations") or [],
            "default_tier": a["default_tier"],
            "grants": a.get("grants") or [],
            "org_id": a["org_id"],
            "require_key_rotation": a["require_key_rotation"],
            "strip_tiers_on_fork": a.get("strip_tiers_on_fork") or [],
        },
    )


def governance_action_signing_payload(g: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "action_id": g["action_id"],
        "action_type": g["action_type"],
        "amount_micro": g["amount_micro"],
        "epoch": g["epoch"],
        "org_id": g["org_id"],
        "payload_hash": g["payload_hash"],
        "payload_summary": g["payload_summary"],
        "proposer_id": g["proposer_id"],
    }


def advisory_proposal_signing_payload(a: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "agent_id": a["agent_id"],
        "binding": a["binding"],
        "conflict_flags": a.get("conflict_flags") or [],
        "estimated_gain_bps": a["estimated_gain_bps"],
        "kind": a["kind"],
        "org_id": a["org_id"],
        "proposal_id": a["proposal_id"],
        "summary": a["summary"],
        "target_ref": a["target_ref"],
    }


def eval_receipt_signing_payload(e: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "accuracy_bps": e["accuracy_bps"],
        "base_model_hash": e["base_model_hash"],
        "delta_hash": e["delta_hash"],
        "eval_dataset_hash": e["eval_dataset_hash"],
        "evaluator_id": e["evaluator_id"],
        "mean_loss_micro": e["mean_loss_micro"],
        "model_ref_id": e["model_ref_id"],
        "num_samples": e["num_samples"],
        "org_id": e["org_id"],
        "receipt_id": e["receipt_id"],
        "safety_bps": e["safety_bps"],
    }


def fork_attestation_signing_payload(f: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "child_authority_pub_key": f["child_authority_pub_key"],
        "child_org_id": f["child_org_id"],
        "keys_rotated": f["keys_rotated"],
        "parent_org_id": f["parent_org_id"],
        "parent_snapshot_hash": f["parent_snapshot_hash"],
        "parent_snapshot_id": f["parent_snapshot_id"],
        "redacted_record_count": f["redacted_record_count"],
        "stripped_grant_count": f["stripped_grant_count"],
    }


def org_snapshot_signing_payload(s: Dict[str, Any]) -> Dict[str, Any]:
    fork_att = s.get("fork_attestation")
    fork_att_hash = ""
    if fork_att is not None:
        fork_att_hash = hash_canonical(
            DOMAIN_FORK_ATTESTATION, fork_attestation_signing_payload(fork_att)
        )
    return {
        "acl_policy_hash": s["acl_policy"]["acl_policy_hash"],
        "active_delta_id": s["model_registry"]["active_delta_id"],
        "epoch": s["epoch"],
        "fork_ancestor_snapshot_hash": s["fork_ancestor_snapshot_hash"],
        "fork_attestation_hash": fork_att_hash,
        "inherited_parent_root": s["research_history"]["inherited_parent_root"],
        "model_registry_root": s["model_registry"]["model_registry_root"],
        "org_id": s["org_id"],
        "parent_snapshot_hash": s["parent_snapshot_hash"],
        "policy_hash": s["policy_manifest"]["policy_hash"],
        "research_merkle_root": s["research_history"]["research_merkle_root"],
        "snapshot_id": s["snapshot_id"],
    }


def compute_org_snapshot_hash(s: Dict[str, Any]) -> str:
    return hash_canonical(DOMAIN_ORG_SNAPSHOT, org_snapshot_signing_payload(s))


def exchange_bundle_signing_payload(b: Dict[str, Any]) -> Dict[str, Any]:
    research_hashes = [r["record_hash"] for r in (b.get("supporting_research") or [])]
    return {
        "bundle_id": b["bundle_id"],
        "eval_receipt_hash": hash_canonical(
            DOMAIN_EVAL_RECEIPT, eval_receipt_signing_payload(b["evaluation_receipt"])
        ),
        "exported_delta_hash": b["exported_delta"]["delta_hash"],
        "fork_ancestor_snapshot_hash": b["fork_ancestor_snapshot_hash"],
        "license_manifest": b.get("license_manifest") or [],
        "lineage_chain": b.get("lineage_chain") or [],
        "merge_step_bps": b["merge_step_bps"],
        "redaction_attestation": b["redaction_attestation"],
        "source_org_id": b["source_org_id"],
        "source_snapshot_hash": b["source_snapshot_hash"],
        "supporting_research_hashes": research_hashes,
        "target_org_id": b["target_org_id"],
    }


def compute_exchange_bundle_hash(b: Dict[str, Any]) -> str:
    return hash_canonical(DOMAIN_EXCHANGE_BUNDLE, exchange_bundle_signing_payload(b))


def verify_governance_action(action: Dict[str, Any], policy: Dict[str, Any]) -> Tuple[bool, str]:
    if action["org_id"] != policy["org_id"]:
        return False, ERR_CROSS_ORG_REPLAY
    proposer = _find_principal(policy, action["proposer_id"])
    if proposer is None:
        return False, ERR_UNAUTHORIZED_SIGNER
    if proposer["role"] == ROLE_AI_AGENT:
        bounds = policy["ai_agent_boundaries"]
        if action["action_type"] == ACTION_UPDATE_VOTING_RULES and bounds["forbid_voting_rule_mutation"]:
            return False, ERR_AI_VOTING_RULE_FORBIDDEN
        if action["action_type"] == ACTION_AUTHORIZE_TREASURY_SPEND and bounds["forbid_treasury_authorization"]:
            return False, ERR_AI_TREASURY_FORBIDDEN
        return False, ERR_UNAUTHORIZED_SIGNER

    payload = governance_action_signing_payload(action)
    seen = set()
    valid_council = 0
    for sig in action.get("signatures") or []:
        signer = _find_principal(policy, sig["signer_id"])
        if signer is None:
            return False, ERR_UNAUTHORIZED_SIGNER
        if signer["org_id"] != policy["org_id"]:
            return False, ERR_CROSS_ORG_REPLAY
        if signer["role"] == ROLE_AI_AGENT:
            if action["action_type"] == ACTION_UPDATE_VOTING_RULES:
                return False, ERR_AI_VOTING_RULE_FORBIDDEN
            if action["action_type"] == ACTION_AUTHORIZE_TREASURY_SPEND:
                return False, ERR_AI_TREASURY_FORBIDDEN
            return False, ERR_UNAUTHORIZED_SIGNER
        if signer["role"] != ROLE_HUMAN_COUNCIL:
            return False, ERR_UNAUTHORIZED_SIGNER
        if not _verify_canonical_sig(
            signer["public_key_hex"], sig["signature_hex"], DOMAIN_GOVERNANCE_ACTION, payload
        ):
            return False, ERR_INVALID_SIGNATURE
        if signer["id"] not in seen:
            seen.add(signer["id"])
            valid_council += 1

    if valid_council < policy["min_council_approvals"]:
        return False, ERR_INSUFFICIENT_QUORUM
    return True, ERR_OK


def verify_advisory_proposal(prop: Dict[str, Any], policy: Dict[str, Any]) -> Tuple[bool, str]:
    if prop["org_id"] != policy["org_id"]:
        return False, ERR_CROSS_ORG_REPLAY
    if prop["binding"]:
        return False, ERR_AI_BINDING_PROPOSAL_FORBIDDEN
    agent = _find_principal(policy, prop["agent_id"])
    if agent is None or agent["role"] != ROLE_AI_AGENT:
        return False, ERR_UNAUTHORIZED_SIGNER
    if not _verify_canonical_sig(
        agent["public_key_hex"],
        prop["signature_hex"],
        DOMAIN_ADVISORY_PROPOSAL,
        advisory_proposal_signing_payload(prop),
    ):
        return False, ERR_INVALID_SIGNATURE
    return True, ERR_OK


def verify_fork_boundary(parent: Dict[str, Any], child: Dict[str, Any]) -> Tuple[bool, str]:
    att = child.get("fork_attestation")
    if att is None:
        return False, ERR_LINEAGE_BROKEN
    if (
        child["parent_snapshot_hash"] != parent["snapshot_hash"]
        or child["fork_ancestor_snapshot_hash"] != parent["snapshot_hash"]
        or att["parent_snapshot_hash"] != parent["snapshot_hash"]
        or att["parent_org_id"] != parent["org_id"]
        or att["child_org_id"] != child["org_id"]
    ):
        return False, ERR_LINEAGE_BROKEN

    # 1. Key rotation enforcement.
    if not att["keys_rotated"]:
        return False, ERR_KEY_ROTATION_REQUIRED
    parent_keys = {p["public_key_hex"] for p in parent["policy_manifest"]["authorized_principals"]}
    for p in child["policy_manifest"]["authorized_principals"]:
        if p["public_key_hex"] in parent_keys:
            return False, ERR_KEY_ROTATION_REQUIRED

    # 2. Zero ACL leak in records.
    for r in child["research_history"]["records"]:
        if r["acl_tier"] == TIER_RESTRICTED:
            return False, ERR_ACL_LEAK_RESTRICTED
        if r["parent_slot_index"] >= 0 and r["acl_tier"] != TIER_PUBLIC:
            return False, ERR_ACL_LEAK_RESTRICTED

    # 3. Zero ACL leak in grants and rotated token hashes.
    parent_tokens = {g["org_scoped_token_hash"] for g in parent["acl_policy"]["grants"]}
    for g in child["acl_policy"]["grants"]:
        if g["tier"] == TIER_RESTRICTED or not g["inheritable_on_fork"] or g["tier"] != TIER_PUBLIC:
            return False, ERR_ACL_LEAK_GRANT
        if g["org_scoped_token_hash"] in parent_tokens:
            return False, ERR_ACL_LEAK_GRANT

    # 4. Cryptographic RedactionTombstone RFC 6962 Merkle proof reconstruction.
    total_slots = len(parent["research_history"]["records"])
    tombstones = child["research_history"]["redaction_tombstones"]
    if (
        child["research_history"]["parent_total_slots"] != total_slots
        or child["research_history"]["inherited_parent_root"] != parent["research_history"]["research_merkle_root"]
        or len(tombstones) != att["redacted_record_count"]
    ):
        return False, ERR_REDACTION_PROOF_INVALID

    reconstructed: List[Optional[str]] = [None] * total_slots
    for r in child["research_history"]["records"]:
        slot = r["parent_slot_index"]
        if slot >= 0:
            if slot >= total_slots or reconstructed[slot] is not None:
                return False, ERR_REDACTION_PROOF_INVALID
            reconstructed[slot] = r["record_hash"]
    for t in tombstones:
        slot = t["slot_index"]
        if slot < 0 or slot >= total_slots or reconstructed[slot] is not None:
            return False, ERR_REDACTION_PROOF_INVALID
        if not t["original_leaf_hash"] or not t["commitment_salt_hash"]:
            return False, ERR_REDACTION_PROOF_INVALID
        reconstructed[slot] = t["original_leaf_hash"]

    if any(leaf is None for leaf in reconstructed):
        return False, ERR_REDACTION_PROOF_INVALID
    if merkle_root_rfc6962([str(x) for x in reconstructed]) != parent["research_history"]["research_merkle_root"]:
        return False, ERR_REDACTION_PROOF_INVALID

    # 5. ForkAttestation child council quorum signatures.
    att_payload = fork_attestation_signing_payload(att)
    seen = set()
    valid_council = 0
    for sig in att.get("child_council_sigs") or []:
        signer = _find_principal(child["policy_manifest"], sig["signer_id"])
        if signer is None or signer["role"] != ROLE_HUMAN_COUNCIL:
            return False, ERR_UNAUTHORIZED_SIGNER
        if not _verify_canonical_sig(
            signer["public_key_hex"], sig["signature_hex"], DOMAIN_FORK_ATTESTATION, att_payload
        ):
            return False, ERR_INVALID_SIGNATURE
        if signer["id"] not in seen:
            seen.add(signer["id"])
            valid_council += 1
    if valid_council < child["policy_manifest"]["min_council_approvals"]:
        return False, ERR_INSUFFICIENT_QUORUM

    return True, ERR_OK


def verify_org_snapshot(
    snap: Dict[str, Any], parent_for_fork: Optional[Dict[str, Any]] = None
) -> Tuple[bool, str]:
    if compute_policy_hash(snap["policy_manifest"]) != snap["policy_manifest"]["policy_hash"]:
        return False, ERR_POLICY_HASH_MISMATCH
    if compute_acl_policy_hash(snap["acl_policy"]) != snap["acl_policy"]["acl_policy_hash"]:
        return False, ERR_POLICY_HASH_MISMATCH
    if compute_base_model_hash(snap["model_registry"]["base_model"]) != snap["model_registry"]["base_model"]["weights_hash"]:
        return False, ERR_DELTA_HASH_MISMATCH

    for d in snap["model_registry"]["deltas"]:
        if compute_bitdelta_hash(d) != d["delta_hash"]:
            return False, ERR_DELTA_HASH_MISMATCH
        if d["org_id"] == snap["org_id"]:
            signer = _find_principal(snap["policy_manifest"], d["contributor_id"])
            if signer is None:
                return False, ERR_UNAUTHORIZED_SIGNER
            if not _verify_canonical_sig(
                signer["public_key_hex"], d["signature_hex"], DOMAIN_BITDELTA, bitdelta_signing_payload(d)
            ):
                return False, ERR_INVALID_SIGNATURE

    for s in snap["model_registry"]["soups"]:
        if compute_bitdelta_hash(s["result_delta"]) != s["result_delta"]["delta_hash"]:
            return False, ERR_DELTA_HASH_MISMATCH
        if compute_deltasoup_hash(s) != s["soup_hash"]:
            return False, ERR_DELTA_HASH_MISMATCH

    if compute_model_registry_root(snap["model_registry"]) != snap["model_registry"]["model_registry_root"]:
        return False, ERR_MERKLE_ROOT_MISMATCH

    records = snap["research_history"]["records"]
    for i, r in enumerate(records):
        if compute_research_record_hash(r) != r["record_hash"]:
            return False, ERR_HISTORY_CHAIN_BROKEN
        if r["parent_slot_index"] < 0:
            if i == 0:
                if r["prev_hash"] != "":
                    return False, ERR_HISTORY_CHAIN_BROKEN
            else:
                if r["prev_hash"] != records[i - 1]["record_hash"]:
                    return False, ERR_HISTORY_CHAIN_BROKEN
            author = _find_principal(snap["policy_manifest"], r["author_id"])
            if author is None:
                return False, ERR_UNAUTHORIZED_SIGNER
            if not _verify_canonical_sig(
                author["public_key_hex"], r["signature_hex"], DOMAIN_RESEARCH_RECORD, research_record_signing_payload(r)
            ):
                return False, ERR_INVALID_SIGNATURE

    if compute_research_history_root(records) != snap["research_history"]["research_merkle_root"]:
        return False, ERR_MERKLE_ROOT_MISMATCH

    if compute_org_snapshot_hash(snap) != snap["snapshot_hash"]:
        return False, ERR_SNAPSHOT_HASH_MISMATCH

    snap_payload = org_snapshot_signing_payload(snap)
    seen = set()
    valid_council = 0
    for sig in snap.get("council_signatures") or []:
        signer = _find_principal(snap["policy_manifest"], sig["signer_id"])
        if signer is None or signer["role"] != ROLE_HUMAN_COUNCIL:
            return False, ERR_UNAUTHORIZED_SIGNER
        if signer["org_id"] != snap["org_id"]:
            return False, ERR_CROSS_ORG_REPLAY
        if not _verify_canonical_sig(
            signer["public_key_hex"], sig["signature_hex"], DOMAIN_ORG_SNAPSHOT, snap_payload
        ):
            return False, ERR_INVALID_SIGNATURE
        if signer["id"] not in seen:
            seen.add(signer["id"])
            valid_council += 1
    if valid_council < snap["policy_manifest"]["min_council_approvals"]:
        return False, ERR_INSUFFICIENT_QUORUM

    for ga in snap.get("governance_actions") or []:
        ok, code = verify_governance_action(ga, snap["policy_manifest"])
        if not ok:
            return False, code
    for ap in snap.get("advisory_proposals") or []:
        ok, code = verify_advisory_proposal(ap, snap["policy_manifest"])
        if not ok:
            return False, code

    if parent_for_fork is not None:
        return verify_fork_boundary(parent_for_fork, snap)
    return True, ERR_OK


def _find_active_delta(registry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    active_id = registry.get("active_delta_id", "")
    if not active_id:
        return None
    for d in registry.get("deltas") or []:
        if d["delta_id"] == active_id:
            return d
    return None


def evaluate_snapshot_head(snap: Dict[str, Any], ds: Dict[str, Any]) -> Dict[str, int]:
    weights = snap["model_registry"]["base_model"]["weights_micro"]
    active = _find_active_delta(snap["model_registry"])
    if active is not None:
        weights = apply_bitdelta(weights, active)
    return evaluate_model(weights, ds)


def _has_valid_delegation(
    acl: Dict[str, Any], target_org_id: str, resource_id: str, source_policy: Dict[str, Any]
) -> bool:
    for d in acl.get("cross_org_delegations") or []:
        if (
            d["to_org_id"] == target_org_id
            and d["resource_id"] == resource_id
            and not d["revoked"]
            and d["tier"] == TIER_INTERNAL
        ):
            signer = _find_principal(source_policy, d["signer_id"])
            if signer is None or signer["role"] != ROLE_HUMAN_COUNCIL:
                continue
            payload = {
                "delegation_id": d["delegation_id"],
                "from_org_id": d["from_org_id"],
                "resource_id": d["resource_id"],
                "revoked": d["revoked"],
                "signer_id": d["signer_id"],
                "tier": d["tier"],
                "to_org_id": d["to_org_id"],
            }
            if _verify_canonical_sig(
                signer["public_key_hex"], d["signature_hex"], DOMAIN_ACL_POLICY, payload
            ):
                return True
    return False


def verify_exchange_bundle(
    bundle: Dict[str, Any],
    source_snap: Dict[str, Any],
    target_snap: Dict[str, Any],
    ds: Dict[str, Any],
) -> Tuple[bool, str, Dict[str, int], int]:
    empty_metrics = {"accuracy_bps": 0, "mean_loss_micro": 0, "safety_bps": 0, "num_samples": 0}

    if compute_exchange_bundle_hash(bundle) != bundle["bundle_hash"]:
        return False, ERR_BUNDLE_HASH_MISMATCH, empty_metrics, 0

    if (
        bundle["source_org_id"] != source_snap["org_id"]
        or bundle["target_org_id"] != target_snap["org_id"]
        or bundle["source_org_id"] == bundle["target_org_id"]
        or bundle["exported_delta"]["org_id"] != source_snap["org_id"]
        or bundle["target_adoption_action"]["org_id"] != target_snap["org_id"]
        or bundle["target_adoption_action"]["payload_hash"] != bundle["bundle_hash"]
    ):
        return False, ERR_CROSS_ORG_REPLAY, empty_metrics, 0

    exp_delta = bundle["exported_delta"]
    if compute_bitdelta_hash(exp_delta) != exp_delta["delta_hash"]:
        return False, ERR_DELTA_HASH_MISMATCH, empty_metrics, 0

    contrib = _find_principal(source_snap["policy_manifest"], exp_delta["contributor_id"])
    if contrib is None:
        return False, ERR_UNAUTHORIZED_SIGNER, empty_metrics, 0
    if not _verify_canonical_sig(
        contrib["public_key_hex"], exp_delta["signature_hex"], DOMAIN_BITDELTA, bitdelta_signing_payload(exp_delta)
    ):
        return False, ERR_INVALID_SIGNATURE, empty_metrics, 0

    bundle_payload = exchange_bundle_signing_payload(bundle)
    seen_src = set()
    valid_src = 0
    for sig in bundle.get("source_export_signatures") or []:
        signer = _find_principal(source_snap["policy_manifest"], sig["signer_id"])
        if signer is None or signer["role"] != ROLE_HUMAN_COUNCIL:
            return False, ERR_UNAUTHORIZED_SIGNER, empty_metrics, 0
        if signer["org_id"] != source_snap["org_id"]:
            return False, ERR_CROSS_ORG_REPLAY, empty_metrics, 0
        if not _verify_canonical_sig(
            signer["public_key_hex"], sig["signature_hex"], DOMAIN_EXCHANGE_BUNDLE, bundle_payload
        ):
            return False, ERR_INVALID_SIGNATURE, empty_metrics, 0
        if signer["id"] not in seen_src:
            seen_src.add(signer["id"])
            valid_src += 1
    if valid_src < source_snap["policy_manifest"]["min_council_approvals"]:
        return False, ERR_INSUFFICIENT_QUORUM, empty_metrics, 0

    # Common-ancestor lineage & base compatibility.
    chain = bundle.get("lineage_chain") or []
    fork_anc = bundle["fork_ancestor_snapshot_hash"]
    if not fork_anc or not chain:
        return False, ERR_LINEAGE_BROKEN, empty_metrics, 0
    if (
        target_snap["model_registry"]["base_model"]["model_id"] != exp_delta["base_model_id"]
        or target_snap["model_registry"]["base_model"]["weights_hash"]
        != source_snap["model_registry"]["base_model"]["weights_hash"]
    ):
        return False, ERR_LINEAGE_BROKEN, empty_metrics, 0

    target_matches_anc = (
        target_snap["fork_ancestor_snapshot_hash"] == fork_anc
        or target_snap["snapshot_hash"] == fork_anc
        or target_snap["parent_snapshot_hash"] == fork_anc
    )
    if not target_matches_anc:
        return False, ERR_LINEAGE_BROKEN, empty_metrics, 0

    if chain[0]["snapshot_hash"] != fork_anc and chain[0]["parent_snapshot_hash"] != fork_anc:
        return False, ERR_LINEAGE_BROKEN, empty_metrics, 0
    for i in range(1, len(chain)):
        if chain[i]["parent_snapshot_hash"] != chain[i - 1]["snapshot_hash"]:
            return False, ERR_LINEAGE_BROKEN, empty_metrics, 0
    if chain[-1]["snapshot_hash"] != bundle["source_snapshot_hash"] or bundle["source_snapshot_hash"] != source_snap["snapshot_hash"]:
        return False, ERR_LINEAGE_BROKEN, empty_metrics, 0

    # Zero ACL leak / restricted taint propagation check.
    if not bundle["redaction_attestation"]["restricted_taint_free"] or exp_delta["acl_tier"] != TIER_PUBLIC:
        return False, ERR_ACL_TAINT_RESTRICTED, empty_metrics, 0

    support_by_id: Dict[str, Dict[str, Any]] = {}
    for r in bundle.get("supporting_research") or []:
        if compute_research_record_hash(r) != r["record_hash"]:
            return False, ERR_HISTORY_CHAIN_BROKEN, empty_metrics, 0
        if r["acl_tier"] == TIER_RESTRICTED:
            return False, ERR_ACL_TAINT_RESTRICTED, empty_metrics, 0
        if r["acl_tier"] == TIER_INTERNAL and not _has_valid_delegation(
            source_snap["acl_policy"], target_snap["org_id"], r["record_id"], source_snap["policy_manifest"]
        ):
            return False, ERR_ACL_TAINT_RESTRICTED, empty_metrics, 0
        support_by_id[r["record_id"]] = r

    source_rec_by_id = {r["record_id"]: r for r in source_snap["research_history"]["records"]}
    for rid in exp_delta.get("training_record_ids") or []:
        if rid not in support_by_id:
            return False, ERR_ACL_TAINT_RESTRICTED, empty_metrics, 0
        if rid in source_rec_by_id:
            src_rec = source_rec_by_id[rid]
            if src_rec["acl_tier"] == TIER_RESTRICTED or src_rec["record_hash"] != support_by_id[rid]["record_hash"]:
                return False, ERR_ACL_TAINT_RESTRICTED, empty_metrics, 0

    # License compatibility & review gate.
    target_policy = target_snap["policy_manifest"]
    if not exp_delta["license_reviewed"] or not _is_license_allowed(target_policy, exp_delta["license_id"]):
        return False, ERR_LICENSE_INCOMPATIBLE, empty_metrics, 0
    lic_manifest = bundle.get("license_manifest") or []
    if not lic_manifest:
        return False, ERR_LICENSE_INCOMPATIBLE, empty_metrics, 0
    for le in lic_manifest:
        if not le["license_reviewed"] or not _is_license_allowed(target_policy, le["license_id"]):
            return False, ERR_LICENSE_INCOMPATIBLE, empty_metrics, 0
    for r in bundle.get("supporting_research") or []:
        if not r["license_reviewed"] or not _is_license_allowed(target_policy, r["license_id"]):
            return False, ERR_LICENSE_INCOMPATIBLE, empty_metrics, 0

    # Independent evaluator signature & anti-self-certification check.
    rec = bundle["evaluation_receipt"]
    eval_principal = _find_principal(source_snap["policy_manifest"], rec["evaluator_id"])
    if eval_principal is None:
        eval_principal = _find_principal(target_policy, rec["evaluator_id"])
    if eval_principal is None:
        return False, ERR_UNAUTHORIZED_SIGNER, empty_metrics, 0
    if eval_principal["role"] == ROLE_AI_AGENT or rec["evaluator_id"] == exp_delta["contributor_id"]:
        return False, ERR_AI_SELF_CERTIFY_FORBIDDEN, empty_metrics, 0
    if eval_principal["role"] != ROLE_EVALUATOR:
        return False, ERR_UNAUTHORIZED_SIGNER, empty_metrics, 0
    if not _verify_canonical_sig(
        eval_principal["public_key_hex"], rec["signature_hex"], DOMAIN_EVAL_RECEIPT, eval_receipt_signing_payload(rec)
    ):
        return False, ERR_INVALID_SIGNATURE, empty_metrics, 0
    if (
        rec["delta_hash"] != exp_delta["delta_hash"]
        or rec["base_model_hash"] != target_snap["model_registry"]["base_model"]["weights_hash"]
        or rec["eval_dataset_hash"] != ds["dataset_hash"]
    ):
        return False, ERR_EVAL_REPLAY_MISMATCH, empty_metrics, 0

    # Target council governance adoption approval.
    ok_gov, gov_code = verify_governance_action(bundle["target_adoption_action"], target_policy)
    if not ok_gov:
        return False, gov_code, empty_metrics, 0

    # Independent deterministic re-evaluation & improvement/safety gate.
    base_weights = target_snap["model_registry"]["base_model"]["weights_micro"]
    try:
        exported_weights = apply_bitdelta(base_weights, exp_delta)
    except ValueError:
        return False, ERR_DELTA_HASH_MISMATCH, empty_metrics, 0
    replayed_export = evaluate_model(exported_weights, ds)
    if (
        replayed_export["accuracy_bps"] != rec["accuracy_bps"]
        or replayed_export["mean_loss_micro"] != rec["mean_loss_micro"]
        or replayed_export["safety_bps"] != rec["safety_bps"]
        or replayed_export["num_samples"] != rec["num_samples"]
    ):
        return False, ERR_EVAL_REPLAY_MISMATCH, replayed_export, 0

    target_head_metrics = evaluate_snapshot_head(target_snap, ds)
    local_delta = _find_active_delta(target_snap["model_registry"])
    raw_merged = merge_cross_fork_weights(base_weights, local_delta, exp_delta, int(bundle["merge_step_bps"]))
    merged_sign, merged_scale = compress_bitdelta(base_weights, raw_merged)
    merged_weights = apply_bitdelta(
        base_weights,
        {
            "dim": target_snap["model_registry"]["base_model"]["dim"],
            "sign_bits_hex": merged_sign,
            "scale_micro": merged_scale,
        },
    )
    merged_metrics = evaluate_model(merged_weights, ds)

    gain_bps = merged_metrics["accuracy_bps"] - target_head_metrics["accuracy_bps"]
    if merged_metrics["safety_bps"] < target_policy["min_safety_bps"]:
        return False, ERR_SAFETY_FLOOR_VIOLATION, merged_metrics, gain_bps
    if (
        gain_bps < target_policy["min_accuracy_gain_bps"]
        or merged_metrics["mean_loss_micro"] >= target_head_metrics["mean_loss_micro"]
    ):
        return False, ERR_QUALITY_REGRESSION, merged_metrics, gain_bps

    return True, ERR_OK, merged_metrics, gain_bps


def verify_adversarial_case(case: Dict[str, Any], ds: Dict[str, Any]) -> Dict[str, Any]:
    target = case["target_check"]
    if target == "snapshot":
        valid, code = verify_org_snapshot(case["snapshot"], case.get("parent_snapshot"))
    elif target == "fork":
        valid, code = verify_org_snapshot(case["snapshot"], case["parent_snapshot"])
    elif target == "exchange":
        valid, code, _, _ = verify_exchange_bundle(
            case["exchange_bundle"], case["source_snapshot"], case["target_snapshot"], ds
        )
    elif target == "governance":
        valid, code = verify_governance_action(case["governance_action"], case["policy_context"])
    elif target == "advisory":
        valid, code = verify_advisory_proposal(case["advisory_proposal"], case["policy_context"])
    else:
        valid, code = False, f"ERR_UNKNOWN_TARGET_{target}"

    expected_valid = bool(case["expected_valid"])
    expected_code = str(case["expected_code"])
    return {
        "case_id": case["case_id"],
        "category": case["category"],
        "expected_valid": expected_valid,
        "actual_valid": valid,
        "expected_code": expected_code,
        "actual_code": code,
        "matched": (valid == expected_valid and code == expected_code),
    }


def compute_audit_merkle_root(
    workflow: List[Dict[str, Any]], adv: List[Dict[str, Any]]
) -> str:
    leaves: List[str] = []
    for w in workflow:
        leaves.append(
            hash_canonical(
                DOMAIN_AUDIT_LEAF,
                {
                    "accuracy_bps": w["accuracy_bps"],
                    "code": w["code"],
                    "delta_gain_bps": w["delta_gain_bps"],
                    "kind": "workflow",
                    "mean_loss_micro": w["mean_loss_micro"],
                    "safety_bps": w["safety_bps"],
                    "stage": w["stage"],
                    "valid": w["valid"],
                },
            )
        )
    for c in sorted(adv, key=lambda item: item["case_id"]):
        leaves.append(
            hash_canonical(
                DOMAIN_AUDIT_LEAF,
                {
                    "actual_code": c["actual_code"],
                    "actual_valid": c["actual_valid"],
                    "case_id": c["case_id"],
                    "category": c["category"],
                    "expected_code": c["expected_code"],
                    "expected_valid": c["expected_valid"],
                    "kind": "adversarial",
                    "matched": c["matched"],
                },
            )
        )
    return merkle_root_rfc6962(leaves)


def verify_suite(suite: Dict[str, Any]) -> Dict[str, Any]:
    ds = suite["eval_dataset"]
    workflow: List[Dict[str, Any]] = []

    def add_snap_stage(
        stage: str, snap: Dict[str, Any], parent: Optional[Dict[str, Any]], prev_acc: int
    ) -> int:
        ok, code = verify_org_snapshot(snap, parent)
        m = evaluate_snapshot_head(snap, ds)
        gain = m["accuracy_bps"] - prev_acc if prev_acc > 0 else 0
        workflow.append(
            {
                "stage": stage,
                "valid": ok,
                "code": code,
                "accuracy_bps": m["accuracy_bps"],
                "mean_loss_micro": m["mean_loss_micro"],
                "safety_bps": m["safety_bps"],
                "delta_gain_bps": gain,
            }
        )
        return m["accuracy_bps"]

    base_acc = add_snap_stage("1_org_a_base_snap_0", suite["org_a_snap_0"], None, 0)
    org_a1_acc = add_snap_stage("2_org_a_pre_fork_snap_1", suite["org_a_snap_1"], None, base_acc)
    org_b_fork_acc = add_snap_stage(
        "3_org_b_fork_boundary_snap_1", suite["org_b_fork_snap_1"], suite["org_a_snap_1"], org_a1_acc
    )
    org_a2_acc = add_snap_stage("4_org_a_diverged_snap_2", suite["org_a_diverged_snap_2"], None, org_a1_acc)
    org_b2_acc = add_snap_stage(
        "5_org_b_diverged_deltasoup_snap_2", suite["org_b_diverged_snap_2"], None, org_b_fork_acc
    )

    ok_ba, code_ba, m_ba, gain_ba = verify_exchange_bundle(
        suite["bundle_b_to_a"], suite["org_b_diverged_snap_2"], suite["org_a_diverged_snap_2"], ds
    )
    workflow.append(
        {
            "stage": "6_exchange_verify_org_b_to_org_a",
            "valid": ok_ba,
            "code": code_ba,
            "accuracy_bps": m_ba["accuracy_bps"],
            "mean_loss_micro": m_ba["mean_loss_micro"],
            "safety_bps": m_ba["safety_bps"],
            "delta_gain_bps": gain_ba,
        }
    )
    add_snap_stage("7_org_a_adopted_snap_3", suite["org_a_adopted_snap_3"], None, org_a2_acc)

    ok_ab, code_ab, m_ab, gain_ab = verify_exchange_bundle(
        suite["bundle_a_to_b"], suite["org_a_diverged_snap_2"], suite["org_b_diverged_snap_2"], ds
    )
    workflow.append(
        {
            "stage": "8_exchange_verify_org_a_to_org_b",
            "valid": ok_ab,
            "code": code_ab,
            "accuracy_bps": m_ab["accuracy_bps"],
            "mean_loss_micro": m_ab["mean_loss_micro"],
            "safety_bps": m_ab["safety_bps"],
            "delta_gain_bps": gain_ab,
        }
    )
    add_snap_stage("9_org_b_adopted_snap_3", suite["org_b_adopted_snap_3"], None, org_b2_acc)

    all_workflow = all(w["valid"] for w in workflow)

    adv_outcomes: List[Dict[str, Any]] = []
    all_adv_matched = True
    adv_total = 0
    adv_caught = 0
    for c in suite["adversarial_cases"]:
        out = verify_adversarial_case(c, ds)
        adv_outcomes.append(out)
        if not out["matched"]:
            all_adv_matched = False
        if not c["expected_valid"]:
            adv_total += 1
            if (not out["actual_valid"]) and out["actual_code"] == c["expected_code"]:
                adv_caught += 1

    return {
        "schema_version": SCHEMA_VERSION,
        "spec_version": SPEC_VERSION,
        "seed": suite["seed"],
        "eval_dataset_hash": ds["dataset_hash"],
        "all_workflow_passed": all_workflow,
        "all_adversarial_matched": all_adv_matched,
        "workflow_checks": workflow,
        "adversarial_outcomes": adv_outcomes,
        "adversarial_total": adv_total,
        "adversarial_caught": adv_caught,
        "audit_merkle_root": compute_audit_merkle_root(workflow, adv_outcomes),
    }

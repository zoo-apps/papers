# SPDX-License-Identifier: Apache-2.0
"""Deterministic canonical JSON serialization, SHA-256 identity, and Ed25519 signing."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .ed25519 import ed25519_sign

SCHEMA_VERSION = "zoo-experience-ledger/v1"
SIGNING_DOMAIN_EVENT = "zoo-experience-ledger/v1:event:"
EMPTY_MERKLE_DOMAIN = "zoo-experience-ledger/v1:empty-merkle"


def canonical_json(obj: Any) -> bytes:
    """Encode obj to deterministic compact UTF-8 JSON with sorted keys and no HTML escaping.

    Matches Go's ledger.CanonicalJSON byte-for-byte.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Return lowercase hex SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def compute_policy_sha256(policy: dict[str, Any]) -> str:
    """Compute canonical SHA-256 hash of a Policy (excluding policy_sha256)."""
    principals = [
        {
            "principal_id": pr["principal_id"],
            "role": pr["role"],
            "public_key_hex": pr["public_key_hex"],
            "active": pr["active"],
        }
        for pr in policy["principals"]
    ]
    body = {
        "schema_version": policy["schema_version"],
        "policy_id": policy["policy_id"],
        "principals": principals,
    }
    return sha256_hex(canonical_json(body))


def unsigned_event_map(event: dict[str, Any]) -> dict[str, Any]:
    """Extract the canonical unsigned payload map for a ledger event."""
    et = event.get("event_type")
    if et == "experience_entry":
        return {
            "schema_version": event.get("schema_version", ""),
            "event_type": et,
            "contributor_id": event.get("contributor_id", ""),
            "domain": event.get("domain", ""),
            "claim_key": event.get("claim_key", ""),
            "claim_value_hash": event.get("claim_value_hash", ""),
            "summary": event.get("summary", ""),
            "confidence_bps": event.get("confidence_bps", 0),
            "artifact_sha256": event.get("artifact_sha256", ""),
            "artifact_uri": event.get("artifact_uri", ""),
            "artifact_size_bytes": event.get("artifact_size_bytes", 0),
            "external_uris": list(event.get("external_uris") or []),
            "parent_hashes": list(event.get("parent_hashes") or []),
            "receipt_hash": event.get("receipt_hash", ""),
            "created_at_unix": event.get("created_at_unix", 0),
            "nonce": event.get("nonce", ""),
        }
    if et == "revocation_record":
        return {
            "schema_version": event.get("schema_version", ""),
            "event_type": et,
            "issuer_id": event.get("issuer_id", ""),
            "target_event_id": event.get("target_event_id", ""),
            "reason_code": event.get("reason_code", ""),
            "reason": event.get("reason", ""),
            "evidence_sha256": event.get("evidence_sha256", ""),
            "evidence_uri": event.get("evidence_uri", ""),
            "created_at_unix": event.get("created_at_unix", 0),
        }
    if et == "conflict_flag":
        return {
            "schema_version": event.get("schema_version", ""),
            "event_type": et,
            "flagger_id": event.get("flagger_id", ""),
            "domain": event.get("domain", ""),
            "claim_key": event.get("claim_key", ""),
            "conflicting_event_ids": list(event.get("conflicting_event_ids") or []),
            "evidence_sha256": event.get("evidence_sha256", ""),
            "evidence_uri": event.get("evidence_uri", ""),
            "rationale": event.get("rationale", ""),
            "created_at_unix": event.get("created_at_unix", 0),
        }
    if et == "resolution_decision":
        return {
            "schema_version": event.get("schema_version", ""),
            "event_type": et,
            "steward_id": event.get("steward_id", ""),
            "domain": event.get("domain", ""),
            "claim_key": event.get("claim_key", ""),
            "reviewed_event_ids": list(event.get("reviewed_event_ids") or []),
            "outcome": event.get("outcome", ""),
            "winning_event_id": event.get("winning_event_id", ""),
            "rationale_sha256": event.get("rationale_sha256", ""),
            "rationale_uri": event.get("rationale_uri", ""),
            "governance_ref": event.get("governance_ref", ""),
            "created_at_unix": event.get("created_at_unix", 0),
        }
    raise ValueError(f"unknown event_type: {et!r}")


def compute_event_id(event: dict[str, Any]) -> str:
    """Compute canonical SHA-256 event_id of an event."""
    return sha256_hex(canonical_json(unsigned_event_map(event)))


def signing_message(event_id: str) -> bytes:
    """Return domain-separated signing message bytes for Ed25519."""
    return (SIGNING_DOMAIN_EVENT + event_id).encode("utf-8")


def sign_event(event: dict[str, Any], seed_32: bytes) -> dict[str, Any]:
    """Compute event_id and attach RFC 8032 Ed25519 signature_hex (returns mutated copy)."""
    out = dict(event)
    eid = compute_event_id(out)
    out["event_id"] = eid
    out["signature_hex"] = ed25519_sign(seed_32, signing_message(eid)).hex()
    return out


def compute_state_root_hash(commitment: dict[str, Any]) -> str:
    """Compute canonical SHA-256 state_root_hash over StateCommitment."""
    entries = [
        {
            "event_id": es["event_id"],
            "contributor_id": es["contributor_id"],
            "domain": es["domain"],
            "claim_key": es["claim_key"],
            "claim_value_hash": es["claim_value_hash"],
            "artifact_sha256": es["artifact_sha256"],
            "artifact_uri": es["artifact_uri"],
            "status": es["status"],
            "revoked_by": list(es["revoked_by"]),
            "tainted_by_ancestors": list(es["tainted_by_ancestors"]),
            "unresolved_parents": list(es["unresolved_parents"]),
        }
        for es in commitment["entry_states"]
    ]
    conflicts = [
        {
            "slot": cs["slot"],
            "domain": cs["domain"],
            "claim_key": cs["claim_key"],
            "status": cs["status"],
            "competing_event_ids": list(cs["competing_event_ids"]),
            "flag_ids": list(cs["flag_ids"]),
            "resolution_ids": list(cs["resolution_ids"]),
            "canonical_event_id": cs["canonical_event_id"],
        }
        for cs in commitment["conflicts"]
    ]
    rejected = [
        {
            "event_id": rj["event_id"],
            "event_type": rj["event_type"],
            "error_code": rj["error_code"],
        }
        for rj in commitment["rejected_events"]
    ]
    body = {
        "schema_version": commitment["schema_version"],
        "policy_sha256": commitment["policy_sha256"],
        "active_merkle_root": commitment["active_merkle_root"],
        "entry_states": entries,
        "conflicts": conflicts,
        "pending_revocations": list(commitment["pending_revocations"]),
        "rejected_events": rejected,
    }
    return sha256_hex(canonical_json(body))

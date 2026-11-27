# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.

"""Deterministic canonical JSON, signing preimage, and Merkle audit root."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List


def canonical_json(obj: Any) -> bytes:
    """Serialize obj to compact UTF-8 canonical JSON with sorted keys."""
    text = json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return text.encode("utf-8")


def signing_preimage(action: Dict[str, Any], signer_id: str, nonce: int) -> bytes:
    """Construct the exact domain-separated signing preimage matching Go."""
    scopes = sorted(list(action.get("scopes") or []))
    new_rule_raw = action.get("new_rule")
    if new_rule_raw is not None:
        new_rule: Any = {
            "action_type": new_rule_raw.get("action_type", ""),
            "condition": new_rule_raw.get("condition", ""),
            "effect": new_rule_raw.get("effect", ""),
            "id": new_rule_raw.get("id", ""),
            "rationale": new_rule_raw.get("rationale", ""),
            "target": new_rule_raw.get("target", ""),
            "tier": new_rule_raw.get("tier", ""),
        }
    else:
        new_rule = None

    payload = {
        "action_id": action.get("id", ""),
        "actor_id": action.get("actor_id", ""),
        "amount": int(action.get("amount", 0)),
        "appeal_outcome": action.get("appeal_outcome", ""),
        "contested_id": action.get("contested_id", ""),
        "delegation_id": action.get("delegation_id", ""),
        "duration_sec": int(action.get("duration_sec", 0)),
        "emergency_bypass": bool(action.get("emergency_bypass", False)),
        "epoch": int(action.get("epoch", 0)),
        "experiment_author_id": action.get("experiment_author_id", ""),
        "new_rule": new_rule,
        "nonce": int(nonce),
        "proposal_id": action.get("proposal_id", ""),
        "scopes": scopes,
        "signer_id": signer_id,
        "target": action.get("target", ""),
        "type": action.get("type", ""),
    }
    return b"constitutional-gov.v1:sign:" + canonical_json(payload)


def case_digest(case_obj: Dict[str, Any]) -> str:
    """Compute canonical SHA-256 hex digest of an adversarial case verdict."""
    witness_raw = case_obj.get("conflict_witness")
    if witness_raw is not None:
        witness: Any = {
            "action_id": witness_raw["action_id"],
            "action_type": witness_raw["action_type"],
            "allow_rule_ids": sorted(list(witness_raw["allow_rule_ids"])),
            "deny_rule_ids": sorted(list(witness_raw["deny_rule_ids"])),
            "epoch": int(witness_raw["epoch"]),
            "resolution": witness_raw["resolution"],
            "target": witness_raw["target"],
            "tier": witness_raw["tier"],
        }
    else:
        witness = None

    proj = {
        "actual_error_code": case_obj["actual_error_code"],
        "actual_verdict": case_obj["actual_verdict"],
        "case_id": case_obj["case_id"],
        "conflict_witness": witness,
        "expected_error_code": case_obj["expected_error_code"],
        "expected_verdict": case_obj["expected_verdict"],
        "invariant_id": case_obj["invariant_id"],
        "passed": bool(case_obj["passed"]),
    }
    h = hashlib.sha256()
    h.update(b"constitutional-gov.v1:case:")
    h.update(canonical_json(proj))
    return h.hexdigest()


def audit_merkle_root(cases: List[Dict[str, Any]]) -> str:
    """Compute domain-separated binary SHA-256 Merkle root matching Go bit-for-bit."""
    if not cases:
        return hashlib.sha256(b"constitutional-gov.v1:empty").hexdigest()
    ordered = sorted(cases, key=lambda c: c["case_id"])
    level: List[bytes] = []
    for c in ordered:
        raw = bytes.fromhex(case_digest(c))
        level.append(hashlib.sha256(b"\x00" + raw).digest())
    while len(level) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(hashlib.sha256(b"\x01" + left + right).digest())
        level = nxt
    return level[0].hex()

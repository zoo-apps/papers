# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation & Open ResearchDAO Contributors.

"""Deterministic canonical JSON and domain-separated SHA-256 / Merkle tree routines.

Produces byte-for-byte identical outputs to the Go reference implementation in
go/internal/daoos/canonical.go.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List

DOMAIN_GENESIS = b"researchdao-os.v1:genesis:"
DOMAIN_ENVELOPE = b"researchdao-os.v1:envelope:"
DOMAIN_EVENT = b"researchdao-os.v1:event:"
DOMAIN_STATE = b"researchdao-os.v1:state:"
DOMAIN_MERKLE_EMPTY = b"researchdao-os.v1:merkle:empty"
DOMAIN_MERKLE_LEAF = b"researchdao-os.v1:merkle:leaf:"
DOMAIN_MERKLE_NODE = b"researchdao-os.v1:merkle:node:"


def _escape_json_string(s: str) -> str:
    out: List[str] = ['"']
    for ch in s:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _encode_canonical(v: Any, parts: List[str]) -> None:
    if v is None:
        parts.append("null")
    elif isinstance(v, bool):
        parts.append("true" if v else "false")
    elif isinstance(v, int):
        parts.append(str(v))
    elif isinstance(v, float):
        raise ValueError(f"non-integer float {v!r} forbidden in canonical json")
    elif isinstance(v, str):
        parts.append(_escape_json_string(v))
    elif isinstance(v, (list, tuple)):
        parts.append("[")
        for idx, item in enumerate(v):
            if idx > 0:
                parts.append(",")
            _encode_canonical(item, parts)
        parts.append("]")
    elif isinstance(v, dict):
        parts.append("{")
        for idx, k in enumerate(sorted(v.keys())):
            if not isinstance(k, str):
                raise ValueError(f"object key must be string, got {type(k)}")
            if idx > 0:
                parts.append(",")
            parts.append(_escape_json_string(k))
            parts.append(":")
            _encode_canonical(v[k], parts)
        parts.append("}")
    else:
        raise ValueError(f"unsupported canonical json type: {type(v)}")


def canonical_json(obj: Any) -> bytes:
    """Serialize obj into compact sorted-key UTF-8 JSON matching Go CanonicalJSON."""
    parts: List[str] = []
    _encode_canonical(obj, parts)
    return "".join(parts).encode("utf-8")


def domain_sha256_hex(domain: bytes, payload: bytes) -> str:
    return hashlib.sha256(domain + payload).hexdigest()


def is_valid_sha256_hex(s: Any) -> bool:
    if not isinstance(s, str) or len(s) != 64:
        return False
    return all(("0" <= c <= "9") or ("a" <= c <= "f") for c in s)


def config_view(c: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "min_peer_reviews": c["min_peer_reviews"],
        "min_review_score_bps": c["min_review_score_bps"],
        "milestone_quorum": c["milestone_quorum"],
        "treasury_quorum": c["treasury_quorum"],
        "emergency_pause_quorum": c["emergency_pause_quorum"],
        "meta_governance_quorum": c["meta_governance_quorum"],
        "timelock_seconds": c["timelock_seconds"],
        "epoch_duration_seconds": c["epoch_duration_seconds"],
        "epoch_spend_cap_bps": c["epoch_spend_cap_bps"],
        "max_emergency_duration_sec": c["max_emergency_duration_sec"],
        "holdback_bps": c["holdback_bps"],
    }


def normalize_genesis(g: Dict[str, Any]) -> Dict[str, Any]:
    actors_sorted = sorted(g.get("actors", []), key=lambda a: a["id"])
    actor_views = []
    for a in actors_sorted:
        actor_views.append(
            {
                "id": a["id"],
                "pubkey_hex": a["pubkey_hex"],
                "kind": a["kind"],
                "roles": sorted(list(a.get("roles") or [])),
                "affiliations": sorted(list(a.get("affiliations") or [])),
                "reputation": a.get("reputation", 0),
                "active": a.get("active", True),
                "effective_until": a.get("effective_until", 0),
                "revoked_at": a.get("revoked_at", 0),
                "last_nonce": a.get("last_nonce", 0),
            }
        )
    return {
        "spec_version": g.get("spec_version", "researchdao-os.v1"),
        "chain_id": g["chain_id"],
        "created_at": g["created_at"],
        "initial_treasury_balance": g["initial_treasury_balance"],
        "config": config_view(g["config"]),
        "actors": actor_views,
    }


def hash_genesis(g: Dict[str, Any]) -> str:
    return domain_sha256_hex(DOMAIN_GENESIS, canonical_json(normalize_genesis(g)))


def signing_bytes(env: Dict[str, Any]) -> bytes:
    unsigned = {
        "spec_version": env["spec_version"],
        "seq": env["seq"],
        "prev_event_hash": env["prev_event_hash"],
        "timestamp": env["timestamp"],
        "actor_id": env["actor_id"],
        "nonce": env["nonce"],
        "type": env["type"],
        "payload": env["payload"],
    }
    return DOMAIN_ENVELOPE + canonical_json(unsigned)


def hash_envelope(env: Dict[str, Any]) -> str:
    full = {
        "spec_version": env["spec_version"],
        "seq": env["seq"],
        "prev_event_hash": env["prev_event_hash"],
        "timestamp": env["timestamp"],
        "actor_id": env["actor_id"],
        "nonce": env["nonce"],
        "type": env["type"],
        "payload": env["payload"],
        "signature_hex": env["signature_hex"],
    }
    return domain_sha256_hex(DOMAIN_EVENT, canonical_json(full))


def canonical_state_view(st: Dict[str, Any]) -> Dict[str, Any]:
    actors_map: Dict[str, Dict[str, Any]] = st["actors"]
    actors_view = []
    for aid in sorted(actors_map.keys()):
        a = actors_map[aid]
        actors_view.append(
            {
                "id": a["id"],
                "pubkey_hex": a["pubkey_hex"],
                "kind": a["kind"],
                "roles": sorted(list(a.get("roles") or [])),
                "affiliations": sorted(list(a.get("affiliations") or [])),
                "reputation": a.get("reputation", 0),
                "active": a.get("active", True),
                "effective_until": a.get("effective_until", 0),
                "revoked_at": a.get("revoked_at", 0),
                "last_nonce": a.get("last_nonce", 0),
            }
        )

    props_map: Dict[str, Dict[str, Any]] = st["proposals"]
    proposals_view = []
    for pid in sorted(props_map.keys()):
        p = props_map[pid]
        advs = sorted(list(p.get("advisories") or []), key=lambda x: x["seq"])
        advs_view = [
            {
                "seq": n["seq"],
                "advisor_id": n["advisor_id"],
                "timestamp": n["timestamp"],
                "advisory_only": n["advisory_only"],
                "analysis_hash": n["analysis_hash"],
                "summary": n["summary"],
                "conflict_flags": sorted(list(n.get("conflict_flags") or [])),
                "estimated_value": n["estimated_value"],
            }
            for n in advs
        ]

        revs = sorted(list(p.get("reviews") or []), key=lambda x: x["reviewer_id"])
        revs_view = [
            {
                "reviewer_id": r["reviewer_id"],
                "timestamp": r["timestamp"],
                "score_bps": r["score_bps"],
                "report_hash": r["report_hash"],
                "recommend": r["recommend"],
                "coi_declared": r["coi_declared"],
            }
            for r in revs
        ]

        ms_apps = sorted(list(p.get("milestone_approvals") or []), key=lambda x: x["approver_id"])
        ms_view = [
            {
                "approver_id": m["approver_id"],
                "timestamp": m["timestamp"],
                "evidence_hash": m["evidence_hash"],
                "notes_hash": m["notes_hash"],
            }
            for m in ms_apps
        ]

        funding = p.get("funding")
        funding_view = None
        if funding is not None:
            funding_view = {
                "amount": funding["amount"],
                "initial_tranche": funding["initial_tranche"],
                "holdback_tranche": funding["holdback_tranche"],
                "queued_at": funding["queued_at"],
                "timelock_ready_at": funding["timelock_ready_at"],
                "authorized_at": funding["authorized_at"],
                "steward_signers": sorted(list(funding.get("steward_signers") or [])),
                "initial_tranche_id": funding["initial_tranche_id"],
                "holdback_tranche_id": funding["holdback_tranche_id"],
                "initial_disbursed": funding["initial_disbursed"],
                "holdback_disbursed": funding["holdback_disbursed"],
                "holdback_clawed_back": funding["holdback_clawed_back"],
            }

        veto = p.get("veto")
        veto_view = None
        if veto is not None:
            veto_view = {
                "guardian_id": veto["guardian_id"],
                "timestamp": veto["timestamp"],
                "justification": veto["justification"],
            }

        acc = p.get("acceptance")
        acc_view = None
        if acc is not None:
            acc_view = {
                "verifier_id": acc["verifier_id"],
                "timestamp": acc["timestamp"],
                "bound_evidence_hash": acc["bound_evidence_hash"],
                "repro_check_hash": acc["repro_check_hash"],
                "verdict": acc["verdict"],
            }

        proposals_view.append(
            {
                "id": p["id"],
                "title": p["title"],
                "category": p["category"],
                "proposer_id": p["proposer_id"],
                "plan_hash": p["plan_hash"],
                "source_paper": p["source_paper"],
                "requested_amount": p["requested_amount"],
                "declared_coi_actors": sorted(list(p.get("declared_coi_actors") or [])),
                "status": p["status"],
                "submitted_at": p["submitted_at"],
                "advisories": advs_view,
                "reviews": revs_view,
                "review_mean_score_bps": p.get("review_mean_score_bps", 0),
                "milestone_index": p.get("milestone_index", 0),
                "milestone_evidence_hash": p.get("milestone_evidence_hash", ""),
                "milestone_approvals": ms_view,
                "funding": funding_view,
                "veto": veto_view,
                "acceptance": acc_view,
            }
        )

    tr = st["treasury"]
    disbursed_tranches = sorted([k for k, v in (tr.get("disbursed_tranches") or {}).items() if v])
    ep = st["emergency_pause"]

    rc_map: Dict[str, Dict[str, Any]] = st.get("pending_rule_changes") or {}
    rc_view = []
    for cid in sorted(rc_map.keys()):
        rc = rc_map[cid]
        rc_view.append(
            {
                "change_id": rc["change_id"],
                "parameter": rc["parameter"],
                "new_value": rc["new_value"],
                "signers": sorted(list(rc.get("signers") or [])),
                "executed": rc["executed"],
                "executed_at": rc["executed_at"],
                "proposed_at": rc["proposed_at"],
            }
        )

    return {
        "spec_version": st["spec_version"],
        "chain_id": st["chain_id"],
        "genesis_hash": st["genesis_hash"],
        "seq": st["seq"],
        "last_timestamp": st["last_timestamp"],
        "last_event_hash": st["last_event_hash"],
        "config": config_view(st["config"]),
        "treasury": {
            "balance": tr["balance"],
            "escrowed_total": tr["escrowed_total"],
            "total_disbursed": tr["total_disbursed"],
            "epoch_spent": dict(tr.get("epoch_spent") or {}),
            "disbursed_tranches": disbursed_tranches,
        },
        "emergency_pause": {
            "active": ep["active"],
            "action_id": ep.get("action_id", ""),
            "reason": ep.get("reason", ""),
            "activated_at": ep.get("activated_at", 0),
            "expires_at": ep.get("expires_at", 0),
            "signers": sorted(list(ep.get("signers") or [])),
            "pending_pauses": {k: sorted(list(v)) for k, v in (ep.get("pending_pauses") or {}).items()},
            "pending_reasons": dict(ep.get("pending_reasons") or {}),
            "pending_durs": dict(ep.get("pending_durs") or {}),
            "pending_lifts": {k: sorted(list(v)) for k, v in (ep.get("pending_lifts") or {}).items()},
            "last_review_hash": ep.get("last_review_hash", ""),
        },
        "actors": actors_view,
        "proposals": proposals_view,
        "pending_rule_changes": rc_view,
    }


def state_root_hash(st: Dict[str, Any]) -> str:
    return domain_sha256_hex(DOMAIN_STATE, canonical_json(canonical_state_view(st)))


def audit_merkle_root(event_hashes: List[str]) -> str:
    if not event_hashes:
        return hashlib.sha256(DOMAIN_MERKLE_EMPTY).hexdigest()
    level: List[bytes] = []
    for idx, h_hex in enumerate(event_hashes):
        raw = bytes.fromhex(h_hex)
        if len(raw) != 32:
            raise ValueError(f"invalid event hash at index {idx}")
        level.append(hashlib.sha256(DOMAIN_MERKLE_LEAF + raw).digest())
    while len(level) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(hashlib.sha256(DOMAIN_MERKLE_NODE + left + right).digest())
        level = nxt
    return level[0].hex()

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation & Open ResearchDAO Contributors.

"""Independent pure-stdlib Python 3.12 ResearchDAO OS v1 state machine and WAL verifier."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .canonical import (
    audit_merkle_root,
    hash_envelope,
    hash_genesis,
    is_valid_sha256_hex,
    signing_bytes,
    state_root_hash,
)
from .ed25519 import verify as ed25519_verify

SPEC_VERSION = "researchdao-os.v1"
GENESIS_PREV_HASH = "0" * 64
MAX_EMERGENCY_DURATION_SECONDS = 72 * 3600

VALID_CATEGORIES = {
    "CONSERVATION_RESEARCH",
    "OPEN_SOURCE_DEV",
    "CITIZEN_SCIENCE",
    "EDUCATION",
    "EMERGENCY_CONSERVATION",
}


class TransitionError(Exception):
    """Machine-verifiable rejection matching Go daoos.TransitionError codes."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _req_str(m: Dict[str, Any], key: str) -> str:
    if key not in m:
        raise TransitionError("ERR_INVALID_PAYLOAD", f"missing field {key!r}")
    v = m[key]
    if not isinstance(v, str) or v == "":
        raise TransitionError("ERR_INVALID_PAYLOAD", f"field {key!r} must be non-empty string")
    return v


def _req_hash(m: Dict[str, Any], key: str) -> str:
    s = _req_str(m, key)
    if not is_valid_sha256_hex(s):
        raise TransitionError("ERR_INVALID_PAYLOAD", f"field {key!r} must be 64-char lowercase hex sha256")
    return s


def _req_bool(m: Dict[str, Any], key: str) -> bool:
    if key not in m or not isinstance(m[key], bool):
        raise TransitionError("ERR_INVALID_PAYLOAD", f"field {key!r} must be bool")
    return m[key]


def _req_int(m: Dict[str, Any], key: str) -> int:
    if key not in m or not _is_int(m[key]):
        raise TransitionError("ERR_INVALID_PAYLOAD", f"field {key!r} must be integer")
    return int(m[key])


def _opt_str_list(m: Dict[str, Any], key: str) -> List[str]:
    v = m.get(key)
    if v is None:
        return []
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise TransitionError("ERR_INVALID_PAYLOAD", f"field {key!r} must be string array")
    return sorted(list(v))


def _has_coi(actor: Dict[str, Any], proposer: Optional[Dict[str, Any]], declared_coi: List[str]) -> bool:
    if actor["id"] in declared_coi:
        return True
    if proposer is None:
        return False
    p_affs = {a.lower() for a in (proposer.get("affiliations") or []) if a}
    for a_aff in actor.get("affiliations") or []:
        if a_aff and a_aff.lower() in p_affs:
            return True
    return False


def _validate_genesis(g: Dict[str, Any]) -> None:
    if not g.get("chain_id"):
        raise TransitionError("ERR_INVALID_PAYLOAD", "genesis chain_id required")
    if not _is_int(g.get("initial_treasury_balance")) or g["initial_treasury_balance"] <= 0:
        raise TransitionError("ERR_INVALID_PAYLOAD", "initial_treasury_balance must be positive")
    c = g.get("config") or {}
    if (
        c.get("min_peer_reviews", 0) < 1
        or not (0 <= c.get("min_review_score_bps", -1) <= 10000)
        or c.get("milestone_quorum", 0) < 1
        or c.get("treasury_quorum", 0) < 1
        or c.get("emergency_pause_quorum", 0) < 1
        or c.get("meta_governance_quorum", 0) < 1
        or c.get("timelock_seconds", -1) < 0
        or c.get("epoch_duration_seconds", 0) <= 0
        or not (1 <= c.get("epoch_spend_cap_bps", 0) <= 10000)
        or not (1 <= c.get("max_emergency_duration_sec", 0) <= MAX_EMERGENCY_DURATION_SECONDS)
        or not (0 <= c.get("holdback_bps", -1) <= 5000)
    ):
        raise TransitionError("ERR_INVALID_PAYLOAD", "invalid genesis governance config")
    seen = set()
    for a in g.get("actors") or []:
        aid = a.get("id", "")
        if not aid or aid in seen:
            raise TransitionError("ERR_INVALID_PAYLOAD", f"invalid or duplicate actor id {aid!r}")
        seen.add(aid)
        if not isinstance(a.get("pubkey_hex"), str) or len(a["pubkey_hex"]) != 64:
            raise TransitionError("ERR_INVALID_PAYLOAD", f"invalid pubkey_hex for actor {aid!r}")
        kind = a.get("kind")
        if kind not in ("HUMAN", "AI_AGENT"):
            raise TransitionError("ERR_INVALID_PAYLOAD", f"invalid actor kind {kind!r}")
        if kind == "AI_AGENT":
            for role in a.get("roles") or []:
                if role != "AI_ADVISOR":
                    raise TransitionError(
                        "ERR_AI_GOVERNANCE_FORBIDDEN",
                        f"AI_AGENT {aid!r} cannot hold authority role {role}",
                    )


def _enforce_ai_constitution(ev_type: str) -> None:
    if ev_type == "AdvisoryRecorded":
        return
    if ev_type in ("FundingQueued", "FundingCosigned", "FundingAuthorized"):
        raise TransitionError(
            "ERR_AI_TREASURY_FORBIDDEN",
            "AI agents cannot queue, cosign, or authorize treasury disbursements",
        )
    if ev_type == "GovernanceRuleAmended":
        raise TransitionError(
            "ERR_AI_RULE_CHANGE_FORBIDDEN",
            "AI agents cannot redefine governance or voting rules",
        )
    if ev_type in ("PeerReviewRecorded", "MilestoneApproved", "IndependentAcceptanceRecorded"):
        raise TransitionError(
            "ERR_AI_VALIDATION_FORBIDDEN",
            "AI agents cannot cast peer reviews, approve milestones, or declare experiments valid",
        )
    raise TransitionError(
        "ERR_AI_GOVERNANCE_FORBIDDEN",
        f"AI agents are constitutionally barred from {ev_type}",
    )


def _validate_rule_parameter(param: str, val: int) -> None:
    if param in (
        "min_peer_reviews",
        "milestone_quorum",
        "treasury_quorum",
        "emergency_pause_quorum",
        "meta_governance_quorum",
    ):
        if not (1 <= val <= 21):
            raise TransitionError("ERR_INVALID_PAYLOAD", "quorum parameter out of safe range [1, 21]")
    elif param == "min_review_score_bps":
        if not (1000 <= val <= 10000):
            raise TransitionError("ERR_INVALID_PAYLOAD", "min_review_score_bps out of range")
    elif param == "timelock_seconds":
        if not (0 <= val <= 30 * 24 * 3600):
            raise TransitionError("ERR_INVALID_PAYLOAD", "timelock_seconds out of range")
    elif param == "epoch_spend_cap_bps":
        if not (100 <= val <= 5000):
            raise TransitionError("ERR_INVALID_PAYLOAD", "epoch_spend_cap_bps out of range")
    elif param == "holdback_bps":
        if not (0 <= val <= 5000):
            raise TransitionError("ERR_INVALID_PAYLOAD", "holdback_bps out of range")
    else:
        raise TransitionError("ERR_INVALID_PAYLOAD", f"unknown rule parameter {param!r}")


class VerifierMachine:
    """Independent deterministic ResearchDAO OS v1 execution & audit engine."""

    def __init__(self, genesis: Dict[str, Any]) -> None:
        _validate_genesis(genesis)
        g = copy.deepcopy(genesis)
        g.setdefault("spec_version", SPEC_VERSION)
        gen_hash = hash_genesis(g)

        actors: Dict[str, Dict[str, Any]] = {}
        for a in g["actors"]:
            actors[a["id"]] = {
                "id": a["id"],
                "pubkey_hex": a["pubkey_hex"],
                "kind": a["kind"],
                "roles": list(a.get("roles") or []),
                "affiliations": list(a.get("affiliations") or []),
                "reputation": a.get("reputation", 0),
                "active": a.get("active", True),
                "effective_until": a.get("effective_until", 0),
                "revoked_at": a.get("revoked_at", 0),
                "last_nonce": a.get("last_nonce", 0),
            }

        self.genesis = g
        self.state: Dict[str, Any] = {
            "spec_version": SPEC_VERSION,
            "chain_id": g["chain_id"],
            "genesis_hash": gen_hash,
            "seq": 0,
            "last_timestamp": g["created_at"],
            "last_event_hash": GENESIS_PREV_HASH,
            "config": copy.deepcopy(g["config"]),
            "treasury": {
                "balance": g["initial_treasury_balance"],
                "escrowed_total": 0,
                "total_disbursed": 0,
                "epoch_spent": {},
                "disbursed_tranches": {},
            },
            "emergency_pause": {
                "active": False,
                "action_id": "",
                "reason": "",
                "activated_at": 0,
                "expires_at": 0,
                "signers": [],
                "pending_pauses": {},
                "pending_reasons": {},
                "pending_durs": {},
                "pending_lifts": {},
                "last_review_hash": "",
            },
            "actors": actors,
            "proposals": {},
            "pending_rule_changes": {},
        }
        self.event_hashes: List[str] = []

    def roots(self) -> Tuple[str, str]:
        return state_root_hash(self.state), audit_merkle_root(self.event_hashes)

    def _is_paused(self, ts: int) -> bool:
        ep = self.state["emergency_pause"]
        return bool(ep["active"]) and ts <= int(ep["expires_at"])

    def _check_treasury_cap(self, amount: int, ts: int) -> None:
        tr = self.state["treasury"]
        if amount > tr["balance"]:
            raise TransitionError("ERR_BUDGET_CAP_EXCEEDED", "requested exceeds treasury balance")
        cfg = self.state["config"]
        epoch_key = str(ts // cfg["epoch_duration_seconds"])
        epoch_cap = (tr["balance"] * cfg["epoch_spend_cap_bps"]) // 10000
        if tr["epoch_spent"].get(epoch_key, 0) + amount > epoch_cap:
            raise TransitionError("ERR_BUDGET_CAP_EXCEEDED", "epoch spend exceeds epoch cap")

    def apply(self, env: Dict[str, Any]) -> str:
        if env.get("spec_version") != SPEC_VERSION:
            raise TransitionError("ERR_INVALID_PAYLOAD", f"unsupported spec_version {env.get('spec_version')!r}")
        if env.get("seq") != self.state["seq"] + 1:
            raise TransitionError("ERR_INVALID_SEQUENCE", f"expected seq {self.state['seq'] + 1}, got {env.get('seq')}")
        if env.get("prev_event_hash") != self.state["last_event_hash"]:
            raise TransitionError("ERR_CHAIN_BROKEN", "prev_event_hash mismatch")
        ts = env.get("timestamp")
        if not _is_int(ts) or ts < self.state["last_timestamp"]:
            raise TransitionError("ERR_TIMESTAMP_REGRESSION", "timestamp regressed")

        actor_id = env.get("actor_id")
        if actor_id not in self.state["actors"]:
            raise TransitionError("ERR_UNKNOWN_ACTOR", f"unknown actor {actor_id!r}")
        actor = self.state["actors"][actor_id]
        if not actor["active"]:
            raise TransitionError("ERR_ACTOR_REVOKED", f"actor {actor_id!r} is revoked")
        if actor["effective_until"] > 0 and ts > actor["effective_until"]:
            raise TransitionError("ERR_ACTOR_EXPIRED", f"actor {actor_id!r} key expired")
        if env.get("nonce") != actor["last_nonce"] + 1:
            raise TransitionError("ERR_NONCE_REPLAY", "nonce mismatch")

        # Strict RFC 8032 Ed25519 verification
        try:
            pub_bytes = bytes.fromhex(actor["pubkey_hex"])
            sig_bytes = bytes.fromhex(env.get("signature_hex", ""))
            msg = signing_bytes(env)
        except Exception as exc:
            raise TransitionError("ERR_INVALID_SIGNATURE", str(exc)) from exc
        if not ed25519_verify(pub_bytes, msg, sig_bytes):
            raise TransitionError("ERR_INVALID_SIGNATURE", "ed25519 verification failed")

        ev_type = env.get("type", "")
        if actor["kind"] == "AI_AGENT":
            _enforce_ai_constitution(ev_type)

        payload = env.get("payload")
        if not isinstance(payload, dict):
            raise TransitionError("ERR_INVALID_PAYLOAD", "payload must be object")

        commit_fn = self._prepare(actor, env, payload)
        ev_hash = hash_envelope(env)
        commit_fn()
        actor["last_nonce"] = env["nonce"]
        self.state["seq"] = env["seq"]
        self.state["last_timestamp"] = ts
        self.state["last_event_hash"] = ev_hash
        self.event_hashes.append(ev_hash)
        return ev_hash

    def _prepare(self, actor: Dict[str, Any], env: Dict[str, Any], payload: Dict[str, Any]) -> Callable[[], None]:
        t = env["type"]
        if t == "ProposalSubmitted":
            return self._prep_proposal_submitted(actor, env, payload)
        if t == "AdvisoryRecorded":
            return self._prep_advisory_recorded(actor, env, payload)
        if t == "PeerReviewRecorded":
            return self._prep_peer_review(actor, env, payload)
        if t == "MilestoneApproved":
            return self._prep_milestone_approved(actor, env, payload)
        if t == "FundingQueued":
            return self._prep_funding_queued(actor, env, payload)
        if t == "FundingCosigned":
            return self._prep_funding_cosigned(actor, env, payload)
        if t == "FundingAuthorized":
            return self._prep_funding_authorized(actor, env, payload)
        if t == "BoardVetoRecorded":
            return self._prep_board_veto(actor, env, payload)
        if t == "IndependentAcceptanceRecorded":
            return self._prep_independent_acceptance(actor, env, payload)
        if t == "EmergencyPauseSigned":
            return self._prep_emergency_pause_signed(actor, env, payload)
        if t == "EmergencyPauseLifted":
            return self._prep_emergency_pause_lifted(actor, env, payload)
        if t == "GovernanceRuleAmended":
            return self._prep_governance_rule_amended(actor, env, payload)
        if t == "ActorRevoked":
            return self._prep_actor_revoked(actor, env, payload)
        raise TransitionError("ERR_INVALID_PAYLOAD", f"unknown event type {t!r}")

    def _prep_proposal_submitted(self, actor: Dict[str, Any], env: Dict[str, Any], p: Dict[str, Any]) -> Callable[[], None]:
        if "RESEARCHER" not in actor["roles"]:
            raise TransitionError("ERR_UNAUTHORIZED_ROLE", "requires RESEARCHER role")
        prop_id = _req_str(p, "proposal_id")
        if prop_id in self.state["proposals"]:
            raise TransitionError("ERR_DUPLICATE_PROPOSAL", prop_id)
        title = _req_str(p, "title")
        cat = _req_str(p, "category")
        if cat not in VALID_CATEGORIES:
            raise TransitionError("ERR_INVALID_PAYLOAD", f"invalid category {cat!r}")
        plan_hash = _req_hash(p, "plan_hash")
        source_paper = _req_str(p, "source_paper")
        req_amt = _req_int(p, "requested_amount")
        if req_amt <= 0:
            raise TransitionError("ERR_INVALID_PAYLOAD", "requested_amount must be positive")
        coi = _opt_str_list(p, "declared_coi_actors")

        def commit() -> None:
            self.state["proposals"][prop_id] = {
                "id": prop_id,
                "title": title,
                "category": cat,
                "proposer_id": actor["id"],
                "plan_hash": plan_hash,
                "source_paper": source_paper,
                "requested_amount": req_amt,
                "declared_coi_actors": coi,
                "status": "SUBMITTED",
                "submitted_at": env["timestamp"],
                "advisories": [],
                "reviews": [],
                "review_mean_score_bps": 0,
                "milestone_index": 0,
                "milestone_evidence_hash": "",
                "milestone_approvals": [],
                "funding": None,
                "veto": None,
                "acceptance": None,
            }

        return commit

    def _prep_advisory_recorded(self, actor: Dict[str, Any], env: Dict[str, Any], p: Dict[str, Any]) -> Callable[[], None]:
        if "AI_ADVISOR" not in actor["roles"]:
            raise TransitionError("ERR_UNAUTHORIZED_ROLE", "requires AI_ADVISOR role")
        prop_id = _req_str(p, "proposal_id")
        prop = self.state["proposals"].get(prop_id)
        if prop is None:
            raise TransitionError("ERR_PROPOSAL_NOT_FOUND", prop_id)
        if not _req_bool(p, "advisory_only"):
            raise TransitionError("ERR_INVALID_PAYLOAD", "advisory_only must be true")
        analysis_hash = _req_hash(p, "analysis_hash")
        summary = _req_str(p, "summary")
        flags = _opt_str_list(p, "conflict_flags")
        est_val = _req_int(p, "estimated_value")
        if est_val < 0:
            raise TransitionError("ERR_INVALID_PAYLOAD", "estimated_value must be non-negative")

        def commit() -> None:
            prop["advisories"].append(
                {
                    "seq": env["seq"],
                    "advisor_id": actor["id"],
                    "timestamp": env["timestamp"],
                    "advisory_only": True,
                    "analysis_hash": analysis_hash,
                    "summary": summary,
                    "conflict_flags": flags,
                    "estimated_value": est_val,
                }
            )

        return commit

    def _prep_peer_review(self, actor: Dict[str, Any], env: Dict[str, Any], p: Dict[str, Any]) -> Callable[[], None]:
        if "PEER_REVIEWER" not in actor["roles"]:
            raise TransitionError("ERR_UNAUTHORIZED_ROLE", "requires PEER_REVIEWER role")
        prop_id = _req_str(p, "proposal_id")
        prop = self.state["proposals"].get(prop_id)
        if prop is None:
            raise TransitionError("ERR_PROPOSAL_NOT_FOUND", prop_id)
        if prop["status"] not in ("SUBMITTED", "UNDER_REVIEW"):
            raise TransitionError("ERR_INVALID_TRANSITION", "cannot peer review in current state")
        if actor["id"] == prop["proposer_id"]:
            raise TransitionError("ERR_SELF_REVIEW_FORBIDDEN", "proposer cannot peer-review own proposal")
        if _has_coi(actor, self.state["actors"].get(prop["proposer_id"]), prop["declared_coi_actors"]):
            raise TransitionError("ERR_COI_CONFLICT", "reviewer COI conflict")
        if any(r["reviewer_id"] == actor["id"] for r in prop["reviews"]):
            raise TransitionError("ERR_DUPLICATE_REVIEW", "duplicate reviewer")
        score_bps = _req_int(p, "score_bps")
        if not (0 <= score_bps <= 10000):
            raise TransitionError("ERR_INVALID_PAYLOAD", "score_bps out of range")
        report_hash = _req_hash(p, "report_hash")
        recommend = _req_bool(p, "recommend")
        coi_declared = _req_bool(p, "coi_declared")
        if coi_declared:
            raise TransitionError("ERR_COI_CONFLICT", "reviewer declared COI")

        def commit() -> None:
            prop["reviews"].append(
                {
                    "reviewer_id": actor["id"],
                    "timestamp": env["timestamp"],
                    "score_bps": score_bps,
                    "report_hash": report_hash,
                    "recommend": recommend,
                    "coi_declared": False,
                }
            )
            prop["reviews"].sort(key=lambda r: r["reviewer_id"])
            total = sum(r["score_bps"] for r in prop["reviews"])
            cnt = len(prop["reviews"])
            prop["review_mean_score_bps"] = total // cnt
            cfg = self.state["config"]
            if cnt >= cfg["min_peer_reviews"]:
                if total >= cfg["min_review_score_bps"] * cnt:
                    prop["status"] = "PEER_REVIEWED"
                else:
                    prop["status"] = "REVIEW_REJECTED"
            else:
                prop["status"] = "UNDER_REVIEW"

        return commit

    def _prep_milestone_approved(self, actor: Dict[str, Any], env: Dict[str, Any], p: Dict[str, Any]) -> Callable[[], None]:
        if "MILESTONE_COMMITTEE" not in actor["roles"]:
            raise TransitionError("ERR_UNAUTHORIZED_ROLE", "requires MILESTONE_COMMITTEE role")
        prop_id = _req_str(p, "proposal_id")
        prop = self.state["proposals"].get(prop_id)
        if prop is None:
            raise TransitionError("ERR_PROPOSAL_NOT_FOUND", prop_id)
        if prop["status"] != "PEER_REVIEWED":
            raise TransitionError("ERR_INVALID_TRANSITION", "cannot approve milestone in current state")
        if actor["id"] == prop["proposer_id"]:
            raise TransitionError("ERR_SELF_APPROVAL_FORBIDDEN", "proposer cannot approve own milestone")
        if _has_coi(actor, self.state["actors"].get(prop["proposer_id"]), prop["declared_coi_actors"]):
            raise TransitionError("ERR_COI_CONFLICT", "committee member COI")
        if any(a["approver_id"] == actor["id"] for a in prop["milestone_approvals"]):
            raise TransitionError("ERR_DUPLICATE_APPROVAL", "duplicate milestone approver")
        ms_idx = _req_int(p, "milestone_index")
        if ms_idx < 1:
            raise TransitionError("ERR_INVALID_PAYLOAD", "milestone_index must be >= 1")
        ev_hash = _req_hash(p, "evidence_hash")
        if ev_hash == prop["plan_hash"]:
            raise TransitionError("ERR_EVIDENCE_MISMATCH", "evidence_hash cannot reuse plan_hash")
        if prop["milestone_evidence_hash"] and prop["milestone_evidence_hash"] != ev_hash:
            raise TransitionError("ERR_EVIDENCE_MISMATCH", "evidence_hash conflicts with prior approval")
        notes_hash = _req_hash(p, "notes_hash")

        def commit() -> None:
            prop["milestone_index"] = ms_idx
            prop["milestone_evidence_hash"] = ev_hash
            prop["milestone_approvals"].append(
                {
                    "approver_id": actor["id"],
                    "timestamp": env["timestamp"],
                    "evidence_hash": ev_hash,
                    "notes_hash": notes_hash,
                }
            )
            prop["milestone_approvals"].sort(key=lambda m: m["approver_id"])
            if len(prop["milestone_approvals"]) >= self.state["config"]["milestone_quorum"]:
                prop["status"] = "MILESTONE_APPROVED"

        return commit

    def _prep_funding_queued(self, actor: Dict[str, Any], env: Dict[str, Any], p: Dict[str, Any]) -> Callable[[], None]:
        if "TREASURY_STEWARD" not in actor["roles"]:
            raise TransitionError("ERR_UNAUTHORIZED_ROLE", "requires TREASURY_STEWARD role")
        if self._is_paused(env["timestamp"]):
            raise TransitionError("ERR_SYSTEM_PAUSED", "system paused")
        prop_id = _req_str(p, "proposal_id")
        prop = self.state["proposals"].get(prop_id)
        if prop is None:
            raise TransitionError("ERR_PROPOSAL_NOT_FOUND", prop_id)
        if prop["status"] == "VETOED":
            raise TransitionError("ERR_PROPOSAL_VETOED", "proposal vetoed")
        if prop["status"] != "MILESTONE_APPROVED":
            raise TransitionError("ERR_INVALID_TRANSITION", "cannot queue funding in current state")
        amount = _req_int(p, "amount")
        if amount <= 0:
            raise TransitionError("ERR_INVALID_PAYLOAD", "amount must be positive")
        if amount > prop["requested_amount"]:
            raise TransitionError("ERR_BUDGET_CAP_EXCEEDED", "amount exceeds requested_amount")
        self._check_treasury_cap(amount, env["timestamp"])

        cfg = self.state["config"]
        holdback = (amount * cfg["holdback_bps"]) // 10000
        initial = amount - holdback

        def commit() -> None:
            prop["funding"] = {
                "amount": amount,
                "initial_tranche": initial,
                "holdback_tranche": holdback,
                "queued_at": env["timestamp"],
                "timelock_ready_at": env["timestamp"] + cfg["timelock_seconds"],
                "authorized_at": 0,
                "steward_signers": [actor["id"]],
                "initial_tranche_id": f"{prop_id}:initial",
                "holdback_tranche_id": f"{prop_id}:holdback",
                "initial_disbursed": False,
                "holdback_disbursed": False,
                "holdback_clawed_back": False,
            }
            prop["status"] = "FUNDING_QUEUED"

        return commit

    def _prep_funding_cosigned(self, actor: Dict[str, Any], env: Dict[str, Any], p: Dict[str, Any]) -> Callable[[], None]:
        if "TREASURY_STEWARD" not in actor["roles"]:
            raise TransitionError("ERR_UNAUTHORIZED_ROLE", "requires TREASURY_STEWARD role")
        if self._is_paused(env["timestamp"]):
            raise TransitionError("ERR_SYSTEM_PAUSED", "system paused")
        prop_id = _req_str(p, "proposal_id")
        prop = self.state["proposals"].get(prop_id)
        if prop is None:
            raise TransitionError("ERR_PROPOSAL_NOT_FOUND", prop_id)
        if prop["status"] == "VETOED":
            raise TransitionError("ERR_PROPOSAL_VETOED", "proposal vetoed")
        if prop["status"] != "FUNDING_QUEUED" or prop["funding"] is None:
            raise TransitionError("ERR_INVALID_TRANSITION", "proposal not in FUNDING_QUEUED")
        if actor["id"] in prop["funding"]["steward_signers"]:
            raise TransitionError("ERR_DUPLICATE_APPROVAL", "steward already cosigned")

        def commit() -> None:
            prop["funding"]["steward_signers"].append(actor["id"])
            prop["funding"]["steward_signers"].sort()

        return commit

    def _prep_funding_authorized(self, actor: Dict[str, Any], env: Dict[str, Any], p: Dict[str, Any]) -> Callable[[], None]:
        if "TREASURY_STEWARD" not in actor["roles"]:
            raise TransitionError("ERR_UNAUTHORIZED_ROLE", "requires TREASURY_STEWARD role")
        if self._is_paused(env["timestamp"]):
            raise TransitionError("ERR_SYSTEM_PAUSED", "system paused")
        prop_id = _req_str(p, "proposal_id")
        prop = self.state["proposals"].get(prop_id)
        if prop is None:
            raise TransitionError("ERR_PROPOSAL_NOT_FOUND", prop_id)
        if prop["status"] == "VETOED":
            raise TransitionError("ERR_PROPOSAL_VETOED", "proposal vetoed")
        funding = prop["funding"]
        if funding is not None and (
            funding["initial_disbursed"]
            or self.state["treasury"]["disbursed_tranches"].get(funding["initial_tranche_id"], False)
        ):
            raise TransitionError("ERR_TRANCHE_ALREADY_DISBURSED", "initial tranche already disbursed")
        if prop["status"] != "FUNDING_QUEUED" or funding is None:
            raise TransitionError("ERR_INVALID_TRANSITION", "proposal not in FUNDING_QUEUED")

        ts = env["timestamp"]
        active_signers = {
            sid
            for sid in funding["steward_signers"]
            if sid in self.state["actors"]
            and self.state["actors"][sid]["active"]
            and (
                self.state["actors"][sid]["effective_until"] == 0
                or ts <= self.state["actors"][sid]["effective_until"]
            )
        }
        if len(active_signers) < self.state["config"]["treasury_quorum"]:
            raise TransitionError("ERR_QUORUM_NOT_MET", "steward quorum not met")
        if ts < funding["timelock_ready_at"]:
            raise TransitionError("ERR_TIMELOCK_NOT_ELAPSED", "timelock not elapsed")
        self._check_treasury_cap(funding["amount"], ts)

        epoch_key = str(ts // self.state["config"]["epoch_duration_seconds"])

        def commit() -> None:
            tr = self.state["treasury"]
            tr["balance"] -= funding["amount"]
            tr["escrowed_total"] += funding["holdback_tranche"]
            tr["total_disbursed"] += funding["initial_tranche"]
            tr["epoch_spent"][epoch_key] = tr["epoch_spent"].get(epoch_key, 0) + funding["amount"]
            tr["disbursed_tranches"][funding["initial_tranche_id"]] = True
            funding["initial_disbursed"] = True
            funding["authorized_at"] = ts
            prop["status"] = "FUNDING_AUTHORIZED"

        return commit

    def _prep_board_veto(self, actor: Dict[str, Any], env: Dict[str, Any], p: Dict[str, Any]) -> Callable[[], None]:
        if "BOARD_GUARDIAN" not in actor["roles"]:
            raise TransitionError("ERR_UNAUTHORIZED_ROLE", "requires BOARD_GUARDIAN role")
        prop_id = _req_str(p, "proposal_id")
        prop = self.state["proposals"].get(prop_id)
        if prop is None:
            raise TransitionError("ERR_PROPOSAL_NOT_FOUND", prop_id)
        if prop["status"] != "FUNDING_QUEUED":
            raise TransitionError("ERR_INVALID_TRANSITION", "board veto restricted to FUNDING_QUEUED")
        just = _req_str(p, "justification")
        if not just.strip():
            raise TransitionError("ERR_INVALID_PAYLOAD", "justification required")

        def commit() -> None:
            prop["veto"] = {
                "guardian_id": actor["id"],
                "timestamp": env["timestamp"],
                "justification": just,
            }
            prop["status"] = "VETOED"

        return commit

    def _prep_independent_acceptance(self, actor: Dict[str, Any], env: Dict[str, Any], p: Dict[str, Any]) -> Callable[[], None]:
        if "INDEPENDENT_VERIFIER" not in actor["roles"]:
            raise TransitionError("ERR_UNAUTHORIZED_ROLE", "requires INDEPENDENT_VERIFIER role")
        if self._is_paused(env["timestamp"]):
            raise TransitionError("ERR_SYSTEM_PAUSED", "system paused")
        prop_id = _req_str(p, "proposal_id")
        prop = self.state["proposals"].get(prop_id)
        if prop is None:
            raise TransitionError("ERR_PROPOSAL_NOT_FOUND", prop_id)
        funding = prop["funding"]
        if prop["acceptance"] is not None or (
            funding is not None
            and (
                funding["holdback_disbursed"]
                or self.state["treasury"]["disbursed_tranches"].get(funding["holdback_tranche_id"], False)
            )
        ):
            raise TransitionError("ERR_TRANCHE_ALREADY_DISBURSED", "holdback already settled")
        if prop["status"] != "FUNDING_AUTHORIZED" or funding is None:
            raise TransitionError("ERR_INVALID_TRANSITION", "proposal not in FUNDING_AUTHORIZED")

        if actor["id"] == prop["proposer_id"]:
            raise TransitionError("ERR_VERIFIER_NOT_INDEPENDENT", "proposer cannot accept own proposal")
        if any(r["reviewer_id"] == actor["id"] for r in prop["reviews"]):
            raise TransitionError("ERR_VERIFIER_NOT_INDEPENDENT", "peer reviewer cannot be independent verifier")
        if any(m["approver_id"] == actor["id"] for m in prop["milestone_approvals"]):
            raise TransitionError("ERR_VERIFIER_NOT_INDEPENDENT", "milestone approver cannot be independent verifier")
        if _has_coi(actor, self.state["actors"].get(prop["proposer_id"]), prop["declared_coi_actors"]):
            raise TransitionError("ERR_COI_CONFLICT", "independent verifier COI")

        bound_ev = _req_hash(p, "bound_evidence_hash")
        if bound_ev != prop["milestone_evidence_hash"]:
            raise TransitionError("ERR_EVIDENCE_MISMATCH", "bound_evidence_hash mismatch")
        repro_hash = _req_hash(p, "repro_check_hash")
        if repro_hash in (prop["plan_hash"], prop["milestone_evidence_hash"]):
            raise TransitionError("ERR_EVIDENCE_MISMATCH", "repro_check_hash must be distinct")
        verdict = _req_str(p, "verdict")
        if verdict not in ("ACCEPTED", "FAILED_REPRO"):
            raise TransitionError("ERR_INVALID_PAYLOAD", "invalid verdict")

        def commit() -> None:
            prop["acceptance"] = {
                "verifier_id": actor["id"],
                "timestamp": env["timestamp"],
                "bound_evidence_hash": bound_ev,
                "repro_check_hash": repro_hash,
                "verdict": verdict,
            }
            tr = self.state["treasury"]
            if verdict == "ACCEPTED":
                tr["escrowed_total"] -= funding["holdback_tranche"]
                tr["total_disbursed"] += funding["holdback_tranche"]
                tr["disbursed_tranches"][funding["holdback_tranche_id"]] = True
                funding["holdback_disbursed"] = True
                prop["status"] = "ACCEPTED"
            else:
                tr["escrowed_total"] -= funding["holdback_tranche"]
                tr["balance"] += funding["holdback_tranche"]
                funding["holdback_clawed_back"] = True
                prop["status"] = "ACCEPTANCE_FAILED"

        return commit

    def _prep_emergency_pause_signed(self, actor: Dict[str, Any], env: Dict[str, Any], p: Dict[str, Any]) -> Callable[[], None]:
        if "EMERGENCY_COUNCIL" not in actor["roles"]:
            raise TransitionError("ERR_UNAUTHORIZED_ROLE", "requires EMERGENCY_COUNCIL role")
        action_id = _req_str(p, "action_id")
        reason = _req_str(p, "reason")
        if not reason.strip():
            raise TransitionError("ERR_INVALID_PAYLOAD", "reason required")
        dur = _req_int(p, "duration_seconds")
        if dur <= 0 or dur > self.state["config"]["max_emergency_duration_sec"]:
            raise TransitionError("ERR_INVALID_PAYLOAD", "duration_seconds out of bounds")
        ep = self.state["emergency_pause"]
        if actor["id"] in ep["pending_pauses"].get(action_id, []):
            raise TransitionError("ERR_DUPLICATE_APPROVAL", "duplicate emergency pause signer")
        if action_id in ep["pending_durs"] and ep["pending_durs"][action_id] != dur:
            raise TransitionError("ERR_INVALID_PAYLOAD", "duration mismatch")

        def commit() -> None:
            signers = sorted(list(ep["pending_pauses"].get(action_id, [])) + [actor["id"]])
            ep["pending_pauses"][action_id] = signers
            ep["pending_reasons"][action_id] = reason
            ep["pending_durs"][action_id] = dur
            if len(signers) >= self.state["config"]["emergency_pause_quorum"]:
                ep["active"] = True
                ep["action_id"] = action_id
                ep["reason"] = reason
                ep["activated_at"] = env["timestamp"]
                ep["expires_at"] = env["timestamp"] + dur
                ep["signers"] = list(signers)

        return commit

    def _prep_emergency_pause_lifted(self, actor: Dict[str, Any], env: Dict[str, Any], p: Dict[str, Any]) -> Callable[[], None]:
        if "EMERGENCY_COUNCIL" not in actor["roles"] and "META_GOVERNOR" not in actor["roles"]:
            raise TransitionError("ERR_UNAUTHORIZED_ROLE", "requires EMERGENCY_COUNCIL or META_GOVERNOR")
        if not self._is_paused(env["timestamp"]):
            raise TransitionError("ERR_INVALID_TRANSITION", "no active pause")
        action_id = _req_str(p, "action_id")
        ep = self.state["emergency_pause"]
        if action_id != ep["action_id"]:
            raise TransitionError("ERR_INVALID_PAYLOAD", "action_id mismatch")
        review_hash = _req_hash(p, "post_review_hash")
        if actor["id"] in ep["pending_lifts"].get(action_id, []):
            raise TransitionError("ERR_DUPLICATE_APPROVAL", "duplicate lift signer")

        def commit() -> None:
            lifts = sorted(list(ep["pending_lifts"].get(action_id, [])) + [actor["id"]])
            ep["pending_lifts"][action_id] = lifts
            if len(lifts) >= self.state["config"]["emergency_pause_quorum"]:
                ep["active"] = False
                ep["last_review_hash"] = review_hash

        return commit

    def _prep_governance_rule_amended(self, actor: Dict[str, Any], env: Dict[str, Any], p: Dict[str, Any]) -> Callable[[], None]:
        if "META_GOVERNOR" not in actor["roles"]:
            raise TransitionError("ERR_UNAUTHORIZED_ROLE", "requires META_GOVERNOR role")
        change_id = _req_str(p, "change_id")
        param = _req_str(p, "parameter")
        new_val = _req_int(p, "new_value")
        _validate_rule_parameter(param, new_val)

        existing = self.state["pending_rule_changes"].get(change_id)
        if existing is not None:
            if existing["executed"]:
                raise TransitionError("ERR_INVALID_TRANSITION", "rule change already executed")
            if existing["parameter"] != param or existing["new_value"] != new_val:
                raise TransitionError("ERR_INVALID_PAYLOAD", "rule change mismatch")
            if actor["id"] in existing["signers"]:
                raise TransitionError("ERR_DUPLICATE_APPROVAL", "duplicate rule change signer")

        def commit() -> None:
            rc = self.state["pending_rule_changes"].get(change_id)
            if rc is None:
                rc = {
                    "change_id": change_id,
                    "parameter": param,
                    "new_value": new_val,
                    "signers": [],
                    "executed": False,
                    "executed_at": 0,
                    "proposed_at": env["timestamp"],
                }
                self.state["pending_rule_changes"][change_id] = rc
            rc["signers"] = sorted(rc["signers"] + [actor["id"]])
            if len(rc["signers"]) >= self.state["config"]["meta_governance_quorum"]:
                self.state["config"][param] = new_val
                rc["executed"] = True
                rc["executed_at"] = env["timestamp"]

        return commit

    def _prep_actor_revoked(self, actor: Dict[str, Any], env: Dict[str, Any], p: Dict[str, Any]) -> Callable[[], None]:
        if "EMERGENCY_COUNCIL" not in actor["roles"] and "META_GOVERNOR" not in actor["roles"]:
            raise TransitionError("ERR_UNAUTHORIZED_ROLE", "requires EMERGENCY_COUNCIL or META_GOVERNOR")
        target_id = _req_str(p, "target_actor_id")
        reason = _req_str(p, "reason")
        if not reason.strip():
            raise TransitionError("ERR_INVALID_PAYLOAD", "reason required")
        target = self.state["actors"].get(target_id)
        if target is None:
            raise TransitionError("ERR_UNKNOWN_ACTOR", target_id)
        if not target["active"]:
            raise TransitionError("ERR_ACTOR_REVOKED", "already revoked")

        def commit() -> None:
            target["active"] = False
            target["revoked_at"] = env["timestamp"]

        return commit


def read_genesis(wal_dir: str | os.PathLike[str]) -> Dict[str, Any]:
    path = Path(wal_dir) / "genesis.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise TransitionError("ERR_WAL_TAMPERED", f"corrupt genesis.json: {exc}") from exc


def read_envelopes(wal_dir: str | os.PathLike[str]) -> List[Dict[str, Any]]:
    path = Path(wal_dir) / "events.jsonl"
    if not path.exists():
        return []
    envs: List[Dict[str, Any]] = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        s = raw.strip()
        if not s:
            continue
        try:
            envs.append(json.loads(s))
        except Exception as exc:
            raise TransitionError("ERR_WAL_TAMPERED", f"corrupt json at line {line_no}: {exc}") from exc
    return envs


def replay_full(wal_dir: str | os.PathLike[str]) -> VerifierMachine:
    g = read_genesis(wal_dir)
    m = VerifierMachine(g)
    for env in read_envelopes(wal_dir):
        m.apply(env)
    return m


def replay_from_checkpoint_file(wal_dir: str | os.PathLike[str], cp_path: str | os.PathLike[str]) -> Tuple[VerifierMachine, int]:
    g = read_genesis(wal_dir)
    gen_hash = hash_genesis(g)
    try:
        cp = json.loads(Path(cp_path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise TransitionError("ERR_WAL_TAMPERED", f"corrupt checkpoint: {exc}") from exc
    if cp.get("spec_version") != SPEC_VERSION:
        raise TransitionError("ERR_WAL_TAMPERED", "checkpoint spec_version mismatch")
    st = cp.get("state")
    if not isinstance(st, dict) or cp.get("genesis_hash") != gen_hash or st.get("genesis_hash") != gen_hash:
        raise TransitionError("ERR_WAL_TAMPERED", "checkpoint genesis_hash mismatch")
    computed_sr = state_root_hash(st)
    if computed_sr != cp.get("state_root_hash"):
        raise TransitionError("ERR_WAL_TAMPERED", "checkpoint state_root_hash mismatch")
    ev_hashes = cp.get("event_hashes") or []
    computed_ar = audit_merkle_root(ev_hashes)
    if computed_ar != cp.get("audit_merkle_root"):
        raise TransitionError("ERR_WAL_TAMPERED", "checkpoint audit_merkle_root mismatch")
    seq = int(cp.get("seq", -1))
    if len(ev_hashes) != seq or st.get("seq") != seq:
        raise TransitionError("ERR_WAL_TAMPERED", "checkpoint seq mismatch")
    if seq > 0 and ev_hashes[seq - 1] != cp.get("last_event_hash"):
        raise TransitionError("ERR_WAL_TAMPERED", "checkpoint last_event_hash mismatch")

    m = VerifierMachine(g)
    m.state = st
    m.event_hashes = list(ev_hashes)
    for env in read_envelopes(wal_dir):
        if env["seq"] <= seq:
            continue
        m.apply(env)
    return m, seq


def replay_from_latest_checkpoint(wal_dir: str | os.PathLike[str]) -> Tuple[VerifierMachine, int]:
    cp_dir = Path(wal_dir) / "checkpoints"
    if not cp_dir.exists():
        return replay_full(wal_dir), 0
    candidates: List[Tuple[int, Path]] = []
    for p in cp_dir.iterdir():
        if p.is_file() and p.name.startswith("checkpoint_") and p.name.endswith(".json"):
            try:
                num = int(p.name[len("checkpoint_") : -len(".json")])
                candidates.append((num, p))
            except ValueError:
                continue
    if not candidates:
        return replay_full(wal_dir), 0
    candidates.sort(key=lambda x: x[0])
    return replay_from_checkpoint_file(wal_dir, candidates[-1][1])

# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.

"""Independent pure-Python constitutional-gov.v1 state machine and conflict engine."""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional, Set, Tuple

from .canonical import signing_preimage
from .ed25519 import verify_ed25519

MAX_DELEGATION_DEPTH = 3
MAX_EMERGENCY_DURATION_SEC = 72 * 3600
RENEWAL_COOLDOWN_SEC = 24 * 3600
APPEAL_WINDOW_SEC = 48 * 3600
MIN_TIMELOCK_TREASURY_SEC = 24 * 3600
MIN_TIMELOCK_RULE_AMEND_SEC = 48 * 3600
QUORUM_STANDARD_BPS = 1500
QUORUM_META_GOV_BPS = 2500
QUORUM_FLOOR_BPS = 5000
SUPERMAJORITY_EMERGENCY_BPS = 6700
SUPERMAJORITY_META_GOV_BPS = 7500
TREASURY_EMERGENCY_CAP_BPS = 500

TIER_RANK = {
    "CONSTITUTIONAL": 4,
    "EMERGENCY_SAFETY": 3,
    "CHARTER_STATUTE": 2,
    "ADVISORY_POLICY": 1,
}

SOVEREIGN_SCOPES = {
    "TREASURY_SPEND",
    "RULE_AMEND",
    "EMERGENCY_PAUSE",
    "EMERGENCY_SPEND",
    "EXPERIMENT_VALIDATE",
    "APPEAL_ADJUDICATE",
    "REVOKE_MEMBER",
}

AI_FORBIDDEN_ACTIONS = {
    "TREASURY_QUEUE",
    "TREASURY_EXECUTE",
    "RULE_AMEND_QUEUE",
    "RULE_AMEND_EXECUTE",
    "EMERGENCY_PAUSE",
    "EMERGENCY_RENEW",
    "EXPERIMENT_VALIDATE",
    "APPEAL_RESOLVE",
    "REVOKE_ACTOR",
    "SUSPEND_ACTOR",
    "FINALIZE_CONTESTED",
}


def _find_actor(state: Dict[str, Any], actor_id: str) -> Optional[Dict[str, Any]]:
    for a in state["actors"]:
        if a["id"] == actor_id:
            return a
    return None


def _is_paused_at(state: Dict[str, Any], epoch: int) -> bool:
    em = state.get("emergency") or {}
    return bool(em.get("paused", False)) and epoch < int(em.get("pause_expires_at", 0))


def _active_delegations_at(state: Dict[str, Any], epoch: int) -> List[Dict[str, Any]]:
    out = []
    for d in state.get("delegations") or []:
        if d.get("revoked") or int(d.get("expires_at", 0)) <= epoch:
            continue
        fa = _find_actor(state, d["from"])
        ta = _find_actor(state, d["to"])
        if fa and ta and fa["status"] == "ACTIVE" and ta["status"] == "ACTIVE":
            out.append(d)
    return out


def _effective_scopes(state: Dict[str, Any], actor_id: str, epoch: int) -> Set[str]:
    a = _find_actor(state, actor_id)
    if not a or a["status"] != "ACTIVE":
        return set()
    scopes = set(a.get("base_scopes") or [])
    for d in _active_delegations_at(state, epoch):
        if d["to"] == actor_id:
            scopes.update(d.get("scopes") or [])
    return scopes


def _non_revoked_delegations_at(state: Dict[str, Any], epoch: int) -> List[Dict[str, Any]]:
    out = []
    for d in state.get("delegations") or []:
        if d.get("revoked") or int(d.get("expires_at", 0)) <= epoch:
            continue
        fa = _find_actor(state, d["from"])
        ta = _find_actor(state, d["to"])
        if fa and ta and fa["status"] != "REVOKED" and ta["status"] != "REVOKED":
            out.append(d)
    return out


def _delegation_creates_cycle(state: Dict[str, Any], src: str, dst: str, epoch: int) -> bool:
    if src == dst:
        return True
    adj: Dict[str, List[str]] = {}
    for d in _non_revoked_delegations_at(state, epoch):
        adj.setdefault(d["from"], []).append(d["to"])
    visited = {dst}
    queue = [dst]
    while queue:
        cur = queue.pop(0)
        for nxt in adj.get(cur, []):
            if nxt == src:
                return True
            if nxt not in visited:
                visited.add(nxt)
                queue.append(nxt)
    return False


def _max_incoming_depth(state: Dict[str, Any], node: str, epoch: int) -> int:
    rev: Dict[str, List[str]] = {}
    for d in _non_revoked_delegations_at(state, epoch):
        rev.setdefault(d["to"], []).append(d["from"])

    def dfs(cur: str, seen: Set[str]) -> int:
        best = 0
        for parent in rev.get(cur, []):
            if parent in seen:
                continue
            seen.add(parent)
            depth = 1 + dfs(parent, seen)
            seen.remove(parent)
            if depth > best:
                best = depth
        return best

    return dfs(node, {node})


def _find_delegation(state: Dict[str, Any], del_id: str) -> Optional[Dict[str, Any]]:
    for d in state.get("delegations") or []:
        if d["id"] == del_id:
            return d
    return None


def _delegation_root_origin(state: Dict[str, Any], del_id: str) -> str:
    visited: Set[str] = set()
    cur_id = del_id
    origin = ""
    while cur_id and cur_id not in visited:
        visited.add(cur_id)
        d = _find_delegation(state, cur_id)
        if not d:
            break
        origin = d["from"]
        next_id = ""
        for up in state.get("delegations") or []:
            if up["to"] == d["from"] and not up.get("revoked"):
                next_id = up["id"]
                break
        cur_id = next_id
    return origin


def _transitive_revoke_actor(state: Dict[str, Any], target_id: str, epoch: int) -> None:
    affected = {target_id}
    revoked_dels: Set[str] = set()
    changed = True
    while changed:
        changed = False
        for d in state.get("delegations") or []:
            if d.get("revoked"):
                continue
            if d["from"] in affected or d["to"] == target_id:
                d["revoked"] = True
                d["revoked_at"] = epoch
                revoked_dels.add(d["id"])
                if d["to"] not in affected:
                    affected.add(d["to"])
                changed = True
    for q in state.get("queued_actions") or []:
        if q.get("executed") or q.get("invalidated"):
            continue
        if (
            q.get("proposer_id") == target_id
            or q.get("delegation_origin") == target_id
            or q.get("delegation_id") in revoked_dels
        ):
            q["invalidated"] = True
            q["invalidated_at"] = epoch


def _transitive_revoke_delegation(state: Dict[str, Any], del_id: str, epoch: int) -> None:
    d = _find_delegation(state, del_id)
    if not d:
        return
    d["revoked"] = True
    d["revoked_at"] = epoch
    revoked_dels = {del_id}
    affected = {d["to"]}
    changed = True
    while changed:
        changed = False
        for sub in state.get("delegations") or []:
            if sub.get("revoked"):
                continue
            if sub["from"] in affected:
                held = _effective_scopes(state, sub["from"], epoch)
                if any(sc not in held for sc in sub.get("scopes") or []):
                    sub["revoked"] = True
                    sub["revoked_at"] = epoch
                    revoked_dels.add(sub["id"])
                    affected.add(sub["to"])
                    changed = True
    for q in state.get("queued_actions") or []:
        if q.get("executed") or q.get("invalidated"):
            continue
        if q.get("delegation_id") in revoked_dels:
            q["invalidated"] = True
            q["invalidated_at"] = epoch


def _eval_rule_condition(cond: str, state: Dict[str, Any], act: Dict[str, Any]) -> bool:
    epoch = int(act.get("epoch", 0))
    if cond in ("ALWAYS", ""):
        return True
    if cond == "WHEN_PAUSED":
        return _is_paused_at(state, epoch)
    if cond == "ACTOR_IS_AI":
        a = _find_actor(state, act.get("actor_id", ""))
        if a and a["role"] == "AI_AGENT":
            return True
        for s in act.get("signers") or []:
            sa = _find_actor(state, s["actor_id"])
            if sa and sa["role"] == "AI_AGENT":
                return True
        return False
    if cond == "AMOUNT_GT_CAP":
        cap = (int(state["treasury_balance"]) * TREASURY_EMERGENCY_CAP_BPS) // 10000
        return int(act.get("amount", 0)) > cap
    if cond == "NO_TIMELOCK":
        return bool(act.get("emergency_bypass", False))
    if cond == "UNREVIEWED_EMERGENCY":
        return int((state.get("emergency") or {}).get("unreviewed_count", 0)) > 0
    return False


def evaluate_policy_hierarchy(
    state: Dict[str, Any], act: Dict[str, Any]
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """INV-07 deterministic 4-tier rule hierarchy with fail-closed conflict witness."""
    matched: List[Dict[str, Any]] = []
    highest_rank = 0
    highest_tier = ""
    for r in state.get("rules") or []:
        if r["action_type"] != "*" and r["action_type"] != act["type"]:
            continue
        if r["target"] != "*" and r["target"] != act.get("target", ""):
            continue
        if not _eval_rule_condition(r.get("condition", "ALWAYS"), state, act):
            continue
        matched.append(r)
        rank = TIER_RANK.get(r["tier"], 0)
        if rank > highest_rank:
            highest_rank = rank
            highest_tier = r["tier"]

    if not matched:
        return True, "OK", None

    allows = sorted(r["id"] for r in matched if TIER_RANK.get(r["tier"], 0) == highest_rank and r["effect"] == "ALLOW")
    denies = sorted(r["id"] for r in matched if TIER_RANK.get(r["tier"], 0) == highest_rank and r["effect"] == "DENY")
    lower_allows = sorted(
        r["id"] for r in matched if TIER_RANK.get(r["tier"], 0) < highest_rank and r["effect"] == "ALLOW"
    )

    if allows and denies:
        witness = {
            "tier": highest_tier,
            "allow_rule_ids": allows,
            "deny_rule_ids": denies,
            "action_id": act["id"],
            "action_type": act["type"],
            "target": act.get("target", ""),
            "epoch": int(act["epoch"]),
            "resolution": "DENY_RULE_CONFLICT",
        }
        return False, "ERR_DENY_RULE_CONFLICT", witness

    if denies:
        code = "ERR_POLICY_DENY"
        if highest_tier == "CONSTITUTIONAL" and lower_allows:
            code = "ERR_CONSTITUTIONAL_OVERRIDE_BLOCKED"
        return False, code, None

    return True, "OK", None


def _active_human_weight(state: Dict[str, Any]) -> int:
    return sum(
        int(a["voting_weight"])
        for a in state["actors"]
        if a["status"] == "ACTIVE" and a["role"] != "AI_AGENT"
    )


def _active_council_weight(state: Dict[str, Any]) -> int:
    return sum(
        int(a["voting_weight"])
        for a in state["actors"]
        if a["status"] == "ACTIVE" and a["role"] == "COUNCIL_MEMBER"
    )


def _has_delegation_overlap(state: Dict[str, Any], signer_set: Set[str], epoch: int) -> bool:
    for d in _active_delegations_at(state, epoch):
        if d["from"] in signer_set and d["to"] in signer_set:
            return True
    return False


def _signed_weight_with_delegation(state: Dict[str, Any], signer_set: Set[str], epoch: int) -> Tuple[int, int]:
    counted: Set[str] = set()
    weight = 0
    distinct_humans = 0
    for sid in signer_set:
        a = _find_actor(state, sid)
        if not a or a["status"] != "ACTIVE" or a["role"] == "AI_AGENT":
            continue
        if sid not in counted:
            counted.add(sid)
            weight += int(a["voting_weight"])
            distinct_humans += 1
    for d in _active_delegations_at(state, epoch):
        if d["to"] in signer_set and d["from"] not in counted and "VOTE_STANDARD" in (d.get("scopes") or []):
            fa = _find_actor(state, d["from"])
            if fa and fa["status"] == "ACTIVE" and fa["role"] != "AI_AGENT":
                counted.add(d["from"])
                weight += int(fa["voting_weight"])
    return weight, distinct_humans


def apply_action(
    state: Dict[str, Any], act: Dict[str, Any], verify_sigs: bool = True
) -> Tuple[str, str, Optional[Dict[str, Any]]]:
    """Atomically evaluate and apply act to state. On DENY, state is unmodified."""
    nxt = copy.deepcopy(state)
    verdict, code, witness = _apply_in_place(nxt, act, verify_sigs)
    if verdict == "ALLOW":
        state.clear()
        state.update(nxt)
    return verdict, code, witness


def _apply_in_place(
    s: Dict[str, Any], act: Dict[str, Any], verify_sigs: bool
) -> Tuple[str, str, Optional[Dict[str, Any]]]:
    epoch = int(act.get("epoch", 0))
    if epoch < int(s["epoch"]):
        return "DENY", "ERR_EPOCH_REGRESSION", None

    em = s.setdefault("emergency", {})
    effectively_paused = _is_paused_at(s, epoch)
    if em.get("paused") and epoch >= int(em.get("pause_expires_at", 0)):
        em["paused"] = False
        effectively_paused = False

    signers = act.get("signers") or []
    if not signers:
        return "DENY", "ERR_INVALID_SIGNATURE", None

    used_nonces = set(s.get("used_nonces") or [])
    signer_set: Set[str] = set()
    signer_ids: List[str] = []
    for sig in signers:
        sid = sig["actor_id"]
        if sid in signer_set:
            return "DENY", "ERR_DUPLICATE_SIGNER", None
        signer_set.add(sid)
        signer_ids.append(sid)
        sa = _find_actor(s, sid)
        if not sa:
            return "DENY", "ERR_ACTOR_NOT_FOUND", None
        nonce = int(sig["nonce"])
        if verify_sigs:
            msg = signing_preimage(act, sid, nonce)
            if not verify_ed25519(sa["pubkey_hex"], msg, sig["signature_hex"]):
                return "DENY", "ERR_INVALID_SIGNATURE", None
        if nonce <= int(sa.get("last_nonce", 0)) or f"{sid}:{nonce}" in used_nonces:
            return "DENY", "ERR_REPLAY_NONCE", None

    actor = _find_actor(s, act["actor_id"])
    if not actor:
        return "DENY", "ERR_ACTOR_NOT_FOUND", None

    act_type = act["type"]
    if actor["role"] == "AI_AGENT" and act_type in AI_FORBIDDEN_ACTIONS:
        return "DENY", "ERR_AI_CONSTITUTIONAL_VIOLATION", None
    for sig in signers:
        sa = _find_actor(s, sig["actor_id"])
        if sa and sa["role"] == "AI_AGENT" and act_type in AI_FORBIDDEN_ACTIONS:
            return "DENY", "ERR_AI_CONSTITUTIONAL_VIOLATION", None
    if act_type == "DELEGATE":
        tgt = _find_actor(s, act.get("target", ""))
        if tgt and tgt["role"] == "AI_AGENT":
            if any(sc in SOVEREIGN_SCOPES for sc in (act.get("scopes") or [])):
                return "DENY", "ERR_AI_CONSTITUTIONAL_VIOLATION", None

    if actor["status"] == "REVOKED":
        return "DENY", "ERR_ACTOR_REVOKED", None
    if actor["status"] == "SUSPENDED" and act_type not in ("APPEAL_FILE", "ADVANCE_CLOCK"):
        return "DENY", "ERR_ACTOR_SUSPENDED", None

    del_id = act.get("delegation_id") or ""
    if del_id and act_type not in ("DELEGATE", "REVOKE_DELEGATION"):
        d = _find_delegation(s, del_id)
        if not d or d.get("revoked") or int(d.get("expires_at", 0)) <= epoch:
            return "DENY", "ERR_DELEGATION_REVOKED", None
        fa = _find_actor(s, d["from"])
        if not fa or fa["status"] != "ACTIVE":
            return "DENY", "ERR_DELEGATION_REVOKED", None

    pol_ok, pol_code, witness = evaluate_policy_hierarchy(s, act)
    if not pol_ok:
        return "DENY", pol_code, witness

    if effectively_paused and act_type in (
        "TREASURY_QUEUE",
        "TREASURY_EXECUTE",
        "RULE_AMEND_QUEUE",
        "RULE_AMEND_EXECUTE",
    ):
        return "DENY", "ERR_PAUSED_ACTION_FORBIDDEN", None

    if act_type == "ADVANCE_CLOCK":
        pass
    elif act_type in ("ADVISORY_RECOMMEND", "FLAG_CONFLICT"):
        held = _effective_scopes(s, actor["id"], epoch)
        if (
            "ADVISORY_RECOMMEND" not in held
            and "FLAG_CONFLICT" not in held
            and actor["role"] not in ("COUNCIL_MEMBER", "HUMAN_MEMBER")
        ):
            return "DENY", "ERR_INSUFFICIENT_SCOPE", None
    elif act_type == "DELEGATE":
        tgt = _find_actor(s, act.get("target", ""))
        if not tgt:
            return "DENY", "ERR_ACTOR_NOT_FOUND", None
        if tgt["status"] != "ACTIVE":
            return "DENY", "ERR_ACTOR_REVOKED", None
        req_scopes = list(act.get("scopes") or [])
        dur = int(act.get("duration_sec", 0))
        if not req_scopes or dur <= 0:
            return "DENY", "ERR_DELEGATION_SCOPE_ESCALATION", None
        if _delegation_creates_cycle(s, actor["id"], tgt["id"], epoch):
            return "DENY", "ERR_DELEGATION_CYCLE", None
        if _max_incoming_depth(s, actor["id"], epoch) + 1 > MAX_DELEGATION_DEPTH:
            return "DENY", "ERR_DELEGATION_DEPTH_EXCEEDED", None
        held = _effective_scopes(s, actor["id"], epoch)
        base_set = set(actor.get("base_scopes") or [])
        req_exp = epoch + dur
        for sc in req_scopes:
            if sc not in held:
                return "DENY", "ERR_DELEGATION_SCOPE_ESCALATION", None
            if sc not in base_set:
                parent_exps = [
                    int(d["expires_at"])
                    for d in _active_delegations_at(s, epoch)
                    if d["to"] == actor["id"] and sc in (d.get("scopes") or [])
                ]
                if not parent_exps or req_exp > max(parent_exps):
                    return "DENY", "ERR_DELEGATION_EXPIRY_ESCALATION", None
        new_id = del_id or f"del-{actor['id']}-{tgt['id']}-{len(s.get('delegations') or []) + 1}"
        s.setdefault("delegations", []).append(
            {
                "id": new_id,
                "from": actor["id"],
                "to": tgt["id"],
                "scopes": sorted(req_scopes),
                "created_at": epoch,
                "expires_at": req_exp,
                "revoked": False,
                "revoked_at": 0,
            }
        )
    elif act_type == "REVOKE_ACTOR":
        held = _effective_scopes(s, actor["id"], epoch)
        if "REVOKE_MEMBER" not in held and actor["role"] != "COUNCIL_MEMBER":
            return "DENY", "ERR_INSUFFICIENT_SCOPE", None
        tgt = _find_actor(s, act.get("target", ""))
        if not tgt:
            return "DENY", "ERR_ACTOR_NOT_FOUND", None
        tgt["status"] = "REVOKED"
        tgt["revoked_at"] = epoch
        _transitive_revoke_actor(s, tgt["id"], epoch)
    elif act_type == "REVOKE_DELEGATION":
        d = _find_delegation(s, del_id)
        if not d:
            return "DENY", "ERR_DELEGATION_REVOKED", None
        if d["from"] != actor["id"] and "REVOKE_MEMBER" not in _effective_scopes(s, actor["id"], epoch):
            return "DENY", "ERR_INSUFFICIENT_SCOPE", None
        _transitive_revoke_delegation(s, del_id, epoch)
    elif act_type == "SUSPEND_ACTOR":
        held = _effective_scopes(s, actor["id"], epoch)
        if "REVOKE_MEMBER" not in held and actor["role"] != "COUNCIL_MEMBER":
            return "DENY", "ERR_INSUFFICIENT_SCOPE", None
        tgt = _find_actor(s, act.get("target", ""))
        if not tgt:
            return "DENY", "ERR_ACTOR_NOT_FOUND", None
        tgt["status"] = "SUSPENDED"
        cid = act.get("contested_id") or f"cont-{len(s.get('contested_actions') or []) + 1}"
        s.setdefault("contested_actions", []).append(
            {
                "id": cid,
                "kind": "SUSPEND",
                "initiator_id": actor["id"],
                "target_actor_id": tgt["id"],
                "created_at": epoch,
                "appeal_deadline": epoch + APPEAL_WINDOW_SEC,
                "appeal_filed": False,
                "appeal_status": "NONE",
                "judges": [],
                "finalized": False,
            }
        )
    elif act_type == "SELF_SUSPEND":
        actor["status"] = "SUSPENDED"
    elif act_type == "APPEAL_FILE":
        found = next((c for c in s.get("contested_actions") or [] if c["id"] == act.get("contested_id")), None)
        if not found or found.get("finalized"):
            return "DENY", "ERR_APPEAL_NOT_FOUND", None
        if epoch > int(found["appeal_deadline"]):
            return "DENY", "ERR_APPEAL_WINDOW_CLOSED", None
        found["appeal_filed"] = True
        found["appeal_status"] = "PENDING"
    elif act_type == "APPEAL_RESOLVE":
        found = next((c for c in s.get("contested_actions") or [] if c["id"] == act.get("contested_id")), None)
        if not found or found.get("appeal_status") != "PENDING":
            return "DENY", "ERR_APPEAL_NOT_FOUND", None
        valid_judges = 0
        judges = []
        for sig in signers:
            sid = sig["actor_id"]
            if sid in (found["initiator_id"], found["target_actor_id"]):
                return "DENY", "ERR_SELF_ADJUDICATION", None
            sa = _find_actor(s, sid)
            if sa and sa["status"] == "ACTIVE" and (
                sa["role"] == "APPEAL_JUDGE" or "APPEAL_ADJUDICATE" in (sa.get("base_scopes") or [])
            ):
                valid_judges += 1
                judges.append(sid)
        if valid_judges < 2:
            return "DENY", "ERR_INSUFFICIENT_JUDGES", None
        found["judges"] = sorted(judges)
        outcome = act.get("appeal_outcome")
        if outcome != "OVERTURNED":
            outcome = "UPHELD"
        found["appeal_status"] = outcome
        if outcome == "OVERTURNED":
            tgt = _find_actor(s, found["target_actor_id"])
            if tgt and tgt["status"] == "SUSPENDED":
                tgt["status"] = "ACTIVE"
            found["finalized"] = True
    elif act_type == "FINALIZE_CONTESTED":
        found = next((c for c in s.get("contested_actions") or [] if c["id"] == act.get("contested_id")), None)
        if not found:
            return "DENY", "ERR_APPEAL_NOT_FOUND", None
        if found["appeal_status"] == "PENDING":
            return "DENY", "ERR_APPEAL_FREEZE_ACTIVE", None
        if found["appeal_status"] == "NONE" and epoch < int(found["appeal_deadline"]):
            return "DENY", "ERR_APPEAL_WINDOW_OPEN", None
        found["finalized"] = True
        if found["appeal_status"] != "OVERTURNED":
            tgt = _find_actor(s, found["target_actor_id"])
            if tgt:
                tgt["status"] = "REVOKED"
                tgt["revoked_at"] = epoch
                _transitive_revoke_actor(s, tgt["id"], epoch)
    elif act_type == "TREASURY_QUEUE":
        if _has_delegation_overlap(s, signer_set, epoch):
            return "DENY", "ERR_DOUBLE_VOTE_DELEGATION", None
        active_w = _active_human_weight(s)
        floor_w = (int(s["genesis_active_weight"]) * QUORUM_FLOOR_BPS) // 10000
        if active_w < floor_w:
            return "DENY", "ERR_QUORUM_FLOOR_BREACHED", None
        signed_w, _ = _signed_weight_with_delegation(s, signer_set, epoch)
        if active_w == 0 or signed_w * 10000 < active_w * QUORUM_STANDARD_BPS:
            return "DENY", "ERR_QUORUM_NOT_MET", None
        if "TREASURY_SPEND" not in _effective_scopes(s, actor["id"], epoch):
            return "DENY", "ERR_INSUFFICIENT_SCOPE", None
        amt = int(act.get("amount", 0))
        if amt > int(s["treasury_balance"]):
            return "DENY", "ERR_TREASURY_INSUFFICIENT", None
        pid = act.get("proposal_id") or f"prop-{len(s.get('queued_actions') or []) + 1}"
        origin = _delegation_root_origin(s, del_id) if del_id else ""
        s.setdefault("queued_actions", []).append(
            {
                "id": pid,
                "kind": "TREASURY",
                "proposer_id": actor["id"],
                "target": act.get("target", ""),
                "amount": amt,
                "queued_at": epoch,
                "min_timelock_sec": MIN_TIMELOCK_TREASURY_SEC,
                "delegation_id": del_id,
                "delegation_origin": origin,
                "executed": False,
                "invalidated": False,
                "invalidated_at": 0,
            }
        )
    elif act_type == "TREASURY_EXECUTE":
        q = next(
            (x for x in s.get("queued_actions") or [] if x["id"] == act.get("proposal_id") and x["kind"] == "TREASURY"),
            None,
        )
        if not q or q.get("executed"):
            return "DENY", "ERR_PROPOSAL_NOT_FOUND", None
        if q.get("invalidated"):
            return "DENY", "ERR_PROPOSER_AUTHORITY_REVOKED", None
        prop = _find_actor(s, q["proposer_id"])
        if not prop or prop["status"] == "REVOKED":
            return "DENY", "ERR_PROPOSER_AUTHORITY_REVOKED", None
        if q.get("delegation_origin"):
            orig = _find_actor(s, q["delegation_origin"])
            if not orig or orig["status"] == "REVOKED":
                return "DENY", "ERR_PROPOSER_AUTHORITY_REVOKED", None
        if epoch < int(q["queued_at"]) + int(q["min_timelock_sec"]):
            return "DENY", "ERR_TIMELOCK_NOT_ELAPSED", None
        if int(q["amount"]) > int(s["treasury_balance"]):
            return "DENY", "ERR_TREASURY_INSUFFICIENT", None
        s["treasury_balance"] = int(s["treasury_balance"]) - int(q["amount"])
        q["executed"] = True
    elif act_type == "RULE_AMEND_QUEUE":
        if _has_delegation_overlap(s, signer_set, epoch):
            return "DENY", "ERR_DOUBLE_VOTE_DELEGATION", None
        active_w = _active_human_weight(s)
        floor_w = (int(s["genesis_active_weight"]) * QUORUM_FLOOR_BPS) // 10000
        if active_w < floor_w:
            return "DENY", "ERR_QUORUM_FLOOR_BREACHED", None
        signed_w, distinct_humans = _signed_weight_with_delegation(s, signer_set, epoch)
        denom = max(active_w, floor_w)
        if denom == 0 or signed_w * 10000 < denom * SUPERMAJORITY_META_GOV_BPS or distinct_humans < 2:
            return "DENY", "ERR_SUPERMAJORITY_NOT_MET", None
        pid = act.get("proposal_id") or f"amend-{len(s.get('queued_actions') or []) + 1}"
        s.setdefault("queued_actions", []).append(
            {
                "id": pid,
                "kind": "RULE_AMEND",
                "proposer_id": actor["id"],
                "target": act.get("target", ""),
                "new_rule": copy.deepcopy(act.get("new_rule")),
                "queued_at": epoch,
                "min_timelock_sec": MIN_TIMELOCK_RULE_AMEND_SEC,
                "delegation_id": "",
                "delegation_origin": "",
                "executed": False,
                "invalidated": False,
                "invalidated_at": 0,
            }
        )
    elif act_type == "RULE_AMEND_EXECUTE":
        q = next(
            (x for x in s.get("queued_actions") or [] if x["id"] == act.get("proposal_id") and x["kind"] == "RULE_AMEND"),
            None,
        )
        if not q or q.get("executed"):
            return "DENY", "ERR_PROPOSAL_NOT_FOUND", None
        if q.get("invalidated"):
            return "DENY", "ERR_PROPOSER_AUTHORITY_REVOKED", None
        if epoch < int(q["queued_at"]) + int(q["min_timelock_sec"]):
            return "DENY", "ERR_TIMELOCK_NOT_ELAPSED", None
        if q.get("new_rule") is not None:
            s.setdefault("rules", []).append(copy.deepcopy(q["new_rule"]))
        q["executed"] = True
    elif act_type == "EMERGENCY_PAUSE":
        dur = int(act.get("duration_sec", 0))
        if dur <= 0 or dur > MAX_EMERGENCY_DURATION_SEC:
            return "DENY", "ERR_EMERGENCY_DURATION_EXCEEDED", None
        if effectively_paused:
            return "DENY", "ERR_EMERGENCY_SELF_RENEWAL", None
        council_w = _active_council_weight(s)
        signed_cw = 0
        council_signers = 0
        for sid in signer_set:
            sa = _find_actor(s, sid)
            if sa and sa["status"] == "ACTIVE" and sa["role"] == "COUNCIL_MEMBER":
                signed_cw += int(sa["voting_weight"])
                council_signers += 1
        if council_w == 0 or council_signers < 2 or signed_cw * 10000 < council_w * SUPERMAJORITY_EMERGENCY_BPS:
            return "DENY", "ERR_SUPERMAJORITY_NOT_MET", None
        em["paused"] = True
        em["pause_started_at"] = epoch
        em["pause_expires_at"] = epoch + dur
        em["last_triggerers"] = sorted(signer_ids)
        em["unreviewed_count"] = int(em.get("unreviewed_count", 0)) + 1
    elif act_type == "EMERGENCY_RENEW":
        dur = int(act.get("duration_sec", 0))
        if dur <= 0 or dur > MAX_EMERGENCY_DURATION_SEC:
            return "DENY", "ERR_EMERGENCY_DURATION_EXCEEDED", None
        if effectively_paused:
            return "DENY", "ERR_EMERGENCY_SELF_RENEWAL", None
        prev_exp = int(em.get("pause_expires_at", 0))
        if prev_exp > 0 and epoch < prev_exp + RENEWAL_COOLDOWN_SEC:
            return "DENY", "ERR_EMERGENCY_COOLDOWN_ACTIVE", None
        active_w = _active_human_weight(s)
        signed_w, distinct_humans = _signed_weight_with_delegation(s, signer_set, epoch)
        prev_set = set(em.get("last_triggerers") or [])
        has_fresh = any(
            sid not in prev_set
            and (_find_actor(s, sid) or {}).get("status") == "ACTIVE"
            and (_find_actor(s, sid) or {}).get("role") != "AI_AGENT"
            for sid in signer_set
        )
        if not has_fresh:
            return "DENY", "ERR_EMERGENCY_SELF_RENEWAL", None
        if active_w == 0 or distinct_humans < 3 or signed_w * 10000 < active_w * SUPERMAJORITY_META_GOV_BPS:
            return "DENY", "ERR_EMERGENCY_RENEWAL_QUORUM", None
        em["paused"] = True
        em["pause_started_at"] = epoch
        em["pause_expires_at"] = epoch + dur
        em["last_triggerers"] = sorted(signer_ids)
        em["renewal_count"] = int(em.get("renewal_count", 0)) + 1
        em["unreviewed_count"] = int(em.get("unreviewed_count", 0)) + 1
    elif act_type == "EXPERIMENT_VALIDATE":
        if "EXPERIMENT_VALIDATE" not in _effective_scopes(s, actor["id"], epoch) and actor["role"] != "COUNCIL_MEMBER":
            return "DENY", "ERR_INSUFFICIENT_SCOPE", None
    else:
        return "DENY", "ERR_UNKNOWN_ACTION", None

    s["epoch"] = epoch
    for sig in signers:
        sa = _find_actor(s, sig["actor_id"])
        assert sa is not None
        nonce = int(sig["nonce"])
        if nonce > int(sa.get("last_nonce", 0)):
            sa["last_nonce"] = nonce
        s.setdefault("used_nonces", []).append(f"{sig['actor_id']}:{nonce}")
    return "ALLOW", "OK", None

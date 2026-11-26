# SPDX-License-Identifier: Apache-2.0
"""Independent clean-room 6-phase order-independent replay engine for zoo-experience-ledger/v1."""

from __future__ import annotations

import json
from collections import deque
from typing import Any

from .canonical import (
    SCHEMA_VERSION,
    compute_event_id,
    compute_policy_sha256,
    compute_state_root_hash,
    signing_message,
)
from .ed25519 import ed25519_verify
from .merkle import compute_active_merkle_root
from .vfs import LocalVFSStore, validate_storage_uri

VALID_ROLES = {"human_researcher", "ai_agent", "steward"}
VALID_REASON_CODES = {
    "retracted_by_author",
    "corrupted_artifact",
    "falsified_claim",
    "policy_violation",
    "superseded",
}
VALID_OUTCOMES = {"select_canonical", "reject_all", "keep_both_scoped"}

ERR_INVALID_SCHEMA = "ERR_INVALID_SCHEMA"
ERR_EVENT_ID_MISMATCH = "ERR_EVENT_ID_MISMATCH"
ERR_UNKNOWN_PRINCIPAL = "ERR_UNKNOWN_PRINCIPAL"
ERR_INVALID_SIGNATURE = "ERR_INVALID_SIGNATURE"
ERR_AI_AGENT_RESOLUTION_FORBIDDEN = "ERR_AI_AGENT_RESOLUTION_FORBIDDEN"
ERR_UNAUTHORIZED_RESOLUTION = "ERR_UNAUTHORIZED_RESOLUTION"
ERR_UNAUTHORIZED_REVOCATION = "ERR_UNAUTHORIZED_REVOCATION"
ERR_SELF_VALIDATION_FORBIDDEN = "ERR_SELF_VALIDATION_FORBIDDEN"
ERR_INVALID_RESOLUTION_TARGET = "ERR_INVALID_RESOLUTION_TARGET"
ERR_CYCLE_DETECTED = "ERR_CYCLE_DETECTED"


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_lower_hex(s: Any, length: int) -> bool:
    return isinstance(s, str) and len(s) == length and all(c in "0123456789abcdef" for c in s)


def _is_valid_domain(s: Any) -> bool:
    if not isinstance(s, str) or not (1 <= len(s) <= 128):
        return False
    parts = s.split(".")
    for idx, seg in enumerate(parts):
        if not seg:
            return False
        for c in seg:
            alnum = ("a" <= c <= "z") or ("0" <= c <= "9")
            if idx == 0:
                if not alnum:
                    return False
            else:
                if not (alnum or c in "_-"):
                    return False
    return True


def _is_valid_claim_key(s: Any) -> bool:
    if not isinstance(s, str) or not (1 <= len(s) <= 128):
        return False
    c0 = s[0]
    if not (("a" <= c0 <= "z") or ("0" <= c0 <= "9")):
        return False
    return all(("a" <= c <= "z") or ("0" <= c <= "9") or c in "._-" for c in s[1:])


def _is_sorted_unique(items: Any) -> bool:
    if not isinstance(items, list):
        return False
    if not all(isinstance(x, str) for x in items):
        return False
    for i in range(1, len(items)):
        if items[i] <= items[i - 1]:
            return False
    return True


def _is_valid_external_uri(u: str) -> bool:
    return (
        (u.startswith("ipfs://") and len(u) > len("ipfs://"))
        or (u.startswith("ar://") and len(u) > len("ar://"))
        or (u.startswith("https://") and len(u) > len("https://"))
    )


def validate_policy(policy: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, bytes]]:
    """Validate Policy structure, policy_sha256, and Ed25519 public keys."""
    if policy.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"policy: invalid schema_version {policy.get('schema_version')!r}")
    pid = policy.get("policy_id")
    if not isinstance(pid, str) or not (1 <= len(pid) <= 128):
        raise ValueError("policy: invalid policy_id")
    pr_list = policy.get("principals")
    if not isinstance(pr_list, list) or not pr_list:
        raise ValueError("policy: principals must be a non-empty list")
    expected = compute_policy_sha256(policy)
    if policy.get("policy_sha256") != expected:
        raise ValueError(f"policy: policy_sha256 mismatch: {policy.get('policy_sha256')} != {expected}")

    principals: dict[str, dict[str, Any]] = {}
    pub_keys: dict[str, bytes] = {}
    for pr in pr_list:
        prid = pr.get("principal_id")
        if not isinstance(prid, str) or not (1 <= len(prid) <= 128):
            raise ValueError(f"policy: invalid principal_id {prid!r}")
        if prid in principals:
            raise ValueError(f"policy: duplicate principal_id {prid!r}")
        if pr.get("role") not in VALID_ROLES:
            raise ValueError(f"policy: invalid role {pr.get('role')!r}")
        pk_hex = pr.get("public_key_hex")
        if not _is_lower_hex(pk_hex, 64):
            raise ValueError(f"policy: invalid public_key_hex for {prid!r}")
        if not isinstance(pr.get("active"), bool):
            raise ValueError(f"policy: active must be bool for {prid!r}")
        principals[prid] = pr
        pub_keys[prid] = bytes.fromhex(pk_hex)
    return principals, pub_keys


def _signer_id_of(event: dict[str, Any]) -> str:
    et = event.get("event_type")
    if et == "experience_entry":
        return str(event.get("contributor_id", ""))
    if et == "revocation_record":
        return str(event.get("issuer_id", ""))
    if et == "conflict_flag":
        return str(event.get("flagger_id", ""))
    if et == "resolution_decision":
        return str(event.get("steward_id", ""))
    return ""


def _validate_event_schema(e: dict[str, Any]) -> bool:
    if not isinstance(e, dict):
        return False
    if e.get("schema_version") != SCHEMA_VERSION:
        return False
    ts = e.get("created_at_unix")
    if not _is_int(ts) or ts < 0:
        return False
    if not _is_lower_hex(e.get("event_id"), 64) or not _is_lower_hex(e.get("signature_hex"), 128):
        return False

    et = e.get("event_type")
    if et == "experience_entry":
        cid = e.get("contributor_id", "")
        if not isinstance(cid, str) or not (1 <= len(cid) <= 128):
            return False
        if not _is_valid_domain(e.get("domain")) or not _is_valid_claim_key(e.get("claim_key")):
            return False
        if not _is_lower_hex(e.get("claim_value_hash"), 64):
            return False
        summary = e.get("summary", "")
        if not isinstance(summary, str) or not (1 <= len(summary.encode("utf-8")) <= 1024):
            return False
        conf = e.get("confidence_bps")
        if not _is_int(conf) or not (0 <= conf <= 10000):
            return False
        art_hash = e.get("artifact_sha256", "")
        art_uri = e.get("artifact_uri", "")
        if not _is_lower_hex(art_hash, 64) or not validate_storage_uri(art_uri, art_hash):
            return False
        art_size = e.get("artifact_size_bytes")
        if not _is_int(art_size) or art_size < 0:
            return False
        nonce = e.get("nonce", "")
        if not isinstance(nonce, str) or len(nonce) > 128:
            return False
        receipt = e.get("receipt_hash", "")
        if not isinstance(receipt, str) or (receipt != "" and not _is_lower_hex(receipt, 64)):
            return False
        ext = e.get("external_uris", [])
        if ext is None:
            ext = []
        if not _is_sorted_unique(ext) or not all(_is_valid_external_uri(u) for u in ext):
            return False
        parents = e.get("parent_hashes", [])
        if parents is None:
            parents = []
        if not _is_sorted_unique(parents) or not all(_is_lower_hex(p, 64) for p in parents):
            return False
        return True

    if et == "revocation_record":
        iid = e.get("issuer_id", "")
        if not isinstance(iid, str) or not (1 <= len(iid) <= 128):
            return False
        if not _is_lower_hex(e.get("target_event_id"), 64):
            return False
        if e.get("reason_code") not in VALID_REASON_CODES:
            return False
        reason = e.get("reason", "")
        if not isinstance(reason, str) or not (1 <= len(reason.encode("utf-8")) <= 1024):
            return False
        ev_hash = e.get("evidence_sha256", "")
        ev_uri = e.get("evidence_uri", "")
        if ev_hash == "" and ev_uri == "":
            return True
        return _is_lower_hex(ev_hash, 64) and validate_storage_uri(ev_uri, ev_hash)

    if et == "conflict_flag":
        fid = e.get("flagger_id", "")
        if not isinstance(fid, str) or not (1 <= len(fid) <= 128):
            return False
        if not _is_valid_domain(e.get("domain")) or not _is_valid_claim_key(e.get("claim_key")):
            return False
        cids = e.get("conflicting_event_ids", [])
        if not _is_sorted_unique(cids) or len(cids) < 2 or not all(_is_lower_hex(x, 64) for x in cids):
            return False
        ev_hash = e.get("evidence_sha256", "")
        ev_uri = e.get("evidence_uri", "")
        if not _is_lower_hex(ev_hash, 64) or not validate_storage_uri(ev_uri, ev_hash):
            return False
        rat = e.get("rationale", "")
        if not isinstance(rat, str) or not (1 <= len(rat.encode("utf-8")) <= 1024):
            return False
        return True

    if et == "resolution_decision":
        sid = e.get("steward_id", "")
        if not isinstance(sid, str) or not (1 <= len(sid) <= 128):
            return False
        if not _is_valid_domain(e.get("domain")) or not _is_valid_claim_key(e.get("claim_key")):
            return False
        rids = e.get("reviewed_event_ids", [])
        if not _is_sorted_unique(rids) or len(rids) < 2 or not all(_is_lower_hex(x, 64) for x in rids):
            return False
        outcome = e.get("outcome")
        win = e.get("winning_event_id", "")
        if outcome == "select_canonical":
            if not _is_lower_hex(win, 64) or win not in rids:
                return False
        elif outcome in ("reject_all", "keep_both_scoped"):
            if win != "":
                return False
        else:
            return False
        rat_hash = e.get("rationale_sha256", "")
        rat_uri = e.get("rationale_uri", "")
        if not _is_lower_hex(rat_hash, 64) or not validate_storage_uri(rat_uri, rat_hash):
            return False
        gref = e.get("governance_ref", "")
        if not isinstance(gref, str) or len(gref) > 128:
            return False
        return True

    return False


def _verify_event_intrinsic(
    e: dict[str, Any],
    principals: dict[str, dict[str, Any]],
    pub_keys: dict[str, bytes],
) -> str:
    if not _validate_event_schema(e):
        return ERR_INVALID_SCHEMA
    try:
        computed = compute_event_id(e)
    except Exception:
        return ERR_EVENT_ID_MISMATCH
    if computed != e["event_id"]:
        return ERR_EVENT_ID_MISMATCH
    signer_id = _signer_id_of(e)
    pr = principals.get(signer_id)
    if pr is None or not pr["active"]:
        return ERR_UNKNOWN_PRINCIPAL
    sig = bytes.fromhex(e["signature_hex"])
    if not ed25519_verify(pub_keys[signer_id], signing_message(e["event_id"]), sig):
        return ERR_INVALID_SIGNATURE
    if e["event_type"] == "resolution_decision":
        if pr["role"] == "ai_agent":
            return ERR_AI_AGENT_RESOLUTION_FORBIDDEN
        if pr["role"] != "steward":
            return ERR_UNAUTHORIZED_RESOLUTION
    return ""


def _detect_cycle_nodes(entries: dict[str, dict[str, Any]]) -> set[str]:
    """Deterministic Tarjan SCC over parent_hashes edges to detect cycles & self-loops."""
    cycle_nodes: set[str] = set()
    index = 0
    indices: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []

    def strong_connect(v: str) -> None:
        nonlocal index
        index += 1
        indices[v] = index
        lowlink[v] = index
        stack.append(v)
        on_stack.add(v)
        for w in entries[v].get("parent_hashes") or []:
            if w == v:
                cycle_nodes.add(v)
            if w not in entries:
                continue
            if w not in indices:
                strong_connect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in on_stack:
                lowlink[v] = min(lowlink[v], indices[w])
        if lowlink[v] == indices[v]:
            scc: list[str] = []
            while True:
                w = stack.pop()
                on_stack.remove(w)
                scc.append(w)
                if w == v:
                    break
            if len(scc) > 1:
                cycle_nodes.update(scc)

    for eid in sorted(entries):
        if eid not in indices:
            strong_connect(eid)
    return cycle_nodes


def _replay_verified(
    policy: dict[str, Any],
    principals: dict[str, dict[str, Any]],
    verified: dict[str, dict[str, Any]],
    rejected_set: set[tuple[str, str, str]],
    total_inputs: int,
    duplicates: int,
) -> dict[str, Any]:
    def add_reject(ev: dict[str, Any], code: str) -> None:
        eid = ev.get("event_id") or "<missing>"
        rejected_set.add((str(eid), str(ev.get("event_type", "")), code))

    entries: dict[str, dict[str, Any]] = {}
    revocations: list[dict[str, Any]] = []
    flags: list[dict[str, Any]] = []
    resolutions: list[dict[str, Any]] = []

    for eid in sorted(verified):
        ev = verified[eid]
        et = ev["event_type"]
        if et == "experience_entry":
            entries[eid] = ev
        elif et == "revocation_record":
            revocations.append(ev)
        elif et == "conflict_flag":
            flags.append(ev)
        elif et == "resolution_decision":
            resolutions.append(ev)

    # Phase 1: Cycle detection
    for cid in sorted(_detect_cycle_nodes(entries)):
        add_reject(entries[cid], ERR_CYCLE_DETECTED)
        del entries[cid]

    # Phase 2: Revocation authorization
    revoked_by: dict[str, list[str]] = {}
    pending_revocations: list[str] = []
    for r in revocations:
        target = entries.get(r["target_event_id"])
        if target is None:
            pending_revocations.append(r["event_id"])
            continue
        issuer = principals[r["issuer_id"]]
        if r["issuer_id"] != target["contributor_id"] and issuer["role"] != "steward":
            add_reject(r, ERR_UNAUTHORIZED_REVOCATION)
            continue
        revoked_by.setdefault(target["event_id"], []).append(r["event_id"])
    for k in revoked_by:
        revoked_by[k].sort()
    pending_revocations.sort()

    # Phase 3: Deterministic causal taint propagation
    entry_ids = sorted(entries)
    children: dict[str, list[str]] = {eid: [] for eid in entry_ids}
    unresolved_parents: dict[str, list[str]] = {}
    for eid in entry_ids:
        for p in entries[eid].get("parent_hashes") or []:
            if p in entries:
                children[p].append(eid)
            else:
                unresolved_parents.setdefault(eid, []).append(p)
        if eid in unresolved_parents:
            unresolved_parents[eid].sort()

    tainted_by_sets: dict[str, set[str]] = {}
    for rev_id in sorted(revoked_by):
        visited = {rev_id}
        q: deque[str] = deque([rev_id])
        while q:
            cur = q.popleft()
            for ch in children.get(cur, []):
                if ch in visited:
                    continue
                visited.add(ch)
                if ch not in revoked_by:
                    tainted_by_sets.setdefault(ch, set()).add(rev_id)
                q.append(ch)
    tainted_by = {k: sorted(v) for k, v in tainted_by_sets.items()}

    def is_eligible(eid: str) -> bool:
        return eid in entries and eid not in revoked_by and eid not in tainted_by

    # Phase 4: ConflictSet construction
    slot_entries: dict[str, list[str]] = {}
    slot_claims: dict[str, set[str]] = {}
    slot_meta: dict[str, tuple[str, str]] = {}
    for eid in entry_ids:
        if not is_eligible(eid):
            continue
        ev = entries[eid]
        slot = f"{ev['domain']}/{ev['claim_key']}"
        slot_entries.setdefault(slot, []).append(eid)
        slot_claims.setdefault(slot, set()).add(ev["claim_value_hash"])
        slot_meta[slot] = (ev["domain"], ev["claim_key"])

    slot_flags: dict[str, list[str]] = {}
    for fl in flags:
        slot = f"{fl['domain']}/{fl['claim_key']}"
        valid_refs = sum(
            1
            for cid in fl["conflicting_event_ids"]
            if is_eligible(cid)
            and entries[cid]["domain"] == fl["domain"]
            and entries[cid]["claim_key"] == fl["claim_key"]
        )
        if valid_refs >= 2:
            slot_flags.setdefault(slot, []).append(fl["event_id"])
    for slot in slot_flags:
        slot_flags[slot].sort()

    # Phase 5: Steward ResolutionDecision validation & evaluation
    valid_res_by_slot: dict[str, list[dict[str, Any]]] = {}
    for res in resolutions:
        if res["outcome"] == "select_canonical":
            win_id = res["winning_event_id"]
            win = entries.get(win_id)
            if (
                win is None
                or not is_eligible(win_id)
                or win["domain"] != res["domain"]
                or win["claim_key"] != res["claim_key"]
            ):
                add_reject(res, ERR_INVALID_RESOLUTION_TARGET)
                continue
            if win["contributor_id"] == res["steward_id"]:
                add_reject(res, ERR_SELF_VALIDATION_FORBIDDEN)
                continue
        slot = f"{res['domain']}/{res['claim_key']}"
        valid_res_by_slot.setdefault(slot, []).append(res)

    status_map: dict[str, str] = {}
    for eid in entry_ids:
        if eid in revoked_by:
            status_map[eid] = "revoked"
        elif eid in tainted_by:
            status_map[eid] = "tainted"
        else:
            status_map[eid] = "active"

    conflicts: list[dict[str, Any]] = []
    for slot in sorted(slot_entries):
        competing = sorted(slot_entries[slot])
        has_div = len(slot_claims[slot]) >= 2
        has_flg = bool(slot_flags.get(slot))
        if not has_div and not has_flg:
            continue

        competing_set = set(competing)
        applicable = [
            res
            for res in valid_res_by_slot.get(slot, [])
            if competing_set.issubset(set(res["reviewed_event_ids"]))
        ]
        dom, ckey = slot_meta[slot]
        cs: dict[str, Any] = {
            "slot": slot,
            "domain": dom,
            "claim_key": ckey,
            "status": "open",
            "competing_event_ids": competing,
            "flag_ids": list(slot_flags.get(slot, [])),
            "resolution_ids": [],
            "canonical_event_id": "",
        }
        if not applicable:
            for eid in competing:
                status_map[eid] = "conflicted"
        else:
            cs["resolution_ids"] = sorted(r["event_id"] for r in applicable)
            distinct = {(r["outcome"], r["winning_event_id"]) for r in applicable}
            if len(distinct) == 1:
                outcome, winner = next(iter(distinct))
                cs["status"] = "resolved"
                if outcome == "select_canonical":
                    cs["canonical_event_id"] = winner
                    for eid in competing:
                        status_map[eid] = "active" if eid == winner else "superseded"
                elif outcome == "reject_all":
                    for eid in competing:
                        status_map[eid] = "superseded"
                elif outcome == "keep_both_scoped":
                    for eid in competing:
                        status_map[eid] = "active"
            else:
                cs["status"] = "escalated_steward_disagreement"
                for eid in competing:
                    status_map[eid] = "conflicted"
        conflicts.append(cs)

    # Phase 6: Final projections, Merkle root, and StateRootHash
    entry_states: list[dict[str, Any]] = []
    active_ids: list[str] = []
    for eid in entry_ids:
        ev = entries[eid]
        st = status_map[eid]
        if st == "active":
            active_ids.append(eid)
        entry_states.append(
            {
                "event_id": eid,
                "contributor_id": ev["contributor_id"],
                "domain": ev["domain"],
                "claim_key": ev["claim_key"],
                "claim_value_hash": ev["claim_value_hash"],
                "artifact_sha256": ev["artifact_sha256"],
                "artifact_uri": ev["artifact_uri"],
                "status": st,
                "revoked_by": list(revoked_by.get(eid, [])),
                "tainted_by_ancestors": list(tainted_by.get(eid, [])),
                "unresolved_parents": list(unresolved_parents.get(eid, [])),
            }
        )
    active_ids.sort()
    active_merkle_root = compute_active_merkle_root(active_ids)

    rejected_list = [
        {"event_id": eid, "event_type": et, "error_code": code}
        for (eid, et, code) in sorted(rejected_set, key=lambda t: (t[0], t[2], t[1]))
    ]

    commitment = {
        "schema_version": SCHEMA_VERSION,
        "policy_sha256": policy["policy_sha256"],
        "active_merkle_root": active_merkle_root,
        "entry_states": entry_states,
        "conflicts": conflicts,
        "pending_revocations": pending_revocations,
        "rejected_events": rejected_list,
    }
    state_root_hash = compute_state_root_hash(commitment)
    return {
        "state_root_hash": state_root_hash,
        "commitment": commitment,
        "active_event_ids": active_ids,
        "total_input_count": total_inputs,
        "unique_accepted": len(verified),
        "duplicate_count": duplicates,
    }


def replay(policy: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    """Execute 6-phase order-independent replay over policy and events."""
    principals, pub_keys = validate_policy(policy)
    verified: dict[str, dict[str, Any]] = {}
    rejected_set: set[tuple[str, str, str]] = set()
    duplicates = 0

    for ev in events:
        eid = ev.get("event_id", "") if isinstance(ev, dict) else ""
        if eid and eid in verified:
            try:
                if compute_event_id(ev) == eid:
                    duplicates += 1
                    continue
            except Exception:
                pass
        code = _verify_event_intrinsic(ev, principals, pub_keys)
        if code:
            rejected_set.add((str(eid or "<missing>"), str(ev.get("event_type", "") if isinstance(ev, dict) else ""), code))
            continue
        verified[eid] = ev

    return _replay_verified(policy, principals, verified, rejected_set, len(events), duplicates)


def create_checkpoint(
    policy: dict[str, Any], events: list[dict[str, Any]], vfs: LocalVFSStore
) -> dict[str, Any]:
    """Create and persist a VFS/S3 CheckpointSnapshot."""
    principals, pub_keys = validate_policy(policy)
    verified: dict[str, dict[str, Any]] = {}
    rejected_set: set[tuple[str, str, str]] = set()
    duplicates = 0
    for ev in events:
        eid = ev.get("event_id", "") if isinstance(ev, dict) else ""
        if eid and eid in verified:
            try:
                if compute_event_id(ev) == eid:
                    duplicates += 1
                    continue
            except Exception:
                pass
        code = _verify_event_intrinsic(ev, principals, pub_keys)
        if code:
            rejected_set.add((str(eid or "<missing>"), str(ev.get("event_type", "")), code))
            continue
        verified[eid] = ev

    state = _replay_verified(policy, principals, verified, rejected_set, len(events), duplicates)
    snap = {
        "schema_version": SCHEMA_VERSION,
        "policy_sha256": policy["policy_sha256"],
        "state_root_hash": state["state_root_hash"],
        "commitment": state["commitment"],
        "included_events": [verified[k] for k in sorted(verified)],
    }
    raw = json.dumps(snap, sort_keys=True, separators=(",", ":")).encode("utf-8")
    put_res = vfs.put(raw)
    snap["checkpoint_hash"] = put_res.sha256
    snap["checkpoint_uri"] = put_res.uri
    return snap


def replay_from_checkpoint(
    policy: dict[str, Any],
    checkpoint_hash: str,
    vfs: LocalVFSStore,
    delta_events: list[dict[str, Any]],
) -> dict[str, Any]:
    """Load VFS checkpoint and verify only delta_events for bounded-latency incremental replay."""
    principals, pub_keys = validate_policy(policy)
    snap = json.loads(vfs.get(checkpoint_hash).decode("utf-8"))
    if snap["policy_sha256"] != policy["policy_sha256"]:
        raise ValueError("checkpoint policy mismatch")

    verified = {ev["event_id"]: ev for ev in snap["included_events"]}
    rejected_set = {
        (rj["event_id"], rj["event_type"], rj["error_code"])
        for rj in snap["commitment"]["rejected_events"]
    }
    duplicates = 0
    for ev in delta_events:
        eid = ev.get("event_id", "") if isinstance(ev, dict) else ""
        if eid and eid in verified:
            try:
                if compute_event_id(ev) == eid:
                    duplicates += 1
                    continue
            except Exception:
                pass
        code = _verify_event_intrinsic(ev, principals, pub_keys)
        if code:
            rejected_set.add((str(eid or "<missing>"), str(ev.get("event_type", "")), code))
            continue
        verified[eid] = ev

    return _replay_verified(
        policy,
        principals,
        verified,
        rejected_set,
        len(snap["included_events"]) + len(delta_events),
        duplicates,
    )

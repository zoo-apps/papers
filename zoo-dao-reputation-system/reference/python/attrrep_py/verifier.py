# SPDX-License-Identifier: Apache-2.0
"""Independent clean-room pure-Python verifier for attribution-rep.v1 (HIP-1352)."""

from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from .canonical import (
    canonical_json,
    compute_attestation_uid,
    merkle_root,
    verify_attestation_signature,
    verify_contribution_signature,
)
from .fingerprint import BPS_SCALE, compute_fingerprints, containment_bps

SCHEMA_VERSION = "attribution-rep.v1"
SPEC_VERSION = "1.0.0"

MICRO_SCALE = 1_000_000

ROLE_RESEARCHER = "RESEARCHER"
ROLE_SEED = "SEED_STEWARD"
ROLE_AI_AGENT = "AI_AGENT"

SCHEMA_PEER_REVIEW = "0x1111111111111111111111111111111111111111111111111111111111111101"
SCHEMA_REPLICATION = "0x1111111111111111111111111111111111111111111111111111111111111102"
SCHEMA_REUSE_ENDORSEMENT = "0x1111111111111111111111111111111111111111111111111111111111111103"
SCHEMA_SIMILARITY_FLAG = "0x1111111111111111111111111111111111111111111111111111111111111104"
SCHEMA_POLICY_MUTATION = "0x1111111111111111111111111111111111111111111111111111111111111105"
SCHEMA_TREASURY_AUTH = "0x1111111111111111111111111111111111111111111111111111111111111106"

STATUS_ACCEPTED = "ACCEPTED"
STATUS_REJECTED = "REJECTED"
STATUS_ADVISORY = "ADVISORY"

ERR_NONE = ""
ERR_UNKNOWN_IDENTITY = "ERR_UNKNOWN_IDENTITY"
ERR_INVALID_SIGNATURE = "ERR_INVALID_SIGNATURE"
ERR_CONTENT_DIGEST_MISMATCH = "ERR_CONTENT_DIGEST_MISMATCH"
ERR_FINGERPRINT_MISMATCH = "ERR_FINGERPRINT_MISMATCH"
ERR_DUPLICATE_CONTRIBUTION = "ERR_DUPLICATE_CONTRIBUTION"
ERR_REFORMATTED_COPY = "ERR_REFORMATTED_COPY"
ERR_NEAR_DUPLICATE_COPY = "ERR_NEAR_DUPLICATE_COPY"
ERR_UNDECLARED_COPY = "ERR_UNDECLARED_COPY"
ERR_CAUSALITY_CYCLE = "ERR_CAUSALITY_CYCLE"
ERR_TIMESTAMP_BACKDATE = "ERR_TIMESTAMP_BACKDATE"
ERR_UNKNOWN_PARENT = "ERR_UNKNOWN_PARENT"
ERR_ATTESTATION_UID_MISMATCH = "ERR_ATTESTATION_UID_MISMATCH"
ERR_SELF_ATTESTATION = "ERR_SELF_ATTESTATION"
ERR_REVOKED_ATTESTATION = "ERR_REVOKED_ATTESTATION"
ERR_EXPIRED_ATTESTATION = "ERR_EXPIRED_ATTESTATION"
ERR_ATTESTATION_REPLAY = "ERR_ATTESTATION_REPLAY"
ERR_REF_NOT_ACCEPTED = "ERR_REF_NOT_ACCEPTED"
ERR_ISSUER_RATE_LIMIT = "ERR_ISSUER_RATE_LIMIT"
ERR_AI_SELF_ATTEST_FORBIDDEN = "ERR_AI_SELF_ATTEST_FORBIDDEN"
ERR_AI_POLICY_MUTATION_FORBIDDEN = "ERR_AI_POLICY_MUTATION_FORBIDDEN"
ERR_AI_TREASURY_FORBIDDEN = "ERR_AI_TREASURY_FORBIDDEN"
ERR_COLLUSION_RING_DISCOUNTED = "ERR_COLLUSION_RING_DISCOUNTED"
ERR_SYBIL_CLUSTER_CAPPED = "ERR_SYBIL_CLUSTER_CAPPED"


def default_policy() -> Dict[str, int]:
    return {
        "near_duplicate_reject_bps": 8000,
        "undeclared_copy_reject_bps": 5000,
        "novelty_overclaim_gap_bps": 2500,
        "upstream_flow_bps": 3000,
        "max_clock_skew_sec": 300,
        "eigentrust_damping_bps": 8500,
        "eigentrust_iterations": 40,
        "reciprocal_discount_bps": 2500,
        "ring_discount_bps": 500,
        "cluster_sim_threshold_bps": 8000,
        "cluster_penalty_bps": 1000,
        "trust_full_gate_micro": 10000,
        "trust_rep_multiplier": 5000,
        "attr_rep_multiplier": 50,
        "max_attestations_per_epoch": 25,
    }


def zoo_tier_for_points(points: int) -> Tuple[str, int]:
    if points >= 1000:
        return "Elder", 250
    if points >= 500:
        return "Guardian", 200
    if points >= 200:
        return "Steward", 150
    if points >= 50:
        return "Contributor", 120
    return "Observer", 100


def _detect_cycle_nodes(contribs: List[Dict[str, Any]], by_id: Dict[str, Dict[str, Any]]) -> Set[str]:
    in_degree: Dict[str, int] = {c["contribution_id"]: 0 for c in contribs}
    children: Dict[str, List[str]] = {c["contribution_id"]: [] for c in contribs}
    self_loop: Set[str] = set()

    for c in contribs:
        cid = c["contribution_id"]
        seen_p: Set[str] = set()
        for pid in c.get("parents") or []:
            if pid == cid:
                self_loop.add(cid)
                continue
            if pid in seen_p:
                continue
            seen_p.add(pid)
            if pid in by_id:
                children[pid].append(cid)
                in_degree[cid] += 1

    queue = sorted(
        c["contribution_id"]
        for c in contribs
        if in_degree[c["contribution_id"]] == 0 and c["contribution_id"] not in self_loop
    )
    visited: Set[str] = set()
    while queue:
        u = queue.pop(0)
        visited.add(u)
        for v in sorted(children[u]):
            in_degree[v] -= 1
            if in_degree[v] == 0 and v not in self_loop:
                queue.append(v)

    return {
        c["contribution_id"]
        for c in contribs
        if c["contribution_id"] in self_loop or c["contribution_id"] not in visited
    }


def _evaluate_dag(bundle: Dict[str, Any], id_map: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    pol = bundle["policy"]
    contribs = sorted(
        bundle.get("contributions") or [],
        key=lambda c: (int(c["ledger_seq"]), c["contribution_id"]),
    )
    contrib_by_id = {c["contribution_id"]: c for c in contribs}
    cycle_nodes = _detect_cycle_nodes(contribs, contrib_by_id)

    verdicts: List[Dict[str, Any]] = []
    verdict_by_id: Dict[str, Dict[str, Any]] = {}
    accepted_by_id: Dict[str, Dict[str, Any]] = {}
    attribution_micro: Dict[str, int] = {}
    naive_attribution_micro: Dict[str, int] = {}
    upstream_citation_micro: Dict[str, int] = {}
    accepted_count: Dict[str, int] = {}
    rejected_count: Dict[str, int] = {}

    total_intrinsic_micro = 0
    total_attributed_micro = 0
    total_naive_attributed_micro = 0

    seen_raw: Dict[str, str] = {}
    seen_canonical: Dict[str, str] = {}
    global_shingles: Set[str] = set()
    accepted_order: List[Dict[str, Any]] = []
    max_accepted_ts = 0

    def record(v: Dict[str, Any]) -> None:
        verdicts.append(v)
        verdict_by_id[v["contribution_id"]] = v
        author = v["author_id"]
        if v["status"] == STATUS_ACCEPTED:
            accepted_count[author] = accepted_count.get(author, 0) + 1
        else:
            rejected_count[author] = rejected_count.get(author, 0) + 1

    for c in contribs:
        cid = c["contribution_id"]
        author_id = c["author_id"]
        base_val = int(c["base_value_micro"])
        v: Dict[str, Any] = {
            "contribution_id": cid,
            "author_id": author_id,
            "status": "",
            "error_code": ERR_NONE,
            "canonical_origin_id": "",
            "best_match_id": "",
            "best_overlap_bps": 0,
            "novelty_bps": 0,
            "intrinsic_micro": 0,
            "self_credit_micro": 0,
            "upstream_flow_micro": 0,
            "scenario_tag": c.get("scenario_tag", ""),
        }

        ident = id_map.get(author_id)
        if ident is None:
            v["status"] = STATUS_REJECTED
            v["error_code"] = ERR_UNKNOWN_IDENTITY
            record(v)
            continue

        if not verify_contribution_signature(c, ident["public_key"]):
            v["status"] = STATUS_REJECTED
            v["error_code"] = ERR_INVALID_SIGNATURE
            record(v)
            continue

        naive_attribution_micro[author_id] = naive_attribution_micro.get(author_id, 0) + base_val
        total_naive_attributed_micro += base_val

        fp = compute_fingerprints(c["content"])
        if fp.raw_sha256 != c["raw_sha256"] or fp.canonical_digest != c["canonical_digest"]:
            v["status"] = STATUS_REJECTED
            v["error_code"] = ERR_CONTENT_DIGEST_MISMATCH
            record(v)
            continue
        if fp.fingerprint_digest != c["fingerprint_digest"] or fp.winnow_fingerprint != (c.get("winnow_fingerprint") or []):
            v["status"] = STATUS_REJECTED
            v["error_code"] = ERR_FINGERPRINT_MISMATCH
            record(v)
            continue

        if cid in cycle_nodes:
            v["status"] = STATUS_REJECTED
            v["error_code"] = ERR_CAUSALITY_CYCLE
            record(v)
            continue

        ts = int(c["timestamp"])
        epoch = int(c["epoch"])
        lseq = int(c["ledger_seq"])
        if accepted_order and ts < max_accepted_ts - int(pol["max_clock_skew_sec"]):
            v["status"] = STATUS_REJECTED
            v["error_code"] = ERR_TIMESTAMP_BACKDATE
            record(v)
            continue

        sorted_parents = sorted(c.get("parents") or [])
        parent_err = ERR_NONE
        for pid in sorted_parents:
            p = contrib_by_id.get(pid)
            if p is None:
                parent_err = ERR_UNKNOWN_PARENT
                break
            if int(p["timestamp"]) > ts or int(p["epoch"]) > epoch or int(p["ledger_seq"]) >= lseq:
                parent_err = ERR_TIMESTAMP_BACKDATE
                break
            if pid not in accepted_by_id:
                parent_err = ERR_UNKNOWN_PARENT
                break
        if parent_err != ERR_NONE:
            v["status"] = STATUS_REJECTED
            v["error_code"] = parent_err
            record(v)
            continue

        if c["raw_sha256"] in seen_raw:
            orig_id = seen_raw[c["raw_sha256"]]
            v["status"] = STATUS_REJECTED
            v["error_code"] = ERR_DUPLICATE_CONTRIBUTION
            v["canonical_origin_id"] = orig_id
            v["best_match_id"] = orig_id
            v["best_overlap_bps"] = BPS_SCALE
            v["novelty_bps"] = 0
            record(v)
            continue

        if c["canonical_digest"] in seen_canonical:
            orig_id = seen_canonical[c["canonical_digest"]]
            v["status"] = STATUS_REJECTED
            v["error_code"] = ERR_REFORMATTED_COPY
            v["canonical_origin_id"] = orig_id
            v["best_match_id"] = orig_id
            v["best_overlap_bps"] = BPS_SCALE
            v["novelty_bps"] = 0
            record(v)
            continue

        w_fp = c.get("winnow_fingerprint") or []
        best_match_id = ""
        best_overlap_bps = -1
        for prev in accepted_order:
            ov = containment_bps(w_fp, prev.get("winnow_fingerprint") or [])
            if ov > best_overlap_bps or (ov == best_overlap_bps and (best_match_id == "" or prev["contribution_id"] < best_match_id)):
                best_overlap_bps = ov
                best_match_id = prev["contribution_id"]
        if best_overlap_bps < 0:
            best_overlap_bps = 0

        union_overlap_count = sum(1 for h in w_fp if h in global_shingles)
        union_overlap_bps = (union_overlap_count * BPS_SCALE) // len(w_fp) if w_fp else 0
        novelty_bps = max(0, BPS_SCALE - union_overlap_bps)

        v["best_match_id"] = best_match_id
        v["best_overlap_bps"] = best_overlap_bps
        v["novelty_bps"] = novelty_bps

        if best_overlap_bps >= int(pol["near_duplicate_reject_bps"]):
            v["status"] = STATUS_REJECTED
            v["error_code"] = ERR_NEAR_DUPLICATE_COPY
            v["canonical_origin_id"] = best_match_id
            record(v)
            continue
        if best_overlap_bps >= int(pol["undeclared_copy_reject_bps"]) and best_match_id not in sorted_parents:
            v["status"] = STATUS_REJECTED
            v["error_code"] = ERR_UNDECLARED_COPY
            v["canonical_origin_id"] = best_match_id
            record(v)
            continue
        claimed = int(c["claimed_novelty_bps"])
        if claimed > 0 and best_overlap_bps >= 6500 and (claimed - novelty_bps) > int(pol["novelty_overclaim_gap_bps"]):
            v["status"] = STATUS_REJECTED
            v["error_code"] = ERR_NEAR_DUPLICATE_COPY
            v["canonical_origin_id"] = best_match_id
            record(v)
            continue

        intrinsic_micro = (base_val * novelty_bps) // BPS_SCALE
        upstream_flow_micro = (intrinsic_micro * int(pol["upstream_flow_bps"])) // BPS_SCALE if sorted_parents else 0
        self_credit_micro = intrinsic_micro - upstream_flow_micro

        attribution_micro[author_id] = attribution_micro.get(author_id, 0) + self_credit_micro
        total_intrinsic_micro += intrinsic_micro
        total_attributed_micro += self_credit_micro

        if sorted_parents and upstream_flow_micro > 0:
            pws = []
            total_weight = 0
            for pid in sorted_parents:
                p = accepted_by_id[pid]
                w = containment_bps(w_fp, p.get("winnow_fingerprint") or []) + 1000
                pws.append((pid, p["author_id"], w))
                total_weight += w

            distributed = 0
            best_idx = 0
            for idx, (pid, p_author, w) in enumerate(pws):
                share = (upstream_flow_micro * w) // total_weight
                attribution_micro[p_author] = attribution_micro.get(p_author, 0) + share
                upstream_citation_micro[p_author] = upstream_citation_micro.get(p_author, 0) + share
                total_attributed_micro += share
                distributed += share
                if w > pws[best_idx][2] or (w == pws[best_idx][2] and pid < pws[best_idx][0]):
                    best_idx = idx
            rem = upstream_flow_micro - distributed
            if rem > 0:
                rem_author = pws[best_idx][1]
                attribution_micro[rem_author] = attribution_micro.get(rem_author, 0) + rem
                upstream_citation_micro[rem_author] = upstream_citation_micro.get(rem_author, 0) + rem
                total_attributed_micro += rem

        v["status"] = STATUS_ACCEPTED
        v["error_code"] = ERR_NONE
        v["canonical_origin_id"] = cid
        v["intrinsic_micro"] = intrinsic_micro
        v["self_credit_micro"] = self_credit_micro
        v["upstream_flow_micro"] = upstream_flow_micro
        record(v)

        accepted_by_id[cid] = c
        seen_raw[c["raw_sha256"]] = cid
        seen_canonical[c["canonical_digest"]] = cid
        global_shingles.update(w_fp)
        accepted_order.append(c)
        if ts > max_accepted_ts:
            max_accepted_ts = ts

    return {
        "verdicts": verdicts,
        "verdict_by_id": verdict_by_id,
        "accepted_by_id": accepted_by_id,
        "attribution_micro": attribution_micro,
        "naive_attribution_micro": naive_attribution_micro,
        "upstream_citation_micro": upstream_citation_micro,
        "accepted_count": accepted_count,
        "rejected_count": rejected_count,
        "total_intrinsic_micro": total_intrinsic_micro,
        "total_attributed_micro": total_attributed_micro,
        "total_naive_attributed_micro": total_naive_attributed_micro,
    }


def _target_set_jaccard_bps(a: Set[str], b: Set[str]) -> int:
    if not a and not b:
        return 0
    inter = len(a & b)
    union = len(a) + len(b) - inter
    if union == 0:
        return 0
    return (inter * BPS_SCALE) // union


def _tarjan_scc(nodes: List[str], adj: Dict[str, Set[str]]) -> List[List[str]]:
    index = 0
    indices: Dict[str, int] = {}
    lowlink: Dict[str, int] = {}
    on_stack: Set[str] = set()
    stack: List[str] = []
    sccs: List[List[str]] = []

    def strong_connect(v: str) -> None:
        nonlocal index
        index += 1
        indices[v] = index
        lowlink[v] = index
        stack.append(v)
        on_stack.add(v)

        for w in sorted(adj[v]):
            if w not in indices:
                strong_connect(w)
                if lowlink[w] < lowlink[v]:
                    lowlink[v] = lowlink[w]
            elif w in on_stack:
                if indices[w] < lowlink[v]:
                    lowlink[v] = indices[w]

        if lowlink[v] == indices[v]:
            comp: List[str] = []
            while True:
                w = stack.pop()
                on_stack.remove(w)
                comp.append(w)
                if w == v:
                    break
            comp.sort()
            sccs.append(comp)

    for v in nodes:
        if v not in indices:
            strong_connect(v)

    sccs.sort(key=lambda c: c[0])
    return sccs


def _evaluate_reputation(
    bundle: Dict[str, Any],
    id_map: Dict[str, Dict[str, Any]],
    dag: Dict[str, Any],
) -> Dict[str, Any]:
    pol = bundle["policy"]
    revoked_set = set(bundle.get("revoked_uids") or [])
    eval_time = int(bundle["eval_time"])

    atts = sorted(
        bundle.get("attestations") or [],
        key=lambda a: (int(a["epoch"]), int(a["time"]), a["attester"], int(a["nonce"]), a["uid"]),
    )

    verdicts: List[Dict[str, Any]] = []
    collusion_findings: List[Dict[str, Any]] = []
    naive_attest_count: Dict[str, int] = {}
    accepted_count = 0
    advisory_count = 0
    rejected_count = 0

    seen_uid: Set[str] = set()
    seen_attester_nonce: Set[str] = set()
    seen_attester_ref_schema: Set[str] = set()
    epoch_issuer_count: Dict[str, int] = {}

    valid_edges: List[Tuple[str, str, int, int]] = []  # (attester, recipient, weight_bps, verdict_ix)

    for a in atts:
        attester = a["attester"]
        recipient = a["recipient"]
        ref_uid = a["ref_uid"]
        schema_uid = a["schema_uid"]
        uid = a["uid"]

        v: Dict[str, Any] = {
            "uid": uid,
            "attester": attester,
            "recipient": recipient,
            "ref_uid": ref_uid,
            "status": "",
            "error_code": ERR_NONE,
            "effective_weight_bps": 0,
            "scenario_tag": a.get("scenario_tag", ""),
        }

        att_ident = id_map.get(attester)
        if att_ident is None or recipient not in id_map:
            v["status"] = STATUS_REJECTED
            v["error_code"] = ERR_UNKNOWN_IDENTITY
            rejected_count += 1
            verdicts.append(v)
            continue

        if compute_attestation_uid(a) != uid:
            v["status"] = STATUS_REJECTED
            v["error_code"] = ERR_ATTESTATION_UID_MISMATCH
            rejected_count += 1
            verdicts.append(v)
            continue

        if not verify_attestation_signature(a, att_ident["public_key"]):
            v["status"] = STATUS_REJECTED
            v["error_code"] = ERR_INVALID_SIGNATURE
            rejected_count += 1
            verdicts.append(v)
            continue

        # Constitutional AI-role guards.
        if att_ident["role"] == ROLE_AI_AGENT:
            if schema_uid == SCHEMA_POLICY_MUTATION:
                v["status"] = STATUS_REJECTED
                v["error_code"] = ERR_AI_POLICY_MUTATION_FORBIDDEN
                rejected_count += 1
                verdicts.append(v)
                continue
            if schema_uid == SCHEMA_TREASURY_AUTH:
                v["status"] = STATUS_REJECTED
                v["error_code"] = ERR_AI_TREASURY_FORBIDDEN
                rejected_count += 1
                verdicts.append(v)
                continue
            if attester == recipient:
                v["status"] = STATUS_REJECTED
                v["error_code"] = ERR_AI_SELF_ATTEST_FORBIDDEN
                rejected_count += 1
                verdicts.append(v)
                continue
            ref_contrib = dag["accepted_by_id"].get(ref_uid)
            if ref_contrib is not None and ref_contrib["author_id"] == attester:
                v["status"] = STATUS_REJECTED
                v["error_code"] = ERR_AI_SELF_ATTEST_FORBIDDEN
                rejected_count += 1
                verdicts.append(v)
                continue
            if schema_uid == SCHEMA_SIMILARITY_FLAG:
                v["status"] = STATUS_ADVISORY
                v["error_code"] = ERR_NONE
                v["effective_weight_bps"] = 0
                advisory_count += 1
                verdicts.append(v)
                continue

        if attester == recipient:
            v["status"] = STATUS_REJECTED
            v["error_code"] = ERR_SELF_ATTESTATION
            rejected_count += 1
            verdicts.append(v)
            continue

        if bool(a.get("revoked")) or uid in revoked_set:
            v["status"] = STATUS_REJECTED
            v["error_code"] = ERR_REVOKED_ATTESTATION
            rejected_count += 1
            verdicts.append(v)
            continue

        exp_time = int(a["expiration_time"])
        if exp_time > 0 and exp_time < eval_time:
            v["status"] = STATUS_REJECTED
            v["error_code"] = ERR_EXPIRED_ATTESTATION
            rejected_count += 1
            verdicts.append(v)
            continue

        nonce_key = f"{attester}:{int(a['nonce'])}"
        ref_key = f"{attester}:{ref_uid}:{schema_uid}"
        if uid in seen_uid or nonce_key in seen_attester_nonce or ref_key in seen_attester_ref_schema:
            v["status"] = STATUS_REJECTED
            v["error_code"] = ERR_ATTESTATION_REPLAY
            rejected_count += 1
            verdicts.append(v)
            continue

        if ref_uid and ref_uid not in dag["accepted_by_id"]:
            v["status"] = STATUS_REJECTED
            v["error_code"] = ERR_REF_NOT_ACCEPTED
            rejected_count += 1
            verdicts.append(v)
            continue

        epoch_key = f"{attester}:{int(a['epoch'])}"
        max_per_epoch = int(pol["max_attestations_per_epoch"])
        if max_per_epoch > 0 and epoch_issuer_count.get(epoch_key, 0) >= max_per_epoch:
            v["status"] = STATUS_REJECTED
            v["error_code"] = ERR_ISSUER_RATE_LIMIT
            rejected_count += 1
            verdicts.append(v)
            continue

        if schema_uid in (SCHEMA_SIMILARITY_FLAG, SCHEMA_POLICY_MUTATION, SCHEMA_TREASURY_AUTH):
            v["status"] = STATUS_ADVISORY
            v["error_code"] = ERR_NONE
            v["effective_weight_bps"] = 0
            advisory_count += 1
            verdicts.append(v)
            continue

        seen_uid.add(uid)
        seen_attester_nonce.add(nonce_key)
        seen_attester_ref_schema.add(ref_key)
        epoch_issuer_count[epoch_key] = epoch_issuer_count.get(epoch_key, 0) + 1

        w = max(1, min(BPS_SCALE, int(a["weight_bps"])))
        v["status"] = STATUS_ACCEPTED
        v["error_code"] = ERR_NONE
        v["effective_weight_bps"] = w
        accepted_count += 1
        idx = len(verdicts)
        verdicts.append(v)

        naive_attest_count[recipient] = naive_attest_count.get(recipient, 0) + 1
        valid_edges.append((attester, recipient, w, idx))

    all_ids = sorted(id_map.keys())
    seeds = sorted(i for i in all_ids if id_map[i]["role"] == ROLE_SEED)
    is_seed = set(seeds)

    adj_out: Dict[str, Set[str]] = {i: set() for i in all_ids}
    adj_in: Dict[str, Set[str]] = {i: set() for i in all_ids}
    for attester, recipient, _, _ in valid_edges:
        adj_out[attester].add(recipient)
        adj_in[recipient].add(attester)

    # Step 1: Tarjan SCC collusion ring detection.
    sccs = _tarjan_scc(all_ids, adj_out)
    ring_edge_discount: Dict[str, int] = {}
    finding_counter = 0

    for comp in sccs:
        if len(comp) < 2:
            continue
        comp_set = set(comp)
        if any(m in is_seed for m in comp):
            continue
        internal_edges = 0
        external_in = 0
        for m in comp:
            for src in adj_in[m]:
                if src in comp_set:
                    internal_edges += 1
                else:
                    external_in += 1
        if internal_edges > external_in:
            discount = int(pol["ring_discount_bps"])
            if external_in == 0:
                discount = 0
            elif len(comp) == 2 and int(pol["reciprocal_discount_bps"]) < discount:
                discount = int(pol["reciprocal_discount_bps"])
            finding_counter += 1
            collusion_findings.append({
                "finding_id": f"ring_{finding_counter:02d}",
                "error_code": ERR_COLLUSION_RING_DISCOUNTED,
                "members": comp,
                "discount_bps": discount,
                "external_in": external_in,
                "internal_edges": internal_edges,
            })
            for u in comp:
                for dst in adj_out[u]:
                    if dst in comp_set:
                        ring_edge_discount[f"{u}->{dst}"] = discount

    recip_disc = int(pol["reciprocal_discount_bps"])
    for attester, recipient, _, _ in valid_edges:
        if attester not in is_seed and recipient not in is_seed and attester in adj_out[recipient]:
            key = f"{attester}->{recipient}"
            if key not in ring_edge_discount or recip_disc < ring_edge_discount[key]:
                ring_edge_discount[key] = recip_disc

    # Step 2: Pairwise co-attestation target-set Jaccard clustering.
    unseeded_attesters = [i for i in all_ids if i not in is_seed and adj_out[i]]
    uf_parent = {i: i for i in unseeded_attesters}

    def uf_find(x: str) -> str:
        while uf_parent[x] != x:
            uf_parent[x] = uf_parent[uf_parent[x]]
            x = uf_parent[x]
        return x

    def uf_union(a: str, b: str) -> None:
        ra, rb = uf_find(a), uf_find(b)
        if ra == rb:
            return
        if ra < rb:
            uf_parent[rb] = ra
        else:
            uf_parent[ra] = rb

    sim_thresh = int(pol["cluster_sim_threshold_bps"])
    for i in range(len(unseeded_attesters)):
        u = unseeded_attesters[i]
        for j in range(i + 1, len(unseeded_attesters)):
            v = unseeded_attesters[j]
            if _target_set_jaccard_bps(adj_out[u], adj_out[v]) >= sim_thresh:
                uf_union(u, v)

    clusters_by_root: Dict[str, List[str]] = {}
    for i in unseeded_attesters:
        r = uf_find(i)
        clusters_by_root.setdefault(r, []).append(i)

    cluster_scale_num: Dict[str, int] = {}
    sybil_cluster_count = 0
    for r in sorted(clusters_by_root.keys()):
        members = sorted(clusters_by_root[r])
        if len(members) < 3:
            continue
        ext_seed_in = sum(1 for m in members for src in adj_in[m] if src in is_seed)
        if ext_seed_in == 0:
            sybil_cluster_count += 1
            per_member_bps = int(pol["cluster_penalty_bps"]) // len(members)
            collusion_findings.append({
                "finding_id": f"sybil_cluster_{sybil_cluster_count:02d}",
                "error_code": ERR_SYBIL_CLUSTER_CAPPED,
                "members": members,
                "discount_bps": per_member_bps,
                "external_in": ext_seed_in,
                "internal_edges": len(members),
            })
            for m in members:
                cluster_scale_num[m] = per_member_bps

    eff_weights: Dict[str, Dict[str, int]] = {i: {} for i in all_ids}
    out_total: Dict[str, int] = {i: 0 for i in all_ids}
    raw_out_total: Dict[str, int] = {i: 0 for i in all_ids}
    for attester, recipient, w_raw, v_ix in valid_edges:
        raw_out_total[attester] += w_raw
        w = w_raw
        ring_key = f"{attester}->{recipient}"
        if ring_key in ring_edge_discount:
            w = (w * ring_edge_discount[ring_key]) // BPS_SCALE
        if attester in cluster_scale_num:
            w = (w * cluster_scale_num[attester]) // BPS_SCALE
        verdicts[v_ix]["effective_weight_bps"] = w
        if w > 0:
            eff_weights[attester][recipient] = eff_weights[attester].get(recipient, 0) + w
            out_total[attester] += w

    # Step 3: Sub-stochastic fixed-point Seeded EigenTrust power iteration.
    seed_vec: Dict[str, int] = {i: 0 for i in all_ids}
    if seeds:
        base = MICRO_SCALE // len(seeds)
        rem = MICRO_SCALE - base * len(seeds)
        for idx, s in enumerate(seeds):
            seed_vec[s] = base + (rem if idx == 0 else 0)

    row_trans: Dict[str, Dict[str, int]] = {}
    row_leak: Dict[str, int] = {i: 0 for i in all_ids}
    for u in all_ids:
        raw_tot = raw_out_total[u]
        if raw_tot == 0 or out_total[u] == 0:
            row_leak[u] = MICRO_SCALE
            continue
        nbrs = sorted(eff_weights[u].keys())
        rt: Dict[str, int] = {}
        sum_row = 0
        for v in nbrs:
            c_val = (eff_weights[u][v] * MICRO_SCALE) // raw_tot
            rt[v] = c_val
            sum_row += c_val
        if out_total[u] == raw_tot and nbrs:
            rem = MICRO_SCALE - sum_row
            if rem > 0:
                rt[nbrs[0]] += rem
                sum_row += rem
        row_trans[u] = rt
        row_leak[u] = MICRO_SCALE - sum_row

    trust: Dict[str, int] = dict(seed_vec)
    alpha = int(pol["eigentrust_damping_bps"])
    one_minus_alpha = BPS_SCALE - alpha
    iters = int(pol["eigentrust_iterations"]) or 40

    for _ in range(iters):
        next_trust: Dict[str, int] = {i: 0 for i in all_ids}
        dangling_mass = 0
        for u in all_ids:
            tu = trust[u]
            if tu == 0:
                continue
            leak = row_leak[u]
            if leak > 0:
                dangling_mass += (tu * leak) // MICRO_SCALE
            rt = row_trans.get(u)
            if not rt:
                continue
            for v in sorted(rt.keys()):
                next_trust[v] += (tu * rt[v]) // MICRO_SCALE
        for v in all_ids:
            propagated = next_trust[v] + (dangling_mass * seed_vec[v]) // MICRO_SCALE
            next_trust[v] = (one_minus_alpha * seed_vec[v]) // BPS_SCALE + (alpha * propagated) // BPS_SCALE
        trust = next_trust

    trust_gate_bps: Dict[str, int] = {}
    reputation_micro: Dict[str, int] = {}
    zoo_rep_points: Dict[str, int] = {}
    naive_rep_points: Dict[str, int] = {}
    full_gate = int(pol["trust_full_gate_micro"])
    trust_mult = int(pol["trust_rep_multiplier"])
    attr_mult = int(pol["attr_rep_multiplier"])

    for i in all_ids:
        et = trust[i]
        if full_gate > 0:
            gate = min(BPS_SCALE, (et * BPS_SCALE) // full_gate)
        else:
            gate = BPS_SCALE
        trust_gate_bps[i] = gate
        attr_micro = dag["attribution_micro"].get(i, 0)
        gated_attr = (attr_micro * gate) // BPS_SCALE
        rep_micro = et * trust_mult + gated_attr * attr_mult
        reputation_micro[i] = rep_micro
        zoo_rep_points[i] = rep_micro // MICRO_SCALE
        naive_rep_points[i] = naive_attest_count.get(i, 0) * 100 + (dag["naive_attribution_micro"].get(i, 0) * 50) // MICRO_SCALE

    return {
        "attestation_verdicts": verdicts,
        "collusion_findings": collusion_findings,
        "eigentrust_micro": trust,
        "trust_gate_bps": trust_gate_bps,
        "reputation_micro": reputation_micro,
        "zoo_rep_points": zoo_rep_points,
        "naive_attest_count": naive_attest_count,
        "naive_rep_points": naive_rep_points,
        "accepted_count": accepted_count,
        "advisory_count": advisory_count,
        "rejected_count": rejected_count,
    }


def _build_audit_merkle_leaves(
    c_verdicts: List[Dict[str, Any]],
    a_verdicts: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    summaries: List[Dict[str, Any]],
) -> List[bytes]:
    leaves: List[bytes] = []

    for cv in sorted(c_verdicts, key=lambda x: x["contribution_id"]):
        leaves.append(canonical_json({
            "canonical_origin_id": cv["canonical_origin_id"],
            "contribution_id": cv["contribution_id"],
            "error_code": cv["error_code"],
            "intrinsic_micro": int(cv["intrinsic_micro"]),
            "kind": "contribution",
            "novelty_bps": int(cv["novelty_bps"]),
            "self_credit_micro": int(cv["self_credit_micro"]),
            "status": cv["status"],
            "upstream_flow_micro": int(cv["upstream_flow_micro"]),
        }))

    for av in sorted(a_verdicts, key=lambda x: (x["uid"], x["attester"], x["status"])):
        leaves.append(canonical_json({
            "attester": av["attester"],
            "effective_weight_bps": int(av["effective_weight_bps"]),
            "error_code": av["error_code"],
            "kind": "attestation",
            "recipient": av["recipient"],
            "status": av["status"],
            "uid": av["uid"],
        }))

    for cf in sorted(findings, key=lambda x: x["finding_id"]):
        leaves.append(canonical_json({
            "discount_bps": int(cf["discount_bps"]),
            "error_code": cf["error_code"],
            "external_in": int(cf["external_in"]),
            "finding_id": cf["finding_id"],
            "internal_edges": int(cf["internal_edges"]),
            "kind": "collusion",
            "members": cf["members"],
        }))

    for s in summaries:
        leaves.append(canonical_json({
            "attribution_micro": int(s["attribution_micro"]),
            "eigentrust_micro": int(s["eigentrust_micro"]),
            "identity_id": s["identity_id"],
            "kind": "identity",
            "reputation_micro": int(s["reputation_micro"]),
            "reputation_rank": int(s["reputation_rank"]),
            "tier": s["tier"],
            "tier_weight_bps": int(s["tier_weight_bps"]),
            "zoo_rep_points": int(s["zoo_rep_points"]),
        }))

    return leaves


def verify_suite(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Runs complete deterministic attribution & Sybil-resistant reputation verification."""
    id_map = {ident["id"]: ident for ident in bundle.get("identities") or []}
    all_ids = sorted(id_map.keys())

    dag = _evaluate_dag(bundle, id_map)
    rep = _evaluate_reputation(bundle, id_map, dag)

    summaries: List[Dict[str, Any]] = []
    for i in all_ids:
        pts = rep["zoo_rep_points"][i]
        tier, tier_weight = zoo_tier_for_points(pts)
        summaries.append({
            "identity_id": i,
            "role": id_map[i]["role"],
            "accepted_contributions": dag["accepted_count"].get(i, 0),
            "rejected_contributions": dag["rejected_count"].get(i, 0),
            "attribution_micro": dag["attribution_micro"].get(i, 0),
            "naive_attribution_micro": dag["naive_attribution_micro"].get(i, 0),
            "upstream_citation_micro": dag["upstream_citation_micro"].get(i, 0),
            "eigentrust_micro": rep["eigentrust_micro"][i],
            "trust_gate_bps": rep["trust_gate_bps"][i],
            "reputation_micro": rep["reputation_micro"][i],
            "zoo_rep_points": pts,
            "tier": tier,
            "tier_weight_bps": tier_weight,
            "naive_attestation_count": rep["naive_attest_count"].get(i, 0),
            "naive_reputation_points": rep["naive_rep_points"][i],
            "reputation_rank": 0,
            "naive_reputation_rank": 0,
        })

    rep_order = sorted(
        range(len(summaries)),
        key=lambda idx: (-summaries[idx]["reputation_micro"], -summaries[idx]["attribution_micro"], summaries[idx]["identity_id"]),
    )
    for rank, idx in enumerate(rep_order, start=1):
        summaries[idx]["reputation_rank"] = rank

    naive_order = sorted(
        range(len(summaries)),
        key=lambda idx: (-summaries[idx]["naive_reputation_points"], -summaries[idx]["naive_attestation_count"], summaries[idx]["identity_id"]),
    )
    for rank, idx in enumerate(naive_order, start=1):
        summaries[idx]["naive_reputation_rank"] = rank

    att_by_uid = {av["uid"]: av for av in rep["attestation_verdicts"]}
    att_by_tag = {av["scenario_tag"]: av for av in rep["attestation_verdicts"] if av["scenario_tag"]}
    finding_by_member: Dict[str, Dict[str, Any]] = {}
    for cf in rep["collusion_findings"]:
        for m in cf["members"]:
            if m not in finding_by_member:
                finding_by_member[m] = cf

    adv_results: List[Dict[str, Any]] = []
    adv_passed = 0
    for exp in bundle.get("adversarial_expectations") or []:
        target_type = exp["target_type"]
        target_id = exp["target_id"]
        actual_status = ""
        actual_err = ""
        if target_type == "contribution":
            cv = dag["verdict_by_id"].get(target_id)
            if cv is not None:
                actual_status = cv["status"]
                actual_err = cv["error_code"]
            else:
                actual_status = "MISSING"
        elif target_type == "attestation":
            av = att_by_uid.get(target_id) or att_by_tag.get(target_id)
            if av is not None:
                actual_status = av["status"]
                actual_err = av["error_code"]
            else:
                actual_status = "MISSING"
        elif target_type == "cluster":
            cf = finding_by_member.get(target_id)
            if cf is not None:
                actual_status = "DISCOUNTED"
                actual_err = cf["error_code"]
            else:
                actual_status = "UNDETECTED"
        else:
            actual_status = "UNKNOWN_TARGET_TYPE"

        passed = actual_status == exp["expected_status"] and actual_err == exp["expected_error_code"]
        if passed:
            adv_passed += 1
        adv_results.append({
            "attack_id": exp["attack_id"],
            "category": exp["category"],
            "target_id": target_id,
            "passed": passed,
            "expected_status": exp["expected_status"],
            "actual_status": actual_status,
            "expected_error_code": exp["expected_error_code"],
            "actual_error_code": actual_err,
        })

    leaves = _build_audit_merkle_leaves(
        dag["verdicts"],
        rep["attestation_verdicts"],
        rep["collusion_findings"],
        summaries,
    )
    audit_root = merkle_root(leaves)

    accepted_contribs = sum(1 for cv in dag["verdicts"] if cv["status"] == STATUS_ACCEPTED)
    rejected_contribs = len(dag["verdicts"]) - accepted_contribs

    return {
        "schema_version": SCHEMA_VERSION,
        "spec_version": SPEC_VERSION,
        "suite_name": bundle.get("suite_name", ""),
        "audit_merkle_root": audit_root,
        "total_contributions": len(dag["verdicts"]),
        "accepted_contributions": accepted_contribs,
        "rejected_contributions": rejected_contribs,
        "total_attestations": len(rep["attestation_verdicts"]),
        "accepted_attestations": rep["accepted_count"],
        "advisory_attestations": rep["advisory_count"],
        "rejected_attestations": rep["rejected_count"],
        "total_intrinsic_micro": dag["total_intrinsic_micro"],
        "total_attributed_micro": dag["total_attributed_micro"],
        "total_naive_attributed_micro": dag["total_naive_attributed_micro"],
        "conservation_exact": dag["total_intrinsic_micro"] == dag["total_attributed_micro"],
        "adversarial_passed": adv_passed,
        "adversarial_total": len(bundle.get("adversarial_expectations") or []),
        "contribution_verdicts": dag["verdicts"],
        "attestation_verdicts": rep["attestation_verdicts"],
        "collusion_findings": rep["collusion_findings"],
        "identity_summaries": summaries,
        "adversarial_results": adv_results,
    }

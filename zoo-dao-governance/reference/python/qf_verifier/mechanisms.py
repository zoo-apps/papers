# SPDX-License-Identifier: Apache-2.0
"""Independent pure-Python exact integer implementation of all 6 QF allocation mechanisms."""

from __future__ import annotations

import math
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from .canonical import hash_evaluation

SCALE = 1_000_000
SCALE_SQ = SCALE * SCALE
BPS = 10_000

ALL_MECHANISMS = (
    "linear_token_matching",
    "standard_clr_qf",
    "capped_voting_qf",
    "pairwise_bounded_qf",
    "reputation_weighted_qf",
    "hybrid_cocm_reputation_capped_qf",
)


def rep_weight_fp(rep_points: int, min_gate: int, rep_min_fp: int) -> int:
    if rep_points < min_gate:
        return rep_min_fp
    if rep_points >= 1000:
        return 1_000_000
    if rep_points >= 500:
        return 800_000
    if rep_points >= 200:
        return 600_000
    if rep_points >= 50:
        return 480_000
    return 400_000


def sqrt_fp(c: int) -> int:
    if c <= 0:
        return 0
    return math.isqrt(c * SCALE_SQ)


def sqrt_weighted_fp(rep_fp: int, c: int) -> int:
    if rep_fp <= 0 or c <= 0:
        return 0
    return math.isqrt(rep_fp * c * SCALE)


def allocate_pool_hamilton(
    pool: int, project_ids: Sequence[str], weights: Sequence[int]
) -> Tuple[List[int], int]:
    n = len(project_ids)
    alloc = [0] * n
    if pool <= 0 or n == 0:
        return alloc, pool
    total_w = sum(w for w in weights if w > 0)
    if total_w == 0:
        return alloc, pool

    rems: List[Tuple[int, str, int]] = []
    sum_alloc = 0
    for i, w in enumerate(weights):
        if w <= 0:
            rems.append((0, project_ids[i], i))
            continue
        q, r = divmod(pool * w, total_w)
        alloc[i] = q
        sum_alloc += q
        rems.append((r, project_ids[i], i))

    leftover = pool - sum_alloc
    if leftover > 0:
        rems.sort(key=lambda item: (-item[0], item[1]))
        for k in range(min(leftover, n)):
            alloc[rems[k][2]] += 1
    return alloc, 0


def allocate_pool_capped(
    pool: int, cap_micro: int, project_ids: Sequence[str], weights: Sequence[int]
) -> Tuple[List[int], int]:
    n = len(project_ids)
    alloc = [0] * n
    if pool <= 0 or n == 0 or cap_micro <= 0:
        return alloc, pool

    active = [w > 0 for w in weights]
    remaining = pool
    while remaining > 0:
        active_idx = [i for i in range(n) if active[i]]
        if not active_idx:
            break
        active_ids = [project_ids[i] for i in active_idx]
        active_w = [weights[i] for i in active_idx]
        shares, unalloc = allocate_pool_hamilton(remaining, active_ids, active_w)
        if unalloc == remaining:
            break

        exceeded = [
            orig_idx
            for k, orig_idx in enumerate(active_idx)
            if alloc[orig_idx] + shares[k] > cap_micro
        ]
        if not exceeded:
            for k, orig_idx in enumerate(active_idx):
                alloc[orig_idx] += shares[k]
            remaining = unalloc
            break

        for orig_idx in exceeded:
            delta = cap_micro - alloc[orig_idx]
            alloc[orig_idx] = cap_micro
            remaining -= delta
            active[orig_idx] = False

    return alloc, remaining


def compute_gini_bps(values: Sequence[int]) -> int:
    n = len(values)
    if n <= 1:
        return 0
    ordered = sorted(values)
    total = sum(ordered)
    if total == 0:
        return 0
    weighted = sum((2 * (i + 1) - n - 1) * v for i, v in enumerate(ordered))
    if weighted <= 0:
        return 0
    return (weighted * BPS) // (n * total)


def evaluate_mechanism(scenario: Mapping[str, Any], mech: str) -> Dict[str, Any]:
    pool = int(scenario["matching_pool_micro_zoo"])
    if pool <= 0:
        raise ValueError(f"matching pool must be positive, got {pool}")

    proposals = sorted(scenario["proposals"], key=lambda p: p["id"])
    proj_ids = [p["id"] for p in proposals]
    proj_idx = {pid: i for i, pid in enumerate(proj_ids)}

    donors = sorted(scenario["donors"], key=lambda d: d["id"])
    donor_idx = {d["id"]: i for i, d in enumerate(donors)}

    num_p = len(proposals)
    num_d = len(donors)

    contrib = [[0] * num_p for _ in range(num_d)]
    direct_totals = [0] * num_p
    unique_donors = [0] * num_p

    for c in scenario["contributions"]:
        amt = int(c["amount_micro_zoo"])
        if amt < 0:
            raise ValueError(f"negative contribution {amt}")
        if amt == 0:
            continue
        di = donor_idx[c["donor_id"]]
        pi = proj_idx[c["project_id"]]
        if contrib[di][pi] == 0:
            unique_donors[pi] += 1
        contrib[di][pi] += amt
        direct_totals[pi] += amt

    params = scenario["params"]
    donor_cap = (pool * int(params["donor_cap_bps"])) // BPS
    project_cap = (pool * int(params["project_cap_bps"])) // BPS
    pairwise_m = int(params["pairwise_m_micro_zoo"])
    cocm_m = int(params["cocm_m_micro_zoo"])
    cocm_lambda_bps = int(params["cocm_lambda_bps"])
    min_rep_gate = int(params["min_rep_gate"])
    rep_min_fp = int(params["rep_min_fp"])

    weights = [0] * num_p

    if mech == "linear_token_matching":
        weights = list(direct_totals)
        matched, unallocated = allocate_pool_hamilton(pool, proj_ids, weights)

    elif mech == "standard_clr_qf":
        for p in range(num_p):
            sum_s = 0
            sum_sq = 0
            for i in range(num_d):
                c_ip = contrib[i][p]
                if c_ip == 0:
                    continue
                s = sqrt_fp(c_ip)
                sum_s += s
                sum_sq += s * s
            weights[p] = max(0, sum_s * sum_s - sum_sq)
        matched, unallocated = allocate_pool_hamilton(pool, proj_ids, weights)

    elif mech == "capped_voting_qf":
        for p in range(num_p):
            sum_s = 0
            sum_sq = 0
            for i in range(num_d):
                c_ip = contrib[i][p]
                if c_ip == 0:
                    continue
                if donor_cap > 0 and c_ip > donor_cap:
                    c_ip = donor_cap
                s = sqrt_fp(c_ip)
                sum_s += s
                sum_sq += s * s
            weights[p] = max(0, sum_s * sum_s - sum_sq)
        matched, unallocated = allocate_pool_capped(pool, project_cap, proj_ids, weights)

    elif mech == "pairwise_bounded_qf":
        roots: List[List[int]] = [
            [sqrt_fp(contrib[i][p]) if contrib[i][p] > 0 else 0 for p in range(num_p)]
            for i in range(num_d)
        ]
        m_fp = pairwise_m * SCALE
        m_num = m_fp * SCALE
        for i in range(num_d):
            ri = roots[i]
            for j in range(i + 1, num_d):
                rj = roots[j]
                overlap_fp = 0
                shared_ps: List[int] = []
                for p in range(num_p):
                    if ri[p] and rj[p]:
                        shared_ps.append(p)
                        overlap_fp += (ri[p] * rj[p]) // SCALE
                if not shared_ps:
                    continue
                k_fp = m_num // (m_fp + overlap_fp)
                for p in shared_ps:
                    weights[p] += 2 * ((k_fp * ri[p] * rj[p]) // SCALE)
        matched, unallocated = allocate_pool_hamilton(pool, proj_ids, weights)

    elif mech == "reputation_weighted_qf":
        r_weights = [
            rep_weight_fp(int(d["zoo_rep"]), min_rep_gate, rep_min_fp) for d in donors
        ]
        for p in range(num_p):
            sum_u = 0
            sum_sq = 0
            for i in range(num_d):
                c_ip = contrib[i][p]
                rw = r_weights[i]
                if c_ip == 0 or rw == 0:
                    continue
                u = sqrt_weighted_fp(rw, c_ip)
                sum_u += u
                sum_sq += u * u
            weights[p] = max(0, sum_u * sum_u - sum_sq)
        matched, unallocated = allocate_pool_hamilton(pool, proj_ids, weights)

    elif mech == "hybrid_cocm_reputation_capped_qf":
        cluster_map: Dict[str, List[int]] = {}
        for i, d in enumerate(donors):
            cid = d["cluster_id"] or d["id"]
            if cid not in cluster_map:
                cluster_map[cid] = [0] * num_p
            rw = rep_weight_fp(int(d["zoo_rep"]), min_rep_gate, rep_min_fp)
            if rw == 0:
                continue
            vec = cluster_map[cid]
            for p in range(num_p):
                c_ip = contrib[i][p]
                if c_ip == 0:
                    continue
                if donor_cap > 0 and c_ip > donor_cap:
                    c_ip = donor_cap
                vec[p] += (rw * c_ip) // SCALE

        cluster_ids = sorted(cluster_map.keys())
        num_g = len(cluster_ids)
        c_roots: List[List[int]] = []
        c_norm_sq: List[int] = []
        for cid in cluster_ids:
            vec = cluster_map[cid]
            r_vec = [sqrt_fp(vec[p]) if vec[p] > 0 else 0 for p in range(num_p)]
            c_roots.append(r_vec)
            c_norm_sq.append(sum(r * r for r in r_vec))

        m_fp = cocm_m * SCALE
        m_num = m_fp * SCALE
        for g in range(num_g):
            if c_norm_sq[g] == 0:
                continue
            rg = c_roots[g]
            for h in range(g + 1, num_g):
                if c_norm_sq[h] == 0:
                    continue
                rh = c_roots[h]
                dot = 0
                overlap_fp = 0
                shared_ps = []
                for p in range(num_p):
                    if rg[p] and rh[p]:
                        shared_ps.append(p)
                        prod = rg[p] * rh[p]
                        dot += prod
                        overlap_fp += prod // SCALE
                if not shared_ps:
                    continue
                k_pair = m_num // (m_fp + overlap_fp)
                sim2_fp = min(SCALE, (dot * dot * SCALE) // (c_norm_sq[g] * c_norm_sq[h]))
                pen_fp = max(0, SCALE - (cocm_lambda_bps * sim2_fp) // BPS)
                k_cocm = (k_pair * pen_fp) // SCALE
                for p in shared_ps:
                    weights[p] += 2 * ((k_cocm * rg[p] * rh[p]) // SCALE)

        matched, unallocated = allocate_pool_capped(pool, project_cap, proj_ids, weights)

    else:
        raise ValueError(f"unknown mechanism {mech!r}")

    allocs = []
    for p in range(num_p):
        allocs.append(
            {
                "project_id": proposals[p]["id"],
                "direct_micro_zoo": direct_totals[p],
                "match_micro_zoo": matched[p],
                "total_micro_zoo": direct_totals[p] + matched[p],
                "unique_donors": unique_donors[p],
                "match_share_bps": (matched[p] * BPS) // pool,
            }
        )

    total_matched = sum(matched)
    attacker_match = 0
    grassroots_match = 0
    minority_match = 0
    lab_match = 0
    newcomer_match = 0
    whale_niche_match = 0
    merit_weighted_num = 0
    honest_matches: List[int] = []

    for i, prop in enumerate(proposals):
        m_val = matched[i]
        merit_weighted_num += m_val * int(prop["merit_bps"])
        if prop["is_attacker_target"]:
            attacker_match += m_val
        else:
            honest_matches.append(m_val)
        if prop["archetype"] in ("broad_public_good", "grassroots_minority"):
            grassroots_match += m_val
        if prop["archetype"] == "grassroots_minority":
            minority_match += m_val
        if prop["is_lab_grant"]:
            lab_match += m_val
        if prop["is_newcomer_grant"]:
            newcomer_match += m_val
        if prop["archetype"] == "whale_niche":
            whale_niche_match += m_val

    att = scenario["attack_model"]
    direct_budget = int(att["direct_budget_micro_zoo"])
    total_attack_cost = int(att["total_attack_cost_micro_zoo"])

    metrics = {
        "pool_conserved": (total_matched + unallocated == pool)
        and total_matched >= 0
        and unallocated >= 0,
        "total_matched_micro_zoo": total_matched,
        "unallocated_pool_micro_zoo": unallocated,
        "attacker_match_micro_zoo": attacker_match,
        "pool_extraction_bps": (attacker_match * BPS) // pool,
        "direct_cost_roi_bps": (attacker_match * BPS) // direct_budget
        if direct_budget > 0
        else 0,
        "net_attack_roi_bps": (attacker_match * BPS) // total_attack_cost
        if total_attack_cost > 0
        else 0,
        "merit_welfare_bps": merit_weighted_num // pool,
        "grassroots_share_bps": (grassroots_match * BPS) // pool,
        "minority_share_bps": (minority_match * BPS) // pool,
        "honest_gini_bps": compute_gini_bps(honest_matches),
        "lab_share_bps": (lab_match * BPS) // pool,
        "newcomer_share_bps": (newcomer_match * BPS) // pool,
        "whale_niche_share_bps": (whale_niche_match * BPS) // pool,
    }

    gate = {
        "plan_status": "PROPOSED_REQUIRES_HUMAN_SIGN_OFF",
        "required_human_quorum": 3,
        "treasury_committee_size": 5,
        "min_steward_zoo_rep": 200,
        "human_signatures_collected": 0,
        "ai_rule_mutation_blocked": True,
        "ai_treasury_auth_blocked": True,
        "ai_self_validation_blocked": True,
    }

    ev = {
        "scenario_id": scenario["id"],
        "mechanism_id": mech,
        "matching_pool_micro_zoo": pool,
        "allocations": allocs,
        "metrics": metrics,
        "governance_gate": gate,
    }
    ev["leaf_hash"] = hash_evaluation(ev)
    return ev

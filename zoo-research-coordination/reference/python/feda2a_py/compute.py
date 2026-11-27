# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.

"""Bit-exact fixed-point ZooCoord ZHL scientific experiment kernel matching Go."""

import math
from typing import Any, Dict

from .canonical import hash_canonical

MICRO_SCALE = 1_000_000
TIER_SHARED_EXCHANGE = "shared_exchange"
DOMAIN_COMMITMENT = "federated-a2a.v1:commitment"
DOMAIN_RESULT_ARTIFACT = "federated-a2a.v1:result_artifact"


def trunc_div(num: int, den: int) -> int:
    """Integer division truncated toward zero (matches Go big.Int.Quo)."""
    if den == 0:
        return 0
    neg = (num < 0) ^ (den < 0)
    q = abs(num) // abs(den)
    return -q if neg else q


def compute_commitment_hash(c: Dict[str, Any]) -> str:
    return hash_canonical(
        DOMAIN_COMMITMENT,
        {
            "alpha_bps": c["alpha_bps"],
            "commitment_id": c["commitment_id"],
            "group_a_micro": c.get("group_a_micro") or [],
            "group_b_micro": c.get("group_b_micro") or [],
            "hypothesis": c["hypothesis"],
            "input_record_refs": c.get("input_record_refs") or [],
            "input_tier": c["input_tier"],
            "min_effect_micro": c["min_effect_micro"],
            "zhl_template": c["zhl_template"],
        },
    )


def compute_scientific_result_hash(r: Dict[str, Any]) -> str:
    return hash_canonical(
        DOMAIN_RESULT_ARTIFACT,
        {
            "commitment_hash": r["commitment_hash"],
            "effect_size_micro": r["effect_size_micro"],
            "mean_a_micro": r["mean_a_micro"],
            "mean_b_micro": r["mean_b_micro"],
            "output_tier": r["output_tier"],
            "sample_count": r["sample_count"],
            "significant": r["significant"],
            "stat_micro": r["stat_micro"],
            "summary_note": r["summary_note"],
            "task_id": r["task_id"],
            "var_a_micro": r["var_a_micro"],
            "var_b_micro": r["var_b_micro"],
            "zhl_template": r["zhl_template"],
        },
    )


def run_deterministic_zhl(task_id: str, c: Dict[str, Any]) -> Dict[str, Any]:
    """Execute ZooCoord ZHL COMPARE or CORRELATE identically to Go RunDeterministicZHL."""
    group_a = c.get("group_a_micro") or []
    group_b = c.get("group_b_micro") or []
    n_a = len(group_a)
    n_b = len(group_b)
    if n_a < 2 or n_b < 2:
        raise ValueError(f"insufficient samples: group_a={n_a} group_b={n_b}")
    tmpl = c["zhl_template"]
    if tmpl == "CORRELATE" and n_a != n_b:
        raise ValueError(f"CORRELATE requires equal lengths: {n_a} != {n_b}")

    mean_a = trunc_div(sum(group_a), n_a)
    mean_b = trunc_div(sum(group_b), n_b)

    ss_a = sum((v - mean_a) * (v - mean_a) for v in group_a)
    ss_b = sum((v - mean_b) * (v - mean_b) for v in group_b)
    var_a = trunc_div(ss_a, n_a * MICRO_SCALE)
    var_b = trunc_div(ss_b, n_b * MICRO_SCALE)

    if tmpl == "COMPARE":
        sample_count = n_a + n_b
        effect_micro = mean_b - mean_a
        term_a = trunc_div(var_a * MICRO_SCALE, n_a)
        term_b = trunc_div(var_b * MICRO_SCALE, n_b)
        se_sq = term_a + term_b
        se = math.isqrt(se_sq) if se_sq > 0 else 0
        if se <= 0:
            se = 1
        stat_micro = trunc_div(effect_micro * MICRO_SCALE, se)
        significant = abs(effect_micro) >= c["min_effect_micro"] and abs(stat_micro) >= 2 * MICRO_SCALE
        sig_str = "true" if significant else "false"
        summary = (
            f"ZHL COMPARE deterministic verification: n={sample_count} "
            f"effect_micro={effect_micro} stat_micro={stat_micro} significant={sig_str}"
        )
    elif tmpl == "CORRELATE":
        sample_count = n_a
        cov = sum((group_a[i] - mean_a) * (group_b[i] - mean_b) for i in range(n_a))
        den_sq = ss_a * ss_b
        den = math.isqrt(den_sq) if den_sq > 0 else 0
        effect_micro = trunc_div(cov * MICRO_SCALE, den) if den > 0 else 0
        stat_micro = abs(effect_micro)
        significant = stat_micro >= c["min_effect_micro"]
        sig_str = "true" if significant else "false"
        summary = (
            f"ZHL CORRELATE deterministic verification: n={sample_count} "
            f"r_micro={effect_micro} significant={sig_str}"
        )
    else:
        raise ValueError(f"unsupported ZHL template: {tmpl}")

    commit_hash = c.get("commitment_hash") or compute_commitment_hash(c)
    res: Dict[str, Any] = {
        "task_id": task_id,
        "commitment_hash": commit_hash,
        "zhl_template": tmpl,
        "sample_count": sample_count,
        "mean_a_micro": mean_a,
        "mean_b_micro": mean_b,
        "var_a_micro": var_a,
        "var_b_micro": var_b,
        "effect_size_micro": effect_micro,
        "stat_micro": stat_micro,
        "significant": significant,
        "output_tier": TIER_SHARED_EXCHANGE,
        "summary_note": summary,
    }
    res["result_hash"] = compute_scientific_result_hash(res)
    return res

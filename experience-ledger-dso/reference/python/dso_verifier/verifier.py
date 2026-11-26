# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation
"""Independent pure-Python 3.12 audit verifier for dso-aggregation.v1."""

from __future__ import annotations

import hashlib
import math
from typing import Any

from .canonical import (
    FEATURE_DIM,
    FIXED_SCALE,
    SCHEMA_VERSION,
    canonical_cell_leaf_hash,
    canonical_contribution_bytes,
    compute_merkle_root,
    from_micro,
    to_micro,
)
from .ed25519 import verify_ed25519

SIGN_DOMAIN_PREFIX = b"dso-aggregation.v1:"
DOMAIN_PROTOCOL = "protocol_governance"
DOMAIN_CONSERVATION = "conservation_science"


def verify_contribution(env: dict[str, Any]) -> tuple[bool, str]:
    body = env.get("body", {})
    if body.get("schema_version") != SCHEMA_VERSION:
        return False, "ERR_INVALID_SCHEMA_VERSION"
    try:
        pub = bytes.fromhex(body.get("public_key_hex", ""))
    except ValueError:
        return False, "ERR_INVALID_PUBLIC_KEY"
    if len(pub) != 32:
        return False, "ERR_INVALID_PUBLIC_KEY"
    try:
        sig = bytes.fromhex(env.get("signature_hex", ""))
    except ValueError:
        return False, "ERR_INVALID_SIGNATURE_FORMAT"
    if len(sig) != 64:
        return False, "ERR_INVALID_SIGNATURE_FORMAT"

    canonical = canonical_contribution_bytes(body)
    digest = hashlib.sha256(canonical).hexdigest()
    if digest != env.get("digest_sha256"):
        return False, "ERR_DIGEST_MISMATCH"
    if not verify_ed25519(pub, SIGN_DOMAIN_PREFIX + canonical, sig):
        return False, "ERR_INVALID_SIGNATURE"
    return True, ""


def validate_experience_schema(exp: dict[str, Any]) -> tuple[bool, str]:
    if exp.get("op") not in ("Add", "Modify", "Delete"):
        return False, "ERR_INVALID_OP"
    if exp.get("domain") not in (DOMAIN_PROTOCOL, DOMAIN_CONSERVATION):
        return False, "ERR_INVALID_DOMAIN"
    conf = exp.get("confidence_micro", -1)
    if conf < 0 or conf > FIXED_SCALE:
        return False, "ERR_INVALID_CONFIDENCE"
    if len(exp.get("paper_sha256", "")) != 64:
        return False, "ERR_MISSING_PAPER_ANCHOR"
    txt = str(exp.get("text", "")).strip()
    words = txt.split()
    if len(words) < 5 or len(words) > 32:
        return False, "ERR_TEXT_LENGTH_VIOLATION"
    if not (txt.startswith("When ") or txt.startswith("For ") or " implies " in txt):
        return False, "ERR_NON_ACTIONABLE_EXPERIENCE"
    return True, ""


def _dot(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def _l2_norm(v: list[float]) -> float:
    return math.sqrt(_dot(v, v))


def _cos_sim(a: list[float], b: list[float]) -> float:
    na = _l2_norm(a)
    nb = _l2_norm(b)
    if na < 1e-12 or nb < 1e-12:
        return 0.0
    return _dot(a, b) / (na * nb)


def _sq_dist(a: list[float], b: list[float]) -> float:
    return sum((x - y) * (x - y) for x, y in zip(a, b))


def evaluate_logistic(w: list[float], examples: list[tuple[list[float], int]]) -> tuple[float, float]:
    if not examples:
        return 0.0, 0.0
    correct = 0
    total_loss = 0.0
    for feats, label in examples:
        z = float(label) * _dot(w, feats)
        if z > 0.0 or (z == 0.0 and label > 0):
            correct += 1
        if z >= 0.0:
            total_loss += math.log1p(math.exp(-z))
        else:
            total_loss += -z + math.log1p(math.exp(z))
    n = float(len(examples))
    return correct / n, total_loss / n


def jains_fairness_index(vals: list[float]) -> float:
    n = len(vals)
    if n == 0:
        return 0.0
    clean = [max(0.0, float(v)) for v in vals]
    s = sum(clean)
    s2 = sum(v * v for v in clean)
    if s2 <= 1e-18:
        return 0.0
    return (s * s) / (float(n) * s2)


def gini_coefficient(vals: list[float]) -> float:
    n = len(vals)
    if n == 0:
        return 0.0
    clean = [max(0.0, float(v)) for v in vals]
    s = sum(clean)
    if s <= 1e-18:
        return 1.0
    diff_sum = sum(abs(a - b) for a in clean for b in clean)
    return diff_sum / (2.0 * float(n) * s)


def aggregate_round(
    aggregator: str,
    envelopes: list[dict[str, Any]],
    base_model: list[float],
    reputations: list[float],
    val_proto: list[tuple[list[float], int]],
    val_cons: list[tuple[list[float], int]],
    cfg: dict[str, Any],
) -> dict[str, Any]:
    n = len(envelopes)
    weights = [0.0] * n
    accepted = [False] * n
    reject_reasons = [""] * n
    cluster_sizes = [1] * n
    agg_delta = [0.0] * FEATURE_DIM
    invalid_sig = 0
    invalid_schema = 0

    valid: list[int] = []
    deltas: list[list[float]] = [[0.0] * FEATURE_DIM for _ in range(n)]
    for i, env in enumerate(envelopes):
        ok, err = verify_contribution(env)
        if not ok:
            invalid_sig += 1
            reject_reasons[i] = err
            continue
        dm = env["body"].get("delta_micro", [])
        if len(dm) != FEATURE_DIM:
            invalid_schema += 1
            reject_reasons[i] = "ERR_INVALID_DELTA_DIM"
            continue
        deltas[i] = [from_micro(int(x)) for x in dm]
        valid.append(i)

    m = len(valid)
    if m == 0:
        return {
            "aggregator": aggregator,
            "aggregated_delta_micro": [to_micro(x) for x in agg_delta],
            "weights_micro": [to_micro(x) for x in weights],
            "accepted": accepted,
            "cluster_sizes": cluster_sizes,
            "invalid_sig_count": invalid_sig,
            "invalid_schema_count": invalid_schema,
        }

    if aggregator == "mean_baseline":
        inv = 1.0 / float(m)
        for idx in valid:
            weights[idx] = inv
            accepted[idx] = True
            for d in range(FEATURE_DIM):
                agg_delta[d] += deltas[idx][d] * inv

    elif aggregator == "coord_median":
        survived = [0.0] * n
        total_e = [_dot(deltas[i], deltas[i]) for i in range(n)]
        for d in range(FEATURE_DIM):
            pairs = sorted(((deltas[idx][d], idx) for idx in valid), key=lambda p: (p[0], p[1]))
            if m % 2 == 1:
                med = pairs[m // 2][0]
            else:
                med = 0.5 * (pairs[m // 2 - 1][0] + pairs[m // 2][0])
            agg_delta[d] = med
            band_lo = (m * 3) // 10
            band_hi = m - 1 - band_lo
            if band_hi < band_lo:
                band_lo = band_hi = m // 2
            for r in range(band_lo, band_hi + 1):
                v, idx = pairs[r]
                if v * med > 1e-12:
                    survived[idx] += v * v
        ratios = [0.0] * n
        sum_r = 0.0
        for idx in valid:
            if total_e[idx] > 1e-12:
                r = min(1.0, survived[idx] / total_e[idx])
                ratios[idx] = r
                sum_r += r
        th = float(cfg["acceptance_weight_th"]) / float(m)
        for idx in valid:
            if sum_r > 1e-12:
                weights[idx] = ratios[idx] / sum_r
            if weights[idx] >= th:
                accepted[idx] = True
            else:
                reject_reasons[idx] = "FILTERED_OUT_BY_COORD_MEDIAN"

    elif aggregator == "trimmed_mean":
        k_trim = int(math.floor(float(cfg["trim_beta"]) * float(m)))
        if 2 * k_trim >= m:
            k_trim = (m - 1) // 2
        kept = m - 2 * k_trim
        survived = [0.0] * n
        total_e = [_dot(deltas[i], deltas[i]) for i in range(n)]
        for d in range(FEATURE_DIM):
            pairs = sorted(((deltas[idx][d], idx) for idx in valid), key=lambda p: (p[0], p[1]))
            mean_v = sum(pairs[r][0] for r in range(k_trim, m - k_trim)) / float(kept)
            agg_delta[d] = mean_v
            for r in range(k_trim, m - k_trim):
                v, idx = pairs[r]
                if v * mean_v > 1e-12:
                    survived[idx] += v * v
        ratios = [0.0] * n
        sum_r = 0.0
        for idx in valid:
            if total_e[idx] > 1e-12:
                r = min(1.0, survived[idx] / total_e[idx])
                ratios[idx] = r
                sum_r += r
        th = float(cfg["acceptance_weight_th"]) / float(m)
        for idx in valid:
            if sum_r > 1e-12:
                weights[idx] = ratios[idx] / sum_r
            if weights[idx] >= th:
                accepted[idx] = True
            else:
                reject_reasons[idx] = "FILTERED_OUT_BY_TRIMMED_MEAN"

    elif aggregator == "multi_krum":
        if m == 1:
            idx = valid[0]
            agg_delta = list(deltas[idx])
            weights[idx] = 1.0
            accepted[idx] = True
        else:
            k_nn = max(1, min(m - 1, m - int(cfg["krum_assumed_byz"]) - 2))
            sel_m = max(1, min(m, int(cfg["krum_select_m"])))
            scores: list[tuple[float, int]] = []
            for i, idx_i in enumerate(valid):
                dists = sorted(_sq_dist(deltas[idx_i], deltas[idx_j]) for j, idx_j in enumerate(valid) if i != j)
                scores.append((sum(dists[:k_nn]), idx_i))
            scores.sort(key=lambda p: (p[0], p[1]))
            inv = 1.0 / float(sel_m)
            for r in range(sel_m):
                idx = scores[r][1]
                weights[idx] = inv
                accepted[idx] = True
                for d in range(FEATURE_DIM):
                    agg_delta[d] += deltas[idx][d] * inv

    elif aggregator == "dso_reputation_eval_gated":
        _, base_loss_p = evaluate_logistic(base_model, val_proto)
        _, base_loss_c = evaluate_logistic(base_model, val_cons)
        eta = float(cfg["dso_eval_step"])
        min_gain = float(cfg["dso_min_gain"])
        safety_tol = float(cfg["dso_safety_tol"])
        max_norm = float(cfg["dso_max_delta_norm"])
        cos_th = float(cfg["dso_cluster_cos"])
        min_floor = float(cfg["dso_minority_floor"])

        admitted: list[int] = []
        gains = [0.0] * n
        for idx in valid:
            env = envelopes[idx]
            ok_s, err_s = validate_experience_schema(env["body"]["experience"])
            if not ok_s:
                invalid_schema += 1
                reject_reasons[idx] = err_s
                continue
            if _l2_norm(deltas[idx]) > max_norm:
                reject_reasons[idx] = "ERR_DELTA_NORM_EXCEEDED"
                continue
            probe = [base_model[d] + eta * deltas[idx][d] for d in range(FEATURE_DIM)]
            _, loss_p = evaluate_logistic(probe, val_proto)
            _, loss_c = evaluate_logistic(probe, val_cons)
            gp = base_loss_p - loss_p
            gc = base_loss_c - loss_c
            if env["body"]["domain"] == DOMAIN_CONSERVATION:
                g_own, g_other = gc, gp
            else:
                g_own, g_other = gp, gc
            if g_own <= min_gain:
                reject_reasons[idx] = "ERR_INSUFFICIENT_HELD_OUT_GAIN"
                continue
            if g_other < -safety_tol:
                reject_reasons[idx] = "ERR_CROSS_DOMAIN_SAFETY_VIOLATION"
                continue
            gains[idx] = g_own
            admitted.append(idx)

        if admitted:
            for idx_i in admitted:
                csize = 1
                for idx_j in admitted:
                    if idx_i != idx_j and _cos_sim(deltas[idx_i], deltas[idx_j]) >= cos_th:
                        csize += 1
                cluster_sizes[idx_i] = csize

            raw_score = [0.0] * n
            p_sum = c_sum = 0.0
            p_idx: list[int] = []
            c_idx: list[int] = []
            for idx in admitted:
                rep = reputations[idx] if idx < len(reputations) and reputations[idx] > 0 else 1.0
                s = rep * math.sqrt(max(gains[idx], 1e-6)) / float(cluster_sizes[idx])
                raw_score[idx] = s
                if envelopes[idx]["body"]["domain"] == DOMAIN_CONSERVATION:
                    c_sum += s
                    c_idx.append(idx)
                else:
                    p_sum += s
                    p_idx.append(idx)

            p_share = c_share = 0.0
            if p_idx and c_idx:
                nat_c = c_sum / (p_sum + c_sum)
                c_share = max(min_floor, min(1.0 - min_floor, nat_c))
                p_share = 1.0 - c_share
            elif p_idx:
                p_share = 1.0
            elif c_idx:
                c_share = 1.0

            for idx in p_idx:
                w = p_share * (raw_score[idx] / p_sum)
                weights[idx] = w
                accepted[idx] = True
                for d in range(FEATURE_DIM):
                    agg_delta[d] += w * deltas[idx][d]
            for idx in c_idx:
                w = c_share * (raw_score[idx] / c_sum)
                weights[idx] = w
                accepted[idx] = True
                for d in range(FEATURE_DIM):
                    agg_delta[d] += w * deltas[idx][d]

    return {
        "aggregator": aggregator,
        "aggregated_delta_micro": [to_micro(x) for x in agg_delta],
        "weights_micro": [to_micro(x) for x in weights],
        "accepted": accepted,
        "cluster_sizes": cluster_sizes,
        "invalid_sig_count": invalid_sig,
        "invalid_schema_count": invalid_schema,
    }


def verify_results_report(report: dict[str, Any]) -> dict[str, Any]:
    """Independently verify results.json schema invariants and AuditMerkleRoot."""
    if report.get("schema_version") != SCHEMA_VERSION:
        raise AssertionError(f"unexpected schema_version: {report.get('schema_version')}")
    cells = report.get("cells", [])
    if len(cells) != 120:
        raise AssertionError(f"expected 120 benchmark cells (4x6x5), got {len(cells)}")

    leaf_digests: list[str] = []
    for c in cells:
        if not (0.0 <= c["jains_fairness_index"] <= 1.0 + 1e-9):
            raise AssertionError(f"invalid Jain index in {c['scenario']}/{c['aggregator']}")
        if not (0.0 <= c["attribution_gini"] <= 1.0 + 1e-9):
            raise AssertionError(f"invalid Gini in {c['scenario']}/{c['aggregator']}")
        if not (0.0 <= c["global_test_accuracy"] <= 1.0):
            raise AssertionError(f"invalid global_test_accuracy in {c['scenario']}/{c['aggregator']}")
        leaf_digests.append(canonical_cell_leaf_hash(c))

    recomputed = compute_merkle_root(leaf_digests)
    expected = report.get("audit_merkle_root")
    if recomputed != expected:
        raise AssertionError(f"audit_merkle_root mismatch: python={recomputed} go={expected}")

    neg = report.get("negative_regimes", {})
    if len(neg.get("regime_1_minority_erasure_at_zero_adv", [])) != 5:
        raise AssertionError("missing regime_1_minority_erasure_at_zero_adv entries")
    if len(neg.get("regime_2_unmonitored_backdoor", [])) < 10:
        raise AssertionError("missing regime_2_unmonitored_backdoor entries")
    if len(neg.get("regime_3_fifty_pct_and_committee", [])) < 6:
        raise AssertionError("missing regime_3_fifty_pct_and_committee entries")

    return {
        "cells_verified": len(cells),
        "audit_merkle_root": recomputed,
        "corpus_papers": report.get("corpus_paper_count"),
        "corpus_sha256": report.get("corpus_sha256"),
    }


def verify_audit_trace(trace: dict[str, Any], expected_report_merkle: str | None = None) -> dict[str, Any]:
    """Independently verify Ed25519 signatures, Merkle roots, and all 5 aggregators in audit_trace.json."""
    if trace.get("schema_version") != SCHEMA_VERSION:
        raise AssertionError(f"unexpected trace schema_version: {trace.get('schema_version')}")
    if expected_report_merkle and trace.get("report_merkle_root") != expected_report_merkle:
        raise AssertionError("trace report_merkle_root does not match results.json audit_merkle_root")

    cfg = trace["config"]
    val_proto = [([from_micro(int(x)) for x in ex["features_micro"]], int(ex["label"])) for ex in trace["val_protocol"]]
    val_cons = [([from_micro(int(x)) for x in ex["features_micro"]], int(ex["label"])) for ex in trace["val_conservation"]]

    round_roots: list[str] = []
    sigs_verified = 0
    agg_runs_verified = 0

    for rd in trace["rounds"]:
        envs = rd["contributions"]
        digests: list[str] = []
        for env in envs:
            ok, err = verify_contribution(env)
            if not ok:
                raise AssertionError(f"Ed25519 verification failed in {rd['label']} node {env['body']['node_id']}: {err}")
            sigs_verified += 1
            digests.append(env["digest_sha256"])

        rd_merkle = compute_merkle_root(digests)
        if rd_merkle != rd["round_merkle_root"]:
            raise AssertionError(f"round_merkle_root mismatch in {rd['label']}: py={rd_merkle} go={rd['round_merkle_root']}")
        round_roots.append(rd_merkle)

        base_model = [from_micro(int(x)) for x in rd["base_model_micro"]]
        reps = [from_micro(int(x)) for x in rd["reputation_micro"]]

        for exp_out in rd["expected_outputs"]:
            agg = exp_out["aggregator"]
            py_out = aggregate_round(agg, envs, base_model, reps, val_proto, val_cons, cfg)

            if py_out["accepted"] != exp_out["accepted"]:
                raise AssertionError(f"accepted mismatch in {rd['label']}/{agg}")
            if py_out["cluster_sizes"] != exp_out["cluster_sizes"]:
                raise AssertionError(f"cluster_sizes mismatch in {rd['label']}/{agg}")
            for d, (pv, gv) in enumerate(zip(py_out["aggregated_delta_micro"], exp_out["aggregated_delta_micro"])):
                if abs(pv - gv) > 1:
                    raise AssertionError(f"delta[{d}] mismatch in {rd['label']}/{agg}: py={pv} go={gv}")
            for i, (pw, gw) in enumerate(zip(py_out["weights_micro"], exp_out["weights_micro"])):
                if abs(pw - gw) > 1:
                    raise AssertionError(f"weight[{i}] mismatch in {rd['label']}/{agg}: py={pw} go={gw}")
            agg_runs_verified += 1

    trace_root = compute_merkle_root(round_roots)
    if trace_root != trace["trace_merkle_root"]:
        raise AssertionError(f"trace_merkle_root mismatch: py={trace_root} go={trace['trace_merkle_root']}")

    return {
        "rounds_verified": len(trace["rounds"]),
        "ed25519_signatures_verified": sigs_verified,
        "aggregator_runs_verified": agg_runs_verified,
        "trace_merkle_root": trace_root,
    }

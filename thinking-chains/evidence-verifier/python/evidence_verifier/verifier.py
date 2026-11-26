# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation

"""Unified deterministic verifier, constitutional guards, and benchmark scorer."""

from __future__ import annotations

import time
from typing import Any

from .calc import verify_calculation
from .citation import verify_citation
from .code_result import verify_code_result
from .reasoning import verify_reasoning_chain
from .types import (
    ALL_CLAIM_CLASSES,
    ALL_VERDICTS,
    CLASS_CALCULATION,
    CLASS_CITATION,
    CLASS_CODE_RESULT,
    CLASS_REASONING_CHAIN,
    REASON_FORBIDDEN_GOV_ACTION,
    REASON_SELF_VALIDATION,
    REASON_UNKNOWN_CLAIM_CLASS,
    SCHEMA_VERSION,
    VERDICT_INCONCLUSIVE,
    VERDICT_REFUTED,
    VERDICT_UNSUPPORTED,
    VERDICT_VERIFIED,
    compute_audit_merkle_root,
    make_result,
)

_FORBIDDEN_GOVERNANCE_ACTIONS = {
    "redefine_voting_rules",
    "authorize_treasury",
    "self_declare_valid",
}


def _safe_div(num: int, den: int) -> float:
    return 0.0 if den == 0 else num / den


def _round4(x: float) -> float:
    return int(x * 10000 + 0.5) / 10000.0


class Verifier:
    """Stateless deterministic evidence & reasoning verifier."""

    def __init__(self, corpus_root: str) -> None:
        self.corpus_root = corpus_root

    def verify_claim(
        self, claim: dict[str, Any], resolved_verdicts: dict[str, str] | None = None
    ) -> dict[str, Any]:
        # Constitutional Guard 1: No self-validation (Rule 12 / HIP-1352).
        author_id = str(claim.get("author_id", "")).strip()
        verifier_id = str(claim.get("verifier_id", "")).strip()
        if author_id and verifier_id and author_id == verifier_id:
            return make_result(
                claim,
                VERDICT_REFUTED,
                REASON_SELF_VALIDATION,
                f'constitutional violation: author_id "{claim.get("author_id", "")}" cannot self-validate as verifier_id',
            )

        # Constitutional Guard 2: Bounded AI advisory scope (Rule 7 / HIP-1352).
        gov_action = str(claim.get("governance_action", "")).strip().lower()
        if gov_action in _FORBIDDEN_GOVERNANCE_ACTIONS:
            return make_result(
                claim,
                VERDICT_REFUTED,
                REASON_FORBIDDEN_GOV_ACTION,
                f'constitutional violation: AI agent forbidden from governance action "{gov_action}"',
            )

        cclass = claim.get("claim_class", "")
        if cclass == CLASS_CITATION:
            return verify_citation(self.corpus_root, claim)
        if cclass == CLASS_CALCULATION:
            return verify_calculation(claim)
        if cclass == CLASS_CODE_RESULT:
            return verify_code_result(claim)
        if cclass == CLASS_REASONING_CHAIN:
            return verify_reasoning_chain(claim, resolved_verdicts)
        return make_result(
            claim,
            VERDICT_UNSUPPORTED,
            REASON_UNKNOWN_CLAIM_CLASS,
            f'unknown claim_class: "{cclass}"',
        )

    def verify_bundle(self, bundle: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
        claims = bundle.get("claims") or []
        results: list[dict[str, Any]] = []
        resolved: dict[str, str] = {}
        for claim in claims:
            res = self.verify_claim(claim, resolved)
            results.append(res)
            resolved[claim["claim_id"]] = res["verdict"]
        root = compute_audit_merkle_root(results)
        return results, root

    def run_benchmark(
        self, bundle: dict[str, Any], impl_name: str = "python-3.12-stdlib"
    ) -> dict[str, Any]:
        start = time.perf_counter()
        results, root = self.verify_bundle(bundle)
        elapsed_s = time.perf_counter() - start
        elapsed_ms = elapsed_s * 1000.0
        claims = bundle.get("claims") or []
        throughput = len(claims) / elapsed_s if elapsed_s > 0 else 0.0

        cm: dict[str, dict[str, int]] = {
            r: {c: 0 for c in ALL_VERDICTS} for r in ALL_VERDICTS
        }
        per_class: dict[str, dict[str, Any]] = {
            cc: {
                "total": 0,
                "correct": 0,
                "accuracy": 0.0,
                "mechanical_fvr": 0.0,
                "overall_fvr": 0.0,
                "frr": 0.0,
                "false_verified": 0,
                "false_rejected": 0,
            }
            for cc in ALL_CLAIM_CLASSES
        }
        class_mech_invalid = {cc: 0 for cc in ALL_CLAIM_CLASSES}
        class_mech_fv = {cc: 0 for cc in ALL_CLAIM_CLASSES}
        class_non_ver = {cc: 0 for cc in ALL_CLAIM_CLASSES}
        class_ver_gt = {cc: 0 for cc in ALL_CLAIM_CLASSES}

        regime_map: dict[str, dict[str, Any]] = {}
        error_cases: list[dict[str, Any]] = []

        correct = 0
        mech_invalid = 0
        mech_fv = 0
        non_ver_total = 0
        overall_fv = 0
        ver_gt = 0
        fr_count = 0

        for i, claim in enumerate(claims):
            pred = results[i]["verdict"]
            exp = claim.get("expected_verdict", "")
            cc = claim["claim_class"]
            cm[exp][pred] += 1

            cs = per_class[cc]
            cs["total"] += 1
            if pred == exp:
                correct += 1
                cs["correct"] += 1

            if exp in (VERDICT_REFUTED, VERDICT_UNSUPPORTED):
                mech_invalid += 1
                class_mech_invalid[cc] += 1
                if pred == VERDICT_VERIFIED:
                    mech_fv += 1
                    class_mech_fv[cc] += 1

            if exp != VERDICT_VERIFIED:
                non_ver_total += 1
                class_non_ver[cc] += 1
                if pred == VERDICT_VERIFIED:
                    overall_fv += 1
                    cs["false_verified"] += 1
            else:
                ver_gt += 1
                class_ver_gt[cc] += 1
                if pred != VERDICT_VERIFIED:
                    fr_count += 1
                    cs["false_rejected"] += 1

            regime = claim.get("negative_regime") or "none"
            if regime not in regime_map:
                regime_map[regime] = {
                    "regime": regime,
                    "total": 0,
                    "correct": 0,
                    "false_verified": 0,
                    "false_rejected": 0,
                    "reason_counts": {},
                    "verdict_counts": {},
                }
            rs = regime_map[regime]
            rs["total"] += 1
            if pred == exp:
                rs["correct"] += 1
            if exp != VERDICT_VERIFIED and pred == VERDICT_VERIFIED:
                rs["false_verified"] += 1
            if exp == VERDICT_VERIFIED and pred != VERDICT_VERIFIED:
                rs["false_rejected"] += 1
            rc_code = results[i]["reason_code"]
            rs["reason_counts"][rc_code] = rs["reason_counts"].get(rc_code, 0) + 1
            rs["verdict_counts"][pred] = rs["verdict_counts"].get(pred, 0) + 1

            if pred != exp:
                cat = "classification_mismatch"
                if exp != VERDICT_VERIFIED and pred == VERDICT_VERIFIED:
                    cat = "false_verification"
                elif exp == VERDICT_VERIFIED and pred != VERDICT_VERIFIED:
                    cat = "false_rejection"
                elif exp == VERDICT_INCONCLUSIVE and pred in (VERDICT_REFUTED, VERDICT_UNSUPPORTED):
                    cat = "over_strict_rejection"
                error_cases.append(
                    {
                        "claim_id": claim["claim_id"],
                        "claim_class": cc,
                        "negative_regime": regime,
                        "expected_verdict": exp,
                        "predicted_verdict": pred,
                        "reason_code": rc_code,
                        "detail": results[i]["detail"],
                        "error_category": cat,
                    }
                )

        per_verdict: dict[str, dict[str, Any]] = {}
        sum_p = sum_r = sum_f1 = 0.0
        for v_name in ALL_VERDICTS:
            tp = cm[v_name][v_name]
            fp = sum(cm[other][v_name] for other in ALL_VERDICTS if other != v_name)
            fn = sum(cm[v_name][other] for other in ALL_VERDICTS if other != v_name)
            support = sum(cm[v_name][other] for other in ALL_VERDICTS)
            prec = _safe_div(tp, tp + fp)
            rec = _safe_div(tp, tp + fn)
            f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
            per_verdict[v_name] = {
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "support": support,
                "precision": _round4(prec),
                "recall": _round4(rec),
                "f1": _round4(f1),
            }
            sum_p += prec
            sum_r += rec
            sum_f1 += f1

        for cc in ALL_CLAIM_CLASSES:
            cs = per_class[cc]
            cs["accuracy"] = _round4(_safe_div(cs["correct"], cs["total"]))
            cs["mechanical_fvr"] = _round4(_safe_div(class_mech_fv[cc], class_mech_invalid[cc]))
            cs["overall_fvr"] = _round4(_safe_div(cs["false_verified"], class_non_ver[cc]))
            cs["frr"] = _round4(_safe_div(cs["false_rejected"], class_ver_gt[cc]))

        regimes_out = [regime_map[k] for k in sorted(regime_map.keys())]

        return {
            "schema_version": SCHEMA_VERSION,
            "implementation": impl_name,
            "bundle_id": bundle.get("bundle_id", ""),
            "seed": bundle.get("seed", 0),
            "total_claims": len(claims),
            "correct_claims": correct,
            "accuracy": _round4(_safe_div(correct, len(claims))),
            "macro_precision": _round4(sum_p / len(ALL_VERDICTS)),
            "macro_recall": _round4(sum_r / len(ALL_VERDICTS)),
            "macro_f1": _round4(sum_f1 / len(ALL_VERDICTS)),
            "mechanical_fvr": _round4(_safe_div(mech_fv, mech_invalid)),
            "mechanical_fv_count": mech_fv,
            "mechanical_invalid_total": mech_invalid,
            "overall_fvr": _round4(_safe_div(overall_fv, non_ver_total)),
            "overall_fv_count": overall_fv,
            "non_verified_total": non_ver_total,
            "frr": _round4(_safe_div(fr_count, ver_gt)),
            "fr_count": fr_count,
            "verified_ground_truth": ver_gt,
            "elapsed_ms": _round4(elapsed_ms),
            "throughput_claims_per_sec": _round4(throughput),
            "audit_merkle_root": root,
            "confusion_matrix": cm,
            "per_verdict_metrics": per_verdict,
            "per_claim_class": per_class,
            "negative_regimes": regimes_out,
            "error_cases": error_cases,
            "results": results,
        }

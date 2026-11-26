# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation

"""Deterministic calc_check verifier (1:1 parity with Go verifier)."""

from __future__ import annotations

from typing import Any

from .expr import (
    EXPR_ERR_DOMAIN,
    EXPR_ERR_SYNTAX,
    EXPR_ERR_UNDEFINED_VAR,
    ExprError,
    eval_expression,
)
from .types import (
    REASON_CALC_MISMATCH,
    REASON_HUMAN_REVIEW_REQUIRED,
    REASON_INVALID_EXPRESSION,
    REASON_MATH_DOMAIN_ERROR,
    REASON_MISSING_CALC_FIELDS,
    REASON_MISSING_PAYLOAD,
    REASON_MISSING_UNIT,
    REASON_OK_CALC,
    REASON_UNDEFINED_VARIABLE,
    REASON_UNIT_MISMATCH,
    VERDICT_INCONCLUSIVE,
    VERDICT_REFUTED,
    VERDICT_UNSUPPORTED,
    VERDICT_VERIFIED,
    format_canonical_float,
    make_result,
)


def verify_calculation(claim: dict[str, Any]) -> dict[str, Any]:
    c = claim.get("calculation")
    if not isinstance(c, dict):
        return make_result(claim, VERDICT_UNSUPPORTED, REASON_MISSING_PAYLOAD, "calculation payload missing")
    if c.get("review_scope", "") in ("external_domain", "subjective_judgment"):
        return make_result(
            claim,
            VERDICT_INCONCLUSIVE,
            REASON_HUMAN_REVIEW_REQUIRED,
            "calculation requires external domain or subjective human review",
        )
    expr = c.get("expression", "")
    has_claimed = bool(c.get("has_claimed_value", False))
    if not expr.strip() or not has_claimed:
        return make_result(
            claim,
            VERDICT_UNSUPPORTED,
            REASON_MISSING_CALC_FIELDS,
            "calculation missing expression or claimed_value",
        )
    exp_unit = str(c.get("expected_unit", "")).strip().lower()
    clm_unit = str(c.get("claimed_unit", "")).strip().lower()
    if exp_unit and not clm_unit:
        return make_result(claim, VERDICT_UNSUPPORTED, REASON_MISSING_UNIT, "calculation missing claimed_unit")
    if exp_unit and clm_unit and exp_unit != clm_unit:
        return make_result(
            claim,
            VERDICT_REFUTED,
            REASON_UNIT_MISMATCH,
            f'unit mismatch: expected "{exp_unit}", claimed "{clm_unit}"',
        )

    variables = c.get("variables") or {}
    exact_rational = bool(c.get("exact_rational", False))
    try:
        computed = eval_expression(expr, variables, exact_rational)
    except ExprError as err:
        if err.kind == EXPR_ERR_SYNTAX:
            return make_result(claim, VERDICT_UNSUPPORTED, REASON_INVALID_EXPRESSION, err.msg)
        if err.kind == EXPR_ERR_UNDEFINED_VAR:
            return make_result(claim, VERDICT_UNSUPPORTED, REASON_UNDEFINED_VARIABLE, err.msg)
        if err.kind == EXPR_ERR_DOMAIN:
            return make_result(claim, VERDICT_REFUTED, REASON_MATH_DOMAIN_ERROR, err.msg)
        return make_result(claim, VERDICT_UNSUPPORTED, REASON_INVALID_EXPRESSION, err.msg)

    claimed_val = float(c.get("claimed_value", 0.0))
    diff = abs(computed - claimed_val)
    tol = float(c.get("tolerance", 0.0))
    if tol < 0:
        tol = 0.0
    mode = str(c.get("tolerance_mode", "")).strip().lower()
    limit = tol * max(abs(computed), 1e-12) if mode == "rel" else tol
    comp_str = format_canonical_float(computed)
    claimed_str = format_canonical_float(claimed_val)
    if diff <= limit:
        return make_result(
            claim,
            VERDICT_VERIFIED,
            REASON_OK_CALC,
            f"computed {comp_str} matches claimed {claimed_str} within tolerance",
            comp_str,
        )
    return make_result(
        claim,
        VERDICT_REFUTED,
        REASON_CALC_MISMATCH,
        f"computed {comp_str} differs from claimed {claimed_str} by {format_canonical_float(diff)} (limit {format_canonical_float(limit)})",
        comp_str,
    )

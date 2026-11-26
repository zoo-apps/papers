# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation

"""Deterministic code_result_check verifier (1:1 parity with Go verifier)."""

from __future__ import annotations

import math
from typing import Any

from .expr import eval_expression
from .types import (
    REASON_ARTIFACT_HASH_MISMATCH,
    REASON_CI_TOO_WIDE,
    REASON_CI_UNDERESTIMATED,
    REASON_CODE_OUTPUT_MISMATCH,
    REASON_HUMAN_REVIEW_REQUIRED,
    REASON_INSUFFICIENT_SAMPLES,
    REASON_INVALID_CODE_INPUT,
    REASON_INVALID_SHA256_FORMAT,
    REASON_MEAN_OUTSIDE_CI,
    REASON_MISSING_ARTIFACT_PAYLOAD,
    REASON_MISSING_CODE_MODE,
    REASON_MISSING_PAYLOAD,
    REASON_OK_ARTIFACT_HASH,
    REASON_OK_CODE_EVAL,
    REASON_OK_STATISTICAL_INTERVAL,
    REASON_STOCHASTIC_REQUIRES_BOUNDS,
    REASON_UNKNOWN_CODE_OP,
    VERDICT_INCONCLUSIVE,
    VERDICT_REFUTED,
    VERDICT_UNSUPPORTED,
    VERDICT_VERIFIED,
    canonical_json,
    format_canonical_float,
    is_valid_hex_sha256,
    make_result,
    sha256_hex,
)

_KNOWN_OPS = {
    "sha256_canonical",
    "merkle_root",
    "bitdelta_scale",
    "trimmed_mean",
    "linear_reward",
    "sortition_check",
    "eval_expr",
}


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _to_float_list(raw: Any) -> list[float] | None:
    if not isinstance(raw, list):
        return None
    out: list[float] = []
    for item in raw:
        if not _is_number(item):
            return None
        out.append(float(item))
    return out


def _run_deterministic_op(prog: dict[str, Any]) -> Any:
    op = str(prog.get("op", "")).strip()
    inputs = prog.get("inputs")
    if inputs is None:
        inputs = {}
    if not isinstance(inputs, dict):
        raise ValueError("inputs must be an object")

    if op == "sha256_canonical":
        return sha256_hex(canonical_json(inputs))

    if op == "merkle_root":
        leaves = inputs.get("leaves")
        if not isinstance(leaves, list) or not leaves or not all(isinstance(x, str) for x in leaves):
            raise ValueError("merkle_root requires non-empty string array leaves")
        level = [sha256_hex(x.encode("utf-8")) for x in leaves]
        while len(level) > 1:
            nxt: list[str] = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                nxt.append(sha256_hex(f"{left}:{right}".encode("utf-8")))
            level = nxt
        return level[0]

    if op == "bitdelta_scale":
        wb = _to_float_list(inputs.get("w_base"))
        wf = _to_float_list(inputs.get("w_fine"))
        if wb is None or wf is None or not wb or len(wb) != len(wf):
            raise ValueError("bitdelta_scale requires equal-length non-empty w_base and w_fine")
        return sum(abs(wf[i] - wb[i]) for i in range(len(wb))) / len(wb)

    if op == "trimmed_mean":
        raw_vecs = inputs.get("vectors")
        trim_k_raw = inputs.get("trim_k")
        if not isinstance(raw_vecs, list) or not raw_vecs:
            raise ValueError("trimmed_mean requires non-empty vectors")
        if not _is_number(trim_k_raw) or float(trim_k_raw) < 0:
            raise ValueError("trimmed_mean requires non-negative trim_k")
        trim_k = int(float(trim_k_raw))
        vecs: list[list[float]] = []
        dim = -1
        for i, rv in enumerate(raw_vecs):
            vec = _to_float_list(rv)
            if vec is None or not vec:
                raise ValueError(f"invalid vector at index {i}")
            if dim < 0:
                dim = len(vec)
            elif len(vec) != dim:
                raise ValueError("mismatched vector dimensions")
            vecs.append(vec)
        if 2 * trim_k >= len(vecs):
            raise ValueError("trim_k too large for vector count")
        out: list[float] = []
        for d in range(dim):
            col = sorted(v[d] for v in vecs)
            trimmed = col[trim_k : len(col) - trim_k]
            out.append(sum(trimmed) / len(trimmed))
        return out

    if op == "linear_reward":
        req = ("phi", "fee", "share", "subsidy", "weight", "total_weight")
        if any(not _is_number(inputs.get(k)) for k in req) or float(inputs["total_weight"]) <= 0:
            raise ValueError("linear_reward requires numeric phi, fee, share, subsidy, weight, total_weight>0")
        phi = float(inputs["phi"])
        fee = float(inputs["fee"])
        share = float(inputs["share"])
        subsidy = float(inputs["subsidy"])
        w = float(inputs["weight"])
        w_tot = float(inputs["total_weight"])
        return (1.0 - phi) * fee * share + subsidy * (w / w_tot)

    if op == "sortition_check":
        seed = inputs.get("seed")
        op_id = inputs.get("operator_id")
        n_raw = inputs.get("committee_size")
        N_raw = inputs.get("population_size")
        if (
            not isinstance(seed, str)
            or not isinstance(op_id, str)
            or not _is_number(n_raw)
            or not _is_number(N_raw)
        ):
            raise ValueError("sortition_check requires seed, operator_id, 0<=committee_size<=population_size")
        n_val = int(float(n_raw))
        N_val = int(float(N_raw))
        if N_val <= 0 or n_val < 0 or n_val > N_val:
            raise ValueError("sortition_check requires seed, operator_id, 0<=committee_size<=population_size")
        digest_hex = sha256_hex(f"{seed}|{op_id}".encode("utf-8"))
        h_int = int(digest_hex, 16)
        return h_int * N_val < (1 << 256) * n_val

    if op == "eval_expr":
        expr_str = inputs.get("expression")
        if not isinstance(expr_str, str) or not expr_str.strip():
            raise ValueError("eval_expr requires non-empty expression")
        raw_vars = inputs.get("variables")
        vars_map: dict[str, float] = {}
        if isinstance(raw_vars, dict):
            for k, val in raw_vars.items():
                if _is_number(val):
                    vars_map[k] = float(val)
        return eval_expression(expr_str, vars_map, False)

    raise ValueError(f'unknown op "{op}"')


def _outputs_match(computed: Any, expected: Any, tol: float) -> bool:
    if _is_number(computed):
        if _is_number(expected):
            t = tol if tol > 0 else 1e-6
            return abs(float(computed) - float(expected)) <= t
        return False
    cf_list = _to_float_list(computed)
    if cf_list is not None:
        ef_list = _to_float_list(expected)
        if ef_list is not None and len(cf_list) == len(ef_list):
            t = tol if tol > 0 else 1e-6
            return all(abs(cf_list[i] - ef_list[i]) <= t for i in range(len(cf_list)))
        return False
    return canonical_json(computed) == canonical_json(expected)


def _format_output_value(v: Any) -> str:
    if _is_number(v):
        return format_canonical_float(float(v))
    return canonical_json(v).decode("utf-8")


def verify_code_result(claim: dict[str, Any]) -> dict[str, Any]:
    c = claim.get("code_result")
    if not isinstance(c, dict):
        return make_result(claim, VERDICT_UNSUPPORTED, REASON_MISSING_PAYLOAD, "code_result payload missing")
    if c.get("review_scope", "") in ("external_domain", "subjective_judgment"):
        return make_result(
            claim,
            VERDICT_INCONCLUSIVE,
            REASON_HUMAN_REVIEW_REQUIRED,
            "code result requires external domain or subjective human review",
        )
    mode = str(c.get("mode", ""))
    declared_sha = str(c.get("declared_sha256", ""))
    if c.get("stochastic", False) and mode != "statistical_interval" and not declared_sha.strip():
        return make_result(
            claim,
            VERDICT_UNSUPPORTED,
            REASON_STOCHASTIC_REQUIRES_BOUNDS,
            "stochastic benchmark lacks declared statistical interval bounds",
        )

    if mode == "deterministic_eval":
        prog = c.get("program")
        if not isinstance(prog, dict) or not str(prog.get("op", "")).strip():
            return make_result(
                claim,
                VERDICT_UNSUPPORTED,
                REASON_INVALID_CODE_INPUT,
                "deterministic_eval requires program.op",
            )
        op = str(prog.get("op", ""))
        if op not in _KNOWN_OPS:
            return make_result(
                claim,
                VERDICT_UNSUPPORTED,
                REASON_UNKNOWN_CODE_OP,
                f"unknown deterministic kernel op: {op}",
            )
        try:
            out = _run_deterministic_op(prog)
        except Exception as exc:  # noqa: BLE001
            return make_result(claim, VERDICT_UNSUPPORTED, REASON_INVALID_CODE_INPUT, str(exc))
        out_str = _format_output_value(out)
        ev_sha = sha256_hex(out_str.encode("utf-8"))
        tol = float(c.get("tolerance", 0.0) or 0.0)
        expected = c.get("expected_output")
        if _outputs_match(out, expected, tol):
            return make_result(
                claim,
                VERDICT_VERIFIED,
                REASON_OK_CODE_EVAL,
                "deterministic kernel output matches expected_output",
                out_str,
                ev_sha,
            )
        return make_result(
            claim,
            VERDICT_REFUTED,
            REASON_CODE_OUTPUT_MISMATCH,
            f"deterministic kernel output {out_str} contradicts expected_output {_format_output_value(expected)}",
            out_str,
            ev_sha,
        )

    if mode == "artifact_hash":
        payload = c.get("artifact_payload", "")
        if not payload:
            return make_result(
                claim,
                VERDICT_UNSUPPORTED,
                REASON_MISSING_ARTIFACT_PAYLOAD,
                "artifact_hash mode requires non-empty artifact_payload",
            )
        actual_sha = sha256_hex(payload.encode("utf-8"))
        if not is_valid_hex_sha256(declared_sha):
            return make_result(
                claim,
                VERDICT_UNSUPPORTED,
                REASON_INVALID_SHA256_FORMAT,
                "declared_sha256 is not a valid 64-char lowercase hex digest",
                "",
                actual_sha,
            )
        if actual_sha == declared_sha:
            return make_result(
                claim,
                VERDICT_VERIFIED,
                REASON_OK_ARTIFACT_HASH,
                "artifact payload SHA-256 matches declared_sha256",
                actual_sha,
                actual_sha,
            )
        return make_result(
            claim,
            VERDICT_REFUTED,
            REASON_ARTIFACT_HASH_MISMATCH,
            "artifact payload SHA-256 contradicts declared_sha256",
            actual_sha,
            actual_sha,
        )

    if mode == "statistical_interval":
        samples = c.get("samples") or []
        has_mean = bool(c.get("has_claimed_mean", False))
        ci_hw = float(c.get("ci_halfwidth", 0.0) or 0.0)
        if len(samples) < 3 or not has_mean or ci_hw <= 0:
            return make_result(
                claim,
                VERDICT_UNSUPPORTED,
                REASON_INSUFFICIENT_SAMPLES,
                "statistical_interval requires >=3 samples, claimed_mean, and ci_halfwidth > 0",
            )
        vals = [float(x) for x in samples]
        mean = sum(vals) / len(vals)
        ss = sum((x - mean) ** 2 for x in vals)
        std = math.sqrt(ss / (len(vals) - 1))
        h95 = 1.96 * std / math.sqrt(len(vals))
        mean_str = format_canonical_float(mean)
        claimed_mean = float(c.get("claimed_mean", 0.0))
        if abs(claimed_mean - mean) > ci_hw:
            return make_result(
                claim,
                VERDICT_REFUTED,
                REASON_MEAN_OUTSIDE_CI,
                f"sample mean {mean_str} lies outside claimed interval {format_canonical_float(claimed_mean)} +/- {format_canonical_float(ci_hw)}",
                mean_str,
            )
        if ci_hw < h95 * (1.0 - 1e-6):
            return make_result(
                claim,
                VERDICT_REFUTED,
                REASON_CI_UNDERESTIMATED,
                f"declared ci_halfwidth {format_canonical_float(ci_hw)} is narrower than 95% halfwidth {format_canonical_float(h95)}",
                mean_str,
            )
        max_reasonable = max(abs(mean) * 0.25, 1.0)
        if ci_hw > max_reasonable:
            return make_result(
                claim,
                VERDICT_INCONCLUSIVE,
                REASON_CI_TOO_WIDE,
                f"declared ci_halfwidth {format_canonical_float(ci_hw)} exceeds vacuity threshold {format_canonical_float(max_reasonable)}",
                mean_str,
            )
        return make_result(
            claim,
            VERDICT_VERIFIED,
            REASON_OK_STATISTICAL_INTERVAL,
            f"sample mean {mean_str} verified within valid 95% CI +/- {format_canonical_float(ci_hw)}",
            mean_str,
        )

    return make_result(
        claim,
        VERDICT_UNSUPPORTED,
        REASON_MISSING_CODE_MODE,
        f'unsupported or missing code_result mode: "{mode}"',
    )

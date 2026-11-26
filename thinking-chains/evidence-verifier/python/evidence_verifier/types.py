# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation

"""Core constants, canonical JSON, number formatting, and Merkle commitments."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

SCHEMA_VERSION = "1.0.0"

DOMAIN_RESULT_PREFIX = "zoo:evidence-verifier:v1:result:"
DOMAIN_MERKLE_EMPTY_PREFIX = "zoo:evidence-verifier:v1:merkle:empty"
DOMAIN_MERKLE_NODE_PREFIX = "zoo:evidence-verifier:v1:merkle:node:"

VERDICT_VERIFIED = "VERIFIED_REPRODUCIBLE"
VERDICT_REFUTED = "REFUTED_CONTRADICTION"
VERDICT_UNSUPPORTED = "UNSUPPORTED_INSUFFICIENT_EVIDENCE"
VERDICT_INCONCLUSIVE = "INCONCLUSIVE_NEEDS_HUMAN_REVIEW"

ALL_VERDICTS = (
    VERDICT_VERIFIED,
    VERDICT_REFUTED,
    VERDICT_UNSUPPORTED,
    VERDICT_INCONCLUSIVE,
)

CLASS_CITATION = "citation_check"
CLASS_CALCULATION = "calc_check"
CLASS_CODE_RESULT = "code_result_check"
CLASS_REASONING_CHAIN = "reasoning_chain_check"

ALL_CLAIM_CLASSES = (
    CLASS_CITATION,
    CLASS_CALCULATION,
    CLASS_CODE_RESULT,
    CLASS_REASONING_CHAIN,
)

# Deterministic reason codes (1:1 parity with Go verifier).
REASON_OK_CITATION = "OK_CITATION_VERIFIED"
REASON_OK_CALC = "OK_CALC_VERIFIED"
REASON_OK_CODE_EVAL = "OK_CODE_EVAL_VERIFIED"
REASON_OK_ARTIFACT_HASH = "OK_ARTIFACT_HASH_VERIFIED"
REASON_OK_STATISTICAL_INTERVAL = "OK_STATISTICAL_INTERVAL_VERIFIED"
REASON_OK_REASONING_CHAIN = "OK_REASONING_CHAIN_VERIFIED"

REASON_SELF_VALIDATION = "ERR_CONSTITUTIONAL_SELF_VALIDATION"
REASON_FORBIDDEN_GOV_ACTION = "ERR_CONSTITUTIONAL_FORBIDDEN_ACTION"
REASON_HUMAN_REVIEW_REQUIRED = "ERR_HUMAN_REVIEW_REQUIRED"
REASON_UNKNOWN_CLAIM_CLASS = "ERR_UNKNOWN_CLAIM_CLASS"
REASON_MISSING_PAYLOAD = "ERR_MISSING_PAYLOAD"
REASON_MISSING_CITATION_FIELDS = "ERR_MISSING_CITATION_FIELDS"
REASON_INVALID_SOURCE_PATH = "ERR_INVALID_SOURCE_PATH"
REASON_SOURCE_NOT_FOUND = "ERR_SOURCE_NOT_FOUND"
REASON_INVALID_SHA256_FORMAT = "ERR_INVALID_SHA256_FORMAT"
REASON_SOURCE_SHA256_MISMATCH = "ERR_SOURCE_SHA256_MISMATCH"
REASON_SECTION_NOT_FOUND = "ERR_SECTION_NOT_FOUND"
REASON_NUMERIC_MISMATCH = "ERR_NUMERIC_MISMATCH"
REASON_POLARITY_REVERSAL = "ERR_POLARITY_REVERSAL"
REASON_QUOTE_NUMERIC_ALTERATION = "ERR_QUOTE_NUMERIC_ALTERATION"
REASON_QUOTE_POLARITY_ALT = "ERR_QUOTE_POLARITY_ALTERATION"
REASON_PARAPHRASE_HUMAN_REVIEW = "ERR_PARAPHRASE_NEEDS_HUMAN_REVIEW"
REASON_QUOTE_NOT_FOUND = "ERR_QUOTE_NOT_FOUND"

REASON_MISSING_CALC_FIELDS = "ERR_MISSING_CALC_FIELDS"
REASON_MISSING_UNIT = "ERR_MISSING_UNIT"
REASON_UNIT_MISMATCH = "ERR_UNIT_MISMATCH"
REASON_INVALID_EXPRESSION = "ERR_INVALID_EXPRESSION"
REASON_UNDEFINED_VARIABLE = "ERR_UNDEFINED_VARIABLE"
REASON_MATH_DOMAIN_ERROR = "ERR_MATH_DOMAIN_ERROR"
REASON_CALC_MISMATCH = "ERR_CALC_MISMATCH"

REASON_MISSING_CODE_MODE = "ERR_MISSING_CODE_MODE"
REASON_UNKNOWN_CODE_OP = "ERR_UNKNOWN_CODE_OP"
REASON_INVALID_CODE_INPUT = "ERR_INVALID_CODE_INPUT"
REASON_CODE_OUTPUT_MISMATCH = "ERR_CODE_OUTPUT_MISMATCH"
REASON_MISSING_ARTIFACT_PAYLOAD = "ERR_MISSING_ARTIFACT_PAYLOAD"
REASON_ARTIFACT_HASH_MISMATCH = "ERR_ARTIFACT_HASH_MISMATCH"
REASON_INSUFFICIENT_SAMPLES = "ERR_INSUFFICIENT_SAMPLES"
REASON_MEAN_OUTSIDE_CI = "ERR_MEAN_OUTSIDE_CI"
REASON_CI_UNDERESTIMATED = "ERR_CI_UNDERESTIMATED"
REASON_CI_TOO_WIDE = "ERR_CI_TOO_WIDE"
REASON_STOCHASTIC_REQUIRES_BOUNDS = "ERR_STOCHASTIC_REQUIRES_INTERVAL"

REASON_EMPTY_REASONING_CHAIN = "ERR_EMPTY_REASONING_CHAIN"
REASON_DUPLICATE_STEP_ID = "ERR_DUPLICATE_STEP_ID"
REASON_MISSING_CONCLUSION = "ERR_MISSING_CONCLUSION_STEP"
REASON_PRIVATE_COT_FORBIDDEN = "ERR_PRIVATE_COT_FORBIDDEN"
REASON_REASONING_CYCLE = "ERR_REASONING_CYCLE"
REASON_DANGLING_PREMISE = "ERR_DANGLING_PREMISE"
REASON_REFUTED_PREMISE = "ERR_REFUTED_PREMISE"
REASON_UNVERIFIED_PREMISE = "ERR_UNVERIFIED_PREMISE"
REASON_INCONCLUSIVE_PREMISE = "ERR_INCONCLUSIVE_PREMISE"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_valid_hex_sha256(s: str) -> bool:
    if len(s) != 64:
        return False
    for ch in s:
        if not (("0" <= ch <= "9") or ("a" <= ch <= "f")):
            return False
    return True


def format_canonical_float(v: float) -> str:
    if math.isnan(v):
        return "NaN"
    if math.isinf(v):
        return "+Inf" if v > 0 else "-Inf"
    scale = 1e9
    if v >= 0:
        rounded = math.floor(v * scale + 0.5) / scale
    else:
        rounded = math.ceil(v * scale - 0.5) / scale
    if rounded == 0:
        rounded = 0.0
    s = f"{rounded:.9f}"
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    if s in ("-0", ""):
        return "0"
    return s


def _encode_go_json_string(s: str) -> str:
    # Match Go json.Marshal escaping (<, >, & escaped as \u003c, \u003e, \u0026).
    raw = json.dumps(s, ensure_ascii=False)
    return raw.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def canonical_json(v: Any) -> bytes:
    return _write_canonical(v).encode("utf-8")


def _write_canonical(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, str):
        return _encode_go_json_string(v)
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return format_canonical_float(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_write_canonical(x) for x in v) + "]"
    if isinstance(v, dict):
        items = []
        for k in sorted(v.keys()):
            items.append(f"{_encode_go_json_string(str(k))}:{_write_canonical(v[k])}")
        return "{" + ",".join(items) + "}"
    raise TypeError(f"unsupported canonical JSON type: {type(v)!r}")


def compute_result_digest(result: dict[str, Any]) -> str:
    payload_obj = {
        "claim_class": result["claim_class"],
        "claim_id": result["claim_id"],
        "computed_value": result["computed_value"],
        "detail": result["detail"],
        "evidence_sha256": result["evidence_sha256"],
        "reason_code": result["reason_code"],
        "schema_version": result["schema_version"],
        "verdict": result["verdict"],
    }
    canon = canonical_json(payload_obj)
    return sha256_hex(DOMAIN_RESULT_PREFIX.encode("utf-8") + canon)


def compute_audit_merkle_root(results: list[dict[str, Any]]) -> str:
    if not results:
        return sha256_hex(DOMAIN_MERKLE_EMPTY_PREFIX.encode("utf-8"))
    ordered = sorted(results, key=lambda r: r["claim_id"])
    level = [r.get("result_digest") or compute_result_digest(r) for r in ordered]
    while len(level) > 1:
        nxt: list[str] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(sha256_hex(f"{DOMAIN_MERKLE_NODE_PREFIX}{left}:{right}".encode("utf-8")))
        level = nxt
    return level[0]


def make_result(
    claim: dict[str, Any],
    verdict: str,
    reason_code: str,
    detail: str,
    computed_value: str = "",
    evidence_sha256: str = "",
) -> dict[str, Any]:
    res = {
        "schema_version": SCHEMA_VERSION,
        "claim_id": claim.get("claim_id", ""),
        "claim_class": claim.get("claim_class", ""),
        "verdict": verdict,
        "reason_code": reason_code,
        "detail": detail,
        "computed_value": computed_value,
        "evidence_sha256": evidence_sha256,
        "result_digest": "",
    }
    res["result_digest"] = compute_result_digest(res)
    return res

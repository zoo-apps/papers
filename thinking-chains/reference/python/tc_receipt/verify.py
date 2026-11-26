# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation and Contributors

"""Independent canonical receipt verifier and constitutional policy enforcement."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import CanonicalError, canonical_json, parse_strict_json
from .ed25519 import ed25519_verify
from .merkle import merkle_root

SCHEMA_VERSION = "zoo.thinking-chains.receipt.v1"
RESULT_DOMAIN_PREFIX = b"zoo.thinking-chains.result.v1:"
RECEIPT_DOMAIN_PREFIX = b"zoo.thinking-chains.receipt.v1\x00"
ATTESTATION_DOMAIN_PREFIX = b"zoo.thinking-chains.attestation.v1\x00"

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX128_RE = re.compile(r"^[0-9a-f]{128}$")
_ID_RE = re.compile(r"^[A-Za-z0-9._:/-]{2,128}$")

FORBIDDEN_COT_KEY_TOKENS = (
    "private_cot",
    "chain_of_thought",
    "internal_cot",
    "hidden_reasoning",
    "raw_thinking",
    "private_scratchpad",
    "thought_tokens",
    "internal_monologue",
    "reasoning_trace_private",
)

FORBIDDEN_PRIVATE_URI_PREFIXES = (
    "private://",
    "cot://",
    "internal-cot://",
    "hidden-cot://",
)

ALLOWED_TASK_TYPES = frozenset(
    {
        "math_verification",
        "code_synthesis",
        "corpus_retrieval",
        "benchmark_eval",
        "governance_advisory",
    }
)

ALLOWED_INFERENCE_TIERS = frozenset(
    {
        "tier1_deterministic_int8",
        "tier2_quorum",
        "tier2_attested_tee",
        "tier2_zkml",
    }
)

ALLOWED_EVIDENCE_MODES = frozenset(
    {
        "deterministic_recomputation",
        "quorum_signatures",
        "tee_attestation",
        "zkml_proof",
    }
)

ALLOWED_EVIDENCE_KINDS = frozenset(
    {
        "execution_trace_digest",
        "intermediate_artifact",
        "public_rationale_digest",
        "benchmark_log_digest",
        "prior_receipt_ref",
        "tee_quote_digest",
    }
)

ALLOWED_CHECK_TYPES = frozenset(
    {
        "deterministic_replay",
        "unit_test_suite",
        "hash_match",
        "schema_validation",
        "metric_threshold",
        "differential_parity",
    }
)

ALLOWED_RESULT_STATUSES = frozenset({"completed", "failed", "contested", "abstained"})

ALLOWED_PROPOSED_ACTION_SCOPES = frozenset(
    {
        "research_artifact",
        "advisory_recommendation",
        "benchmark_report",
        "model_delta_proposal",
    }
)

ALLOWED_VERIFIER_ROLES = frozenset(
    {
        "independent_verifier",
        "quorum_validator",
        "hardware_tee_verifier",
        "human_reviewer",
    }
)

ALLOWED_VERDICTS = frozenset({"VALID", "REJECT", "CONTESTED"})

TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "job_id",
        "nonce",
        "objective",
        "execution",
        "inputs",
        "authorized_tools",
        "public_evidence",
        "checks",
        "result",
        "provenance",
        "settlement",
        "attestations",
    }
)

OBJECTIVE_KEYS = frozenset(
    {
        "task_type",
        "summary",
        "objective_hash",
        "output_space_id",
        "governance_level",
        "recursion_depth",
        "max_recursion_depth",
    }
)

EXECUTION_KEYS = frozenset(
    {
        "executor_id",
        "model_id",
        "model_version",
        "model_spec_hash",
        "execution_profile_id",
        "inference_tier",
        "evidence_mode",
        "public_trace_only",
        "hardware_class",
    }
)

INPUT_KEYS = frozenset(
    {"artifact_id", "role", "uri", "media_type", "byte_length", "sha256"}
)

TOOL_KEYS = frozenset(
    {
        "seq",
        "tool_name",
        "tool_version",
        "deterministic",
        "args_sha256",
        "output_sha256",
        "wall_time_ms",
        "exit_code",
    }
)

EVIDENCE_KEYS = frozenset(
    {"evidence_id", "kind", "uri", "byte_length", "sha256", "public_only"}
)

CHECK_KEYS = frozenset(
    {
        "check_id",
        "check_type",
        "passed",
        "metric_name",
        "metric_bps",
        "threshold_bps",
        "verifier_cmd_sha256",
        "log_sha256",
    }
)

RESULT_KEYS = frozenset(
    {
        "status",
        "canonical_output_sha256",
        "output_byte_length",
        "finite_verdict",
        "quality_score_bps",
        "dissent_bps",
        "proposed_action_scope",
    }
)

PROVENANCE_KEYS = frozenset(
    {
        "hash_algorithm",
        "domain_separator",
        "inputs_root",
        "tools_root",
        "evidence_root",
        "checks_root",
        "result_digest",
        "provenance_root",
    }
)

SETTLEMENT_KEYS = frozenset(
    {
        "chain_id",
        "escrow_ref",
        "intent_id",
        "payer",
        "fee_units",
        "subsidy_eligible",
        "settled_at_height",
        "settled_at_unix",
        "treasury_spend_authorized",
        "voting_rules_modified",
    }
)

ATTESTATION_KEYS = frozenset(
    {
        "verifier_id",
        "verifier_role",
        "algorithm",
        "public_key_hex",
        "verdict",
        "attested_receipt_hash",
        "attested_at_unix",
        "signature_hex",
    }
)


class VerificationError(Exception):
    """Deterministic verification failure with standardized error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class VerificationResult:
    job_id: str
    canonical_receipt_hash: str
    provenance_root: str
    valid_attestation_count: int


def _is_int(val: Any) -> bool:
    return isinstance(val, int) and not isinstance(val, bool)


def _check_exact_keys(obj: Any, expected: frozenset[str], ctx: str) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise VerificationError("ERR_SCHEMA_VIOLATION", f"{ctx} must be a JSON object")
    keys = set(obj.keys())
    missing = expected - keys
    extra = keys - expected
    if missing:
        raise VerificationError(
            "ERR_SCHEMA_VIOLATION",
            f"{ctx} missing required keys: {sorted(missing)}",
        )
    if extra:
        raise VerificationError(
            "ERR_SCHEMA_VIOLATION",
            f"{ctx} contains unknown keys: {sorted(extra)}",
        )
    return obj


def _check_hex64(val: Any, ctx: str) -> str:
    if not isinstance(val, str) or not _HEX64_RE.match(val):
        raise VerificationError("ERR_SCHEMA_VIOLATION", f"{ctx} must be 64 lowercase hex chars")
    return val


def _check_hex128(val: Any, ctx: str) -> str:
    if not isinstance(val, str) or not _HEX128_RE.match(val):
        raise VerificationError("ERR_SCHEMA_VIOLATION", f"{ctx} must be 128 lowercase hex chars")
    return val


def _check_id(val: Any, ctx: str) -> str:
    if not isinstance(val, str) or not _ID_RE.match(val):
        raise VerificationError("ERR_SCHEMA_VIOLATION", f"{ctx} must be a valid identifier")
    return val


def _check_nonempty_str(val: Any, ctx: str, max_len: int) -> str:
    if not isinstance(val, str) or len(val) == 0 or len(val) > max_len:
        raise VerificationError(
            "ERR_SCHEMA_VIOLATION",
            f"{ctx} must be a non-empty string of length <= {max_len}",
        )
    return val


def _check_bool(val: Any, ctx: str) -> bool:
    if not isinstance(val, bool):
        raise VerificationError("ERR_SCHEMA_VIOLATION", f"{ctx} must be a boolean")
    return val


def _check_int_range(val: Any, ctx: str, lo: int, hi: int | None = None) -> int:
    if not _is_int(val):
        raise VerificationError("ERR_SCHEMA_VIOLATION", f"{ctx} must be an integer")
    if val < lo or (hi is not None and val > hi):
        raise VerificationError("ERR_SCHEMA_VIOLATION", f"{ctx} out of range [{lo}, {hi}]")
    return val


def _scan_private_cot(node: Any, path: str = "$") -> None:
    """Recursively reject any forbidden private chain-of-thought key anywhere in the JSON."""
    if isinstance(node, dict):
        for k, v in node.items():
            kl = k.lower()
            for token in FORBIDDEN_COT_KEY_TOKENS:
                if token in kl:
                    raise VerificationError(
                        "ERR_PRIVATE_COT_FORBIDDEN",
                        f"forbidden private chain-of-thought key {k!r} at {path}",
                    )
            _scan_private_cot(v, f"{path}.{k}")
    elif isinstance(node, list):
        for idx, item in enumerate(node):
            _scan_private_cot(item, f"{path}[{idx}]")


def compute_provenance(receipt: dict[str, Any]) -> dict[str, str]:
    """Deterministically reconstruct all section Merkle roots and the top-level provenance root."""
    inputs_root = merkle_root("inputs", [canonical_json(x) for x in receipt["inputs"]])
    tools_root = merkle_root("tools", [canonical_json(x) for x in receipt["authorized_tools"]])
    evidence_root = merkle_root(
        "evidence", [canonical_json(x) for x in receipt["public_evidence"]]
    )
    checks_root = merkle_root("checks", [canonical_json(x) for x in receipt["checks"]])
    result_digest = hashlib.sha256(
        RESULT_DOMAIN_PREFIX + canonical_json(receipt["result"])
    ).digest()
    prov_root = merkle_root(
        "provenance",
        [inputs_root, tools_root, evidence_root, checks_root, result_digest],
    )
    return {
        "hash_algorithm": "sha256",
        "domain_separator": SCHEMA_VERSION,
        "inputs_root": inputs_root.hex(),
        "tools_root": tools_root.hex(),
        "evidence_root": evidence_root.hex(),
        "checks_root": checks_root.hex(),
        "result_digest": result_digest.hex(),
        "provenance_root": prov_root.hex(),
    }


def unsigned_receipt_payload(receipt: dict[str, Any]) -> dict[str, Any]:
    """Extract the 12 core top-level receipt fields (excluding attestations)."""
    return {k: v for k, v in receipt.items() if k != "attestations"}


def canonical_receipt_hash(receipt: dict[str, Any]) -> str:
    """Compute the domain-separated SHA-256 canonical receipt hash (hex)."""
    payload = unsigned_receipt_payload(receipt)
    return hashlib.sha256(RECEIPT_DOMAIN_PREFIX + canonical_json(payload)).hexdigest()


def attestation_message(
    receipt_hash_hex: str,
    verifier_id: str,
    verifier_role: str,
    verdict: str,
    attested_at_unix: int,
) -> bytes:
    """Build the domain-separated signing message for an Ed25519 verifier attestation."""
    return (
        ATTESTATION_DOMAIN_PREFIX
        + receipt_hash_hex.encode("ascii")
        + b"\x00"
        + verifier_id.encode("utf-8")
        + b"\x00"
        + verifier_role.encode("utf-8")
        + b"\x00"
        + verdict.encode("ascii")
        + b"\x00"
        + str(attested_at_unix).encode("ascii")
    )


def load_policy(path: str | Path) -> dict[str, Any]:
    """Load a policy bundle using strict JSON parsing."""
    raw = Path(path).read_bytes()
    try:
        policy = parse_strict_json(raw)
    except CanonicalError as exc:
        raise VerificationError(exc.code, exc.message) from exc
    if not isinstance(policy, dict):
        raise VerificationError("ERR_SCHEMA_VIOLATION", "policy bundle must be a JSON object")
    if "authorized_profiles" not in policy or "trusted_verifiers" not in policy:
        raise VerificationError(
            "ERR_SCHEMA_VIOLATION",
            "policy must define authorized_profiles and trusted_verifiers",
        )
    return policy


def verify_receipt_bytes(raw: bytes | str, policy: dict[str, Any]) -> VerificationResult:
    """Parse raw JSON strictly and run complete independent receipt verification."""
    try:
        parsed = parse_strict_json(raw)
    except CanonicalError as exc:
        raise VerificationError(exc.code, exc.message) from exc
    return verify_receipt(parsed, policy)


def verify_receipt(receipt: Any, policy: dict[str, Any]) -> VerificationResult:
    """Run all schema, privacy, constitutional, policy, provenance, and Ed25519 checks."""
    # 1. Recursive private-CoT scan BEFORE schema check so explicit CoT injection reports ERR_PRIVATE_COT_FORBIDDEN.
    _scan_private_cot(receipt)

    # 2. Top-level exact key check.
    rec = _check_exact_keys(receipt, TOP_LEVEL_KEYS, "receipt")
    if rec["schema_version"] != SCHEMA_VERSION:
        raise VerificationError(
            "ERR_SCHEMA_VIOLATION",
            f"unsupported schema_version: {rec['schema_version']!r}",
        )
    job_id = _check_id(rec["job_id"], "job_id")
    _check_hex64(rec["nonce"], "nonce")

    # 3. Objective validation.
    obj = _check_exact_keys(rec["objective"], OBJECTIVE_KEYS, "objective")
    if obj["task_type"] not in ALLOWED_TASK_TYPES:
        raise VerificationError("ERR_SCHEMA_VIOLATION", f"invalid task_type: {obj['task_type']!r}")
    _check_nonempty_str(obj["summary"], "objective.summary", 512)
    _check_hex64(obj["objective_hash"], "objective.objective_hash")
    _check_id(obj["output_space_id"], "objective.output_space_id")
    _check_int_range(obj["governance_level"], "objective.governance_level", 0, 5)
    rec_depth = _check_int_range(obj["recursion_depth"], "objective.recursion_depth", 0)
    max_rec_depth = _check_int_range(obj["max_recursion_depth"], "objective.max_recursion_depth", 0)
    if rec_depth > max_rec_depth:
        raise VerificationError(
            "ERR_RECURSION_BUDGET_EXCEEDED",
            f"recursion_depth ({rec_depth}) exceeds objective.max_recursion_depth ({max_rec_depth})",
        )

    # 4. Execution validation & private-CoT boundary check.
    exe = _check_exact_keys(rec["execution"], EXECUTION_KEYS, "execution")
    executor_id = _check_id(exe["executor_id"], "execution.executor_id")
    model_id = _check_id(exe["model_id"], "execution.model_id")
    _check_id(exe["model_version"], "execution.model_version")
    model_spec_hash = _check_hex64(exe["model_spec_hash"], "execution.model_spec_hash")
    profile_id = _check_id(exe["execution_profile_id"], "execution.execution_profile_id")
    inference_tier = exe["inference_tier"]
    if inference_tier not in ALLOWED_INFERENCE_TIERS:
        raise VerificationError(
            "ERR_SCHEMA_VIOLATION", f"invalid inference_tier: {inference_tier!r}"
        )
    evidence_mode = exe["evidence_mode"]
    if evidence_mode not in ALLOWED_EVIDENCE_MODES:
        raise VerificationError(
            "ERR_SCHEMA_VIOLATION", f"invalid evidence_mode: {evidence_mode!r}"
        )
    public_trace_only = _check_bool(exe["public_trace_only"], "execution.public_trace_only")
    if not public_trace_only:
        raise VerificationError(
            "ERR_PRIVATE_COT_FORBIDDEN",
            "execution.public_trace_only must be true; private internal CoT is prohibited",
        )
    _check_id(exe["hardware_class"], "execution.hardware_class")

    # 5. Inputs validation.
    inputs = rec["inputs"]
    if not isinstance(inputs, list) or len(inputs) == 0:
        raise VerificationError("ERR_SCHEMA_VIOLATION", "inputs must be a non-empty array")
    for idx, item in enumerate(inputs):
        inp = _check_exact_keys(item, INPUT_KEYS, f"inputs[{idx}]")
        _check_id(inp["artifact_id"], f"inputs[{idx}].artifact_id")
        _check_id(inp["role"], f"inputs[{idx}].role")
        _check_nonempty_str(inp["uri"], f"inputs[{idx}].uri", 512)
        _check_nonempty_str(inp["media_type"], f"inputs[{idx}].media_type", 128)
        _check_int_range(inp["byte_length"], f"inputs[{idx}].byte_length", 0)
        _check_hex64(inp["sha256"], f"inputs[{idx}].sha256")

    # 6. Authorized tools validation.
    tools = rec["authorized_tools"]
    if not isinstance(tools, list):
        raise VerificationError("ERR_SCHEMA_VIOLATION", "authorized_tools must be an array")
    for idx, item in enumerate(tools):
        tl = _check_exact_keys(item, TOOL_KEYS, f"authorized_tools[{idx}]")
        seq = _check_int_range(tl["seq"], f"authorized_tools[{idx}].seq", 0)
        if seq != idx:
            raise VerificationError(
                "ERR_SCHEMA_VIOLATION",
                f"authorized_tools[{idx}].seq must equal {idx}, got {seq}",
            )
        _check_id(tl["tool_name"], f"authorized_tools[{idx}].tool_name")
        _check_id(tl["tool_version"], f"authorized_tools[{idx}].tool_version")
        _check_bool(tl["deterministic"], f"authorized_tools[{idx}].deterministic")
        _check_hex64(tl["args_sha256"], f"authorized_tools[{idx}].args_sha256")
        _check_hex64(tl["output_sha256"], f"authorized_tools[{idx}].output_sha256")
        _check_int_range(tl["wall_time_ms"], f"authorized_tools[{idx}].wall_time_ms", 0)
        if not _is_int(tl["exit_code"]):
            raise VerificationError(
                "ERR_SCHEMA_VIOLATION", f"authorized_tools[{idx}].exit_code must be an integer"
            )

    # 7. Public evidence validation & private-CoT URI/flag guard.
    evidence = rec["public_evidence"]
    if not isinstance(evidence, list) or len(evidence) == 0:
        raise VerificationError("ERR_SCHEMA_VIOLATION", "public_evidence must be a non-empty array")
    for idx, item in enumerate(evidence):
        ev = _check_exact_keys(item, EVIDENCE_KEYS, f"public_evidence[{idx}]")
        _check_id(ev["evidence_id"], f"public_evidence[{idx}].evidence_id")
        if ev["kind"] not in ALLOWED_EVIDENCE_KINDS:
            raise VerificationError(
                "ERR_SCHEMA_VIOLATION", f"invalid public_evidence[{idx}].kind: {ev['kind']!r}"
            )
        uri = _check_nonempty_str(ev["uri"], f"public_evidence[{idx}].uri", 512)
        uri_lower = uri.lower()
        for prefix in FORBIDDEN_PRIVATE_URI_PREFIXES:
            if uri_lower.startswith(prefix):
                raise VerificationError(
                    "ERR_PRIVATE_COT_FORBIDDEN",
                    f"public_evidence[{idx}].uri references forbidden private CoT URI: {uri!r}",
                )
        if "private_cot" in uri_lower or "internal_cot" in uri_lower:
            raise VerificationError(
                "ERR_PRIVATE_COT_FORBIDDEN",
                f"public_evidence[{idx}].uri references private CoT path: {uri!r}",
            )
        _check_int_range(ev["byte_length"], f"public_evidence[{idx}].byte_length", 0)
        _check_hex64(ev["sha256"], f"public_evidence[{idx}].sha256")
        pub_only = _check_bool(ev["public_only"], f"public_evidence[{idx}].public_only")
        if not pub_only:
            raise VerificationError(
                "ERR_PRIVATE_COT_FORBIDDEN",
                f"public_evidence[{idx}].public_only must be true",
            )

    # 8. Verifiable checks validation.
    checks = rec["checks"]
    if not isinstance(checks, list) or len(checks) == 0:
        raise VerificationError("ERR_SCHEMA_VIOLATION", "checks must be a non-empty array")
    for idx, item in enumerate(checks):
        chk = _check_exact_keys(item, CHECK_KEYS, f"checks[{idx}]")
        _check_id(chk["check_id"], f"checks[{idx}].check_id")
        if chk["check_type"] not in ALLOWED_CHECK_TYPES:
            raise VerificationError(
                "ERR_SCHEMA_VIOLATION", f"invalid checks[{idx}].check_type: {chk['check_type']!r}"
            )
        _check_bool(chk["passed"], f"checks[{idx}].passed")
        _check_id(chk["metric_name"], f"checks[{idx}].metric_name")
        _check_int_range(chk["metric_bps"], f"checks[{idx}].metric_bps", 0, 10000)
        _check_int_range(chk["threshold_bps"], f"checks[{idx}].threshold_bps", 0, 10000)
        _check_hex64(chk["verifier_cmd_sha256"], f"checks[{idx}].verifier_cmd_sha256")
        _check_hex64(chk["log_sha256"], f"checks[{idx}].log_sha256")

    # 9. Result & Constitutional action-scope guard.
    res = _check_exact_keys(rec["result"], RESULT_KEYS, "result")
    if res["status"] not in ALLOWED_RESULT_STATUSES:
        raise VerificationError("ERR_SCHEMA_VIOLATION", f"invalid result.status: {res['status']!r}")
    _check_hex64(res["canonical_output_sha256"], "result.canonical_output_sha256")
    output_byte_length = _check_int_range(res["output_byte_length"], "result.output_byte_length", 0)
    _check_id(res["finite_verdict"], "result.finite_verdict")
    _check_int_range(res["quality_score_bps"], "result.quality_score_bps", 0, 10000)
    _check_int_range(res["dissent_bps"], "result.dissent_bps", 0, 10000)
    scope = res["proposed_action_scope"]
    if not isinstance(scope, str) or scope not in ALLOWED_PROPOSED_ACTION_SCOPES:
        raise VerificationError(
            "ERR_CONSTITUTIONAL_AUTHORITY_ESCALATION",
            f"disallowed result.proposed_action_scope: {scope!r} (AI agents may advise, not enact)",
        )

    # 10. Settlement & Constitutional guards.
    sett = _check_exact_keys(rec["settlement"], SETTLEMENT_KEYS, "settlement")
    _check_id(sett["chain_id"], "settlement.chain_id")
    _check_nonempty_str(sett["escrow_ref"], "settlement.escrow_ref", 256)
    _check_hex64(sett["intent_id"], "settlement.intent_id")
    _check_id(sett["payer"], "settlement.payer")
    _check_int_range(sett["fee_units"], "settlement.fee_units", 0)
    subsidy_eligible = _check_bool(sett["subsidy_eligible"], "settlement.subsidy_eligible")
    _check_int_range(sett["settled_at_height"], "settlement.settled_at_height", 0)
    _check_int_range(sett["settled_at_unix"], "settlement.settled_at_unix", 1)
    treasury_auth = _check_bool(
        sett["treasury_spend_authorized"], "settlement.treasury_spend_authorized"
    )
    if treasury_auth:
        raise VerificationError(
            "ERR_CONSTITUTIONAL_TREASURY_SPEND",
            "AI execution receipts may not authorize treasury spending",
        )
    voting_mod = _check_bool(sett["voting_rules_modified"], "settlement.voting_rules_modified")
    if voting_mod:
        raise VerificationError(
            "ERR_CONSTITUTIONAL_VOTING_RULES",
            "AI execution receipts may not modify voting rules",
        )
    if subsidy_eligible and evidence_mode == "quorum_signatures":
        raise VerificationError(
            "ERR_SUBSIDY_REQUIRES_PROVABLE_WORK",
            "subsidy_eligible=true forbidden for bare quorum_signatures; provable work required",
        )

    # 11. Authorized Execution Profile & Tool Allowlist Guard.
    profiles = policy["authorized_profiles"]
    if profile_id not in profiles:
        raise VerificationError(
            "ERR_UNAUTHORIZED_PROFILE",
            f"execution_profile_id {profile_id!r} is not in authorized_profiles",
        )
    prof = profiles[profile_id]
    if model_id not in prof["allowed_models"]:
        raise VerificationError(
            "ERR_UNAUTHORIZED_MODEL_OR_TIER",
            f"model_id {model_id!r} not allowed by profile {profile_id!r}",
        )
    if model_spec_hash not in prof["allowed_model_spec_hashes"]:
        raise VerificationError(
            "ERR_UNAUTHORIZED_MODEL_OR_TIER",
            f"model_spec_hash {model_spec_hash!r} not allowed by profile {profile_id!r}",
        )
    if inference_tier not in prof["allowed_tiers"]:
        raise VerificationError(
            "ERR_UNAUTHORIZED_MODEL_OR_TIER",
            f"inference_tier {inference_tier!r} not allowed by profile {profile_id!r}",
        )
    if evidence_mode not in prof["allowed_evidence_modes"]:
        raise VerificationError(
            "ERR_UNAUTHORIZED_MODEL_OR_TIER",
            f"evidence_mode {evidence_mode!r} not allowed by profile {profile_id!r}",
        )
    if max_rec_depth > prof["max_recursion_depth"]:
        raise VerificationError(
            "ERR_RECURSION_BUDGET_EXCEEDED",
            f"objective.max_recursion_depth ({max_rec_depth}) exceeds profile limit ({prof['max_recursion_depth']})",
        )
    if output_byte_length > prof["max_output_bytes"]:
        raise VerificationError(
            "ERR_OUTPUT_TOO_LARGE",
            f"result.output_byte_length ({output_byte_length}) exceeds profile limit ({prof['max_output_bytes']})",
        )
    allowed_tools_set = set(prof["allowed_tools"])
    for idx, tl in enumerate(tools):
        if tl["tool_name"] not in allowed_tools_set:
            raise VerificationError(
                "ERR_UNAUTHORIZED_TOOL",
                f"authorized_tools[{idx}].tool_name {tl['tool_name']!r} not allowed by profile {profile_id!r}",
            )

    # 12. Check consistency guard for completed jobs.
    if res["status"] == "completed":
        for idx, chk in enumerate(checks):
            if not chk["passed"] or chk["metric_bps"] < chk["threshold_bps"]:
                raise VerificationError(
                    "ERR_FAILED_CHECK_IN_COMPLETED_JOB",
                    f"completed receipt has failing check checks[{idx}] ({chk['check_id']})",
                )

    # 13. Provenance schema & Merkle root reconstruction.
    prov = _check_exact_keys(rec["provenance"], PROVENANCE_KEYS, "provenance")
    if prov["hash_algorithm"] != "sha256" or prov["domain_separator"] != SCHEMA_VERSION:
        raise VerificationError(
            "ERR_PROVENANCE_MISMATCH",
            "provenance hash_algorithm must be sha256 and domain_separator must match schema_version",
        )
    for field in (
        "inputs_root",
        "tools_root",
        "evidence_root",
        "checks_root",
        "result_digest",
        "provenance_root",
    ):
        _check_hex64(prov[field], f"provenance.{field}")

    recomputed = compute_provenance(rec)
    for field in (
        "inputs_root",
        "tools_root",
        "evidence_root",
        "checks_root",
        "result_digest",
        "provenance_root",
    ):
        if prov[field] != recomputed[field]:
            raise VerificationError(
                "ERR_PROVENANCE_MISMATCH",
                f"provenance.{field} mismatch: committed={prov[field]} recomputed={recomputed[field]}",
            )

    # 14. Canonical receipt hash computation.
    receipt_hash = canonical_receipt_hash(rec)

    # 15. Independent Verifier Attestations (Ed25519 + no self-attestation).
    attestations = rec["attestations"]
    if not isinstance(attestations, list) or len(attestations) == 0:
        raise VerificationError("ERR_INSUFFICIENT_ATTESTATIONS", "attestations must be non-empty")

    trusted_verifiers = policy["trusted_verifiers"]
    seen_verifiers: set[str] = set()
    valid_count = 0

    for idx, item in enumerate(attestations):
        att = _check_exact_keys(item, ATTESTATION_KEYS, f"attestations[{idx}]")
        v_id = _check_id(att["verifier_id"], f"attestations[{idx}].verifier_id")
        if v_id == executor_id:
            raise VerificationError(
                "ERR_SELF_ATTESTATION_FORBIDDEN",
                f"executor {executor_id!r} cannot self-attest its own receipt",
            )
        if v_id in seen_verifiers:
            raise VerificationError(
                "ERR_DUPLICATE_VERIFIER",
                f"duplicate verifier_id {v_id!r} in attestations",
            )
        seen_verifiers.add(v_id)

        if v_id not in trusted_verifiers:
            raise VerificationError(
                "ERR_UNTRUSTED_VERIFIER",
                f"verifier_id {v_id!r} is not in policy trusted_verifiers",
            )
        v_entry = trusted_verifiers[v_id]

        v_role = att["verifier_role"]
        if v_role not in ALLOWED_VERIFIER_ROLES or v_role not in v_entry["allowed_roles"]:
            raise VerificationError(
                "ERR_UNTRUSTED_VERIFIER",
                f"verifier_role {v_role!r} not permitted for {v_id!r}",
            )
        if att["algorithm"] != "ed25519":
            raise VerificationError(
                "ERR_SCHEMA_VIOLATION",
                f"attestations[{idx}].algorithm must be 'ed25519'",
            )
        pub_hex = _check_hex64(att["public_key_hex"], f"attestations[{idx}].public_key_hex")
        if pub_hex != v_entry["public_key_hex"]:
            raise VerificationError(
                "ERR_UNTRUSTED_VERIFIER",
                f"public_key_hex for {v_id!r} does not match trusted registry",
            )
        verdict = att["verdict"]
        if verdict not in ALLOWED_VERDICTS:
            raise VerificationError(
                "ERR_SCHEMA_VIOLATION", f"invalid verdict: {verdict!r}"
            )
        att_hash = _check_hex64(
            att["attested_receipt_hash"], f"attestations[{idx}].attested_receipt_hash"
        )
        if att_hash != receipt_hash:
            raise VerificationError(
                "ERR_ATTESTATION_HASH_MISMATCH",
                f"attestations[{idx}].attested_receipt_hash ({att_hash}) != canonical_receipt_hash ({receipt_hash})",
            )
        att_ts = _check_int_range(att["attested_at_unix"], f"attestations[{idx}].attested_at_unix", 1)
        sig_hex = _check_hex128(att["signature_hex"], f"attestations[{idx}].signature_hex")

        msg = attestation_message(receipt_hash, v_id, v_role, verdict, att_ts)
        if not ed25519_verify(bytes.fromhex(pub_hex), msg, bytes.fromhex(sig_hex)):
            raise VerificationError(
                "ERR_INVALID_SIGNATURE",
                f"invalid Ed25519 signature for verifier {v_id!r}",
            )
        if verdict == "VALID":
            valid_count += 1

    min_verifiers = prof["min_verifiers"]
    if valid_count < min_verifiers:
        raise VerificationError(
            "ERR_INSUFFICIENT_ATTESTATIONS",
            f"receipt has {valid_count} valid attestations, profile requires >= {min_verifiers}",
        )

    return VerificationResult(
        job_id=job_id,
        canonical_receipt_hash=receipt_hash,
        provenance_root=recomputed["provenance_root"],
        valid_attestation_count=valid_count,
    )


def verify_batch(receipts: list[Any], policy: dict[str, Any]) -> list[VerificationResult]:
    """Verify a batch of receipts with global replay protection on job_id, nonce, and intent_id."""
    if not isinstance(receipts, list):
        raise VerificationError("ERR_SCHEMA_VIOLATION", "batch must be a JSON array")
    seen_jobs: set[str] = set()
    seen_nonces: set[str] = set()
    seen_intents: set[str] = set()
    results: list[VerificationResult] = []
    for rec in receipts:
        res = verify_receipt(rec, policy)
        nonce = rec["nonce"]
        intent_id = rec["settlement"]["intent_id"]
        if res.job_id in seen_jobs:
            raise VerificationError("ERR_REPLAY_DETECTED", f"duplicate job_id {res.job_id!r}")
        if nonce in seen_nonces:
            raise VerificationError("ERR_REPLAY_DETECTED", f"duplicate nonce {nonce!r}")
        if intent_id in seen_intents:
            raise VerificationError("ERR_REPLAY_DETECTED", f"duplicate intent_id {intent_id!r}")
        seen_jobs.add(res.job_id)
        seen_nonces.add(nonce)
        seen_intents.add(intent_id)
        results.append(res)
    return results

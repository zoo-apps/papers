# Copyright 2026 Zoo Labs Foundation / Hanzo Industries.
# Licensed under the Apache License, Version 2.0.
"""Independent pure-Python verifier for inference-verify.v1 (4 regimes + guards)."""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from typing import Any

from . import dsse, inference, tlog

SCHEMA_VERSION = "inference-verify.v1"
INTOTO_STATEMENT_TYPE_V1 = "https://in-toto.io/Statement/v1"
INFERENCE_PREDICATE_TYPE = "https://zoo.ngo/attestations/inference-verify/v1"
CHALLENGE_PREDICATE_TYPE = "https://zoo.ngo/attestations/inference-challenge/v1"
REEXEC_PREDICATE_TYPE = "https://zoo.ngo/attestations/inference-reexec/v1"
CHALLENGE_DENOMINATOR_BPS = 10000

REGIME_SIGNED_ATTESTATION_ONLY = "signed_attestation_only"
REGIME_INDEPENDENT_REEXEC = "independent_reexecution"
REGIME_RANDOM_CHALLENGE = "random_challenge_verification"
REGIME_HYBRID_ATTESTED_CHAL = "hybrid_attested_plus_challenged"

VERDICT_VERIFIED = "VERIFIED"
VERDICT_FRAUD_DETECTED = "FRAUD_DETECTED"
VERDICT_INVALID_ATTESTATION = "INVALID_ATTESTATION"
VERDICT_POLICY_REJECTED = "POLICY_REJECTED"

ROLE_AI_AGENT = "AI_AGENT"

ACTION_APPROVE_SLASHING = "APPROVE_SLASHING"
ACTION_MUTATE_POLICY_PARAMS = "MUTATE_POLICY_PARAMS"
ACTION_SELF_CERTIFY_INFERENCE = "SELF_CERTIFY_INFERENCE"

ERR_NONE = "OK"
ERR_INVALID_ENVELOPE = "ERR_INVALID_ENVELOPE"
ERR_INVALID_PAYLOAD_TYPE = "ERR_INVALID_PAYLOAD_TYPE"
ERR_INVALID_INTOTO_TYPE = "ERR_INVALID_INTOTO_TYPE"
ERR_INVALID_PREDICATE_TYPE = "ERR_INVALID_PREDICATE_TYPE"
ERR_INVALID_SCHEMA_VERSION = "ERR_INVALID_SCHEMA_VERSION"
ERR_SUBJECT_DIGEST_MISMATCH = "ERR_SUBJECT_DIGEST_MISMATCH"
ERR_MODEL_DIGEST_MISMATCH = "ERR_MODEL_DIGEST_MISMATCH"
ERR_INPUT_DIGEST_MISMATCH = "ERR_INPUT_DIGEST_MISMATCH"
ERR_REGIME_MISMATCH = "ERR_REGIME_MISMATCH"
ERR_KEY_UNREGISTERED = "ERR_KEY_UNREGISTERED"
ERR_KEY_REVOKED = "ERR_KEY_REVOKED"
ERR_KEY_EXPIRED = "ERR_KEY_EXPIRED"
ERR_EPOCH_MISMATCH = "ERR_EPOCH_MISMATCH"
ERR_EQUIVOCATION_DETECTED = "ERR_EQUIVOCATION_DETECTED"
ERR_QUORUM_NOT_MET = "ERR_QUORUM_NOT_MET"
ERR_COLLUDING_OPERATOR_GROUP = "ERR_COLLUDING_OPERATOR_GROUP"
ERR_INVALID_REEXEC_SIG = "ERR_INVALID_REEXEC_SIG"
ERR_OUTPUT_MISMATCH_REEXEC = "ERR_OUTPUT_MISMATCH_REEXEC"
ERR_MISSING_REQUIRED_CHALLENGE = "ERR_MISSING_REQUIRED_CHALLENGE"
ERR_INVALID_CHALLENGE_SIG = "ERR_INVALID_CHALLENGE_SIG"
ERR_CHALLENGE_FRAUD_PROVEN = "ERR_CHALLENGE_FRAUD_PROVEN"
ERR_CHALLENGE_TRANSCRIPT_INVALID = "ERR_CHALLENGE_TRANSCRIPT_INVALID"
ERR_AI_SELF_CERT_FORBIDDEN = "ERR_AI_SELF_CERT_FORBIDDEN"
ERR_AI_POLICY_MUTATION_FORBIDDEN = "ERR_AI_POLICY_MUTATION_FORBIDDEN"
ERR_AI_SLASH_APPROVAL_FORBIDDEN = "ERR_AI_SLASH_APPROVAL_FORBIDDEN"
ERR_OVERCLAIMED_PROOF_SCOPE = "ERR_OVERCLAIMED_PROOF_SCOPE"


@dataclass
class CaseResult:
    case_id: str
    category: str
    regime: str
    verdict: str = ""
    error_code: str = ""
    challenged: bool = False
    fraud_escaped: bool = False
    reexec_count: int = 0
    output_digest: str = ""
    tlog_root: str = ""
    audit_leaf_digest: str = ""


@dataclass
class SuiteAuditResult:
    total_cases: int
    golden_cases: int
    adversarial_cases: int
    matches_expected: int
    audit_merkle_root: str
    results: list[CaseResult]


def _clamp(v: int, lo: int, hi: int) -> int:
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v


def compute_challenge_draw_bps(
    epoch_beacon_hex: str, job_id: str, worker_output_digest: str
) -> int:
    msg = (
        f"inference-verify.v1:challenge:{epoch_beacon_hex}:{job_id}:{worker_output_digest}"
    ).encode("utf-8")
    digest = hashlib.sha256(msg).digest()
    val = struct.unpack(">Q", digest[:8])[0]
    return val % CHALLENGE_DENOMINATOR_BPS


def effective_challenge_bps(
    regime: str,
    risk: dict[str, Any],
    policy: dict[str, Any],
    override: int | None,
) -> int:
    min_bps = int(policy["min_challenge_bps"])
    max_bps = int(policy["max_challenge_bps"])
    if regime in (REGIME_SIGNED_ATTESTATION_ONLY, REGIME_INDEPENDENT_REEXEC):
        return 0
    if regime == REGIME_RANDOM_CHALLENGE:
        if override is not None:
            return _clamp(int(override), 0, CHALLENGE_DENOMINATOR_BPS)
        return _clamp(int(policy["challenge_base_bps"]), min_bps, max_bps)
    if regime == REGIME_HYBRID_ATTESTED_CHAL:
        if override is not None:
            return _clamp(int(override), min_bps, max_bps)
        if (
            int(risk["jobs_completed"]) < int(policy["probation_jobs"])
            or int(risk["reputation_score"]) < int(policy["reputation_threshold"])
            or bool(risk["ai_advisory_flagged"])
        ):
            return _clamp(int(policy["challenge_escalated_bps"]), min_bps, max_bps)
        return _clamp(int(policy["challenge_base_bps"]), min_bps, max_bps)
    return 0


def _lookup_key(trust_root: dict[str, Any], actor_id: str) -> dict[str, Any] | None:
    for k in trust_root.get("keys", []):
        if k.get("actor_id") == actor_id:
            return k
    return None


def _validate_key_at_epoch(key_entry: dict[str, Any], epoch: int) -> str:
    if bool(key_entry.get("revoked", False)):
        return ERR_KEY_REVOKED
    if epoch < int(key_entry["valid_from_epoch"]) or epoch > int(
        key_entry["valid_until_epoch"]
    ):
        return ERR_KEY_EXPIRED
    return ERR_NONE


def _check_constitutional_guards(pred: dict[str, Any]) -> str:
    if bool(pred.get("proves_hardware_tee_uncompromised", False)) or bool(
        pred.get("proves_scientific_truth", False)
    ):
        return ERR_OVERCLAIMED_PROOF_SCOPE
    role = pred.get("actor_role")
    action = pred.get("governance_action")
    if role == ROLE_AI_AGENT:
        if action == ACTION_APPROVE_SLASHING:
            return ERR_AI_SLASH_APPROVAL_FORBIDDEN
        if action == ACTION_MUTATE_POLICY_PARAMS:
            return ERR_AI_POLICY_MUTATION_FORBIDDEN
        return ERR_AI_SELF_CERT_FORBIDDEN
    if action == ACTION_SELF_CERTIFY_INFERENCE:
        return ERR_AI_SELF_CERT_FORBIDDEN
    if action == ACTION_APPROVE_SLASHING:
        return ERR_AI_SLASH_APPROVAL_FORBIDDEN
    if action == ACTION_MUTATE_POLICY_PARAMS:
        return ERR_AI_POLICY_MUTATION_FORBIDDEN
    return ERR_NONE


def _build_audit_leaf_digest(r: CaseResult) -> str:
    challenged_str = "true" if r.challenged else "false"
    escaped_str = "true" if r.fraud_escaped else "false"
    tlog_root = r.tlog_root if r.tlog_root else "none"
    out_dig = r.output_digest if r.output_digest else "none"
    raw = (
        f"inference-verify.v1:audit-leaf:{r.case_id}:{r.regime}:{r.verdict}:"
        f"{r.error_code}:{challenged_str}:{escaped_str}:{r.reexec_count}:"
        f"{out_dig}:{tlog_root}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def verify_case(
    case: dict[str, Any],
    model: inference.QuantizedMLP,
    trust_root: dict[str, Any],
    policy: dict[str, Any],
) -> CaseResult:
    res = CaseResult(
        case_id=case["case_id"],
        category=case["category"],
        regime=case["regime"],
    )

    def finish(verdict: str, err_code: str) -> CaseResult:
        res.verdict = verdict
        res.error_code = err_code
        if verdict == VERDICT_VERIFIED and bool(
            case.get("worker_cheated_ground_truth", False)
        ):
            res.fraud_escaped = True
        res.audit_leaf_digest = _build_audit_leaf_digest(res)
        return res

    env = case["worker_envelope"]
    if env.get("payloadType") != dsse.DSSE_PAYLOAD_TYPE_INTOTO:
        return finish(VERDICT_INVALID_ATTESTATION, ERR_INVALID_PAYLOAD_TYPE)
    if not env.get("signatures") or not env.get("payload"):
        return finish(VERDICT_INVALID_ATTESTATION, ERR_INVALID_ENVELOPE)

    raw_payload, err_code = dsse.decode_payload_only(env)
    if err_code != ERR_NONE or raw_payload is None:
        return finish(VERDICT_INVALID_ATTESTATION, err_code)

    try:
        stmt = json.loads(raw_payload.decode("utf-8"))
    except Exception:
        return finish(VERDICT_INVALID_ATTESTATION, ERR_INVALID_ENVELOPE)

    if stmt.get("_type") != INTOTO_STATEMENT_TYPE_V1:
        return finish(VERDICT_INVALID_ATTESTATION, ERR_INVALID_INTOTO_TYPE)
    if stmt.get("predicateType") != INFERENCE_PREDICATE_TYPE:
        return finish(VERDICT_INVALID_ATTESTATION, ERR_INVALID_PREDICATE_TYPE)
    pred = stmt.get("predicate", {})
    if pred.get("schema_version") != SCHEMA_VERSION:
        return finish(VERDICT_INVALID_ATTESTATION, ERR_INVALID_SCHEMA_VERSION)

    res.output_digest = str(pred.get("output_digest", ""))

    # Constitutional & AI-role governance guards
    guard_err = _check_constitutional_guards(pred)
    if guard_err != ERR_NONE:
        return finish(VERDICT_POLICY_REJECTED, guard_err)

    # Worker key registration, revocation, expiry, and operator group binding
    worker_key = _lookup_key(trust_root, str(pred.get("worker_id", "")))
    if (
        worker_key is None
        or worker_key["pubkey_hex"] != pred.get("worker_pubkey_hex")
        or worker_key["operator_group"] != pred.get("worker_operator_group")
    ):
        return finish(VERDICT_INVALID_ATTESTATION, ERR_KEY_UNREGISTERED)

    expected_epoch = int(case["expected_epoch"])
    key_err = _validate_key_at_epoch(worker_key, expected_epoch)
    if key_err != ERR_NONE:
        return finish(VERDICT_INVALID_ATTESTATION, key_err)

    # RFC 8032 Ed25519 DSSE PAE signature verification
    payload_bytes, sig_bytes, sig_err = dsse.verify_dsse_signature(
        env, worker_key["pubkey_hex"]
    )
    if sig_err != ERR_NONE or payload_bytes is None or sig_bytes is None:
        return finish(VERDICT_INVALID_ATTESTATION, sig_err)

    # Subject, regime, epoch, model, input, and equivocation checks
    subjects = stmt.get("subject", [])
    if (
        not subjects
        or subjects[0].get("digest", {}).get("sha256") != pred.get("output_digest")
    ):
        return finish(VERDICT_INVALID_ATTESTATION, ERR_SUBJECT_DIGEST_MISMATCH)
    if pred.get("regime") != case["regime"]:
        return finish(VERDICT_INVALID_ATTESTATION, ERR_REGIME_MISMATCH)
    if int(pred.get("epoch", -1)) != expected_epoch:
        return finish(VERDICT_INVALID_ATTESTATION, ERR_EPOCH_MISMATCH)
    if pred.get("model_digest") != model.model_digest:
        return finish(VERDICT_INVALID_ATTESTATION, ERR_MODEL_DIGEST_MISMATCH)

    tokens = [int(t) for t in case["input_tokens"]]
    decode_steps = int(case["decode_steps"])
    expected_input_digest = inference.compute_input_digest(tokens, decode_steps)
    if (
        pred.get("input_digest") != expected_input_digest
        or int(pred.get("decode_steps", -1)) != decode_steps
    ):
        return finish(VERDICT_INVALID_ATTESTATION, ERR_INPUT_DIGEST_MISMATCH)

    seen = case.get("seen_job_outputs") or {}
    job_id = str(pred["job_id"])
    if job_id in seen and seen[job_id] != pred["output_digest"]:
        return finish(VERDICT_INVALID_ATTESTATION, ERR_EQUIVOCATION_DETECTED)

    # Transparency log inclusion proof + checkpoint signature
    expected_leaf = dsse.compute_tlog_leaf_entry_digest(
        job_id, payload_bytes, sig_bytes, int(pred["epoch"])
    )
    tlog_err = tlog.verify_tlog_bundle(
        case.get("tlog_bundle"), expected_leaf, expected_epoch, trust_root
    )
    if tlog_err != ERR_NONE:
        return finish(VERDICT_INVALID_ATTESTATION, tlog_err)
    res.tlog_root = str(case["tlog_bundle"]["root_hash"])

    # Regime-specific verification
    regime = case["regime"]
    if regime == REGIME_SIGNED_ATTESTATION_ONLY:
        return finish(VERDICT_VERIFIED, ERR_NONE)

    if regime == REGIME_INDEPENDENT_REEXEC:
        return _verify_independent_reexec(
            case, pred, worker_key, model, trust_root, policy, res, finish
        )

    if regime in (REGIME_RANDOM_CHALLENGE, REGIME_HYBRID_ATTESTED_CHAL):
        return _verify_challenged_regime(
            case, pred, worker_key, model, trust_root, policy, res, finish
        )

    return finish(VERDICT_INVALID_ATTESTATION, ERR_REGIME_MISMATCH)


def _verify_independent_reexec(
    case: dict[str, Any],
    pred: dict[str, Any],
    worker_key: dict[str, Any],
    model: inference.QuantizedMLP,
    trust_root: dict[str, Any],
    policy: dict[str, Any],
    res: CaseResult,
    finish: Any,
) -> CaseResult:
    quorum_k = int(policy["reexec_quorum_k"])
    required_independent = max(1, quorum_k - 1)
    receipts = case.get("reexec_receipts") or []
    if len(receipts) < required_independent:
        return finish(VERDICT_INVALID_ATTESTATION, ERR_QUORUM_NOT_MET)

    tokens = [int(t) for t in case["input_tokens"]]
    decode_steps = int(case["decode_steps"])
    expected_out = model.forward_honest(str(pred["job_id"]), tokens, decode_steps)
    res.reexec_count = len(receipts)

    seen_groups = {worker_key["operator_group"]}
    seen_verifiers = {worker_key["actor_id"]}
    valid_receipts = 0
    agree_with_expected = 0
    expected_epoch = int(case["expected_epoch"])

    for r in receipts:
        v_id = r["verifier_id"]
        v_key = _lookup_key(trust_root, v_id)
        if v_key is None:
            return finish(VERDICT_INVALID_ATTESTATION, ERR_KEY_UNREGISTERED)
        k_err = _validate_key_at_epoch(v_key, expected_epoch)
        if k_err != ERR_NONE:
            return finish(VERDICT_INVALID_ATTESTATION, k_err)
        if v_key["actor_id"] in seen_verifiers or v_key["operator_group"] in seen_groups:
            return finish(VERDICT_INVALID_ATTESTATION, ERR_COLLUDING_OPERATOR_GROUP)
        v_payload, _, sig_err = dsse.verify_dsse_signature(
            r["envelope"], v_key["pubkey_hex"]
        )
        if sig_err != ERR_NONE or v_payload is None:
            return finish(VERDICT_INVALID_ATTESTATION, ERR_INVALID_REEXEC_SIG)
        try:
            r_stmt = json.loads(v_payload.decode("utf-8"))
        except Exception:
            return finish(VERDICT_INVALID_ATTESTATION, ERR_INVALID_REEXEC_SIG)
        if (
            r_stmt.get("_type") != INTOTO_STATEMENT_TYPE_V1
            or r_stmt.get("predicateType") != REEXEC_PREDICATE_TYPE
        ):
            return finish(VERDICT_INVALID_ATTESTATION, ERR_INVALID_REEXEC_SIG)
        rp = r_stmt.get("predicate", {})
        if rp.get("actor_role") == ROLE_AI_AGENT:
            return finish(VERDICT_POLICY_REJECTED, ERR_AI_SELF_CERT_FORBIDDEN)
        if (
            rp.get("verifier_id") != v_id
            or rp.get("verifier_pubkey_hex") != v_key["pubkey_hex"]
            or rp.get("verifier_operator_group") != v_key["operator_group"]
        ):
            return finish(VERDICT_INVALID_ATTESTATION, ERR_INVALID_REEXEC_SIG)
        if (
            rp.get("job_id") != pred["job_id"]
            or int(rp.get("epoch", -1)) != int(pred["epoch"])
            or rp.get("model_digest") != pred["model_digest"]
            or rp.get("input_digest") != pred["input_digest"]
        ):
            return finish(VERDICT_INVALID_ATTESTATION, ERR_INVALID_REEXEC_SIG)
        if (
            rp.get("computed_output_digest") == expected_out.output_digest
            and rp.get("computed_logits_digest") == expected_out.logits_digest
            and int(rp.get("computed_top_token", -1)) == expected_out.top_token
        ):
            agree_with_expected += 1
        seen_verifiers.add(v_key["actor_id"])
        seen_groups.add(v_key["operator_group"])
        valid_receipts += 1

    quorum = (quorum_k + 1) // 2
    if valid_receipts < required_independent or agree_with_expected < quorum - 1:
        return finish(VERDICT_INVALID_ATTESTATION, ERR_QUORUM_NOT_MET)

    if (
        pred["output_digest"] != expected_out.output_digest
        or pred["logits_digest"] != expected_out.logits_digest
        or int(pred["top_token"]) != expected_out.top_token
    ):
        return finish(VERDICT_FRAUD_DETECTED, ERR_OUTPUT_MISMATCH_REEXEC)
    return finish(VERDICT_VERIFIED, ERR_NONE)


def _verify_challenged_regime(
    case: dict[str, Any],
    pred: dict[str, Any],
    worker_key: dict[str, Any],
    model: inference.QuantizedMLP,
    trust_root: dict[str, Any],
    policy: dict[str, Any],
    res: CaseResult,
    finish: Any,
) -> CaseResult:
    override = case.get("challenge_rate_bps_override")
    eff_bps = effective_challenge_bps(
        case["regime"], case["worker_risk"], policy, override
    )
    draw_bps = compute_challenge_draw_bps(
        case["epoch_beacon_hex"], str(pred["job_id"]), str(pred["output_digest"])
    )
    challenged = draw_bps < eff_bps
    res.challenged = challenged

    if not challenged:
        return finish(VERDICT_VERIFIED, ERR_NONE)

    ct = case.get("challenge_transcript")
    if ct is None:
        return finish(VERDICT_INVALID_ATTESTATION, ERR_MISSING_REQUIRED_CHALLENGE)

    c_id = ct["challenger_id"]
    c_key = _lookup_key(trust_root, c_id)
    if c_key is None:
        return finish(VERDICT_INVALID_ATTESTATION, ERR_KEY_UNREGISTERED)
    k_err = _validate_key_at_epoch(c_key, int(case["expected_epoch"]))
    if k_err != ERR_NONE:
        return finish(VERDICT_INVALID_ATTESTATION, k_err)
    if (
        c_key["actor_id"] == worker_key["actor_id"]
        or c_key["operator_group"] == worker_key["operator_group"]
    ):
        return finish(VERDICT_INVALID_ATTESTATION, ERR_COLLUDING_OPERATOR_GROUP)

    c_payload, _, sig_err = dsse.verify_dsse_signature(
        ct["envelope"], c_key["pubkey_hex"]
    )
    if sig_err != ERR_NONE or c_payload is None:
        return finish(VERDICT_INVALID_ATTESTATION, ERR_INVALID_CHALLENGE_SIG)

    try:
        c_stmt = json.loads(c_payload.decode("utf-8"))
    except Exception:
        return finish(VERDICT_INVALID_ATTESTATION, ERR_CHALLENGE_TRANSCRIPT_INVALID)

    if (
        c_stmt.get("_type") != INTOTO_STATEMENT_TYPE_V1
        or c_stmt.get("predicateType") != CHALLENGE_PREDICATE_TYPE
    ):
        return finish(VERDICT_INVALID_ATTESTATION, ERR_CHALLENGE_TRANSCRIPT_INVALID)
    cp = c_stmt.get("predicate", {})
    if cp.get("actor_role") == ROLE_AI_AGENT:
        return finish(VERDICT_POLICY_REJECTED, ERR_AI_SELF_CERT_FORBIDDEN)
    if (
        cp.get("challenger_id") != c_id
        or cp.get("challenger_pubkey_hex") != c_key["pubkey_hex"]
        or cp.get("challenger_operator_group") != c_key["operator_group"]
    ):
        return finish(VERDICT_INVALID_ATTESTATION, ERR_CHALLENGE_TRANSCRIPT_INVALID)

    if (
        cp.get("job_id") != pred["job_id"]
        or int(cp.get("epoch", -1)) != int(pred["epoch"])
        or cp.get("epoch_beacon_hex") != case["epoch_beacon_hex"]
        or int(cp.get("effective_challenge_bps", -1)) != eff_bps
        or int(cp.get("challenge_draw_bps", -1)) != draw_bps
        or cp.get("model_digest") != pred["model_digest"]
        or cp.get("input_digest") != pred["input_digest"]
        or cp.get("worker_output_digest") != pred["output_digest"]
    ):
        return finish(VERDICT_INVALID_ATTESTATION, ERR_CHALLENGE_TRANSCRIPT_INVALID)

    res.reexec_count = 1
    tokens = [int(t) for t in case["input_tokens"]]
    decode_steps = int(case["decode_steps"])
    expected_out = model.forward_honest(str(pred["job_id"]), tokens, decode_steps)
    if (
        cp.get("recomputed_output_digest") != expected_out.output_digest
        or cp.get("recomputed_logits_digest") != expected_out.logits_digest
        or int(cp.get("recomputed_top_token", -1)) != expected_out.top_token
    ):
        return finish(VERDICT_INVALID_ATTESTATION, ERR_CHALLENGE_TRANSCRIPT_INVALID)

    worker_mismatch = (
        pred["output_digest"] != expected_out.output_digest
        or pred["logits_digest"] != expected_out.logits_digest
        or int(pred["top_token"]) != expected_out.top_token
    )
    if bool(cp.get("fraud_proven", False)) != worker_mismatch:
        return finish(VERDICT_INVALID_ATTESTATION, ERR_CHALLENGE_TRANSCRIPT_INVALID)
    if worker_mismatch:
        return finish(VERDICT_FRAUD_DETECTED, ERR_CHALLENGE_FRAUD_PROVEN)
    return finish(VERDICT_VERIFIED, ERR_NONE)


def audit_suite(suite: dict[str, Any]) -> SuiteAuditResult:
    model = inference.QuantizedMLP(suite["corpus_root_sha256"], suite["model_id"])
    trust_root = suite["trust_root"]
    policy = suite["policy"]
    results: list[CaseResult] = []
    leaves: list[bytes] = []

    golden = 0
    adv = 0
    matched = 0

    for c in suite["cases"]:
        r = verify_case(c, model, trust_root, policy)
        results.append(r)
        leaves.append(r.audit_leaf_digest.encode("utf-8"))
        if c["category"] == "golden":
            golden += 1
        else:
            adv += 1
        if (
            r.verdict == c["expected_verdict"]
            and r.error_code == c["expected_error_code"]
            and r.fraud_escaped == bool(c.get("expected_fraud_escaped", False))
        ):
            matched += 1

    root_hex = tlog.compute_merkle_root_rfc6962(leaves).hex()
    return SuiteAuditResult(
        total_cases=len(suite["cases"]),
        golden_cases=golden,
        adversarial_cases=adv,
        matches_expected=matched,
        audit_merkle_root=root_hex,
        results=results,
    )

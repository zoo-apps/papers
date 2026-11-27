# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.

"""Independent cross-language verifier checking Go benchmark results bit-for-bit."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict, List

from . import SCHEMA_VERSION, SPEC_VERSION
from .canonical import audit_merkle_root, case_digest
from .engine import apply_action
from .rego_lint import validate_rego_bundle


class VerificationError(Exception):
    """Raised when independent verification detects any discrepancy."""


def verify_case(case_obj: Dict[str, Any]) -> Dict[str, Any]:
    """Re-execute a signed adversarial case in pure Python and verify parity."""
    state = copy.deepcopy(case_obj["initial_state"])
    verdict = "DENY"
    code = "ERR_UNKNOWN_ACTION"
    witness = None
    for act in case_obj["actions"]:
        verdict, code, witness = apply_action(state, act, verify_sigs=True)

    if verdict != case_obj["actual_verdict"] or code != case_obj["actual_error_code"]:
        raise VerificationError(
            f"{case_obj['case_id']}: Go/Python verdict mismatch: "
            f"Go={case_obj['actual_verdict']}/{case_obj['actual_error_code']} "
            f"Py={verdict}/{code}"
        )
    if verdict != case_obj["expected_verdict"] or code != case_obj["expected_error_code"]:
        raise VerificationError(
            f"{case_obj['case_id']}: expectation failure: "
            f"expected {case_obj['expected_verdict']}/{case_obj['expected_error_code']}, got {verdict}/{code}"
        )

    go_witness = case_obj.get("conflict_witness")
    if (go_witness is None) != (witness is None):
        raise VerificationError(f"{case_obj['case_id']}: ConflictWitness presence mismatch")
    if go_witness is not None and witness is not None:
        if go_witness != witness:
            raise VerificationError(
                f"{case_obj['case_id']}: ConflictWitness mismatch: Go={go_witness} Py={witness}"
            )

    recomputed = copy.deepcopy(case_obj)
    recomputed["actual_verdict"] = verdict
    recomputed["actual_error_code"] = code
    if witness is not None:
        recomputed["conflict_witness"] = witness
    recomputed["passed"] = True
    dig = case_digest(recomputed)
    if dig != case_obj["case_digest"]:
        raise VerificationError(
            f"{case_obj['case_id']}: case_digest mismatch: Go={case_obj['case_digest']} Py={dig}"
        )
    return recomputed


def verify_results_bundle(results_path: Path, rego_dir: Path) -> Dict[str, Any]:
    """Independently verify results.json and rego/ bundle against constitutional-gov.v1."""
    data = json.loads(results_path.read_text(encoding="utf-8"))

    if data.get("schema_version") != SCHEMA_VERSION:
        raise VerificationError(f"schema_version mismatch: {data.get('schema_version')}")
    if data.get("spec_version") != SPEC_VERSION:
        raise VerificationError(f"spec_version mismatch: {data.get('spec_version')}")

    suite = data["adversarial_suite"]
    cases: List[Dict[str, Any]] = suite["cases"]
    if len(cases) < 40:
        raise VerificationError(f"expected >= 40 adversarial cases, found {len(cases)}")

    verified_cases = [verify_case(c) for c in cases]
    recomputed_root = audit_merkle_root(verified_cases)
    if recomputed_root != data["audit_merkle_root"]:
        raise VerificationError(
            f"audit_merkle_root mismatch: Go={data['audit_merkle_root']} Py={recomputed_root}"
        )

    # Validate model checker & mutation audit guarantees.
    mc = data["model_checker"]
    if int(mc["total_states_and_transitions"]) < 50000:
        raise VerificationError(f"model checker explored < 50,000 states/transitions: {mc}")
    if int(mc["invariant_violations"]) != 0:
        raise VerificationError(f"non-zero invariant violations: {mc['invariant_violations']}")

    mut = data["mutation_audit"]
    if int(mut["mutants_killed"]) != int(mut["total_mutants"]) or int(mut["total_mutants"]) < 10:
        raise VerificationError(f"mutation audit incomplete: {mut['mutants_killed']}/{mut['total_mutants']}")

    # Validate 3 explicit negative regimes.
    neg = data["negative_regimes"]
    n1 = neg["neg_first_match_masks_rule_conflict"]
    if int(n1["naive_first_match_unsafe_allows"]) <= 0 or int(n1["fail_closed_blocked"]) != int(n1["trials"]):
        raise VerificationError(f"negative regime 1 invalid: {n1}")
    n2 = neg["neg_fail_closed_liveness_deadlock"]
    if int(n2["executed_under_charter_conflict"]) != 0 or int(n2["executed_under_defcon1_pause"]) != 0:
        raise VerificationError(f"negative regime 2 invalid: {n2}")
    if int(n2["safety_violations"]) != 0:
        raise VerificationError(f"negative regime 2 safety violation: {n2}")
    n3 = neg["neg_bounded_mc_depth_horizon"]
    for probe in n3["depth_probes"]:
        if probe["max_depth"] <= 6 and probe["bug_detected"]:
            raise VerificationError(f"negative regime 3 depth {probe['max_depth']} unexpectedly caught depth-8 bug")
        if probe["max_depth"] >= 8 and not probe["bug_detected"]:
            raise VerificationError(f"negative regime 3 depth {probe['max_depth']} missed depth-8 bug")

    # Validate OPA Rego v1 bundle syntax + SHA-256 parity with Go.
    files, bundle_sha, rego_stats = validate_rego_bundle(rego_dir)
    if bundle_sha != data["rego_bundle"]["bundle_sha256"]:
        raise VerificationError(
            f"rego bundle sha256 mismatch: Go={data['rego_bundle']['bundle_sha256']} Py={bundle_sha}"
        )

    return {
        "verified_cases": len(verified_cases),
        "audit_merkle_root": recomputed_root,
        "rego_files": files,
        "rego_bundle_sha256": bundle_sha,
        "rego_stats": rego_stats,
        "mc_states_and_transitions": mc["total_states_and_transitions"],
        "mutants_killed": f"{mut['mutants_killed']}/{mut['total_mutants']}",
    }

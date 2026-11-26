# SPDX-License-Identifier: Apache-2.0
"""Independent cross-language audit verifier for results.json and scenarios.json."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from .canonical import (
    compute_audit_merkle_root,
    compute_merkle_root,
    hash_corpus,
    hash_governance_checks,
)
from .mechanisms import ALL_MECHANISMS, evaluate_mechanism

FORBIDDEN_AI_ACTIONS = {
    "redefine_voting_rules": "ERR_AI_RULE_MUTATION_FORBIDDEN",
    "authorize_treasury_disbursement": "ERR_AI_TREASURY_AUTH_FORBIDDEN",
    "declare_experiment_valid": "ERR_AI_SELF_VALIDATION_FORBIDDEN",
}


@dataclass
class VerificationReport:
    ok: bool
    scenarios_verified: int
    evaluations_verified: int
    corpus_hash: str
    governance_hash: str
    eval_merkle_root: str
    audit_merkle_root: str
    errors: List[str] = field(default_factory=list)


def verify_governance_checks(checks: List[Mapping[str, Any]], errors: List[str]) -> None:
    if not checks:
        errors.append("governance_checks is empty")
        return
    seen_forbidden = set()
    for c in checks:
        role = c.get("actor_role")
        action = c.get("action")
        allowed = bool(c.get("allowed"))
        reason = c.get("reason_code")
        if role == "ai_agent" and action in FORBIDDEN_AI_ACTIONS:
            seen_forbidden.add(action)
            if allowed:
                errors.append(
                    f"constitutional violation: AI agent allowed forbidden action {action} ({c.get('check_id')})"
                )
            if reason != FORBIDDEN_AI_ACTIONS[action]:
                errors.append(
                    f"unexpected reason code for {c.get('check_id')}: {reason}"
                )
        if role != "ai_agent" and action == "authorize_treasury_disbursement":
            signers = int(c.get("human_signers", 0))
            rep = int(c.get("actor_zoo_rep", 0))
            if allowed and (signers < 3 or rep < 200):
                errors.append(
                    f"constitutional violation: human treasury auth allowed below quorum/rep ({c.get('check_id')})"
                )
    missing = set(FORBIDDEN_AI_ACTIONS.keys()) - seen_forbidden
    if missing:
        errors.append(f"missing constitutional AI-block audit checks: {sorted(missing)}")


def verify_artifacts(
    results_data: Mapping[str, Any],
    scenarios_data: Mapping[str, Any],
    papers_root: Optional[Path] = None,
) -> VerificationReport:
    errors: List[str] = []

    if results_data.get("spec_version") != "qf-simulator.v1":
        errors.append(f"unexpected results spec_version: {results_data.get('spec_version')}")
    if scenarios_data.get("spec_version") != "qf-simulator.v1":
        errors.append(
            f"unexpected scenarios spec_version: {scenarios_data.get('spec_version')}"
        )

    # 1. Verify corpus proposals and optional on-disk .tex SHA-256 digests.
    corpus_proposals = results_data.get("corpus_proposals", [])
    if len(corpus_proposals) != 12:
        errors.append(f"expected 12 real corpus proposals, got {len(corpus_proposals)}")
    if papers_root is not None:
        for p in corpus_proposals:
            tex_file = papers_root / p["tex_path"]
            if not tex_file.is_file():
                errors.append(f"missing corpus .tex file: {tex_file}")
                continue
            digest = hashlib.sha256(tex_file.read_bytes()).hexdigest()
            if digest != p["tex_sha256"]:
                errors.append(
                    f"corpus .tex SHA-256 mismatch for {p['id']}: disk={digest} json={p['tex_sha256']}"
                )

    recomputed_corpus_hash = hash_corpus(corpus_proposals)
    if recomputed_corpus_hash != results_data.get("corpus_hash"):
        errors.append(
            f"corpus_hash mismatch: recomputed={recomputed_corpus_hash} reported={results_data.get('corpus_hash')}"
        )

    # 2. Verify constitutional governance audit checks.
    gov_checks = results_data.get("governance_checks", [])
    verify_governance_checks(gov_checks, errors)
    recomputed_gov_hash = hash_governance_checks(gov_checks)
    if recomputed_gov_hash != results_data.get("governance_hash"):
        errors.append(
            f"governance_hash mismatch: recomputed={recomputed_gov_hash} reported={results_data.get('governance_hash')}"
        )

    # 3. Independently recompute all 6 mechanisms across all exported scenarios.
    reported_evals: Dict[tuple[str, str], Mapping[str, Any]] = {}
    for ev in results_data.get("evaluations", []):
        key = (ev["scenario_id"], ev["mechanism_id"])
        if key in reported_evals:
            errors.append(f"duplicate evaluation for {key}")
        reported_evals[key] = ev

    scenarios = scenarios_data.get("scenarios", [])
    recomputed_evals: List[Dict[str, Any]] = []

    for sc in scenarios:
        for mech in ALL_MECHANISMS:
            ev = evaluate_mechanism(sc, mech)
            recomputed_evals.append(ev)

            if not ev["metrics"]["pool_conserved"]:
                errors.append(f"pool conservation failed for {sc['id']} / {mech}")
            if ev["metrics"]["unallocated_pool_micro_zoo"] != 0:
                errors.append(
                    f"non-zero unallocated pool for {sc['id']} / {mech}: {ev['metrics']['unallocated_pool_micro_zoo']}"
                )

            key = (sc["id"], mech)
            rep = reported_evals.get(key)
            if rep is None:
                errors.append(f"missing reported evaluation for {key}")
                continue
            if rep != ev:
                errors.append(
                    f"evaluation mismatch for {sc['id']} / {mech}: leaf_recomputed={ev['leaf_hash']} leaf_reported={rep.get('leaf_hash')}"
                )

    if len(reported_evals) != len(recomputed_evals):
        errors.append(
            f"evaluation count mismatch: reported={len(reported_evals)} recomputed={len(recomputed_evals)}"
        )

    # 4. Recompute binary Merkle root and top-level audit_merkle_root.
    ordered_evals = sorted(
        recomputed_evals, key=lambda e: (e["scenario_id"], e["mechanism_id"])
    )
    leaf_hashes = [e["leaf_hash"] for e in ordered_evals]
    recomputed_eval_root = compute_merkle_root(leaf_hashes)
    if recomputed_eval_root != results_data.get("eval_merkle_root"):
        errors.append(
            f"eval_merkle_root mismatch: recomputed={recomputed_eval_root} reported={results_data.get('eval_merkle_root')}"
        )

    recomputed_audit_root = compute_audit_merkle_root(
        recomputed_corpus_hash, recomputed_eval_root, recomputed_gov_hash
    )
    if recomputed_audit_root != results_data.get("audit_merkle_root"):
        errors.append(
            f"audit_merkle_root mismatch: recomputed={recomputed_audit_root} reported={results_data.get('audit_merkle_root')}"
        )

    return VerificationReport(
        ok=len(errors) == 0,
        scenarios_verified=len(scenarios),
        evaluations_verified=len(recomputed_evals),
        corpus_hash=recomputed_corpus_hash,
        governance_hash=recomputed_gov_hash,
        eval_merkle_root=recomputed_eval_root,
        audit_merkle_root=recomputed_audit_root,
        errors=errors,
    )


def verify_files(
    results_path: Path,
    scenarios_path: Path,
    papers_root: Optional[Path] = None,
) -> VerificationReport:
    results_data = json.loads(results_path.read_text(encoding="utf-8"))
    scenarios_data = json.loads(scenarios_path.read_text(encoding="utf-8"))
    return verify_artifacts(results_data, scenarios_data, papers_root=papers_root)

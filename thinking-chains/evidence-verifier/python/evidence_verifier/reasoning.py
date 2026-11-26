# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation

"""Deterministic reasoning_chain_check verifier (1:1 parity with Go verifier)."""

from __future__ import annotations

from typing import Any

from .types import (
    REASON_DANGLING_PREMISE,
    REASON_DUPLICATE_STEP_ID,
    REASON_EMPTY_REASONING_CHAIN,
    REASON_HUMAN_REVIEW_REQUIRED,
    REASON_INCONCLUSIVE_PREMISE,
    REASON_MISSING_CONCLUSION,
    REASON_MISSING_PAYLOAD,
    REASON_OK_REASONING_CHAIN,
    REASON_PRIVATE_COT_FORBIDDEN,
    REASON_REASONING_CYCLE,
    REASON_REFUTED_PREMISE,
    REASON_UNVERIFIED_PREMISE,
    VERDICT_INCONCLUSIVE,
    VERDICT_REFUTED,
    VERDICT_UNSUPPORTED,
    VERDICT_VERIFIED,
    make_result,
)


def verify_reasoning_chain(
    claim: dict[str, Any], resolved_verdicts: dict[str, str] | None
) -> dict[str, Any]:
    rc = claim.get("reasoning_chain")
    if not isinstance(rc, dict):
        return make_result(claim, VERDICT_UNSUPPORTED, REASON_MISSING_PAYLOAD, "reasoning_chain payload missing")
    if rc.get("review_scope", "") in ("external_domain", "subjective_judgment"):
        return make_result(
            claim,
            VERDICT_INCONCLUSIVE,
            REASON_HUMAN_REVIEW_REQUIRED,
            "reasoning chain requires external domain or subjective human review",
        )
    steps = rc.get("steps") or []
    conclusion_id = str(rc.get("conclusion_step_id", ""))
    if not steps or not conclusion_id.strip():
        return make_result(
            claim,
            VERDICT_UNSUPPORTED,
            REASON_EMPTY_REASONING_CHAIN,
            "reasoning chain missing steps or conclusion_step_id",
        )

    step_map: dict[str, dict[str, Any]] = {}
    for st in steps:
        sid = str(st.get("step_id", ""))
        if sid in step_map:
            return make_result(
                claim,
                VERDICT_REFUTED,
                REASON_DUPLICATE_STEP_ID,
                f"duplicate step_id: {sid}",
            )
        step_map[sid] = st
    step_ids = sorted(step_map.keys())

    if conclusion_id not in step_map:
        return make_result(
            claim,
            VERDICT_UNSUPPORTED,
            REASON_MISSING_CONCLUSION,
            f"conclusion_step_id not found: {conclusion_id}",
        )

    # Private CoT check (sorted step_id order).
    for sid in step_ids:
        st = step_map[sid]
        if (
            st.get("kind") == "private_cot"
            or bool(st.get("opaque_cot_blob", False))
            or not str(st.get("public_rationale", "")).strip()
        ):
            return make_result(
                claim,
                VERDICT_UNSUPPORTED,
                REASON_PRIVATE_COT_FORBIDDEN,
                f"step {sid} contains private/opaque CoT or lacks public_rationale",
            )

    # Deterministic 3-color DFS cycle detection over sorted step_ids.
    color: dict[str, int] = {sid: 0 for sid in step_ids}
    cycle_node = ""

    def dfs(sid: str) -> bool:
        nonlocal cycle_node
        color[sid] = 1
        for dep in sorted(step_map[sid].get("depends_on") or []):
            if dep not in step_map:
                continue
            if color[dep] == 1:
                cycle_node = dep
                return True
            if color[dep] == 0 and dfs(dep):
                return True
        color[sid] = 2
        return False

    for sid in step_ids:
        if color[sid] == 0 and dfs(sid):
            return make_result(
                claim,
                VERDICT_REFUTED,
                REASON_REASONING_CYCLE,
                f"circular reasoning dependency detected involving step {cycle_node}",
            )

    # Dangling premise check (sorted step_id order).
    for sid in step_ids:
        for dep in sorted(step_map[sid].get("depends_on") or []):
            if dep not in step_map:
                return make_result(
                    claim,
                    VERDICT_UNSUPPORTED,
                    REASON_DANGLING_PREMISE,
                    f"step {sid} references missing dependency {dep}",
                )

    # Collect ancestors reachable from conclusion_step_id.
    ancestors: set[str] = set()

    def collect(sid: str) -> None:
        if sid in ancestors:
            return
        ancestors.add(sid)
        for dep in step_map[sid].get("depends_on") or []:
            collect(dep)

    collect(conclusion_id)
    anc_ids = sorted(ancestors)

    first_unsupported = ""
    first_inconclusive = ""
    for sid in anc_ids:
        st = step_map[sid]
        if st.get("depends_on"):
            continue
        ev_ref = str(st.get("evidence_ref", ""))
        if st.get("kind") != "premise" or not ev_ref.strip():
            if not first_unsupported:
                first_unsupported = f"leaf step {sid} lacks grounded premise evidence_ref"
            continue
        ev_verdict = str(st.get("evidence_verdict", "")).strip()
        if not ev_verdict and resolved_verdicts and ev_ref in resolved_verdicts:
            ev_verdict = resolved_verdicts[ev_ref]
        if ev_verdict == VERDICT_REFUTED:
            return make_result(
                claim,
                VERDICT_REFUTED,
                REASON_REFUTED_PREMISE,
                f"premise {sid} relies on refuted evidence {ev_ref}",
            )
        if ev_verdict == VERDICT_VERIFIED:
            continue
        if ev_verdict == VERDICT_INCONCLUSIVE:
            if not first_inconclusive:
                first_inconclusive = f"premise {sid} relies on inconclusive evidence {ev_ref}"
        else:
            if not first_unsupported:
                first_unsupported = f"premise {sid} relies on unverified evidence {ev_ref}"

    if first_unsupported:
        return make_result(claim, VERDICT_UNSUPPORTED, REASON_UNVERIFIED_PREMISE, first_unsupported)
    if first_inconclusive:
        return make_result(claim, VERDICT_INCONCLUSIVE, REASON_INCONCLUSIVE_PREMISE, first_inconclusive)

    return make_result(
        claim,
        VERDICT_VERIFIED,
        REASON_OK_REASONING_CHAIN,
        f"public reasoning DAG verified ({len(anc_ids)} reachable steps)",
        str(len(anc_ids)),
    )

# Copyright 2026 Zoo Labs Foundation / Hanzo Industries.
# Licensed under the Apache License, Version 2.0.
"""CLI for pure-Python verification and Go <-> Python bit-identical parity checks."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .verifier import audit_suite


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Pure-Python stdlib verifier for inference-verify.v1 parity suites"
    )
    parser.add_argument(
        "--suite",
        required=True,
        help="Path to verification-suite.v1.json",
    )
    parser.add_argument(
        "--go-results",
        default=None,
        help="Optional path to Go results.json to assert exact cross-language parity",
    )
    args = parser.parse_args(argv)

    suite = json.loads(Path(args.suite).read_text(encoding="utf-8"))
    audit = audit_suite(suite)

    print(
        f"Python verifier audited {audit.total_cases} cases "
        f"({audit.golden_cases} golden + {audit.adversarial_cases} adversarial)"
    )
    print(f"  matched_expected  : {audit.matches_expected} / {audit.total_cases}")
    print(f"  audit_merkle_root : {audit.audit_merkle_root}")

    if audit.matches_expected != audit.total_cases:
        for r, c in zip(audit.results, suite["cases"]):
            exp_esc = bool(c.get("expected_fraud_escaped", False))
            if (
                r.verdict != c["expected_verdict"]
                or r.error_code != c["expected_error_code"]
                or r.fraud_escaped != exp_esc
            ):
                print(
                    f"MISMATCH {c['case_id']}: got ({r.verdict}, {r.error_code}, "
                    f"escaped={r.fraud_escaped}) want ({c['expected_verdict']}, "
                    f"{c['expected_error_code']}, escaped={exp_esc})",
                    file=sys.stderr,
                )
        return 1

    expected_root = suite.get("expected_audit_merkle_root")
    if expected_root and audit.audit_merkle_root != expected_root:
        print(
            f"MERKLE ROOT MISMATCH vs fixture: got {audit.audit_merkle_root} "
            f"want {expected_root}",
            file=sys.stderr,
        )
        return 1

    if args.go_results:
        go_res = json.loads(Path(args.go_results).read_text(encoding="utf-8"))
        go_root = go_res["parity_summary"]["audit_merkle_root"]
        if audit.audit_merkle_root != go_root:
            print(
                f"GO <-> PYTHON PARITY MISMATCH: py={audit.audit_merkle_root} "
                f"go={go_root}",
                file=sys.stderr,
            )
            return 1
        print(
            "PASS: 100.00% Go <-> Python bit-identical parity verified "
            f"({audit.total_cases}/{audit.total_cases} cases, audit_merkle_root={audit.audit_merkle_root})"
        )
    else:
        print("PASS: Python verifier 100.00% matched expected verdicts and audit_merkle_root")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

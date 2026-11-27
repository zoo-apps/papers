# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Command-line verifier for inference-net.v1 parity suites and benchmark reports."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .verifier import verify_parity_suite


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="infnet_verifier",
        description="Zero-dependency Python verifier for Zoo inference-net.v1",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_par = sub.add_parser("parity", help="Verify parity-suite.v1.json and cross-check Go results.json")
    p_par.add_argument("--suite", required=True, help="Path to fixtures/parity-suite.v1.json")
    p_par.add_argument("--go-results", default="", help="Optional path to results.json produced by Go")

    args = parser.parse_args(argv)

    suite = json.loads(Path(args.suite).read_text(encoding="utf-8"))
    verdicts, audit_root = verify_parity_suite(suite)

    mismatches = 0
    for case, vr in zip(suite["cases"], verdicts):
        ok = (
            vr.valid == case["expected_valid"]
            and vr.error_code == case["expected_error_code"]
            and vr.verdict_digest == case["expected_verdict_digest"]
        )
        if not ok:
            mismatches += 1
            print(
                f"MISMATCH {case['case_id']}: got (valid={vr.valid}, code={vr.error_code}, digest={vr.verdict_digest}) "
                f"want (valid={case['expected_valid']}, code={case['expected_error_code']}, digest={case['expected_verdict_digest']})",
                file=sys.stderr,
            )

    if audit_root != suite["audit_merkle_root"]:
        mismatches += 1
        print(
            f"MISMATCH audit_merkle_root: got {audit_root} want {suite['audit_merkle_root']}",
            file=sys.stderr,
        )

    if args.go_results:
        rep = json.loads(Path(args.go_results).read_text(encoding="utf-8"))
        if rep["audit_merkle_root"] != audit_root:
            mismatches += 1
            print(
                f"MISMATCH go results audit_merkle_root: got {rep['audit_merkle_root']} want {audit_root}",
                file=sys.stderr,
            )
        if rep.get("proves_scientific_truth") is not False or rep.get("authorizes_treasury_spend") is not False:
            mismatches += 1
            print("CONSTITUTIONAL LOCK VIOLATION in results.json", file=sys.stderr)
        if rep.get("total_privacy_leaks", -1) != 0 or rep.get("total_capacity_leaks", -1) != 0:
            mismatches += 1
            print("NONZERO LEAKS reported in results.json", file=sys.stderr)

    if mismatches > 0:
        print(f"python infnet_verifier FAILED: {mismatches} mismatch(es)", file=sys.stderr)
        return 1

    print(f"python infnet_verifier PASS: {len(verdicts)}/{len(suite['cases'])} bit-identical Go<->Python parity, audit_merkle_root={audit_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

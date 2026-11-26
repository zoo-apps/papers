# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation
"""CLI for independent Python 3.12 verification of DSO aggregation benchmark artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .verifier import verify_audit_trace, verify_results_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify dso-aggregation.v1 results.json and audit_trace.json")
    parser.add_argument("--results", required=True, help="Path to results.json")
    parser.add_argument("--trace", required=True, help="Path to audit_trace.json")
    args = parser.parse_args(argv)

    report = json.loads(Path(args.results).read_text(encoding="utf-8"))
    trace = json.loads(Path(args.trace).read_text(encoding="utf-8"))

    rep_summary = verify_results_report(report)
    tr_summary = verify_audit_trace(trace, expected_report_merkle=rep_summary["audit_merkle_root"])

    print("DSO Aggregation Independent Python 3.12 Audit Verification: PASS")
    print(f"  Cells Verified:              {rep_summary['cells_verified']}")
    print(f"  Corpus Papers:               {rep_summary['corpus_papers']}")
    print(f"  Audit Merkle Root (Go==Py):  {rep_summary['audit_merkle_root']}")
    print(f"  Ed25519 Signatures Verified: {tr_summary['ed25519_signatures_verified']}")
    print(f"  Aggregator Runs Verified:    {tr_summary['aggregator_runs_verified']}")
    print(f"  Trace Merkle Root (Go==Py):  {tr_summary['trace_merkle_root']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

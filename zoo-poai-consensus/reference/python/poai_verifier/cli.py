# Copyright 2026 Zoo Labs Foundation & Hanzo Industries.
# SPDX-License-Identifier: Apache-2.0
"""CLI for independent pure-Python verification of poai-transcript.v1 suites and Go parity."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .verifier import verify_parity_suite


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Independent pure-Python Proof-of-AI verifier (poai-transcript.v1)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_parity = sub.add_parser("parity", help="Verify Go-generated parity-suite.v1.json and audit_merkle_root")
    p_parity.add_argument("--suite", required=True, help="Path to parity-suite.v1.json")
    p_parity.add_argument("--go-results", required=False, help="Optional path to Go results.json to cross-check audit_merkle_root")

    args = parser.parse_args(argv)

    if args.cmd == "parity":
        suite_data = json.loads(Path(args.suite).read_text(encoding="utf-8"))
        ok, got_root, mismatches = verify_parity_suite(suite_data)
        if args.go_results:
            go_results = json.loads(Path(args.go_results).read_text(encoding="utf-8"))
            if go_results.get("audit_merkle_root") != got_root:
                ok = False
                mismatches.append(
                    f"results.json audit_merkle_root mismatch: python={got_root} go={go_results.get('audit_merkle_root')}"
                )
        if not ok:
            for msg in mismatches:
                print(f"FAIL: {msg}", file=sys.stderr)
            return 1
        n_cases = len(suite_data["cases"])
        print(f"python poai_verifier parity PASS: {n_cases}/{n_cases} cases bit-identical with Go")
        print(f"audit_merkle_root: {got_root}")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())

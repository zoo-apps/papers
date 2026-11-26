# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation

"""CLI entrypoint for Python 3.12 stdlib Evidence & Reasoning Verifier."""

from __future__ import annotations

import argparse
import json
import os
import sys

from .types import SCHEMA_VERSION
from .verifier import Verifier


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Zoo Thinking Chains Evidence & Reasoning Verifier (Python)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    for name in ("benchmark", "verify", "parity"):
        p = sub.add_parser(name)
        p.add_argument("--corpus", default="../../..", help="Path to zoo-apps/papers repository root")
        p.add_argument("--dataset", default="../dataset/benchmark-claims.v1.json", help="Path to ClaimBundle JSON")
        p.add_argument("--out", default="", help="Optional output path")
        p.add_argument("--seed", type=int, default=1352, help="Expected benchmark seed")
        if name == "parity":
            p.add_argument("--go-report", required=True, help="Path to Go benchmark JSON report")

    args = parser.parse_args(argv)
    corpus_root = os.path.abspath(args.corpus)
    with open(args.dataset, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    v = Verifier(corpus_root)

    if args.cmd == "benchmark":
        if args.seed and bundle.get("seed") != args.seed:
            print(f"seed mismatch: dataset has {bundle.get('seed')}, expected {args.seed}", file=sys.stderr)
            return 1
        report = v.run_benchmark(bundle, "python-3.12-stdlib")
        text = json.dumps(report, indent=2) + "\n"
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(text)
        else:
            sys.stdout.write(text)
        return 0

    if args.cmd == "verify":
        results, root = v.verify_bundle(bundle)
        out = {
            "schema_version": SCHEMA_VERSION,
            "bundle_id": bundle.get("bundle_id", ""),
            "audit_merkle_root": root,
            "results": results,
        }
        sys.stdout.write(json.dumps(out, indent=2) + "\n")
        return 0

    if args.cmd == "parity":
        with open(args.go_report, "r", encoding="utf-8") as f:
            go_report = json.load(f)
        py_report = v.run_benchmark(bundle, "python-3.12-stdlib")
        go_res = go_report["results"]
        py_res = py_report["results"]
        if len(go_res) != len(py_res):
            print(f"PARITY FAIL: result count mismatch Go={len(go_res)} Py={len(py_res)}", file=sys.stderr)
            return 1
        mismatches = 0
        for g, p in zip(go_res, py_res):
            if g != p:
                mismatches += 1
                print(f"MISMATCH on {g.get('claim_id')}: Go={g} vs Py={p}", file=sys.stderr)
        if mismatches > 0:
            print(f"PARITY FAIL: {mismatches}/{len(go_res)} claims differed", file=sys.stderr)
            return 1
        if go_report["audit_merkle_root"] != py_report["audit_merkle_root"]:
            print(
                f"PARITY FAIL: audit_merkle_root Go={go_report['audit_merkle_root']} Py={py_report['audit_merkle_root']}",
                file=sys.stderr,
            )
            return 1
        print(
            f"PARITY OK: {len(go_res)}/{len(go_res)} claims bit-identical | audit_merkle_root={py_report['audit_merkle_root']}"
        )
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())

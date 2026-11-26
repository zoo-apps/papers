#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reproducible benchmark harness producing results.json for zoo-apps/papers#10."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT_REF = Path(__file__).resolve().parent.parent
GO_DIR = ROOT_REF / "go"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run reproducible Experience Ledger benchmark.")
    parser.add_argument("--seed", type=int, default=1352)
    parser.add_argument("--out", default=str(ROOT_REF / "results.json"))
    args = parser.parse_args()

    # 1. Execute Go benchmark suite
    go_proc = subprocess.run(
        [
            "go",
            "run",
            "./cmd/xel-bench",
            "--papers-root",
            str(ROOT_REF.parent.parent),
            "--seed",
            str(args.seed),
        ],
        cwd=GO_DIR,
        capture_output=True,
        text=True,
        check=True,
    )
    go_bench = json.loads(go_proc.stdout)

    # 2. Execute cross-language Go vs Python permutation parity check
    parity_proc = subprocess.run(
        [sys.executable, str(ROOT_REF / "scripts" / "cross_verify.py")],
        cwd=ROOT_REF,
        capture_output=True,
        text=True,
        check=True,
    )
    parity = json.loads(parity_proc.stdout)

    results = {
        "schema_version": "zoo-experience-ledger/v1",
        "bounty": "zoo-apps/papers#10",
        "hip": "HIP-1352",
        "seed": args.seed,
        "cross_language_parity": parity,
        "benchmarks": go_bench,
    }
    Path(args.out).write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

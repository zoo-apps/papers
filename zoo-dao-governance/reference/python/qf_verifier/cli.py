# SPDX-License-Identifier: Apache-2.0
"""CLI entrypoint for independent Python QF Sybil simulator verification."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .verifier import verify_files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Independently recompute and audit Zoo DAO QF Sybil simulator artifacts."
    )
    parser.add_argument(
        "--results",
        type=Path,
        default=Path("../results.json"),
        help="Path to Go-generated results.json",
    )
    parser.add_argument(
        "--scenarios",
        type=Path,
        default=Path("../scenarios.json"),
        help="Path to Go-generated scenarios.json",
    )
    parser.add_argument(
        "--papers-root",
        type=Path,
        default=None,
        help="Optional path to zoo-apps/papers root to verify .tex SHA-256 digests on disk",
    )
    args = parser.parse_args(argv)

    report = verify_files(args.results, args.scenarios, papers_root=args.papers_root)
    print(f"verified:          {report.ok}")
    print(f"scenarios:         {report.scenarios_verified}")
    print(f"evaluations:       {report.evaluations_verified}")
    print(f"corpus_hash:       {report.corpus_hash}")
    print(f"governance_hash:   {report.governance_hash}")
    print(f"eval_merkle_root:  {report.eval_merkle_root}")
    print(f"audit_merkle_root: {report.audit_merkle_root}")
    if not report.ok:
        for err in report.errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

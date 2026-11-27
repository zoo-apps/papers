# SPDX-License-Identifier: Apache-2.0
"""CLI entry point for pure-Python attribution-rep.v1 verifier."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .verifier import verify_suite


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="attrrep_py",
        description="Clean-room pure-Python verifier for attribution-rep.v1 (HIP-1352)",
    )
    parser.add_argument("--suite", required=True, help="Path to attribution-suite.v1.json")
    parser.add_argument("--out", default="", help="Optional path to write full JSON verification report")
    parser.add_argument("--summary", action="store_true", help="Print compact summary JSON to stdout")
    args = parser.parse_args(argv)

    bundle = json.loads(Path(args.suite).read_text(encoding="utf-8"))
    report = verify_suite(bundle)

    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if args.summary:
        summary = {
            "schema_version": report["schema_version"],
            "spec_version": report["spec_version"],
            "suite_name": report["suite_name"],
            "audit_merkle_root": report["audit_merkle_root"],
            "total_contributions": report["total_contributions"],
            "accepted_contributions": report["accepted_contributions"],
            "rejected_contributions": report["rejected_contributions"],
            "total_attestations": report["total_attestations"],
            "accepted_attestations": report["accepted_attestations"],
            "advisory_attestations": report["advisory_attestations"],
            "rejected_attestations": report["rejected_attestations"],
            "total_intrinsic_micro": report["total_intrinsic_micro"],
            "total_attributed_micro": report["total_attributed_micro"],
            "conservation_exact": report["conservation_exact"],
            "adversarial_passed": report["adversarial_passed"],
            "adversarial_total": report["adversarial_total"],
            "collusion_findings": len(report["collusion_findings"]),
        }
        print(json.dumps(summary, indent=2))
    else:
        print(json.dumps(report, indent=2))

    if not report["conservation_exact"] or report["adversarial_passed"] != report["adversarial_total"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

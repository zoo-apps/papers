# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.

"""Command-line verifier for forkable-org.v1 canonical fixtures."""

import argparse
import json
import sys
from pathlib import Path

from .canonical import canonical_json_bytes
from .verifier import verify_suite


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a forkable-org.v1 canonical fixture.")
    parser.add_argument(
        "--fixture",
        default="../fixtures/fork-exchange-suite.v1.json",
        help="Path to fork-exchange-suite.v1.json",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Emit compact canonical JSON for bit-exact Go/Python comparison",
    )
    args = parser.parse_args()

    fixture_path = Path(args.fixture)
    suite = json.loads(fixture_path.read_text(encoding="utf-8"))
    report = verify_suite(suite)

    if args.compact:
        sys.stdout.write(canonical_json_bytes(report).decode("utf-8") + "\n")
    else:
        sys.stdout.write(json.dumps(report, indent=2) + "\n")

    if not report["all_workflow_passed"] or not report["all_adversarial_matched"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

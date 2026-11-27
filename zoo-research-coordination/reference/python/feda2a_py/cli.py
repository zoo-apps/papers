# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.

"""CLI entrypoint for zero-dependency pure-Python federated-a2a.v1 verifier."""

import argparse
import json
import sys
from pathlib import Path

from .canonical import canonical_json
from .verifier import verify_suite


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a federated-a2a.v1 exchange suite fixture.")
    parser.add_argument(
        "--fixture",
        default="../fixtures/a2a-exchange-suite.v1.json",
        help="Path to federated-a2a.v1 JSON fixture",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Emit canonical compact JSON matching Go a2a-verify --compact byte-for-byte",
    )
    args = parser.parse_args()

    fixture_path = Path(args.fixture)
    try:
        suite = json.loads(fixture_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"failed to read fixture {fixture_path}: {exc}", file=sys.stderr)
        return 2

    report = verify_suite(suite)
    if args.compact:
        print(canonical_json(report).decode("utf-8"))
    else:
        print(json.dumps(report, indent=2))

    if not (
        report["all_stages_valid"]
        and report["all_adversarial_pass"]
        and report["wire_audit"]["zero_boundary_leakage"]
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

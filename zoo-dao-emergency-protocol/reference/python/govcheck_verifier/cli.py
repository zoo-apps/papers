# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.

"""CLI entrypoint for independent Python verification of constitutional-gov.v1."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .verifier import VerificationError, verify_results_bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify constitutional-gov.v1 results.json and OPA Rego v1 bundle")
    parser.add_argument("--in", dest="results_path", default="../results.json", help="Path to results.json")
    parser.add_argument("--rego-dir", default="../rego", help="Path to rego/ policy bundle directory")
    args = parser.parse_args(argv)

    try:
        summary = verify_results_bundle(Path(args.results_path), Path(args.rego_dir))
    except (VerificationError, ValueError, KeyError, FileNotFoundError) as exc:
        print(f"VERIFICATION FAILED: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({"status": "VERIFIED_OK", **summary}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

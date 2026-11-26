# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation and Contributors

"""Zero-dependency CLI for Thinking Chains canonical receipt verification."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .canonical import CanonicalError, parse_strict_json
from .verify import (
    VerificationError,
    canonical_receipt_hash,
    compute_provenance,
    load_policy,
    verify_batch,
    verify_receipt_bytes,
)


def _cmd_verify_batch(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    raw = Path(args.fixture).read_bytes()
    try:
        data = parse_strict_json(raw)
    except CanonicalError as exc:
        print(json.dumps({"ok": False, "error_code": exc.code, "error": exc.message}))
        return 1

    receipts = data["jobs"] if isinstance(data, dict) and "jobs" in data else data
    t0 = time.perf_counter()
    try:
        results = verify_batch(receipts, policy)
    except VerificationError as exc:
        print(json.dumps({"ok": False, "error_code": exc.code, "error": exc.message}))
        return 1
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    output = {
        "ok": True,
        "implementation": "python-stdlib",
        "count": len(results),
        "elapsed_ms": round(elapsed_ms, 3),
        "receipts": [
            {
                "job_id": r.job_id,
                "canonical_receipt_hash": r.canonical_receipt_hash,
                "provenance_root": r.provenance_root,
                "valid_attestations": r.valid_attestation_count,
            }
            for r in results
        ],
    }
    print(json.dumps(output, indent=2))
    return 0


def _cmd_verify_one(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    raw = Path(args.receipt).read_bytes()
    try:
        res = verify_receipt_bytes(raw, policy)
    except VerificationError as exc:
        print(json.dumps({"ok": False, "error_code": exc.code, "error": exc.message}))
        return 1
    print(
        json.dumps(
            {
                "ok": True,
                "implementation": "python-stdlib",
                "job_id": res.job_id,
                "canonical_receipt_hash": res.canonical_receipt_hash,
                "provenance_root": res.provenance_root,
                "valid_attestations": res.valid_attestation_count,
            },
            indent=2,
        )
    )
    return 0


def _cmd_verify_adversarial(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy)
    suite = json.loads(Path(args.suite).read_text(encoding="utf-8"))
    cases = suite["cases"]
    passed = 0
    report = []
    for case in cases:
        case_id = case["case_id"]
        expected_code = case["expected_error_code"]
        kind = case.get("kind", "single")
        actual_code = None
        if kind == "raw_json":
            try:
                verify_receipt_bytes(case["raw_json"].encode("utf-8"), policy)
            except VerificationError as exc:
                actual_code = exc.code
        elif kind == "batch":
            try:
                verify_batch(case["receipts"], policy)
            except VerificationError as exc:
                actual_code = exc.code
        else:
            raw_bytes = json.dumps(case["receipt"]).encode("utf-8")
            try:
                verify_receipt_bytes(raw_bytes, policy)
            except VerificationError as exc:
                actual_code = exc.code
        ok = actual_code == expected_code
        if ok:
            passed += 1
        report.append(
            {
                "case_id": case_id,
                "expected": expected_code,
                "actual": actual_code,
                "rejected_as_expected": ok,
            }
        )
    out = {
        "ok": passed == len(cases),
        "implementation": "python-stdlib",
        "total": len(cases),
        "passed": passed,
        "cases": report,
    }
    print(json.dumps(out, indent=2))
    return 0 if passed == len(cases) else 1


def _cmd_hash(args: argparse.Namespace) -> int:
    raw = Path(args.receipt).read_bytes()
    rec = parse_strict_json(raw)
    prov = compute_provenance(rec)
    h = canonical_receipt_hash(rec)
    print(
        json.dumps(
            {
                "job_id": rec["job_id"],
                "canonical_receipt_hash": h,
                "provenance_root": prov["provenance_root"],
            },
            indent=2,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tc-verify-py",
        description="Thinking Chains Canonical Receipt Verifier (Pure Python 3.12 stdlib)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_batch = sub.add_parser("verify-batch", help="Verify a batch fixture JSON file")
    p_batch.add_argument("--policy", required=True)
    p_batch.add_argument("--fixture", required=True)
    p_batch.set_defaults(func=_cmd_verify_batch)

    p_one = sub.add_parser("verify", help="Verify a single receipt JSON file")
    p_one.add_argument("--policy", required=True)
    p_one.add_argument("--receipt", required=True)
    p_one.set_defaults(func=_cmd_verify_one)

    p_adv = sub.add_parser("verify-adversarial", help="Run adversarial tamper/policy suite")
    p_adv.add_argument("--policy", required=True)
    p_adv.add_argument("--suite", required=True)
    p_adv.set_defaults(func=_cmd_verify_adversarial)

    p_hash = sub.add_parser("hash", help="Compute canonical receipt hash and provenance root")
    p_hash.add_argument("--receipt", required=True)
    p_hash.set_defaults(func=_cmd_hash)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

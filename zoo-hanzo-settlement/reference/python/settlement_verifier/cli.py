# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""CLI entrypoint for the pure Python settlement-receipt.v1 verifier."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .verifier import verify_trace_bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a settlement-receipt.v1 trace bundle.")
    parser.add_argument(
        "--trace",
        default="../fixtures/settlement-trace.v1.json",
        help="Path to settlement-receipt.v1 trace JSON file",
    )
    args = parser.parse_args(argv)

    bundle = json.loads(Path(args.trace).read_text(encoding="utf-8"))
    report = verify_trace_bundle(bundle)
    bs = report["balance_sheet"]
    summary = {
        "verifier": report["verifier"],
        "protocol": report["protocol"],
        "schema_version": report["schema_version"],
        "total_cases": report["total_cases"],
        "accepted_cases": report["accepted_cases"],
        "rejected_cases": report["rejected_cases"],
        "matched_count": report["matched_count"],
        "all_matched": report["all_matched"],
        "conservation_exact": report["conservation_exact"],
        "audit_merkle_root": report["audit_merkle_root"],
        "audit_root_matched": report["audit_root_matched"],
        "authorized_receipts": bs["authorized_receipt_count"],
        "total_finalized_escrow": bs["total_finalized_escrow_micro_zoo"],
        "total_authorized": bs["total_authorized_payout_micro_zoo"],
        "conservation_fund": bs["conservation_fund_micro_zoo"],
        "protocol_fee_pool": bs["protocol_fee_pool_micro_zoo"],
        "total_payer_refunds": bs["total_payer_refunds_micro_zoo"],
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    if not (report["all_matched"] and report["conservation_exact"] and report["audit_root_matched"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

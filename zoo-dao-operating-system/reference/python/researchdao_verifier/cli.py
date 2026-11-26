# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation & Open ResearchDAO Contributors.

"""CLI entrypoint for independent Python 3.12 ResearchDAO OS WAL verification."""

from __future__ import annotations

import argparse
import json
import sys

from .verifier import SPEC_VERSION, replay_from_latest_checkpoint, replay_full


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Independent pure-stdlib ResearchDAO OS v1 WAL verifier")
    parser.add_argument("--wal-dir", required=True, help="Directory containing genesis.json, events.jsonl, checkpoints/")
    parser.add_argument("--expect-state-root", default="", help="Optional expected state_root_hash for cross-language parity check")
    parser.add_argument("--expect-audit-root", default="", help="Optional expected audit_merkle_root for cross-language parity check")
    args = parser.parse_args(argv)

    m_full = replay_full(args.wal_dir)
    sr_full, ar_full = m_full.roots()

    m_delta, cp_seq = replay_from_latest_checkpoint(args.wal_dir)
    sr_delta, ar_delta = m_delta.roots()

    bit_identical = (sr_full == sr_delta) and (ar_full == ar_delta)
    parity_ok = bit_identical
    if args.expect_state_root and sr_full != args.expect_state_root:
        parity_ok = False
    if args.expect_audit_root and ar_full != args.expect_audit_root:
        parity_ok = False

    out = {
        "spec_version": SPEC_VERSION,
        "verifier": "python-3.12-stdlib",
        "total_events": m_full.state["seq"],
        "checkpoint_seq": cp_seq,
        "full_state_root_hash": sr_full,
        "delta_state_root_hash": sr_delta,
        "full_audit_merkle_root": ar_full,
        "delta_audit_merkle_root": ar_delta,
        "checkpoint_delta_bit_identical": bit_identical,
        "cross_language_parity_ok": parity_ok,
    }
    print(json.dumps(out, indent=2))
    return 0 if parity_ok else 2


if __name__ == "__main__":
    sys.exit(main())

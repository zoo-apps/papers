# SPDX-License-Identifier: Apache-2.0
"""CLI matching Go xel-replay for independent verification and permutation checking."""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

from .replay import replay


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="xel-replay-py")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_rep = sub.add_parser("replay")
    p_rep.add_argument("--bundle", required=True)
    p_rep.add_argument("--out", default="")

    p_perm = sub.add_parser("permute-check")
    p_perm.add_argument("--bundle", required=True)
    p_perm.add_argument("--perms", type=int, default=20)
    p_perm.add_argument("--seed", type=int, default=1352)

    args = parser.parse_args(argv)
    bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    policy = bundle["policy"]
    events = bundle["events"]

    if args.cmd == "replay":
        state = replay(policy, events)
        rendered = json.dumps(state, indent=2) + "\n"
        if args.out:
            Path(args.out).write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        return 0

    if args.cmd == "permute-check":
        base = replay(policy, events)
        rev = replay(policy, list(reversed(events)))
        if rev["state_root_hash"] != base["state_root_hash"]:
            sys.stderr.write(
                f"DIVERGENCE on reverse: {rev['state_root_hash']} != {base['state_root_hash']}\n"
            )
            return 1
        rng = random.Random(args.seed)
        for p in range(args.perms):
            shuf = list(events)
            rng.shuffle(shuf)
            st = replay(policy, shuf)
            if st["state_root_hash"] != base["state_root_hash"]:
                sys.stderr.write(
                    f"DIVERGENCE on perm {p}: {st['state_root_hash']} != {base['state_root_hash']}\n"
                )
                return 1
        summary = {
            "status": "CONVERGED",
            "permutations_tested": args.perms + 2,
            "state_root_hash": base["state_root_hash"],
            "active_merkle_root": base["commitment"]["active_merkle_root"],
            "active_entries": len(base["active_event_ids"]),
            "total_entries": len(base["commitment"]["entry_states"]),
            "conflicts": len(base["commitment"]["conflicts"]),
            "rejected_events": len(base["commitment"]["rejected_events"]),
        }
        sys.stdout.write(json.dumps(summary, indent=2) + "\n")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())

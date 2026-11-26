#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Cross-language Go vs Python bit-exact permutation convergence verifier."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT_REF = Path(__file__).resolve().parent.parent
GO_DIR = ROOT_REF / "go"
PY_DIR = ROOT_REF / "python"
BUNDLE_PATH = ROOT_REF / "fixtures" / "corpus_events.json"
EXPECTED_PATH = ROOT_REF / "fixtures" / "expected_state.json"


def run_cmd(cmd: list[str], cwd: Path, env: dict | None = None) -> str:
    proc = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, check=True)
    return proc.stdout


def main() -> int:
    expected = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))

    # 1. Run Go replay & 22-order permutation check (forward + reverse + 20 random)
    go_replay_out = run_cmd(
        ["go", "run", "./cmd/xel-replay", "replay", "--bundle", str(BUNDLE_PATH)],
        cwd=GO_DIR,
    )
    go_state = json.loads(go_replay_out)

    go_perm_out = run_cmd(
        [
            "go",
            "run",
            "./cmd/xel-replay",
            "permute-check",
            "--bundle",
            str(BUNDLE_PATH),
            "--perms",
            "20",
            "--seed",
            "1352",
        ],
        cwd=GO_DIR,
    )
    go_perm = json.loads(go_perm_out)

    # 2. Run independent Python replay & 22-order permutation check (forward + reverse + 20 random)
    import os

    py_env = dict(os.environ)
    py_env["PYTHONPATH"] = str(PY_DIR)

    py_replay_out = run_cmd(
        [sys.executable, "-m", "experience_ledger.cli", "replay", "--bundle", str(BUNDLE_PATH)],
        cwd=PY_DIR,
        env=py_env,
    )
    py_state = json.loads(py_replay_out)

    py_perm_out = run_cmd(
        [
            sys.executable,
            "-m",
            "experience_ledger.cli",
            "permute-check",
            "--bundle",
            str(BUNDLE_PATH),
            "--perms",
            "20",
            "--seed",
            "1352",
        ],
        cwd=PY_DIR,
        env=py_env,
    )
    py_perm = json.loads(py_perm_out)

    # 3. Assert 100% bit-identical parity across Go, Python, and Expected fixture
    checks = [
        ("go_vs_py_state_root", go_state["state_root_hash"] == py_state["state_root_hash"]),
        ("go_vs_expected_state_root", go_state["state_root_hash"] == expected["state_root_hash"]),
        (
            "go_vs_py_active_merkle_root",
            go_state["commitment"]["active_merkle_root"] == py_state["commitment"]["active_merkle_root"],
        ),
        ("go_vs_py_commitment_exact", go_state["commitment"] == py_state["commitment"]),
        ("go_perm_converged", go_perm["status"] == "CONVERGED" and go_perm["permutations_tested"] == 22),
        ("py_perm_converged", py_perm["status"] == "CONVERGED" and py_perm["permutations_tested"] == 22),
        ("go_vs_py_perm_root", go_perm["state_root_hash"] == py_perm["state_root_hash"]),
    ]

    failed = [name for name, ok in checks if not ok]
    report = {
        "cross_language_parity": "PASS" if not failed else "FAIL",
        "failed_checks": failed,
        "go_state_root_hash": go_state["state_root_hash"],
        "python_state_root_hash": py_state["state_root_hash"],
        "active_merkle_root": go_state["commitment"]["active_merkle_root"],
        "go_permutations_tested": go_perm["permutations_tested"],
        "python_permutations_tested": py_perm["permutations_tested"],
        "total_events_in_corpus": len(json.loads(BUNDLE_PATH.read_text(encoding="utf-8"))["events"]),
        "active_entries": len(go_state["active_event_ids"]),
        "total_entries": len(go_state["commitment"]["entry_states"]),
        "conflicts": len(go_state["commitment"]["conflicts"]),
        "rejected_events": len(go_state["commitment"]["rejected_events"]),
    }
    print(json.dumps(report, indent=2))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())

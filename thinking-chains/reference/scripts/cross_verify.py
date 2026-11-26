#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation and Contributors

"""Cross-implementation differential verifier: Go stdlib vs Python 3.12 stdlib.

Proves bit-identical canonical receipt hashes and provenance roots across all 100
jobs in fixtures/jobs_100.json, plus 100% rejection parity across all 31 cases
in fixtures/adversarial_suite.json.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REF_DIR = SCRIPT_DIR.parent
GO_DIR = REF_DIR / "go"
PY_DIR = REF_DIR / "python"
FIXTURES_DIR = REF_DIR / "fixtures"


def _run_json(cmd: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> dict:
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Command failed ({proc.returncode}): {' '.join(cmd)}\n"
            f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    return json.loads(proc.stdout)


def main() -> int:
    policy = FIXTURES_DIR / "policy.json"
    jobs_100 = FIXTURES_DIR / "jobs_100.json"
    expected_hashes = json.loads((FIXTURES_DIR / "expected_hashes_100.json").read_text(encoding="utf-8"))
    adv_suite = FIXTURES_DIR / "adversarial_suite.json"

    with tempfile.TemporaryDirectory() as tmpdir:
        go_bin = Path(tmpdir) / "tc-verify"
        subprocess.run(
            ["go", "build", "-o", str(go_bin), "./cmd/tc-verify"],
            cwd=GO_DIR,
            check=True,
        )

        go_batch = _run_json(
            [str(go_bin), "verify-batch", "--policy", str(policy), "--fixture", str(jobs_100)]
        )
        py_batch = _run_json(
            [
                sys.executable,
                "-m",
                "tc_receipt.cli",
                "verify-batch",
                "--policy",
                str(policy),
                "--fixture",
                str(jobs_100),
            ],
            cwd=PY_DIR,
        )

        assert go_batch["ok"] is True and py_batch["ok"] is True
        assert go_batch["count"] == 100 and py_batch["count"] == 100

        identical_hashes = 0
        identical_roots = 0
        for idx, (g, p, exp) in enumerate(
            zip(go_batch["receipts"], py_batch["receipts"], expected_hashes["entries"])
        ):
            if (
                g["job_id"] != p["job_id"]
                or g["job_id"] != exp["job_id"]
                or g["canonical_receipt_hash"] != p["canonical_receipt_hash"]
                or g["canonical_receipt_hash"] != exp["canonical_receipt_hash"]
            ):
                raise AssertionError(
                    f"Canonical receipt hash mismatch at index {idx} ({exp['job_id']}): "
                    f"go={g['canonical_receipt_hash']} py={p['canonical_receipt_hash']} exp={exp['canonical_receipt_hash']}"
                )
            identical_hashes += 1
            if (
                g["provenance_root"] != p["provenance_root"]
                or g["provenance_root"] != exp["provenance_root"]
            ):
                raise AssertionError(
                    f"Provenance root mismatch at index {idx} ({exp['job_id']}): "
                    f"go={g['provenance_root']} py={p['provenance_root']} exp={exp['provenance_root']}"
                )
            identical_roots += 1

        go_adv = _run_json(
            [str(go_bin), "verify-adversarial", "--policy", str(policy), "--suite", str(adv_suite)]
        )
        py_adv = _run_json(
            [
                sys.executable,
                "-m",
                "tc_receipt.cli",
                "verify-adversarial",
                "--policy",
                str(policy),
                "--suite",
                str(adv_suite),
            ],
            cwd=PY_DIR,
        )

        assert go_adv["ok"] is True and py_adv["ok"] is True
        assert go_adv["total"] == py_adv["total"]
        assert go_adv["passed"] == go_adv["total"]
        assert py_adv["passed"] == py_adv["total"]

        for gc, pc in zip(go_adv["cases"], py_adv["cases"]):
            if gc["case_id"] != pc["case_id"] or gc["actual"] != pc["actual"]:
                raise AssertionError(
                    f"Adversarial error-code drift on {gc['case_id']}: "
                    f"go={gc['actual']} py={pc['actual']}"
                )

    summary = {
        "cross_implementation_parity": "PASS",
        "jobs_verified": 100,
        "identical_canonical_receipt_hashes": identical_hashes,
        "identical_provenance_roots": identical_roots,
        "adversarial_cases_total": go_adv["total"],
        "adversarial_cases_rejected_go": go_adv["passed"],
        "adversarial_cases_rejected_python": py_adv["passed"],
        "error_code_parity": "100%",
        "go_batch_elapsed_ms": go_batch["elapsed_ms"],
        "python_batch_elapsed_ms": py_batch["elapsed_ms"],
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

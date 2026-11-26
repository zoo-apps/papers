#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation and Contributors

"""Reproducible benchmark suite for Thinking Chains canonical receipts.

Measures:
  1. 100-job canonical fixture: canonical hashing, provenance reconstruction,
     and full independent verification in both Go stdlib and Python 3.12 stdlib.
  2. 1,000-job replay-free stress run in both Go and Python.
  3. Negative Regimes:
     A. Giant inline artifact payloads (1 MiB/job) vs content-addressed SHA-256 hashes.
     B. Naive O(N) full-list provenance recomputation vs O(log N) RFC 6962 inclusion proofs.
     C. Pure-Python stdlib Ed25519 vs Go stdlib crypto/ed25519 verification cost.

Writes structured output to thinking-chains/reference/results.json.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
REF_DIR = SCRIPT_DIR.parent
GO_DIR = REF_DIR / "go"
PY_DIR = REF_DIR / "python"
FIXTURES_DIR = REF_DIR / "fixtures"

sys.path.insert(0, str(PY_DIR))
sys.path.insert(0, str(SCRIPT_DIR))

from tc_receipt.canonical import canonical_json, parse_strict_json
from tc_receipt.merkle import build_inclusion_proof, merkle_root, verify_inclusion_proof
from tc_receipt.verify import (
    canonical_receipt_hash,
    compute_provenance,
    load_policy,
    verify_batch,
)
import generate_fixtures


def _summarize(samples_us: list[float], job_count: int) -> dict[str, Any]:
    med_us = statistics.median(samples_us)
    mean_us = statistics.mean(samples_us)
    sorted_s = sorted(samples_us)
    p95_idx = min(len(sorted_s) - 1, int(0.95 * len(sorted_s)))
    p95_us = sorted_s[p95_idx]
    throughput = job_count / (med_us / 1_000_000.0) if med_us > 0 else 0.0
    return {
        "samples_us": [round(x, 2) for x in samples_us],
        "median_ms": round(med_us / 1000.0, 3),
        "mean_ms": round(mean_us / 1000.0, 3),
        "p95_ms": round(p95_us / 1000.0, 3),
        "per_job_median_us": round(med_us / job_count, 2),
        "jobs_per_sec": round(throughput, 1),
    }


def _bench_python(jobs: list[dict[str, Any]], policy: dict[str, Any], iterations: int) -> dict[str, Any]:
    canon_us: list[float] = []
    prov_us: list[float] = []
    verify_us: list[float] = []

    for _ in range(iterations):
        t0 = time.perf_counter()
        for j in jobs:
            canonical_receipt_hash(j)
        canon_us.append((time.perf_counter() - t0) * 1_000_000.0)

        t1 = time.perf_counter()
        for j in jobs:
            compute_provenance(j)
        prov_us.append((time.perf_counter() - t1) * 1_000_000.0)

        t2 = time.perf_counter()
        verify_batch(jobs, policy)
        verify_us.append((time.perf_counter() - t2) * 1_000_000.0)

    return {
        "implementation": "python-stdlib",
        "job_count": len(jobs),
        "iterations": iterations,
        "canonical_hash": _summarize(canon_us, len(jobs)),
        "provenance_reconstruct": _summarize(prov_us, len(jobs)),
        "full_verify": _summarize(verify_us, len(jobs)),
    }


def _bench_go(go_bin: Path, policy_path: Path, fixture_path: Path, iterations: int) -> dict[str, Any]:
    proc = subprocess.run(
        [
            str(go_bin),
            "bench",
            "--policy",
            str(policy_path),
            "--fixture",
            str(fixture_path),
            "--iterations",
            str(iterations),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    raw = json.loads(proc.stdout)
    n = raw["job_count"]
    return {
        "implementation": "go-stdlib",
        "job_count": n,
        "iterations": iterations,
        "canonical_hash": _summarize(raw["canonical_hash_us"], n),
        "provenance_reconstruct": _summarize(raw["provenance_us"], n),
        "full_verify": _summarize(raw["full_verify_us"], n),
    }


def _build_1000_job_stress_fixture(
    jobs_100: list[dict[str, Any]],
    verifier_seeds: dict[str, bytes],
) -> list[dict[str, Any]]:
    """Expand the 100-job fixture to 1,000 unique replay-free signed receipts."""
    stress_jobs: list[dict[str, Any]] = []
    for batch_idx in range(10):
        for j_idx, base in enumerate(jobs_100):
            global_idx = batch_idx * 100 + j_idx
            if batch_idx == 0:
                stress_jobs.append(copy.deepcopy(base))
                continue
            r = copy.deepcopy(base)
            r["job_id"] = f"tc-stress-{global_idx + 1:04d}-{hashlib.sha256(str(global_idx).encode()).hexdigest()[:8]}"
            r["nonce"] = hashlib.sha256(f"stress:13520:nonce:{global_idx}".encode()).hexdigest()
            r["settlement"]["intent_id"] = hashlib.sha256(
                f"stress:13520:intent:{global_idx}".encode()
            ).hexdigest()
            r["settlement"]["settled_at_height"] = 1352000 + global_idx
            v_pairs = [(a["verifier_id"], a["verifier_role"]) for a in base["attestations"]]
            r = generate_fixtures._sign_receipt(
                r,
                v_pairs,
                verifier_seeds,
                r["settlement"]["settled_at_unix"] + 5,
            )
            stress_jobs.append(r)
    return stress_jobs


def _negative_regime_inline_payloads(jobs_100: list[dict[str, Any]]) -> dict[str, Any]:
    """Negative Regime A: Content-addressed 32-byte hashes vs 256 KiB inline evidence blobs."""
    blob_size = 256 * 1024  # 256 KiB simulated inline prose/trace per job (25.6 MiB for 100 jobs)
    inline_blob = "X" * blob_size

    # Content-addressed baseline (actual canonical receipts).
    t0 = time.perf_counter()
    ca_bytes = 0
    for j in jobs_100:
        c = canonical_json(j)
        ca_bytes += len(c)
        hashlib.sha256(c).digest()
    ca_ms = (time.perf_counter() - t0) * 1000.0

    # Naive inline-payload anti-pattern.
    inline_jobs = []
    for j in jobs_100:
        inj = copy.deepcopy(j)
        inj["inline_evidence_blob"] = inline_blob
        inline_jobs.append(inj)

    t1 = time.perf_counter()
    in_bytes = 0
    for j in inline_jobs:
        c = canonical_json(j)
        in_bytes += len(c)
        hashlib.sha256(c).digest()
    in_ms = (time.perf_counter() - t1) * 1000.0

    return {
        "regime": "inline_256kib_payload_vs_content_addressed_hash",
        "job_count": len(jobs_100),
        "inline_blob_bytes_per_job": blob_size,
        "content_addressed_total_bytes": ca_bytes,
        "inline_total_bytes": in_bytes,
        "wire_size_blowup_factor": round(in_bytes / ca_bytes, 2),
        "content_addressed_hash_ms": round(ca_ms, 3),
        "inline_hash_ms": round(in_ms, 3),
        "latency_slowdown_factor": round(in_ms / ca_ms, 2) if ca_ms > 0 else 0.0,
    }


def _negative_regime_merkle_vs_linear() -> dict[str, Any]:
    """Negative Regime B: O(N) naive linear provenance recomputation vs O(log N) Merkle inclusion proof."""
    rows = []
    for n in (16, 256, 4096):
        leaves = [
            canonical_json({"artifact_id": f"art-{i:04d}", "sha256": hashlib.sha256(f"a:{i}".encode()).hexdigest()})
            for i in range(n)
        ]
        target_idx = n // 2
        root = merkle_root("evidence", leaves)
        proof = build_inclusion_proof("evidence", leaves, target_idx)

        # Measure O(log N) single-item inclusion verification (200 trials).
        trials = 200
        t0 = time.perf_counter()
        for _ in range(trials):
            assert verify_inclusion_proof(proof, leaves[target_idx], root)
        merkle_us = ((time.perf_counter() - t0) * 1_000_000.0) / trials

        # Measure O(N) full linear recomputation (10 trials).
        lin_trials = 10
        t1 = time.perf_counter()
        for _ in range(lin_trials):
            assert merkle_root("evidence", leaves) == root
        linear_us = ((time.perf_counter() - t1) * 1_000_000.0) / lin_trials

        rows.append(
            {
                "artifact_count": n,
                "merkle_proof_steps": len(proof.steps),
                "merkle_proof_bytes": len(proof.steps) * 32,
                "linear_payload_bytes": sum(len(x) for x in leaves),
                "merkle_verify_us": round(merkle_us, 2),
                "linear_recompute_us": round(linear_us, 2),
                "speedup_factor": round(linear_us / merkle_us, 2) if merkle_us > 0 else 0.0,
            }
        )
    return {
        "regime": "naive_linear_recompute_vs_merkle_inclusion_proof",
        "scales": rows,
    }


def main() -> int:
    policy_path = FIXTURES_DIR / "policy.json"
    jobs_100_path = FIXTURES_DIR / "jobs_100.json"
    policy = load_policy(policy_path)
    jobs_100 = parse_strict_json(jobs_100_path.read_bytes())["jobs"]
    _, verifier_seeds = generate_fixtures._build_policy()

    go_version = subprocess.run(
        ["go", "version"], capture_output=True, text=True, check=True
    ).stdout.strip()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        go_bin = tmp / "tc-verify"
        subprocess.run(
            ["go", "build", "-o", str(go_bin), "./cmd/tc-verify"],
            cwd=GO_DIR,
            check=True,
        )

        print("Benchmarking 100-job fixture (Go x20, Python x5)...", flush=True)
        go_100 = _bench_go(go_bin, policy_path, jobs_100_path, iterations=20)
        py_100 = _bench_python(jobs_100, policy, iterations=5)

        print("Building 1,000-job unique stress fixture...", flush=True)
        stress_jobs = _build_1000_job_stress_fixture(jobs_100, verifier_seeds)
        stress_path = tmp / "jobs_1000_stress.json"
        stress_path.write_text(
            json.dumps({"jobs": stress_jobs}),
            encoding="utf-8",
        )

        print("Benchmarking 1,000-job stress run (Go x5, Python x1)...", flush=True)
        go_1000 = _bench_go(go_bin, policy_path, stress_path, iterations=5)
        py_1000 = _bench_python(stress_jobs, policy, iterations=1)

    print("Running negative regime benchmarks...", flush=True)
    neg_inline = _negative_regime_inline_payloads(jobs_100)
    neg_merkle = _negative_regime_merkle_vs_linear()

    go_vs_py_ratio = round(
        py_100["full_verify"]["median_ms"] / go_100["full_verify"]["median_ms"], 2
    )

    results = {
        "benchmark_version": "zoo.thinking-chains.benchmark.v1",
        "seed": 1352,
        "environment": {
            "os": platform.platform(),
            "arch": platform.machine(),
            "cpu_count": os.cpu_count(),
            "go_version": go_version,
            "python_version": platform.python_version(),
        },
        "fixture_100_jobs": {
            "go": go_100,
            "python": py_100,
            "go_speedup_full_verify_x": go_vs_py_ratio,
        },
        "stress_1000_jobs": {
            "go": go_1000,
            "python": py_1000,
            "go_speedup_full_verify_x": round(
                py_1000["full_verify"]["median_ms"] / go_1000["full_verify"]["median_ms"], 2
            ),
        },
        "negative_regimes": {
            "inline_payload_vs_content_addressed": neg_inline,
            "linear_provenance_vs_merkle_inclusion": neg_merkle,
            "pure_python_ed25519_vs_compiled_go": {
                "go_100_full_verify_ms": go_100["full_verify"]["median_ms"],
                "python_100_full_verify_ms": py_100["full_verify"]["median_ms"],
                "python_slowdown_factor": go_vs_py_ratio,
                "go_1000_jobs_per_sec": go_1000["full_verify"]["jobs_per_sec"],
                "python_1000_jobs_per_sec": py_1000["full_verify"]["jobs_per_sec"],
            },
        },
    }

    out_path = REF_DIR / "results.json"
    out_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote benchmark results to {out_path}")
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

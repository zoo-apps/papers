# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.

"""Reproducible Pure-Python offline verification latency benchmark (depths 1..16 & bitstrings 1K..131K)."""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

from .bitstring import bitstring_is_revoked, decode_bitstring
from .verifier import prepare_epoch, verify_presentation, verify_presentation_with_epoch


def _stats(samples: List[float]) -> Dict[str, float]:
    cp = sorted(samples)
    mean = sum(cp) / len(cp)
    p50 = cp[len(cp) // 2]
    idx95 = max(0, min(len(cp) - 1, int(len(cp) * 0.95) - 1))
    return {
        "mean": round(mean, 2),
        "p50": round(p50, 2),
        "p95": round(cp[idx95], 2),
    }


def run_benchmark(bundle: Dict[str, Any], iterations: int = 5) -> Dict[str, Any]:
    depth_rows = []
    for item in bundle["depth_cases"]:
        depth = int(item["depth"])
        ctx = item["context"]
        pres = item["presentation"]

        epoch, err_code, err_msg = prepare_epoch(ctx, int(pres["eval_time"]))
        if err_code or epoch is None:
            raise RuntimeError(f"depth {depth} prepare_epoch failed: {err_code} {err_msg}")

        warm_lat: List[float] = []
        warm_sigs = 0
        for _ in range(iterations):
            t0 = time.perf_counter()
            res = verify_presentation_with_epoch(epoch, ctx, pres)
            dt_us = (time.perf_counter() - t0) * 1e6
            if not res["valid"]:
                raise RuntimeError(f"depth {depth} warm verify failed: {res['error_code']}")
            warm_lat.append(dt_us)
            warm_sigs = int(res["signature_checks"])

        cold_iters = max(2, iterations // 2)
        cold_lat: List[float] = []
        for _ in range(cold_iters):
            t0 = time.perf_counter()
            res = verify_presentation(ctx, pres)
            dt_us = (time.perf_counter() - t0) * 1e6
            if not res["valid"]:
                raise RuntimeError(f"depth {depth} cold verify failed: {res['error_code']}")
            cold_lat.append(dt_us)

        ws = _stats(warm_lat)
        cs = _stats(cold_lat)
        depth_rows.append(
            {
                "depth": depth,
                "iterations": iterations,
                "warm_mean_us": ws["mean"],
                "warm_p50_us": ws["p50"],
                "warm_p95_us": ws["p95"],
                "warm_ops_per_sec": round(1e6 / ws["mean"], 2) if ws["mean"] > 0 else 0.0,
                "cold_mean_us": cs["mean"],
                "warm_sig_checks": warm_sigs,
            }
        )

    bit_rows = []
    for item in bundle["bitstring_cases"]:
        bl = int(item["bit_length"])
        sl = item["context"]["status_lists"][0]
        subj = sl["credential_subject"]
        t0 = time.perf_counter()
        raw = decode_bitstring(subj["encoded_list"], subj["encoding"], bl)
        decode_us = round((time.perf_counter() - t0) * 1e6, 2)

        lookup_n = 5000
        t1 = time.perf_counter()
        for i in range(lookup_n):
            bitstring_is_revoked(raw, bl, (i * 31) % bl)
        lookup_us = round(((time.perf_counter() - t1) * 1e6) / lookup_n, 4)

        bit_rows.append(
            {
                "bit_length": bl,
                "decode_us": decode_us,
                "warm_lookup_mean_us": lookup_us,
            }
        )

    return {
        "seed": int(bundle["seed"]),
        "python_depth_benchmarks": depth_rows,
        "python_bitstring_benchmarks": bit_rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run pure-Python offline verification benchmark.")
    parser.add_argument("--bundle", required=True, help="Exported depth+bitstring benchmark JSON bundle from id-bench")
    parser.add_argument("--iters", type=int, default=5, help="Warm iterations per depth")
    parser.add_argument("--merge-results", default="", help="Optional path to results.json to merge python_depth_benchmarks into")
    args = parser.parse_args()

    bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    out = run_benchmark(bundle, iterations=args.iters)

    if args.merge_results:
        res_path = Path(args.merge_results)
        results = json.loads(res_path.read_text(encoding="utf-8"))
        results["python_depth_benchmarks"] = out["python_depth_benchmarks"]
        results["python_bitstring_benchmarks"] = out["python_bitstring_benchmarks"]
        res_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

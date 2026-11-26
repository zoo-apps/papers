<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Zoo Labs Foundation and Contributors
-->

# Thinking Chains Canonical Receipt — Reproducible Benchmark & Research Artifact

This document reports reproducible empirical measurements for the zero-dependency Go and Python reference implementations of **`zoo.thinking-chains.receipt.v1`** (`zoo-apps/papers#7`, `hip-1352`), documents three measured **Negative Regimes**, and states explicitly **what remains unproven**.

Raw machine-readable data is stored in [`results.json`](results.json).

---

## 1. Environment & Reproduction Command

- **OS / Kernel**: `Linux-6.18.57-x86_64-with-glibc2.39`
- **CPU**: 2 vCPU `x86_64`
- **Go**: `go version go1.24.3 linux/amd64` (zero external dependencies)
- **Python**: `Python 3.12.16` (zero external dependencies; pure-stdlib RFC 8032 Ed25519)
- **Fixture Seed**: `--seed 1352` (100 jobs grounded in 112 real `.tex` files from `zoo-apps/papers`)

To reproduce every number below from scratch:

```bash
python3 thinking-chains/reference/scripts/generate_fixtures.py --seed 1352
python3 thinking-chains/reference/scripts/cross_verify.py
python3 thinking-chains/reference/scripts/run_benchmark.py
```

---

## 2. Cross-Implementation Differential Parity Proof

Executed via [`scripts/cross_verify.py`](scripts/cross_verify.py):

| Check | Go (`go-stdlib`) | Python (`python-stdlib`) | Result |
| --- | --- | --- | --- |
| 100-job fixture reconstructed & verified | `100 / 100` | `100 / 100` | **PASS** |
| Bit-identical `canonical_receipt_hash` across Go & Python | `100 / 100` | `100 / 100` | **100% IDENTICAL** |
| Bit-identical `provenance_root` across Go & Python | `100 / 100` | `100 / 100` | **100% IDENTICAL** |
| Adversarial tamper / policy / CoT / constitutional / replay suite | `31 / 31` rejected | `31 / 31` rejected | **100% ERROR-CODE PARITY** |

---

## 3. Core Throughput & Latency Benchmarks

### 3.1 100-Job Canonical Fixture (`fixtures/jobs_100.json`, 220 Ed25519 signatures total)

| Stage | Go Median (ms) | Go p95 (ms) | Go Per-Job (µs) | Go Throughput (jobs/s) | Python Median (ms) | Python p95 (ms) | Python Per-Job (µs) | Python Throughput (jobs/s) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Canonical Receipt Hash (`CanonicalJSON` + SHA-256) | 8.241 | 12.976 | 82.41 | 12,134.2 | 87.437 | 157.526 | 874.37 | 1,143.7 |
| Provenance Merkle Reconstruction (5 trees + root) | 5.107 | 10.382 | 51.07 | 19,582.1 | 49.788 | 118.646 | 497.88 | 2,008.5 |
| **Full Independent Verification** (schema + guards + Merkle + Ed25519 + replay) | **41.256** | **47.143** | **412.56** | **2,423.9** | **1,886.182** | **2,780.161** | **18,861.82** | **53.0** |

### 3.2 1,000-Job Replay-Free Stress Run (2,200 Ed25519 signatures total)

| Stage | Go Median (ms) | Go Per-Job (µs) | Go Throughput (jobs/s) | Python Median (ms) | Python Per-Job (µs) | Python Throughput (jobs/s) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Canonical Receipt Hash | 74.481 | 74.48 | 13,426.2 | 810.902 | 810.90 | 1,233.2 |
| Provenance Merkle Reconstruction | 57.772 | 57.77 | 17,309.5 | 501.239 | 501.24 | 1,995.1 |
| **Full Independent Verification** | **438.978** | **438.98** | **2,278.0** | **17,183.026** | **17,183.03** | **58.2** |

Go sustains **~2,278–2,424 full receipt verifications/sec** on a single 2-vCPU VM with zero external dependencies, staying nearly linear from 100 to 1,000 jobs (412.56 µs/job vs 438.98 µs/job).

---

## 4. Negative Regimes (Where Naive Designs Break Down)

To ground architectural choices in measured costs rather than claims, we benchmarked three concrete anti-patterns against the canonical receipt design:

### 4.1 Negative Regime A — Giant Inline Artifact Payloads vs Content-Addressed Hashes

Embedding raw prose rationales or execution traces inline (256 KiB per job across 100 jobs) instead of committing 32-byte SHA-256 content-addressed hashes:

| Representation (100 jobs) | Serialized Wire Size | Blowup | Canonicalize + SHA-256 Time | Slowdown |
| --- | ---: | ---: | ---: | ---: |
| Content-addressed canonical receipts (this spec) | 538,376 B (525.8 KiB) | 1.00x | 107.753 ms | 1.00x |
| Inline 256 KiB payload per job (anti-pattern) | 26,755,376 B (25.52 MiB) | **49.70x** | 5,373.785 ms | **49.87x** |

**Takeaway**: Enforcing Principle 4 (*Finite outputs only; prose as hash-addressed evidence*) prevents O(payload) consensus bloat and keeps receipt canonicalization ~50x smaller and faster even for modest 256 KiB artifacts.

### 4.2 Negative Regime B — Naive $O(N)$ Linear Provenance Recomputation vs $O(\log N)$ RFC 6962 Merkle Inclusion Proofs

Auditing membership of a single artifact inside a receipt with $N$ committed evidence items (Python stdlib measurements):

| Artifact Count ($N$) | Linear Payload | Merkle Proof Size | Linear Recompute (µs) | Merkle Verify (µs) | Speedup |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 16 | 1,632 B | 128 B (4 steps) | 71.70 | 7.56 | **9.48x** |
| 256 | 26,112 B | 256 B (8 steps) | 1,667.97 | 14.42 | **115.65x** |
| 4,096 | 417,792 B | 384 B (12 steps) | 28,528.36 | 35.46 | **804.53x** |

**Takeaway**: For multi-hundred or multi-thousand artifact research runs (e.g., corpus shards or benchmark trace logs), linear unindexed provenance degrades linearly to 28.5 ms and >400 KiB per check, whereas RFC 6962 Merkle inclusion proofs verify in 35.5 µs with 384 bytes.

### 4.3 Negative Regime C — Pure-Python Stdlib Ed25519 vs Compiled Go `crypto/ed25519`

| Workload | Go Stdlib | Python Stdlib | Slowdown |
| --- | ---: | ---: | ---: |
| 100-job full verification | 41.256 ms (2,423.9 jobs/s) | 1,886.182 ms (53.0 jobs/s) | **45.72x** |
| 1,000-job full verification | 438.978 ms (2,278.0 jobs/s) | 17,183.026 ms (58.2 jobs/s) | **39.14x** |

**Takeaway**: Pure-Python big-integer Ed25519 is completely zero-dependency and invaluable as an independent differential audit oracle, but it is **~40–46x slower** than compiled Go `crypto/ed25519`. Consensus nodes and high-throughput settlement verifiers MUST use compiled Go/Rust implementations rather than pure-Python elliptic curve arithmetic.

---

## 5. What Remains Unproven (Open Research Gaps)

Per the Thinking Chains paper (`sections/19-failure-modes.tex`, `sections/21-open-problems.tex`) and the bounty standard of epistemic honesty, this receipt implementation **proves structural integrity, authorization compliance, provenance binding, and independent verifier signatures**, and **does NOT prove** the following:

1. **Correctness of Tier-2 Forward Passes (Execution vs. Truth)**:
   - A valid receipt with `quorum_signatures` proves *which* independent verifiers attested to a finite output and that the committed inputs, tools, checks, and result were not tampered with after attestation.
   - It does **not** cryptographically prove that a frontier floating-point LLM actually executed the claimed weights on the claimed input (that requires either hardware TEE quote chain verification or scalable zkML proofs such as P3Q STARKs, which remain an active frontier).
2. **Hardware TEE Quote Chain & Revocation Verification**:
   - This reference verifier validates the hash commitment (`tee_quote_digest`) and verifier signatures over it, but does **not** perform live vendor root-of-trust X.509/CRL certificate validation against confidential GPU hardware (e.g., NVIDIA Hopper/Blackwell RIM/OCSP endpoints).
3. **Post-Quantum Signature Finality (ML-DSA / SLH-DSA)**:
   - The reference implementation uses classical **RFC 8032 Ed25519** so that both Go and Python stdlibs verify signatures with zero external dependencies.
   - Full Thinking Chains Quasar finality (`thinking-chains.tex` §12) requires post-quantum signatures (**ML-DSA / FIPS 204** and **SLH-DSA / FIPS 205**), which are not yet in Python's standard library and remain a planned v2 wire extension (`algorithm: "ml-dsa-65"`).
4. **Model Diversity & Correlated Blind Spots (Monoculture)**:
   - Checking `verifier_id != executor_id` prevents single-agent self-attestation, and checking `model_spec_hash` prevents model misrepresentation, but neither proves that two distinct verifiers are *epistemically independent* (two models fine-tuned from the same base checkpoint can share identical blind spots).
5. **Semantic Completeness of Public Evidence & Side-Channel CoT Leakage**:
   - The private-CoT prohibition guard (`ERR_PRIVATE_COT_FORBIDDEN`) rejects explicit private CoT schema keys, `public_trace_only=false`, and private URI schemes. It cannot prevent a malicious executor from stenographically encoding private text inside an opaque off-chain content-addressed blob whose hash is listed as `public_evidence` without inspecting the off-chain payload itself.
6. **Persistent Cross-Epoch Replay State & On-Chain Settlement Finality**:
   - `VerifyBatch` enforces replay uniqueness (`job_id`, `nonce`, `intent_id`) in memory within a batch. Production deployment requires a durable, consensus-committed nullifier/consumed-intent set on the host settlement chain.
7. **Incentive Compatibility for Subjective Tasks & Meaningful Human Review**:
   - Constitutional guards block an AI receipt from claiming `treasury_spend_authorized=true` or `voting_rules_modified=true` at the schema/verifier boundary, but preventing human rubber-stamping and designing proper scoring rules that reward honest minority dissent remain open mechanism-design and socio-technical problems (`sections/21-open-problems.tex`).

# Proof of AI: Grounded Reproducible Benchmark & Proof-Limits Report (`--seed 1350`)

- **Tracking Issue / HIP**: `zoo-apps/papers#13` · `HIP-1350`
- **Specification**: [`SPEC.md`](SPEC.md) (`poai-transcript.v1`, `v1.0.0`)
- **Machine-Readable Artifact**: [`results.json`](results.json)
- **Parity Fixture Suite**: [`fixtures/parity-suite.v1.json`](fixtures/parity-suite.v1.json) (`16` cases)
- **Pinned Corpus Manifest**: [`corpus-manifest.json`](corpus-manifest.json)
  - `corpus_manifest_sha256`: `7057cb566812f8bdba7a05e834c9030bae33ae7ab87464f1b6e67d5717df27a4`
  - `corpus_root_sha256`: `dc82a25a36179c5ae3e5c56f56227d5577cb641fedd1afd8681cef42db08674a`
- **Canonical Cross-Language `audit_merkle_root`**:
  - `11b937ade480d14c0f1064ef33702d44863dfac4045f22dcafd13f9c195a0bbe` (**16 / 16 bit-identical** across Go 1.24 stdlib and independent pure-Python 3.12 stdlib verifiers)
- **Kernel Profile**: `int8-whole-k-i32-fp2147483647.v1` ($p = 2^{31} - 1 = 2{,}147{,}483{,}647$)

---

## 1. Reproducibility & Pinned Corpus Grounding

All quantized `int8` weight/activation matrix tiles are deterministically derived via SHA-256 counter mode from the Merkle root of **6 real `.tex` sources** in `zoo-apps/papers` (`127,795` bytes total), verified against disk at every benchmark run:

| Pinned `.tex` Source | Bytes | SHA-256 | Role |
|---|---:|---|---|
| `zoo-poai-consensus/sections/00-status-summary.tex` | 3,377 | `d666041d…1afb55a9b` | Implementation boundary |
| `zoo-poai-consensus/sections/15-binding-scheme.tex` | 9,865 | `b9602778…5e3e1e76…` | Receipt binding |
| `zoo-poai-consensus/sections/17-freivalds-hash.tex` | 19,021 | `13c22ffb…0eaf0fe` | Freivalds execution proof |
| `zoo-poai-consensus/sections/25-receipt-soundness.tex` | 13,027 | `3c6f81f3…f9ee4a5` | Receipt soundness & honest boundary |
| `zoo-gym-compute-proof/zoo-gym-compute-proof.tex` | 32,499 | `dfd4506a…c237953` | Zoo Gym compute proof |
| `thinking-chains/thinking-chains.tex` | 50,006 | `11098056…1d4db25` | Thinking Chains Law of Cognition |

### Exact Reproduction Commands

```bash
cd zoo-poai-consensus/reference

# 1. Regenerate results.json and fixtures/parity-suite.v1.json (seed 1350, 1,000 trials/cell)
(cd go && go run ./cmd/poai-bench --repo ../../.. --manifest ../corpus-manifest.json --seed 1350 --trials 1000 --out ../results.json --fixtures ../fixtures/parity-suite.v1.json)

# 2. Verify with Go CLI and race-enabled Go tests
(cd go && go run ./cmd/poai-verify --suite ../fixtures/parity-suite.v1.json && go vet ./... && go test -v -race -count=1 ./...)

# 3. Verify independently with zero-dependency pure-Python CLI and unittest suite
(cd python && PYTHONPATH=. python3 -m poai_verifier.cli parity --suite ../fixtures/parity-suite.v1.json --go-results ../results.json && PYTHONPATH=. python3 -m unittest discover -s tests -v)
```

---

## 2. Honest Baseline (Zero False Rejections)

Because `int8` whole-$K$ integer accumulation is associative and $|C_{i,j}| \le 2^{30} < (p - 1)/2$ for $d \le 65{,}536$, honest matrix products experience **zero modular wraparound and zero false rejections**:

| Challenge Mode | Rounds $k$ | Honest Trials | Verified | False Rejects | Empirical FRR |
|---|---:|---:|---:|---:|---:|
| `binary_01` | 40 | 1,000 | 1,000 | 0 | **0.00%** |
| `field_fp` ($p = 2^{31}-1$) | 2 | 1,000 | 1,000 | 0 | **0.00%** |

---

## 3. CPU Verification Speedup vs. Full $O(n^3)$ Recomputation

Measured in pure Go 1.24 (`linux/amd64`) comparing exact integer GEMM ($O(n^3)$) against Freivalds CPU verification ($O(k n^2)$, including SHA-256 PRG challenge derivation):

| Dim $n$ | GEMM ($\mu\text{s}$) | Mode | $k=1$ | $k=2$ | $k=4$ | $k=8$ | $k=16$ | $k=40$ |
|---:|---:|---|---:|---:|---:|---:|---:|---:|
| 64 | 302.84 | `binary_01` | **23.34x** (`12.97 µs`) | 4.47x (`67.72 µs`) | 1.90x (`159.15 µs`) | 1.20x (`253.41 µs`) | 0.43x (`706.56 µs`) | 0.22x (`1,394.73 µs`) |
| 64 | 302.84 | `field_fp` | **5.09x** (`59.55 µs`) | **2.08x** (`145.52 µs`) | 1.26x (`240.02 µs`) | 0.63x (`480.04 µs`) | 0.25x (`1,189.44 µs`) | 0.12x (`2,589.23 µs`) |
| 128 | 2,518.37 | `binary_01` | **15.21x** (`165.59 µs`) | 6.47x (`389.31 µs`) | 4.57x (`551.19 µs`) | 2.24x (`1,122.06 µs`) | 1.15x (`2,197.05 µs`) | 0.47x (`5,410.86 µs`) |
| 128 | 2,518.37 | `field_fp` | **7.97x** (`316.06 µs`) | **3.11x** (`809.19 µs`) | 1.26x (`2,006.61 µs`) | 0.84x (`2,998.49 µs`) | 0.55x (`4,570.48 µs`) | 0.25x (`10,071.66 µs`) |
| 256 | 24,001.84 | `binary_01` | **30.00x** (`800.06 µs`) | 23.61x (`1,016.44 µs`) | 11.00x (`2,182.43 µs`) | 5.68x (`4,226.95 µs`) | 2.79x (`8,595.08 µs`) | 1.18x (`20,377.81 µs`) |
| 256 | 24,001.84 | `field_fp` | **29.87x** (`803.43 µs`) | **12.02x** (`1,996.22 µs`) | 6.54x (`3,667.57 µs`) | 3.03x (`7,932.73 µs`) | 1.50x (`16,001.23 µs`) | 0.63x (`38,402.95 µs`) |
| 512 | 119,349.99 | `binary_01` | **51.80x** (`2,304.23 µs`) | 24.86x (`4,800.37 µs`) | 14.92x (`8,000.61 µs`) | 7.10x (`16,801.29 µs`) | 3.66x (`32,646.68 µs`) | 1.43x (`83,349.02 µs`) |
| 512 | 119,349.99 | `field_fp` | **29.84x** (`4,000.31 µs`) | **14.92x** (`8,000.61 µs`) | **7.78x** (`15,335.34 µs`) | 3.94x (`30,265.80 µs`) | 1.90x (`62,867.18 µs`) | 0.77x (`155,140.47 µs`) |

### Key Takeaway: Prime-Field `field_fp` Dominates Binary `{0,1}`

At $n = 512$:
- **`binary_01` at $k = 40$** achieves false-accept bound $\le 2^{-40} \approx 9.09 \times 10^{-13}$ at **`1.43x`** speedup (`83.35 ms`).
- **`field_fp` at $k = 2$** achieves false-accept bound $\le (2^{31}-1)^{-2} \approx 2.17 \times 10^{-19}$ (**~4.2 million times stronger soundness**) at **`14.92x`** speedup (`8.00 ms`) — **10.4x faster** than `binary_01` ($k=40$).
- **`field_fp` at $k = 4$** achieves 124-bit soundness ($\le 4.70 \times 10^{-38}$) while still delivering **`7.78x`** speedup (`15.34 ms`).

---

## 4. Empirical Corruption Detection Matrix (`40,000` Corrupted Trials)

Five distinct corruption classes were injected into exact integer products ($32 \times 32$, `1,000` independent trials per `(mode, class, k)` cell):

### 4.1 Binary `{0, 1}` Freivalds (`error <= 2^-k`)

| Corruption Class | $k=1$ (Theory $\ge 50.00\%$) | $k=2$ ($\ge 75.00\%$) | $k=4$ ($\ge 93.75\%$) | $k=8$ ($\ge 99.61\%$) | $k=16$ ($\ge 99.9985\%$) | $k=40$ ($\ge 1 - 2^{-40}$) |
|---|---:|---:|---:|---:|---:|---:|
| `single_element_bitflip` | 50.50% (`505/1000`) | 74.60% (`746/1000`) | 95.00% (`950/1000`) | 99.40% (`994/1000`) | **100.00%** | **100.00%** |
| `single_element_plus_one` | 47.30% (`473/1000`) | 74.50% (`745/1000`) | 93.60% (`936/1000`) | 99.60% (`996/1000`) | **100.00%** | **100.00%** |
| `row_swap` | **100.00%** | **100.00%** | **100.00%** | **100.00%** | **100.00%** | **100.00%** |
| `low_rank_perturbation` | 78.20% (`782/1000`) | 96.20% (`962/1000`) | 99.60% (`996/1000`) | **100.00%** | **100.00%** | **100.00%** |
| `lazy_zero_output` | **100.00%** | **100.00%** | **100.00%** | **100.00%** | **100.00%** | **100.00%** |

*Observation*: Single-element corruptions saturate the exact worst-case Freivalds bound ($1 - 2^{-k}$, with binomial standard error $\sigma \approx 1.58\%$ at $k=1, N=1000$), whereas multi-entry corruptions (`row_swap`, `low_rank_perturbation`, `lazy_zero_output`) are detected at strictly higher rates because multiple nonzero error coordinates must simultaneously cancel.

### 4.2 Prime-Field $\mathbb{F}_p$ Freivalds ($p = 2^{31}-1$, `error <= p^-k`)

| Corruption Class | $k=1$ (Theory $\le 4.66 \times 10^{-10}$ escape) | $k=2$ (Theory $\le 2.17 \times 10^{-19}$ escape) |
|---|---:|---:|
| `single_element_bitflip` | **100.00%** (`1000/1000`) | **100.00%** (`1000/1000`) |
| `single_element_plus_one` | **100.00%** (`1000/1000`) | **100.00%** (`1000/1000`) |
| `row_swap` | **100.00%** (`1000/1000`) | **100.00%** (`1000/1000`) |
| `low_rank_perturbation` | **100.00%** (`1000/1000`) | **100.00%** (`1000/1000`) |
| `lazy_zero_output` | **100.00%** (`1000/1000`) | **100.00%** (`1000/1000`) |

---

## 5. Three Explicit Honest Negative Regimes

### Negative Regime 1: Non-Interactive Fiat-Shamir Prover Grinding (`neg_fiat_shamir_grinding_low_k`)

When a prover controls `prover_salt_hex` under non-interactive `fiat_shamir` with low $k \in \{1, 2, 3, 4\}$ in `binary_01` mode, the prover can brute-force a passing challenge vector $r$ on a **corrupted** matrix $C'$ (`single_element_plus_one`) in $\approx 2^k$ attempts:

| Rounds $k$ | Expected Attempts ($2^k$) | Actual Attempts to Forge | Forged Salt Hex | `fiat_shamir` Verdict | `grinding_risk_warning` | `external_verifier_nonce` Verdict |
|---:|---:|---:|---|---|---:|---|
| 1 | 2 | **1** | `46050000000000000000000000000000` | `COMPUTE_VERIFIED` (forged!) | `true` | **`COMPUTE_CORRUPTED`** |
| 2 | 4 | **7** | `46050000000000000600000000000000` | `COMPUTE_VERIFIED` (forged!) | `true` | **`COMPUTE_CORRUPTED`** |
| 3 | 8 | **3** | `46050000000000000200000000000000` | `COMPUTE_VERIFIED` (forged!) | `true` | **`COMPUTE_CORRUPTED`** |
| 4 | 16 | **17** | `46050000000000001000000000000000` | `COMPUTE_VERIFIED` (forged!) | `true` | **`COMPUTE_CORRUPTED`** |

**Conclusion**: Non-interactive Fiat-Shamir with low $k$ is **broken against adaptive grinding**. Production deployments MUST use an **external post-commitment verifier/beacon nonce** (`external_verifier_nonce`) OR cryptographic soundness ($k \ge 40$ binary / $k \ge 2$ over $\mathbb{F}_p$, and preferably $k \ge 4$ over $\mathbb{F}_p$ for 124-bit non-interactive security).

### Negative Regime 2: Semantic & End-to-End Inference Blindness (`neg_valid_matmul_untruthful_or_wrong_weights`)

We constructed a 100% honest GEMM $C = A_{\text{backdoor}} \cdot B$ where:
- Reference weight Merkle root: `369d31826974eb5b466bffc9610b712cdd287b80e74954de51a9c1b63f7b102d`
- Substituted backdoor weight Merkle root: `9bf8c39395e800a2310ea93574cbb937f370c147a6512325a1dd6b2e248910a8` (`weights_match_reference = false`)
- Non-linear layers (RMSNorm, SiLU, Softmax) were **omitted** (`nonlinearities_verified = false`)
- Claimed conclusion was factually false: `"2 + 2 = 5 and this unreviewed run proves global theorem convergence (non-linearities skipped)"`

**Observed Result**:
- Freivalds returns **`COMPUTE_VERIFIED`** because $C = A_{\text{backdoor}} \cdot B$ holds algebraically!
- The schema-locked constitutional boundary explicitly emits:
  - `proves_matrix_product_only = true`
  - `proves_full_model_inference = false`
  - `proves_scientific_truth = false`
  - `proves_weight_provenance = false`
- When the exact same valid matrix-product transcript attempts to set `requested_governance_action = "self_declare_valid"`, the constitutional pre-gate immediately blocks it with **`POLICY_REJECTED`** (`["ERR_FORBIDDEN_GOVERNANCE_ACTION"]`).

### Negative Regime 3: Small-Matrix / High-$k$ Verification Overhead Crossover (`neg_small_matrix_verification_overhead`)

Because Freivalds performs $3$ matrix-vector products plus SHA-256 PRG derivation per round ($O(k n^2)$), when $n$ is small relative to $k$, verification is **strictly slower ($< 1.0\text{x}$)** than direct $O(n^3)$ exact integer recomputation:

| Dim $n$ | GEMM ($\mu\text{s}$) | Mode | Rounds $k$ | Verify ($\mu\text{s}$) | Speedup | Verdict |
|---:|---:|---|---:|---:|---:|---|
| 16 | 6.64 | `binary_01` | 16 | 65.04 | **0.102x** | 9.8x slower than recomputation |
| 16 | 6.64 | `binary_01` | 40 | 117.26 | **0.057x** | 17.7x slower than recomputation |
| 16 | 6.64 | `field_fp` | 16 | 78.69 | **0.084x** | 11.9x slower than recomputation |
| 16 | 6.64 | `field_fp` | 40 | 188.63 | **0.035x** | 28.4x slower than recomputation |
| 32 | 42.74 | `binary_01` | 16 | 140.49 | **0.304x** | 3.3x slower than recomputation |
| 32 | 42.74 | `binary_01` | 40 | 384.42 | **0.111x** | 9.0x slower than recomputation |
| 32 | 42.74 | `field_fp` | 16 | 267.51 | **0.160x** | 6.3x slower than recomputation |
| 32 | 42.74 | `field_fp` | 40 | 692.54 | **0.062x** | 16.2x slower than recomputation |

**Practical Crossover Rule**: Direct recomputation is strictly cheaper whenever $n \lesssim 3k$ (and for `binary_01` at $k=40$, speedup only exceeds $1.0\text{x}$ for $n \ge 256$). For `field_fp` at $k = 2$, speedup already exceeds $2.0\text{x}$ at $n = 64$, $12.0\text{x}$ at $n = 256$, and $14.9\text{x}$ at $n = 512$ (scaling linearly as $\Theta(n / k)$ for real transformer projections $n \in [2048, 16384]$).

---

## 6. Cross-Language Go ↔ Python Parity Audit

All 16 canonical test cases in [`fixtures/parity-suite.v1.json`](fixtures/parity-suite.v1.json) (spanning honest square/rectangular GEMMs, all 5 corruption classes across `binary_01` & `field_fp`, tampered Ed25519 signature, post-commitment tampering, Fiat-Shamir grinding forgery, semantic blindness, and `POLICY_REJECTED` governance escalation) were verified independently by Go 1.24 stdlib and pure-Python 3.12 stdlib (including pure-Python RFC 8032 Ed25519):

- **Parity Rate**: **16 / 16 (100.00%) bit-identical** across `compute_verdict`, `error_codes`, `first_failing_round`, every round's `r_sha256` / `abr_sha256` / `cr_sha256`, and `audit_merkle_root`.
- **Canonical `audit_merkle_root`**: `11b937ade480d14c0f1064ef33702d44863dfac4045f22dcafd13f9c195a0bbe`.

---

## 7. What Remains Unproven

In accordance with `zoo-apps/papers#13` and `zoo-poai-consensus/sections/00-status-summary.tex` & `25-receipt-soundness.tex`, this artifact **explicitly does not prove**:

1. **Floating-Point GPU Tensor Cores (IEEE-754 FP16 / BF16 / FP8 / `f8q8` block-float)**: Real CUDA/Metal floating-point GEMMs are non-associative across hardware and reduction trees. Exact Freivalds applies ONLY to pinned whole-$K$ integer accumulators; shipping block-float kernels would false-reject honest provers.
2. **Non-Linear Layers, Attention Softmax, RoPE, and Token Decoding**: Element-wise activations (SiLU/GELU), RMSNorm/LayerNorm, attention softmax, MoE top-$k$ routing, and greedy argmax tie-breaking are NOT matrix multiplications and require separate deterministic commit-and-recompute verification over a complete `GraphTrace`.
3. **Model Weight & Checkpoint Attestation**: Freivalds checks $C = A \cdot B$ for whatever matrix $A$ is committed in `matrix_a_root`. Proving $A$ came from an authorized open-weight checkpoint requires an external registry binding (`modelWeightsRoot`).
4. **KV-Cache Continuity Across Autoregressive Tokens**: Single-layer GEMM transcripts do not attest that cached key/value tensors carried from tokens $1 \dots t-1$ match the committed prompt prefix and prior verified steps.
5. **Scientific Value, Reasoning Truthfulness, or Alignment**: Mechanical compute verification (`COMPUTE_VERIFIED`) never establishes whether an inference answer is true, safe, or scientifically valuable. Those require independent evidence/reasoning verification (`zoo-apps/papers#8`, HIP-1352) and authorized human/governance decision-makers.
6. **Zero-Knowledge Privacy & Sublinear Verification (zkML / L5 Tier)**: Freivalds requires the verifier to read $A, B, C$ in $O(k n^2)$ time and provides zero privacy for proprietary weights or prompts. Full succinctness and privacy require SNARK/STARK/sumcheck proving systems.
7. **Live Consensus Settlement & Data Availability**: This reference implementation proves the cryptographic verification primitive and cross-language encoding parity; it does not wire live A-Chain admission, nullifier consumption, data availability, or minting authority.

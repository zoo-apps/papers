# Attested vs Challenged Inference Verification Benchmark (`--seed 1350`)

- **Specification**: `inference-verify.v1` (`v1.0.0`, [`SPEC.md`](SPEC.md))
- **Tracking Issue / HIP**: `zoo-apps/papers#14` · `HIP-1350`
- **Raw Machine-Readable Output**: [`results.json`](results.json)
- **Grounded Corpus**: `7` pinned `zoo-apps/papers` LaTeX sources (`130,577` bytes, `512`-token vocab, `10,750` grounded tokens, `corpus_root_sha256 = 7fffb012db82784871f7fe4ab1256b6990dc383f24e280cc8f83cf5b4f6b210f`)
- **Deterministic Model**: `zoo-qmlp-32x64x16.v1` (`model_digest = e7ec44147d6c2bd21d94cf2d13aaa9e084f432b76ed2c2834e18b8ddb94d401f`)
- **Dual-Language Parity (`Go <-> Python`)**: **`225 / 225` (100.00%)** (`200` golden + `25` adversarial) · `audit_merkle_root = 25c97f0530963ec34792d8ff08eaad79080829c7cd9992d8bdd90b16054b199d`

---

## 1. Reproducibility Commands

All numbers below are deterministically reproduced from `--seed 1350` using zero external dependencies in both Go (`go 1.24`, stdlib only) and Python (`python 3.12`, stdlib only):

```bash
cd zoo-gym-compute-proof/reference

# 1. Run Go vet + race-detector tests (8 tests, 0 races)
(cd go && go vet ./... && go test -v -race -count=1 ./...)

# 2. Regenerate results.json & 225-case parity fixture (--seed 1350)
(cd go && go run ./cmd/verify-bench \
  --repo ../../.. \
  --manifest ../corpus-manifest.json \
  --seed 1350 \
  --out ../results.json \
  --fixtures ../fixtures/verification-suite.v1.json)

# 3. Verify 225-case fixture independently in Go and Pure Python
(cd go && go run ./cmd/verify-audit --suite ../fixtures/verification-suite.v1.json)
(cd python && python3 -m unittest discover -v)
(cd python && python3 -m inferverify_py.cli \
  --suite ../fixtures/verification-suite.v1.json \
  --go-results ../results.json)
```

---

## 2. Wall-Clock Crypto vs Compute Microbenchmark (`decode_steps = 8`, `400` iterations)

Measured in pure Go stdlib on CPU with a 1,024-leaf RFC 6962 transparency log:

| Operation | Latency (µs / op) | Relative / Notes |
|---|---:|---|
| Honest quantized MLP inference (`8` steps) | `75.62 µs` | `1.00x` baseline inference compute |
| Lazy dummy cheater model (`8` steps) | `3.95 µs` | **`94.78%` compute savings** (strong cheating incentive) |
| in-toto DSSE v1 Ed25519 signing | `51.68 µs` | `O(1)` worker signing overhead |
| in-toto DSSE v1 Ed25519 verification | `81.26 µs` | `O(1)` verifier signature check |
| RFC 6962 transparency-log proof + checkpoint verify (`N=1024`) | `92.34 µs` | `O(log N)` Merkle inclusion + STH Ed25519 verify |
| **`signed_attestation_only` total verify** | **`173.60 µs`** | **`2.81x` faster verify** than `k=3` re-exec (`0` re-executions) |
| **`independent_reexecution` (`k=3`) total verify** | **`487.36 µs`** | Includes `2` full re-executions + `2` verifier DSSE checks |

> Note: For larger real-world GPU/LLM workloads where single-job inference takes `50–5,000 ms` rather than `75 µs`, the `~174 µs` constant-time DSSE + Rekor proof overhead becomes `< 0.35%`, while the **`3.00x` vs `1.07x–1.09x` compute cost multiplier** completely dominates total system cost.

---

## 3. Head-to-Head Regime Comparison Under Identical Threat Model

Economic policy parameters: job fee $F = 10.00$, honest compute cost $c_{\text{honest}} = 5.00$ (honest profit $= +5.00$/job), lazy cheat cost $c_{\text{cheat}} = 0.25$ (cheating savings $g = 4.75$/job), worker bond $B = 200.00$, slashing penalty $S = 150.00$, challenger reward $R = 50.00$.

### 3.1 Scenario A: Realistic Mixed Fleet (`1,000` jobs, `15%` adversarial workers cheating `50%` of the time $\Rightarrow$ `59` cheated jobs)

| Regime & Configuration | Compute Cost | Challenged | Fraud Detected | Fraud Escaped | Cheat Det. % | Honest FRR | Verify Overhead (µs) | Cheater Profit / Job | Cheat Adv. vs Honest | IC? |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|:---:|
| `signed_attestation_only` (DSSE + Rekor) | **`1.000x`** | `0` | `0` | `59` | **`0.00%`** | `0.00%` | `173.60` | `+9.75` | `+4.75` | **No** |
| `independent_reexecution` (`k=2`) | `2.000x` | `0` | `59` | `0` | **`100.00%`** | `0.00%` | `330.48` | `-150.25` | `-155.25` | **Yes** |
| `independent_reexecution` (`k=3`) | `3.000x` | `0` | `59` | `0` | **`100.00%`** | `0.00%` | `487.36` | `-150.25` | `-155.25` | **Yes** |
| `random_challenge` (`p=0.05, S=150`) | `1.045x` | `45` | `0`* | `59`* | `0.00%`* | `0.00%` | `180.66` | `+9.75`* | `+4.75`* | **Variance*** |
| `random_challenge` (`p=0.10, S=150`) | `1.097x` | `97` | `2` | `57` | `3.39%` | `0.00%` | `188.81` | `+4.33` | `-0.67` | **Yes** |
| `random_challenge` (`p=0.25, S=150`) | `1.238x` | `238` | `15` | `44` | `25.42%` | `0.00%` | `210.93` | `-30.93` | `-35.93` | **Yes** |
| **`hybrid_attested_plus_challenged` (`5%/25%, S=150`)** | **`1.091x`** | `91` | **`15`** | `44` | **`25.42%`** | **`0.00%`** | **`187.87`** | **`-30.93`** | **`-35.93`** | **Yes** |

\* **Finite-Sample Variance Finding**: At uniform $p = 0.05$ over only $59$ cheated jobs, the exact probability of zero catches is $(1 - 0.05)^{59} = 4.85\%$ — and under `--seed 1350`, uniform $p = 0.05$ experienced a lucky zero-catch streak (`0/59`) despite being asymptotically IC ($p(F+S)=8.0 > 4.75$). In contrast, **`hybrid_attested_plus_challenged` spent `< 1.10x` total compute (`1.091x`, lower than uniform `p=0.10` at `1.097x`) yet matched uniform `p=0.25`'s `25.42%` detection (`15/59` caught, `-30.93`/job cheater loss)** by escalating probationary/flagged workers to $p_{\text{esc}} = 0.25$ while leaving established honest workers at $p_{\text{base}} = 0.05$!

### 3.2 Scenario B: Full Rational Adversarial Stream (`500` jobs, `100%` lazy-dummy workers)

| Regime & Configuration | Compute Cost | Fraud Detected | Fraud Escaped | Cheat Det. % | Cheater Profit / Job | Cheat Adv. vs Honest | IC? |
|---|---:|---:|---:|---:|---:|---:|:---:|
| `signed_attestation_only` | `1.000x` | `0` | `500` | **`0.00%`** | `+9.75` | `+4.75` | **No** |
| `independent_reexecution` (`k=3`) | `3.000x` | `500` | `0` | **`100.00%`** | `-150.25` | `-155.25` | **Yes** |
| `random_challenge` (`p=0.05, S=150`) | `1.056x` | `28` | `472` | `5.60%` | `+0.79` | `-4.21` | **Yes** |
| `hybrid_attested_plus_challenged` (`5%/25%, S=150`) | `1.198x` | `99` | `401` | `19.80%` | `-21.93` | `-26.93` | **Yes** |

---

## 4. Random Challenge Parameter Sweep (`p × cheat_rate × slash_ratio`, `2,000` jobs/cell)

Slice at `cheat_rate = 0.50` (`~1,000` cheated jobs per cell; honest profit $= +5.00$/job, cheating gain $g = 4.75$/job). Full `60`-cell sweep across `cheat_rate ∈ {0.10, 0.50, 1.00}` is recorded in [`results.json`](results.json):

| Challenge Rate $p$ | Slash Ratio $S/g$ | Slash $S$ | Empirical Det. % | Compute Mult. | Theory $\mathbb{E}[\pi_{\text{cheat}}]$ | Empirical $\pi_{\text{cheat}}$ | IC ($p(F+S) > g$)? |
|---:|---:|---:|---:|---:|---:|---:|:---:|
| `0.01` | `1x` | `4.75` | `1.25%` | `1.0105x` | `+9.60` | `+9.56` | **No** |
| `0.01` | `5x` | `23.75` | `1.25%` | `1.0105x` | `+9.41` | `+9.33` | **No** |
| `0.01` | `20x` | `95.00` | `1.25%` | `1.0105x` | `+8.70` | `+8.43` | **No** |
| `0.01` | `100x` | `475.00` | `1.25%` | `1.0105x` | **`+4.90`** | **`+3.67`** | **Yes** |
| `0.05` | `1x` | `4.75` | `4.91%` | `1.0500x` | `+9.01` | `+9.03` | **No** |
| `0.05` | `5x` | `23.75` | `4.91%` | `1.0500x` | `+8.06` | `+8.09` | **No** |
| `0.05` | `20x` | `95.00` | `4.91%` | `1.0500x` | **`+4.50`** | **`+4.60`** | **Yes** |
| `0.05` | `100x` | `475.00` | `4.91%` | `1.0500x` | **`-14.50`** | **`-14.06`** | **Yes** |
| `0.10` | `5x` | `23.75` | `10.97%` | `1.1030x` | `+6.38` | `+6.05` | **No** |
| `0.10` | `20x` | `95.00` | `10.97%` | `1.1030x` | **`-0.75`** | **`-1.77`** | **Yes** |
| `0.25` | `1x` | `4.75` | `27.10%` | `1.2610x` | `+6.06` | `+5.75` | **No** |
| `0.25` | `5x` | `23.75` | `27.10%` | `1.2610x` | **`+1.31`** | **`+0.60`** | **Yes** |
| `0.50` | `1x` | `4.75` | `47.31%` | `1.4775x` | **`+2.38`** | **`+2.77`** | **Yes** |
| `0.50` | `100x` | `475.00` | `47.31%` | `1.4775x` | **`-232.75`** | **`-219.71`** | **Yes** |

Every cell tracks the exact closed-form threshold $p(F + S) > 4.75$: below the threshold, empirical cheater profit exceeds honest profit (`+5.00`); above the threshold, cheating becomes strictly dominated.

---

## 5. Three Explicit Honest Negative Regimes

### Negative Regime 1: `neg_attestation_blind_to_valid_key_cheating`
- **Setup**: `500` jobs executed by an enrolled valid-key worker substituting the lazy dummy model (`94.78%` compute savings), emitting valid in-toto DSSE v1 Ed25519 signatures and valid RFC 6962 Rekor-style inclusion proofs.
- **Result**: **`0 / 500` detected (`0.00%`)**, **`500 / 500` escaped (`100.00%`)**, cheater net profit **`+9.75`/job** vs honest `+5.00`/job (`+4.75`/job excess profit).
- **Conclusion**: Cryptographic provenance (in-toto DSSE + Sigstore Cosign/Rekor) proves **signer identity, non-repudiation, and log ordering** — it provides **zero execution integrity** on its own.

### Negative Regime 2: `neg_undercollateralized_challenge_profitable_cheating`
- **Setup**: `2,000` cheated jobs under `random_challenge_verification` with low sampling $p = 0.01$ and undercollateralized slash $S = 20.00$ ($p(F+S) = 0.30 \ll 4.75 = g$; minimum required slash for IC at $p = 0.01$ is $S_{\min} = 465.00$).
- **Result**: `25 / 2,000` frauds caught (`1.25%`), yet rational attacker earns **`+9.375`/job empirical** (theory `+9.450`/job) vs honest `+5.000`/job — a **`+4.375`/job strictly positive cheating advantage**.
- **Conclusion**: Random challenge verification without adequate collateralization ($p(F+S) > g$) creates a false sense of security and remains economically exploitable.

### Negative Regime 3: `neg_full_reexecution_cost_ceiling`
- **Setup**: `1,000` jobs on a `100%`-honest bulk inference workload (`0%` adversaries).
- **Result**: Unconditional `k=3` `independent_reexecution` incurs **`3.000x` compute multiplier (`200.0%` wasted redundant compute)** and `487.36 µs`/job verification overhead, whereas `hybrid_attested_plus_challenged` incurs only **`1.073x` compute (`7.3%` overhead)** and `185.05 µs`/job — a **`2.80x` compute cost reduction** while preserving `100%` DSSE + transparency-log provenance and strict economic deterrence.

---

## 6. Dual-Language Parity & Adversarial Test Matrix (`225` Cases)

Both the Go (`inferverify`) and completely independent pure-Python (`inferverify_py`, pure-Python RFC 8032 Ed25519, zero external deps) verifiers audited [`fixtures/verification-suite.v1.json`](fixtures/verification-suite.v1.json):

- **Total Cases**: `225` (`200` golden across all 4 regimes + `25` explicit adversarial attacks)
- **Go Verifier Match**: **`225 / 225` (100.00%)** · `audit_merkle_root = 25c97f0530963ec34792d8ff08eaad79080829c7cd9992d8bdd90b16054b199d`
- **Python Verifier Match**: **`225 / 225` (100.00%)** · `audit_merkle_root = 25c97f0530963ec34792d8ff08eaad79080829c7cd9992d8bdd90b16054b199d`
- **Adversarial Coverage (`25/25` caught or explicitly documented)**: forged DSSE sig, tampered DSSE payload, missing tlog proof, tampered RFC 6962 Merkle path, forged tlog checkpoint sig, untrusted tlog key, revoked worker key, expired worker key, unregistered worker key, epoch replay, equivocating duplicate job, subject digest mismatch, wrong in-toto `_type`, valid-key lazy cheater escaping attestation-only (`adv_14`), lazy cheater caught by re-execution (`adv_15`), challenge (`adv_16`), and hybrid escalation (`adv_17`), colluding same-operator re-execution (`adv_18`), colluding self-challenger (`adv_19`), forged challenge sig (`adv_20`), skipped required challenge (`adv_21`), AI self-certification (`adv_22`), AI policy mutation (`adv_23`), AI slashing approval (`adv_24`), and overclaimed TEE proof scope (`adv_25`).

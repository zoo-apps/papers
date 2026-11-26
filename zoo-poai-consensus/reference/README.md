# Proof of AI: CPU-Verifiable GPU Work (`zoo-apps/papers#13`)

Zero-dependency, Apache-2.0 reference implementation, versioned specification (`poai-transcript.v1`), JSON Schema, dual independent Go/Python verifiers, and grounded reproducible benchmark for **`zoo-apps/papers#13` (`HIP-1350`)**, aligned with [`zoo-poai-consensus`](../zoo-poai-consensus.tex), [`zoo-gym-compute-proof`](../../zoo-gym-compute-proof/zoo-gym-compute-proof.tex), and [`thinking-chains`](../../thinking-chains/thinking-chains.tex).

- **License**: Apache-2.0
- **External Dependencies**: **Zero** (Go 1.24 stdlib + Pure Python 3.12 stdlib, including pure-Python RFC 8032 Ed25519)
- **Arithmetic Profile**: Exact whole-$K$ `int8 × int8 → int64` GEMM over Mersenne prime field $\mathbb{F}_p$, $p = 2^{31} - 1 = 2{,}147{,}483{,}647$ (zero overflow, zero false rejections)
- **Challenge Modes**: Both binary $\{0,1\}$ Freivalds ($\text{error} \le 2^{-k}$) and prime-field $\mathbb{F}_p$ Freivalds ($\text{error} \le p^{-k}$), with both `external_verifier_nonce` (recommended) and `fiat_shamir` (with grinding-risk detection)

## Repository Layout

```text
zoo-poai-consensus/reference/
├── README.md                              # Overview, quickstart & headline results
├── SPEC.md                                # Versioned specification (poai-transcript.v1, v1.0.0)
├── BENCHMARK.md                           # Speedup/soundness tables, 3 negative regimes & What Remains Unproven
├── corpus-manifest.json                   # Pinned SHA-256 digests of 6 real zoo-apps/papers .tex files
├── results.json                           # Machine-readable benchmark results (--seed 1350, 40,000+ trials)
├── schema/
│   └── poai-transcript.v1.schema.json     # JSON Schema Draft 2020-12 with const-locked constitutional fields
├── fixtures/
│   └── parity-suite.v1.json               # 16 canonical transcripts for Go <-> Python bit-identical parity
├── go/                                    # Pure Go 1.24 stdlib prover, verifier, benchmark & CLIs (0 deps)
│   ├── go.mod
│   ├── poai/
│   │   ├── field.go                       # Exact int8 GEMM & overflow-free F_p arithmetic
│   │   ├── matrix.go                      # Canonical matrix encodings, row Merkle trees & trace root
│   │   ├── transcript.go                  # poai-transcript.v1 binary header, Ed25519 & audit Merkle root
│   │   ├── freivalds.go                   # SHA-256 PRG challenges, Freivalds verifier & constitutional pre-gate
│   │   ├── benchmark.go                   # Grounded corpus benchmark, 5 corruptions & 3 negative regimes
│   │   └── poai_test.go                   # 13 race-detector unit & property tests
│   └── cmd/
│       ├── poai-bench/main.go             # Reproducible benchmark + parity fixture generator CLI
│       └── poai-verify/main.go            # Transcript & parity suite verifier CLI
└── python/                                # Independent Pure Python 3.12 stdlib verifier (0 deps)
    ├── poai_verifier/
    │   ├── ed25519.py                     # Pure-Python RFC 8032 Ed25519 signature verifier
    │   ├── field.py                       # Exact GEMM & F_p arithmetic
    │   ├── matrix.py                      # Canonical commitments & Merkle trees
    │   ├── verifier.py                    # Independent transcript, Freivalds & constitutional verifier
    │   └── cli.py                         # Parity & verification CLI
    └── tests/
        └── test_poai_verifier.py          # 12 unittest cases asserting 100% Go <-> Python parity
```

## Quickstart & Verification

```bash
cd zoo-poai-consensus/reference

# Go vet + race-detector test suite (13 tests, 0 races)
(cd go && go vet ./... && go test -v -race -count=1 ./...)

# Pure-Python unittest suite (12 tests, 0 external packages)
(cd python && PYTHONPATH=. python3 -m unittest discover -s tests -v)

# Reproduce benchmark (--seed 1350) and assert Go <-> Python bit-identical parity
(cd go && go run ./cmd/poai-bench --repo ../../.. --manifest ../corpus-manifest.json --seed 1350 --trials 1000 --out ../results.json --fixtures ../fixtures/parity-suite.v1.json)
(cd go && go run ./cmd/poai-verify --suite ../fixtures/parity-suite.v1.json)
(cd python && PYTHONPATH=. python3 -m poai_verifier.cli parity --suite ../fixtures/parity-suite.v1.json --go-results ../results.json)
```

## Headline Benchmark Results (`--seed 1350`)

- **Cross-Language Parity**: **16 / 16 (100.00%) Go ↔ Python bit-identical** verdicts, error codes, per-round digests, and `audit_merkle_root` (`11b937ade480d14c0f1064ef33702d44863dfac4045f22dcafd13f9c195a0bbe`).
- **Honest False-Rejection Rate (FRR)**: **0.00%** (`0 / 1,000` in both `binary_01` $k=40$ and `field_fp` $k=2$).
- **CPU Verification Speedup ($n = 512$)**:
  - `field_fp` ($k = 1$, error $\le 4.66 \times 10^{-10}$): **`29.84x`** (`119.35 ms` GEMM vs `4.00 ms` verify)
  - `field_fp` ($k = 2$, error $\le 2.17 \times 10^{-19}$): **`14.92x`** (`119.35 ms` vs `8.00 ms`) — **10.4x faster and >4,000,000x more sound** than `binary_01` ($k = 40$, `1.43x`)
  - `binary_01` ($k = 1$, error $\le 0.5$): **`51.80x`** (`119.35 ms` vs `2.30 ms`)
- **Empirical Corruption Detection (`40,000` trials across 5 classes)**:
  - `field_fp` ($k = 1, 2$): **100.00%** (`1000 / 1000`) across all 5 classes (`single_element_bitflip`, `single_element_plus_one`, `row_swap`, `low_rank_perturbation`, `lazy_zero_output`).
  - `binary_01`: tracks exact theory $1 - 2^{-k}$ on worst-case single-element corruptions (`~50%` at $k=1$, `~75%` at $k=2$, `~94%` at $k=4$, `~99.5%` at $k=8$, **100.00%** at $k=16, 40$).
- **Documented Proof Limits & Honest Negative Regimes**: Full analysis of Fiat-Shamir grinding at low $k$, semantic/backdoor-weight blindness + constitutional `POLICY_REJECTED` guards, small-matrix verification overhead (`0.035x–0.304x` at $n \in \{16, 32\}$), and **What Remains Unproven** are documented in [`BENCHMARK.md`](BENCHMARK.md) and [`SPEC.md`](SPEC.md).

# Experience Ledger DSO — Byzantine-Robust Aggregation & Participation Fairness Benchmark (`dso-aggregation.v1`)

Reference implementation, versioned specification, grounded real-corpus benchmark, and independent cross-language audit verifier for **`zoo-apps/papers#9`** (`HIP-1352` — *Byzantine-robust DSO aggregation*).

## Highlights

- **Zero external dependencies**: Pure Go 1.24 stdlib (`go/`) + pure Python 3.12 stdlib (`python/`, including pure-Python RFC 8032 Ed25519 verification).
- **Grounded in real `zoo-apps/papers` `.tex` corpus**: 88 real research papers (`73` `protocol_governance` / `5,534` paragraphs + `15` `conservation_science` / `1,099` paragraphs), content-anchored by SHA-256 (`--seed 1352`).
- **5 head-to-head aggregation rules**: `mean_baseline`, `coord_median`, `trimmed_mean`, `multi_krum`, `dso_reputation_eval_gated`.
- **4 mandatory threat & honest-disagreement scenarios** across `f ∈ {0%, 10%, 20%, 30%, 40%, 50%}` ($N = 30$ nodes, 120 cells):
  1. `adversarial_semantic` — label-flipped, norm-matched semantic poisoning
  2. `colluding_sybil_cartel` — tightly clustered Sybil cartel ($\cos > 0.999$) engineered to capture Multi-Krum
  3. `low_quality_noisy` — high-variance lazy freeloaders violating DSO Section 3 schema
  4. `honest_disagreement_noniid` — strict 75/25 disjoint majority/minority honest specialists under $f \in [0\%, 50\%]$
- **3 explicit honest negative regimes** + **"What Remains Unproven / Open Research Gaps"** in [`BENCHMARK.md`](BENCHMARK.md).

## Layout

```
experience-ledger-dso/reference/
├── README.md                              # This guide
├── SPEC.md                                # Versioned protocol & fairness metric spec (dso-aggregation.v1)
├── BENCHMARK.md                           # Full experimental tables, negative regimes & unproven gaps
├── results.json                           # Deterministic 120-cell benchmark output (--seed 1352)
├── audit_trace.json                       # 5 signed rounds (150 Ed25519 envelopes) for Go<->Python parity
├── schema/
│   └── dso-aggregation.v1.schema.json     # Draft 2020-12 JSON Schema
├── go/
│   ├── go.mod                             # Go 1.24, zero external dependencies
│   ├── cmd/dso-bench/main.go              # Benchmark runner CLI
│   └── internal/dso/                      # Corpus loader, Ed25519, 5 aggregators, fairness, simulator, tests
└── python/
    ├── dso_verifier/                      # Independent pure-Python 3.12 Ed25519 & aggregation audit verifier
    └── tests/test_verifier.py             # Cross-language parity & tamper-rejection unittest suite
```

## Quickstart & Exact Reproduction

### 1. Run Go 1.24 Verification Suite (`go vet` + `-race` tests)

```bash
cd experience-ledger-dso/reference/go
go vet ./...
go test -v -race -count=1 ./...
```

### 2. Regenerate Deterministic Benchmark & Audit Trace (`--seed 1352`)

```bash
cd experience-ledger-dso/reference/go
go run ./cmd/dso-bench --seed 1352 --repo-root ../../.. --out-results ../results.json --out-trace ../audit_trace.json
```

### 3. Run Independent Pure-Python 3.12 Audit Verifier & Parity Tests

```bash
cd experience-ledger-dso/reference/python
PYTHONDONTWRITEBYTECODE=1 python3 -m dso_verifier.cli --results ../results.json --trace ../audit_trace.json
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -v
```

Both Go and Python MUST report bit-identical digests:
- `audit_merkle_root`: `6afc3857524d5d2191b03927b0239887bc9c2e4749f6859c6f0e5275aca88152`
- `trace_merkle_root`: `3ce5605d62f2dd7c2614d15a7db451cf3c54d698545adce2251c31bf30b26672`

## License

Apache-2.0 (`SPDX-License-Identifier: Apache-2.0`).

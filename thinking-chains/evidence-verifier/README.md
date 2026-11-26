# Open Evidence and Reasoning Verifier (`zoo-apps/papers#8`)

Reference implementation, versioned specification, grounded 120-claim benchmark, and error analysis for **`zoo-apps/papers#8` (HIP-1352: Open evidence and reasoning verification)** aligned with Zoo Thinking Chains (`thinking-chains/thinking-chains.tex`).

- **License**: Apache-2.0
- **External Dependencies**: **Zero** (Go 1.24 stdlib + Python 3.12 stdlib)
- **LLM Calls Required**: **Zero** (implements Constitutional Rule 10: *Inspectable without an LLM*)

## What It Verifies

Every `EvidenceClaim` is evaluated deterministically into one of four normative verdicts:
- `VERIFIED_REPRODUCIBLE`
- `REFUTED_CONTRADICTION`
- `UNSUPPORTED_INSUFFICIENT_EVIDENCE`
- `INCONCLUSIVE_NEEDS_HUMAN_REVIEW`

Across four claim classes + two non-bypassable constitutional guards:
1. **Constitutional Pre-Gate**: Blocks self-validation (`author_id == verifier_id`) and forbidden autonomous AI governance actions (`redefine_voting_rules`, `authorize_treasury`, `self_declare_valid`).
2. **`citation_check`**: Pinned SHA-256 verification against real `.tex` sources in `zoo-apps/papers`, section scoping, deterministic LaTeX normalization, exact span matching, numeric consistency, and clause-level polarity reversal detection.
3. **`calc_check`**: Deterministic LL(1) math & statistics AST evaluator (supporting exact arbitrary-precision rationals via `math/big.Rat` / `fractions.Fraction`, `pct_delta`, `ratio`, `hoeffding_upper`, `ci95_halfwidth`, `mean`/`median`/`var`/`std`), unit checking, tolerance verification, and domain error detection.
4. **`code_result_check`**: Sandboxed deterministic reference kernels (`bitdelta_scale`, `trimmed_mean`, `linear_reward`, `merkle_root`, `sha256_canonical`, `sortition_check`, `eval_expr`), content-addressed SHA-256 artifact verification, and bounded 95% confidence interval verification for stochastic ML benchmarks.
5. **`reasoning_chain_check`**: Public reasoning DAG audit enforcing acyclicity, zero dangling premises, rejection of private/opaque CoT blobs, and transitive premise groundedness (including live cross-claim resolution within a bundle).

## Repository Layout

```text
thinking-chains/evidence-verifier/
├── README.md                          # Overview & quickstart
├── SPEC.md                            # Versioned specification (v1.0.0)
├── BENCHMARK.md                       # Published benchmark, confusion matrix, error analysis & unproven gaps
├── results.json                       # Machine-readable benchmark results (seed 1352, 120 claims)
├── schema/
│   └── evidence-claim.v1.schema.json  # JSON Schema Draft 2020-12
├── dataset/
│   ├── corpus-manifest.json           # Pinned SHA-256 digests of 8 real zoo-apps/papers .tex files
│   ├── generate_benchmark.py          # Deterministic dataset builder (--seed 1352)
│   └── benchmark-claims.v1.json       # 120 labeled public claims (30 per class)
├── go/                                # Pure Go 1.24 stdlib verifier & CLI (0 external modules)
│   ├── go.mod
│   ├── verifier/
│   └── cmd/verifier/
└── python/                            # Independent Pure Python 3.12 stdlib verifier & CLI (0 external deps)
    ├── evidence_verifier/
    └── tests/
```

## Quickstart & Verification

```bash
cd thinking-chains/evidence-verifier

# Go tests with race detector
(cd go && go vet ./... && go test -v -race -count=1 ./...)

# Python unittest suite (includes 120/120 Go <-> Python bit-identical parity check)
(cd python && python3 -m unittest discover -s tests -v)

# Regenerate & check benchmark parity directly via CLI
(cd go && go run ./cmd/verifier benchmark --corpus ../../.. --dataset ../dataset/benchmark-claims.v1.json --seed 1352 --out ../results.json)
PYTHONPATH=python python3 -m evidence_verifier.cli parity --corpus ../.. --dataset dataset/benchmark-claims.v1.json --go-report results.json
```

## Key Benchmark Highlights (`--seed 1352`, `120` Claims)

- **120 / 120 (100.00%) Go ↔ Python bit-identical parity** (`audit_merkle_root`: `2f3e7dd02712ce5388da5483d562d9389eb1c2bea00d0d8af5cc2ed7affdc2a6`)
- **Mechanical False Verification Rate (FVR)**: **0.00%** (`0 / 52`)
- **Overall Accuracy**: **89.17%** (`107 / 120`; **100.00%** on the `107` standard-regime claims)
- **Macro F1**: **0.8713** | **Overall FVR (Cherry-Picking)**: **4.48%** (`3 / 67`) | **FRR**: **15.09%** (`8 / 53`)
- Full confusion matrix, error analysis, 3 honest negative regimes, and open research gaps are documented in [`BENCHMARK.md`](BENCHMARK.md).

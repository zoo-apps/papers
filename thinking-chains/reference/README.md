<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Zoo Labs Foundation and Contributors
-->

# Thinking Chains Canonical Execution Receipt — Reference Implementation

Reference implementation, versioned specification, JSON Schema, 100-job grounded fixture, 31-case adversarial tamper suite, and reproducible benchmark for **`zoo-apps/papers#7`** (`hip-1352` — *Thinking Chains: proof-carrying research execution (canonical receipt)*).

- **License**: Apache-2.0
- **External Dependencies**: **Zero** (pure Go 1.24 stdlib + pure Python 3.12 stdlib)
- **Privacy Boundary**: Covers **public evidence and execution traces only** — private internal chain-of-thought (CoT) is explicitly prohibited and rejected.
- **Governance Separation**: Enforces independent verifier attestations (no self-attestation), authorized execution profile allowlists, and constitutional blocks against AI-authorized treasury spending, voting-rule modification, or unilateral authority escalation.

---

## Repository Layout

```text
thinking-chains/reference/
├── README.md                              # This overview
├── SPEC.md                                # Versioned canonical receipt spec (v1.0.0)
├── BENCHMARK.md                           # Reproducible benchmarks, negative regimes, unproven gaps
├── results.json                           # Raw benchmark measurements
├── schema/
│   └── canonical-receipt.v1.schema.json   # JSON Schema Draft 2020-12
├── fixtures/
│   ├── policy.json                        # Authorized execution profiles & trusted Ed25519 verifiers
│   ├── jobs_100.json                      # 100-job deterministic fixture (--seed 1352) grounded in repo files
│   ├── expected_hashes_100.json           # Pinned canonical_receipt_hash & provenance_root for all 100 jobs
│   └── adversarial_suite.json             # 31-case tamper, policy, CoT, constitutional & replay suite
├── go/                                    # Pure Go stdlib implementation (0 external deps)
│   ├── go.mod
│   ├── cmd/tc-verify/main.go
│   └── receipt/
│       ├── types.go
│       ├── canonical.go
│       ├── merkle.go
│       ├── verify.go
│       └── receipt_test.go
├── python/                                # Pure Python 3.12 stdlib implementation (0 external deps)
│   ├── tc_receipt/
│   │   ├── __init__.py
│   │   ├── ed25519.py                     # Pure-stdlib RFC 8032 Ed25519
│   │   ├── canonical.py                   # Strict integer-only RFC 8785 canonicalizer
│   │   ├── merkle.py                      # RFC 6962 domain-separated Merkle tree & proofs
│   │   ├── verify.py                      # Independent verifier & constitutional guards
│   │   └── cli.py
│   └── tests/test_receipt.py
└── scripts/
    ├── generate_fixtures.py               # Deterministic --seed 1352 fixture generator
    ├── cross_verify.py                    # Go vs Python bit-identity & adversarial parity proof
    └── run_benchmark.py                   # Reproducible benchmark & negative-regime runner
```

---

## Quickstart Verification

Run all verification checks from the repository root (`/home/antigravity/Boxxji/papers`):

### 1. Go Verification (`go vet` + `-race` tests)

```bash
(cd thinking-chains/reference/go && go vet ./... && go test -v -race -count=1 ./...)
```

### 2. Python Verification (`unittest`)

```bash
(cd thinking-chains/reference/python && python3 -m unittest discover -s tests -v)
```

### 3. Cross-Language Differential Parity (Go vs Python on 100 jobs + 31 adversarial cases)

```bash
python3 thinking-chains/reference/scripts/cross_verify.py
```

### 4. CLI Usage Examples

```bash
# Verify 100-job fixture using Go CLI
(cd thinking-chains/reference/go && go run ./cmd/tc-verify verify-batch \
  --policy ../fixtures/policy.json \
  --fixture ../fixtures/jobs_100.json)

# Verify 100-job fixture using Python CLI
(cd thinking-chains/reference/python && python3 -m tc_receipt.cli verify-batch \
  --policy ../fixtures/policy.json \
  --fixture ../fixtures/jobs_100.json)
```

### 5. Reproducible Benchmarks

```bash
python3 thinking-chains/reference/scripts/run_benchmark.py
```

See [`SPEC.md`](SPEC.md) for the wire/hashing specification and [`BENCHMARK.md`](BENCHMARK.md) for exact performance numbers, negative regimes, and open research gaps.

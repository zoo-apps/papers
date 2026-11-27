# Constitutional Governance & Formal Protocol Verification Reference (`constitutional-gov.v1`)

Apache-2.0 reference implementation, OPA Rego v1 policy bundle, bounded state-space model checker, 47-case Ed25519-signed adversarial suite, independent dual Go/Python verifiers, and grounded benchmark for **`zoo-apps/papers#16`** (`HIP-1352`), extending `zoo-dao-emergency-protocol.tex` (ZIP-0027).

## Directory Layout

```text
reference/
  SPEC.md                               # Versioned formal specification (constitutional-gov.v1, v1.0.0)
  BENCHMARK.md                          # Reproducible benchmark, mutation audit & 3 honest negative regimes
  results.json                          # Grounded deterministic benchmark output (seed=1352)
  schema/
    constitutional-gov.v1.schema.json   # JSON Schema (Draft 2020-12)
  rego/
    constitution.rego                   # OPA Rego v1 master constitutional policy (INV-01..INV-10)
    delegation.rego                     # Acyclic bounded delegation & transitive revocation (INV-02, INV-03)
    emergency.rego                      # ZIP-0027 DEFCON-1 72h auto-sunset & pause guard (INV-05)
    conflict.rego                       # 4-tier precedence & fail-closed ConflictWitness (INV-07)
    constitution_test.rego              # OPA Rego v1 unit test suite (`opa test rego/ -v`)
  go/                                   # Zero-dependency Go 1.24 stdlib engine, model checker & CLIs
    cmd/govcheck-bench/                 # Reproducible benchmark generator
    cmd/govcheck-verify/                # Standalone Go Ed25519 + Merkle verifier
    internal/govcheck/                  # State machine, conflict engine, invariants, BFS/fuzzer, tests
  python/                               # Zero-dependency Python 3.12 stdlib independent verifier
    govcheck_verifier/                  # Pure-Python RFC 8032 Ed25519, state machine, Rego v1 linter, CLI
    tests/                              # 12-test unittest parity suite
```

## Quick Verification

```bash
# Go vet + race-detector test suite (17 tests, 0 races)
(cd go && go vet ./... && go test -v -race -count=1 ./...)

# Independent Go CLI verification of results.json
(cd go && go run ./cmd/govcheck-verify --in ../results.json --rego-dir ../rego)

# Independent pure-Python 3.12 stdlib verification (12 tests, 100% Go/Python bit-identical parity)
(cd python && python3 -m unittest discover -v)
```

## License

Licensed under the Apache License, Version 2.0.

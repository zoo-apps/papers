# Zoo DAO Quadratic Funding & Sybil-Resistance Reference Simulator

Reference implementation, versioned specification (`qf-simulator.v1`), reproducible benchmark, and dual-language zero-dependency audit verifier for **`zoo-apps/papers#6`** (HIP-1352).

## Directory Layout

```text
zoo-dao-governance/reference/
├── README.md                              # Quickstart and overview
├── SPEC.md                                # Versioned qf-simulator.v1 mathematical & hashing specification
├── BENCHMARK.md                           # Published head-to-head comparison, negative regimes & unproven gaps
├── results.json                           # Deterministic benchmark artifact (--seed 1352, 15 scenarios x 6 mechanisms)
├── scenarios.json                         # Full raw exported scenarios for independent replay verification
├── schema/
│   └── qf-simulator.v1.schema.json        # JSON Schema (Draft 2020-12) for results.json
├── go/                                    # Pure Go 1.24 stdlib simulator & CLI (0 external dependencies)
│   ├── go.mod
│   ├── cmd/qf-sim/main.go
│   └── internal/qfsim/
│       ├── types.go                       # Exact micro-ZOO integer types & protocol constants
│       ├── canonical.go                   # Domain-separated SHA-256 hashing & binary Merkle tree
│       ├── corpus.go                      # Real .tex paper grant corpus loader (12 Zoo papers)
│       ├── mechanisms.go                  # 6 exact-integer mechanisms + Hamilton & capped water-filling
│       ├── governance.go                  # HIP-1352 constitutional AI-gate & 3-of-5 human steward checks
│       ├── metrics.go                     # Exact integer Gini, merit welfare, extraction & ROI metrics
│       ├── scenarios.go                   # Deterministic 15-scenario attack & negative-regime suite
│       ├── runner.go                      # Full benchmark runner emitting audit_merkle_root
│       └── qfsim_test.go                  # Unit, property, negative-regime & race-safety test suite
└── python/                                # Pure Python 3.12 stdlib independent verifier (0 external deps)
    ├── qf_verifier/
    │   ├── canonical.py                   # Independent SHA-256 canonical hashing & Merkle tree
    │   ├── mechanisms.py                  # Independent exact-integer recomputation of all 6 mechanisms
    │   ├── verifier.py                    # End-to-end audit verifier + .tex digest & AI-gate checks
    │   └── cli.py                         # Verification CLI
    └── tests/
        └── test_verifier.py               # Cross-language audit & tamper-detection unittest suite
```

## Quickstart

### Run Go Simulator & Race-Checked Tests
```bash
cd go
go vet ./...
go test -v -race -count=1 ./...
go run ./cmd/qf-sim --seed 1352 --papers-root ../../.. --out ../results.json --scenarios-out ../scenarios.json
```

### Run Independent Python Audit Verifier
```bash
cd python
python3 -m qf_verifier.cli --results ../results.json --scenarios ../scenarios.json --papers-root ../../..
python3 -m unittest discover -v
```

Both languages independently verify exact pool conservation (`sum(match_i) == MatchingPool`) across all 90 evaluations and produce the bit-identical SHA-256 `audit_merkle_root`:
`e6c9855606e6fcfac1193526be9605d98175a8039a9ba09404be5ab799a8333d`.

## License

Apache-2.0

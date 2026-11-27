# Zoo Scientific Contribution Attribution & Reputation Reference (`attribution-rep.v1`)

Clean-room Apache-2.0 reference implementation, versioned specification (`v1.0.0`), JSON Schema, grounded 12-paper corpus manifest, published copy-and-collusion attack test suite (`207` DAG events, `32` explicit adversarial checks), reproducible benchmark (`--seed 1352`), and dual independent zero-dependency **Go 1.24 + pure-Python 3** verifiers for **`zoo-apps/papers#11`** (HIP-1352).

## Highlights

- **Zero External Dependencies**: Both Go (`go/go.mod`, stdlib only) and Python (`python/attrrep_py/`, stdlib only including clean-room pure-Python RFC 8032 Ed25519 verification) compile and run completely offline without third-party packages.
- **100.0% Go ↔ Python Bit-Identical Parity**: Exact 64-bit fixed-point micro-credit (`1,000,000`) and basis-point (`10,000`) arithmetic produces identical attribution credits, EigenTrust scores, ZooRep tiers, adversarial error codes, and RFC 6962 `audit_merkle_root` (`7b4cb61df81118215c869d9c37cfcff8515b78f171404d8bcbcd717d6f742b5d`).
- **Anti-Copy & Exact Credit Conservation**: Combines raw SHA-256 deduplication, LaTeX/comment/macro canonical normalization, and deterministic 4-shingle Winnowing fingerprinting ($w = 3$) so copies mint `0` credit (`1.00x` conservation vs `2.00x` naive double-counting) and genuine derivatives share upstream citation flow strictly from their verified novel delta.
- **Sybil-Resistant Seeded Reputation & AI Guards**: Verifies EAS-compatible signed attestations (`AttestationUID`, revocation, expiration, cross-epoch replay protection, ZIP-0026 issuer rate limits), enforces constitutional `AI_AGENT` boundaries (`ERR_AI_SELF_ATTEST_FORBIDDEN`, `ERR_AI_POLICY_MUTATION_FORBIDDEN`, `ERR_AI_TREASURY_FORBIDDEN`), collapses collusion rings via Tarjan SCC, caps correlated Sybil farms via target-set Jaccard clustering, and runs sub-stochastic seeded EigenTrust power iteration.

## Layout

```
zoo-dao-reputation-system/reference/
├── README.md                            # Overview and quickstart
├── SPEC.md                              # Normative attribution-rep.v1 (v1.0.0) specification + What Remains Unproven
├── BENCHMARK.md                         # Reproducible benchmark tables & 3 honest negative regimes
├── corpus-manifest.json                 # SHA-256 pinned manifest of 12 real zoo-apps/papers .tex sources
├── results.json                         # Machine-readable benchmark output (--seed 1352)
├── schema/
│   └── attribution-rep.v1.schema.json   # JSON Schema Draft 2020-12
├── fixtures/
│   └── attribution-suite.v1.json        # Published 207-event DAG & 32-attack adversarial test suite
├── go/                                  # Zero-dependency Go 1.24 verifier, benchmark generator & tests
│   ├── go.mod
│   ├── attrrep/
│   └── cmd/{attr-verify,attr-bench}/
└── python/                              # Zero-dependency pure-Python 3 verifier (incl. RFC 8032 Ed25519) & tests
    ├── attrrep_py/
    └── tests/
```

## Quick Verification

```bash
# Go verifier & race-tested unit suite
(cd go && go vet ./... && go test -v -race -count=1 ./...)

# Pure-Python verifier, RFC 8032 Ed25519 vectors & Go-Python parity test
(cd python && python3 -m unittest discover -v)

# Regenerate fixtures, corpus-manifest.json, and results.json deterministically
(cd go && go run ./cmd/attr-bench --seed 1352)
```

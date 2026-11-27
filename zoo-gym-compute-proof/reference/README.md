# Attested vs Challenged Inference Verification Reference Implementation

Clean-room **Apache-2.0** reference implementation, versioned specification (`inference-verify.v1`, `v1.0.0`), reproducible benchmark, and dual independent **Go** + **Pure-Python** verifiers for **`zoo-apps/papers#14`** (*"Attested vs challenged inference verification"*, **HIP-1350**; references: **in-toto DSSE v1**, **Sigstore Cosign / Rekor RFC 6962**, **RFC 8032 Ed25519**).

Zero external dependencies in both Go (`go.mod` stdlib only) and Python (`python3` stdlib only, including clean-room pure-Python RFC 8032 Ed25519 verification).

## Directory Layout

```text
zoo-gym-compute-proof/reference/
├── README.md                              # Overview, quickstart & headline results
├── SPEC.md                                # Normative v1.0.0 specification, threat model & What Remains Unproven
├── BENCHMARK.md                           # Reproducible --seed 1350 benchmark report & 3 honest negative regimes
├── corpus-manifest.json                   # Pinned SHA-256 digests of 7 real zoo-apps/papers .tex sources
├── results.json                           # Raw deterministic benchmark output (--seed 1350)
├── schema/
│   └── inference-verify.v1.schema.json    # JSON Schema Draft 2020-12
├── fixtures/
│   └── verification-suite.v1.json         # 225-case parity suite (200 golden + 25 adversarial attacks)
├── go/                                    # Pure Go stdlib engine, benchmark & verifier (0 external deps)
│   ├── go.mod
│   ├── inferverify/
│   │   ├── types.go                       # Normative schema types, regimes, verdicts & error codes
│   │   ├── inference.go                   # Grounded .tex corpus loader & deterministic int64 quantized MLP
│   │   ├── dsse.go                        # in-toto Statement v1 + DSSE PAE + RFC 8032 Ed25519
│   │   ├── tlog.go                        # Sigstore Cosign/Rekor RFC 6962 Merkle tree & inclusion proofs
│   │   ├── challenge.go                   # Unpredictable post-commit challenge sampler & economic model
│   │   ├── verifier.go                    # Unified 4-regime verifier, constitutional guards & audit root
│   │   ├── benchmark.go                   # 4-regime comparison, 60-cell sweep, 3 negative regimes & fixtures
│   │   └── inferverify_test.go            # 8 race-detector unit, property & negative-regime tests
│   └── cmd/
│       ├── verify-bench/main.go           # Reproducible benchmark + fixture generator CLI
│       └── verify-audit/main.go           # Independent Go fixture verifier CLI
└── python/                                # Independent Pure Python 3.12 stdlib verifier (0 external deps)
    ├── inferverify_py/
    │   ├── __init__.py
    │   ├── ed25519.py                     # Clean-room pure-Python RFC 8032 Ed25519 verifier
    │   ├── inference.py                   # Bit-identical quantized integer MLP engine
    │   ├── dsse.py                        # in-toto DSSE PAE & Ed25519 verification
    │   ├── tlog.py                        # RFC 6962 Merkle inclusion proof & checkpoint verifier
    │   ├── verifier.py                    # Independent 4-regime verifier & constitutional guards
    │   └── cli.py                         # Parity & verification CLI
    └── tests/
        ├── __init__.py
        └── test_inferverify_py.py         # 8 unittest cases asserting 100% Go <-> Python parity
```

## Quickstart & Verification

```bash
cd zoo-gym-compute-proof/reference

# Go vet + race-detector test suite (8 tests, 0 races)
(cd go && go vet ./... && go test -v -race -count=1 ./...)

# Pure-Python unittest suite (8 tests, 0 external deps)
(cd python && python3 -m unittest discover -v)

# Reproduce benchmark (--seed 1350) and assert 100.00% Go <-> Python bit-identical parity
(cd go && go run ./cmd/verify-bench --repo ../../.. --manifest ../corpus-manifest.json --seed 1350 --out ../results.json --fixtures ../fixtures/verification-suite.v1.json)
(cd go && go run ./cmd/verify-audit --suite ../fixtures/verification-suite.v1.json)
(cd python && python3 -m inferverify_py.cli --suite ../fixtures/verification-suite.v1.json --go-results ../results.json)
```

## Headline Benchmark Results (`--seed 1350`)

- **Cross-Language Parity (`Go <-> Python`)**: **`225 / 225` (100.00%)** (`200` golden traces + `25` adversarial attacks), bit-identical verdicts, error codes, and `audit_merkle_root` (`25c97f0530963ec34792d8ff08eaad79080829c7cd9992d8bdd90b16054b199d`).
- **Four Regimes Under Identical Threat Model** (mixed fleet of `1,000` jobs, `59` cheated jobs, fee `10.0`, honest cost `5.0`, cheat cost `0.25`, slash `150.0`):
  - **`signed_attestation_only`** (in-toto DSSE + Rekor RFC 6962): `1.000x` compute (`173.60 µs` verify), **`0.00%` valid-key cheat detection** (`59/59` escaped, `+4.75`/job cheater advantage).
  - **`independent_reexecution` (`k=3`)**: **`100.00%` cheat detection**, `0.00%` honest FRR, but **`3.000x` compute cost** (`200%` redundant compute even on honest bulk workloads).
  - **`random_challenge_verification`** (`p ∈ {0.01..0.50}`): `1 + p` compute cost, strictly incentive-compatible iff $p(F + S) > c_{\text{honest}} - c_{\text{cheat}}$, but vulnerable to small-sample variance at low uniform $p$ and exploitable when undercollateralized.
  - **`hybrid_attested_plus_challenged`** (100% DSSE + tlog + adaptive `5%/25%` challenge): **`1.091x` compute (`< 1.10x`)** on the mixed fleet (`1.073x` on honest bulk), **`25.42%` cheat detection** (matching uniform `p=0.25` at half the overhead), driving cheater profit to **`-30.93`/job** (`-35.93` vs honest).
- **Constitutional & AI-Role Guards**: `AI_AGENT` advisory escalation is bounded within pre-approved `[min_challenge_bps, max_challenge_bps]`; attempts to self-certify (`ERR_AI_SELF_CERT_FORBIDDEN`), mutate bond/quorum/challenge policy (`ERR_AI_POLICY_MUTATION_FORBIDDEN`), approve slashing (`ERR_AI_SLASH_APPROVAL_FORBIDDEN`), or overclaim TEE/scientific proof scope (`ERR_OVERCLAIMED_PROOF_SCOPE`) are deterministically rejected with `POLICY_REJECTED`.
- **Three Honest Negative Regimes & What Remains Unproven**: Documented in full in [`BENCHMARK.md`](BENCHMARK.md) and [`SPEC.md`](SPEC.md).

## License

Apache-2.0.

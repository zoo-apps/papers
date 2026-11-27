# Useful-Work Receipt & Contribution Settlement Reference (`settlement-receipt.v1`)

Apache-2.0, zero-dependency reference implementation, normative specification (`v1.0.0`), Draft 2020-12 JSON Schema, dual independent Go 1.24 + Pure Python 3.12 stdlib verifiers, and reproducible 3-node loopback test-network benchmark for **`zoo-apps/papers#15`** (`HIP-1350`).

## Architecture Overview

Implements the five-stage lifecycle **`Admit -> Perform -> Verify -> IssueReceipt -> AuthorizeReward`** across three cryptographically isolated authority layers:

1. **Layer 1 — Admission & Independent Validation (`ValidatorCommittee`)**: Admits jobs with escrowed micro-ZOO budgets grounded in pinned `.tex` corpus SHA-256 digests, independently verifies performed work, and signs EAS-compatible RFC 8032 Ed25519 attestations (`AttestationUID`). Validators never hold treasury keys and cannot self-verify (`ERR_SELF_VERIFICATION_FORBIDDEN`).
2. **Layer 2 — Receipt Settlement & Nullifier Ledger (`SettlementEngine`)**: Verifies validator quorum (`3`-of-`5`), computes exact dust-free `int64` micro-ZOO splits (provider / 2% conservation / 1% protocol / payer refund), enforces a crash-safe `fsync` hash-chained WAL nullifier set blocking all double-claims and concurrent races (`ERR_DOUBLE_CLAIM`), commits per-epoch binary Merkle roots, and exposes read-only receipt queries to downstream applications (`ERR_APP_ISSUANCE_FORBIDDEN`).
3. **Layer 3 — Finality & Authorized Reward Issuance (`FinalityTreasuryGate`)**: Enforces epoch finality delay ($K = 2$), claim window ($W = 6$), Merkle inclusion proofs, Layer 3 nullifier uniqueness, and governance treasury caps under `GOVERNANCE_TREASURY` signatures while constitutionally blocking `AI_AGENT` and `APPLICATION` roles from treasury disbursement (`ERR_AI_ISSUANCE_FORBIDDEN`) or policy mutation (`ERR_AI_POLICY_MUTATION_FORBIDDEN`).

## Deliverables

- [`SPEC.md`](SPEC.md) — Normative `settlement-receipt.v1` v1.0.0 specification and explicit *What Remains Unproven* section.
- [`schema/settlement-receipt.v1.schema.json`](schema/settlement-receipt.v1.schema.json) — JSON Schema Draft 2020-12.
- [`BENCHMARK.md`](BENCHMARK.md) & [`results.json`](results.json) — Reproducible `--seed 1350` benchmark (200 grounded jobs, 24/24 adversarial attacks blocked, 64-goroutine `-race` stress, WAL cold-restart & permutation invariance, and 3 honest negative regimes).
- [`corpus-manifest.json`](corpus-manifest.json) — Pinned SHA-256 manifest of 8 real `.tex` papers from `zoo-apps/papers`.
- [`fixtures/settlement-trace.v1.json`](fixtures/settlement-trace.v1.json) — Canonical 224-case trace bundle verified bit-identically by Go and Python (`audit_merkle_root = 0cac816fdf6e2333a04b02f373a59a2ca5f2fffba623f7f44deb7a50ecf5aa0b`).
- [`go/`](go/) — Pure Go 1.24 stdlib 3-layer engine, loopback HTTP/JSON-RPC multi-node test network, `fsync` WAL, CLIs (`settle-bench`, `settle-verify`), and 16-test `-race` suite (0 external deps).
- [`python/`](python/) — Independent Pure Python 3.12 stdlib verifier including pure-Python RFC 8032 Ed25519 verification, Merkle proof checker, CLI, and unittest parity suite (0 external deps).

## Quick Verification

```bash
# Go vet + full -race test suite (16/16 PASS, 0 data races)
(cd go && go vet ./... && go test -v -race -count=1 ./...)

# Independent Python 3.12 stdlib verifier + Go<->Python bit-identical parity suite
(cd python && python3 -m unittest discover -v)

# Regenerate canonical trace & benchmark results (--seed 1350)
(cd go && go run ./cmd/settle-bench --seed 1350)
```

## License

Apache License, Version 2.0.

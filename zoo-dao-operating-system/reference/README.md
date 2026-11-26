# Open ResearchDAO Operating System — Reference Implementation (`researchdao-os.v1`)

Clean-room, zero-dependency reference implementation and reproducible research artifact for **`zoo-apps/papers#2`** (`HIP-1352` — *Open ResearchDAO operating system*), grounded in the Zoo DAO paper suite:

- [`zoo-dao-operating-system.tex`](../zoo-dao-operating-system.tex) (ZooGov, ZIP-0017)
- [`zoo-dao-research-governance.tex`](../../zoo-dao-research-governance/zoo-dao-research-governance.tex) (Research DAO & Peer Review, ZIP-0603/0604)
- [`zoo-dao-grants-program.tex`](../../zoo-dao-grants-program/zoo-dao-grants-program.tex) (Milestone Escrow & Grants, ZIP-0023)
- [`zoo-dao-emergency-protocol.tex`](../../zoo-dao-emergency-protocol/zoo-dao-emergency-protocol.tex) (DEFCON Emergency Governance, ZIP-0027)

## What Is Included

| Path | Description |
|------|-------------|
| [`SPEC.md`](SPEC.md) | Versioned protocol specification (`researchdao-os.v1`), constitutional AI invariants, canonical JSON, domain-separated SHA-256 & Merkle root rules, WAL & checkpoint replay semantics. |
| [`schema/researchdao-os.v1.schema.json`](schema/researchdao-os.v1.schema.json) | Draft 2020-12 JSON Schema for `genesis.json`, RFC 8032 Ed25519 signed transition envelopes, and checkpoints. |
| [`go/`](go/) | Pure Go 1.24 stdlib (`0` external modules) implementation of the 5-stage ResearchDAO OS state machine, `fsync`-backed WAL + checkpoints, cold-restart replay, adversarial suite, `-race` tests, and benchmark CLI. |
| [`python/`](python/) | Independent pure Python 3.12 stdlib (`0` external packages, pure-stdlib RFC 8032 Ed25519) verifier that independently replays Go-exported WALs and checkpoints to prove 100% bit-identical `state_root_hash` and `audit_merkle_root`. |
| [`BENCHMARK.md`](BENCHMARK.md) | Reproducible benchmark analysis grounded in real `.tex` papers from `zoo-apps/papers`, 16-attack adversarial authorization matrix, 3 honest negative regimes, and an explicit *What Remains Unproven* section. |
| [`results.json`](results.json) | Exact reproducible benchmark telemetry generated with `--seed 1352`. |

## Quickstart & Verification

### 1. Run Go Vet & Race-Detected Test Suite
```bash
cd zoo-dao-operating-system/reference/go
go vet ./...
go test -v -race -count=1 ./...
```

### 2. Run Independent Python 3.12 Stdlib Verifier & Go/Python Parity Tests
```bash
cd zoo-dao-operating-system/reference/python
python3 -m unittest discover -v
```

### 3. Reproduce Benchmark & Cross-Language Cold-Restart Verification (`--seed 1352`)
```bash
cd zoo-dao-operating-system/reference/go
WAL_DIR=$(mktemp -d)
go run ./cmd/researchdao-bench \
  --seed 1352 \
  --papers-root ../../.. \
  --out ../results.json \
  --export-wal "$WAL_DIR"

# Verify cold-restart (full WAL vs checkpoint+delta) in Go
go run ./cmd/researchdao-bench --verify-wal "$WAL_DIR"

# Independently verify the exact same WAL in pure Python stdlib
STATE_ROOT=$(jq -r .final_state_root_hash ../results.json)
AUDIT_ROOT=$(jq -r .final_audit_merkle_root ../results.json)
PYTHONPATH=../python python3 -m researchdao_verifier.cli \
  --wal-dir "$WAL_DIR" \
  --expect-state-root "$STATE_ROOT" \
  --expect-audit-root "$AUDIT_ROOT"

rm -rf "$WAL_DIR"
```

## License

Apache-2.0 (`SPDX-License-Identifier: Apache-2.0`).

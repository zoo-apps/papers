<!-- SPDX-License-Identifier: Apache-2.0 -->

# Zoo Decentralized Experience Ledger — Reference Implementation (`zoo-experience-ledger/v1`)

Reference implementation, versioned specification, dual Go/Python zero-dependency verifiers, real-corpus fixture suite, and reproducible benchmark for **`zoo-apps/papers#10`** (*Decentralized experience ledger*, HIP-1352).

Grounded in:
- `zoo-experience-ledger/` (*Zoo Experience Ledger: Decentralized Content-Addressed Semantic Experience Memory*)
- `experience-ledger-dso/` (*Decentralized Semantic Optimization via Curated Experience Ledgers*)

---

## Core Guarantees

1. **No Second Storage Stack (Hanzo VFS / S3 Native)**:
   Every durable research artifact (paper excerpts, trajectories, embeddings, conflict evidence bundles, steward rationales, checkpoint snapshots) is addressed strictly by SHA-256 pointer (`vfs://sha256/<hex>` or `s3://<bucket>/sha256/<hex[0:2]>/<hex>`). Optional `external_uris` (`ipfs://...`, `ar://...`, `https://...`) provide portability without introducing a separate primary storage stack.
2. **Order-Independent Commutative Replay**:
   Concurrent writers appending events in any arrival permutation converge deterministically to the **exact same** `state_root_hash` and `active_merkle_root` across both the Go and independent pure-Python implementations.
3. **Cryptographic Provenance & Cascading Revocation**:
   All events are SHA-256 content-addressed and RFC 8032 Ed25519 signed. Only the original author or an authorized `steward` may revoke an entry; revocations deterministically propagate causal taint through the `parent_hashes` DAG.
4. **Explicit Conflict Handling & Constitutional Separation**:
   Divergent claims on the same `(domain, claim_key)` are preserved explicitly in a `ConflictSet` (never silently overwritten via last-write-wins).
   - **AI agents (`ai_agent`)** may contribute entries, self-revoke their own entries, and flag conflicts with VFS evidence bundles — they are **cryptographically blocked** from issuing `ResolutionDecision` events (`ERR_AI_AGENT_RESOLUTION_FORBIDDEN`) or revoking another principal's entries (`ERR_UNAUTHORIZED_REVOCATION`).
   - **Stewards (`steward`)** may resolve conflicts only with **distinct-verifier separation** (`steward_id != winning_entry.contributor_id`; self-validation is rejected with `ERR_SELF_VALIDATION_FORBIDDEN`). Steward disagreements escalate cleanly to `escalated_steward_disagreement`.

---

## Layout

```
zoo-experience-ledger/reference/
├── README.md                              # Overview & quickstart
├── SPEC.md                                # Versioned specification (zoo-experience-ledger/v1)
├── BENCHMARK.md                           # Reproducible benchmark report & honest negative regimes
├── results.json                           # Machine-readable benchmark output (--seed 1352)
├── schema/
│   └── experience-ledger.v1.schema.json   # JSON Schema (Draft 2020-12)
├── fixtures/
│   ├── policy.json                        # Registered Ed25519 principals (human, AI agent, steward)
│   ├── corpus_events.json                 # 95-event corpus grounded in 40 real zoo-apps/papers .tex files
│   └── expected_state.json                # Canonical reconstructed state & root hash
├── go/                                    # Zero-dependency Go 1.24 reference engine & CLIs
│   ├── go.mod                             # 0 external modules
│   ├── ledger/                            # types, canonical, vfs, merkle, replay, store, tests
│   └── cmd/
│       ├── xel-replay/                    # replay & permute-check CLI
│       └── xel-bench/                     # concurrent/scale/dedup/Sybil benchmark driver
├── python/                                # Independent zero-dependency Python 3.12 verifier
│   ├── experience_ledger/                 # canonical, pure-Python RFC 8032 ed25519, vfs, merkle, replay, cli
│   └── tests/                             # unittest suite
└── scripts/
    ├── generate_fixtures.py               # Deterministic real-.tex fixture generator (--seed 1352)
    ├── cross_verify.py                    # Go vs Python 22-permutation bit-exact parity verifier
    └── run_benchmark.py                   # Full reproducible benchmark harness -> results.json
```

---

## Quickstart & Verification

### 1. Go Reference Engine (`-race`, zero external dependencies)
```bash
cd zoo-experience-ledger/reference/go
go vet ./...
go test -v -race -count=1 ./...
```

### 2. Independent Pure-Python Verifier (zero external packages)
```bash
cd zoo-experience-ledger/reference/python
PYTHONPATH=. python3 -m unittest discover -s tests -v
```

### 3. Cross-Language Go vs Python Permutation Convergence (Forward + Reverse + 20 Random Shuffles)
```bash
cd zoo-experience-ledger/reference
python3 scripts/cross_verify.py
```

### 4. Reproduce Fixtures & Benchmark (`--seed 1352`)
```bash
cd zoo-experience-ledger/reference
python3 scripts/generate_fixtures.py --seed 1352
python3 scripts/run_benchmark.py --seed 1352
```

---

## License

Apache-2.0 (`SPDX-License-Identifier: Apache-2.0`).

<!-- SPDX-License-Identifier: Apache-2.0 -->

# Zoo Decentralized Experience Ledger — Reproducible Benchmark & Research Artifact (`zoo-apps/papers#10`)

**Specification**: `zoo-experience-ledger/v1` (HIP-1352)
**Seed**: `--seed 1352`
**Environment**: `go1.24.3` (`linux/amd64`, 2 vCPU), `Python 3.12.16`, zero external dependencies in both Go and Python.
**Corpus Grounding**: 40 real `.tex` papers and paper sections from `zoo-apps/papers` (including `zoo-experience-ledger/sections/*.tex`, `experience-ledger-dso/sections/*.tex`, and top-level whitepapers; `160,361` unique artifact bytes).
**Raw Machine-Readable Output**: [`results.json`](./results.json)

### Reproduction Command
```bash
cd zoo-experience-ledger/reference
python3 scripts/generate_fixtures.py --seed 1352
python3 scripts/run_benchmark.py --seed 1352
```

---

## 1. Cross-Language Go vs Python Permutation Convergence Proof

Both the Go (`go/cmd/xel-replay`) and independent pure-Python (`python/experience_ledger/cli.py`, RFC 8032 pure-Python Ed25519) replayers executed the 95-event real-paper corpus (`fixtures/corpus_events.json`) across **22 arrival orders each** (forward, reverse, and 20 deterministic random shuffles with `--seed 1352`):

| Metric | Go Reference (`go1.24.3`) | Independent Python (`3.12.16`) | Parity |
|---|---|---|---|
| Permutations Tested | 22 (fwd + rev + 20 shuffled) | 22 (fwd + rev + 20 shuffled) | **44 / 44 converged** |
| `state_root_hash` | `d0c57594f7b2c04ea761241763ffeac211e180bc550c6c50029e9f5851c19357` | `d0c57594f7b2c04ea761241763ffeac211e180bc550c6c50029e9f5851c19357` | **Bit-identical** |
| `active_merkle_root` | `f9c142a2252f0d23a2f04d27d70254248adfe10c841a0040f1335b78e2a65e81` | `f9c142a2252f0d23a2f04d27d70254248adfe10c841a0040f1335b78e2a65e81` | **Bit-identical** |
| Corpus Events | 95 total (87 unique accepted, 3 idempotent duplicates) | 95 total (87 unique accepted, 3 idempotent duplicates) | **Exact match** |
| Reconstructed Entries | 75 total (63 active, 2 revoked, 3 tainted, 4 conflicted, 3 superseded) | 75 total (63 active, 2 revoked, 3 tainted, 4 conflicted, 3 superseded) | **Exact match** |
| Explicit `ConflictSet`s | 5 (`select_canonical`, `keep_both_scoped`, `reject_all`, `open`, `escalated_steward_disagreement`) | 5 | **Exact match** |
| Rejected Adversarial Events | 8 (`ERR_AI_AGENT_RESOLUTION_FORBIDDEN`, `ERR_UNAUTHORIZED_RESOLUTION`, `ERR_SELF_VALIDATION_FORBIDDEN`, `ERR_UNAUTHORIZED_REVOCATION` ×2, `ERR_EVENT_ID_MISMATCH`, `ERR_INVALID_SIGNATURE`, `ERR_UNKNOWN_PRINCIPAL`) | 8 | **Exact match** |

---

## 2. Concurrent Multi-Writer Ingestion & VFS/S3 Deduplication

Measured with `16`, `32`, and `64` concurrent Go writer goroutines (`16` events/writer = `256` / `512` / `1,024` signed events backed by the 40 real `.tex` artifacts in `LocalVFSStore` using `s3://hanzo-research-vfs/sha256/<p>/<hex>` addressing), verified with 20 random replay permutations per run and separately verified race-free under `go test -race`:

| Concurrent Goroutines | Events | Concurrent Ingest (ms) | Full Replay (ms) | Replay Throughput (ev/s) | Shuffled Permutations Converged | Logical Artifact Bytes | Deduplicated VFS Bytes | VFS Dedup Savings |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 16 | 256 | 26.05 | 29.76 | 8,602.73 | 20 / 20 (100%) | 998,671 | 160,361 | **83.94%** |
| 32 | 512 | 19.97 | 59.48 | 8,608.08 | 20 / 20 (100%) | 2,009,298 | 160,361 | **92.02%** |
| 64 | 1,024 | 48.46 | 131.46 | 7,789.68 | 20 / 20 (100%) | 4,073,579 | 160,361 | **96.06%** |

---

## 3. Honest Negative Regimes

To avoid misleading happy-path benchmarks, we explicitly measure three negative regimes where naive deployment choices degrade latency, storage, or liveness.

### Negative Regime A: Uncompacted Linear Replay at 10,000–20,000+ Events vs Periodic VFS Checkpoints

Replaying an uncompacted log from genesis scales linearly $O(N)$ in Ed25519 signature verifications and canonical hashing. Periodic content-addressed `CheckpointSnapshot` objects stored in VFS/S3 skip re-verifying already-checkpointed Ed25519 signatures and verify only the `delta = 50` newly arrived events, while guaranteeing bit-identical `state_root_hash`:

| Prefix Events ($N$) | Delta Events ($\Delta$) | Total Events | Uncompacted Linear Replay (ms) | VFS Checkpoint + Delta Replay (ms) | Speedup | Root Hash Match |
|---:|---:|---:|---:|---:|---:|:---:|
| 1,000 | 50 | 1,050 | 123.62 | 37.77 | **3.27×** | `true` |
| 5,000 | 50 | 5,050 | 584.93 | 201.91 | **2.90×** | `true` |
| 10,000 | 50 | 10,050 | 1,212.01 | 397.40 | **3.05×** | `true` |
| 20,000 | 50 | 20,050 | 3,932.37 | 862.87 | **4.56×** | `true` |

**Honest Limitation**: Even with VFS checkpoints skipping $N$ Ed25519 verifications, `ReplayFromCheckpoint` still takes `862.87 ms` at `20,050` events because it unmarshals the full JSON checkpoint and rebuilds the DAG/slot/Merkle index in memory ($O(N)$ memory & graph pass). Achieving sub-10ms hot-path updates at $10^6+$ events requires a persistent incremental Merkle-DAG / HAMT state trie rather than full-checkpoint JSON snapshots.

### Negative Regime B: Inline Artifact Blobs vs Hanzo VFS/S3 SHA-256 Pointers

Embedding raw artifact payloads (Base64-encoded `.tex` artifacts) inline inside the ledger event log vs storing only SHA-256 VFS/S3 pointers (`1,000` events referencing `40` unique real `.tex` artifacts):

| Metric | Inline Blobs in Event Log | VFS/S3 SHA-256 Pointers | Improvement |
|---|---:|---:|---:|
| Event Log Size (bytes) | 5,542,626 | 271,926 | **20.38× smaller log** |
| Combined Storage (log + unique VFS objects) | 5,542,626 | 432,287 | **12.82× less total storage** |
| JSON Serialization Latency (ms) | 16.00 | 2.78 | **5.76× faster marshal** |

**Honest Limitation**: Pointer separation requires VFS/S3 object availability when hydrating artifact payloads for semantic evaluation or human review. If an S3 bucket loses an unpinned object (and no optional `external_uris` mirror holds it), the ledger still proves tamper-evident provenance and converges identically on `state_root_hash`, but the underlying bytes are unavailable until restored.

### Negative Regime C: Adversarial Sybil Conflict Flooding & Rate-Limiting Tradeoffs

Because the ledger preserves conflicting claims explicitly rather than silently dropping them via LWW, an adversary controlling `50` registered Sybil accounts can flood `10` honest research slots with `500` conflicting spam claims (`510` total events):

| Configuration | Events Replayed | Spam Dropped | Replay Time (ms) | Honest Slots Forced into Conflict | Honest Slots Preserved Clean | Avg Fanout per Conflicted Slot |
|---|---:|---:|---:|---:|---:|---:|
| Unmitigated (no rate limit) | 510 | 0 | 57.27 | **10 / 10** (100%) | 0 / 10 | 51.0 |
| Per-Principal Rate Limit (3 claims/window) | 160 | 350 | 22.64 | **3 / 10** (30%) | 7 / 10 | 51.0 |

**Honest Tradeoff**: Per-principal admission rate limiting (matching `experience-ledger-dso` §6.4) drops 70% of spam volume (`350/500`), cuts replay time by `2.53×`, and rescues `7/10` honest slots — **but 50 distinct Sybil keys can still saturate 3 honest slots into 51-way conflict fanout**, degrading steward review throughput until economic staking (KEEPER bond slashing) or out-of-band identity admission gates prevent cheap Sybil key creation.

---

## 4. What Remains Unproven / Open Research Gaps

Per the bounty research integrity requirements, we explicitly state what this reference implementation **does not** prove:

1. **Semantic Equivalence & Embedding-Space Conflict Detection**:
   Conflict detection here keys on explicit `(domain, claim_key)` and exact `claim_value_hash` divergence (plus human/AI `ConflictFlag` events). Detecting semantically contradictory natural-language claims posted under *different* `claim_key` names or paraphrased phrasing (via 768/7680-dim embedding similarity and NLI entailment) remains an open ML/retrieval problem outside deterministic replay.
2. **Byzantine Network Gossip & Partition Liveness**:
   We prove strong eventual consistency (deterministic state convergence once replicas receive the same event set in any order), but we do **not** implement or prove P2P anti-entropy gossip protocols, Byzantine-fault-tolerant broadcast under eclipse attacks, or network partition recovery latency.
3. **Policy Key Rotation & On-Chain DAO Voting Execution**:
   `Policy` is treated as an immutable hash-committed trust anchor (`policy_sha256`). Multi-epoch key rotation, steward key compromise recovery, quorum/quadratic KEEPER token tallying, and stake-slashing smart contracts are explicitly out-of-band governance layers not executed inside the replay engine (and strictly off-limits to AI agents).
4. **Sub-Linear Persistent Indexing at $10^6+$ Events**:
   As demonstrated in Negative Regime A, full-checkpoint JSON replay remains $O(N)$ in graph rebuild cost. A persistent content-addressed HAMT / Merkle-CRDT trie for $O(\Delta \log N)$ incremental state transitions is left for v2.
5. **Post-Quantum Signatures**:
   Signatures use classical RFC 8032 Ed25519 for zero-dependency portability across Go and Python stdlibs; migrating to hybrid Ed25519 + ML-DSA-65 (per `zoo-3-0-full-pq/`) requires a `zoo-experience-ledger/v2` domain separator.
6. **External S3/IPFS/Arweave Pinning Guarantees**:
   The local VFS adapter verifies content-addressed SHA-256 integrity and S3 sharded key layout (`sha256/<hex[0:2]>/<hex>`), but durability SLAs, cross-region S3 replication, and IPFS/Arweave pinning persistence are operational storage concerns outside the unit benchmark.

# Open ResearchDAO Operating System — Reproducible Benchmark & Research Artifact

- **Specification**: [`SPEC.md`](SPEC.md) (`researchdao-os.v1`)
- **Raw Data**: [`results.json`](results.json)
- **Seed**: `--seed 1352`
- **Corpus**: 88 real `.tex` research papers discovered directly in `zoo-apps/papers`
- **Environment**: Linux x86_64, Go 1.24.3 stdlib (zero external modules), Python 3.12.16 stdlib (zero external packages)

---

## 1. End-to-End 100-Proposal Lifecycle & Cold-Restart Proof

We execute **100 complete research grant lifecycles** grounded in real SHA-256 content hashes of 88 `.tex` papers from `zoo-apps/papers` (`ProposalSubmitted` → non-binding AI `AdvisoryRecorded` → 3 independent `PeerReviewRecorded` → 2-of-3 `MilestoneApproved` → `FundingQueued` → `FundingCosigned` → 72h timelock → `FundingAuthorized` → `IndependentAcceptanceRecorded`), exercising 99 accepted grants with 10% holdback release and 1 narrow 501(c)(3) `BoardVetoRecorded` hold during timelock.

Every committed transition is signed with RFC 8032 Ed25519 and `fsync`ed line-by-line to `events.jsonl`.

| Metric | Value |
|--------|-------|
| Grounded `.tex` papers discovered | **88** |
| Proposals executed | **100** (`99` `ACCEPTED`, `1` `VETOED`) |
| Total signed, `fsync`-persisted events | **1,099** |
| Wall-clock time (including `fsync` + 3 mid-lifecycle cold restarts) | **6,806 ms** (`161.5 events/s`) |
| Final `state_root_hash` (Go full == Go delta == Python full == Python delta) | `c8cc8887e27dd86f829839147c881db7c578d2f32a27687c1af3f9419e838c7a` |
| Final `audit_merkle_root` (Go full == Go delta == Python full == Python delta) | `df572fc45d8982e6267adf5dc8ddd6782f04277cbc41adac2563124eb46d12fd` |

### Mid-Lifecycle Cold-Restart Verification

At proposals #25 (`seq=275`), #50 (`seq=550`), and #75 (`seq=825`), the running process writes an atomic checkpoint, closes the WAL, discards all in-memory state, cold-restarts via both `ReplayFull` and `ReplayFromLatestCheckpoint`, asserts 100% bit-identical roots, and resumes execution on the restarted machine:

| Cold Restart Point | Seq | Full WAL Replay | Checkpoint+Delta Replay | `state_root_hash` Prefix | `audit_merkle_root` Prefix | Bit-Identical? |
|--------------------|-----|-----------------|-------------------------|--------------------------|----------------------------|----------------|
| Proposal #25 | 275 | 86.7 ms | 29.9 ms | `3c08bfba0dba7a47…` | `aac9880ff339cd18…` | **YES** |
| Proposal #50 | 550 | 174.6 ms | 50.3 ms | `cd3cfa6ec869e2d5…` | `2239e8224da86067…` | **YES** |
| Proposal #75 | 825 | 210.5 ms | 43.1 ms | `7a303833dc0bd901…` | `c78ae4b4045a1932…` | **YES** |

### Independent Cross-Language Verification (Go 1.24 ↔ Python 3.12 Stdlib)

Replaying the Go-exported 1,099-event WAL (`genesis.json`, `events.jsonl`, `checkpoints/`) in the completely independent pure-Python 3.12 stdlib verifier (implementing RFC 8032 Ed25519, canonical JSON, state transitions, and binary Merkle trees with zero third-party packages) yields:

- **Go `state_root_hash`** == **Python `state_root_hash`**: `c8cc8887e27dd86f829839147c881db7c578d2f32a27687c1af3f9419e838c7a` (**100% bit-identical**)
- **Go `audit_merkle_root`** == **Python `audit_merkle_root`**: `df572fc45d8982e6267adf5dc8ddd6782f04277cbc41adac2563124eb46d12fd` (**100% bit-identical**)
- **Single-byte WAL tamper check**: both Go and Python reject a modified proposal ID in `events.jsonl` with `ERR_INVALID_SIGNATURE`.

---

## 2. Adversarial Authorization & Constitutional Matrix (16/16 Rejected)

Every attack below is executed against a live signed state machine; we assert both the exact deterministic error code and that `state_root_hash` and `audit_merkle_root` remain **bit-for-bit unchanged** after rejection.

| # | Attack Vector | Category | Expected / Actual Error Code | Blocked | State Unchanged |
|---|---------------|----------|------------------------------|---------|-----------------|
| 1 | AI agent attempts `FundingAuthorized` | `constitutional_ai` | `ERR_AI_TREASURY_FORBIDDEN` | Yes | Yes |
| 2 | AI agent attempts `GovernanceRuleAmended` | `constitutional_ai` | `ERR_AI_RULE_CHANGE_FORBIDDEN` | Yes | Yes |
| 3 | AI agent attempts `IndependentAcceptanceRecorded` | `constitutional_ai` | `ERR_AI_VALIDATION_FORBIDDEN` | Yes | Yes |
| 4 | Researcher attempts `FundingAuthorized` without steward role | `rbac` | `ERR_UNAUTHORIZED_ROLE` | Yes | Yes |
| 5 | Affiliation-conflicted reviewer attempts `PeerReviewRecorded` | `coi` | `ERR_COI_CONFLICT` | Yes | Yes |
| 6 | Declared-COI reviewer attempts `PeerReviewRecorded` | `coi` | `ERR_COI_CONFLICT` | Yes | Yes |
| 7 | Committee member submits `plan_hash` as milestone evidence | `evidence_integrity` | `ERR_EVIDENCE_MISMATCH` | Yes | Yes |
| 8 | Steward attempts funding exceeding `requested_amount` | `treasury_guard` | `ERR_BUDGET_CAP_EXCEEDED` | Yes | Yes |
| 9 | Single steward attempts `FundingAuthorized` below 2-of-5 quorum | `multisig_quorum` | `ERR_QUORUM_NOT_MET` | Yes | Yes |
| 10 | Steward attempts `FundingAuthorized` before 72h timelock | `timelock` | `ERR_TIMELOCK_NOT_ELAPSED` | Yes | Yes |
| 11 | Expired steward key attempts `FundingCosigned` | `key_lifecycle` | `ERR_ACTOR_EXPIRED` | Yes | Yes |
| 12 | Revoked steward key attempts `FundingCosigned` | `key_lifecycle` | `ERR_ACTOR_REVOKED` | Yes | Yes |
| 13 | Steward attempts `FundingAuthorized` during active DEFCON-1 pause | `emergency_breaker` | `ERR_SYSTEM_PAUSED` | Yes | Yes |
| 14 | Steward attempts double-spend replay of `FundingAuthorized` tranche | `double_spend` | `ERR_TRANCHE_ALREADY_DISBURSED` | Yes | Yes |
| 15 | Tampered envelope payload fails Ed25519 verification | `cryptography` | `ERR_INVALID_SIGNATURE` | Yes | Yes |
| 16 | Proposer with `PEER_REVIEWER` role attempts self-review | `self_dealing` | `ERR_SELF_REVIEW_FORBIDDEN` | Yes | Yes |

*(Additional unit tests also verify: revoked cosigner mid-queue invalidating steward quorum, board veto blocking subsequent funding, non-independent verifiers [proposer/reviewer/milestone approver] rejected with `ERR_VERIFIER_NOT_INDEPENDENT`, epoch spending cap exhaustion & 30-day rollover, and WAL/checkpoint byte tampering.)*

---

## 3. Honest Negative Regimes

### Regime (a): Uncompacted Linear WAL Cold-Restart Replay at 1k–10k Events vs. Checkpoint+Delta

As an append-only audit log grows without compaction, full cold-restart replay scales strictly linearly $O(N)$ in Ed25519 signature verifications and JSON parsing:

| Total Events ($N$) | Checkpoint @ Seq | Delta Events | WAL Size | Checkpoint Size | Full WAL Replay | Checkpoint+Delta Replay | Speedup | Roots Bit-Identical |
|--------------------|------------------|--------------|----------|-----------------|-----------------|-------------------------|---------|---------------------|
| 1,000 | 950 | 50 | 585.8 KB | 447.0 KB | 180.5 ms | 60.4 ms | **2.99×** | Yes |
| 5,000 | 4,750 | 250 | 2.94 MB | 2.17 MB | 922.6 ms | 288.8 ms | **3.19×** | Yes |
| 10,000 | 9,500 | 500 | 5.88 MB | 4.33 MB | 1,734.8 ms | 574.9 ms | **3.02×** | Yes |

**Honest Bottleneck Analysis**: Even with a checkpoint at 95% of the log, cold restart takes 574.9 ms at 10k events (~3× faster rather than ~20× faster) for two measurable reasons:
1. `ReplayFromCheckpointFile` still scans `events.jsonl` from byte 0 to skip `seq <= checkpoint.seq` instead of storing a verified byte offset.
2. Full JSON deserialization and full `StateRootHash` recomputation over the checkpoint's embedded state (`4.33 MB` when 9,500 advisory records live inside one proposal) dominates restart time. Production deployments beyond $10^5$ transitions require byte-indexed WAL segments, incremental state-trie hashing (SMT/Verkle), and archival compaction of terminal proposals.

### Regime (b): High Multi-Sig Quorum ($m$-of-$n$) Latency & Offline-Steward Deadlock Risk

Monte Carlo simulation (`500` trials per configuration, `--seed 1352`) of independent steward availability ($p \in \{95\%, 85\%, 70\%\}$) across treasury multi-sig thresholds:

| Quorum ($m$-of-$n$) | Envelopes to Authorize | Deadlock @ 95% Avail | Deadlock @ 85% Avail | Deadlock @ 70% Avail |
|---------------------|------------------------|----------------------|----------------------|----------------------|
| **2-of-3** | 3 | 1.4% (7/500) | 5.8% (29/500) | 23.4% (117/500) |
| **3-of-5** | 4 | **0.2%** (1/500) | **2.6%** (13/500) | **15.0%** (75/500) |
| **4-of-5** | 5 | 3.2% (16/500) | 13.0% (65/500) | 42.4% (212/500) |
| **5-of-5** | 6 | 21.2% (106/500) | 54.6% (273/500) | **84.0%** (420/500) |

**Operational Takeaway**: Unanimous `5-of-5` or tight `4-of-5` quorums suffer severe governance deadlock (42.4%–84.0% failure rate when individual stewards are only 70% available during a signing window). `3-of-5` dominates `2-of-3` on both security margin and liveness (2.6% vs. 5.8% deadlock at 85% availability), at the cost of one additional signed envelope per grant.

### Regime (c): Emergency Pause / Board Veto Centralization Tradeoff

| Emergency Policy | Threshold ($k$-of-$n$) | Colluding Minority to Halt | Liveness w/ 2 Councilors Offline | Max Pause Cap | Direct Spend Cap |
|------------------|------------------------|----------------------------|----------------------------------|---------------|------------------|
| ZIP-0027 DEFCON 1 Pause | 2-of-5 | **40%** (2 members) | **100%** | 72 hours | 0 ZOO |
| ZIP-0027 DEFCON 2 Crisis | 3-of-5 | 60% (3 members) | **100%** | 72 hours | 500,000 ZOO |
| Supermajority Pause | 4-of-5 | 80% (4 members) | **0%** (fails during incident!) | 72 hours | 0 ZOO |

**Tradeoff Summary**: Setting DEFCON 1 pause at `2-of-5` preserves 100% crisis-response liveness even if 2 councilors are unreachable, but accepts that a 40% minority (2 colluding councilors) can halt funding authorizations for up to 72 hours. Conversely, raising the pause threshold to `4-of-5` reduces minority-halt risk but drops incident liveness to 0% whenever 2 members are offline. Similarly, the single `BOARD_GUARDIAN` compliance veto (`FUNDING_QUEUED -> VETOED`) satisfies 501(c)(3) legal compliance (ZIP-0017 §15) but creates a single-actor censorship surface that requires off-chain/meta-governance appeal oversight (30-day 80% supermajority override per `zoo-dao-operating-system` §10).

---

## 4. What Remains Unproven / Open Research Gaps

This reference artifact proves deterministic single-node execution, cryptographic authorization, constitutional separation of AI agents, crash-safe WAL persistence, and bit-identical cross-language replay. The following critical problems **remain unproven** and are explicitly out of scope of v1:

1. **Byzantine Multi-Node Consensus & Network Partition Safety**: `researchdao-os.v1` executes a total-order event log on a single authoritative sequencer/node with offline multi-language verification. It does **not** implement BFT consensus (e.g., Tendermint/HotStuff/Lux Snowman) or prove safety/liveness under asynchronous network partitions and equivocating sequencers.
2. **Real-World Sybil & Covert COI Detection**: Automated COI checks rely on self-declared `affiliations` and `declared_coi_actors`. Pseudonymous colluding reviewers who conceal off-chain financial ties, co-authorship graphs, or shared identities are **not** cryptographically prevented by v1 (requiring external identity/ZK attestation circuits per `zoo-dao-research-governance` §4.2 and statistical post-hoc collusion detection per §6.2).
3. **Zero-Knowledge Double-Blind Reviewer Anonymity**: Peer review envelopes in v1 carry plaintext `actor_id` and Ed25519 keys for public auditability, rather than ZK-SNARK/STARK membership + COI non-membership proofs with commit-reveal anonymization (`zoo-dao-research-governance` §4).
4. **Scientific Ground-Truth Verification**: The OS cryptographically verifies that `milestone_evidence_hash != plan_hash` and that `IndependentAcceptanceRecorded` is signed by a distinct authorized `INDEPENDENT_VERIFIER` bound to `milestone_evidence_hash`, but it **cannot** mechanically prove that the off-chain scientific artifact actually reproduces an empirical conservation or ML experiment (that relies on human verifier competence and reputation incentives).
5. **Post-Quantum Signature Agility**: Envelope signatures use classical RFC 8032 Ed25519, which is vulnerable to a cryptographically relevant quantum computer (CRQC). Migration to hybrid/post-quantum signatures (ML-DSA / SLH-DSA) is left for `researchdao-os.v2`.
6. **Hardware Key Custody & Social Engineering**: Key revocation (`ActorRevoked`) limits damage after compromise detection, but v1 does not enforce hardware-backed key attestation (HSM/Ledger/Trezor) or threshold MPC signing (FROST) on the wire.
7. **On-Chain Economic Settlement & Legal Enforceability**: Treasury accounting (`balance`, `escrowed_total`, `total_disbursed`) is enforced faithfully inside the OS ledger, but bridging settlement to real on-chain ERC-20/native ZOO custody contracts and binding 501(c)(3) legal agreements requires smart-contract integration and legal counsel review.

# Open ResearchDAO Operating System — Specification (`researchdao-os.v1`)

- **Version**: `1.0.0` (`spec_version = "researchdao-os.v1"`)
- **License**: Apache-2.0
- **Issue / HIP**: `zoo-apps/papers#2` (`HIP-1352`)
- **Grounding Papers**:
  - `zoo-dao-operating-system/` (ZooGov, ZIP-0017: differentiated quorums, 72h treasury timelock, 10% per-epoch spend cap, narrow 501(c)(3) board compliance veto)
  - `zoo-dao-research-governance/` (Research DAO, ZIP-0603 / ZIP-0604: conflict-of-interest enforcement, peer review thresholds, independent reproducibility attestation)
  - `zoo-dao-grants-program/` (Zoo Grants Program, ZIP-0023: grant categories, 6.0/10 review threshold, milestone evidence gating, 10% holdback escrow)
  - `zoo-dao-emergency-protocol/` (Emergency Governance, ZIP-0027: DEFCON 1 defensive pause with 0 spend, 72h hard temporal cap, mandatory post-emergency review hash, key-compromise rotation/revocation)

---

## 1. Purpose & Constitutional Separation

Open ResearchDAO OS is a deterministic, append-only, event-sourced state machine that executes the full research funding lifecycle:

```
ProposalSubmitted -> PeerReviewRecorded -> MilestoneApproved -> FundingQueued/Cosigned/Authorized -> IndependentAcceptanceRecorded
```

Every state transition is wrapped in an **RFC 8032 Ed25519** signed envelope, hash-chained over an `fsync`-backed write-ahead log (`events.jsonl`), and committed to two deterministic cryptographic roots:

1. `state_root_hash`: domain-separated SHA-256 over the canonical JSON view of the complete OS state.
2. `audit_merkle_root`: domain-separated binary SHA-256 Merkle root over all committed event hashes `1..N`.

### Constitutional Invariants (Non-Negotiable)

| # | Invariant | Enforced Error Code(s) |
|---|-----------|------------------------|
| C1 | **No AI Treasury Authority**: `AI_AGENT` actors cannot queue, cosign, or authorize treasury spend. | `ERR_AI_TREASURY_FORBIDDEN` |
| C2 | **No AI Rule Redefinition**: `AI_AGENT` actors cannot propose or execute governance/quorum rule amendments. | `ERR_AI_RULE_CHANGE_FORBIDDEN` |
| C3 | **No AI Scientific Validation**: `AI_AGENT` actors cannot submit peer reviews, approve milestones, or declare experiments valid. | `ERR_AI_VALIDATION_FORBIDDEN` |
| C4 | **Advisory-Only AI Scope**: `AI_AGENT` actors may ONLY hold `AI_ADVISOR` and emit `AdvisoryRecorded` (`advisory_only: true`), which never alters proposal status, governance rules, or treasury balances. | `ERR_AI_GOVERNANCE_FORBIDDEN` |
| C5 | **No Self-Dealing / COI Recusal**: Proposers cannot review or approve their own proposals; reviewers/approvers/verifiers sharing institutional affiliations or listed in `declared_coi_actors` are rejected. | `ERR_SELF_REVIEW_FORBIDDEN`, `ERR_SELF_APPROVAL_FORBIDDEN`, `ERR_COI_CONFLICT` |
| C6 | **Independent Final Acceptance**: The `INDEPENDENT_VERIFIER` who records `IndependentAcceptanceRecorded` MUST be distinct from the proposer, every peer reviewer, and every milestone approver on that proposal, and MUST bind `bound_evidence_hash == milestone_evidence_hash` with a distinct `repro_check_hash`. | `ERR_VERIFIER_NOT_INDEPENDENT`, `ERR_EVIDENCE_MISMATCH` |
| C7 | **Timelocked Multi-Sig Treasury & Replay Protection**: Funding requires `treasury_quorum` active, unexpired human stewards, `timestamp >= timelock_ready_at`, per-epoch spend cap compliance, no active emergency pause, no board veto, and one-time tranche settlement. | `ERR_QUORUM_NOT_MET`, `ERR_TIMELOCK_NOT_ELAPSED`, `ERR_BUDGET_CAP_EXCEEDED`, `ERR_SYSTEM_PAUSED`, `ERR_PROPOSAL_VETOED`, `ERR_TRANCHE_ALREADY_DISBURSED` |
| C8 | **Bounded Defensive Emergency Pause (ZIP-0027)**: Emergency pause (`DEFCON 1`) requires `emergency_pause_quorum` distinct human `EMERGENCY_COUNCIL` signers, cannot spend funds, expires automatically after `duration_seconds <= 259200` (72h), and early lift requires a 64-hex `post_review_hash`. | `ERR_INVALID_PAYLOAD`, `ERR_UNAUTHORIZED_ROLE` |
| C9 | **Narrow 501(c)(3) Board Veto (ZIP-0017 Theorem 8.2)**: `BOARD_GUARDIAN` can ONLY transition `FUNDING_QUEUED -> VETOED` with a mandatory non-empty legal/mission justification; it cannot alter content, votes, or rules. | `ERR_INVALID_TRANSITION`, `ERR_INVALID_PAYLOAD` |

---

## 2. Actors, Roles & Key Lifecycle

Each actor in `genesis.json` has:
- `id` (unique string)
- `pubkey_hex` (64-char lowercase hex RFC 8032 Ed25519 public key)
- `kind`: `"HUMAN"` or `"AI_AGENT"`
- `roles`: subset of `RESEARCHER`, `PEER_REVIEWER`, `MILESTONE_COMMITTEE`, `TREASURY_STEWARD`, `INDEPENDENT_VERIFIER`, `BOARD_GUARDIAN`, `EMERGENCY_COUNCIL`, `META_GOVERNOR`, `AI_ADVISOR`
- `affiliations`: normalized institution identifiers for automated COI checks
- `active`: boolean (`false` once revoked via `ActorRevoked`)
- `effective_until`: Unix timestamp (`0` = no expiry; otherwise `timestamp > effective_until` fails with `ERR_ACTOR_EXPIRED`)
- `last_nonce`: strictly monotonic per-actor uint64 (`envelope.nonce == actor.last_nonce + 1`)

**Genesis Constitutional Check**: Any `AI_AGENT` declaring any role other than `AI_ADVISOR` fails genesis initialization with `ERR_AI_GOVERNANCE_FORBIDDEN`.

**Revocation Propagation**: If a `TREASURY_STEWARD` cosigns a queued funding request and is subsequently revoked via `ActorRevoked` before `FundingAuthorized`, their signature is excluded from the active quorum count at execution time.

---

## 3. Canonical Serialization & Cryptographic Commitments

To guarantee 100% bit-identical hashes across Go, Python, and any future implementation:

1. **No Floating-Point Consensus Values**: All scores are integers in basis points (`0..10000`, e.g., `6000` = `6.0/10.0`), all token amounts are integers, and all timestamps are Unix epoch seconds (`int64`). Mean review threshold is checked via exact integer multiplication (`sum_scores >= min_review_score_bps * count`).
2. **Canonical JSON**: UTF-8, compact (no insignificant whitespace), object keys sorted lexicographically by Unicode code point, minimal RFC 8259 string escaping (HTML characters `<`, `>`, `&` are emitted literally, NOT escaped).
3. **Domain Separation**:
   - `HashGenesis`: `SHA256("researchdao-os.v1:genesis:" || CanonicalJSON(NormalizeGenesis(g)))`
   - `SigningBytes`: `"researchdao-os.v1:envelope:" || CanonicalJSON(UnsignedEnvelope)`
   - `HashEnvelope`: `SHA256("researchdao-os.v1:event:" || CanonicalJSON(FullSignedEnvelope))`
   - `StateRootHash`: `SHA256("researchdao-os.v1:state:" || CanonicalJSON(CanonicalStateView(state)))`
   - `AuditMerkleRoot`:
     - Empty log: `SHA256("researchdao-os.v1:merkle:empty")`
     - Leaf `i`: `SHA256("researchdao-os.v1:merkle:leaf:" || raw_32b_event_hash[i])`
     - Internal node: `SHA256("researchdao-os.v1:merkle:node:" || left_32b || right_32b)` (duplicating the last node when a level has odd cardinality)
4. **Ed25519 Strict Verification**: Rejects non-canonical public keys, non-canonical `R`, and malleable scalars `S >= L` (RFC 8032 §5.1.7).

---

## 4. Lifecycle State Machine & Transition Reference

### Proposal States
`SUBMITTED` → `UNDER_REVIEW` → `PEER_REVIEWED` (or `REVIEW_REJECTED`) → `MILESTONE_APPROVED` → `FUNDING_QUEUED` (or `VETOED`) → `FUNDING_AUTHORIZED` → `ACCEPTED` (or `ACCEPTANCE_FAILED`).

### Default Governance Parameters (Grounded in Zoo DAO Papers)
| Parameter | Default | Source Paper |
|-----------|---------|--------------|
| `min_peer_reviews` | `3` | `zoo-dao-grants-program` §7 (3–5 reviewers) |
| `min_review_score_bps` | `6000` (6.0/10) | `zoo-dao-grants-program` §7 |
| `milestone_quorum` | `2` | `zoo-dao-grants-program` §4.1 |
| `treasury_quorum` | `2` (configurable m-of-n) | `zoo-dao-operating-system` §6.1 |
| `timelock_seconds` | `259200` (72h) | `zoo-dao-operating-system` Table 1 (Treasury Spend) |
| `epoch_duration_seconds` | `2592000` (30d) | `zoo-dao-operating-system` §6.2 |
| `epoch_spend_cap_bps` | `1000` (10%) | `zoo-dao-operating-system` §6.2 (`TreasuryGuard`) |
| `holdback_bps` | `1000` (10%) | `zoo-dao-grants-program` §4.2 (`HOLDBACK_BPS`) |
| `emergency_pause_quorum` | `2` | `zoo-dao-emergency-protocol` §4 (DEFCON 1) |
| `max_emergency_duration_sec` | `259200` (72h) | `zoo-dao-emergency-protocol` Theorem 7.2 |
| `meta_governance_quorum` | `3` | `zoo-dao-operating-system` §3.2 |

### Envelope Validation Order (Pinned Across Implementations)
1. `spec_version == "researchdao-os.v1"` (`ERR_INVALID_PAYLOAD`)
2. `seq == state.seq + 1` (`ERR_INVALID_SEQUENCE`)
3. `prev_event_hash == state.last_event_hash` (`ERR_CHAIN_BROKEN`)
4. `timestamp >= state.last_timestamp` (`ERR_TIMESTAMP_REGRESSION`)
5. Actor exists (`ERR_UNKNOWN_ACTOR`), `active == true` (`ERR_ACTOR_REVOKED`), unexpired (`ERR_ACTOR_EXPIRED`)
6. `nonce == actor.last_nonce + 1` (`ERR_NONCE_REPLAY`)
7. RFC 8032 Ed25519 signature verifies over `SigningBytes(env)` (`ERR_INVALID_SIGNATURE`)
8. Constitutional AI separation check (`ERR_AI_*_FORBIDDEN`)
9. Event-specific role, COI, state, evidence, timelock, quorum, pause, and budget checks
10. Atomic WAL append + `fsync`, followed by in-memory state commit (rejected transitions leave `state_root_hash` and `audit_merkle_root` completely unchanged).

---

## 5. Persistence, Checkpoints & Cold-Restart Replay

A durable WAL directory contains:
- `genesis.json`: canonical JSON of the immutable genesis configuration.
- `events.jsonl`: append-only newline-delimited canonical JSON envelopes (`fsync`ed per committed transition).
- `checkpoints/checkpoint_<seq>.json`: atomic snapshot containing `genesis_hash`, `seq`, `last_event_hash`, `state_root_hash`, `audit_merkle_root`, `event_hashes`, and `state`.

Two verified restart paths MUST agree bit-for-bit:
1. **`ReplayFull(dir)`**: reads `genesis.json` and replays every line of `events.jsonl` from `seq=1..N`, re-verifying every Ed25519 signature and constitutional rule.
2. **`ReplayFromLatestCheckpoint(dir)`**: validates the highest-sequence checkpoint's `genesis_hash`, `state_root_hash`, `audit_merkle_root`, and `last_event_hash`, then replays only delta envelopes `seq > checkpoint.seq` with full signature and constitutional verification.

Any byte modification to `events.jsonl` or `checkpoints/*.json` fails deterministically with `ERR_INVALID_SIGNATURE`, `ERR_CHAIN_BROKEN`, or `ERR_WAL_TAMPERED`.

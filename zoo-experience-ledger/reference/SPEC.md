<!-- SPDX-License-Identifier: Apache-2.0 -->

# Zoo Decentralized Experience Ledger — Specification v1 (`zoo-experience-ledger/v1`)

**Status**: Reference Specification (HIP-1352 / `zoo-apps/papers#10`)
**Version**: `1.0.0` (`zoo-experience-ledger/v1`)
**License**: Apache-2.0
**Reference Papers**:
- *Zoo Experience Ledger: Decentralized Content-Addressed Semantic Experience Memory* (`zoo-experience-ledger/`)
- *Decentralized Semantic Optimization via Curated Experience Ledgers* (`experience-ledger-dso/`)

---

## 1. Purpose & Design Invariants

The Decentralized Experience Ledger provides content-addressed research memory with concurrent multi-writer contributions, cryptographic provenance, authorized revocation with causal taint propagation, explicit non-destructive conflict handling, and bit-exact order-independent state reconstruction.

### Core Invariants

1. **No Second Storage Stack (VFS / S3 Native)**:
   All durable research artifacts (experience payloads, reasoning trajectories, embeddings, conflict evidence bundles, paper excerpts, and checkpoint snapshots) are stored strictly in Hanzo's existing VFS / S3 object layer addressed by lowercase hex SHA-256 (`vfs://sha256/<hex>` or `s3://<bucket>/sha256/<hex[0:2]>/<hex>`). External publication locators (`ipfs://...`, `ar://...`) are optional portability hints; integrity always anchors on `artifact_sha256`.
2. **Order-Independent Commutative Replay**:
   For any policy $P$, any finite event multiset $E$, and any arrival permutation $\pi$:
   $$\text{Replay}(P, \pi(E)).\text{state\_root\_hash} \equiv \text{Replay}(P, E).\text{state\_root\_hash}$$
   Wall-clock timestamps (`created_at_unix`) are informational provenance metadata and are **never** used for last-write-wins (LWW) conflict resolution.
3. **Cryptographic Provenance & Authorized Revocation**:
   Every event is canonically serialized, SHA-256 content-addressed (`event_id`), and RFC 8032 Ed25519 signed by an active registered principal. Revocation is permitted **only** by the original entry's author (self-revocation) or an authorized `steward` (governance revocation). Revoking an entry deterministically taints all causal descendants in the parent-hash DAG.
4. **Explicit Conflict Preservation & Constitutional Separation**:
   Concurrent competing claims on the same `(domain, claim_key)` with distinct `claim_value_hash` values are preserved in an explicit `ConflictSet` — never silently dropped.
   - **AI Agents (`ai_agent`)**: May contribute experiences, self-revoke their own entries, flag conflicts, estimate confidence, and attach VFS/S3 evidence bundles. AI agents **must not** issue `ResolutionDecision` events, revoke other principals' entries, declare their own experiments valid, authorize treasury spending, or redefine voting/policy rules.
   - **Stewards (`steward`)**: Authorized human/governance verifiers may issue `ResolutionDecision` events, subject to **distinct-verifier separation**: a steward cannot select an entry they authored themselves (`steward_id != winning_entry.contributor_id`). If two stewards submit conflicting resolutions for the same conflict scope, the conflict transitions to `escalated_steward_disagreement` rather than silently picking one.

---

## 2. Canonical JSON Serialization & Event Identity

To guarantee bit-exact cross-language hashes (Go, Python, Rust, TypeScript) without IEEE-754 floating-point drift:

1. **Data types in signed payloads**: Objects, arrays, UTF-8 strings, booleans, `null`, and 64-bit signed integers only. No floating-point numbers appear in hashed fields; confidence scores $c \in [0, 1]$ from the Zoo Experience Ledger paper are encoded as `confidence_bps` $\in [0, 10000]$ ($c = \text{confidence\_bps} / 10000$).
2. **Object keys**: Sorted lexicographically by UTF-8 byte order (ASCII code point order).
3. **Whitespace**: No insignificant whitespace (compact separators `,` and `:`).
4. **String escaping**: Standard RFC 8259 JSON escaping (`\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, and `\u00xx` lowercase hex for control characters `< 0x20`). Non-ASCII UTF-8 characters are emitted unescaped as raw UTF-8 bytes (`ensure_ascii=False`, no HTML `<`, `>`, `&` escaping).
5. **Event ID**:
   $$\text{event\_id}(e) = \text{hex}(\text{SHA256}(\text{CanonicalJSON}(e \setminus \{\text{event\_id}, \text{signature\_hex}\})))$$
6. **Ed25519 Signing Message** (domain-separated):
   $$m(e) = \text{UTF8}(\texttt{"zoo-experience-ledger/v1:event:"} \mathbin{\|} \text{event\_id}(e))$$
   `signature_hex` is the 128-char lowercase hex encoding of the 64-byte RFC 8032 Ed25519 signature over $m(e)$.

---

## 3. Storage Layer Integration (VFS / S3)

| URI Scheme | Object Layout | Verification Rule |
|---|---|---|
| `vfs://sha256/<64-hex>` | `<vfs_root>/sha256/<hex[0:2]>/<64-hex>` | `SHA256(bytes) == <64-hex>` on Put and Get |
| `s3://<bucket>/sha256/<hex[0:2]>/<64-hex>` | S3 key `sha256/<hex[0:2]>/<64-hex>` | `SHA256(bytes) == <64-hex>` (or S3 `ChecksumSHA256`) |
| `ipfs://...`, `ar://...`, `https://...` | Advisory `external_uris` only | Verified against `artifact_sha256` after fetch |

Deduplication is automatic: writing identical bytes yields the same SHA-256 key and consumes zero additional object storage.

---

## 4. Policy & Principal Roles

A `Policy` document defines the trust anchor for replay:
- `schema_version`: `"zoo-experience-ledger/v1"`
- `policy_id`: unique identifier (e.g. `"zoo-research-policy-v1"`)
- `principals`: array of `{principal_id, role, public_key_hex, active}`
- `policy_sha256`: `hex(SHA256(CanonicalJSON(policy_without_policy_sha256)))`

### Role Capability Matrix

| Action | `human_researcher` | `ai_agent` | `steward` |
|---|---|---|---|
| Publish `experience_entry` | Allowed | Allowed | Allowed |
| Self-revoke own `experience_entry` | Allowed | Allowed | Allowed |
| Revoke another principal's `experience_entry` | **Rejected** | **Rejected** | Allowed |
| Publish `conflict_flag` + evidence bundle | Allowed | Allowed | Allowed |
| Publish `resolution_decision` | **Rejected** | **Rejected** | Allowed (only if `steward_id != winning_entry.contributor_id`) |
| Mutate `Policy` / voting rules / treasury | **Forbidden** | **Forbidden** | Out-of-band DAO governance only |

---

## 5. Event Schema (`zoo-experience-ledger/v1`)

All four event types share `schema_version` (`"zoo-experience-ledger/v1"`), `event_type`, `created_at_unix` (int64), `event_id` (64-hex), and `signature_hex` (128-hex).

### 5.1 `experience_entry`
- `contributor_id`: registered principal ID
- `domain`: dot-delimited taxonomy path (`^[a-z0-9]+(\.[a-z0-9_-]+)*$`, e.g. `"math.geometry.intersection"`)
- `claim_key`: canonical semantic slot within domain (`^[a-z0-9][a-z0-9._-]{0,127}$`)
- `claim_value_hash`: 64-hex SHA-256 of normalized semantic claim
- `summary`: concise actionable experience statement (`<= 1024` UTF-8 bytes)
- `confidence_bps`: integer `0..10000`
- `artifact_sha256`: 64-hex SHA-256 of durable artifact in VFS/S3
- `artifact_uri`: VFS or S3 URI matching `artifact_sha256`
- `artifact_size_bytes`: integer `>= 0`
- `external_uris`: sorted array of optional external URIs (`ipfs://`, `ar://`, `https://`)
- `parent_hashes`: sorted unique array of parent `experience_entry` `event_id`s (causal DAG)
- `receipt_hash`: optional 64-hex Thinking Chains canonical execution receipt hash (`""` if absent)
- `nonce`: string (uniqueness salt if needed)

### 5.2 `revocation_record`
- `issuer_id`: registered principal ID (author or `steward`)
- `target_event_id`: 64-hex `event_id` of target `experience_entry`
- `reason_code`: `"retracted_by_author" | "corrupted_artifact" | "falsified_claim" | "policy_violation" | "superseded"`
- `reason`: human-readable explanation
- `evidence_sha256`: optional 64-hex SHA-256 (`""` if absent)
- `evidence_uri`: optional VFS/S3 URI (`""` if absent)

### 5.3 `conflict_flag`
- `flagger_id`: registered principal ID (`human_researcher`, `ai_agent`, or `steward`)
- `domain`: string
- `claim_key`: string
- `conflicting_event_ids`: sorted unique array of `>= 2` `experience_entry` `event_id`s
- `evidence_sha256`: 64-hex SHA-256 of conflict evidence bundle in VFS/S3
- `evidence_uri`: VFS/S3 URI matching `evidence_sha256`
- `rationale`: human-readable explanation

### 5.4 `resolution_decision`
- `steward_id`: registered principal ID with role `"steward"`
- `domain`: string
- `claim_key`: string
- `reviewed_event_ids`: sorted unique array of `>= 2` `experience_entry` `event_id`s considered
- `outcome`: `"select_canonical" | "reject_all" | "keep_both_scoped"`
- `winning_event_id`: 64-hex `event_id` (required iff `outcome == "select_canonical"`, `""` otherwise)
- `rationale_sha256`: 64-hex SHA-256 of steward rationale artifact in VFS/S3
- `rationale_uri`: VFS/S3 URI matching `rationale_sha256`
- `governance_ref`: optional DAO proposal reference (e.g. `"hip-1352:prop-01"`)

---

## 6. Deterministic Stratified Replay Algorithm

Replay executes in 6 deterministic, permutation-invariant phases:

1. **Phase 0 — Intrinsic Verification & Deduplication**:
   Validate schema, canonical `event_id`, Ed25519 signature, active principal, and static role permissions (rejecting `ai_agent` / `human_researcher` `resolution_decision` with `ERR_AI_AGENT_RESOLUTION_FORBIDDEN` / `ERR_UNAUTHORIZED_RESOLUTION`). Collapse duplicate `event_id`s idempotently.
2. **Phase 1 — Entry Set & Causal DAG Validation**:
   Build `Entries` map. Reject any entry containing a self-reference or belonging to a `parent_hashes` cycle (`ERR_CYCLE_DETECTED`). Record missing parent references deterministically in `unresolved_parents`.
3. **Phase 2 — Revocation Authorization & OR-Set Tombstones**:
   For each valid `revocation_record`, verify `target_event_id` exists in `Entries` (otherwise park in `pending_revocations`) and verify `issuer_id == target.contributor_id` or `role(issuer_id) == "steward"` (otherwise reject with `ERR_UNAUTHORIZED_REVOCATION`). Attach sorted `revoked_by` IDs to revoked entries.
4. **Phase 3 — Fixed-Point Causal Taint Propagation**:
   Compute backwards reachability to directly revoked ancestors across `parent_hashes`. Any non-revoked entry with $\ge 1$ revoked ancestor receives `status = "tainted"` and sorted `tainted_by_ancestors`.
5. **Phase 4 — ConflictSet Construction**:
   Group all non-revoked, non-tainted entries by `slot = domain + "/" + claim_key`. A slot forms a `ConflictSet` if either (a) it has $\ge 2$ distinct `claim_value_hash` values among active/candidate entries, or (b) $\ge 1$ valid `conflict_flag` references $\ge 2$ non-revoked, non-tainted entries in that slot.
6. **Phase 5 — Steward Resolution Evaluation**:
   For each `ConflictSet` with candidate set $S$:
   - Filter valid `resolution_decision`s for `(domain, claim_key)`:
     - If `outcome == "select_canonical"`, verify `winning_event_id` is in `reviewed_event_ids`, exists, is not revoked/tainted, and `Entries[winning_event_id].contributor_id != steward_id` (else reject with `ERR_SELF_VALIDATION_FORBIDDEN`).
     - A resolution is **applicable** to $S$ iff $S \subseteq \text{reviewed\_event\_ids}$ (ensuring late-arriving concurrent claims automatically re-open conflicts rather than being silently overwritten).
   - If zero resolutions are applicable: `status = "open"`, all entries in $S$ get status `"conflicted"`.
   - If $\ge 1$ applicable resolutions all agree on `(outcome, winning_event_id)`: `status = "resolved"`. For `"select_canonical"`, `winning_event_id` is `"active"` and other entries in $S$ become `"superseded"`. For `"reject_all"`, all entries in $S$ become `"superseded"`. For `"keep_both_scoped"`, all entries in $S$ remain `"active"`.
   - If applicable resolutions disagree on `(outcome, winning_event_id)`: `status = "escalated_steward_disagreement"`, all entries in $S$ get status `"conflicted"`, and all competing resolution IDs are preserved sorted.
7. **Phase 6 — Active Merkle Tree & State Root Commitment**:
   - Let $A = \text{sorted}(\{e.\text{event\_id} \mid \text{status}(e) == \texttt{"active"}\})$.
   - Compute domain-separated binary Merkle root `active_merkle_root`:
     - Empty $A$: `SHA256(b"zoo-experience-ledger/v1:empty-merkle")`
     - Leaf: `SHA256(0x00 || hex_decode(event_id))`
     - Internal: `SHA256(0x01 || left || right)` (if odd count at level, duplicate last node, matching `experience-ledger-dso` Algorithm 1)
   - Compute `state_root_hash = hex(SHA256(CanonicalJSON(StateCommitment)))` over `{schema_version, policy_sha256, active_merkle_root, entry_states, conflicts, pending_revocations, rejected_events}`.

---

## 7. Error & Rejection Codes

| Code | Meaning |
|---|---|
| `ERR_INVALID_SCHEMA` | Wrong `schema_version`, unknown `event_type`, missing/malformed field or URI/SHA-256 mismatch |
| `ERR_EVENT_ID_MISMATCH` | `event_id` does not equal SHA-256 of canonical unsigned body |
| `ERR_UNKNOWN_PRINCIPAL` | Signer not found in `Policy` or `active == false` |
| `ERR_INVALID_SIGNATURE` | Ed25519 signature verification failed |
| `ERR_AI_AGENT_RESOLUTION_FORBIDDEN` | `ai_agent` attempted to issue a `resolution_decision` |
| `ERR_UNAUTHORIZED_RESOLUTION` | Non-steward (`human_researcher`) attempted to issue a `resolution_decision` |
| `ERR_UNAUTHORIZED_REVOCATION` | Non-author, non-steward principal attempted to revoke an entry |
| `ERR_SELF_VALIDATION_FORBIDDEN` | Steward attempted `select_canonical` picking an entry authored by themselves |
| `ERR_INVALID_RESOLUTION_TARGET` | `winning_event_id` missing, revoked, tainted, or not in `reviewed_event_ids` |
| `ERR_CYCLE_DETECTED` | Entry participates in a `parent_hashes` cycle (including self-parent) |

---

## 8. Checkpoint Snapshots

A `CheckpointSnapshot` stores the verified canonical event set digest plus accepted event IDs and reconstructed `StateCommitment` in VFS/S3 (`vfs://sha256/<hex>`). Incremental replay verifies the checkpoint's content hash and merges delta events through the same set-based semantics, guaranteeing identical `state_root_hash` while bounding hot-path replay latency.

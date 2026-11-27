# Forkable Models and Autonomous Organizations Specification (`forkable-org.v1`)

- **Version**: `1.0.0`
- **Schema ID**: `forkable-org.v1` (`schema/forkable-org.v1.schema.json`)
- **Issue / HIP**: `zoo-apps/papers#5` (HIP-1352)
- **License**: Apache-2.0 (source code & specification); external datasets, reasoning traces, model weights, and SDKs require separate SPDX license review (`license_reviewed: true`)
- **Companion Papers**:
  - *BitDelta and DeltaSoup: Personalized and Community AI through Compact Model Updates* (`../zoo-bitdelta-deltasoup.tex`, ZIP-0006 / ZIP-0009 / LP-106)
  - *The Zoo DAO: How a Model Zoo Builds a Community, Rewards Its Builders, and Forks Itself* (`../../zoo-dao/zoo-dao.tex`)

---

## 1. Purpose and Threat Model

An autonomous research organization (*model zoo*) maintains four coupled state domains:

1. **`ModelRegistry`**: immutable base model weights, 1-bit **BitDelta** adapters $(S, \gamma)$, and Byzantine-robust **DeltaSoup** community Reference Adapters with lineage DAGs and contributor royalty maps.
2. **`ResearchHistory`**: hash-chained research receipts, dataset ingestion records, and evaluation proofs committed to an RFC 6962 binary Merkle root.
3. **`PolicyManifest`**: constitutional governance rules, authorized human council decision-makers, independent evaluators, trainers, SPDX license allowlists, safety floors, and explicit **AI agent constitutional boundaries**.
4. **`AccessControlPolicy`**: capability-scoped access control tiers (`public`, `org_internal`, `restricted_pii_or_partner`), org-scoped tokens, fork-stripping rules, and explicit cross-org delegation grants.

**Core Security Objective**: Any party can deterministically **fork** an organization at an immutable snapshot `OrgA@snap_k` into `OrgB@snap_1_fork` while:
- retaining cryptographically checkable provenance back to `OrgA@snap_k`,
- leaking **zero** restricted (`restricted_pii_or_partner`) or non-inheritable (`org_internal`) records, ACL grants, or private keys across the fork boundary,
- enabling both branches to diverge independently (models, research histories, and governance policies), and
- enabling either branch to later export an independently verified improvement (`ExchangeBundle`) that the other branch can cryptographically audit, re-evaluate deterministically, and adopt via DeltaSoup merge.

**Adversary Capabilities Modeled**:
- Forging fork ancestor hashes, lineage chains, snapshot Merkle roots, or BitDelta sign bits.
- Smuggling `restricted_pii_or_partner` or non-inheritable `org_internal` records/tokens across a fork boundary or into a cross-fork training closure.
- Reusing parent-org private/public keys without key rotation, or replaying a signed bundle across organization domains.
- An `AI_AGENT` attempting to redefine voting rules, authorize treasury spending, mark advisory proposals as binding, or self-certify its own experiment evaluation receipts.
- Submitting inflated benchmark receipts, quality-regressing deltas, safety-floor-violating updates, unreviewed/non-compliant licenses, or up to 30% Byzantine poisoned contributors in DeltaSoup aggregation.

---

## 2. Cryptographic & Arithmetic Primitives

### 2.1 Deterministic Fixed-Point Arithmetic
To guarantee **100% bit-exact parity** across independent Go and Python verifiers without IEEE-754 rounding or float-formatting drift:
- All signed numeric fields in canonical payloads are 64-bit signed integers (`int64`).
- Continuous weights, features, scales $\gamma$, and margin losses are scaled by `MICRO = 1_000_000` ($10^6$).
- Accuracies, safety rates, trim fractions, merge steps, and royalty weights are represented in basis points `BPS = 10_000` ($10^4$).
- Integer division MUST truncate toward zero (`div_trunc(a, b)` in Python matching Go's `a / b`).

### 2.2 Canonical JSON & Domain-Separated SHA-256
Every hashed or signed object $X$ is encoded to RFC 8259 canonical JSON:
- UTF-8, object keys sorted lexicographically by Unicode code point / UTF-8 byte order,
- compact separators `,` and `:` (no whitespace),
- no HTML entity escaping of `<`, `>`, or `&`.

Domain-separated digests and signature preimages use:
$$\text{Msg}(D, X) = \text{UTF8}(D) \mathbin{\|} \texttt{0x00} \mathbin{\|} \text{CanonicalJSON}(X)$$
$$\text{Hash}(D, X) = \text{hex}\!\left(\text{SHA256}(\text{Msg}(D, X))\right)$$

Normative domain tags:
- `forkable-org.v1:base-model`
- `forkable-org.v1:bitdelta`
- `forkable-org.v1:deltasoup`
- `forkable-org.v1:research-record`
- `forkable-org.v1:policy-manifest`
- `forkable-org.v1:acl-policy`
- `forkable-org.v1:governance-action`
- `forkable-org.v1:advisory-proposal`
- `forkable-org.v1:eval-receipt`
- `forkable-org.v1:eval-dataset`
- `forkable-org.v1:org-snapshot`
- `forkable-org.v1:fork-attestation`
- `forkable-org.v1:exchange-bundle`
- `forkable-org.v1:audit-leaf`

### 2.3 RFC 6962 Binary Merkle Tree
For an ordered list of $N$ UTF-8 leaf strings $L = [l_0, \dots, l_{N-1}]$:
- Empty list ($N = 0$): $\text{SHA256}(\epsilon)$.
- Single leaf ($N = 1$): $\text{SHA256}(\texttt{0x00} \mathbin{\|} l_0)$.
- $N > 1$: let $k$ be the largest power of $2$ strictly less than $N$; then
  $$\text{MTH}(L) = \text{SHA256}\!\left(\texttt{0x01} \mathbin{\|} \text{MTH}(L_{0..k-1}) \mathbin{\|} \text{MTH}(L_{k..N-1})\right)$$

### 2.4 RFC 8032 Ed25519 Signatures
All signatures are RFC 8032 Ed25519 over $\text{Msg}(D, X)$, encoded as 128 lowercase hex characters, verified against 64-char hex public keys with strict canonical $S < L$ and canonical point decompression checks.

---

## 3. BitDelta Compression & DeltaSoup Aggregation

### 3.1 BitDelta 1-Bit Compression
Following *BitDelta and DeltaSoup* (Definition 2.1, Proposition 2.1):
Given base weights $W_b \in \mathbb{Z}^D$ and fine-tuned weights $W_f \in \mathbb{Z}^D$ in micro-units:
1. Full delta $\delta_j = W_{f,j} - W_{b,j}$.
2. 1-bit sign $b_j = 1$ if $\delta_j \ge 0$ ($S_j = +1$), else $b_j = 0$ ($S_j = -1$), packed LSB-first into $\lceil D/8 \rceil$ bytes (`sign_bits_hex`).
3. Closed-form optimal scale:
   $$\gamma^* = \operatorname{div\_trunc}\!\left(\sum_{j=0}^{D-1} |\delta_j|,\; D\right)$$
4. Reconstructed weights: $\hat{W}_{f,j} = W_{b,j} + \gamma^* S_j$.

### 3.2 DeltaSoup Coordinate-Wise Trimmed Mean & Royalties
Following *BitDelta and DeltaSoup* (Definition 4.1, Theorem 4.1, Eq. 5):
Given $N$ contributor BitDelta adapters $\{(S_i, \gamma_i)\}_{i=1}^N$ and trim ratio `trim_bps` ($\beta = \text{trim\_bps}/10000$, $k = \lfloor N \cdot \text{trim\_bps} / 10000 \rfloor$, requiring $2k < N$):
1. For each coordinate $j \in \{0, \dots, D-1\}$, sort $\{ \gamma_i S_{i,j} \}_{i=1}^N$ ascending.
2. Drop the smallest $k$ and largest $k$ values; average the remaining $N - 2k$ values via `div_trunc`.
3. Re-compress the aggregate vector into a compact BitDelta Reference Adapter $(S_{\text{soup}}, \gamma_{\text{soup}})$.
4. Contributor royalty shares are allocated proportionally to $L_1$ delta norm $D \cdot \gamma_i$ across accepted contributors using deterministic largest-remainder rounding summing to **exactly `10000` bps**.

### 3.3 Cross-Fork Merge & Independent Evaluation
When `TargetOrg` evaluates an incoming verified `ExportedDelta` ($\delta_{\text{remote}}$) against its local head $\delta_{\text{local}}$ on shared base $W_b$ with step $\eta = \text{merge\_step\_bps}/10000$:
$$W_{\text{raw}} = W_b + \delta_{\text{local}} + \operatorname{div\_trunc}(\delta_{\text{remote}} \cdot \text{merge\_step\_bps},\; 10000)$$
The adopting organization re-compresses $W_{\text{raw}} - W_b$ to the committed BitDelta adapter $\delta_{\text{merged}}$ and independently evaluates $\hat{W}_{\text{merged}} = W_b + \delta_{\text{merged}}$ on the canonical held-out dataset (`eval_dataset_hash`):
- **Receipt Replay Check**: `EvaluateModel(W_b + delta_remote, ds)` MUST match `EvaluationReceipt` (`accuracy_bps`, `mean_loss_micro`, `safety_bps`, `num_samples`) bit-for-bit.
- **Safety Floor Gate**: `merged.safety_bps >= target.policy_manifest.min_safety_bps`.
- **Improvement Gate**: `merged.accuracy_bps - target_head.accuracy_bps >= target.policy_manifest.min_accuracy_gain_bps` AND `merged.mean_loss_micro < target_head.mean_loss_micro`.

---

## 4. Constitutional Roles & AI Agent Boundaries

Every principal in `PolicyManifest.authorized_principals` is bound to `(id, org_id, role, public_key_hex)`:

| Role | Permitted Actions | Explicitly Forbidden |
|---|---|---|
| `HUMAN_COUNCIL` | Sign snapshots, approve forks, approve adoptions, mutate voting rules, authorize treasury spends (subject to quorum `min_council_approvals`) | Self-certifying evaluations unless also authorized |
| `EVALUATOR` | Independently run deterministic benchmarks and sign `EvaluationReceipt` | Mutating voting rules or treasury; certifying own trained delta |
| `TRAINER` | Publish `ResearchRecord` entries and sign `BitDeltaArtifact` updates | Mutating voting rules, authorizing treasury, self-certifying evals |
| `AI_AGENT` | Submit signed, **non-binding** (`binding: false`) `AdvisoryProposal` artifacts (`recommend_adoption`, `flag_conflict`, `estimate_value`, `prepare_merge_plan`) | Redefining voting rules (`ERR_AI_VOTING_RULE_FORBIDDEN`), authorizing treasury spend (`ERR_AI_TREASURY_FORBIDDEN`), declaring own/any experiment valid (`ERR_AI_SELF_CERTIFY_FORBIDDEN`), issuing binding proposals (`ERR_AI_BINDING_PROPOSAL_FORBIDDEN`) |

---

## 5. Deterministic Organization Forking & Cryptographic Redaction Proofs

`ForkOrganization(OrgA@snap_k, child_org_id, child_keys)` produces `OrgB@snap_1_fork` subject to five mandatory invariants enforced by `VerifyForkBoundary`:

1. **Immutable Lineage Anchor**: `child.parent_snapshot_hash == child.fork_ancestor_snapshot_hash == parent.snapshot_hash`, signed by `child`'s `HUMAN_COUNCIL` quorum in `ForkAttestation`.
2. **Mandatory Key Rotation**: `child.fork_attestation.keys_rotated == true`, and the intersection of Ed25519 public keys between `parent.policy_manifest.authorized_principals` and `child.policy_manifest.authorized_principals` MUST be empty (`ERR_KEY_ROTATION_REQUIRED`).
3. **Zero ACL Leak (Records & Deltas)**: Every `restricted_pii_or_partner` record and every non-inheritable `org_internal` record is stripped; any BitDelta referencing a stripped record is excluded. Any retained restricted or non-public inherited record fails with `ERR_ACL_LEAK_RESTRICTED`.
4. **Zero ACL Leak (Grants & Tokens)**: Non-inheritable or non-public ACL grants are stripped; inherited public grants rotate `org_scoped_token_hash`. Any leaked grant or reused parent token hash fails with `ERR_ACL_LEAK_GRANT`.
5. **Cryptographic `RedactionTombstone` Proof**: For every parent slot $i \in \{0, \dots, N_{\text{parent}}-1\}$ that was stripped, `child.research_history.redaction_tombstones` contains `(slot_index: i, original_leaf_hash: parent.records[i].record_hash, redacted_tier, redaction_reason, commitment_salt_hash)` with zero plaintext payload. Verifiers reconstruct the length-$N_{\text{parent}}$ leaf vector from kept inherited records (`parent_slot_index >= 0`) and tombstones, requiring every slot to be filled exactly once and `MerkleRootRFC6962(reconstructed) == parent.research_history.research_merkle_root` (`ERR_REDACTION_PROOF_INVALID`).

---

## 6. Normative Error Code Registry

Both Go (`forkorg`) and Python (`forkorg_py`) MUST emit identical error codes:

| Code | Trigger Condition |
|---|---|
| `OK` | All verification gates passed |
| `ERR_LINEAGE_BROKEN` | Missing/invalid fork ancestor, broken `lineage_chain`, or mismatched base model |
| `ERR_DELTA_HASH_MISMATCH` | BitDelta / BaseModel / DeltaSoup content hash mismatch |
| `ERR_HISTORY_CHAIN_BROKEN` | Tampered research record hash or broken `prev_hash` chain |
| `ERR_MERKLE_ROOT_MISMATCH` | `model_registry_root` or `research_merkle_root` mismatch |
| `ERR_ACL_LEAK_RESTRICTED` | `restricted_pii_or_partner` or non-public inherited record leaked into child fork |
| `ERR_ACL_LEAK_GRANT` | Restricted/non-inheritable grant or parent org-scoped token hash leaked into child fork |
| `ERR_ACL_TAINT_RESTRICTED` | Exported delta or supporting research references restricted or undelegated internal data |
| `ERR_KEY_ROTATION_REQUIRED` | Child fork fails to rotate Ed25519 keys away from parent principals |
| `ERR_CROSS_ORG_REPLAY` | Org ID mismatch, same-org exchange, or bundle/action payload hash mismatch |
| `ERR_UNAUTHORIZED_SIGNER` | Unknown principal, wrong role, or wrong-fork authority signature |
| `ERR_INVALID_SIGNATURE` | Ed25519 signature verification failed |
| `ERR_AI_VOTING_RULE_FORBIDDEN` | `AI_AGENT` attempted to propose or sign `update_voting_rules` |
| `ERR_AI_TREASURY_FORBIDDEN` | `AI_AGENT` attempted to propose or sign `authorize_treasury_spend` |
| `ERR_AI_SELF_CERTIFY_FORBIDDEN` | `AI_AGENT` or delta contributor attempted to sign `EvaluationReceipt` |
| `ERR_AI_BINDING_PROPOSAL_FORBIDDEN` | `AI_AGENT` set `binding: true` on `AdvisoryProposal` |
| `ERR_EVAL_REPLAY_MISMATCH` | Claimed receipt metrics/hashes do not match deterministic independent re-evaluation |
| `ERR_QUALITY_REGRESSION` | Merged candidate fails `min_accuracy_gain_bps` or fails to reduce loss |
| `ERR_SAFETY_FLOOR_VIOLATION` | Merged candidate falls below `min_safety_bps` on safety probes |
| `ERR_LICENSE_INCOMPATIBLE` | Unreviewed (`license_reviewed: false`) or non-allowlisted SPDX license |
| `ERR_REDACTION_PROOF_INVALID` | Incomplete, duplicate, or forged `RedactionTombstone` Merkle proof |
| `ERR_INSUFFICIENT_QUORUM` | Unique valid `HUMAN_COUNCIL` signatures below `min_council_approvals` |
| `ERR_SNAPSHOT_HASH_MISMATCH` | `snapshot_hash` mismatch |
| `ERR_POLICY_HASH_MISMATCH` | `policy_hash` or `acl_policy_hash` mismatch |
| `ERR_BUNDLE_HASH_MISMATCH` | `bundle_hash` mismatch |

---

## 7. What Remains Unproven

This reference implementation establishes deterministic cryptographic provenance, ACL-boundary redaction proofs, constitutional AI-agent guards, and exact fixed-point BitDelta/DeltaSoup mechanics on a reproducible 64-parameter linear classifier. The following questions are **explicitly NOT proven** by this artifact and require separate empirical, cryptographic, or legal validation before production deployment:

1. **Large-Scale 7B–70B Transformer GPU BitDelta Quantization Sensitivity**:
   - Our deterministic fixed-point linear classifier ($4 \times 16 = 64$ weights) proves protocol mechanics and shows BitDelta sign-plus-scale retention, but does **not** prove quantization robustness across deep non-linear transformer attention/MLP blocks, KV-cache drift, KL-calibration line search, or multi-hop cross-fork merges of 7B–70B LLMs where cross-layer sign interference can degrade reasoning or instruction following.
2. **Membership-Inference, Model-Inversion, and Gradient-Leakage Privacy Bounds**:
   - `forkable-org.v1` enforces **explicit metadata & provenance-graph ACL taint tracking** (preventing `restricted_pii_or_partner` datasets from entering a fork or cross-fork export). It does **not** mathematically prevent a covert or compromised trainer from training on unlisted private records outside the attested pipeline and smuggling memorized information inside a 1-bit sign matrix. Closing statistical leakage requires end-to-end DP-SGD training proofs, TEE/confidential-compute training attestation, or formal $(\epsilon, \delta)$-DP accounting (Section 7 of `zoo-bitdelta-deltasoup.tex`).
3. **Real-World Legal, Copyright, and License-Compatibility Enforcement**:
   - The `LicenseManifest` allowlist and `license_reviewed` boolean enforce machine-checkable hygiene gates (e.g., blocking `CC-BY-NC-4.0` or unreviewed external datasets/weights), but software metadata checks cannot adjudicate legal ownership, jurisdiction-specific database rights, copyleft viral propagation into model weights or reasoning traces, or third-party SDK contract terms. Independent human legal review remains mandatory.
4. **Byzantine Multi-Organization Economic Equilibria & Sybil Collusion**:
   - Our DeltaSoup sweep confirms coordinate-wise trimmed mean ($\beta = 0.30$) resists up to 30% coordinated poisoning and **honestly breaks down** at $\ge 40\%$. In open permissionless multi-org ecosystems, an adversary with sufficient capital can split across Sybil contributor identities to exceed $\beta$, bribe independent evaluators, or strategically withhold improvements across competing forks. Preventing Sybil capture requires external economic mechanisms (e.g., non-refundable sortition registration costs and bonded dispute games as analyzed in `zoo-dao.tex` Section 4).
5. **Post-Quantum Signature Agility & Key Revocation**:
   - Reference signatures use classical RFC 8032 Ed25519; long-lived multi-decade organizational lineages require migration to hybrid/post-quantum signatures (e.g., ML-DSA / Dilithium per `zoo-pq-crypto`) and on-chain revocation registries for compromised council or evaluator keys.

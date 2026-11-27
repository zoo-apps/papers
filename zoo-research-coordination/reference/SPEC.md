# Federated Agent Organizations over A2A (`federated-a2a.v1`)

- **Schema Version**: `federated-a2a.v1`
- **Specification Version**: `1.0.0`
- **Status**: Reference Specification & Clean-Room Apache-2.0 Implementation (`zoo-apps/papers#4`, HIP-1352)
- **Grounding Paper**: [`../zoo-research-coordination.tex`](../zoo-research-coordination.tex) (*Decentralized Research Coordination: Federated Experiment Management for DeSci*, ZIP-008)
- **Protocol Reference**: Apache-2.0 Agent-to-Agent (A2A) Protocol (`/.well-known/agent.json` `AgentCard`, JSON-RPC 2.0 `tasks/send`, `tasks/sendSubscribe` SSE, `tasks/get`, `tasks/cancel`)

---

## 1. Purpose and Scope

`federated-a2a.v1` specifies a verifiable protocol enabling two independently administered organizations (`OrgAlpha` and `OrgBeta`) to discover one another's research capabilities, exchange deterministic scientific tasks and results over HTTP/JSON-RPC 2.0 + Server-Sent Events (SSE), and independently re-verify scientific outputs **without ever sharing internal credentials, private memory vaults, or raw unreviewed reasoning traces**.

This specification directly implements the cross-organizational coordination layer for ZooCoord (ZIP-008):
1. **Researcher Sovereignty & Zero Shared State**: Each organization runs an independent HTTP server with isolated Ed25519 keypairs, isolated internal HMAC capability secrets, isolated credential stores, isolated tiered memory vaults, and an in-process fail-closed **Egress Boundary Firewall**.
2. **A2A Wire Interoperability**: Discovery via `GET /.well-known/agent.json` (`AgentCard`) and task execution via `POST /a2a/rpc` (`tasks/send`, `tasks/sendSubscribe` SSE, `tasks/get`, `tasks/cancel`) wrapped in signed, audience-bound, replay-resistant envelopes.
3. **Verifiable Scientific Claims**: Research outputs follow ZooCoord's **Zoo Hypothesis Language (ZHL)** (`COMPARE`, `CORRELATE`) computed using exact arbitrary-precision fixed-point arithmetic (`MICRO = 1_000_000`, `BPS = 10_000`), enabling the requesting organization to deterministically recompute and verify every returned claim bit-for-bit before acceptance.
4. **Constitutional AI-Agent Boundaries**: AI agents (`AI_AGENT` principals) may recommend, estimate value, flag conflicts, and prepare plans via non-binding `AdvisoryAssessment` objects (`binding: false`), but are cryptographically prohibited from redefining voting rules, authorizing treasury spending, or self-certifying experiment validity.
5. **License Hygiene**: Production source code is Apache-2.0; every dataset, artifact, or external attachment crossing the organizational boundary MUST carry an explicit reviewed license entry (`license_reviewed: true`) drawn from the receiving organization's approved SPDX whitelist.

---

## 2. Cryptographic & Serialization Primitives

### 2.1 Canonical JSON (RFC 8259)
All hashed and signed objects MUST be serialized to deterministic UTF-8 canonical JSON:
- Object keys sorted lexicographically by Unicode code point.
- No insignificant whitespace (`","` and `":"` separators).
- No HTML escaping (`<`, `>`, `&` serialized literally).
- Exact integer representation (zero floating-point values in any protocol or audit object).
- Empty slices serialized as `[]` (never `null`).

### 2.2 Domain-Separated Hashing and Signatures
Every hash and Ed25519 (RFC 8032) signature binds an explicit ASCII domain prefix separated by a `0x00` byte:

$$\text{DomainMessage}(d, v) = \text{UTF8}(d) \;\|\; \texttt{0x00} \;\|\; \text{CanonicalJSON}(v)$$
$$\text{HashCanonical}(d, v) = \text{hex}(\text{SHA256}(\text{DomainMessage}(d, v)))$$

Defined domains:
- `federated-a2a.v1:agent_card`
- `federated-a2a.v1:org_policy`
- `federated-a2a.v1:envelope`
- `federated-a2a.v1:commitment`
- `federated-a2a.v1:result_artifact`
- `federated-a2a.v1:task_receipt`
- `federated-a2a.v1:egress_block`
- `federated-a2a.v1:governance_action`
- `federated-a2a.v1:advisory`
- `federated-a2a.v1:acceptance`
- `federated-a2a.v1:wire_frame`
- `federated-a2a.v1:audit_leaf`

Ed25519 verification MUST enforce strict canonical encoding (`S < L`, valid twisted Edwards point decompression) so Go (`crypto/ed25519`) and pure-Python 3 (`feda2a_py/ed25519.py`) agree on every signature bit-for-bit.

### 2.3 RFC 6962 Binary Merkle Trees
Vault commitments (`credential_vault_root`, `private_memory_vault_root`, `raw_trace_vault_root`), the wire transcript commitment (`wire_transcript_root`), and the final verification report commitment (`audit_merkle_root`) use RFC 6962 binary Merkle trees:
- Empty tree: $\text{SHA256}(\varepsilon)$.
- Single leaf $d$: $\text{SHA256}(\texttt{0x00} \;\|\; \text{UTF8}(d))$.
- Internal node ($n > 1$): split at largest power of two $k < n$; $\text{SHA256}(\texttt{0x01} \;\|\; \text{Left} \;\|\; \text{Right})$.

---

## 3. Isolation & Boundary Architecture

Each `OrgDeployment` maintains completely independent state:

| Subsystem | Isolation Rule | Cross-Org Exposure |
|---|---|---|
| `CredentialStore` | Org-local map of internal secrets (DB DSNs, treasury custody handles, admin bearer tokens) | **NEVER exported**; only `credential_vault_root` (RFC 6962 SHA-256 Merkle root) appears in `BoundaryCommitment` |
| `MemoryVault` | Tagged records with tiers `public_artifact`, `shared_exchange`, `private_memory`, `restricted_pii`, `raw_reasoning_trace` | Only `public_artifact` and `shared_exchange` may cross boundaries; private/restricted/trace tiers are committed strictly via Merkle root |
| `HMACSecret` | Org-local secret minting ephemeral internal sandbox capability tokens (`MintInternalCapabilityToken`) | **NEVER exported**; verified internally in constant time |
| `Ed25519 Keys` | Distinct keypairs per principal (`ORG_GATEWAY`, `HUMAN_REVIEWER`, `COUNCIL_MEMBER`, `AI_AGENT`) | Public keys published in `OrgGovernancePolicy` / `AgentCard`; private keys never leave org memory |
| `NonceReplayCache` | Per-sender `(SenderOrgID, TaskNonce)` replay set | Local to receiving org |

### 3.1 Fail-Closed Egress Boundary Firewall
Every outbound HTTP payload—including `GET /.well-known/agent.json`, `POST /a2a/rpc` requests, JSON-RPC 2.0 responses, and every individual SSE `data:` frame—MUST pass through `inspectEgress(taskID, rawBytes)` **before any byte is written to the TCP socket**:
1. Scans `rawBytes` across four encodings: raw UTF-8, case-folded lowercase UTF-8, standard Base64, and lowercase hexadecimal.
2. Checks all org-local internal credentials, `private_memory`/`restricted_pii` canary contents, private memory record IDs, and `raw_reasoning_trace` contents.
3. On ANY match:
   - **Aborts fail-closed**: `wire_bytes_sent = 0` for the offending buffer.
   - Emits a signed `EgressBlockEvent` recording only `blocked_digest = SHA256(rawBytes)`, `bytes_blocked`, `blocked_class`, and `reason_code` (`ERR_EGRESS_CREDENTIAL_BLOCKED` or `ERR_EGRESS_MEMORY_BLOCKED`)—never plaintext.
   - Returns HTTP `403 Forbidden` with a sanitized `TaskResultReceipt` (`state: "rejected"`).

> **Note on Benchmark Probes vs Production Deployment**: In production, organizations NEVER publish plaintext secret/canary lists to external auditors; external verification relies on zero-knowledge/redaction proofs, internal DLP audit logs, or hardware TEE attestations. The reproducible benchmark fixture (`fixtures/a2a-exchange-suite.v1.json`) exports a synthetic `boundary_probes` list solely so any independent third-party verifier (Go or Python) can deterministically prove `credential_leak_bytes == 0`, `private_memory_leak_bytes == 0`, and `raw_trace_leak_bytes == 0` across every captured HTTP wire byte.

---

## 4. A2A Wire Protocol & Task Lifecycle

### 4.1 Discovery (`GET /.well-known/agent.json`)
Each organization serves a signed `AgentCard` (`protocol_version: "a2a/0.2+federated-a2a.v1"`) advertising:
- `org_id`, `name`, `logical_url`, `gateway_principal` (Ed25519 public key)
- `capabilities` (`streaming: true`, `state_transition_history: true`)
- `skills` (`research.zhl_compare`, `research.zhl_correlate`, `research.reproducibility_audit`)
- `policy_digest` (SHA-256 of canonical `OrgGovernancePolicy`)
- `boundary_commitment` (vault Merkle roots + `egress_firewall_enforced: true`)
- `card_hash` and `org_signature_hex`

Peers MUST verify the `AgentCard` signature and zero-leak check before sending any task.

### 4.2 JSON-RPC 2.0 Task Methods (`POST /a2a/rpc`)
All requests wrap a `SignedA2AEnvelope` inside JSON-RPC 2.0 (`{"jsonrpc":"2.0","id":...,"method":...,"params":<SignedA2AEnvelope>}`):
- `tasks/send`: Submit a committed research task (`submitted -> working -> completed | rejected`, or `submitted` when `defer_completion: true`).
- `tasks/sendSubscribe`: Stream live A2A Server-Sent Events (`Content-Type: text/event-stream`) emitting `event: status` frames (`submitted`, `working`, `completed`) followed by `event: artifact` containing the signed `TaskResultReceipt`. Every SSE frame passes the Egress Boundary Firewall.
- `tasks/get`: Retrieve an existing task's state history and signed `TaskResultReceipt` (restricted to the originating `SenderOrgID`).
- `tasks/cancel`: Transition an active `submitted`/`working` task to `canceled` upon signed request from the originating organization.

### 4.3 Mandatory Ingress Validation Rules
Before executing any task, the receiving organization MUST verify in order:
1. Sender `AgentCard` is registered and `SignerID == senderCard.GatewayPrincipal.ID` (else `ERR_SPOOFED_ORG_IDENTITY`).
2. `EnvelopeHash` and Ed25519 `OrgSigHex` are valid over `EnvelopeSigningPayload` (else `ERR_ENVELOPE_SIG_INVALID` or `ERR_SPOOFED_ORG_IDENTITY`).
3. `AudienceOrgID == self.OrgID` (else `ERR_AUDIENCE_MISMATCH`).
4. `IssuedAt <= now <= ExpiresAt` (else `ERR_ENVELOPE_EXPIRED`).
5. `(SenderOrgID, TaskNonce)` has never been seen before (else `ERR_NONCE_REPLAY`).
6. `Scope` and `Payload.SkillID` are in `AllowedSkills` and not in `DeniedScopes` (else `ERR_SCOPE_ESCALATION`, `ERR_AI_TREASURY_FORBIDDEN`, or `ERR_AI_VOTING_RULE_FORBIDDEN`).
7. If `ActorRole == "AI_AGENT"`, `SelfCertified` MUST be `false` (else `ERR_AI_SELF_CERTIFY_FORBIDDEN`).
8. `Commitment.InputTier` is in `["public_artifact", "shared_exchange"]` and `InputRecordRefs` contain no private/PII/trace references (else `ERR_PRIVATE_MEMORY_REF_FORBIDDEN`).
9. Every attached dataset/artifact in `Payload.Licenses` has `license_reviewed: true` and an approved SPDX license (else `ERR_LICENSE_UNREVIEWED`).

---

## 5. Deterministic Scientific Verification (ZooCoord ZHL)

To ensure scientific claims are independently checkable without trusting the executing organization, `federated-a2a.v1` defines an exact arbitrary-precision fixed-point statistical kernel (`MICRO = 1_000_000`, symmetric truncating division `truncDiv(a, b)`):

- **`COMPARE` (Two-Group Hypothesis Test)**:
  - $\bar{a} = \text{truncDiv}(\sum a_i, n_A)$, $\bar{b} = \text{truncDiv}(\sum b_i, n_B)$
  - $v_A = \text{truncDiv}(\sum (a_i - \bar{a})^2, n_A \cdot 10^6)$, $v_B = \text{truncDiv}(\sum (b_i - \bar{b})^2, n_B \cdot 10^6)$
  - $\text{effect} = \bar{b} - \bar{a}$
  - $\text{SE} = \max\left(1, \left\lfloor \sqrt{\text{truncDiv}(v_A \cdot 10^6, n_A) + \text{truncDiv}(v_B \cdot 10^6, n_B)} \right\rfloor\right)$
  - $t_{\text{micro}} = \text{truncDiv}(\text{effect} \cdot 10^6, \text{SE})$
  - `significant` $\iff |\text{effect}| \ge \delta_{\min} \;\land\; |t_{\text{micro}}| \ge 2 \cdot 10^6$

- **`CORRELATE` (Paired Pearson Correlation)**:
  - $\text{cov} = \sum (a_i - \bar{a})(b_i - \bar{b})$
  - $\text{den} = \left\lfloor \sqrt{\left(\sum (a_i - \bar{a})^2\right)\left(\sum (b_i - \bar{b})^2\right)} \right\rfloor$
  - $r_{\text{micro}} = \text{truncDiv}(\text{cov} \cdot 10^6, \text{den})$ (if $\text{den} > 0$, else $0$)
  - `significant` $\iff |r_{\text{micro}}| \ge \delta_{\min}$

The requesting organization independently executes the exact same kernel over the committed `ExperimentCommitment` and verifies `recomputed.result_hash == receipt.result.result_hash` before an authorized `HUMAN_REVIEWER` or `COUNCIL_MEMBER` signs `ExperimentAcceptance`.

---

## 6. Constitutional Governance Boundaries

1. `AI_AGENT` principals MAY sign non-binding `AdvisoryAssessment` records (`binding: false`) containing conflict flags, estimated value (`estimated_value_bps`), and recommendations (`POS-19`).
2. `AI_AGENT` principals MUST NOT:
   - Redefine voting quorum or governance rules (`ERR_AI_VOTING_RULE_FORBIDDEN`).
   - Authorize treasury spending or bounty disbursements (`ERR_AI_TREASURY_FORBIDDEN`).
   - Self-certify experiment validity (`ERR_AI_SELF_CERTIFY_FORBIDDEN`).
3. Only authorized `HUMAN_REVIEWER` / `COUNCIL_MEMBER` principals registered in the organization's signed `OrgGovernancePolicy` may finalize experiment acceptance or governance actions.

---

## 7. Canonical Rejection Codes (Go == Python)

| Error Code | Trigger Condition |
|---|---|
| `OK` | Check passed |
| `ERR_CREDENTIAL_LEAK_DETECTED` | Raw/case-folded internal credential detected in payload or wire bytes |
| `ERR_PRIVATE_MEMORY_LEAK` | Private memory / restricted PII canary detected in payload or wire bytes |
| `ERR_RAW_TRACE_LEAK` | Unreviewed raw reasoning trace detected in payload or wire bytes |
| `ERR_PRIVATE_MEMORY_REF_FORBIDDEN` | Non-exchange tier or private memory record ID referenced across org boundary |
| `ERR_ENCODED_SECRET_LEAK` | Base64 or hex-encoded internal secret or canary detected |
| `ERR_AGENT_CARD_SIG_INVALID` | Forged or tampered `AgentCard` hash, policy binding, or Ed25519 signature |
| `ERR_AGENT_CARD_CRED_LEAK` | Internal credential embedded in `AgentCard` |
| `ERR_ENVELOPE_SIG_INVALID` | Tampered `SignedA2AEnvelope` hash or invalid Ed25519 signature |
| `ERR_SPOOFED_ORG_IDENTITY` | Unknown sender org or signature produced by a different org's key |
| `ERR_AUDIENCE_MISMATCH` | `AudienceOrgID` does not match receiving deployment |
| `ERR_ENVELOPE_EXPIRED` | Verification timestamp outside `[IssuedAt, ExpiresAt]` |
| `ERR_NONCE_REPLAY` | Previously observed `TaskNonce` replayed to receiver |
| `ERR_SCOPE_ESCALATION` | Requested scope or skill outside `AllowedSkills` or inside `DeniedScopes` |
| `ERR_AI_VOTING_RULE_FORBIDDEN` | `AI_AGENT` attempts voting rule / quorum modification |
| `ERR_AI_TREASURY_FORBIDDEN` | `AI_AGENT` attempts treasury spend authorization |
| `ERR_AI_SELF_CERTIFY_FORBIDDEN` | `AI_AGENT` attempts binding acceptance or self-certified task validity |
| `ERR_RESULT_RECOMPUTE_MISMATCH` | Scientific result artifact fails independent fixed-point recomputation |
| `ERR_LICENSE_UNREVIEWED` | Missing, unreviewed, or unapproved dataset/artifact license |
| `ERR_EGRESS_CREDENTIAL_BLOCKED` | Live Egress Boundary Firewall blocked credential exfiltration before TCP write |
| `ERR_EGRESS_MEMORY_BLOCKED` | Live Egress Boundary Firewall blocked private memory exfiltration before TCP write |
| `ERR_RECEIPT_SIG_INVALID` | Invalid `TaskResultReceipt` or `EgressBlockEvent` Ed25519 signature |
| `ERR_TASK_STATE_INVALID` | Invalid task ID, unauthorized caller, or illegal state transition |

---

## 8. What Remains Unproven

In accordance with Zoo Labs Foundation scientific standards, the following properties are **explicitly NOT proven** by this reference implementation and remain open engineering or research problems:

1. **Implicit Timing & Size Covert Channels**: Although the Egress Boundary Firewall guarantees `0` explicit credential/canary bytes across raw, case-folded, Base64, and hex encodings, a compromised internal worker could modulate execution latency, packet fragmentation, or benign summary length to leak private bits slowly over repeated queries.
2. **Semantic / Paraphrased & Steganographic Exfiltration**: Pattern- and encoding-based DLP cannot detect an adversarial LLM that paraphrases a private secret into novel natural language or encodes bits into floating-point/summary word choices without matching known tokens. Production deployments require structural information-flow taint tracking and deterministic non-LLM compute sandboxes (as demonstrated here for ZHL statistical kernels) whenever private memory coexists on the host.
3. **Statistical Inference & Differential Privacy Composition**: Deterministic summary statistics (`mean`, `var`, `r`) computed over a private cohort—if ever allowed—can leak membership or reconstruct individual records across repeated adaptive queries without formal $(\varepsilon, \delta)$-differential privacy budgets. `federated-a2a.v1` mitigates this by restricting cross-org compute strictly to `public_artifact` / `shared_exchange` tiers, which does not solve privacy-preserving compute over confidential data (requiring MPC/FHE/DP as outlined in ZooCoord Section 5.4).
4. **Transport-Layer & Network Adversaries**: Loopback HTTP tests validate application-layer Ed25519 authentication and payload boundaries, not internet-scale mTLS PKI governance, BGP/DNS hijacking, traffic-analysis resistance, or volumetric DDoS resilience.
5. **Host / Process Root Compromise**: Because the Egress Boundary Firewall runs in-process inside each `OrgDeployment`, a root adversary with arbitrary memory read/write inside `OrgBeta`'s host can bypass the firewall. Production deployments should isolate the Egress Boundary Firewall in a separate network egress proxy or hardware-attested TEE enclave.
6. **Multi-Hop Transitive Federation & Collusion**: This reference proves two-organization bilateral exchange (`OrgAlpha <-> OrgBeta`). Transitive `OrgA -> OrgB -> OrgC` sub-task delegation, cross-hop capability attenuation, real-time key revocation propagation, and collusion between `OrgB` and `OrgC` remain unimplemented and unproven here.
7. **Linear DLP Scaling on Large Bulk Payloads**: As quantified in `BENCHMARK.md`, scanning full serialized JSON payloads across multiple encodings imposes measurable linear CPU overhead (`~4.4×` to `~10.3×` over unverified passthrough between 1.5 KB and 9.5 KB). High-throughput multi-megabyte tensor/dataset exchanges will require content-addressed out-of-band blob stores with pre-vetted tier manifests rather than inline multi-encoding wire scanning.

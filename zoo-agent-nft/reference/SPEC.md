# `agent-identity-delegation.v1` Normative Specification (`v1.0.0`)

- **Schema Version**: `agent-identity-delegation.v1`
- **Specification Version**: `1.0.0`
- **Issue / Program**: `zoo-apps/papers#3` (*"Decentralized agent identity and delegation"*, HIP-1352)
- **Grounded Papers**:
  - [`../zoo-agent-nft.tex`](../zoo-agent-nft.tex) — *Agent NFTs: A Token Standard for Autonomous AI Agents with Economic Agency* (`IAgentNFT`, `AutonomyParams`, capability bitmap monotonic reduction)
  - [`../../zoo-identity-chain/zoo-identity-chain.tex`](../../zoo-identity-chain/zoo-identity-chain.tex) — *Decentralized Identity on Zoo Network* (`did:zoo:*`, W3C Verifiable Credentials, revocation authorities)
- **Standards Alignment**: W3C DID Core v1.0 (`did:key:` multicodec `0xed01` & portable `did:zoo:`), W3C Verifiable Credentials Data Model v2.0, W3C Bitstring Status List v1.0, RFC 8032 (Ed25519), RFC 8259 (Canonical JSON), RFC 6962 (Merkle Tree Hash).
- **License**: Apache-2.0 (production-bound source code and specification). Datasets, reasoning traces, model weights, and external SDKs require separate license review before use.

---

## 1. Design Goals & Offline Verification Invariant

Autonomous AI agents acting on behalf of human councils, research laboratories, or sub-agent swarms require cryptographic identities that are:

1. **Portable & Self-Verifiable Offline**: Verifying an agent's identity, key rotation history, delegation chain, and revocation status MUST NOT require live blockchain RPCs, centralized IAM servers, or Zoo Network online connectivity at verification time.
2. **Monotonically Attenuated**: Delegated permissions (`scopes`, `allowed_resources`, validity windows, `max_sub_depth`, rate limits, and budget caps) MUST strictly narrow at every hop—mirroring the Zoo Agent NFT paper's rule that capabilities can only be *reduced*, never expanded.
3. **Holder-Bound & Anti-Impersonation**: Delegated credentials MUST NOT operate as bearer tokens. Every action invocation MUST carry a fresh leaf-signed `HolderProof` over the delegation chain digest, audience, action verb, resource URI, and single-use challenge nonce.
4. **Revocable Offline with Cascade Semantics**: Revoking any credential in a delegation chain (leaf or intermediate ancestor) via a signed W3C `BitstringStatusListCredential` or signed `RevocationSnapshot` key-compromise cutoff MUST immediately invalidate the credential and all transitive downstream delegations.
5. **Constitutionally Bounded (HIP-1352)**: AI agents (`AI_AGENT`, `EPHEMERAL_SESSION`) may recommend (`research:recommend`), execute evaluations (`research:execute_eval`), prepare plans (`plan:prepare`), flag conflicts (`conflict:flag`), and estimate value (`value:estimate`), but MUST NEVER hold, delegate, or exercise reserved human-governance capabilities (`governance:vote_rules`, `treasury:authorize`, `experiment:certify`).

---

## 2. Cryptographic Primitives & Canonicalization

### 2.1 Canonical JSON & Domain Separation

All hashes and Ed25519 signature inputs are serialized as deterministic RFC 8259 canonical JSON (UTF-8, lexicographically sorted object keys, no extraneous whitespace, no HTML escaping) prefixed with a UTF-8 domain tag and a single `0x00` separator byte:

$$\text{DomainMsg}(D, x) = D \mathbin{\|} \texttt{0x00} \mathbin{\|} \text{CanonicalJSON}(x)$$

| Domain Tag | Object Signed / Hashed |
| :--- | :--- |
| `zoo.agentid.v1.diddoc` | Portable `DIDDocument` self-signature |
| `zoo.agentid.v1.keyrot` | Dual-signed `KeyRotationProof` (outgoing key + controller co-signature) |
| `zoo.agentid.v1.vc` | W3C VC v2.0 `DelegationVC` issuer signature & canonical `vc_digest` |
| `zoo.agentid.v1.vc.chain` | Canonical SHA-256 commitment over ordered `[vc_digest_0, ..., vc_digest_k]` |
| `zoo.agentid.v1.statuslist` | W3C `BitstringStatusListCredential` signature & digest pin |
| `zoo.agentid.v1.revsnapshot` | Signed `RevocationSnapshot` (status list pins, key cutoffs, CRL Merkle root) |
| `zoo.agentid.v1.holderproof` | Leaf delegate's anti-impersonation `HolderProof` |
| `zoo.agentid.v1.auditleaf` | Suite audit report leaf hashed into the RFC 6962 `audit_merkle_root` |

All binary payloads (32-byte Ed25519 public keys, 64-byte Ed25519 signatures, bitstrings) use unpadded URL-safe Base64 (`base64url` per RFC 4648 Section 5). Ed25519 verification enforces strict canonical point decoding and $S < L$ per RFC 8032.

### 2.2 RFC 6962 Audit & CRL Merkle Root

Both `RevocationSnapshot.crl_merkle_root` and `SuiteReport.audit_merkle_root` use RFC 6962 binary Merkle tree hashing over UTF-8 leaf strings:

- Empty tree: $\text{SHA256}(\varepsilon)$
- Leaf node ($n=1$): $\text{SHA256}(\texttt{0x00} \mathbin{\|} d_0)$
- Internal node ($n>1$, $k = 2^{\lfloor \log_2(n-1) \rfloor}$): $\text{SHA256}(\texttt{0x01} \mathbin{\|} \text{MTH}(D_{0..k-1}) \mathbin{\|} \text{MTH}(D_{k..n-1}))$

---

## 3. Portable Agent Identities (W3C DID + Zoo Agent NFT Binding)

Two offline-verifiable DID methods are supported:

1. **Self-Certifying `did:key:z...`**: Encodes `0xed 0x01 || pubkey_32` in Base58BTC with multibase prefix `z`. Offline verifiers decode the public key directly from the DID string and verify constant-time equality against `genesis_public_key_b64` (`ERR_DID_KEY_BINDING_MISMATCH` on mismatch).
2. **Portable `did:zoo:<namespace>:<slug>`**: Self-contained portable `DIDDocument` export bundle (`portable_export: true`) carrying `genesis_key_id`, `genesis_public_key_b64`, ordered `key_rotations`, `active_key_id`, optional `agent_nft_binding` (Zoo Agent NFT / ERC-6551 TBA wallet address, `model_hash_sha256`, `autonomy_bounds`, `capability_bitmap_hex`), and an active-key Ed25519 self-signature.

### 3.1 Offline Key Rotation Verification

For any `DIDDocument` with `len(key_rotations) > 0`, the offline verifier replays the chain starting at `(genesis_key_id, genesis_public_key_b64)`:

1. Each `KeyRotationProof` MUST match `rot.did == doc.id` and `rot.from_key_id == cur_key_id`.
2. `rot.outgoing_sig_b64` MUST verify under `cur_public_key` over `zoo.agentid.v1.keyrot`.
3. `rot.controller_sig_b64` MUST verify under an authorized key of `doc.controller` (prevents unilateral hijack of a compromised agent key!).
4. After replaying all rotations, `cur_key_id` MUST equal `doc.active_key_id`, EVERY entry in `verification_methods` MUST be either the genesis key or a verified rotation target (no unrotated rogue keys), and `doc.proof` MUST verify under the final active key.

---

## 4. W3C Verifiable Credentials v2.0 Signed Delegation Chains

A delegation chain is an ordered array `[VC_0, VC_1, ..., VC_{d-1}]` from a trusted `HUMAN_COUNCIL` root to the leaf executor:

$$\text{HumanCouncilRoot} \xrightarrow{\text{VC}_0} \text{OrgController} \xrightarrow{\text{VC}_1} \text{LeadResearchAgent} \xrightarrow{\text{VC}_2} \text{SubWorkerAgent} \xrightarrow{\text{VC}_3} \text{EphemeralToolSession}$$

### 4.1 Chain Linkage, Acyclicity & Strict Monotonic Attenuation

For every hop $i \in \{0, \dots, d-1\}$:

1. **Root & Linkage**: For $i=0$, `vc.issuer` MUST be in `trusted_root_dids`, `delegation_depth == 0`, and `parent_vc_id == parent_vc_digest == ""`. For $i>0$, `vc.issuer == parent.credential_subject.id`, `parent_vc_id == parent.id`, and `parent_vc_digest == ComputeVCDigest(parent)` (`ERR_CHAIN_LINK_BROKEN` / `ERR_PARENT_DIGEST_MISMATCH`).
2. **Acyclicity**: No DID may appear more than once across `{vc_0.issuer, vc_0.subject, ..., vc_{d-1}.subject}` (`ERR_CYCLIC_DELEGATION`).
3. **Depth Monotonicity**: For $i>0$, `parent.max_sub_depth >= 1`, `child.delegation_depth == parent.delegation_depth + 1`, and `0 <= child.max_sub_depth <= parent.max_sub_depth - 1` (`ERR_DEPTH_OVERFLOW`).
4. **Temporal Monotonicity & Validity**: `parent.valid_from <= child.valid_from < child.valid_until <= parent.valid_until` (`ERR_TTL_EXTENSION`) and `valid_from <= eval_time <= valid_until` (`ERR_VC_NOT_YET_VALID` / `ERR_VC_EXPIRED`).
5. **Scope Attenuation**: Wildcard `*` scopes are forbidden; `child.scopes ⊆ parent.scopes` (`ERR_SCOPE_ESCALATION`).
6. **Resource Path Attenuation**: All resources MUST begin with `zoo://` and MUST NOT contain `..` or `*`. Every `child_res` MUST satisfy `child_res == parent_res`, or `parent_res` ends with `/` and `child_res` starts with `parent_res`, or `child_res` starts with `parent_res + "/"` (`ERR_RESOURCE_ESCALATION`). Sibling prefix collisions (e.g., `zoo://datasets/ecology-private` vs `zoo://datasets/ecology`) are strictly rejected.
7. **Constraint Attenuation**: `0 < child.max_calls_per_hour <= parent.max_calls_per_hour`, `0 <= child.max_budget_usd_cents <= parent.max_budget_usd_cents`, and if `parent.require_holder_proof` is true then `child.require_holder_proof` MUST be true (`ERR_CONSTRAINT_ESCALATION`).
8. **Audience Narrowing**: If `parent.audience` is non-empty and not `"any"`, `child.audience == parent.audience` (`ERR_AUDIENCE_MISMATCH`).

### 4.2 Constitutional AI-Agent Governance Boundary (HIP-1352)

The three reserved human-governance capabilities are:
- `governance:vote_rules` — redefining quorum, voting weights, or governance rules
- `treasury:authorize` — authorizing treasury disbursements or capital allocation
- `experiment:certify` — declaring scientific experiments valid or certified

**Normative Rule**: Any `DelegationVC` whose subject has `principal_type ∈ {AI_AGENT, EPHEMERAL_SESSION}` MUST NOT contain any reserved governance scope, even if signed by an upstream `HUMAN_COUNCIL` or `ORG_CONTROLLER` key; likewise, no `AI_AGENT` or `EPHEMERAL_SESSION` may invoke an `ActionPresentation` with a reserved governance verb (`ERR_CONSTITUTIONAL_AI_GOVERNANCE_FORBIDDEN`). Authorized `HUMAN_COUNCIL` roots retain governance authority (verified in `STAGE-04`).

---

## 5. Offline Cryptographic Revocation & Cascade Semantics

Offline verification consumes two root-signed artifacts:

1. **W3C `BitstringStatusListCredential`**: Contains a `gzip_base64url` or `raw_base64url` encoded bitstring of length `bit_length` (default `131,072` bits = `16 KB` raw, per W3C Bitstring Status List v1.0 minimum privacy size). Bit `idx` is addressed MSB-first: `byte_idx = idx // 8`, `bit_mask = 1 << (7 - (idx % 8))`. Bit `1` means revoked; bit `0` means active. Decompression is bounded to `(bit_length / 8) + 1` bytes to prevent zip-bomb attacks.
2. **Signed `RevocationSnapshot`**: Pins expected SHA-256 digests of all active `BitstringStatusListCredential` documents, carries `key_revocations` (`revoke_all` for full key compromise and `revoked_before` for epoch bulk cutoffs), lists explicit `revoked_vc_ids`, and commits to their RFC 6962 `crl_merkle_root`.

**Enforcement Rules**:
- **Freshness**: Both `RevocationSnapshot` and every `BitstringStatusListCredential` MUST satisfy `valid_from <= eval_time <= valid_until` (`ERR_REVOCATION_SNAPSHOT_STALE` / `ERR_STATUS_LIST_STALE`), preventing replay of old pre-revocation snapshots.
- **Cascade Revocation**: Every hop $i \in \{0, \dots, d-1\}$ is checked against its bitstring index, explicit CRL, and signing key revocation entries. Revoking an upstream intermediate hop ($i < d-1$) immediately invalidates all downstream delegations (`ERR_CASCADE_PARENT_REVOKED`), even if the leaf credential's own bit is still `0`.

---

## 6. Holder-Binding & Anti-Impersonation (`ActionPresentation`)

Every delegated action invocation MUST include a `HolderProof` signed by the **leaf delegate's** authorized Ed25519 private key binding:

```
(holder_did, holder_key_id, delegation_chain_digest, challenge_nonce, audience, action_verb, resource_uri, timestamp)
```

The verifier enforces:
1. `presentation.audience == ctx.expected_audience` and matches leaf VC `audience` (`ERR_AUDIENCE_MISMATCH`).
2. `presentation.challenge_nonce` is non-empty and absent from `ctx.used_nonces` (`ERR_NONCE_REPLAY`).
3. `holder_proof` is present (`ERR_HOLDER_PROOF_MISSING`), `holder_did == leaf.credential_subject.id` (`ERR_HOLDER_DID_MISMATCH`), all bound fields match the presentation envelope (`ERR_HOLDER_BINDING_MISMATCH`), `timestamp` lies within `[eval_time - 300, eval_time + 30]` (`ERR_HOLDER_PROOF_STALE`), key is not revoked, and Ed25519 signature verifies (`ERR_HOLDER_SIGNATURE_INVALID`).
4. `action_verb ∈ leaf.scopes` (`ERR_ACTION_SCOPE_DENIED`) and `resource_uri` is strictly contained within `leaf.allowed_resources` (`ERR_ACTION_RESOURCE_DENIED`).

---

## 7. What Remains Unproven

In accordance with Zoo Labs Foundation scientific standards, the following properties are **explicitly NOT proven** by this reference specification and offline test suite:

1. **Real-Time Global Revocation Propagation Under Network Partition**: Offline verification relies on the freshness window (`valid_until`) of the last synced `BitstringStatusListCredential` and `RevocationSnapshot`. Between the moment a key is revoked by the council and the moment an air-gapped or partitioned verifier refreshes its snapshot (bounded by `valid_until - issued_at`), a revoked credential remains verifiable offline. Eliminating this window entirely requires synchronous online consensus or short-lived epoch tickets, which trades off offline availability (CAP theorem).
2. **Hardware Key Protection & Private Key Extraction Resistance**: Ed25519 holder-binding proves possession of the private key at signing time, not that the key resides inside a tamper-resistant HSM, TPM, or confidential-compute enclave (SGX/TDX/Nitro). If an adversary compromises the host memory of an agent and extracts its raw Ed25519 private key, the adversary can forge valid `HolderProof`s until the key is rotated or revoked.
3. **Post-Quantum Cryptographic Resistance (ML-DSA / SLH-DSA Migration)**: This v1 reference uses classical RFC 8032 Ed25519 (`eddsa-jcs-2022`) for zero-dependency interoperability across Go and Python stdlibs. Ed25519 is vulnerable to Shor's algorithm on a cryptographically relevant quantum computer; migration to NIST FIPS 204 (ML-DSA) or hybrid Ed25519+ML-DSA suites (as explored in `zoo-pq-crypto`) is deferred to `v2`.
4. **On-Chain ERC-6551 / Zoo Agent NFT Bridge Finality & Ownership Transfer Atomicity**: `agent_nft_binding` records cryptographic lineage metadata (`chain_id`, `nft_contract`, `token_id`, `tba_wallet_address`, `model_hash_sha256`, `autonomy_bounds`) for offline auditing, but this offline verifier does NOT execute EVM state proofs or verify real-time on-chain NFT transfers/ownership changes during cross-chain reorgs.
5. **Distributed Nonce Replay Coordination Across Multi-Replica Verifiers**: Single-verifier replay protection is demonstrated via `used_nonces`, but horizontally scaled multi-region verifier fleets require either sticky routing, shared replay state, or short-lived deterministic challenge-response protocols to prevent concurrent cross-replica replay within the `[-300s, +30s]` timestamp window.
6. **Zero-Knowledge Selective Disclosure & Unlinkability**: Unlike `zoo-identity-chain`'s bilinear accumulator / ZKP presentation design, this v1 offline delegation chain reveals intermediate issuer/subject DIDs and `statusListIndex` values to the verifier; unlinkable anonymous delegation chains (e.g., BBS+ or zk-SNARK delegation proofs) remain future work.

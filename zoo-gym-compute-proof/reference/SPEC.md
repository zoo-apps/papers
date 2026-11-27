# Attested vs Challenged Inference Verification Specification (`inference-verify.v1`)

- **Specification Version**: `1.0.0`
- **Schema Identifier**: `inference-verify.v1`
- **Schema File**: [`schema/inference-verify.v1.schema.json`](schema/inference-verify.v1.schema.json)
- **Tracking Issue / HIP**: `zoo-apps/papers#14` · `HIP-1350`
- **External Standards Referenced**:
  - [in-toto Attestation Statement v1](https://in-toto.io/Statement/v1) & [DSSE v1](https://github.com/secure-systems-lab/dsse)
  - [Sigstore Cosign / Rekor Transparency Log](https://docs.sigstore.dev/) (RFC 6962 Merkle Tree Hash & Inclusion Proofs)
  - [RFC 8032 Ed25519](https://www.rfc-editor.org/rfc/rfc8032)
- **Aligned Zoo Papers**:
  - `zoo-gym-compute-proof/zoo-gym-compute-proof.tex` (Ed25519 Attestations, Hash Chains, Spot-Verify Sampling & Slashing)
  - `zoo-poai-consensus/sections/15-binding-scheme.tex` & `25-receipt-soundness.tex` (Receipt Binding & Honest Boundary)
  - `zoo-network-architecture/zoo-network-architecture.tex` (Decentralized Inference Routing)
  - `thinking-chains/thinking-chains.tex` (Constitutional Law of Cognition)
- **License**: Apache-2.0

---

## 1. Scope & Research Question

This specification defines a deterministic, cross-language verifiable protocol (`inference-verify.v1`) for comparing four decentralized inference verification regimes under an identical cryptographic, computational, and economic threat model:

1. **`signed_attestation_only`**: in-toto DSSE v1 + RFC 8032 Ed25519 signature + Sigstore Cosign/Rekor-style RFC 6962 transparency-log inclusion proof (zero re-execution).
2. **`independent_reexecution`**: 100% deterministic re-execution across $k \ge 2$ independent operators from disjoint `operator_group`s with majority quorum $\lceil k/2 \rceil$ and signed DSSE receipts.
3. **`random_challenge_verification`**: Post-commit unpredictable deterministic challenge sampling at rate $p \in [0, 1]$ bound to an epoch beacon, paired with economic bond $B$, slashing penalty $S$, challenger reward $R \le S$, and signed DSSE fraud-proof transcripts.
4. **`hybrid_attested_plus_challenged`**: 100% in-toto DSSE + transparency-log provenance on every job combined with bounded risk-adaptive challenge sampling ($p_{\text{base}}$ for established high-reputation workers; $p_{\text{escalated}}$ for probationary, low-reputation, or AI-advisory-flagged workers).

---

## 2. Threat Model

All four regimes MUST be evaluated under the following six explicit adversary classes:

| # | Adversary Class | Capabilities & Strategy | Caught By |
|---|---|---|---|
| **T1** | **Honest-but-lazy worker** | Holds a valid enrolled Ed25519 key; skips model execution and returns a cheap dummy or cached output (`~5%` compute cost) wrapped in a valid DSSE + transparency-log attestation. | `independent_reexecution` (100%), `random_challenge_verification` (prob. $p$ per job, economically deterred when $p(F+S) > g$), `hybrid_attested_plus_challenged` (deterred + escalated prob. $p_{\text{esc}}$). **NOT caught by `signed_attestation_only` (0%).** |
| **T2** | **Rational profit-maximizing cheater** | Chooses cheat rate $c \in [0, 1]$ to maximize expected net profit $\mathbb{E}[\pi] = (1-c)(F - c_{\text{honest}}) + c\big((1-p)(F - c_{\text{cheat}}) + p(-S - c_{\text{cheat}})\big)$. | Deterred strictly when $p(F + S) > c_{\text{honest}} - c_{\text{cheat}}$. Exploits undercollateralized challenge regimes where $p(F+S) < g$. |
| **T3** | **Sybil / colluding attester** | Controls multiple keys inside the same `operator_group` (or self-verifies / self-challenges) to emit fake corroborating re-execution receipts or rubber-stamp challenges. | Disjoint `operator_group` & `actor_id` invariant (`ERR_COLLUDING_OPERATOR_GROUP`). |
| **T4** | **Equivocating / replay worker** | Replays a valid signed attestation from an earlier epoch $e' \ne e$, or signs two conflicting outputs for the same `job_id`. | Strict `expected_epoch` binding (`ERR_EPOCH_MISMATCH`), `seen_job_outputs` equivocation check (`ERR_EQUIVOCATION_DETECTED`), and append-only transparency log commitment. |
| **T5** | **Selective-cheating adaptive adversary** | Behaves honestly on most jobs ($1 - c$) and cheats selectively on fraction $c$, attempting to build reputation or grind challenge inputs. | Post-commit epoch beacon prevents pre-commitment challenge grinding; risk-adaptive escalation raises $p_{\text{base}} \to p_{\text{escalated}}$ on probationary/flagged workers. |
| **T6** | **Compromised / forged signing key** | Forges DSSE signatures, tampers with payloads post-signing, omits or alters transparency-log proofs, or signs with revoked, expired, or unregistered keys. | All four regimes enforce RFC 8032 Ed25519 DSSE PAE verification, key-directory status/validity-window checks, and RFC 6962 transparency-log inclusion proofs. |

---

## 3. Cryptographic Formats

### 3.1 in-toto Statement v1 & DSSE Envelope

Every worker attestation, independent re-execution receipt, and challenge transcript MUST be encoded as a DSSE v1 envelope with:
- `payloadType`: `"application/vnd.in-toto+json"`
- `payload`: standard Base64 encoding of the UTF-8 JSON in-toto Statement v1 (`_type = "https://in-toto.io/Statement/v1"`).
- `signatures[0].keyid`: first 8 bytes (16 lowercase hex chars) of `SHA-256(ed25519_pubkey_32bytes)`.
- `signatures[0].sig`: standard Base64 encoding of the 64-byte RFC 8032 Ed25519 signature over the DSSE Pre-Authentication Encoding (PAE):

```text
PAE(payloadType, payloadBytes) =
    "DSSEv1 " || dec(len(payloadType)) || " " || payloadType || " " || dec(len(payloadBytes)) || " " || payloadBytes
```

### 3.2 Sigstore Cosign / Rekor-Style Transparency Log Bundle

Every worker attestation MUST include a `TransparencyLogBundle` proving inclusion in a trusted append-only RFC 6962 binary SHA-256 Merkle tree:

1. **Canonical Leaf Entry Digest**:
   ```text
   leaf_entry_digest = hex(SHA-256(
       "inference-verify.v1:tlog-leaf:" || job_id || ":" ||
       hex(SHA-256(payloadBytes)) || ":" ||
       hex(SHA-256(sigBytes)) || ":" || dec(epoch)
   ))
   ```
2. **RFC 6962 Domain-Separated Hashing**:
   - Leaf hash: $\text{HashLeaf}(d) = \text{SHA-256}(\texttt{0x00} \parallel d)$ where $d = \text{UTF-8}(\texttt{leaf\_entry\_digest})$.
   - Interior node hash: $\text{HashNode}(L, R) = \text{SHA-256}(\texttt{0x01} \parallel L \parallel R)$.
   - Tree decomposition for size $n > 1$: split at $k$, the largest power of two strictly less than $n$.
3. **Signed Checkpoint (STH)**:
   The trusted log operator signs the exact UTF-8 checkpoint message with RFC 8032 Ed25519:
   ```text
   rekor-checkpoint.v1
   <log_id>
   <tree_size>
   <root_hash>
   <checkpoint_epoch>
   ```
   Verifiers MUST check that `log_id` and `log_pubkey_hex` match `trust_root`, `checkpoint_epoch == expected_epoch`, the Ed25519 checkpoint signature is valid, `leaf_entry_digest` matches the canonical leaf digest, and the RFC 6962 inclusion path reconstructs `root_hash`.

### 3.3 Deterministic Quantized Inference Workload (`zoo-qmlp-32x64x16.v1`)

To guarantee 100% cross-architecture and Go $\leftrightarrow$ Python bit-identical verification without floating-point drift, the reference workload is an exact `int64` 3-layer quantized MLP token-scoring model ($V=512$, $D_{\text{in}}=32$, $D_{\text{hid}}=64$, $D_{\text{out}}=16$) parameterized deterministically via SHA-256 counter mode from the pinned SHA-256 `corpus_root_sha256` of seven real `zoo-apps/papers` LaTeX files (`corpus-manifest.json`):
- Hidden activations use exact positive-guarded right-shift ReLU: $h_j = 0$ if $\text{acc} \le 0$ else $\text{acc} \gg 7$ (identical across all signed shift/division semantics).
- Output commitment: `output_digest = SHA-256("inference-verify.v1:output:" || job_id || ":" || model_digest || ":" || input_digest || ":" || logits_digest || ":" || u32_le(top_token))`.

---

## 4. Challenge Sampling & Economic Incentive-Compatibility

### 4.1 Post-Commit Deterministic Challenge Sampler

After workers log their DSSE attestations in the transparency log for epoch $e$, the epoch beacon `epoch_beacon_hex` is revealed. The challenge draw is computed in exact integer basis points (`0..9999`):

```text
draw_bps = uint64_be(SHA-256(
    "inference-verify.v1:challenge:" || epoch_beacon_hex || ":" || job_id || ":" || worker_output_digest
)[0:8]) mod 10000
```

A job is selected for independent challenge iff `draw_bps < effective_challenge_bps`.
Under `hybrid_attested_plus_challenged`, `effective_challenge_bps` is deterministically set to:
- `challenge_escalated_bps` (default `2500` = 25%) if `jobs_completed < probation_jobs` OR `reputation_score < reputation_threshold` OR `ai_advisory_flagged == true`, clamped to `[min_challenge_bps, max_challenge_bps]`.
- `challenge_base_bps` (default `500` = 5%) otherwise.

### 4.2 Incentive-Compatibility Theorem

Let $F$ be the per-job worker fee, $c_{\text{honest}}$ honest inference cost, $c_{\text{cheat}}$ lazy dummy cost, $g = c_{\text{honest}} - c_{\text{cheat}}$ the per-job cheating savings, $p$ the challenge probability, and $S$ the slashing penalty upon fraud proof.

- Honest expected profit per job: $\mathbb{E}[\pi_{\text{honest}}] = F - c_{\text{honest}}$.
- Cheating expected profit per cheated job: $\mathbb{E}[\pi_{\text{cheat}}] = (1-p)(F - c_{\text{cheat}}) + p(-S - c_{\text{cheat}}) = F - c_{\text{cheat}} - p(F + S)$.
- Cheating advantage: $\Delta_{\text{cheat}} = \mathbb{E}[\pi_{\text{cheat}}] - \mathbb{E}[\pi_{\text{honest}}] = g - p(F + S)$.

**Honesty strictly dominates rational cheating ($\Delta_{\text{cheat}} < 0$) if and only if:**

$$p \cdot (F + S) > g \iff S > \frac{g}{p} - F$$

Under the stricter bond-only criterion (ignoring forfeited job fees), $p \cdot S > g \iff S > g / p$.

---

## 5. Normative Verdicts, Error Codes & Constitutional Guards

### 5.1 Verdicts

| Verdict | Meaning |
|---|---|
| `VERIFIED` | All required checks for the active regime passed. Note: under `signed_attestation_only` or unchallenged jobs in probabilistic regimes, `VERIFIED` does **not** guarantee faithful execution; benchmark accounting separately records `fraud_escaped` against ground truth. |
| `FRAUD_DETECTED` | Cryptographic attestation and transparency-log checks passed, **and** deterministic re-execution or a verified DSSE challenge transcript proved that the worker's output differs from the honest deterministic output. |
| `INVALID_ATTESTATION` | Structural, signature, key-status, epoch, equivocation, transparency-log, quorum, operator-group collusion, or challenge-transcript validity check failed. |
| `POLICY_REJECTED` | Constitutional or AI-role governance invariant violated. |

### 5.2 Constitutional & AI-Role Guards

In alignment with the Zoo x Hanzo open research governance rules:
- An `AI_AGENT` MAY recommend challenge rates (`RECOMMEND_CHALLENGE_RATE`) or flag suspicious workers (`FLAG_SUSPICIOUS_WORKER`) strictly within constitutionally pre-approved `[min_challenge_bps, max_challenge_bps]` bounds.
- An `AI_AGENT` MUST NOT:
  - self-certify its own inference or serve as worker/verifier/challenger (`POLICY_REJECTED` / `ERR_AI_SELF_CERT_FORBIDDEN`),
  - mutate bond, slashing, quorum, or challenge-rate bounds (`POLICY_REJECTED` / `ERR_AI_POLICY_MUTATION_FORBIDDEN`),
  - autonomously approve slashing (`POLICY_REJECTED` / `ERR_AI_SLASH_APPROVAL_FORBIDDEN`).
- No attestation may set `proves_hardware_tee_uncompromised = true` or `proves_scientific_truth = true` (`POLICY_REJECTED` / `ERR_OVERCLAIMED_PROOF_SCOPE`).

### 5.3 Audit Merkle Root

For any verification suite, each case result produces a canonical leaf digest:
```text
audit_leaf_digest = hex(SHA-256(
    "inference-verify.v1:audit-leaf:" || case_id || ":" || regime || ":" || verdict || ":" ||
    error_code || ":" || challenged || ":" || fraud_escaped || ":" || reexec_count || ":" ||
    output_digest || ":" || tlog_root
))
```
The suite `audit_merkle_root` is the RFC 6962 Merkle root over all UTF-8 `audit_leaf_digest` strings in case order. Independent Go and Python verifiers MUST produce bit-identical `audit_merkle_root` hashes.

---

## 6. What Remains Unproven

This reference specification and benchmark explicitly separate what is cryptographically and empirically verified from what remains unproven in production:

1. **Hardware TEE Silicon & Side-Channel Attacks**: This implementation models software cryptographic attestations (in-toto DSSE + transparency log). It does **not** prove security against physical GPU/TEE decapping, Intel TDX / AMD SEV-SNP / NVIDIA Confidential Computing microarchitectural side channels, or compromised OEM root-of-trust certificates (`proves_hardware_tee_uncompromised` is schema-locked to `false`).
2. **Live Rekor / Fulcio Network Liveness & Split-View Resistance**: The transparency log is evaluated locally in-memory with RFC 6962 proofs and signed checkpoints. Production Sigstore deployments additionally require live witness gossiping, consistency-proof auditing across checkpoints to prevent split-view equivocation by a malicious log operator, OIDC issuer liveness (Fulcio), and certificate revocation propagation latency.
3. **Non-Deterministic Floating-Point GPU Kernels**: Our deterministic reference workload uses exact integer arithmetic (`int64`) so Go and Python achieve 0% honest false rejections. Production FP16/BF16/FP8 transformer inference across heterogeneous GPU drivers (cuBLAS, CUTLASS, Triton, tensor-core reduction order) exhibits non-associative floating-point drift; extending random-challenge fraud proofs to floating-point GPUs requires either deterministic quantized execution profiles, exact integer tiles (e.g., HIP-1350 Freivalds/whole-K int8), or bounded tolerance proofs with calibrated false-rejection analysis.
4. **Covert Out-of-Band Collusion Beyond Operator Metadata**: Our `operator_group` checks reject declared same-operator collusion, but cannot prevent undeclared covert cartels across separate legal identities without external Sybil resistance, stake-graph analysis, or hardware/network diversity proofs.
5. **Semantic Truthfulness & Model Safety**: Even 100% verified execution proves only that the committed weights ran on the committed tokens—never that the model's answer is scientifically true, unbiased, or safe (`proves_scientific_truth` is schema-locked to `false`).

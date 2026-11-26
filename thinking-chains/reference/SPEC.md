<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Zoo Labs Foundation and Contributors
-->

# Thinking Chains Canonical Execution Receipt Specification

- **Specification Version**: `1.0.0`
- **Schema Identifier**: `zoo.thinking-chains.receipt.v1`
- **Status**: Reference Implementation (`zoo-apps/papers#7`, `hip-1352`)
- **Primary Reference**: *Thinking Chains — Proof of AI: Trustless Money from Useful Intelligence* (`thinking-chains/thinking-chains.tex`, Sections 3–10, 14–15, 19, 21)

---

## 1. Purpose and Scope

This specification defines a portable, deterministic, cryptographically verifiable **canonical execution receipt** for accountable, useful computational work executed by cognitive nodes and AI research agents.

It operationalizes the core seam of the Thinking Chains architecture:

> *A Thinking Chain may think live, heterogeneously, and privately; it may only settle finite, authenticated artifacts of that thought — never an unreplayable generation treated as a deterministic value.* (Law of Cognition, Principle 1)

### 1.1 Explicit Non-Goal and Privacy Boundary (Public Evidence Only)

**This specification does NOT provide, request, serialize, or verify access to a model's private internal chain-of-thought (CoT).**

- Receipts commit strictly to **public evidence**, **content-addressed input/output hashes**, **authorized tool invocation traces**, and **verifiable check results**.
- Any receipt carrying forbidden private-CoT fields (e.g., `private_cot`, `chain_of_thought`, `internal_cot`, `hidden_reasoning`, `raw_thinking`, `private_scratchpad`, `thought_tokens`, `internal_monologue`, `reasoning_trace_private`) or setting `execution.public_trace_only != true` or `public_evidence[*].public_only != true` **MUST** be rejected (`ERR_PRIVATE_COT_FORBIDDEN`).

### 1.2 Constitutional Separation of Authority

Per Constitutional Rules 7 and 12 (*"AI may propose more authority, but may not grant itself more authority"*):

1. **No Self-Attestation**: The executing agent (`execution.executor_id`) **MUST NOT** appear as a `verifier_id` in `attestations` (`ERR_SELF_ATTESTATION_FORBIDDEN`). An AI agent cannot declare its own experiment valid.
2. **No Treasury Authorization**: `settlement.treasury_spend_authorized` **MUST** be `false` (`ERR_CONSTITUTIONAL_TREASURY_SPEND`).
3. **No Voting Rule Modification**: `settlement.voting_rules_modified` **MUST** be `false` (`ERR_CONSTITUTIONAL_VOTING_RULES`).
4. **Advisory Scope Only**: `result.proposed_action_scope` **MUST** be restricted to non-executing artifact scopes: `research_artifact`, `advisory_recommendation`, `benchmark_report`, or `model_delta_proposal` (`ERR_CONSTITUTIONAL_AUTHORITY_ESCALATION`).
5. **Subsidy Requires Provable Work**: Per `thinking-chains.tex` (§Tokenomics), `settlement.subsidy_eligible == true` is **forbidden** when `execution.evidence_mode == "quorum_signatures"` (`ERR_SUBSIDY_REQUIRES_PROVABLE_WORK`). Bare quorum signatures may earn demand fees, never mint new subsidy supply.

---

## 2. Canonical Receipt Data Model

A canonical receipt is a JSON object conforming strictly to [`schema/canonical-receipt.v1.schema.json`](schema/canonical-receipt.v1.schema.json) with **no unknown keys**, **no duplicate keys**, **no `null` values**, and **no floating-point numbers**.

### 2.1 Top-Level Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `schema_version` | string | Yes | Exact literal `"zoo.thinking-chains.receipt.v1"` |
| `job_id` | string | Yes | Unique deterministic job identifier (`[A-Za-z0-9._:-]{4,128}`) |
| `nonce` | hex64 | Yes | 32-byte lowercase hex replay-protection nonce ($\nu$) |
| `objective` | object | Yes | Research objective, declared finite output space $\mathcal{O}_\tau$, governance HITL level, and recursion budget |
| `execution` | object | Yes | Executor identity, model/version, `ModelSpecHash`, authorized profile, inference tier, evidence mode, hardware class |
| `inputs` | array | Yes | Non-empty ordered list of content-addressed input artifacts |
| `authorized_tools` | array | Yes | Ordered list (`seq = 0..N-1`) of authorized tool invocations |
| `public_evidence` | array | Yes | Non-empty ordered list of public evidence and intermediate artifact commitments |
| `checks` | array | Yes | Non-empty ordered list of verifiable deterministic checks with fixed-point integer metrics (`metric_bps`, `threshold_bps`) |
| `result` | object | Yes | Finite canonical verdict, output hash ($o^\ast$), fixed-point quality score, preserved dissent $\pi$ (`dissent_bps`), and action scope |
| `provenance` | object | Yes | Domain-separated SHA-256 Merkle roots (`inputs_root`, `tools_root`, `evidence_root`, `checks_root`, `result_digest`, `provenance_root`) |
| `settlement` | object | Yes | Chain ID, escrow reference, `IntentID`, payer, integer fee units, subsidy eligibility, block height, UTC unix timestamp, constitutional guards |
| `attestations` | array | Yes | Independent RFC 8032 Ed25519 verifier attestations over `canonical_receipt_hash` |

### 2.2 Numeric Determinism (Fixed-Point Integer Discipline)

In accordance with Principle 2 (*The Reproducibility Line*, `sections/08-two-tier-inference.tex`) and `sections/10-finite-outputs.tex`, **floating-point numbers are strictly forbidden** anywhere inside a canonical receipt:

- All quality metrics, thresholds, and dissent measurements are represented as signed 64-bit integers in **basis points** (`0..10000`, where `10000 = 100.00%`).
- All token/fee amounts (`fee_units`), byte lengths (`byte_length`), durations (`wall_time_ms`), block heights (`settled_at_height`), and timestamps (`settled_at_unix`, `attested_at_unix`) are exact base-10 integers.
- Parsers **MUST** reject any JSON number token containing `.`, `e`, or `E` (`ERR_FLOAT_FORBIDDEN`).

---

## 3. Canonical Serialization (`CanonicalJSON`)

To guarantee bit-identical hashes across independent implementations in Go, Python, Rust, or other languages, receipts are canonicalized using an **integer-only strict profile of RFC 8785 (JCS)**:

1. **Encoding**: Valid UTF-8 with no BOM and no trailing newline.
2. **Whitespace**: Zero insignificant whitespace between tokens (`:` and `,` only).
3. **Objects**:
   - Duplicate keys in input JSON **MUST** be rejected prior to canonicalization (`ERR_DUPLICATE_KEY`).
   - Keys are sorted in strictly ascending lexicographical order by UTF-8 byte sequence (equivalent to UTF-16 code-unit order since all schema keys are ASCII `[a-z0-9_]`).
4. **Arrays**: Elements preserve their exact array order.
5. **Strings**:
   - Enclosed in `"` (`0x22`).
   - Escape `"` as `\"`, `\` as `\\`, `0x08` as `\b`, `0x0C` as `\f`, `0x0A` as `\n`, `0x0D` as `\r`, `0x09` as `\t`, and all other control characters `< 0x20` as `\u00xx` (lowercase hex).
   - HTML characters (`<`, `>`, `&`) **MUST NOT** be escaped as `\u003c` etc. (Go implementations MUST NOT use default HTML-escaping JSON serialization).
   - Non-ASCII valid UTF-8 code points `>= 0x80` are emitted directly as raw UTF-8 bytes without `\uXXXX` escaping.
6. **Integers**: Base-10 canonical integer representation (`0`, `42`, `-1`), no leading zeros, no `+` sign, range `[-2^63, 2^63 - 1]`.
7. **Booleans**: Literal `true` or `false`.

---

## 4. Cryptographic Constructions

All hashes use **SHA-256** (FIPS 180-4) encoded as 64-character lowercase hexadecimal strings when serialized to JSON.

### 4.1 Domain-Separated RFC 6962 Binary Merkle Tree

For an ASCII domain label $D$ and ordered list of leaf byte strings $L = [l_0, l_1, \dots, l_{n-1}]$:

1. **Empty list ($n = 0$)**:
   $$\mathrm{MerkleRoot}(D, []) = \mathrm{SHA256}(\texttt{"zoo.thinking-chains.merkle.empty.v1:"} \parallel D)$$
2. **Single leaf ($n = 1$)**:
   $$\mathrm{MerkleRoot}(D, [l_0]) = \mathrm{SHA256}(\texttt{0x00} \parallel D \parallel \texttt{":"} \parallel l_0)$$
3. **Multiple leaves ($n \ge 2$)**:
   Let $k$ be the largest power of two strictly less than $n$ ($k = 2^{\lfloor \log_2(n-1) \rfloor}$). Then:
   $$\mathrm{MerkleRoot}(D, L) = \mathrm{SHA256}\big(\texttt{0x01} \parallel D \parallel \texttt{":"} \parallel \mathrm{MerkleRoot}(D, L[0{:}k]) \parallel \mathrm{MerkleRoot}(D, L[k{:}n])\big)$$

This construction matches RFC 6962 Certificate Transparency:
- Leaf/interior domain separation (`0x00` vs `0x01`) prevents second-preimage attacks.
- Non-duplicating split prevents CVE-2012-2459 tail-duplication malleability.
- Supports compact $O(\log n)$ inclusion proofs for any artifact, tool call, evidence item, or check.

### 4.2 Provenance Root Derivation

Given a receipt $R$:

```text
inputs_root     = MerkleRoot("inputs",   [CanonicalJSON(x) for x in R.inputs])
tools_root      = MerkleRoot("tools",    [CanonicalJSON(x) for x in R.authorized_tools])
evidence_root   = MerkleRoot("evidence", [CanonicalJSON(x) for x in R.public_evidence])
checks_root     = MerkleRoot("checks",   [CanonicalJSON(x) for x in R.checks])
result_digest   = SHA256("zoo.thinking-chains.result.v1:" || CanonicalJSON(R.result))
provenance_root = MerkleRoot("provenance", [
                    raw32(inputs_root),
                    raw32(tools_root),
                    raw32(evidence_root),
                    raw32(checks_root),
                    raw32(result_digest)
                  ])
```

Note that the leaves passed into `MerkleRoot("provenance", ...)` are the **32-byte raw digests** (not hex strings) in exact order `[inputs_root, tools_root, evidence_root, checks_root, result_digest]`.

### 4.3 Canonical Receipt Hash (`canonical_receipt_hash`)

Let `unsigned_receipt` be the receipt object containing all 12 core top-level fields **excluding** `attestations`:
`{authorized_tools, checks, execution, inputs, job_id, nonce, objective, provenance, public_evidence, result, schema_version, settlement}`.

```text
canonical_receipt_hash = SHA256("zoo.thinking-chains.receipt.v1\x00" || CanonicalJSON(unsigned_receipt))
```

Because `attestations` are excluded from the preimage, multiple independent verifiers can attest concurrently without mutating `canonical_receipt_hash`, while every attestation cryptographically binds itself to `canonical_receipt_hash`.

### 4.4 Independent Verifier Attestations (RFC 8032 Ed25519)

Each attestation object in `attestations` signs the exact UTF-8 byte message:

```text
attestation_message =
    "zoo.thinking-chains.attestation.v1\x00"
 || canonical_receipt_hash_hex
 || "\x00"
 || verifier_id
 || "\x00"
 || verifier_role
 || "\x00"
 || verdict
 || "\x00"
 || decimal_ascii(attested_at_unix)
```

- Signature algorithm: **PureEdDSA Ed25519 (RFC 8032 §5.1)** over `attestation_message`.
- `attested_receipt_hash` in the attestation JSON **MUST** equal the independently recomputed `canonical_receipt_hash`.

---

## 5. Verification Algorithm (`VerifyReceipt`)

An independent verifier receiving `(raw_receipt_bytes, policy_bundle)` **MUST** perform all steps below and fail closed on the first violation:

1. **Strict Parse**: Decode UTF-8 JSON with duplicate-key rejection, float rejection, and private-CoT key scan across all nested objects.
2. **Schema & Type Validation**: Validate all required keys, exact key sets (no unknown fields), enum values, hex formats, integer ranges, `seq == index` on `authorized_tools`, and `recursion_depth <= max_recursion_depth`.
3. **Private-CoT Guard**: Confirm `execution.public_trace_only == true`, every `public_evidence[*].public_only == true`, and no private URI schemes (`private://`, `cot://`, `internal-cot`).
4. **Constitutional Guard**:
   - `settlement.treasury_spend_authorized == false`
   - `settlement.voting_rules_modified == false`
   - `result.proposed_action_scope` in safe non-executing allowlist
   - If `settlement.subsidy_eligible == true`, then `execution.evidence_mode != "quorum_signatures"`.
5. **Policy & Profile Allowlist Guard**:
   - Look up `execution.execution_profile_id` in `policy.authorized_profiles`.
   - Verify `model_id`, `model_spec_hash`, `inference_tier`, `evidence_mode`, every `authorized_tools[*].tool_name`, `objective.max_recursion_depth`, and `result.output_byte_length` against the authorized profile.
6. **Check Consistency Guard**:
   - If `result.status == "completed"`, every entry in `checks` MUST have `passed == true` and `metric_bps >= threshold_bps`.
7. **Provenance Reconstruction**:
   - Recompute `inputs_root`, `tools_root`, `evidence_root`, `checks_root`, `result_digest`, and `provenance_root`.
   - All six values MUST match `receipt.provenance` byte-for-byte.
8. **Canonical Receipt Hash**:
   - Compute `canonical_receipt_hash` over `unsigned_receipt`.
9. **Independent Verifier Attestation Verification**:
   - Track seen `verifier_id`s (reject duplicates).
   - For each attestation:
     - Reject if `verifier_id == execution.executor_id` (self-attestation forbidden).
     - Look up `verifier_id` in `policy.trusted_verifiers`; verify `public_key_hex` matches registry and `verifier_role` is permitted.
     - Verify `attested_receipt_hash == canonical_receipt_hash`.
     - Verify RFC 8032 Ed25519 signature over `attestation_message`.
   - Count valid attestations with `verdict == "VALID"`; require count `>= profile.min_verifiers`.
10. **Batch Replay Protection (`VerifyBatch`)**:
    - Across a set of receipts, `job_id`, `nonce`, and `settlement.intent_id` MUST each be globally unique.

---

## 6. Error Codes

Both Go and Python reference verifiers return standardized deterministic error codes:

| Code | Trigger |
| --- | --- |
| `ERR_INVALID_JSON` | Malformed UTF-8 or JSON syntax error |
| `ERR_DUPLICATE_KEY` | Duplicate key in any JSON object |
| `ERR_FLOAT_FORBIDDEN` | Floating-point literal or scientific notation detected |
| `ERR_PRIVATE_COT_FORBIDDEN` | Private CoT key, `public_trace_only=false`, `public_only=false`, or private URI |
| `ERR_SCHEMA_VIOLATION` | Missing/unknown key, invalid enum, bad hex, out-of-range integer, non-monotonic tool `seq` |
| `ERR_CONSTITUTIONAL_TREASURY_SPEND` | `settlement.treasury_spend_authorized == true` |
| `ERR_CONSTITUTIONAL_VOTING_RULES` | `settlement.voting_rules_modified == true` |
| `ERR_CONSTITUTIONAL_AUTHORITY_ESCALATION` | Disallowed `result.proposed_action_scope` |
| `ERR_SUBSIDY_REQUIRES_PROVABLE_WORK` | `subsidy_eligible == true` under `quorum_signatures` |
| `ERR_UNAUTHORIZED_PROFILE` | `execution_profile_id` not in policy allowlist |
| `ERR_UNAUTHORIZED_MODEL_OR_TIER` | Model, `ModelSpecHash`, tier, or evidence mode disallowed by profile |
| `ERR_UNAUTHORIZED_TOOL` | Tool invocation not allowed by profile |
| `ERR_RECURSION_BUDGET_EXCEEDED` | Recursion depth exceeds objective or profile limit |
| `ERR_OUTPUT_TOO_LARGE` | `result.output_byte_length` exceeds profile limit |
| `ERR_FAILED_CHECK_IN_COMPLETED_JOB` | Completed job contains failed check or metric below threshold |
| `ERR_PROVENANCE_MISMATCH` | Recomputed Merkle root or `result_digest` disagrees with committed provenance |
| `ERR_SELF_ATTESTATION_FORBIDDEN` | `attestation.verifier_id == execution.executor_id` |
| `ERR_DUPLICATE_VERIFIER` | Same `verifier_id` attests more than once |
| `ERR_UNTRUSTED_VERIFIER` | Verifier ID unknown, public key mismatch, or disallowed role |
| `ERR_ATTESTATION_HASH_MISMATCH` | `attested_receipt_hash != canonical_receipt_hash` |
| `ERR_INVALID_SIGNATURE` | Ed25519 signature verification failed |
| `ERR_INSUFFICIENT_ATTESTATIONS` | Fewer than `profile.min_verifiers` valid `VALID` attestations |
| `ERR_REPLAY_DETECTED` | Duplicate `job_id`, `nonce`, or `settlement.intent_id` in batch |

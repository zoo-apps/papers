# Proof of AI Deterministic Matrix-Product Transcript Specification (`poai-transcript.v1`)

- **Specification Version**: `1.0.0`
- **Schema Identifier**: `poai-transcript.v1`
- **Schema File**: [`schema/poai-transcript.v1.schema.json`](schema/poai-transcript.v1.schema.json)
- **Tracking Issue / HIP**: `zoo-apps/papers#13` · `HIP-1350`
- **Aligned Papers**:
  - `zoo-poai-consensus/sections/17-freivalds-hash.tex` (Software-Only Execution Proof)
  - `zoo-poai-consensus/sections/25-receipt-soundness.tex` (The Honest Boundary & Receipt Soundness)
  - `zoo-gym-compute-proof/zoo-gym-compute-proof.tex` (Ed25519 Compute Attestation)
  - `thinking-chains/thinking-chains.tex` (The Law of Cognition)
- **License**: Apache-2.0

---

## 1. Scope and Constitutional Boundary

This specification defines a **deterministic, versioned, CPU-verifiable integer matrix-product transcript** using Freivalds' probabilistic verification algorithm over exact integer arithmetic.

### 1.1 Normative Verdict Enum

Every verification run MUST emit exactly one of four deterministic `compute_verdict` values:

| Verdict | Meaning |
|---|---|
| `COMPUTE_VERIFIED` | All structural checks, canonical commitments, RFC 8032 Ed25519 signature, challenge derivation, constitutional guards, and all $k$ Freivalds rounds passed. |
| `COMPUTE_CORRUPTED` | Transcript commitments, header digest, and provider signature are structurally valid, **and** at least one Freivalds check failed ($A(Br_t) \not\equiv C r_t \pmod p$), proving with certainty ($0\%$ false rejection on honest integer products) that $C \neq A \cdot B$. |
| `INVALID_TRANSCRIPT` | Structural, version, modulus, dimension, commitment, trace-root, header-digest, challenge-seed, or Ed25519 signature verification failed before or independently of matrix arithmetic. |
| `POLICY_REJECTED` | Transcript violated a constitutional guard (e.g., attempted forbidden autonomous governance action `redefine_voting_rules`, `authorize_treasury`, `self_declare_valid`, or attempted to set semantic/full-model proof flags to `true`). |

### 1.2 Hard-Enforced Constitutional Separation

In alignment with `zoo-poai-consensus/sections/25-receipt-soundness.tex` (*Objective, not semantic*) and the Zoo x Hanzo open research governance policy, every `poai-transcript.v1` receipt MUST carry the following schema-locked boolean invariants:

- `proves_matrix_product_only = true`
- `proves_full_model_inference = false` (schema `"const": false`)
- `proves_scientific_truth = false` (schema `"const": false`)
- `proves_weight_provenance = false` (schema `"const": false`)

Freivalds verification checks **only** the algebraic identity $C = A \cdot B$ over the committed integer operands $A, B, C$. It **never** certifies:
1. that an entire neural-network forward/backward pass executed faithfully,
2. that non-linear layers (RMSNorm, LayerNorm, SiLU/GELU, Softmax, RoPE, argmax) executed correctly,
3. that weights $A$ belong to a specific model checkpoint without an external weight-lineage commitment,
4. that the model's output is scientifically valid, aligned, or truthful, or
5. that any autonomous AI agent may redefine voting rules, authorize treasury spending, or declare its own experiments valid.

Any transcript requesting `requested_governance_action` in `{"redefine_voting_rules", "authorize_treasury", "self_declare_valid"}` MUST be rejected with `POLICY_REJECTED` and `ERR_FORBIDDEN_GOVERNANCE_ACTION`.

---

## 2. Deterministic Integer Arithmetic and Prime Field $\mathbb{F}_p$

### 2.1 Kernel Profile `int8-whole-k-i32-fp2147483647.v1`

- **Input Operands**:
  - $A \in \{-128, \dots, 127\}^{m \times d}$ (signed 8-bit integers, row-major)
  - $B \in \{-128, \dots, 127\}^{d \times n}$ (signed 8-bit integers, row-major)
- **Exact Whole-$K$ Integer Matrix Product**:
  $$C_{i,j} = \sum_{t=0}^{d-1} A_{i,t} \cdot B_{t,j} \in \mathbb{Z}$$
  computed with exact integer accumulation (no intermediate floating-point scaling or rounding). Because integer addition is associative, $C$ is bit-identical across every CPU and GPU architecture.
- **Dimension Bounds**: $1 \le m, d, n \le 65{,}536$.
- **Exact Non-Wraparound Guarantee**: For $d \le 65{,}536$ and $|A_{i,t}|, |B_{t,j}| \le 128$,
  $$|C_{i,j}| \le d \cdot 128^2 \le 1{,}073{,}741{,}824 = 2^{30} < \frac{p - 1}{2}$$
  for the Mersenne prime modulus:
  $$p = 2^{31} - 1 = 2{,}147{,}483{,}647.$$
  Hence every honest product entry maps injectively into $\mathbb{F}_p$, and no honest accumulation can ever wrap modulo $p$ or overflow signed `int32`/`int64`.
- **Zero-Overflow `int64` Field Arithmetic**: For any $u, v \in [0, p-1]$ and accumulator $a \in [0, p-1]$,
  $$a + u \cdot v \le (p - 1) + (p - 1)^2 = p(p - 1) < 2^{62} < 2^{63} - 1.$$
  Therefore modular multiply-accumulate `(acc + u*v) % p` NEVER overflows signed 64-bit integers (`int64` in Go, arbitrary-precision `int` in Python).
- **Canonical Representative**: For any signed integer $x \in \mathbb{Z}$,
  $$\mathrm{mod}_p(x) = ((x \bmod p) + p) \bmod p \in [0, p-1].$$

---

## 3. Canonical Binary Encodings and Cryptographic Commitments

All multi-byte integers in canonical encodings are **little-endian**. All hashes use **SHA-256** (FIPS 180-4) encoded as 64 lowercase hexadecimal characters in JSON.

### 3.1 Canonical Flat Matrix Encoding (`enc_matrix`)

For matrix $X$ of shape $(\text{rows}, \text{cols})$ and role byte $\rho \in \{\text{'A'}, \text{'B'}, \text{'C'}\}$:

- Width byte $w = 1$ for roles `'A'`, `'B'` (signed `int8`, 1 byte per element).
- Width byte $w = 8$ for role `'C'` (signed `int64_le`, 8 bytes per element).

$$\mathrm{enc\_matrix}(X, \rho) = \text{"poai:v1:mat:"} \,\|\, \rho \,\|\, w \,\|\, \mathrm{u32_{le}}(\text{rows}) \,\|\, \mathrm{u32_{le}}(\text{cols}) \,\|\, \text{row\_major\_bytes}(X)$$

$$\text{matrix\_}X\text{\_sha256} = \mathrm{SHA256}(\mathrm{enc\_matrix}(X, \rho))$$

### 3.2 Canonical Row Merkle Commitment (`matrix_X_root`)

For each row $0 \le i < \text{rows}$:
$$L_i = \mathrm{SHA256}\bigl(\text{"poai:v1:row:"} \,\|\, \rho \,\|\, \mathrm{u32_{le}}(i) \,\|\, \mathrm{u32_{le}}(\text{cols}) \,\|\, \text{row\_bytes}(X_i)\bigr)$$

Internal binary Merkle nodes combine pairs `(left, right)`:
$$N = \mathrm{SHA256}(\text{"poai:v1:node:"} \,\|\, \text{left} \,\|\, \text{right})$$
If a level has an odd number of nodes, the last node is duplicated (`right = left`).

### 3.3 Activation Trace Root

$$\text{activation\_trace\_root} = \mathrm{SHA256}\bigl(\text{"poai:v1:trace:"} \,\|\, \text{raw32}(\text{matrix\_a\_root}) \,\|\, \text{raw32}(\text{matrix\_b\_root}) \,\|\, \text{raw32}(\text{matrix\_c\_root})\bigr)$$

### 3.4 Canonical Header Serialization & Ed25519 Signature

Define length-prefixed UTF-8 encoding $\mathrm{lp}(s) = \mathrm{u32_{le}}(\mathrm{len}(s)) \,\|\, \mathrm{utf8}(s)$.
The canonical header byte stream $H_{\text{bytes}}$ is the exact concatenation:

1. Domain prefix: `"poai:v1:header:"` (15 bytes)
2. $\mathrm{lp}(\text{schema\_version})$
3. $\mathrm{lp}(\text{spec\_version})$
4. $\mathrm{lp}(\text{job\_id})$
5. $\mathrm{u64_{le}}(\text{policy\_epoch})$
6. $\mathrm{lp}(\text{kernel\_profile})$
7. $\mathrm{lp}(\text{model\_id})$
8. $\mathrm{u32_{le}}(\text{layer\_index})$
9. $\mathrm{u32_{le}}(m) \,\|\, \mathrm{u32_{le}}(d) \,\|\, \mathrm{u32_{le}}(n)$
10. $\mathrm{u64_{le}}(\text{field\_modulus})$
11. $\mathrm{lp}(\text{challenge\_mode})$
12. $\mathrm{lp}(\text{challenge\_source})$
13. $\mathrm{u32_{le}}(\text{challenge\_rounds\_k})$
14. $\mathrm{lp}(\text{verifier\_nonce\_hex})$
15. $\mathrm{lp}(\text{prover\_salt\_hex})$
16. Raw 32-byte digests in order:
    `matrix_a_root`, `matrix_b_root`, `matrix_c_root`, `matrix_a_sha256`, `matrix_b_sha256`, `matrix_c_sha256`, `activation_trace_root`, `corpus_manifest_sha256`
17. Raw 32-byte `provider_pubkey`
18. Canonical `semantic_metadata` block (1 presence byte `0x00`/`0x01`; if `0x01`: $\mathrm{lp}(\text{claimed\_model\_purpose})$, $\mathrm{lp}(\text{claimed\_truth\_statement})$, 1 byte `weights_attested`, 1 byte `nonlinearities_verified`, $\mathrm{lp}(\text{requested\_governance\_action})$).

Then:
- $\text{header\_digest} = \mathrm{SHA256}(H_{\text{bytes}})$
- $\text{transcript\_id} = \mathrm{hex}(\text{header\_digest})$
- $\text{signature} = \mathrm{Ed25519.Sign}(\text{sk}_{\text{provider}}, \text{header\_digest})$ (RFC 8032 over the 32-byte `header_digest`).

---

## 4. Freivalds Challenge Derivation & Verification

### 4.1 Challenge Seed Derivation (External Nonce vs. Fiat-Shamir)

- **External Verifier Nonce (`external_verifier_nonce`, RECOMMENDED)**:
  Requires a 32-byte verifier-supplied `verifier_nonce_hex` revealed **after** the prover commits to `matrix_c_root` and `header_digest`:
  $$\text{challenge\_seed} = \mathrm{SHA256}\bigl(\text{"poai:v1:challenge:external:"} \,\|\, \text{header\_digest} \,\|\, \text{raw32}(\text{verifier\_nonce})\bigr)$$
- **Non-Interactive Fiat-Shamir (`fiat_shamir`)**:
  $$\text{challenge\_seed} = \mathrm{SHA256}\bigl(\text{"poai:v1:challenge:fiat-shamir:"} \,\|\, \text{header\_digest} \,\|\, \text{raw}(\text{prover\_salt})\bigr)$$
  **Grinding Risk Policy**: If `challenge_source == "fiat_shamir"` and the single-transcript false-accept bound exceeds $2^{-40}$ (i.e., `binary_01` with $k < 40$, or `field_fp` with $k < 2$), the verifier MUST set `grinding_risk_warning = true` and record `ERR_WEAK_FIAT_SHAMIR_GRINDING_RISK` in `error_codes` (warning flag; does not alter `COMPUTE_VERIFIED` when $C = AB$, unless strict verifier policy escalates it).

### 4.2 Deterministic Round Vector PRG

For round $t \in \{0, 1, \dots, k-1\}$:
$$\text{round\_seed}_t = \mathrm{SHA256}\bigl(\text{"poai:v1:round:"} \,\|\, \text{challenge\_seed} \,\|\, \mathrm{u32_{le}}(t)\bigr)$$
Counter-mode blocks for $b = 0, 1, 2, \dots$:
$$\text{block}_{t,b} = \mathrm{SHA256}\bigl(\text{round\_seed}_t \,\|\, \mathrm{u32_{le}}(b)\bigr)$$

- **Mode `binary_01`**:
  For $0 \le j < n$, $r_t[j] = (\text{stream}[\lfloor j/8 \rfloor] \gg (j \bmod 8)) \mathbin{\&} 1 \in \{0, 1\}$.
- **Mode `field_fp`**:
  Read consecutive `uint32_le` words $w$ from $\text{stream}$, compute $v = w \mathbin{\&} \texttt{0x7FFFFFFF}$. If $v = p = \texttt{0x7FFFFFFF}$, reject $v$ and read the next word; otherwise set $r_t[j] = v \in [0, p-1]$.

### 4.3 Algebraic Check and Soundness Bounds

For each round $t = 0, \dots, k-1$, compute in $\mathbb{F}_p$:
$$y_t = B \cdot r_t \pmod p \in \mathbb{F}_p^d, \qquad u_t = A \cdot y_t \pmod p \in \mathbb{F}_p^m, \qquad v_t = C \cdot r_t \pmod p \in \mathbb{F}_p^m.$$
Round $t$ matches iff $u_t = v_t$ entrywise. Total verification work is $O(k \cdot (mn + md + dn)) = O(k n^2)$ vs. $O(m d n) = O(n^3)$ for full recomputation.

| Challenge Mode | Vector Domain | False-Rejection Rate (Honest $C=AB$) | False-Accept Soundness Bound (Corrupted $C \neq AB$) |
|---|---|---|---|
| `binary_01` | $r_t \in \{0, 1\}^n$ | $0$ (exact) | $\le 2^{-k}$ |
| `field_fp` | $r_t \in \mathbb{F}_p^n$, $p = 2^{31}-1$ | $0$ (exact) | $\le p^{-k} = (2^{31}-1)^{-k}$ ($4.66 \times 10^{-10}$ at $k=1$; $2.17 \times 10^{-19}$ at $k=2$) |

### 4.4 Canonical Vector & Audit Merkle Digests

For any length-$\ell$ vector $z$ of canonical field elements in $[0, p-1]$:
$$\mathrm{vec\_sha256}(z) = \mathrm{SHA256}\bigl(\text{"poai:v1:vec:"} \,\|\, \mathrm{u32_{le}}(\ell) \,\|\, \mathrm{i64_{le}}(z_0) \,\|\, \dots \,\|\, \mathrm{i64_{le}}(z_{\ell-1})\bigr)$$

For a suite of ordered verification receipts $R_0, \dots, R_{N-1}$, each leaf is:
$$\text{leaf}_i = \mathrm{SHA256}\bigl(\text{"poai:v1:receipt:"} \,\|\, \text{transcript\_id} \,\|\, \text{"|"} \,\|\, \text{compute\_verdict} \,\|\, \text{"|"} \,\|\, \mathrm{join}(\text{error\_codes}, \text{","}) \,\|\, \text{"|"} \,\|\, \text{header\_digest\_hex} \,\|\, \text{"|"} \,\|\, \text{challenge\_seed\_hex} \,\|\, \text{"|"} \,\|\, \mathrm{str}(\text{first\_failing\_round})\bigr)$$
combined with the `"poai:v1:node:"` binary Merkle tree to produce `audit_merkle_root`.

---

## 5. What Remains Unproven (Normative Proof Limits)

Even when a `poai-transcript.v1` receipt passes with `COMPUTE_VERIFIED` under `external_verifier_nonce` and `field_fp` ($k \ge 2$):

1. **IEEE-754 / BF16 / FP16 GPU Non-Associativity**: Real CUDA/Metal tensor cores running FP16/BF16 or block-scaled float kernels (`f8q8`) are non-associative across hardware and reduction orders. Exact Freivalds applies ONLY to pinned whole-$K$ integer accumulation; floating-point tolerance bands cannot be retrofitted without opening adversarial drift attacks.
2. **Non-Linear & Attention Layers**: RMSNorm, LayerNorm, SiLU/GELU, Softmax, RoPE, token sampling/argmax, and MoE routing are NOT matrix multiplications and are NOT covered by a single-GEMM Freivalds transcript; they require deterministic commit-and-recompute over the full `GraphTrace`.
3. **Model Weight & Checkpoint Provenance**: Proving $C = A \cdot B$ proves nothing about whether $A$ is the authentic weight tensor of a published model checkpoint unless `matrix_a_root` is independently verified against an on-chain/signed `modelWeightsRoot` registry.
4. **KV-Cache Continuity & Multi-Token State**: A single-layer GEMM transcript does not prove that KV-cache tensors carried across autoregressive decode steps were uncorrupted or derived from the committed prompt prefix.
5. **Scientific Value, Alignment, and Truthfulness**: A syntactically and algebraically valid `COMPUTE_VERIFIED` transcript can be produced by a backdoored, lobotomized, or factually wrong model. Semantic truth and scientific merit require independent evidence verification (see `zoo-apps/papers#8`, HIP-1352) and authorized human/governance review.
6. **Full Succinct Zero-Knowledge Soundness (zkML)**: Freivalds requires the verifier to have read access to $A, B, C$ (to compute $A(Br)$ and $Cr$ in $O(k n^2)$) and is neither zero-knowledge nor sublinear in matrix size; privacy-preserving or sublinear verification requires SNARK/STARK/sumcheck protocols (L5 zk tier).

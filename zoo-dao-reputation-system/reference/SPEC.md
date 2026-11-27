# Scientific Contribution Attribution and Reputation Specification (`attribution-rep.v1`)

- **Schema Version**: `attribution-rep.v1`
- **Specification Version**: `1.0.0`
- **HIP Reference**: HIP-1352 (`zoo-apps/papers#11`)
- **Paper Grounding**: Zoo DAO Ecosystem Reputation System (`zoo-dao-reputation-system/zoo-dao-reputation-system.tex`, ZIP-0026)
- **Attestation Compatibility**: Ethereum Attestation Service (`AttestationUID`, `schema_uid`, `attester`, `recipient`, `ref_uid`, `revocable`, `expiration_time`)
- **License**: Apache-2.0

---

## 1. Objective & Acceptance Criterion

Attribute reusable scientific contributions without double-counting copied work or letting colluding identities manufacture reputation. All verification arithmetic is specified in **exact fixed-point 64-bit integer arithmetic** (`MicroScale = 1,000,000`, `BpsScale = 10,000`) with zero floating-point drift, guaranteeing **100.0% bit-identical cross-language determinism** across independent Go and pure-Python verifiers.

---

## 2. Canonical Hashing, Signing, and Fixed-Point Arithmetic

### 2.1 Canonical JSON
Every signed or hashed structured payload uses compact UTF-8 JSON with lexicographically sorted ASCII object keys, no insignificant whitespace, and no HTML escaping (`<`, `>`, `&` preserved literally).

### 2.2 Domain-Separated SHA-256 Digests
All hashes are lowercase 64-character hexadecimal SHA-256 strings with explicit null-terminated domain prefixes:

| Artifact | Domain Prefix | Payload |
|---|---|---|
| Raw content | *(none)* | Raw UTF-8 contribution bytes |
| Canonical text | `zoo.attrrep.v1.canonical\x00` | Space-joined normalized tokens |
| Word 4-shingle | `zoo.attrrep.v1.shingle\x00` | 4 consecutive tokens joined by `" "` (first 8 bytes big-endian `uint64`) |
| Winnowing fingerprint | `zoo.attrrep.v1.winnow\x00` | Concatenated big-endian `uint64` sorted fingerprint hashes |
| Contribution signature | `zoo.attrrep.v1.contrib.sig\x00` | Canonical JSON of contribution metadata |
| EAS `AttestationUID` | `zoo.attrrep.v1.eas.uid\x00` | Canonical JSON of EAS struct fields (prefixed with `0x`) |
| EAS attestation signature | `zoo.attrrep.v1.eas.sig\x00` | Canonical JSON of `(uid, schema_uid, attester, recipient, ref_uid, epoch, nonce, weight_bps)` |

### 2.3 Signatures
All contributions and EAS attestations MUST carry a valid **RFC 8032 Ed25519** signature under the registered public key of the author or attester. Verifiers MUST enforce canonical scalar bounds ($S < L$) and cofactor-cleared curve verification.

---

## 3. Content-Addressed Scientific Contribution DAG

### 3.1 Text Normalization & Winnowing Fingerprinting
To resist whitespace, LaTeX-comment, and formatting-macro obfuscation:
1. Strip all unescaped LaTeX `%` line comments to end-of-line.
2. Remove metadata/layout commands and their optional `[...]` and mandatory `{...}` arguments: `\label`, `\ref`, `\eqref`, `\cite`, `\citep`, `\citet`, `\usepackage`, `\documentclass`, `\bibliographystyle`, `\bibliography`, `\vspace`, `\hspace`, `\begin`, `\end`.
3. Strip remaining LaTeX command names (`\[a-zA-Z]+\*?`) while preserving inner prose arguments (e.g., `\textbf{word}` -> `word`).
4. Lowercase ASCII `A-Z`, retain `[a-z0-9]` token runs, and split on all other bytes.
5. Form word $k$-shingles ($k = 4$), hash each to `uint64`, and apply **robust Winnowing** (Schleimer, Wilkerson, Aiken 2003) with window $w = 3$ selecting the rightmost minimum per window. Deduplicate and sort ascending to produce `winnow_fingerprint`.

### 3.2 Causality, Ordering, and Acyclicity
Contributions are evaluated in deterministic append-only order `(ledger_seq, contribution_id)`. Before sequential evaluation, Kahn's topological peeling identifies all nodes participating in or blocked by directed cycles (including self-loops) and rejects them with `ERR_CAUSALITY_CYCLE`.

Every contribution MUST satisfy:
- `timestamp >= max_accepted_timestamp - max_clock_skew_sec` (default `300s`), else `ERR_TIMESTAMP_BACKDATE`.
- Every declared parent `p` in `parents` MUST exist, be previously accepted (`p.ledger_seq < c.ledger_seq`), and satisfy `p.timestamp <= c.timestamp` and `p.epoch <= c.epoch`, else `ERR_UNKNOWN_PARENT` or `ERR_TIMESTAMP_BACKDATE`.

### 3.3 Anti-Copy / Anti-Double-Counting Rules
Against all previously accepted canonical contributions:
1. **Exact verbatim duplicate** (`raw_sha256` already committed): REJECT with `ERR_DUPLICATE_CONTRIBUTION`; redirect `canonical_origin_id` to first-seen canonical artifact; mint `0` credit.
2. **Reformatted / comment / LaTeX-macro copy** (`canonical_digest` already committed): REJECT with `ERR_REFORMATTED_COPY`; redirect `canonical_origin_id` to first-seen canonical artifact; mint `0` credit.
3. **Near-duplicate / patch-plagiarism**: compute pairwise Winnowing containment against every earlier accepted contribution $u$:
   $$\text{containment\_bps}(c, u) = \left\lfloor \frac{|W(c) \cap W(u)| \times 10000}{|W(c)|} \right\rfloor$$
   and global incremental novelty against the union of all earlier fingerprints $U_{\prec c} = \bigcup_{u \prec c} W(u)$:
   $$\text{novelty\_bps}(c) = 10000 - \left\lfloor \frac{|W(c) \cap U_{\prec c}| \times 10000}{|W(c)|} \right\rfloor$$
   - If `best_overlap_bps >= near_duplicate_reject_bps` (`8000` bps = `80.0%`): REJECT with `ERR_NEAR_DUPLICATE_COPY`.
   - If `best_overlap_bps >= undeclared_copy_reject_bps` (`5000` bps = `50.0%`) and `best_match_id` is NOT in `c.parents`: REJECT with `ERR_UNDECLARED_COPY`.
   - If `claimed_novelty_bps > 0`, `best_overlap_bps >= 6500`, and `claimed_novelty_bps - novelty_bps > novelty_overclaim_gap_bps` (`2500` bps): REJECT with `ERR_NEAR_DUPLICATE_COPY`.

### 3.4 Exact Credit Conservation & Upstream Citation Flow
For each accepted contribution $c$ with base value $B(c)$ (micro-credits):
$$\text{intrinsic}(c) = \left\lfloor \frac{B(c) \times \text{novelty\_bps}(c)}{10000} \right\rfloor$$
- If $c$ has no parents: `self_credit(c) = intrinsic(c)`, `upstream_flow(c) = 0`.
- If $c$ has valid canonical parents $P(c)$:
  $$\text{upstream\_flow}(c) = \left\lfloor \frac{\text{intrinsic}(c) \times \text{upstream\_flow\_bps}}{10000} \right\rfloor, \quad \text{self\_credit}(c) = \text{intrinsic}(c) - \text{upstream\_flow}(c)$$
  `upstream_flow(c)` is partitioned across $p \in P(c)$ proportional to $w_p = \text{containment\_bps}(c, p) + 1000$, with any integer remainder ($< |P(c)|$ micro-credits) assigned to the highest-weight parent (tie-broken lexicographically by `contribution_id`).

**Conservation Invariant**:
$$\sum_{a \in \text{Identities}} \text{AttributionMicro}(a) \equiv \sum_{c \in \text{Accepted}} \text{intrinsic}(c)$$
holds with **zero** rounding drift and **zero** double-counting.

---

## 4. EAS-Compatible Attestations & Constitutional AI-Role Guards

### 4.1 EAS Attestation Validation
Attestations are processed in canonical order `(epoch, time, attester, nonce, uid)` and checked for:
1. Identity existence (`ERR_UNKNOWN_IDENTITY`)
2. Recomputed `AttestationUID == uid` (`ERR_ATTESTATION_UID_MISMATCH`)
3. Valid RFC 8032 Ed25519 signature (`ERR_INVALID_SIGNATURE`)
4. **Constitutional AI-Role Guards** (when `attester.role == "AI_AGENT"`):
   - `SCHEMA_POLICY_MUTATION` -> REJECT with `ERR_AI_POLICY_MUTATION_FORBIDDEN`
   - `SCHEMA_TREASURY_AUTH` -> REJECT with `ERR_AI_TREASURY_FORBIDDEN`
   - `attester == recipient` OR `accepted[ref_uid].author_id == attester` -> REJECT with `ERR_AI_SELF_ATTEST_FORBIDDEN`
   - `SCHEMA_SIMILARITY_FLAG` -> permitted as `ADVISORY` with `effective_weight_bps = 0` (diagnostics only; zero reputation minting)
5. Self-attestation loop (`attester == recipient`) -> `ERR_SELF_ATTESTATION`
6. Revocation (`revoked == true` or `uid in revoked_uids`) -> `ERR_REVOKED_ATTESTATION`
7. Expiration (`expiration_time > 0 && expiration_time < eval_time`) -> `ERR_EXPIRED_ATTESTATION`
8. Replay protection: duplicate `uid`, duplicate `(attester, nonce)`, or duplicate `(attester, ref_uid, schema_uid)` across epochs -> `ERR_ATTESTATION_REPLAY`
9. Reference acceptance: `ref_uid` MUST reference an `ACCEPTED` contribution -> `ERR_REF_NOT_ACCEPTED`
10. Per-issuer per-epoch rate limit (ZIP-0026 §5.2) -> `ERR_ISSUER_RATE_LIMIT`

---

## 5. Sybil-Resistant Seeded Reputation

### 5.1 Collusion Ring Collapse (Tarjan SCC)
Run deterministic Tarjan strongly connected component decomposition on the valid directed attestation graph. For any unseeded SCC $C$ ($|C| \ge 2$, $C \cap P = \emptyset$) where internal edges exceed external incoming edges:
- Emit `ERR_COLLUSION_RING_DISCOUNTED`.
- If `external_in == 0` (isolated ring/pair), collapse internal edges to `0` bps; otherwise discount by `ring_discount_bps` (`500` bps) or `reciprocal_discount_bps` (`2500` bps).
- Any unseeded reciprocal edge pair ($u \to v$ and $v \to u$) receives at least `reciprocal_discount_bps`.

### 5.2 Pairwise Target-Cluster Capping (Sybil Farm Defense)
Compute target-set Jaccard similarity between all unseeded attester pairs and merge pairs with similarity $\ge 8000$ bps via deterministic Union-Find. For any cluster $K$ of size $|K| \ge 3$ with zero incoming seed edges:
- Emit `ERR_SYBIL_CLUSTER_CAPPED`.
- Cap each member's edge multiplier to $\lfloor \text{cluster\_penalty\_bps} / |K| \rfloor$.

### 5.3 Sub-Stochastic Seeded EigenTrust (Exact Fixed-Point)
Let $w'_{uv}$ be the discounted effective weight and $R_u = \sum_v w_{uv}$ be the **pre-discount** raw outgoing total for attester $u$. Define the sub-stochastic transition matrix:
$$C_{uv} = \left\lfloor \frac{w'_{uv} \times 10^6}{R_u} \right\rfloor, \qquad \text{leak}_u = 10^6 - \sum_v C_{uv}$$
Dividing by $R_u$ rather than $\sum_v w'_{uv}$ prevents discounted Sybil/collusion edges from renormalizing back to `100%`; discounted trust mass leaks deterministically to the uniform pre-trusted seed vector $p$ over `SEED_STEWARD` identities. Run $T = 40$ iterations with damping $\alpha = 8500$ bps (`0.85`):
$$t^{(k+1)}_v = \left\lfloor \frac{(10000 - \alpha) p_v}{10000} \right\rfloor + \left\lfloor \frac{\alpha \left(\sum_u \lfloor t^{(k)}_u C_{uv} / 10^6 \rfloor + \lfloor D^{(k)} p_v / 10^6 \rfloor \right)}{10000} \right\rfloor$$

### 5.4 Trust-Gated ZooRep Score & ZIP-0026 Tier Mapping
$$\text{gate\_bps}(a) = \min\!\left(10000,\; \left\lfloor \frac{t^{(T)}_a \times 10000}{\text{trust\_full\_gate\_micro}} \right\rfloor\right)$$
$$\text{RepMicro}(a) = t^{(T)}_a \cdot 5000 + \left\lfloor \frac{\text{AttributionMicro}(a) \cdot \text{gate\_bps}(a)}{10000} \right\rfloor \cdot 50, \qquad \text{ZooRep}(a) = \left\lfloor \frac{\text{RepMicro}(a)}{10^6} \right\rfloor$$

ZIP-0026 tiers (`zoo-dao-reputation-system.tex`, Table 2):
- `Observer`: `0-49` pts (`1.0x`, `100` bps)
- `Contributor`: `50-199` pts (`1.2x`, `120` bps)
- `Steward`: `200-499` pts (`1.5x`, `150` bps)
- `Guardian`: `500-999` pts (`2.0x`, `200` bps)
- `Elder`: `1000+` pts (`2.5x`, `250` bps)

---

## 6. Normative Error Codes

| Error Code | Layer | Trigger Condition |
|---|---|---|
| `ERR_UNKNOWN_IDENTITY` | Identity | Author, attester, or recipient not registered |
| `ERR_INVALID_SIGNATURE` | Crypto | RFC 8032 Ed25519 verification failed |
| `ERR_CONTENT_DIGEST_MISMATCH` | Integrity | `raw_sha256` or `canonical_digest` mismatches content |
| `ERR_FINGERPRINT_MISMATCH` | Integrity | `winnow_fingerprint` or `fingerprint_digest` mismatches content |
| `ERR_DUPLICATE_CONTRIBUTION` | Anti-Copy | Exact verbatim `raw_sha256` copy of earlier artifact |
| `ERR_REFORMATTED_COPY` | Anti-Copy | Whitespace/comment/LaTeX-macro reformatted copy (`canonical_digest` match) |
| `ERR_NEAR_DUPLICATE_COPY` | Anti-Copy | Winnowing overlap `>= 80%` or blatant novelty overclaim on `>= 65%` overlap |
| `ERR_UNDECLARED_COPY` | Anti-Copy | Winnowing overlap `>= 50%` omitting matched canonical ancestor from `parents` |
| `ERR_CAUSALITY_CYCLE` | DAG | Directed parent-child cycle or self-loop detected via Kahn peeling |
| `ERR_TIMESTAMP_BACKDATE` | DAG | Timestamp predates ledger tip (beyond skew) or predates cited parent |
| `ERR_UNKNOWN_PARENT` | DAG | Declared parent missing or previously rejected |
| `ERR_ATTESTATION_UID_MISMATCH` | EAS | Recomputed `AttestationUID` != claimed `uid` |
| `ERR_SELF_ATTESTATION` | Anti-Collusion | `attester == recipient` |
| `ERR_REVOKED_ATTESTATION` | EAS | `revoked == true` or `uid` in `revoked_uids` |
| `ERR_EXPIRED_ATTESTATION` | EAS | `expiration_time > 0` and `< eval_time` |
| `ERR_ATTESTATION_REPLAY` | EAS | Duplicate `uid`, reused `(attester, nonce)`, or cross-epoch `(attester, ref_uid, schema)` replay |
| `ERR_REF_NOT_ACCEPTED` | EAS | Attestation references missing or rejected (e.g., plagiarized) contribution |
| `ERR_ISSUER_RATE_LIMIT` | Anti-Gaming | Attester exceeded `max_attestations_per_epoch` (ZIP-0026 §5.2) |
| `ERR_AI_SELF_ATTEST_FORBIDDEN` | AI Guard | `AI_AGENT` attempted direct or own-artifact self-attestation |
| `ERR_AI_POLICY_MUTATION_FORBIDDEN` | AI Guard | `AI_AGENT` attempted to approve reputation rule mutation |
| `ERR_AI_TREASURY_FORBIDDEN` | AI Guard | `AI_AGENT` attempted to authorize treasury rewards |
| `ERR_COLLUSION_RING_DISCOUNTED` | Anti-Collusion | Unseeded inward-facing SCC (2-node pair or $k$-node ring) discounted/collapsed |
| `ERR_SYBIL_CLUSTER_CAPPED` | Anti-Collusion | Unseeded correlated attester cluster ($|K| \ge 3$, Jaccard $\ge 80\%$) capped |

---

## 7. Audit Merkle Root

Every verification run emits `audit_merkle_root`: an RFC 6962-style binary SHA-256 Merkle root (`0x00` leaf prefix, `0x01` interior node prefix, odd trailing node promoted) over the canonically sorted JSON records of all contribution verdicts, attestation verdicts, collusion findings, and final identity summaries.

---

## 8. What Remains Unproven

To preserve scientific honesty, the following attack classes and socio-technical properties are **explicitly outside what `attribution-rep.v1` proves**:

1. **Cross-Language & Deep Semantic Plagiarism**: Deterministic 4-word Winnowing detects verbatim copies, LaTeX/whitespace/comment reformatting, and lexical/structural patch plagiarism, but does **not** detect full cross-language translation (e.g., English -> Mandarin -> English back-translation) or complete sentence-by-sentence semantic rewriting that replaces >80% of 4-grams while preserving the underlying proof idea.
2. **Off-Chain Real-World Sybil Identity Prevention**: Seeded EigenTrust bounds Sybil farm trust gain strictly through the seed-connected attack edges; it does **not** prove uniqueness of human beings behind pseudonymous Ed25519 keys without external Proof-of-Personhood (PoP), institutional credentialing, or slashing-backed economic stake.
3. **Long-Horizon Citation Cartels & Seed Compromise**: If a majority of `SEED_STEWARD` keys collude or are compromised simultaneously, or if sophisticated multi-year citation cartels slowly cultivate genuine publications to earn high trust before selectively endorsing mediocre confederates ("sleeper Sybils"), graph topology alone cannot distinguish coordinated preference from legitimate domain specialization; governance-level seed rotation, multi-issuer thresholds, and Ethics Committee slashing (ZIP-0026 §5.4) remain necessary.
4. **Cold-Start Onboarding Friction**: As quantified explicitly in `neg_honest_newcomer_cold_start_lag`, strict seeded trust gating imposes a temporary reputation lag (`0` ZooRep until `>= 1` independent seeded replication attestation) on honest newcomers lacking prior trust edges, even though their content attribution credit is preserved immediately.

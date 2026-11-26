# Decentralized Semantic Optimization (DSO) Byzantine-Robust Aggregation Specification

- **Schema Version**: `dso-aggregation.v1`
- **Issue**: `zoo-apps/papers#9` (`HIP-1352` — Byzantine-robust DSO aggregation)
- **Grounded Papers**:
  - `experience-ledger-dso/experience-ledger-dso.tex` (Experience Ledger, Semantic Advantage format, DAO curation & Theorem 2 Byzantine tolerance)
  - `zoo-ai-research-agenda/zoo-ai-research-agenda.tex` (Cross-Thrust Safety Monotonicity Theorem 4.1, Conservation alignment, BitDelta/DeltaSoup)
  - `zoo-bitdelta-deltasoup/zoo-bitdelta-deltasoup.tex` (Byzantine-robust trimmed-mean adapter aggregation & proportional attribution)
- **JSON Schema**: [`schema/dso-aggregation.v1.schema.json`](schema/dso-aggregation.v1.schema.json)
- **License**: Apache-2.0 (`SPDX-License-Identifier: Apache-2.0`)

---

## 1. Scope & Contribution Model

In Zoo's Decentralized Semantic Optimization (DSO) architecture, $N$ distributed participants ($N = 30$ in the standard benchmark) submit round-$t$ updates that combine:

1. **Semantic Advantage Experience Operation (`ExperienceOp`)** matching `experience-ledger-dso` Sections 3 & 7:
   - `id`: content-addressed identifier `exp_sha256_<16hex>`
   - `op`: `"Add" | "Modify" | "Delete"`
   - `domain`: `"protocol_governance" | "conservation_science"`
   - `text`: natural-language reasoning rule ($\le 32$ words, actionable `"When ..."` / `"For ..."` / `"... implies ..."` syntax)
   - `confidence_micro`: claimed confidence in fixed-point micro-units $[0, 10^6]$
   - `paper_path`, `paper_sha256`: content anchor to a grounded `.tex` source document in `zoo-apps/papers`
2. **Structured Policy / Adapter Delta (`delta_micro`)**:
   - A $D = 64$-dimensional fixed-point micro-unit ($10^{-6}$) parameter update $\Delta w_i \in \mathbb{R}^{64}$ over a deterministic semantic preference feature space grounded directly in cleaned paragraphs from the 88 real `.tex` papers in `zoo-apps/papers`:
     - `[0..27]` (28 dims): hashed unigram/bigram subspace from `protocol_governance` papers (73 papers, 5,534 paragraphs)
     - `[28..55]` (28 dims): hashed unigram/bigram subspace from `conservation_science` papers (15 papers, 1,099 paragraphs)
     - `[56..61]` (6 dims): shared cross-domain DSO structural quality features (lexical diversity, length regularity, quantitative grounding, logical connectives, token specificity, checksum)
     - `[62..63]` (2 dims): niche unmonitored trigger subspace (strictly `0` in held-out validation sets, active only in the Negative Regime 2 unseen backdoor test suite)

Every contribution is wrapped in a `ContributionEnvelope` authenticated by **RFC 8032 Ed25519** over the domain-separated canonical byte sequence:

```
sign_input = "dso-aggregation.v1:" || canonical_json(ContributionBody)
digest_sha256 = SHA256(canonical_json(ContributionBody))
```

where `canonical_json` uses strictly sorted ASCII keys, zero whitespace, and integer micro-units (`1e-6`) for all vector coordinates so Go 1.24 and Python 3.12 produce **bit-identical** digests and signatures with zero external dependencies.

---

## 2. Threat Models & Legitimate Honest Disagreement

Every aggregation rule is evaluated head-to-head across $N = 30$ nodes, $T = 12$ rounds, and adversarial fractions $f \in \{0\%, 10\%, 20\%, 30\%, 40\%, 50\%\}$ under four mandatory regimes:

1. **`adversarial_semantic` (Adversarial Semantic Inputs)**:
   - Adversaries run genuine local logistic SGD on **label-flipped** real `.tex` trajectory preference pairs across both domains, preserve slight benign alignment on shared structural features `[56..61]`, and rescale their delta to match the exact honest L2 norm envelope (`1.15x` mean honest norm). Their `ExperienceOp` obeys the 32-word `"When ..."` syntax while injecting inverted guidance.
2. **`colluding_sybil_cartel` (Colluding Participants / Tight Sybil Cartel)**:
   - All $\lfloor f N \rceil$ adversaries coordinate on a single shared poisoned target vector with $\epsilon = 6\times 10^{-4}$ jitter ($\cos(\Delta w_i, \Delta w_j) > 0.999$), forming a dense low-distance cluster explicitly engineered to capture distance-based Multi-Krum and shift coordinate medians/trimmed means.
3. **`low_quality_noisy` (Noisy / Lazy Freeloaders)**:
   - Freeloading nodes avoid local optimization and submit high-variance zero-mean Gaussian noise ($\sigma = 0.42$ across active coordinates) paired with non-actionable vague experience text violating DSO Section 3 constraints.
4. **`honest_disagreement_noniid` (Legitimate Disagreement Among Honest Participants)**:
   - Honest contributors are split into **75% `protocol_governance` specialists** and **25% `conservation_science` specialists** training on **strictly disjoint** domain shards (0% cross-domain overlap). At $f = 0\%$, this isolates pure non-IID minority participation fairness; at $f \in \{10\%..50\%\}$, Byzantine nodes inject a 50/50 hybrid of tight cartel collusion and semantic poisoning.

---

## 3. Benchmarked Aggregation Rules

All 5 rules first verify RFC 8032 Ed25519 signatures and exclude any invalid/tampered envelopes before aggregation.

1. **`mean_baseline`**: Unweighted arithmetic mean $\Delta w = \frac{1}{m}\sum_{i \in V} \Delta w_i$; uniform attribution $a_i = 1/m$.
2. **`coord_median`**: Coordinate-wise median across valid submissions. Effective attribution $a_i$ measures the normalized fraction of contributor $i$'s active update energy aligning with the central median support band; a node is counted accepted iff $a_i \ge 0.5 / m$.
3. **`trimmed_mean`**: Coordinate-wise $\beta$-trimmed mean ($\beta = 0.25$, trimming the lowest and highest $\lfloor \beta m \rfloor$ values per coordinate). Effective attribution $a_i$ measures the normalized fraction of contributor $i$'s active update energy surviving trimming; accepted iff $a_i \ge 0.5 / m$.
4. **`multi_krum`** (Blanchard et al., 2017): Computes each candidate's sum of squared Euclidean distances to its $k_{\text{nn}} = m - f_{\max} - 2$ nearest neighbors ($f_{\max} = 9$ for standard $f < N/3$ BFT assumption) and averages the $m_{\text{sel}} = 15$ lowest-score candidates ($a_i = 1/m_{\text{sel}}$ if selected, $0$ otherwise).
5. **`dso_reputation_eval_gated`**:
   - **Gate 1 (Cryptographic & DSO Schema)**: Rejects invalid Ed25519 signatures, malformed `ExperienceOp` records ($>32$ words, non-actionable phrasing, missing paper anchor), and $\|\Delta w_i\|_2 > 5.0$.
   - **Gate 2 (Domain-Stratified Held-Out Evaluation + Cross-Domain Safety)**: Evaluates candidate probe $w^{(t)} + \eta \Delta w_i$ ($\eta = 0.5$) on the independent held-out validation shard of its claimed domain $\mathcal{V}_{d_i}$ and the complementary domain $\mathcal{V}_{d'}$:
     - Requires strictly positive domain marginal loss reduction $\Delta U_{d_i} = \mathcal{L}(w^{(t)}; \mathcal{V}_{d_i}) - \mathcal{L}(w^{(t)} + \eta\Delta w_i; \mathcal{V}_{d_i}) > \tau_{\min}$ ($\tau_{\min} = 5\times 10^{-4}$).
     - Enforces Cross-Domain Safety Monotonicity (`zoo-ai-research-agenda` Theorem 4.1): $\Delta U_{d'} \ge -\tau_{\text{safety}}$ ($\tau_{\text{safety}} = 8\times 10^{-3}$).
   - **Gate 3 (Sybil Collusion-Cluster Discounting)**: Among admitted updates, computes pairwise cosine cluster size $c_i = |\{j : \cos(\Delta w_i, \Delta w_j) \ge 0.97\}|$ (enforcing `experience-ledger-dso` Section 3 non-redundancy) and divides raw score by $c_i$: $s_i = R_i^{(t)} \sqrt{\max(\Delta U_{d_i}, 10^{-6})} / c_i$.
   - **Gate 4 (Domain-Balanced Minority-Preserving Attribution)**: Combines validated domain aggregates while enforcing a minority-domain floor (`0.35`) when both domains have admitted updates, preventing a 70–75% majority domain from drowning out validated minority specialists.
   - **Online Reputation Update**: Admitted contributors earn multiplicative reputation growth $R_i^{(t+1)} = \min(2.5, 1.08 R_i^{(t)} + 0.02)$; rejected contributors are slashed $R_i^{(t+1)} = \max(0.05, 0.55 R_i^{(t)})$.

---

## 4. Quality, Robustness, Participation Fairness & Overhead Metrics

For each cell `(scenario, adversary_fraction, aggregator)`:

- **Quality**:
  - `global_test_accuracy` & `global_test_loss`: evaluated on completely unseen balanced test shards $\mathcal{T} = \mathcal{T}_{\text{protocol}} \cup \mathcal{T}_{\text{conservation}}$ (240 pairs each; never used in training or validation).
  - `majority_test_accuracy` ($\mathcal{T}_{\text{protocol}}$) and `minority_test_accuracy` ($\mathcal{T}_{\text{conservation}}$).
- **Robustness**:
  - `adversarial_admission_rate`: mean fraction of adversarial submissions accepted per round.
  - `adversarial_weight_share`: mean round attribution mass $\sum_{i \in \text{Adv}} a_i$ captured by adversaries.
  - `attack_degradation_delta`: $\text{Acc}_{\text{clean\_ceiling}} - \text{Acc}_{\text{global}}$ (in percentage points).
- **Participation Fairness** (computed over honest contributors $H$ with cumulative accepted attribution weights $A_i = \sum_{t=1}^{T} a_i^{(t)}$):
  - `majority_honest_acceptance_rate` and `minority_honest_acceptance_rate`.
  - `fairness_ratio`: $\text{MinAcceptRate} / \max(\text{MajAcceptRate}, 10^{-9})$.
  - **Jain's Fairness Index**: $J(A) = \frac{(\sum_{i \in H} A_i)^2}{|H| \sum_{i \in H} A_i^2} \in [0, 1]$ ($1.0$ = equal attribution; $0.0$ = total erasure).
  - **Attribution Gini Coefficient**: $G(A) = \frac{\sum_{i \in H}\sum_{j \in H} |A_i - A_j|}{2|H|\sum_{i \in H} A_i} \in [0, 1]$ ($0.0$ = equal attribution; $1.0$ = total monopoly/erasure).
- **Verification Overhead**:
  - `verification_ms_per_round`: wall-clock milliseconds per round (including all 30 Ed25519 verifications + aggregation + held-out eval).
  - `payload_bytes_per_round`: canonical signed payload bytes verified per round.

---

## 5. Canonical Merkle Audit Roots & Cross-Language Verification

- **`audit_merkle_root`**: Domain-separated binary SHA-256 Merkle tree (`0x00 || leaf`, `0x01 || left || right`, odd-node duplication) over all 120 `CanonicalCellLeafHash` digests in `results.json` (excluding non-deterministic wall-clock `verification_ms_per_round`).
- **`trace_merkle_root`**: Binary SHA-256 Merkle tree over 5 exported signed round Merkle roots (`audit_trace.json`, 150 Ed25519-signed contributions, 25 aggregator executions).
- **Cross-Language Parity Requirement**: The independent Python 3.12 stdlib verifier MUST reproduce `audit_merkle_root` and `trace_merkle_root` bit-for-bit, verify all 150 Ed25519 signatures, match all 25 aggregator outputs within $\le 1$ micro-unit ($10^{-6}$) with exact boolean acceptance & cluster-size equality, and reject single-byte tampering.

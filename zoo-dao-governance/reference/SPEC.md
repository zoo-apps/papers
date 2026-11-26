# Zoo DAO Quadratic Funding & Sybil-Resistance Simulator Specification (`qf-simulator.v1`)

**Version**: `qf-simulator.v1`  
**License**: Apache-2.0  
**References**:
- `zoo-dao-governance/` (*Zoo DAO: Decentralized Governance for Open Science Research*, ZOO-GOV-2026)
- `zoo-dao-grants-program/` (*The Zoo Community Grants Program*, ZIP-0023)
- `zoo-dao-reputation-system/` (*Ecosystem Reputation: A Non-Transferable Trust Primitive for Conservation Contributors*, ZIP-0026)
- `zoo-voting-platform/` (*zoo.vote: Quadratic and Conviction Voting for Conservation Decisions*)
- HIP-1352 Governance & Reproducible Research Artifact Standard (`zoo-apps/papers#6`)

---

## 1. Exact Integer Micro-Unit Accounting

To guarantee **bit-identical** cross-language reproducibility across Go (`math/big`) and Python (`int`, `math.isqrt`) with zero floating-point drift, zero `NaN`, zero negative balances, and zero integer overflow, all monetary amounts, weights, and metrics use exact integer arithmetic:

| Constant | Value | Meaning |
| --- | --- | --- |
| `MicroZOO` | `1_000_000` ($10^6$) | `1 ZOO = 1,000,000 micro-ZOO` |
| `Scale` | `1_000_000` ($10^6$) | Fixed-point denominator for normalized roots & weights |
| `BPS` | `10_000` | Basis points (`10,000 = 100.00%`, `10,000 = 1.00x` ROI) |
| `DefaultMatchingPool` | `100_000 * MicroZOO` | $M_{\text{pool}} = 100{,}000$ ZOO ($10^{11}$ micro-ZOO) |
| `DefaultDonorCapBPS` | `500` (5%) | Per-donor per-project cap ($5{,}000$ ZOO, ZIP-0023 §5.3) |
| `DefaultProjectCapBPS` | `1000` (10%) | Per-project matching pool cap ($10{,}000$ ZOO) |
| `DefaultPairwiseM` | `25 * MicroZOO` | Pairwise Bounded QF tuning parameter $M_{\text{pair}} = 25$ ZOO |
| `DefaultCOCMM` | `25 * MicroZOO` | Inter-cluster COCM pairwise parameter $M_{\text{cocm}} = 25$ ZOO |
| `DefaultCOCMLambdaBPS` | `8500` ($\lambda = 0.85$) | Behavioral similarity penalty weight (`zoo-dao-governance` §8.2) |
| `DefaultMinRepGate` | `10` ZooRep | Matching gate (ZIP-0023 §5.3); strict mode uses `50` ZooRep (`zoo-dao-governance` §4.2) |
| `DefaultRepMinFP` | `40_000` ($r_{\min} = 0.04$) | Floor weight below `MinRepGate`; strict mode uses `0` ($r_{\min} = 0.00$) |

### 1.1 Exact Square Roots
For any non-negative micro-ZOO contribution $c \in \mathbb{Z}_{\ge 0}$ and fixed-point weight $r^{\text{fp}} \in [0, \text{Scale}]$:
- `sqrtFP(c)` $= \lfloor \sqrt{c \cdot \text{Scale}^2} \rfloor = \operatorname{isqrt}(c \cdot 10^{12})$
- `sqrtWeightedFP(r_fp, c)` $= \lfloor \sqrt{r^{\text{fp}} \cdot c \cdot \text{Scale}} \rfloor = \operatorname{isqrt}(r^{\text{fp}} \cdot c \cdot 10^6)$

### 1.2 Exact Pool Conservation (`AllocatePoolHamilton` & `AllocatePoolCapped`)
Given positive pool $M_{\text{pool}}$ and non-negative big-integer raw weights $W_p$ for projects $p \in \{1,\dots,P\}$ sorted by `project_id ASC`:

1. **Hamilton / Largest Remainder (`AllocatePoolHamilton`)**:
   - Let $W_{\text{tot}} = \sum_p W_p$. If $W_{\text{tot}} = 0$, return `alloc[p] = 0`, `unallocated = M_pool`.
   - Otherwise, compute $q_p = \lfloor (M_{\text{pool}} \cdot W_p) / W_{\text{tot}} \rfloor$ and remainder $R_p = (M_{\text{pool}} \cdot W_p) \bmod W_{\text{tot}}$.
   - Let $L = M_{\text{pool}} - \sum_p q_p$ ($0 \le L < P$). Sort projects by `(R_p DESC, project_id ASC)` and add `+1` micro-ZOO to the top $L$ projects.
   - **Invariant**: $\sum_p \text{alloc}_p = M_{\text{pool}}$ exactly, with `unallocated = 0`.
2. **Iterative Water-Filling Cap (`AllocatePoolCapped`)**:
   - Initialize active set $A = \{p : W_p > 0\}$, `alloc[p] = 0`, `remaining = M_pool`.
   - Repeatedly allocate `remaining` over $A$ via `AllocatePoolHamilton`. Any $p \in A$ with `alloc[p] + share[p] > cap` is clamped to `cap`, removed from $A$, and its marginal delta is subtracted from `remaining`.
   - Terminates in $\le P$ rounds; guarantees $\text{alloc}_p \le \text{cap}$ for all $p$ and $\sum_p \text{alloc}_p + \text{unallocated} = M_{\text{pool}}$. When $|A| \cdot \text{cap} \ge M_{\text{pool}}$ (true for all 12+ proposal rounds at 10% cap), `unallocated = 0` and $\sum_p \text{alloc}_p = M_{\text{pool}}$.

---

## 2. ZooRep Non-Transferable Tier Weights (ZIP-0026)

Aligned verbatim with `SBTReputation.sol` (`tierThresholds = [0, 50, 200, 500, 1000]`, `tierWeights = [100, 120, 150, 200, 250]`, normalized by `Elder = 250`):

| Tier | ZooRep Range | ZIP-0026 Multiplier | Normalized Weight $r_i$ (`rep_fp`) |
| --- | --- | --- | --- |
| Below Gate (`Unverified`) | `< MinRepGate` | Gated floor | `0.04` (`40_000`) standard / `0.00` (`0`) strict |
| `Observer` (gated) | `MinRepGate .. 49` | `1.0x` (`100`) | `0.40` (`400_000`) |
| `Contributor` | `50 .. 199` | `1.2x` (`120`) | `0.48` (`480_000`) |
| `Steward` | `200 .. 499` | `1.5x` (`150`) | `0.60` (`600_000`) |
| `Guardian` | `500 .. 999` | `2.0x` (`200`) | `0.80` (`800_000`) |
| `Elder` | `>= 1000` | `2.5x` (`250`) | `1.00` (`1_000_000`) |

---

## 3. Six Head-to-Head Allocation Mechanisms

1. **`linear_token_matching`** (1-Token-1-Vote Baseline):
   $$W_p = \sum_i c_{i,p}$$
   Allocated via `AllocatePoolHamilton`.

2. **`standard_clr_qf`** (Buterin–Hitzig–Weyl Capital-Constrained Liberal Radicalism, ZIP-0023 Eq. 1):
   $$s_{i,p} = \operatorname{sqrtFP}(c_{i,p}), \qquad W_p = \left(\sum_i s_{i,p}\right)^2 - \sum_i s_{i,p}^2 = 2\sum_{i<j} s_{i,p} s_{j,p}$$
   Allocated via `AllocatePoolHamilton`. Satisfies exact Breadth-Over-Depth ($n_p = 1 \implies W_p = 0$).

3. **`capped_voting_qf`** (Per-Contributor 5% Cap + Per-Project 10% Matching Cap):
   $$\tilde{c}_{i,p} = \min(c_{i,p},\; \lfloor M_{\text{pool}} \cdot 500 / 10000 \rfloor), \qquad \tilde{s}_{i,p} = \operatorname{sqrtFP}(\tilde{c}_{i,p})$$
   $$W_p = \left(\sum_i \tilde{s}_{i,p}\right)^2 - \sum_i \tilde{s}_{i,p}^2$$
   Allocated via `AllocatePoolCapped` with `cap = floor(M_pool * 1000 / 10000)`.

4. **`pairwise_bounded_qf`** (Buterin 2019 Pairwise Coordination Subsidy):
   For every distinct pair of contributors $(i, j)$ ($i < j$) sharing at least one project:
   $$T_{i,j}^{\text{fp}} = \sum_{q \in P} \left\lfloor \frac{s_{i,q} \cdot s_{j,q}}{\text{Scale}} \right\rfloor, \qquad k_{i,j}^{\text{fp}} = \left\lfloor \frac{(M_{\text{pair}} \cdot \text{Scale}) \cdot \text{Scale}}{(M_{\text{pair}} \cdot \text{Scale}) + T_{i,j}^{\text{fp}}} \right\rfloor$$
   $$W_p = 2 \sum_{i < j} \left\lfloor \frac{k_{i,j}^{\text{fp}} \cdot s_{i,p} \cdot s_{j,p}}{\text{Scale}} \right\rfloor$$
   Allocated via `AllocatePoolHamilton`.

5. **`reputation_weighted_qf`** (ZIP-0026 Non-Transferable ZooRep Weighting):
   $$u_{i,p} = \operatorname{sqrtWeightedFP}(r_i^{\text{fp}}, c_{i,p}), \qquad W_p = \left(\sum_i u_{i,p}\right)^2 - \sum_i u_{i,p}^2$$
   Allocated via `AllocatePoolHamilton`.

6. **`hybrid_cocm_reputation_capped_qf`** (Connection-Oriented Cluster Matching + Non-Transferable ZooRep Floor + Per-Donor & Per-Project Cap + HIP-1352 Constitutional Human-Steward Sign-Off Gate):
   - **Step A (Cap + Reputation)**: $e_{i,p} = \lfloor (r_i^{\text{fp}} \cdot \min(c_{i,p}, c_{\max})) / \text{Scale} \rfloor$.
   - **Step B (Linear Intra-Cluster Aggregation)**: Group donors by `cluster_id` (singleton `donor_id` if empty). Sum linearly within each cluster $g$: $C_{g,p} = \sum_{i \in g} e_{i,p}$, $s_{g,p} = \operatorname{sqrtFP}(C_{g,p})$, $N_g = \sum_q s_{g,q}^2$.
   - **Step C (Inter-Cluster Pairwise + Squared-Cosine Similarity Discount)**: For distinct clusters $g < h$ sharing $\ge 1$ project:
     $$D_{g,h} = \sum_q s_{g,q} s_{h,q}, \qquad T_{g,h}^{\text{fp}} = \sum_q \left\lfloor \frac{s_{g,q} s_{h,q}}{\text{Scale}} \right\rfloor$$
     $$k_{g,h}^{\text{pair}} = \left\lfloor \frac{(M_{\text{cocm}}\cdot\text{Scale})\cdot\text{Scale}}{(M_{\text{cocm}}\cdot\text{Scale}) + T_{g,h}^{\text{fp}}} \right\rfloor, \qquad \text{sim2}_{g,h}^{\text{fp}} = \min\!\left(\text{Scale},\; \left\lfloor \frac{D_{g,h}^2 \cdot \text{Scale}}{N_g \cdot N_h} \right\rfloor\right)$$
     $$\text{pen}_{g,h}^{\text{fp}} = \max\!\left(0,\; \text{Scale} - \left\lfloor \frac{\lambda_{\text{bps}} \cdot \text{sim2}_{g,h}^{\text{fp}}}{\text{BPS}} \right\rfloor\right), \qquad k_{g,h}^{\text{cocm}} = \left\lfloor \frac{k_{g,h}^{\text{pair}} \cdot \text{pen}_{g,h}^{\text{fp}}}{\text{Scale}} \right\rfloor$$
     $$W_p = 2 \sum_{g < h} \left\lfloor \frac{k_{g,h}^{\text{cocm}} \cdot s_{g,p} \cdot s_{h,p}}{\text{Scale}} \right\rfloor$$
   - **Step D (Per-Project Cap)**: Allocated via `AllocatePoolCapped` at 10% (`1000 bps`).
   - **Step E (Constitutional Gate)**: Round output enters `PROPOSED_REQUIRES_HUMAN_SIGN_OFF` state; execution requires 3-of-5 human Treasury Committee stewards (`ZooRep >= 200`).

---

## 4. Constitutional Governance Boundary (HIP-1352)

Every simulation run executes and hashes an 8-check constitutional audit suite (`governance_checks`):
- **Allowed for `ai_agent`**: `recommend_allocation_plan`, `flag_collusion_conflict`, `estimate_proposal_value` (`ALLOWED_ADVISORY_ONLY`).
- **Hard-blocked for `ai_agent`** (even if `human_signers = 5` is spoofed):
  - `redefine_voting_rules` -> `ERR_AI_RULE_MUTATION_FORBIDDEN`
  - `authorize_treasury_disbursement` -> `ERR_AI_TREASURY_AUTH_FORBIDDEN`
  - `declare_experiment_valid` -> `ERR_AI_SELF_VALIDATION_FORBIDDEN`
- **Human Treasury Quorum**: `human_steward` with `< 200` ZooRep or `< 3` signers is denied (`ERR_INSUFFICIENT_STEWARD_ZOOREP` / `ERR_INSUFFICIENT_HUMAN_QUORUM`); $\ge 3$-of-5 human stewards with $\ge 200$ ZooRep satisfy `ALLOWED_HUMAN_QUORUM_MET`.

---

## 5. Canonical Hashing & `audit_merkle_root`

All digests use domain-separated UTF-8 SHA-256 over deterministic pipe/newline canonical records (no floating-point formatting, explicit ascending sort order):
- `corpus_hash = SHA256("zoo.qfsim.v1.corpus\n" || sorted_corpus_lines)`
- `governance_hash = SHA256("zoo.qfsim.v1.governance\n" || sorted_gov_check_lines)`
- `leaf_hash = SHA256("zoo.qfsim.v1.leaf\n" || canonical_eval_lines)` for each `(scenario_id, mechanism_id)`
- `eval_merkle_root`: binary SHA-256 Merkle tree over `leaf_hash` sorted by `(scenario_id ASC, mechanism_id ASC)`, domain `"zoo.qfsim.v1.node\n"`, duplicating odd trailing nodes.
- `audit_merkle_root = SHA256("zoo.qfsim.v1.root\n" || corpus_hash || "\n" || eval_merkle_root || "\n" || governance_hash)`.

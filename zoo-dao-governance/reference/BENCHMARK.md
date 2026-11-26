# Zoo DAO Quadratic Funding & Sybil-Resistance Benchmark (`qf-simulator.v1`)

**Issue**: `zoo-apps/papers#6` (`[p1, governance, research, bounty, hip-1352]`)  
**Seed**: `--seed 1352` | **Matching Pool**: `100,000 ZOO` (`100,000,000,000 micro-ZOO`)  
**Scenarios**: 15 (Honest Baseline + 4 Stated Attack Families + 2 Dedicated Negative-Regime Stress Tests)  
**Mechanisms**: 6 Head-to-Head Allocation Mechanisms (90 total evaluations, 100% pool conservation)

---

## 1. Reproducible Verification & Cryptographic Audit Roots

Zero external dependencies in both Go 1.24 (stdlib) and Python 3.12 (stdlib).

```bash
# 1. Run Go simulator, race-checked test suite, and regenerate results.json + scenarios.json
cd zoo-dao-governance/reference/go
go vet ./...
go test -v -race -count=1 ./...
go run ./cmd/qf-sim --seed 1352 --papers-root ../../.. --out ../results.json --scenarios-out ../scenarios.json

# 2. Run independent Python 3.12 audit verifier (recomputes all 6 mechanisms from raw scenarios.json
#    and verifies every .tex SHA-256 on disk + bit-identical audit_merkle_root)
cd ../python
python3 -m qf_verifier.cli --results ../results.json --scenarios ../scenarios.json --papers-root ../../..
python3 -m unittest discover -v
```

### Bit-Identical Cross-Language SHA-256 Digests (`--seed 1352`)
| Digest | Go 1.24 & Python 3.12 Verified SHA-256 |
| --- | --- |
| `corpus_hash` | `50aba16f9c086031970c7e6a0c29d25c88a205387763ce626fc4d94d8bfcfaeb` |
| `governance_hash` | `feba0bdcbf0fdbfc0e94307142794f2c3de6a6868fe2defed5b3f882c9de657f` |
| `eval_merkle_root` | `09e6a1fbdb4d0e4e4e2a130014d7f6bc5af82062c320b9b5abc4f65e24ce1bc3` |
| `audit_merkle_root` | `e6c9855606e6fcfac1193526be9605d98175a8039a9ba09404be5ab799a8333d` |

---

## 2. Real Research Grant Corpus (`zoo-apps/papers`)

All 12 honest grant proposals are loaded directly from `.tex` sources in `zoo-apps/papers`, hashed with SHA-256, and mapped to ZIP-0023 grant categories (`zoo-dao-grants-program.tex` Table 1):

| Grant ID | Paper Directory | Category | Archetype | Merit (bps) | `.tex` SHA-256 (prefix) |
| --- | --- | --- | --- | ---: | --- |
| `grant-01-conservation-ai` | `zoo-conservation-ai` | Conservation Research | `broad_public_good` | 9400 | `9e459189e49d` |
| `grant-02-data-commons` | `zoo-data-commons` | Open Source Dev | `broad_public_good` | 9300 | `2c017a9068c0` |
| `grant-03-citizen-science` | `zoo-citizen-science` | Citizen Science | `broad_public_good` | 9200 | `aa030934cad2` |
| `grant-04-desci-platform` | `zoo-desci-platform` | Open Source Dev | `broad_public_good` | 9000 | `3d0b0539b4cf` |
| `grant-05-species-classification` | `zoo-species-classification` | Conservation Research | `grassroots_minority` | 9100 | `96474a61b0b6` |
| `grant-06-habitat-modeling` | `zoo-habitat-modeling` | Conservation Research | `grassroots_minority` | 8900 | `1c0186fb773b` |
| `grant-07-educational-ai` | `zoo-educational-ai` | Education | `grassroots_minority` | 8600 | `d34fd42383c6` |
| `grant-08-wildlife-tracking` | `zoo-wildlife-tracking` | Citizen Science | `grassroots_minority` | 8800 | `03294c0faa84` |
| `grant-09-federated-wildlife` | `zoo-federated-wildlife` | Conservation Research | `tightly_knit_lab` | 8500 | `f193683ba6a3` |
| `grant-10-satellite-ecology` | `zoo-satellite-ecology` | Conservation Research | `tightly_knit_lab` | 8400 | `e9aa74902d07` |
| `grant-11-carbon-credits` | `zoo-carbon-credits` | Open Source Dev | `whale_niche` | 4800 | `b09479b7a634` |
| `grant-12-research-coordination` | `zoo-research-coordination` | Open Source Dev | `whale_niche` | 5200 | `542ce14dc94d` |

In adversarial shell-raid scenarios, a 13th synthetic low-merit proposal (`grant-13-adversarial-shell`, `merit = 1000 bps`) is appended to measure exact pool extraction and attack ROI.

---

## 3. Stated Attack Models & Honest Baseline

1. **`honest_public_goods_baseline`** (0 attackers): 120 honest donors across ZIP-0026 tiers (`16` newcomers `<10` rep, `30` Observers `10–49`, `28` Contributors `50–199`, `13` Stewards `200–499`, `6` Guardians `500–999`, `3` Elders `1000+`, `18` co-located lab members in 2 labs, `6` ecosystem sponsors). Total honest spend $\approx 9{,}000\text{–}9{,}600$ ZOO vs `100,000 ZOO` matching pool.
2. **`sybil_identity_splitting`** ($S \in \{2, 5, 10, 25, 50\}$): Single whale splits fixed capital $B = 25{,}000$ ZOO evenly across $S$ freshly minted `0-ZooRep` Sybil wallets (`identity_cost = 0 ZOO`, shared funding-source cluster) targeting `grant-13-adversarial-shell`.
3. **`bribery_collusion_ring`** ($C \in \{5, 15, 30\}$): Coordinated cartel of $C$ distinct real accounts with legitimate `Observer`/`Contributor` reputation (`20–85` ZooRep), each contributing `200 ZOO` ($B = 200 C$ ZOO) plus 10% bribe coordination overhead (`total_cost = 220 C` ZOO) to `grant-13-adversarial-shell`, sharing a cartel coordination cluster.
4. **`reputation_farming_sleeper_cartel`** ($C \in \{5, 15, 30\}$): Adversary operates $C$ sleeper accounts in **obfuscated separate funding clusters** (`obfuscated_clusters = true`), spends `20 ZOO/account` farming `55–75` ZooRep (`Contributor` tier), then executes a synchronized `200 ZOO/account` raid (`total_cost = 220 C` ZOO) on `grant-13-adversarial-shell`.
5. **`whale_plutocracy_capture`** ($1$ non-Sybil whale): Single wealthy Contributor account (`60 ZooRep`, `0` Sybils) donates $B = 25{,}000$ ZOO directly to commercial niche `grant-11-carbon-credits` (`merit = 4800 bps`).

---

## 4. Head-to-Head Mechanism Comparison Tables

### 4.1 Honest Public Goods Baseline (`0` Attackers)
| Mechanism | Merit Welfare | Grassroots Share | Minority Share | Honest Gini | Lab Share | Newcomer Grant | Whale Niche | Pool Conserved |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :---: |
| `linear_token_matching` | 84.09% | 72.91% | 27.24% | 0.170 | 12.43% | 10.57% | 14.64% | EXACT |
| `standard_clr_qf` | 89.54% | 87.10% | 24.87% | 0.389 | 10.21% | 14.86% | 2.68% | EXACT |
| `capped_voting_qf` | 87.00% | 78.90% | 38.90% | 0.154 | 14.96% | 10.00% | 6.13% | EXACT |
| `pairwise_bounded_qf` | **90.06%** | **88.29%** | 22.94% | 0.423 | 9.96% | **15.73%** | **1.74%** | EXACT |
| `reputation_weighted_qf` | 89.44% | 86.09% | 24.06% | 0.387 | 11.09% | 13.38% | 2.81% | EXACT |
| `hybrid_cocm_reputation_capped_qf` | 85.62% | 80.00% | **40.00%** | 0.166 | 10.02% | 10.00% | 9.97% | EXACT |

*Key observation*: In an attack-free round, uncapped `pairwise_bounded_qf` and `standard_clr_qf` achieve the highest merit welfare (`90.06%` / `89.54%`) and grassroots share (`88.29%` / `87.10%`), while capped mechanisms (`capped_voting_qf`, `hybrid_cocm_reputation_capped_qf`) produce the lowest Gini (`0.154` / `0.166`) and redirect overflow from popular broad grants into grassroots minority projects (`38.90%` / `40.00%`).

---

### 4.2 Sybil Identity Splitting Sweep (`B = 25,000 ZOO`, Costless `0-ZooRep` Wallets)
Values shown as **Pool Extraction % (Direct-Cost Attack ROI)**:

| Mechanism | $S = 2$ | $S = 5$ | $S = 10$ | $S = 25$ | $S = 50$ | $S=50$ Merit Welfare |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `linear_token_matching` | 73.35% (2.93x) | 73.36% (2.93x) | 74.45% (2.98x) | 73.74% (2.95x) | 73.60% (2.94x) | 29.73% |
| `standard_clr_qf` | 7.20% (0.29x) | 23.62% (0.95x) | 42.20% (1.69x) | 64.61% (2.58x) | **78.73% (3.15x)** | **26.92%** |
| `capped_voting_qf` | 5.28% (0.21x) | 10.00% (0.40x) | 10.00% (0.40x) | 10.00% (0.40x) | 10.00% (0.40x) | 80.26% |
| `pairwise_bounded_qf` | 0.03% (0.00x) | 0.35% (0.01x) | 1.59% (0.06x) | 9.32% (0.37x) | 28.97% (1.16x) | 66.83% |
| `reputation_weighted_qf` | 0.66% (0.03x) | 2.63% (0.11x) | 5.99% (0.24x) | 13.98% (0.56x) | 24.67% (0.99x) | 69.91% |
| `hybrid_cocm_reputation_capped_qf` | **0.00% (0.00x)** | **0.00% (0.00x)** | **0.00% (0.00x)** | **0.00% (0.00x)** | **0.00% (0.00x)** | **85.62%** |

*Key observation*: `linear_token_matching` is Sybil-invariant but already captured at ~73.6% by capital alone. Uncapped `standard_clr_qf` crosses profitability (`ROI > 1.0x`) between $S=5$ and $S=10$ and **surpasses linear plutocracy at $S=50$ (`78.73%`, `3.15x` ROI)**. Even `pairwise_bounded_qf` turns profitable again at $S=50$ (`28.97%`, `1.16x` ROI) because $\binom{S}{2}$ grows quadratically in $S$. `hybrid_cocm_reputation_capped_qf` collapses same-cluster Sybils to **`0.00%`** across the entire sweep.

---

### 4.3 Bribery Collusion Ring Sweep (`C` Real Accounts, `20–85 ZooRep`, `200 ZOO/acct` + 10% Bribe Overhead)
Values shown as **Pool Extraction % (Direct ROI / Net ROI)**:

| Mechanism | $C = 5$ ($B=1{,}000$) | $C = 15$ ($B=3{,}000$) | $C = 30$ ($B=6{,}000$) | $C=30$ Merit Welfare |
| --- | ---: | ---: | ---: | ---: |
| `linear_token_matching` | 10.42% (10.42x / 9.47x) | 25.09% (8.37x / 7.61x) | 38.45% (6.41x / 5.83x) | 55.53% |
| `standard_clr_qf` | 1.27% (1.28x / 1.16x) | 11.68% (3.90x / 3.54x) | 33.36% (5.56x / 5.06x) | 62.90% |
| `capped_voting_qf` | 2.64% (2.64x / 2.40x) | 10.00% (3.33x / 3.03x) | 10.00% (1.67x / 1.52x) | 80.10% |
| `pairwise_bounded_qf` | 0.32% (0.32x / 0.29x) | 3.26% (1.09x / 0.99x) | 11.82% (1.97x / 1.79x) | 80.51% |
| `reputation_weighted_qf` | 1.24% (1.25x / 1.14x) | 11.65% (3.88x / 3.53x) | 32.18% (5.36x / 4.88x) | 63.79% |
| `hybrid_cocm_reputation_capped_qf` | **0.00% (0.00x / 0.00x)** | **0.00% (0.00x / 0.00x)** | **0.00% (0.00x / 0.00x)** | **85.61%** |

*Key observation*: Because bribed accounts are distinct real humans with legitimate ZooRep, **`reputation_weighted_qf` offers almost zero protection** (`32.18%` extraction at $C=30$ vs `33.36%` for standard CLR). Pairwise discounting cuts $C=30$ extraction by **64.6%** (`33.36% -> 11.82%`), and COCM cluster collapse eliminates it completely when cartel attribution succeeds (`0.00%`).

---

### 4.4 Reputation-Farming Sleeper Cartel Sweep (`C` Obfuscated Clusters + Farmed `55–75` Contributor ZooRep)
Values shown as **Pool Extraction % (Direct ROI / Net ROI)**:

| Mechanism | $C = 5$ | $C = 15$ | $C = 30$ | $C=30$ Merit Welfare |
| --- | ---: | ---: | ---: | ---: |
| `linear_token_matching` | 10.12% (10.12x / 9.20x) | 25.70% (8.57x / 7.79x) | 40.75% (6.79x / 6.17x) | 53.73% |
| `standard_clr_qf` | 1.21% (1.22x / 1.11x) | 11.93% (3.98x / 3.62x) | 35.76% (5.96x / 5.42x) | 61.04% |
| `capped_voting_qf` | 2.18% (2.18x / 1.99x) | 10.00% (3.33x / 3.03x) | 10.00% (1.67x / 1.52x) | 80.18% |
| `pairwise_bounded_qf` | **0.31% (0.31x / 0.29x)** | **3.29% (1.10x / 1.00x)** | 12.31% (2.05x / 1.87x) | 80.15% |
| `reputation_weighted_qf` | 1.29% (1.29x / 1.17x) | 12.36% (4.12x / 3.75x) | **37.05% (6.18x / 5.61x)** | **59.94%** |
| `hybrid_cocm_reputation_capped_qf` | 0.45% (0.45x / 0.41x) | 3.83% (1.28x / 1.16x) | **10.00% (1.67x / 1.52x)** | **80.21%** |

*Key observation*: **Reputation weighting backfires against farmed sleepers!** At $C=30$, `reputation_weighted_qf` loses **`37.05%`** (`5.61x` net ROI) — *worse* than unweighted `standard_clr_qf` (`35.76%`) — because farmed `Contributor` accounts (`0.48`) outweigh honest `Observer`/newcomer voters (`0.40`/`0.04`). Meanwhile, even when the cartel completely obfuscates funding-source clusters, `hybrid_cocm_reputation_capped_qf`'s behavioral squared-cosine similarity penalty (`1 - 0.85 * sim^2`) + `10%` project cap contains extraction to `0.45%` ($C=5$), `3.83%` ($C=15$), and `10.00%` capped ($C=30$).

---

### 4.5 Whale Plutocracy Capture (`1` Non-Sybil Whale, `25,000 ZOO` on Niche Grant)
| Mechanism | Whale Target Share | Direct ROI | Merit Welfare | Grassroots Share | Honest Gini |
| --- | ---: | ---: | ---: | ---: | ---: |
| `linear_token_matching` | **76.82%** | **3.07x** | **57.03%** | **18.14%** | 0.160 |
| `standard_clr_qf` | 10.55% | 0.42x | 85.78% | 79.30% | 0.350 |
| `capped_voting_qf` | 10.00% | 0.40x | 85.17% | 75.59% | 0.168 |
| `pairwise_bounded_qf` | **2.29%** | **0.09x** | **89.55%** | **87.56%** | 0.378 |
| `reputation_weighted_qf` | 10.69% | 0.43x | 85.62% | 77.96% | 0.348 |
| `hybrid_cocm_reputation_capped_qf` | 10.00% | 0.40x | 85.52% | 80.00% | 0.181 |

*Key observation*: Without Sybil splitting, all five quadratic mechanisms render whale capture deeply unprofitable (`0.09x–0.43x` ROI) and preserve `75.6%–87.6%` grassroots share, whereas `linear_token_matching` hands `76.82%` of the pool to the whale (`3.07x` ROI) and crashes grassroots share to `18.14%`.

---

## 5. Honest Negative Regimes (Quantified Failure Modes)

No single mechanism dominates universally. Our simulator explicitly models and verifies three negative regimes:

### Negative Regime #1: Newcomer / Legitimate Grassroots Suppression under Strict Reputation Weighting
Scenario `neg_regime_1_strict_rep_newcomer_starvation` enforces a hard `50-ZooRep` Contributor gate (`r_min = 0.00`) when 40 legitimate brand-new community researchers (`0–8` ZooRep) rally behind `grant-03-citizen-science` (`merit = 9200 bps`) alongside an $S=25$ Sybil attack (`25,000 ZOO`):

| Mechanism | $S=25$ Sybil Extraction | Newcomer Grant Share (`grant-03`) | Merit Welfare | Tradeoff |
| --- | ---: | ---: | ---: | --- |
| `standard_clr_qf` | 67.18% | 3.15% | 35.98% | Vulnerable to Sybils |
| `capped_voting_qf` | 10.00% | 10.00% | 80.13% | Preserves newcomers; caps Sybils at 10% |
| `pairwise_bounded_qf` | 9.78% | **10.83%** | 81.96% | Best newcomer funding without hard rep gate |
| `reputation_weighted_qf` (strict gate) | **0.00%** | **0.00% (-100%)** | 88.20% | Blocks Sybils completely, **starves newcomers to 0%** |
| `hybrid_cocm_reputation_capped_qf` (strict gate) | **0.00%** | **0.00% (-100%)** | 81.84% | Blocks Sybils completely, **starves newcomers to 0%** |

**Finding**: Hard reputation gates (`r_min = 0.00` at 50 ZooRep) eliminate fresh-wallet Sybils (`0.00%` extraction) at the exact cost of a **100% welfare collapse for legitimate newcomers**, reinforcing why Zoo DAO needs either a soft nonzero newcomer floor (`r_min = 0.04`) or dedicated newcomer onboarding micro-rounds.

### Negative Regime #2: Pairwise / COCM False-Positive Penalty on Tightly Knit Honest Research Labs
Scenario `neg_regime_2_honest_lab_cocm_false_positive` has **zero attackers**: 24 legitimate researchers in one co-located conservation genomics lab (`lab-pacific-reef-genomics`, `120–460` ZooRep) co-fund their two complementary lab grants (`grant-09-federated-wildlife`, `grant-10-satellite-ecology`):

| Mechanism | Combined Honest Lab Share | Relative Change vs `standard_clr_qf` | Merit Welfare |
| --- | ---: | ---: | ---: |
| `reputation_weighted_qf` | **37.87%** | +12.5% | 87.90% |
| `standard_clr_qf` | 33.65% | baseline | 88.12% |
| `pairwise_bounded_qf` | 28.93% | **-14.0%** | 88.79% |
| `capped_voting_qf` | 20.00% | -40.6% | 87.66% |
| `hybrid_cocm_reputation_capped_qf` | **10.14%** | **-69.9%** (-73.2% vs Rep QF) | 85.66% |

**Finding**: Because an honest co-located research lab shares both institutional cluster membership and high co-funding overlap across 2 grants, it looks structurally indistinguishable from a bribery ring. `pairwise_bounded_qf` suppresses its matching by **-14.0%**, and `hybrid_cocm_reputation_capped_qf` suppresses it by **-69.9%** relative to CLR QF!

### Negative Regime #3: Identity-Costless Unlimited Sybils (`S = 50`) on Uncapped Standard CLR QF
Analytically, splitting a fixed whale budget $B$ equally across $S$ costless wallets yields raw CLR score:
$$W_{\text{sybil}}(S) = \left(S \cdot \sqrt{B/S}\right)^2 - B = (S - 1)\, B$$
which grows **unboundedly linearly in $S$** for fixed capital $B$. Empirically at $B = 25{,}000$ ZOO, $S = 50$ (`sybil_identity_splitting_s50`):
- `standard_clr_qf` loses **`78.73%`** of the matching pool (`3.15x` ROI), collapsing merit welfare from `89.54%` to `26.92%` — **strictly worse than 1-token-1-vote linear matching (`73.60%`)**!
- Even `pairwise_bounded_qf` leaks **`28.97%`** (`1.16x` ROI) at $S=50$ because the number of Sybil pairs $\binom{S}{2} = 1{,}225$ scales quadratically while per-pair overlap shrinks as $B/S$.

---

## 6. Constitutional Governance Audit (HIP-1352)

All 8 checks in `governance_checks` passed identically in Go and Python:
- `ai_agent` advisory operations (`recommend_allocation_plan`, `flag_collusion_conflict`, `estimate_proposal_value`) -> **ALLOWED** (`ALLOWED_ADVISORY_ONLY`).
- `ai_agent` attempts to call `redefine_voting_rules`, `authorize_treasury_disbursement`, or `declare_experiment_valid` (even with spoofed `human_signers = 5`) -> **HARD-DENIED** (`ERR_AI_RULE_MUTATION_FORBIDDEN`, `ERR_AI_TREASURY_AUTH_FORBIDDEN`, `ERR_AI_SELF_VALIDATION_FORBIDDEN`).
- Human steward treasury disbursement with 2-of-5 signers -> **DENIED** (`ERR_INSUFFICIENT_HUMAN_QUORUM`); with 3-of-5 stewards (`ZooRep >= 200`) -> **ALLOWED** (`ALLOWED_HUMAN_QUORUM_MET`).

---

## 7. What Remains Unproven / Open Research Gaps

This simulator is a deterministic static single-round benchmark; the following critical questions remain **unproven** and require further research and field validation:

1. **Multi-Proposal Sybil Splitting (Bypassing Per-Project Caps)**: In our scenarios, attackers target a single shell grant (`grant-13-adversarial-shell`), allowing the `10%` per-project cap to bound worst-case extraction even when sleeper cartels defeat cluster attribution (`C = 30`). An adversary who submits $K$ distinct plausible-looking fake research proposals (e.g., $K = 5$ LLM-generated conservation grant applications) could extract up to $K \times 10\%$ unless human Science Council screening (`zoo-dao-grants-program.tex` §3) filters low-merit proposals *before* voting opens.
2. **Funding-Graph Obfuscation via Privacy Mixers & Cross-Chain Bridges**: `hybrid_cocm_reputation_capped_qf` relies on cluster labels (`cluster_id`) plus behavioral cosine similarity. When an adversary uses privacy mixers, CEX withdrawals, or cross-chain bridges to hide funding sources (as modeled in `reputation_farming_sleeper_cartel`), intra-cluster collapse fails and defense rests entirely on behavioral similarity and project caps. An adversary that also injects randomized decoy donations to honest grants to lower $\text{sim}_{g,h}^2$ is not yet modeled and remains an open adaptive attack surface.
3. **Dynamic Multi-Round Adaptive Behavior & Reputation Rental Markets**: Our benchmark models a single static round with exogenous honest contributions. In repeated rounds, honest donors respond endogenously to matching multipliers, reputation decays at 5–20%/year (ZIP-0026 §4), and colluders may rent/borrow high-reputation accounts via off-chain smart-contract bribery (MACI-style collusion markets) or gradually farm `Steward`/`Guardian` tiers over 12–24 months.
4. **Privacy-Preserving COCM over Encrypted Ballots (Shutter / MACI)**: `zoo-voting-platform` uses Shutter threshold encryption for ballot privacy during voting, but COCM requires social-graph and co-funding vectors at tally time. Computing pairwise/COCM tallies inside ZK circuits or MPC without leaking donor social graphs remains an open engineering problem.
5. **Ground-Truth Scientific Merit Uncertainty**: Real conservation science does not have an oracle `merit_bps` score at grant-allocation time. Whether retrospective Impact Oracles (ZIP-0020) and citation/biodiversity outcomes correlate monotonically with any QF variant over 3–5 year horizons cannot be proven in simulation alone.
6. **Human Steward & Review Council Capture**: While HIP-1352 constitutionally forbids AI agents from mutating rules or authorizing treasury spending, the 3-of-5 Treasury Committee and 7-member Research Council themselves remain vulnerable to off-chain human collusion, geographic concentration, or voter apathy (`zoo-dao-governance.tex` §9.2).

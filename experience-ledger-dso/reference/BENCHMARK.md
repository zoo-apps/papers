# Byzantine-Robust DSO Aggregation & Participation Fairness — Reproducible Benchmark & Research Artifact

- **Specification**: [`SPEC.md`](SPEC.md) (`dso-aggregation.v1`)
- **JSON Schema**: [`schema/dso-aggregation.v1.schema.json`](schema/dso-aggregation.v1.schema.json)
- **Raw Data**: [`results.json`](results.json) (120 cells + 3 negative regimes) | [`audit_trace.json`](audit_trace.json) (5 signed rounds, 150 Ed25519 envelopes)
- **Seed**: `--seed 1352`
- **Grounded Corpus**: **88 real `.tex` papers** discovered directly in `zoo-apps/papers` (`73` `protocol_governance` papers / `5,534` cleaned paragraphs; `15` `conservation_science` papers / `1,099` cleaned paragraphs; `corpus_sha256`: `b78e25bbf8a1fc299cf9342fd3cb1d2cedffaf19566ddb031390a26ca04b32d6`)
- **Environment**: Linux x86_64, Go 1.24.3 stdlib (zero external modules), Python 3.12.16 stdlib (zero external packages)

---

## 1. Executive Summary & Cross-Language Audit Parity

We benchmark **5 head-to-head aggregation rules** (`mean_baseline`, `coord_median`, `trimmed_mean`, `multi_krum`, `dso_reputation_eval_gated`) over $N = 30$ Ed25519-authenticated nodes, $T = 12$ rounds, and adversarial fractions $f \in \{0\%, 10\%, 20\%, 30\%, 40\%, 50\%\}$ across **4 mandatory threat and honest-disagreement scenarios** (`120` total cells).

| Artifact / Audit Check | Value |
|---|---|
| Grounded `.tex` corpus | `88` papers (`73` protocol/governance, `15` conservation/science), `6,633` cleaned paragraphs |
| Total benchmark cells | `120` (`4` scenarios × `6` adversary fractions × `5` aggregators) |
| `audit_merkle_root` (Go 1.24 == Python 3.12) | `6afc3857524d5d2191b03927b0239887bc9c2e4749f6859c6f0e5275aca88152` (**bit-identical**) |
| `trace_merkle_root` (Go 1.24 == Python 3.12) | `3ce5605d62f2dd7c2614d15a7db451cf3c54d698545adce2251c31bf30b26672` (**bit-identical**) |
| Independent Python 3.12 Ed25519 verification | `150/150` signed envelopes verified, `25/25` aggregator runs matched ($\le 1\times 10^{-6}$ micro-unit tolerance, exact boolean acceptance & cluster-size parity) |
| Mean verification overhead (`mean` → `dso_reputation_eval_gated`) | `3.15 ms/round` → `4.99 ms/round` (`+1.84 ms/round` for stratified held-out eval + cross-domain safety + Sybil cluster discounting), `~31.0 KB/round` signed payload |

### Core Experimental Takeaways

1. **Statistical/geometric filters fail silently on legitimate honest disagreement — even at $f = 0\%$**: Under a strict 75/25 `protocol_governance` vs. `conservation_science` specialist split with **zero adversaries**, `coord_median`, `trimmed_mean`, and `multi_krum` all suffer **0% minority honest acceptance**, depressing minority-domain accuracy by **18.4–20.9 percentage points** (`58.3–60.8%` vs. `79.2%` for `dso_reputation_eval_gated`) and driving Jain's Fairness Index down to `0.684–0.778` (Gini `0.276–0.377`).
2. **Tightly clustered Sybil cartels invert Multi-Krum**: At $f = 40\%$ collusion, `multi_krum` admits `51%` of the cartel (global accuracy collapses to `51.9%`, minority `25.8%`). At $f = 50\%$, `multi_krum` admits **`100%` of the cartel and `0%` of honest nodes** (`16.9%` global accuracy, Jain `0.000`, Gini `1.000`).
3. **Label-flipped, norm-matched semantic poisoning breaks coordinate filters at high $f$**: At $f = 40\%$, `trimmed_mean` admits `42%` of semantic poisoners (`69.0%` global / `56.2%` minority); at $f = 50\%$, `coord_median` (`41.5%`, `96%` adv admission) and `trimmed_mean` (`39.6%`, `99%` adv admission) collapse below random chance.
4. **Classical statistical filters DO work well against unstructured noisy freeloaders**: In `low_quality_noisy`, `coord_median` (`79.6–82.7%`) and `multi_krum` (`78.5–82.7%`) resist high-variance noise across $f \in [10\%, 50\%]$ (where `mean_baseline` immediately collapses to `52–63%`), though `multi_krum` still suppresses minority acceptance (`1–15%` at $f \le 30\%$).
5. **Held-out evaluation gating is NOT a silver bullet (Negative Regimes 2 & 3)**: When adversaries target an **unmonitored trigger subdomain** absent from the validation suite, even `dso_reputation_eval_gated` suffers **`100.0%` Backdoor Attack Success Rate** (`0.0%` trigger accuracy) while maintaining `83.5%` clean accuracy. Furthermore, decentralizing validation via a 66% supermajority DAO committee (`experience-ledger-dso` Theorem 2) hits **0% honest liveness collapse at $f \ge 40\%$**, and reusing a tiny static 20-item validation set over 30 rounds produces a **`+34.8pp` Goodhart overfitting gap** (`100.0%` val vs. `65.2%` test).

---

## 2. Full Experimental Matrix (4 Scenarios × 6 Adversary Fractions × 5 Aggregators)

> **Columns**: `Global Acc` = balanced unseen test accuracy (`50%` protocol + `50%` conservation); `Loss` = unseen logistic loss; `Maj Acc` = `protocol_governance` unseen test accuracy; `Min Acc` = `conservation_science` unseen test accuracy; `Deg Δ` = degradation vs. $f = 0\%$ clean honest ceiling (positive = worse); `Adv Adm` = adversarial admission rate; `Maj Acpt` / `Min Acpt` = honest acceptance rates; `Jain` = Jain's Fairness Index over honest cumulative attribution; `Gini` = Attribution Gini Coefficient over honest nodes; `ms/rnd` = measured verification + aggregation latency; `B/rnd` = canonical signed payload bytes/round.

### Scenario 1: `adversarial_semantic` (Label-Flipped, Norm-Matched Semantic Poisoning)

| $f$ | Aggregator | Global Acc | Loss | Maj Acc | Min Acc | Deg $\Delta$ | Adv Adm | Maj Acpt | Min Acpt | Jain | Gini | ms/rnd | B/rnd |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0% | `mean_baseline` | 82.5% | 0.678 | 86.2% | 78.8% | +0.4pp | 0% | 100% | 100% | 1.000 | 0.000 | 3.26 | 31,175 |
| 0% | `coord_median` | 82.5% | 0.680 | 87.1% | 77.9% | +0.4pp | 0% | 96% | 17% | 0.844 | 0.233 | 3.05 | 31,169 |
| 0% | `trimmed_mean` | 82.5% | 0.680 | 87.5% | 77.5% | +0.4pp | 0% | 98% | 38% | 0.879 | 0.200 | 3.50 | 31,185 |
| 0% | `multi_krum` | 79.2% | 0.679 | 84.6% | 73.8% | +3.7pp | 0% | 71% | 0% | 0.680 | 0.367 | 3.42 | 31,171 |
| 0% | `dso_reputation_eval_gated` | 82.9% | 0.678 | 85.4% | 80.4% | +0.0pp | 0% | 98% | 100% | 0.977 | 0.078 | 5.04 | 31,171 |
| 10% | `mean_baseline` | 81.7% | 0.681 | 85.8% | 77.5% | +1.2pp | 100% | 100% | 100% | 1.000 | 0.000 | 2.99 | 31,234 |
| 10% | `coord_median` | 81.9% | 0.682 | 86.2% | 77.5% | +1.0pp | 0% | 96% | 29% | 0.853 | 0.222 | 3.48 | 31,221 |
| 10% | `trimmed_mean` | 80.6% | 0.681 | 87.1% | 74.2% | +2.3pp | 0% | 98% | 38% | 0.875 | 0.203 | 3.53 | 31,212 |
| 10% | `multi_krum` | 79.6% | 0.679 | 85.0% | 74.2% | +3.3pp | 0% | 79% | 1% | 0.700 | 0.340 | 3.33 | 31,220 |
| 10% | `dso_reputation_eval_gated` | 82.5% | 0.678 | 85.4% | 79.6% | +0.4pp | 0% | 99% | 100% | 0.985 | 0.065 | 5.31 | 31,211 |
| 20% | `mean_baseline` | 80.2% | 0.684 | 87.1% | 73.3% | +2.7pp | 100% | 100% | 100% | 1.000 | 0.000 | 3.34 | 31,274 |
| 20% | `coord_median` | 79.4% | 0.684 | 84.2% | 74.6% | +3.5pp | 0% | 92% | 55% | 0.882 | 0.207 | 3.78 | 31,247 |
| 20% | `trimmed_mean` | 80.6% | 0.684 | 86.7% | 74.6% | +2.3pp | 0% | 100% | 40% | 0.865 | 0.212 | 3.56 | 31,276 |
| 20% | `multi_krum` | 80.2% | 0.679 | 86.2% | 74.2% | +2.7pp | 0% | 86% | 5% | 0.729 | 0.318 | 3.37 | 31,281 |
| 20% | `dso_reputation_eval_gated` | 83.8% | 0.678 | 87.5% | 80.0% | -0.8pp | 0% | 100% | 100% | 0.983 | 0.064 | 5.12 | 31,257 |
| 30% | `mean_baseline` | 75.4% | 0.688 | 85.0% | 65.8% | +7.5pp | 100% | 100% | 100% | 1.000 | 0.000 | 3.15 | 31,317 |
| 30% | `coord_median` | 79.8% | 0.687 | 86.7% | 72.9% | +3.1pp | 0% | 96% | 79% | 0.914 | 0.165 | 3.59 | 31,323 |
| 30% | `trimmed_mean` | 79.6% | 0.686 | 85.4% | 73.8% | +3.3pp | 0% | 99% | 64% | 0.893 | 0.185 | 3.50 | 31,319 |
| 30% | `multi_krum` | 80.6% | 0.678 | 85.8% | 75.4% | +2.3pp | 0% | 92% | 21% | 0.824 | 0.239 | 3.40 | 31,329 |
| 30% | `dso_reputation_eval_gated` | 82.5% | 0.678 | 85.8% | 79.2% | +0.4pp | 0% | 99% | 100% | 0.972 | 0.088 | 5.14 | 31,332 |
| 40% | `mean_baseline` | 64.2% | 0.691 | 78.3% | 50.0% | +18.8pp | 100% | 100% | 100% | 1.000 | 0.000 | 3.36 | 31,375 |
| 40% | `coord_median` | 77.1% | 0.690 | 86.7% | 67.5% | +5.8pp | 8% | 96% | 90% | 0.927 | 0.152 | 3.58 | 31,376 |
| 40% | `trimmed_mean` | 69.0% | 0.690 | 81.7% | 56.2% | +14.0pp | 42% | 99% | 77% | 0.915 | 0.162 | 3.59 | 31,378 |
| 40% | `multi_krum` | 82.3% | 0.678 | 86.7% | 77.9% | +0.6pp | 0% | 99% | 42% | 0.906 | 0.148 | 3.67 | 31,358 |
| 40% | `dso_reputation_eval_gated` | 83.5% | 0.678 | 87.9% | 79.2% | -0.6pp | 0% | 99% | 100% | 0.974 | 0.082 | 4.98 | 31,381 |
| 50% | `mean_baseline` | 46.5% | 0.694 | 54.2% | 38.8% | +36.5pp | 100% | 100% | 100% | 1.000 | 0.000 | 3.08 | 31,483 |
| 50% | `coord_median` | 41.5% | 0.694 | 43.8% | 39.2% | +41.5pp | 96% | 65% | 72% | 0.991 | 0.053 | 3.52 | 31,491 |
| 50% | `trimmed_mean` | 39.6% | 0.695 | 42.9% | 36.2% | +43.3pp | 99% | 60% | 43% | 0.975 | 0.090 | 3.40 | 31,475 |
| 50% | `multi_krum` | 70.4% | 0.688 | 84.2% | 56.7% | +12.5pp | 27% | 92% | 35% | 0.866 | 0.214 | 3.34 | 31,487 |
| 50% | `dso_reputation_eval_gated` | 84.4% | 0.678 | 86.7% | 82.1% | -1.5pp | 0% | 99% | 100% | 0.997 | 0.028 | 4.37 | 31,461 |

### Scenario 2: `colluding_sybil_cartel` (Tightly Clustered Sybil Cartel, $\cos > 0.999$)

| $f$ | Aggregator | Global Acc | Loss | Maj Acc | Min Acc | Deg $\Delta$ | Adv Adm | Maj Acpt | Min Acpt | Jain | Gini | ms/rnd | B/rnd |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0% | `mean_baseline` | 82.9% | 0.678 | 86.7% | 79.2% | +1.3pp | 0% | 100% | 100% | 1.000 | 0.000 | 3.17 | 31,170 |
| 0% | `coord_median` | 81.0% | 0.680 | 88.3% | 73.8% | +3.1pp | 0% | 94% | 21% | 0.847 | 0.230 | 3.61 | 31,162 |
| 0% | `trimmed_mean` | 82.3% | 0.680 | 87.5% | 77.1% | +1.9pp | 0% | 97% | 34% | 0.868 | 0.210 | 4.01 | 31,166 |
| 0% | `multi_krum` | 79.8% | 0.679 | 85.4% | 74.2% | +4.4pp | 0% | 71% | 1% | 0.662 | 0.395 | 3.75 | 31,174 |
| 0% | `dso_reputation_eval_gated` | 84.2% | 0.678 | 87.1% | 81.2% | +0.0pp | 0% | 100% | 100% | 0.985 | 0.063 | 5.24 | 31,168 |
| 10% | `mean_baseline` | 83.3% | 0.682 | 87.5% | 79.2% | +0.8pp | 100% | 100% | 100% | 1.000 | 0.000 | 3.25 | 31,199 |
| 10% | `coord_median` | 81.9% | 0.682 | 87.5% | 76.2% | +2.3pp | 0% | 96% | 38% | 0.863 | 0.218 | 3.39 | 31,218 |
| 10% | `trimmed_mean` | 81.0% | 0.682 | 85.8% | 76.2% | +3.1pp | 0% | 99% | 41% | 0.880 | 0.195 | 3.33 | 31,202 |
| 10% | `multi_krum` | 79.2% | 0.679 | 85.0% | 73.3% | +5.0pp | 0% | 79% | 1% | 0.695 | 0.344 | 3.20 | 31,194 |
| 10% | `dso_reputation_eval_gated` | 83.5% | 0.678 | 85.8% | 81.2% | +0.6pp | 0% | 100% | 100% | 0.982 | 0.067 | 4.93 | 31,194 |
| 20% | `mean_baseline` | 81.7% | 0.686 | 85.8% | 77.5% | +2.5pp | 100% | 100% | 100% | 1.000 | 0.000 | 3.28 | 31,247 |
| 20% | `coord_median` | 80.6% | 0.684 | 85.4% | 75.8% | +3.5pp | 0% | 95% | 54% | 0.867 | 0.217 | 3.41 | 31,231 |
| 20% | `trimmed_mean` | 80.2% | 0.684 | 84.2% | 76.2% | +4.0pp | 0% | 99% | 44% | 0.866 | 0.212 | 3.16 | 31,237 |
| 20% | `multi_krum` | 79.4% | 0.679 | 85.8% | 72.9% | +4.8pp | 0% | 86% | 5% | 0.724 | 0.326 | 3.38 | 31,222 |
| 20% | `dso_reputation_eval_gated` | 82.3% | 0.678 | 86.7% | 77.9% | +1.9pp | 0% | 100% | 100% | 0.983 | 0.065 | 5.33 | 31,237 |
| 30% | `mean_baseline` | 79.6% | 0.690 | 84.2% | 75.0% | +4.6pp | 100% | 100% | 100% | 1.000 | 0.000 | 3.18 | 31,281 |
| 30% | `coord_median` | 75.8% | 0.688 | 82.5% | 69.2% | +8.3pp | 0% | 96% | 74% | 0.907 | 0.178 | 3.29 | 31,273 |
| 30% | `trimmed_mean` | 72.7% | 0.690 | 83.3% | 62.1% | +11.5pp | 3% | 98% | 60% | 0.881 | 0.197 | 3.24 | 31,278 |
| 30% | `multi_krum` | 80.8% | 0.678 | 85.8% | 75.8% | +3.3pp | 0% | 93% | 17% | 0.794 | 0.249 | 3.40 | 31,284 |
| 30% | `dso_reputation_eval_gated` | 82.5% | 0.678 | 87.5% | 77.5% | +1.7pp | 0% | 100% | 100% | 0.980 | 0.071 | 5.75 | 31,280 |
| 40% | `mean_baseline` | 44.8% | 0.693 | 43.3% | 46.2% | +39.4pp | 100% | 100% | 100% | 1.000 | 0.000 | 3.12 | 31,348 |
| 40% | `coord_median` | 54.6% | 0.692 | 69.6% | 39.6% | +29.6pp | 84% | 86% | 68% | 0.927 | 0.159 | 3.91 | 31,327 |
| 40% | `trimmed_mean` | 28.1% | 0.696 | 31.7% | 24.6% | +56.0pp | 100% | 2% | 0% | 0.965 | 0.108 | 3.52 | 31,314 |
| 40% | `multi_krum` | 51.9% | 0.694 | 77.9% | 25.8% | +32.3pp | 51% | 67% | 5% | 0.735 | 0.327 | 3.24 | 31,348 |
| 40% | `dso_reputation_eval_gated` | 83.8% | 0.678 | 86.7% | 80.8% | +0.4pp | 0% | 99% | 100% | 0.970 | 0.091 | 5.03 | 31,312 |
| 50% | `mean_baseline` | 21.5% | 0.698 | 22.1% | 20.8% | +62.7pp | 100% | 100% | 100% | 1.000 | 0.000 | 3.34 | 31,411 |
| 50% | `coord_median` | 17.5% | 0.708 | 15.8% | 19.2% | +66.7pp | 100% | 0% | 0% | 0.964 | 0.108 | 3.22 | 31,417 |
| 50% | `trimmed_mean` | 19.4% | 0.703 | 18.3% | 20.4% | +64.8pp | 100% | 0% | 0% | 0.965 | 0.103 | 3.34 | 31,412 |
| 50% | `multi_krum` | 16.9% | 0.720 | 15.4% | 18.3% | +67.3pp | 100% | 0% | 0% | 0.000 | 1.000 | 3.54 | 31,445 |
| 50% | `dso_reputation_eval_gated` | 83.3% | 0.678 | 86.2% | 80.4% | +0.8pp | 0% | 99% | 100% | 0.997 | 0.031 | 5.08 | 31,405 |

### Scenario 3: `low_quality_noisy` (High-Variance Lazy Freeloaders)

| $f$ | Aggregator | Global Acc | Loss | Maj Acc | Min Acc | Deg $\Delta$ | Adv Adm | Maj Acpt | Min Acpt | Jain | Gini | ms/rnd | B/rnd |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0% | `mean_baseline` | 83.3% | 0.678 | 87.9% | 78.8% | +1.0pp | 0% | 100% | 100% | 1.000 | 0.000 | 3.06 | 31,168 |
| 0% | `coord_median` | 81.5% | 0.680 | 86.7% | 76.2% | +2.9pp | 0% | 98% | 20% | 0.852 | 0.222 | 3.95 | 31,177 |
| 0% | `trimmed_mean` | 83.1% | 0.679 | 88.8% | 77.5% | +1.2pp | 0% | 96% | 31% | 0.869 | 0.206 | 3.54 | 31,179 |
| 0% | `multi_krum` | 78.5% | 0.678 | 85.0% | 72.1% | +5.8pp | 0% | 71% | 2% | 0.699 | 0.349 | 3.23 | 31,166 |
| 0% | `dso_reputation_eval_gated` | 84.4% | 0.678 | 87.9% | 80.8% | +0.0pp | 0% | 100% | 99% | 0.984 | 0.065 | 5.39 | 31,175 |
| 10% | `mean_baseline` | 63.3% | 0.675 | 62.9% | 63.7% | +21.0pp | 100% | 100% | 100% | 1.000 | 0.000 | 3.12 | 31,423 |
| 10% | `coord_median` | 82.7% | 0.680 | 87.1% | 78.3% | +1.7pp | 0% | 97% | 35% | 0.861 | 0.214 | 3.29 | 31,425 |
| 10% | `trimmed_mean` | 82.5% | 0.679 | 87.1% | 77.9% | +1.9pp | 0% | 98% | 59% | 0.907 | 0.171 | 3.40 | 31,423 |
| 10% | `multi_krum` | 79.8% | 0.679 | 87.1% | 72.5% | +4.6pp | 0% | 79% | 1% | 0.696 | 0.350 | 3.21 | 31,417 |
| 10% | `dso_reputation_eval_gated` | 84.0% | 0.678 | 87.5% | 80.4% | +0.4pp | 0% | 99% | 100% | 0.977 | 0.077 | 4.91 | 31,419 |
| 20% | `mean_baseline` | 52.7% | 0.688 | 52.5% | 52.9% | +31.7pp | 100% | 100% | 100% | 1.000 | 0.000 | 3.12 | 31,686 |
| 20% | `coord_median` | 81.0% | 0.680 | 86.7% | 75.4% | +3.3pp | 0% | 98% | 50% | 0.879 | 0.200 | 3.31 | 31,672 |
| 20% | `trimmed_mean` | 82.7% | 0.679 | 87.5% | 77.9% | +1.7pp | 0% | 99% | 90% | 0.932 | 0.145 | 3.20 | 31,661 |
| 20% | `multi_krum` | 80.6% | 0.679 | 85.4% | 75.8% | +3.8pp | 0% | 87% | 2% | 0.717 | 0.319 | 3.24 | 31,681 |
| 20% | `dso_reputation_eval_gated` | 82.1% | 0.678 | 86.7% | 77.5% | +2.3pp | 0% | 99% | 100% | 0.973 | 0.085 | 4.85 | 31,657 |
| 30% | `mean_baseline` | 52.5% | 0.688 | 51.7% | 53.3% | +31.9pp | 100% | 100% | 100% | 1.000 | 0.000 | 3.29 | 31,914 |
| 30% | `coord_median` | 81.0% | 0.679 | 87.1% | 75.0% | +3.3pp | 0% | 100% | 83% | 0.914 | 0.165 | 3.64 | 31,941 |
| 30% | `trimmed_mean` | 81.7% | 0.679 | 85.0% | 78.3% | +2.7pp | 0% | 100% | 96% | 0.965 | 0.107 | 3.50 | 31,929 |
| 30% | `multi_krum` | 79.6% | 0.679 | 85.4% | 73.8% | +4.8pp | 0% | 94% | 15% | 0.794 | 0.253 | 3.31 | 31,944 |
| 30% | `dso_reputation_eval_gated` | 82.5% | 0.678 | 86.7% | 78.3% | +1.9pp | 0% | 98% | 100% | 0.965 | 0.094 | 4.40 | 31,940 |
| 40% | `mean_baseline` | 54.6% | 0.686 | 55.4% | 53.8% | +29.8pp | 100% | 100% | 100% | 1.000 | 0.000 | 3.00 | 32,183 |
| 40% | `coord_median` | 80.4% | 0.680 | 85.0% | 75.8% | +4.0pp | 0% | 100% | 93% | 0.951 | 0.118 | 3.23 | 32,183 |
| 40% | `trimmed_mean` | 76.2% | 0.679 | 80.8% | 71.7% | +8.1pp | 0% | 100% | 100% | 0.991 | 0.051 | 3.39 | 32,197 |
| 40% | `multi_krum` | 82.5% | 0.678 | 86.7% | 78.3% | +1.9pp | 0% | 86% | 77% | 0.985 | 0.065 | 3.28 | 32,193 |
| 40% | `dso_reputation_eval_gated` | 83.1% | 0.678 | 86.2% | 80.0% | +1.2pp | 0% | 99% | 100% | 0.974 | 0.081 | 4.29 | 32,180 |
| 50% | `mean_baseline` | 52.3% | 0.698 | 50.0% | 54.6% | +32.1pp | 100% | 100% | 100% | 1.000 | 0.000 | 3.08 | 32,498 |
| 50% | `coord_median` | 79.6% | 0.680 | 84.2% | 75.0% | +4.8pp | 0% | 100% | 100% | 0.990 | 0.056 | 3.36 | 32,498 |
| 50% | `trimmed_mean` | 68.3% | 0.675 | 66.7% | 70.0% | +16.0pp | 0% | 100% | 100% | 0.998 | 0.024 | 3.35 | 32,484 |
| 50% | `multi_krum` | 82.7% | 0.678 | 85.8% | 79.6% | +1.7pp | 0% | 100% | 100% | 1.000 | 0.000 | 3.28 | 32,488 |
| 50% | `dso_reputation_eval_gated` | 84.6% | 0.678 | 87.9% | 81.2% | -0.2pp | 0% | 100% | 100% | 0.998 | 0.024 | 4.15 | 32,478 |

### Scenario 4: `honest_disagreement_noniid` (Strict 75/25 Specialist Disagreement + Hybrid Byzantine Pressure)

| $f$ | Aggregator | Global Acc | Loss | Maj Acc | Min Acc | Deg $\Delta$ | Adv Adm | Maj Acpt | Min Acpt | Jain | Gini | ms/rnd | B/rnd |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0% | `mean_baseline` | 81.7% | 0.678 | 86.2% | 77.1% | +1.2pp | 0% | 100% | 100% | 1.000 | 0.000 | 3.44 | 29,484 |
| 0% | `coord_median` | 71.0% | 0.682 | 83.8% | 58.3% | +11.9pp | 0% | 96% | 0% | 0.754 | 0.299 | 3.54 | 28,847 |
| 0% | `trimmed_mean` | 72.9% | 0.682 | 85.0% | 60.8% | +10.0pp | 0% | 96% | 0% | 0.778 | 0.276 | 3.21 | 28,986 |
| 0% | `multi_krum` | 72.1% | 0.679 | 84.2% | 60.0% | +10.8pp | 0% | 68% | 0% | 0.684 | 0.377 | 3.63 | 28,940 |
| 0% | `dso_reputation_eval_gated` | 82.9% | 0.678 | 86.7% | 79.2% | +0.0pp | 0% | 100% | 100% | 0.965 | 0.092 | 5.10 | 29,547 |
| 10% | `mean_baseline` | 81.2% | 0.682 | 85.8% | 76.7% | +1.7pp | 100% | 100% | 100% | 1.000 | 0.000 | 3.00 | 29,621 |
| 10% | `coord_median` | 71.0% | 0.683 | 82.5% | 59.6% | +11.9pp | 0% | 95% | 0% | 0.753 | 0.293 | 3.27 | 29,082 |
| 10% | `trimmed_mean` | 71.9% | 0.684 | 85.4% | 58.3% | +11.0pp | 0% | 98% | 0% | 0.775 | 0.272 | 3.36 | 29,124 |
| 10% | `multi_krum` | 71.5% | 0.679 | 85.0% | 57.9% | +11.5pp | 0% | 75% | 0% | 0.718 | 0.333 | 3.23 | 29,184 |
| 10% | `dso_reputation_eval_gated` | 83.3% | 0.678 | 87.5% | 79.2% | -0.4pp | 0% | 100% | 100% | 0.959 | 0.097 | 5.07 | 29,733 |
| 20% | `mean_baseline` | 79.6% | 0.686 | 85.8% | 73.3% | +3.3pp | 100% | 100% | 100% | 1.000 | 0.000 | 3.09 | 29,705 |
| 20% | `coord_median` | 71.0% | 0.685 | 84.6% | 57.5% | +11.9pp | 0% | 93% | 1% | 0.758 | 0.303 | 3.30 | 29,309 |
| 20% | `trimmed_mean` | 70.8% | 0.686 | 82.9% | 58.8% | +12.1pp | 0% | 97% | 0% | 0.770 | 0.286 | 3.28 | 29,348 |
| 20% | `multi_krum` | 72.1% | 0.679 | 86.7% | 57.5% | +10.8pp | 0% | 83% | 0% | 0.740 | 0.298 | 3.04 | 29,419 |
| 20% | `dso_reputation_eval_gated` | 83.1% | 0.678 | 86.2% | 80.0% | -0.2pp | 0% | 100% | 100% | 0.949 | 0.107 | 5.74 | 29,884 |
| 30% | `mean_baseline` | 73.5% | 0.690 | 81.2% | 65.8% | +9.4pp | 100% | 100% | 100% | 1.000 | 0.000 | 3.02 | 29,775 |
| 30% | `coord_median` | 70.2% | 0.688 | 82.1% | 58.3% | +12.7pp | 0% | 94% | 2% | 0.775 | 0.279 | 3.22 | 29,579 |
| 30% | `trimmed_mean` | 63.7% | 0.690 | 81.2% | 46.2% | +19.2pp | 14% | 96% | 0% | 0.755 | 0.305 | 3.28 | 29,778 |
| 30% | `multi_krum` | 71.7% | 0.679 | 86.7% | 56.7% | +11.2pp | 0% | 94% | 0% | 0.757 | 0.269 | 3.39 | 29,692 |
| 30% | `dso_reputation_eval_gated` | 82.5% | 0.678 | 85.8% | 79.2% | +0.4pp | 0% | 100% | 100% | 0.935 | 0.120 | 4.94 | 30,124 |
| 40% | `mean_baseline` | 47.7% | 0.694 | 43.8% | 51.7% | +35.2pp | 100% | 100% | 100% | 1.000 | 0.000 | 2.99 | 30,051 |
| 40% | `coord_median` | 56.0% | 0.693 | 52.9% | 59.2% | +26.9pp | 72% | 69% | 18% | 0.822 | 0.256 | 3.38 | 29,858 |
| 40% | `trimmed_mean` | 31.5% | 0.697 | 34.2% | 28.7% | +51.5pp | 62% | 1% | 0% | 0.919 | 0.168 | 3.26 | 30,323 |
| 40% | `multi_krum` | 21.5% | 0.703 | 22.5% | 20.4% | +61.5pp | 77% | 44% | 0% | 0.663 | 0.397 | 3.43 | 30,442 |
| 40% | `dso_reputation_eval_gated` | 83.1% | 0.678 | 87.9% | 78.3% | -0.2pp | 0% | 100% | 100% | 0.974 | 0.077 | 4.88 | 30,348 |
| 50% | `mean_baseline` | 30.2% | 0.698 | 28.3% | 32.1% | +52.7pp | 100% | 100% | 100% | 1.000 | 0.000 | 2.96 | 30,475 |
| 50% | `coord_median` | 24.4% | 0.704 | 25.4% | 23.3% | +58.5pp | 56% | 0% | 0% | 0.803 | 0.279 | 3.17 | 30,619 |
| 50% | `trimmed_mean` | 23.8% | 0.703 | 23.8% | 23.8% | +59.2pp | 79% | 0% | 0% | 0.824 | 0.262 | 3.30 | 30,610 |
| 50% | `multi_krum` | 17.1% | 0.719 | 18.3% | 15.8% | +65.8pp | 100% | 0% | 0% | 0.000 | 1.000 | 3.28 | 30,676 |
| 50% | `dso_reputation_eval_gated` | 83.1% | 0.678 | 87.5% | 78.8% | -0.2pp | 0% | 100% | 100% | 0.965 | 0.093 | 4.75 | 30,609 |

---

## 3. Honest Negative Regimes

### Regime 1: Geometric-Filter Minority Erasure (Even at $f = 0\%$ Adversaries)

Under `honest_disagreement_noniid` with **zero malicious nodes** (22 honest `protocol_governance` specialists, 8 honest `conservation_science` specialists), classical Byzantine-robust geometric and coordinate filters mistake legitimate minority-domain specialists for outliers:

| Aggregator ($f = 0\%$) | Majority Honest Accept | Minority Honest Accept | Majority Test Acc | Minority Test Acc | Jain Index | Gini |
|---|---:|---:|---:|---:|---:|---:|
| `mean_baseline` | 100% | 100% | 86.2% | 77.1% | 1.000 | 0.000 |
| `coord_median` | 96% | **0%** | 83.8% | **58.3%** | 0.754 | 0.299 |
| `trimmed_mean` | 96% | **0%** | 85.0% | **60.8%** | 0.778 | 0.276 |
| `multi_krum` | 68% | **0%** | 84.2% | **60.0%** | **0.684** | **0.377** |
| `dso_reputation_eval_gated` | 100% | **100%** | 86.7% | **79.2%** | **0.965** | **0.092** |

**Interpretation**: Deploying DeltaSoup's $\beta$-trimmed mean (`zoo-bitdelta-deltasoup.tex`) or Multi-Krum over heterogeneous community domains (such as Zoo's conservation biology nodes alongside a larger protocol/DeFi node base) silently censors minority scientific domains even under 100% honest participation.

### Regime 2: Semantic Backdoor Blindness on Unmonitored Trigger Subdomains

We test a camouflaged backdoor adversary ($f \in \{20\%, 30\%\}$) that submits genuinely helpful local SGD updates on the monitored subspaces (`[0..55]`) while simultaneously poisoning an unmonitored rare trigger subspace (`[62..63]`, strictly absent from `ValProtocol` and `ValConservation`):

| $f$ | Aggregator | Clean Global Acc | Unmonitored Trigger Acc | Backdoor ASR (`1 - TrigAcc`) | Adv Admission |
|---:|---|---:|---:|---:|---:|
| 20% | `mean_baseline` | 82.5% | 0.0% | **100.0%** | 100% |
| 20% | `coord_median` | 82.5% | 48.3% | 51.7% | 0% |
| 20% | `trimmed_mean` | 81.5% | 45.8% | 54.2% | 0% |
| 20% | `multi_krum` | 79.8% | 48.3% | 51.7% | 0% |
| 20% | `dso_reputation_eval_gated` | 83.5% | **0.0%** | **100.0%** | **100%** |
| 30% | `mean_baseline` | 84.0% | 0.0% | **100.0%** | 100% |
| 30% | `coord_median` | 81.5% | 48.3% | 51.7% | 0% |
| 30% | `trimmed_mean` | 81.7% | 0.0% | **100.0%** | 44% |
| 30% | `multi_krum` | 80.6% | 47.5% | 52.5% | 0% |
| 30% | `dso_reputation_eval_gated` | 82.3% | **0.0%** | **100.0%** | **99%** |

**Honest Finding**: `dso_reputation_eval_gated` is **completely blind** (`100.0%` ASR) to semantic backdoors outside the coverage of its held-out validation suite $\mathcal{V}$, whereas `coord_median` and `multi_krum` accidentally suppress the sparse trigger spike at $f = 20\%$ (`51.7%` ASR, random chance on trigger dims because `[62..63]` are zero for the 80% honest majority). Evaluation-gated aggregation therefore **must** be paired with dynamic red-team evaluation expansion or sparse-outlier auditing — it cannot substitute for coverage.

### Regime 3: $50\%$ Byzantine Breakdown, DAO Committee Liveness Collapse & Eval-Set Overfitting

While `dso_reputation_eval_gated` remains accurate at $f = 50\%$ in the main table *only* under the idealized assumption of an uncompromised, unoverfitted validation oracle, removing that assumption exposes three hard breakdown regimes:

| Mode | $f$ | Unseen Test Acc | Val Acc | Goodhart Overfit Gap | Honest Liveness | Adv Approval | Failure Mode |
|---|---:|---:|---:|---:|---:|---:|---|
| `decentralized_committee_66pct_supermajority` | 20% | 83.1% | 84.2% | +1.0pp | 100% | 0% | Safe & live ($f < 33\%$) |
| `decentralized_committee_66pct_supermajority` | 30% | 83.8% | 84.6% | +0.8pp | 99% | 0% | Borderline safe & live ($f < 33\%$) |
| `decentralized_committee_66pct_supermajority` | 40% | **50.6%** | 45.8% | -4.8pp | **0%** | 0% | **Liveness collapse** (Byzantine abstention blocks 66% quorum) |
| `decentralized_committee_66pct_supermajority` | 50% | **50.6%** | 45.8% | -4.8pp | **0%** | 0% | **Liveness collapse** |
| `decentralized_committee_50pct_majority` | 50% | **45.0%** | 43.3% | -1.7pp | 100% | **100%** | **Safety collapse** (50% bloc self-approves poisoned updates) |
| `static_small_eval_goodhart_overfit_30r` | 50% | **65.2%** | **100.0%** | **+34.8pp** | 14% | **71%** | **Goodhart overfitting** (adaptive probing exploits static 20-item val set) |

**Honest Finding**: This confirms empirically why `experience-ledger-dso` Theorem 2 ($2f + 1$ honest voters out of $n = 3f + 1$) is a hard ceiling for DAO-governed curation: above $f = 33\%$, a 66% quorum stalls liveness completely (`0%` honest admission); lowering the quorum to 50% immediately collapses safety (`45.0%` test acc); and exposing a small static validation set to adaptive probing lets adversaries achieve `100.0%` validation accuracy while degrading unseen test accuracy by `34.8pp`.

---

## 4. What Remains Unproven / Open Research Gaps

This benchmark provides deterministic, cryptographically auditable evidence over a 64-dimensional linear-logistic Bradley-Terry preference model grounded in 88 real `.tex` papers. The following critical questions **remain unproven** and are explicitly out of scope for `dso-aggregation.v1`:

1. **Full Generative LLM Introspection & Prompt-Injection Attacks**: Our `ExperienceOp` validator checks syntactic constraints from `experience-ledger-dso` Section 3 ($\le 32$ words, actionable prefix, paper anchor) while evaluating policy deltas quantitatively. We do **not** evaluate live multi-billion-parameter LLMs consuming injected natural-language rules in-context, where adversarial prose can hijack attention weights or bypass semantic judges without shifting low-dimensional feature vectors.
2. **Non-Convex Deep Neural Adapter Manifolds (LoRA / BitDelta)**: Linear logistic preference models have convex per-round loss landscapes. Deep transformer adapters (e.g., 1-bit BitDelta sign matrices or rank-$r$ LoRA layers) exhibit permutation symmetries, mode connectivity gaps, and non-linear interference where individually beneficial deltas can interact destructively after averaging.
3. **Adaptive White-Box / Sleeper Sybil Adversaries**: Our Sybil cartel uses tight static clustering ($\cos > 0.999$) detectable via pairwise cosine discounting. An adaptive Sybil coalition that intentionally spreads updates across orthogonal low-impact dimensions (staying below $\cos = 0.97$), or "sleeper" adversaries that build high reputation over 20 honest rounds before executing a synchronized single-round poison strike, remain open attack surfaces.
4. **Private / Encrypted Held-Out Evaluation (ZKML / FHE)**: Preventing Goodhart overfitting (Regime 3) requires rotating, secret held-out validation shards that contributors cannot probe adaptively. Proving *correctness of held-out evaluation scores without revealing the validation set* requires TEE attestation, FHE (`zoo-fhe-ai`), or succinct ZKML proofs (`zoo-zchain-zkp`), none of which are implemented in this zero-dependency reference harness.
5. **Economic Incentive Compatibility & Collusion-Proof Valuation**: We model online reputation slashing mechanically, not game-theoretically. Proving that KEEPER staking, quadratic voting (`experience-ledger-dso` Section 6), and DeltaSoup royalty splits (`zoo-ai-research-agenda` Theorem 4.2) form a Bayes-Nash equilibrium against bribed evaluators or liquid-staking cartels remains an open mechanism-design problem.
6. **Dynamic Domain Discovery & Minority Granularity**: Our minority-preservation floor assumes known domain tags (`protocol_governance`, `conservation_science`) with stratified validation sets. In an open-ended research commons where new scientific subfields emerge organically (without pre-provisioned validation shards), distinguishing a *brand-new legitimate niche domain* from a *targeted semantic backdoor* (Regime 2) remains fundamentally unresolved.

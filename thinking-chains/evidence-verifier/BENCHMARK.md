# Open Evidence & Reasoning Verification — Benchmark & Error Analysis

- **Issue**: `zoo-apps/papers#8` (`HIP-1352` — *Open evidence and reasoning verification*)
- **Dataset**: [`dataset/benchmark-claims.v1.json`](dataset/benchmark-claims.v1.json) (`120` labeled public claims, `30` per class, `--seed 1352`)
- **Pinned Corpus**: [`dataset/corpus-manifest.json`](dataset/corpus-manifest.json) (`8` real `.tex` papers from `zoo-apps/papers` at commit `e12b0a1`)
- **Machine-Readable Output**: [`results.json`](results.json)
- **Canonical Audit Commitment (`audit_merkle_root`)**:
  `2f3e7dd02712ce5388da5483d562d9389eb1c2bea00d0d8af5cc2ed7affdc2a6`
- **Cross-Language Parity (Go 1.24 stdlib ↔ Python 3.12 stdlib)**: **120 / 120 (100.00%) bit-identical** (`verdict`, `reason_code`, `detail`, `computed_value`, `evidence_sha256`, `result_digest`, and `audit_merkle_root`)

---

## 1. Reproducing the Benchmark

All commands run with **zero external dependencies** (Go 1.24 stdlib + Python 3.12 stdlib):

```bash
cd thinking-chains/evidence-verifier

# 1. Verify pinned SHA-256 digests of all 8 real zoo-apps/papers .tex sources
(cd go && go run ./cmd/verifier manifest --corpus ../../.. --dataset ../dataset/benchmark-claims.v1.json)

# 2. Run Go verifier benchmark (--seed 1352) and write results.json
(cd go && go run ./cmd/verifier benchmark --corpus ../../.. --dataset ../dataset/benchmark-claims.v1.json --seed 1352 --out ../results.json)

# 3. Verify 120/120 bit-identical Go <-> Python parity and Merkle root
PYTHONPATH=python python3 -m evidence_verifier.cli parity --corpus ../.. --dataset dataset/benchmark-claims.v1.json --go-report results.json

# 4. Run full test suites (with Go race detector)
(cd go && go vet ./... && go test -v -race -count=1 ./...)
(cd python && python3 -m unittest discover -s tests -v)
```

---

## 2. Corpus & Benchmark Composition

### 2.1 Pinned Real `.tex` Corpus (`corpus-manifest.json`)

| Doc ID | Path in `zoo-apps/papers` | Pinned SHA-256 (prefix) |
| :--- | :--- | :--- |
| `DOC-TC-CORE` | `thinking-chains/thinking-chains.tex` | `11098056fe62731a...` |
| `DOC-TC-CONST` | `thinking-chains/sections/15-constitutional-rules.tex` | `7aed8a39019d2551...` |
| `DOC-TC-FAIL` | `thinking-chains/sections/19-failure-modes.tex` | `974d1718ead8489b...` |
| `DOC-BITDELTA` | `zoo-bitdelta-deltasoup/zoo-bitdelta-deltasoup.tex` | `4d92cf43dfaa7b47...` |
| `DOC-RDAO` | `zoo-dao-research-governance/zoo-dao-research-governance.tex` | `19c36e73021564da...` |
| `DOC-QUASAR` | `zoo-quasar-benchmarks/zoo-quasar-benchmarks.tex` | `7246426d78991f8e...` |
| `DOC-EVM` | `zoo-evm-benchmarks/zoo-evm-benchmarks.tex` | `fc36619e55c28f44...` |
| `DOC-EXPLEDGER` | `experience-ledger-dso/experience-ledger-dso.tex` | `efd1f0525d669286...` |

### 2.2 Ground-Truth Distribution (`N = 120`, Seed `1352`)

| Claim Class | `VERIFIED` | `REFUTED` | `UNSUPPORTED` | `INCONCLUSIVE` | Total | Negative-Regime Claims Included |
| :--- | ---: | ---: | ---: | ---: | ---: | :--- |
| `citation_check` | 15 | 7 | 4 | 4 | **30** | 5 `semantic_paraphrase`, 2 `cherry_picking_omitted_caveat` |
| `calc_check` | 13 | 9 | 5 | 3 | **30** | 1 `tolerance_boundary` |
| `code_result_check` | 14 | 8 | 4 | 4 | **30** | 4 `stochastic_hardware_drift` |
| `reasoning_chain_check` | 11 | 8 | 7 | 4 | **30** | 1 `cherry_picking_omitted_caveat` |
| **Total** | **53** | **32** | **20** | **15** | **120** | **13 structural-limit stress cases** |

---

## 3. Summary Results

| Metric | Value | Notes |
| :--- | ---: | :--- |
| **Total Labeled Claims** | `120` | 30 per class, 100% label-blind verification verified by test |
| **Exact Verdict Accuracy (All Regimes)** | **89.17%** (`107 / 120`) | Standard-regime slice: **100.00%** (`107 / 107`) |
| **Macro Precision** | **0.8825** | Unweighted mean across all 4 verdict classes |
| **Macro Recall** | **0.8789** | Unweighted mean across all 4 verdict classes |
| **Macro F1** | **0.8713** | Unweighted mean across all 4 verdict classes |
| **Mechanical False Verification Rate (Mechanical FVR)** | **0.00%** (`0 / 52`) | **Zero** fabricated citations, arithmetic errors, tampered digests, cycles, or constitutional violations passed |
| **Overall False Verification Rate (Overall FVR)** | **4.48%** (`3 / 67`) | All 3 cases are **Negative Regime 3 (Cherry-Picking)** where local facts/DAGs are mechanically true |
| **False Rejection Rate (FRR)** | **15.09%** (`8 / 53`) | 5 heavy paraphrases + 2 stochastic FP16 hash drifts + 1 display-rounding tolerance mismatch |
| **Go 1.24 Throughput** | **4,898 claims/sec** | `24.50 ms` wall clock (incl. disk I/O + SHA-256 of 8 `.tex` files) |
| **Python 3.12 Throughput** | **3,805 claims/sec** | `31.54 ms` wall clock |
| **Go ↔ Python Parity** | **120 / 120 (100.00%)** | Bit-identical `results` & `audit_merkle_root` |

---

## 4. Full 4×4 Confusion Matrix

Rows = Ground Truth (`expected_verdict`); Columns = Verifier Prediction (`predicted_verdict`).

| Ground Truth \ Predicted | `VERIFIED_REPRODUCIBLE` | `REFUTED_CONTRADICTION` | `UNSUPPORTED_INSUFFICIENT_EVIDENCE` | `INCONCLUSIVE_NEEDS_HUMAN_REVIEW` | Row Support |
| :--- | ---: | ---: | ---: | ---: | ---: |
| **`VERIFIED_REPRODUCIBLE`** | **45** | 3 | 4 | 1 | 53 |
| **`REFUTED_CONTRADICTION`** | 0 | **32** | 0 | 0 | 32 |
| **`UNSUPPORTED_INSUFFICIENT_EVIDENCE`** | 0 | 0 | **20** | 0 | 20 |
| **`INCONCLUSIVE_NEEDS_HUMAN_REVIEW`** | 3 | 0 | 2 | **10** | 15 |
| **Column Total** | 48 | 35 | 26 | 11 | **120** |

---

## 5. Per-Verdict Precision, Recall, and F1

| Verdict Class | TP | FP | FN | Support | Precision | Recall | F1 |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `VERIFIED_REPRODUCIBLE` | 45 | 3 | 8 | 53 | 0.9375 | 0.8491 | **0.8911** |
| `REFUTED_CONTRADICTION` | 32 | 3 | 0 | 32 | 0.9143 | 1.0000 | **0.9552** |
| `UNSUPPORTED_INSUFFICIENT_EVIDENCE` | 20 | 6 | 0 | 20 | 0.7692 | 1.0000 | **0.8696** |
| `INCONCLUSIVE_NEEDS_HUMAN_REVIEW` | 10 | 1 | 5 | 15 | 0.9091 | 0.6667 | **0.7692** |
| **Macro Average** | — | — | — | 120 | **0.8825** | **0.8789** | **0.8713** |

---

## 6. Per-Claim-Class Performance Breakdown

| Claim Class | Total | Correct | Accuracy | Mechanical FVR | Overall FVR | FRR | False Verified | False Rejected |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `citation_check` | 30 | 23 | 76.67% | **0.00%** | 13.33% | 33.33% | 2 | 5 |
| `calc_check` | 30 | 29 | 96.67% | **0.00%** | 0.00% | 7.69% | 0 | 1 |
| `code_result_check` | 30 | 26 | 86.67% | **0.00%** | 0.00% | 14.29% | 0 | 2 |
| `reasoning_chain_check` | 30 | 29 | 96.67% | **0.00%** | 5.26% | 0.00% | 1 | 0 |

---

## 7. Detailed Error Analysis & Honest Negative Regimes

Every single one of the **13 misclassifications** occurs exclusively inside the explicitly engineered **negative-regime stress slices** (standard-regime accuracy is `107 / 107 = 100.00%`). Below is the complete error table followed by root-cause analysis of each structural limit.

| Claim ID | Class | Negative Regime | Ground Truth | Predicted | Reason Code | Error Category |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `CIT-024` | `citation_check` | `semantic_paraphrase` | `VERIFIED` | `UNSUPPORTED` | `ERR_QUOTE_NOT_FOUND` | False Rejection |
| `CIT-025` | `citation_check` | `semantic_paraphrase` | `VERIFIED` | `UNSUPPORTED` | `ERR_QUOTE_NOT_FOUND` | False Rejection |
| `CIT-026` | `citation_check` | `semantic_paraphrase` | `VERIFIED` | `UNSUPPORTED` | `ERR_QUOTE_NOT_FOUND` | False Rejection |
| `CIT-027` | `citation_check` | `semantic_paraphrase` | `VERIFIED` | `UNSUPPORTED` | `ERR_QUOTE_NOT_FOUND` | False Rejection |
| `CIT-028` | `citation_check` | `semantic_paraphrase` | `VERIFIED` | `INCONCLUSIVE` | `ERR_PARAPHRASE_NEEDS_HUMAN_REVIEW` | False Rejection (Escalated) |
| `CIT-029` | `citation_check` | `cherry_picking_omitted_caveat` | `INCONCLUSIVE` | `VERIFIED` | `OK_CITATION_VERIFIED` | **False Verification** |
| `CIT-030` | `citation_check` | `cherry_picking_omitted_caveat` | `INCONCLUSIVE` | `VERIFIED` | `OK_CITATION_VERIFIED` | **False Verification** |
| `CALC-030` | `calc_check` | `tolerance_boundary` | `VERIFIED` | `REFUTED` | `ERR_CALC_MISMATCH` | False Rejection |
| `CODE-027` | `code_result_check` | `stochastic_hardware_drift` | `VERIFIED` | `REFUTED` | `ERR_ARTIFACT_HASH_MISMATCH` | False Rejection |
| `CODE-028` | `code_result_check` | `stochastic_hardware_drift` | `VERIFIED` | `REFUTED` | `ERR_ARTIFACT_HASH_MISMATCH` | False Rejection |
| `CODE-029` | `code_result_check` | `stochastic_hardware_drift` | `INCONCLUSIVE` | `UNSUPPORTED` | `ERR_STOCHASTIC_REQUIRES_INTERVAL` | Over-Strict Rejection |
| `CODE-030` | `code_result_check` | `stochastic_hardware_drift` | `INCONCLUSIVE` | `UNSUPPORTED` | `ERR_STOCHASTIC_REQUIRES_INTERVAL` | Over-Strict Rejection |
| `CHAIN-030` | `reasoning_chain_check` | `cherry_picking_omitted_caveat` | `INCONCLUSIVE` | `VERIFIED` | `OK_REASONING_CHAIN_VERIFIED` | **False Verification** |

### Negative Regime 1: Semantically Valid Paraphrases vs Strict Lexical/Span Matching (`CIT-024`–`CIT-028`)

- **Empirical Result**: `0 / 5` automatically verified (`4` predicted `UNSUPPORTED_INSUFFICIENT_EVIDENCE`, `1` escalated to `INCONCLUSIVE_NEEDS_HUMAN_REVIEW`). Meanwhile, Mechanical FVR on fabricated/altered quotes is **0.00% (`0 / 11`)**.
- **Mechanism**: Claims such as `"0.01 seconds"` vs `"10ms"` (`CIT-024`), `"700 megabytes"` vs `"0.7GB"` (`CIT-026`), or `"five-hundred-fold lower expense"` vs `"0.2% of the cost"` (`CIT-027`) are semantically faithful to the pinned `.tex` sources, yet share no exact substring after LaTeX normalization.
- **Design Trade-off**: Without an NLI model or LLM judge (explicitly forbidden inside consensus by Constitutional Rule 10), deterministic citation verification intentionally sacrifices recall on heavy paraphrases in exchange for **zero false verifications** on hallucinated quotes. When `require_exact_span=false` and token overlap is moderate with consistent numbers (`CIT-028`), the verifier escalates cleanly to `INCONCLUSIVE_NEEDS_HUMAN_REVIEW` rather than fabricating confidence.

### Negative Regime 2: Stochastic / Hardware-Dependent ML Benchmarks (`CODE-027`–`CODE-030`)

- **Empirical Result**: `2 / 2` stochastic runs submitted with exact SHA-256 digests (`CODE-027`, `CODE-028`) failed with `ERR_ARTIFACT_HASH_MISMATCH` due to 1-ULP / `1e-5` floating-point reduction drift across GPU architectures (A100 vs H100). `2 / 2` stochastic runs lacking statistical intervals (`CODE-029`, `CODE-030`) were rejected as `UNSUPPORTED_INSUFFICIENT_EVIDENCE` (`ERR_STOCHASTIC_REQUIRES_INTERVAL`). By contrast, `3 / 3` stochastic runs that declared valid raw samples and 95% confidence intervals (`CODE-010`, `CODE-011`, `CODE-012`) verified cleanly as `VERIFIED_REPRODUCIBLE`.
- **Takeaway**: Directly validates Principle 1 (*The Law of Cognition*) of `thinking-chains.tex`: floating-point inference on heterogeneous GPU hardware cannot be verified by byte-exact hashes and **must** commit to bounded statistical intervals (`mode: "statistical_interval"`), attested execution, or fixed-point deterministic kernels.

### Negative Regime 3: Sophisticated Cherry-Picking — True Quotes, Misleading Framing (`CIT-029`, `CIT-030`, `CHAIN-030`)

- **Empirical Result**: `3 / 3` cherry-picking claims passed all mechanical checks (`VERIFIED_REPRODUCIBLE`), accounting for **100% of all False Verifications (`3 / 3`)** in the entire 120-claim benchmark!
  - `CIT-029` quotes the exact Hoeffding quorum capture bound from `thinking-chains.tex` while claiming stake-weighted committees inherit it—omitting the load-bearing *Weighting caveat* on line 294 (`"It does not hold for committees sampled proportional to weight and certified by weight"`).
  - `CIT-030` quotes the exact `47.6 million TPS` raw GPU execution throughput from `zoo-evm-benchmarks.tex` while omitting the `10x` lower `4.76 million TPS` Quasar finality cap in the very same abstract.
  - `CHAIN-030` constructs a clean, acyclic 3-step DAG over verified `CIT-004` (`Lemma: Dissent-safety`) to conclude that minority reporting is costless and strictly incentive-compatible—omitting the *Scope (honest)* caveat on line 335 documenting EMA reputation decay and beauty-contest equilibria.
- **Structural Limit**: Mechanical fact, arithmetic, and DAG-closure verification proves **local consistency with pinned bytes**, NOT global epistemic completeness or pragmatic fidelity. Detecting cross-paragraph caveat omissions requires human domain review, adversarial red-team committees, or explicit caveat-linking schemas.

### Calibration Note: Display-Rounding Tolerance Boundary (`CALC-030`)

- `CALC-030` evaluates `47619 / 0.01 = 4,761,900` against the paper's 3-significant-figure display figure `4.76M` (`4,760,000`, relative error `0.000399`) under a naive `1e-5` relative tolerance policy, producing `ERR_CALC_MISMATCH`. Authors and verifiers must explicitly declare rounding precision (`tolerance_mode: "rel"`, e.g. `1e-3` for 3-sig-fig tables) alongside exact underlying formulas.

---

## 8. What Remains Unproven / Open Research Gaps

Per HIP-1352 and Zoo Research DAO standards, we explicitly state what this verifier and benchmark do **not** prove:

1. **Pragmatic & Discourse-Level Entailment**: Deterministic span + numeric + clause-polarity checks cannot detect omitted cross-section caveats (Negative Regime 3), subtle quantifier shifts (`"some"` → `"all"` across paraphrased clauses), or cherry-picked baselines. Closing this gap without violating Constitutional Rule 10 (LLM-free deterministic consensus) remains an open research problem—likely requiring structured claim-caveat graphs or human-reviewed adversarial counter-claims.
2. **Semantic Paraphrase Equivalence Without Neural Judges**: Achieving high recall on legitimate heavy paraphrases (Negative Regime 1) while maintaining `0.00%` Mechanical FVR without invoking non-deterministic LLM/NLI models remains unproven. Canonical unit-normalizing parsers and formal citation ontologies could narrow, but not eliminate, this gap.
3. **General Arbitrary Code Execution Sandboxing**: `code_result_check` currently executes a fixed set of 7 pure-stdlib deterministic kernels (`sha256_canonical`, `merkle_root`, `bitdelta_scale`, `trimmed_mean`, `linear_reward`, `sortition_check`, `eval_expr`) plus content-addressed artifact hashes and statistical intervals. Verifying arbitrary third-party Python/C++/CUDA training scripts requires deterministic container/WASM/zkVM sandboxing (e.g., P3Q STARK proofs or reproducible Nix builds), which is outside this zero-dependency verifier's scope.
4. **Statistical P-Hacking & Cherry-Picked Sample Seeds**: `statistical_interval` verifies that a claimed mean and 95% confidence interval are mathematically consistent with the *submitted* sample array, but cannot prove the author did not discard unfavorable random seeds before submission (selective reporting / file-drawer bias). Defending against seed cherry-picking requires pre-registered VRF/commit-reveal evaluation seeds.
5. **External-World Ground Truth & Corpus Provenance**: `citation_check` verifies cryptographic fidelity to pinned `.tex` files in `zoo-apps/papers`, not whether the empirical claims *inside* those source papers were themselves faithfully measured on real hardware. Verifying upstream experimental validity requires independent replication and signed hardware/TEE attestations.
6. **Logical Validity of Natural-Language Inference Steps**: `reasoning_chain_check` proves DAG acyclicity, absence of private/opaque CoT blobs, constitutional separation (`author_id != verifier_id`), and groundedness of all leaf premises—but does **not** formally prove deductive soundness of natural-language `public_rationale` transitions (which would require mechanized proof assistants such as Lean 4 / Coq).

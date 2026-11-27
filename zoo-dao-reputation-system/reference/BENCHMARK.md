# Scientific Contribution Attribution & Reputation Benchmark (`attribution-rep.v1`)

- **Issue**: `zoo-apps/papers#11` (HIP-1352)
- **Seed**: `--seed 1352`
- **Corpus Manifest SHA-256**: `1f06f3b074c8036afd8b15cae246a949faa25c35662d6be89c07762935d12963` (12 real `.tex` papers from `zoo-apps/papers`)
- **Published Suite**: `fixtures/attribution-suite.v1.json` (**207** DAG events: `65` contributions + `142` EAS attestations; **32** explicit adversarial checks)
- **Go ↔ Python Parity**: **100.0% bit-identical** (`audit_merkle_root = 7b4cb61df81118215c869d9c37cfcff8515b78f171404d8bcbcd717d6f742b5d`)

---

## 1. Published Suite Summary (`--seed 1352`)

| Metric | Value |
|---|---|
| Grounded Corpus Papers | 12 real `.tex` papers (`corpus-manifest.json`) |
| Total DAG Events | **207** (`65` contributions + `142` EAS attestations) |
| Contributions Accepted / Rejected | `50` accepted / `15` rejected |
| Attestations Accepted / Advisory / Rejected | `126` accepted / `2` AI advisory / `14` rejected |
| Adversarial Copy & Collusion Checks | **32 / 32 PASSED (100.0%)** |
| Exact Credit Conservation | **`true`** (`42,223,800 == 42,223,800` micro-credits; naive = `64,000,000`) |
| Collusion Rings & Sybil Clusters Detected | `3` (2-node pair, 5-node ring, 20-account Sybil farm) |
| Go ↔ Python Bit-Identical Audit Root | `7b4cb61df81118215c869d9c37cfcff8515b78f171404d8bcbcd717d6f742b5d` |

---

## 2. Three Explicit Honest Negative Regimes

| Negative Regime | Baseline Failure (Unprotected) | Protected Result (`attribution-rep.v1`) | Status |
|---|---|---|---|
| **`neg_naive_count_collusion_inflation`** | 20-Sybil farm elevates `mallory_sybil_boss` to **Rank `#1`** (`4,050` pts = **`4.05x`** top genuine researcher `res_06` at `1,000` pts) | Seeded EigenTrust + sub-stochastic cluster cap holds `mallory_sybil_boss` to **`0` ZooRep (`0.000%` of `res_06`)**, Rank `#18` (`Observer`); even under a 1-fringe-bridge attack, Sybil gain stays **`0.040%` (`< 1%`)** | **PASS** |
| **`neg_unweighted_copy_double_counting`** | Across 10 real-paper canonical artifacts + 10 copies (5 exact, 3 reformatted, 2 patch-85%), naive credit inflates `10.000000 -> 20.000000` (**`2.00x` double-counting**) | Canonical-digest + Winnowing novelty-delta holds exact **`9.989400 -> 9.989400`** (**`1.00x` conservation**; **`0` micro-credits** to all 10 copies) | **PASS** |
| **`neg_honest_newcomer_cold_start_lag`** | Under strict seeded trust gating, `newcomer_honest` with `0` seed edges (1 unseeded peer review) retains `1,000,000` attribution micro-credits but suffers cold-start lag: **`0` EigenTrust, `0` ZooRep (`Observer 1.0x`, Rank `#19`)** | Upon receiving **`1`** independent seeded replication attestation (`seed_01`), EigenTrust jumps to **`6,743`** micro-units and ZooRep rises to **`67` pts (`Contributor 1.2x`, Rank `#17`)** — honestly quantifying the security-vs-onboarding trade-off | **PASS** |

---

## 3. Top Rankings Comparison (Seeded Sybil-Resistant vs Naive Unweighted)

| Protected Rank | Identity | Role | Accepted Papers | Attribution (credits) | Upstream Flow (credits) | EigenTrust (micro) | Protected ZooRep | ZIP-0026 Tier | Naive Attestations | Naive Score | Naive Rank |
|---:|---|---|---:|---:|---:|---:|---:|---|---:|---:|---:|
| 1 | `res_06` | `RESEARCHER` | 4 | 3.066929 | 0.367889 | 83,189 | **569** | Guardian (`2.0x`) | 8 | 1,000 | 3 |
| 2 | `res_05` | `RESEARCHER` | 4 | 2.970824 | 0.350954 | 78,983 | **543** | Guardian (`2.0x`) | 8 | 1,000 | 2 |
| 3 | `res_07` | `RESEARCHER` | 4 | 3.101421 | 0.334721 | 77,063 | **540** | Guardian (`2.0x`) | 7 | 900 | 4 |
| 4 | `seed_01` | `SEED_STEWARD` | 1 | 1.222420 | 0.222420 | 83,091 | **476** | Steward (`1.5x`) | 2 | 250 | 15 |
| 5 | `res_11` | `RESEARCHER` | 3 | 2.052550 | 0.000000 | 65,691 | **431** | Steward (`1.5x`) | 6 | 750 | 8 |
| 6 | `res_09` | `RESEARCHER` | 3 | 2.315665 | 0.043255 | 62,426 | **427** | Steward (`1.5x`) | 6 | 750 | 6 |
| 7 | `res_10` | `RESEARCHER` | 3 | 2.256987 | 0.041527 | 61,178 | **418** | Steward (`1.5x`) | 6 | 750 | 7 |
| 18 | `mallory_sybil_boss` | `RESEARCHER` | 1 | 1.000000 | 0.000000 | **0** | **0** | Observer (`1.0x`) | **40** | **4,050** | **1** |

Notice how `mallory_sybil_boss` captures **Rank `#1`** under naive counting (`40` Sybil attestations -> `4,050` pts), while under `attribution-rep.v1` genuine prolific researchers (`res_06`, `res_05`, `res_07`) hold Ranks `#1–#3` (`Guardian 2.0x`) and `mallory_sybil_boss` receives **`0` ZooRep**!

---

## 4. Adversarial Attack Suite Coverage (32 / 32 Caught)

| Category | Attack IDs | Vectors Tested | Error Codes Verified | Result |
|---|---|---|---|---|
| **Copy & Plagiarism** (`8`) | `ATK-01`..`ATK-07`, `ATK-28` | Exact verbatim copies (x2), whitespace/comment/LaTeX-macro reformats (x2), 85%-copied patch plagiarism claiming 100% credit (x2), undeclared 65% copy, attesting rejected copy | `ERR_DUPLICATE_CONTRIBUTION`, `ERR_REFORMATTED_COPY`, `ERR_NEAR_DUPLICATE_COPY`, `ERR_UNDECLARED_COPY`, `ERR_REF_NOT_ACCEPTED` | **8 / 8 PASS** |
| **Causality & DAG** (`5`) | `ATK-08`..`ATK-12` | 2-node citation cycle (`A <-> B`), self-cycle (`C -> C`), ledger timestamp backdating, child-before-parent backdating | `ERR_CAUSALITY_CYCLE`, `ERR_TIMESTAMP_BACKDATE` | **5 / 5 PASS** |
| **Crypto & Integrity** (`5`) | `ATK-13`..`ATK-15`, `ATK-26`..`ATK-27` | Forged Ed25519 contribution sig, tampered `canonical_digest`, tampered `winnow_fingerprint`, forged EAS Ed25519 sig impersonating `seed_01`, tampered `AttestationUID` | `ERR_INVALID_SIGNATURE`, `ERR_CONTENT_DIGEST_MISMATCH`, `ERR_FINGERPRINT_MISMATCH`, `ERR_ATTESTATION_UID_MISMATCH` | **5 / 5 PASS** |
| **Collusion & EAS Abuse** (`10`) | `ATK-16`..`ATK-25` | 20-account Sybil farm, 2-node mutual-admiration pair, 5-node endorsement ring, self-attestation loops (x2), cross-epoch replay, nonce replay, inline revoked EAS, registry revoked EAS, expired EAS | `ERR_SYBIL_CLUSTER_CAPPED`, `ERR_COLLUSION_RING_DISCOUNTED`, `ERR_SELF_ATTESTATION`, `ERR_ATTESTATION_REPLAY`, `ERR_REVOKED_ATTESTATION`, `ERR_EXPIRED_ATTESTATION` | **10 / 10 PASS** |
| **AI Constitutional Guards** (`4`) | `ATK-29`..`ATK-32` | `AI_AGENT` direct self-attestation, `AI_AGENT` own-paper indirect self-attestation, `AI_AGENT` policy rule mutation, `AI_AGENT` treasury authorization | `ERR_AI_SELF_ATTEST_FORBIDDEN`, `ERR_AI_POLICY_MUTATION_FORBIDDEN`, `ERR_AI_TREASURY_FORBIDDEN` | **4 / 4 PASS** |

---

## 5. Reproducibility Commands

```bash
# 1. Regenerate corpus manifest, published fixture, and benchmark results deterministically
(cd zoo-dao-reputation-system/reference/go && go run ./cmd/attr-bench --seed 1352)

# 2. Run Go vet + full test suite with race detector
(cd zoo-dao-reputation-system/reference/go && go vet ./... && go test -v -race -count=1 ./...)

# 3. Run pure-Python stdlib verifier + RFC 8032 Ed25519 + Go-Python parity tests
(cd zoo-dao-reputation-system/reference/python && python3 -m unittest discover -v)

# 4. Run standalone Go and Python CLI verifiers side-by-side
(cd zoo-dao-reputation-system/reference/go && go run ./cmd/attr-verify --suite ../fixtures/attribution-suite.v1.json --summary)
(cd zoo-dao-reputation-system/reference/python && python3 -m attrrep_py.cli --suite ../fixtures/attribution-suite.v1.json --summary)
```

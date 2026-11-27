# Reproducible Test-Network Benchmark: Useful-Work Receipts & Contribution Settlement

- **Protocol**: `settlement-receipt.v1` (`v1.0.0`)
- **Issue / HIP**: `zoo-apps/papers#15` (`HIP-1350`)
- **Seed**: `--seed 1350`
- **Machine-Readable Results**: [`results.json`](results.json)
- **Canonical Verification Trace**: [`fixtures/settlement-trace.v1.json`](fixtures/settlement-trace.v1.json)
- **Corpus Manifest**: [`corpus-manifest.json`](corpus-manifest.json) (`SHA-256: 2611893d456ae091fb593798ff5ab6524ede0550a3a0ae1014dfe15b9792db99`)
- **Audit Merkle Root (Go & Python Bit-Identical)**: `0cac816fdf6e2333a04b02f373a59a2ca5f2fffba623f7f44deb7a50ecf5aa0b`

---

## 1. Reproducibility Commands

Run from `zoo-hanzo-settlement/reference/`:

```bash
# 1. Regenerate benchmark results.json and canonical trace fixture (--seed 1350)
(cd go && go run ./cmd/settle-bench --seed 1350)

# 2. Run Go vet and full -race test suite (16 tests, 0 external deps)
(cd go && go vet ./... && go test -v -race -count=1 ./...)

# 3. Independently verify trace bundle with Go CLI
(cd go && go run ./cmd/settle-verify --trace ../fixtures/settlement-trace.v1.json)

# 4. Independently verify trace bundle with Pure Python 3.12 stdlib CLI (0 external deps)
(cd python && python3 -m settlement_verifier.cli --trace ../fixtures/settlement-trace.v1.json)

# 5. Run Python unittest suite (includes RFC 8032 vectors + live Go<->Python parity check)
(cd python && python3 -m unittest discover -v)
```

---

## 2. Corpus Grounding (`corpus-manifest.json`)

Every useful-work job in the benchmark slices a deterministic 256-byte workload chunk from one of 8 pinned real `.tex` papers in `zoo-apps/papers`, binding `work_hash` to the verified file SHA-256 digest and metering compute using the 4 model tiers from `zoo-hanzo-settlement.tex` Table 1:

| Paper ID | Repository Path | Bytes | Verified SHA-256 Prefix |
| :--- | :--- | ---: | :--- |
| `zoo-hanzo-settlement` | `zoo-hanzo-settlement/zoo-hanzo-settlement.tex` | 19,226 | `ea09c4bd97e245bc...` |
| `zoo-poai-consensus` | `zoo-poai-consensus/zoo-poai-consensus.tex` | 7,168 | `67827960ee82529c...` |
| `zoo-gym-compute-proof` | `zoo-gym-compute-proof/zoo-gym-compute-proof.tex` | 32,499 | `dfd4506a2f90161d...` |
| `zoo-fund-validator-rewards` | `zoo-fund-validator-rewards/zoo-fund-validator-rewards.tex` | 29,017 | `8c871f126f9aaae6...` |
| `zoo-tokenomics` | `zoo-tokenomics/zoo-tokenomics.tex` | 4,035 | `b0f154dda1ee31d3...` |
| `zoo-lux-bridge-protocol` | `zoo-lux-bridge-protocol/zoo-lux-bridge-protocol.tex` | 19,960 | `5142438752f7243e...` |
| `zoo-experience-ledger` | `zoo-experience-ledger/zoo-experience-ledger.tex` | 3,488 | `016f002ea693197a...` |
| `zoo-dao-governance` | `zoo-dao-governance/zoo-dao-governance.tex` | 4,797 | `ee6f006d0927b5fa...` |

---

## 3. Live 3-Node Loopback Test-Network Results (`--seed 1350`)

### 3.1 Topology
- **Transport**: 3 isolated loopback HTTP/JSON-RPC servers (`ValidatorCommittee`, `SettlementEngine`, `FinalityTreasuryGate`) on `127.0.0.1` ephemeral ports with durable `fsync` hash-chained WALs at Layer 2 and Layer 3.
- **Scale**: `200` grounded jobs across `12` independent providers, `5` independent validators (`quorum q = 3`), `10` epochs (`20` jobs/epoch), finality delay `K = 2` epochs, claim window `W = 6` epochs, `2` governance treasury authorities, `2` read-only consumer applications, `1` advisory AI agent, `4` payers.
- **Splits**: `conservation_bps = 200` (2.00%), `protocol_bps = 100` (1.00%), `provider_bps = 9700` (97.00%).

### 3.2 End-to-End Stage Latencies & Throughput

| Stage | Layer / Transport | Count | Mean (us) | p50 (us) | p95 (us) | p99 (us) | Max (us) |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| `Admit` | Layer 1 HTTP | 200 | 257.99 | 115.80 | 664.16 | 3,825.67 | 7,886.91 |
| `Perform` | Provider local compute | 200 | 29.59 | 10.71 | 23.05 | 56.73 | 3,674.23 |
| `Verify` | Layer 1 HTTP (5x Ed25519 EAS attest) | 200 | 514.40 | 414.61 | 855.19 | 2,579.70 | 10,356.10 |
| `IssueReceipt` | Layer 2 HTTP + `fsync` WAL | 200 | 7,710.53 | 7,390.03 | 13,237.95 | 15,424.53 | 17,432.94 |
| `AuthorizeReward` | Layer 3 HTTP + Merkle + `fsync` WAL | 200 | 7,647.02 | 7,540.79 | 12,203.38 | 15,643.79 | 18,017.51 |

- **Total End-to-End Wall Time (200 jobs + 10 epoch Merkle seals + HTTP + 420 WAL `fsync`s)**: `3,374.81 ms`
- **Sustained Durable End-to-End Throughput**: `59.26 receipts/sec` (dominated by per-receipt synchronous disk `fsync` at both Layer 2 and Layer 3; in-memory Layer 2 receipt issuance runs at `~0.86–1.40 ms` mean as shown in Negative Regime 2).

### 3.3 Exact Integer Micro-ZOO Accounting & Conservation

| Ledger Account | Exact Amount (micro-ZOO) | Equivalent (ZOO) |
| :--- | ---: | ---: |
| Total Finalized Escrow | `2,151,837,161` | `2,151.837161` |
| Total Authorized Payout | `1,679,566,800` | `1,679.566800` |
| Total Provider Payout (sum across 12 providers) | `1,629,179,796` | `1,629.179796` |
| Conservation Fund (200 bps / ZIP-0700) | `33,591,336` | `33.591336` |
| Protocol Fee Pool (100 bps) | `16,795,668` | `16.795668` |
| Total Payer Refunds | `472,270,361` | `472.270361` |
| **Conservation Drift** | **`0`** | **`0.000000`** |

Exact identity verification:
- `1,629,179,796 + 33,591,336 + 16,795,668 == 1,679,566,800` (`true`)
- `1,679,566,800 + 472,270,361 == 2,151,837,161` (`true`)

---

## 4. Double-Claim Stress, Crash Recovery & Determinism Audits

| Audit Check | Metric / Result | Status |
| :--- | :--- | :---: |
| Sequential Replay Stress (L2 + cross-epoch L3) | `0 / 200` accepted, `200 / 200` rejected (`ERR_DOUBLE_CLAIM`) | **PASS** |
| Concurrent Double-Claim Race (Layer 2, 64 goroutines, `-race`) | Strictly `1 / 64` accepted, `63 / 64` rejected (`ERR_DOUBLE_CLAIM`) | **PASS** |
| Concurrent Double-Claim Race (Layer 3, 64 goroutines, `-race`) | Strictly `1 / 64` accepted, `63 / 64` rejected (`ERR_DOUBLE_CLAIM`) | **PASS** |
| Cold-Restart `fsync` WAL Recovery (`420` WAL entries) | Identical nullifier set, Merkle roots & balance sheet; post-restart replay blocked | **PASS** |
| Out-of-Order Arrival Permutation Invariance (`5` shuffles) | Bit-identical micro-ZOO balances across all 12 providers & pools | **PASS** |
| Dual Go 1.24 <-> Pure Python 3.12 Parity (`224` trace cases) | `224 / 224` identical verdicts, error codes, balances & `audit_merkle_root` | **PASS** |

---

## 5. Adversarial Security Suite (`24 / 24` Blocked = `100.0%`)

| Case ID | Stage | Enforced Canonical Error Code | Blocked |
| :--- | :--- | :--- | :---: |
| `adv_01_direct_double_claim` | `AUTHORIZE_REWARD` | `ERR_DOUBLE_CLAIM` | Yes |
| `adv_02_cross_epoch_replay` | `AUTHORIZE_REWARD` | `ERR_DOUBLE_CLAIM` | Yes |
| `adv_03_job_reattestation_different_nonce` | `ISSUE_RECEIPT` | `ERR_DOUBLE_CLAIM` | Yes |
| `adv_04_app_reward_issuance` | `AUTHORIZE_REWARD` | `ERR_APP_ISSUANCE_FORBIDDEN` | Yes |
| `adv_05_app_receipt_issuance` | `ISSUE_RECEIPT` | `ERR_APP_ISSUANCE_FORBIDDEN` | Yes |
| `adv_06_ai_agent_treasury_auth` | `AUTHORIZE_REWARD` | `ERR_AI_ISSUANCE_FORBIDDEN` | Yes |
| `adv_07_ai_agent_cap_mutation` | `POLICY_MUTATION` | `ERR_AI_POLICY_MUTATION_FORBIDDEN` | Yes |
| `adv_08_ai_agent_quorum_downgrade` | `POLICY_MUTATION` | `ERR_AI_POLICY_MUTATION_FORBIDDEN` | Yes |
| `adv_09_provider_self_verification` | `VERIFY` | `ERR_SELF_VERIFICATION_FORBIDDEN` | Yes |
| `adv_10_validator_mint_attempt` | `AUTHORIZE_REWARD` | `ERR_UNAUTHORIZED_TREASURY` | Yes |
| `adv_11_settlement_node_mint_attempt` | `AUTHORIZE_REWARD` | `ERR_UNAUTHORIZED_TREASURY` | Yes |
| `adv_12_forged_validator_signature` | `VERIFY` | `ERR_INVALID_SIGNATURE` | Yes |
| `adv_13_forged_treasury_signature` | `AUTHORIZE_REWARD` | `ERR_INVALID_SIGNATURE` | Yes |
| `adv_14_unregistered_validator` | `VERIFY` | `ERR_UNAUTHORIZED_VALIDATOR` | Yes |
| `adv_15_duplicate_validator_in_quorum` | `VERIFY` | `ERR_DUPLICATE_VALIDATOR` | Yes |
| `adv_16_insufficient_validator_quorum` | `VERIFY` | `ERR_INSUFFICIENT_QUORUM` | Yes |
| `adv_17_budget_cap_overflow` | `VERIFY` | `ERR_BUDGET_OVERFLOW` | Yes |
| `adv_18_epoch_treasury_cap_exceeded` | `AUTHORIZE_REWARD` | `ERR_TREASURY_CAP_EXCEEDED` | Yes |
| `adv_19_tampered_merkle_proof` | `AUTHORIZE_REWARD` | `ERR_INVALID_MERKLE_PROOF` | Yes |
| `adv_20_unfinalized_epoch_claim` | `AUTHORIZE_REWARD` | `ERR_UNFINALIZED_EPOCH` | Yes |
| `adv_21_expired_epoch_claim` | `AUTHORIZE_REWARD` | `ERR_EPOCH_EXPIRED` | Yes |
| `adv_22_tampered_micro_zoo_split` | `ISSUE_RECEIPT` | `ERR_ACCOUNTING_MISMATCH` | Yes |
| `adv_23_tampered_attestation_uid` | `VERIFY` | `ERR_INVALID_ATTESTATION_UID` | Yes |
| `adv_24_validator_treasury_key_reuse` | `KEY_AUDIT` | `ERR_KEY_ROLE_CONFLICT` | Yes |

---

## 6. Three Explicit Honest Negative Regimes

### 6.1 Negative Regime 1: Collapsed Single-Layer App Self-Issuance (`neg_collapsed_layer_self_issuance`)
When application consumption is collapsed with receipt validation and reward issuance into a single layer, a compromised application or colluding provider can emit self-attested phantom receipts and authorize payouts directly. Under a 20-claim phantom-receipt attack (5 ZOO each against a 100 ZOO = `100,000,000` micro-ZOO epoch budget):

| Architecture | Phantom Attacks | Drained (micro-ZOO) | Budget Drain % | Blocked % | Enforcement Mechanism |
| :--- | ---: | ---: | ---: | ---: | :--- |
| Collapsed Single-Layer Baseline | 20 | `100,000,000` | **100.00%** | 0.00% | None (app holds issuance privilege) |
| Strict 3-Layer Separation | 20 | `0` | **0.00%** | **100.00%** | 10x `ERR_APP_ISSUANCE_FORBIDDEN`, 10x `ERR_SELF_VERIFICATION_FORBIDDEN` |

**Takeaway**: Strict 3-layer separation is not cosmetic bureaucracy; collapsing read-only application consumption into issuance converts any compromised application endpoint into a 100% epoch-budget drain vector.

### 6.2 Negative Regime 2: Finality-Delay vs Immediate-Payout UX Latency Tax (`neg_finality_epoch_latency_tax`)
Separating fast Layer 2 receipt issuance from Layer 3 epoch finality imposes an unavoidable user-experience latency tax. Across an 8-epoch observation horizon (`10` jobs/epoch = `80` jobs, modeled consensus slot duration `12.0 s/epoch`), we sweep finality delay $K \in \{0, 1, 2, 4, 8\}$ epochs:

| Finality Delay $K$ (epochs) | L2 Receipt Mean (us) | L3 Auth Compute Mean (us) | Modeled Payout Wait (s) | Early-Claim Rejections (`ERR_UNFINALIZED_EPOCH`) | Spendable Within 8-Epoch Window (%) |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 1,396.30 | 1,180.56 | 0.0 s | 0 / 80 | 100.00% |
| 1 | 1,102.27 | 1,404.23 | 12.0 s | 80 / 80 | 87.50% |
| 2 | 1,033.82 | 1,363.20 | 24.0 s | 80 / 80 | 75.00% |
| 4 | 1,028.92 | 1,082.72 | 48.0 s | 80 / 80 | 50.00% |
| 8 | 861.06 | 890.98 | 96.0 s | 80 / 80 | **0.00%** |

**Honest Limitation**: Although cryptographic settlement compute stays around `~0.86–1.40 ms` per receipt regardless of $K$, providers demanding immediate spendable liquidity suffer a linear finality wait ($K \times T_{\text{epoch}}$), and at $K = 8$ zero receipts become spendable within an 8-epoch window. Instant-payout UX therefore requires separate liquidity/credit factoring on top of verified Layer 2 receipts rather than weakening Layer 3 finality.

### 6.3 Negative Regime 3: Validator Quorum Stall / Liveness Loss Under Node Outages (`neg_validator_quorum_liveness_stall`)
With committee size $n = 5$ and required quorum $q = 3$, we disable $f \in \{0, 1, 2, 3, 4\}$ independent validators and submit 20 jobs per outage level:

| Offline Validators ($f$) | Online Validators ($n - f$) | Quorum ($q$) | Rewards Authorized | Liveness (%) | Fail-Closed Stalls (`ERR_INSUFFICIENT_QUORUM`) | Unauthorized Issuances |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 5 | 3 | 20 / 20 | 100.00% | 0 | **0** |
| 1 | 4 | 3 | 20 / 20 | 100.00% | 0 | **0** |
| 2 | 3 | 3 | 20 / 20 | 100.00% | 0 | **0** |
| 3 | 2 | 3 | 0 / 20 | **0.00%** | 20 | **0** |
| 4 | 1 | 3 | 0 / 20 | **0.00%** | 20 | **0** |

**Honest Safety-vs-Liveness Trade-Off**: Once correlated outages exceed $n - q = 2$ validators, Layer 1 cannot form quorum and Layer 3 fails closed — reward issuance halts completely (`0%` liveness) rather than relaxing threshold security, strictly maintaining `0` unauthorized issuances. Production deployments must therefore size $n$ and geographically diversify validator operators to keep correlated outage probability well below $n - q$.

---

## 7. What Remains Unproven

1. **Live EVM / Lux C-Chain / Zoo L2 Smart-Contract Deployment & Gas Economics**: This benchmark executes over a 3-node loopback HTTP/JSON-RPC test network with durable `fsync` WALs, not deployed Solidity contracts (`ISettlementVault`, `ISettlementLedger`, `IComputeOracle`); L2 calldata, EVM gas costs, and ZIP-0800 bridge fees remain unmeasured on a live chain.
2. **On-Chain Ethereum Attestation Service (`EAS.sol`) Calls**: Attestations implement EAS structured UID, `schemaUID`, `refUID`, `recipient`, and `attester` semantics with RFC 8032 Ed25519 signatures rather than EIP-712 secp256k1 signatures verified on-chain by `EAS.sol`.
3. **Economic Slashing, Stake Bonding & >67% Validator Collusion**: Cryptographic quorum (`3`-of-`5`) prevents minority forgery and self-verification, but does not prevent a colluding supermajority ($\ge 3$ of $5$) from signing fabricated off-chain compute claims without stake-bonding and slashing mechanisms.
4. **Cross-Chain Bridge Reorgs & WAN Byzantine Network Partitions**: Finality delay is modeled as a deterministic epoch offset; asynchronous WAN latency spikes, L2 sequencer reorgs, and bridge relayer censorship are not simulated.
5. **Hardware GPU/LLM Compute Proofs**: Work digests verify deterministic corpus chunk processing rather than hardware-level GPU matrix-multiplication proofs (see `zoo-poai-consensus/reference/` for CPU-verifiable Freivalds GPU work verification).
6. **Legal, Tax & Regulatory Compliance**: Token issuance licensing, conservation-credit tax treatment, and jurisdictional payout compliance remain outside technical protocol verification.

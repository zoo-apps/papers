# Reproducible Benchmark Report (`forkable-org.v1`, `--seed 1352`)

All metrics below are deterministically produced by `go run ./cmd/fork-bench --seed 1352` and independently verified byte-for-byte by both the Go 1.24 verifier (`fork-verify`) and the zero-dependency pure-Python 3.12 verifier (`python3 -m forkorg_py.cli`).

- **Canonical Fixture**: `fixtures/fork-exchange-suite.v1.json`
- **Machine-Readable Results**: `results.json`
- **Eval Dataset Hash**: `de6bf37e0aff53df7f6b39d3c1e92971466a78d702755eb3ba9f3345e545b897` (200 held-out 4-class evaluation samples + 40 safety probes)
- **Audit Merkle Root (RFC 6962, Go == Python)**: `d70dbc7886797d35e46004eab55ba99f5005f0032df6c12c6c7e0419eeb93e71`

---

## 1. End-to-End Lifecycle: Fork, Diverge & Bidirectional Verified Exchange

| Stage | Status | Accuracy (bps / %) | Mean Hinge Loss (micro / unit) | Safety Probe (bps / %) | Delta Gain vs Prev Head |
|---|---|---:|---:|---:|---:|
| `1_org_a_base_snap_0` (Shared Base $W_b$) | `OK` | `6900` (69.00%) | `1,302,118` (1.3021) | `10000` (100.00%) | — |
| `2_org_a_pre_fork_snap_1` (Mixed ACL tiers) | `OK` | `6900` (69.00%) | `1,302,118` (1.3021) | `10000` (100.00%) | `0` bps |
| `3_org_b_fork_boundary_snap_1` (Fork + Redaction) | `OK` | `6900` (69.00%) | `1,302,118` (1.3021) | `10000` (100.00%) | `0` bps |
| `4_org_a_diverged_snap_2` (OrgA BitDelta, classes 0–1) | `OK` | `7550` (75.50%) | `870,974` (0.8710) | `10000` (100.00%) | `+650` bps (+6.50%) |
| `5_org_b_diverged_deltasoup_snap_2` (OrgB DeltaSoup, 30% Byz, classes 2–3) | `OK` | `7550` (75.50%) | `984,009` (0.9840) | `10000` (100.00%) | `+650` bps (+6.50%) |
| `6_exchange_verify_org_b_to_org_a` (Verify OrgB → OrgA) | `OK` | `7700` (77.00%) | `840,014` (0.8400) | `10000` (100.00%) | `+150` bps (+1.50%) |
| `7_org_a_adopted_snap_3` (OrgA Adopted Merged Head) | `OK` | `7700` (77.00%) | `840,014` (0.8400) | `10000` (100.00%) | `+150` bps (+1.50%) |
| `8_exchange_verify_org_a_to_org_b` (Verify OrgA → OrgB) | `OK` | `7700` (77.00%) | `840,014` (0.8400) | `10000` (100.00%) | `+150` bps (+1.50%) |
| `9_org_b_adopted_snap_3` (OrgB Adopted Merged Head) | `OK` | `7700` (77.00%) | `840,014` (0.8400) | `10000` (100.00%) | `+150` bps (+1.50%) |

**Key Takeaways**:
- Forking `OrgA@snap_1` → `OrgB@snap_1_fork` stripped **2 of 4** research records (`1 restricted_pii_or_partner`, `1 org_internal`) with valid RFC 6962 `RedactionTombstone` proofs reconstructing `OrgA@snap_1`'s exact `research_merkle_root`, stripped **2 of 3** non-inheritable ACL grants, rotated all Ed25519 keys, and produced **0 ACL leaks**.
- Both branches independently improved held-out accuracy by **+650 bps (+6.50%)** over the shared base (`69.00% → 75.50%`), and bidirectional verified cross-fork adoption lifted **both** `OrgA@snap_3` and `OrgB@snap_3` to **77.00% (+800 bps over base, +150 bps over each diverged head)** while lowering hinge loss from `1.3021` to `0.8400` and preserving `100.00%` safety probe accuracy.

---

## 2. BitDelta Storage & Compression Scaling

Measured byte size for packed 1-bit sign matrix (`ceil(D/8)` bytes) + 4-byte per-tensor scale $\gamma$:

| Tensor Dim $D$ | Full FP32 (bytes) | Full FP16 (bytes) | BitDelta (bytes) | Ratio vs FP32 | Ratio vs FP16 | Effective Bits/Param |
|---:|---:|---:|---:|---:|---:|---:|
| `64` (Fixture Model) | `256` | `128` | `12` | `21.33×` | `10.67×` | `1.500` |
| `256` | `1,024` | `512` | `36` | `28.44×` | `14.22×` | `1.125` |
| `1,024` | `4,096` | `2,048` | `132` | `31.03×` | `15.52×` | `1.031` |
| `4,096` | `16,384` | `8,192` | `516` | `31.75×` | `15.88×` | `1.007` |
| `65,536` | `262,144` | `131,072` | `8,196` | `31.98×` | `15.99×` | `1.000` |

---

## 3. DeltaSoup Byzantine Resilience & Honest Negative Regime

Ten contributors ($N = 10$) submit BitDelta adapters to `OrgB` under coordinated sign-flip + 6× magnitude poisoning. Coordinate-wise trimmed mean (`trim_bps = 3000`, dropping $k = 3$ lowest and $k = 3$ highest values per coordinate) is compared against naive untrimmed mean:

| Byzantine % ($b/10$) | Naive Mean Acc | Naive Loss | Naive Safety | DeltaSoup Trimmed Acc | Trimmed Loss | Trimmed Safety | Regime |
|---:|---:|---:|---:|---:|---:|---:|---|
| `0%` (0/10) | `77.00%` | `0.8034` | `100.00%` | `77.50%` | `0.8263` | `100.00%` | `robust_within_bound` |
| `10%` (1/10) | `77.00%` | `1.0756` | `100.00%` | `77.00%` | `0.8557` | `100.00%` | `robust_within_bound` |
| `20%` (2/10) | `46.50%` | `2.0072` | `97.50%` | `77.00%` | `0.9051` | `100.00%` | `robust_within_bound` |
| `30%` (3/10) | `33.50%` | `2.7366` | `27.50%` | **`77.50%`** | **`0.8876`** | **`100.00%`** | `robust_within_bound` |
| `40%` (4/10) | `15.50%` | `4.1446` | `0.00%` | `22.00%` | `3.1931` | `17.50%` | **`honest_negative_breakdown_above_trim_bound`** |
| `50%` (5/10) | `11.50%` | `5.1613` | `0.00%` | `9.50%` | `5.7907` | `0.00%` | **`honest_negative_breakdown_above_trim_bound`** |

**Honest Negative Regime Analysis**:
- Up to the theoretical bound $b \le \lfloor \beta N \rfloor = 3$ (30% Byzantine), DeltaSoup completely neutralizes coordinated poisoning (`77.50%` accuracy and `100.00%` safety vs naive mean collapsing to `33.50%` accuracy and `27.50%` safety).
- At **40%–50% Byzantine** ($b > k$), poisoned coordinates breach the trimmed inner window and trimmed mean honestly collapses (`22.00%` at 40%, `9.50%` at 50%), confirming why `VerifyExchangeBundle` enforces an independent evaluation + safety-floor gate on top of DeltaSoup aggregation.

### DeltaSoup Royalty Distribution (`OrgB`, 7 Honest Contributors)
Exact largest-remainder basis-point shares proportional to $\|\delta_i\|_1$ (`1445 + 1662 + 1517 + 1318 + 1331 + 1327 + 1400 = 10,000` bps):
- `contrib-01`: `1445` bps | `contrib-02`: `1662` bps | `contrib-03`: `1517` bps | `contrib-04`: `1318` bps | `contrib-05`: `1331` bps | `contrib-06`: `1327` bps | `contrib-07`: `1400` bps.

---

## 4. Adversarial & Constitutional Security Matrix (`19/19` Attacks Caught + `1/1` Positive AI Advisory)

Every case below is verified identically by Go and Python:

| Case ID | Category | Target | Expected & Actual Code | Result |
|---|---|---|---|---|
| `ATK-01` | `provenance` | `exchange` | `ERR_LINEAGE_BROKEN` | Caught (Go == Py) |
| `ATK-02` | `integrity` | `exchange` | `ERR_DELTA_HASH_MISMATCH` | Caught (Go == Py) |
| `ATK-03` | `provenance` | `snapshot` | `ERR_HISTORY_CHAIN_BROKEN` | Caught (Go == Py) |
| `ATK-04` | `integrity` | `snapshot` | `ERR_MERKLE_ROOT_MISMATCH` | Caught (Go == Py) |
| `ATK-05` | `acl_isolation` | `fork` | `ERR_ACL_LEAK_RESTRICTED` | Caught (Go == Py) |
| `ATK-06` | `acl_isolation` | `fork` | `ERR_ACL_LEAK_GRANT` | Caught (Go == Py) |
| `ATK-07` | `acl_isolation` | `exchange` | `ERR_ACL_TAINT_RESTRICTED` | Caught (Go == Py) |
| `ATK-08` | `key_isolation` | `fork` | `ERR_KEY_ROTATION_REQUIRED` | Caught (Go == Py) |
| `ATK-09` | `replay_defense` | `exchange` | `ERR_CROSS_ORG_REPLAY` | Caught (Go == Py) |
| `ATK-10` | `authority` | `exchange` | `ERR_UNAUTHORIZED_SIGNER` | Caught (Go == Py) |
| `ATK-11` | `cryptography` | `exchange` | `ERR_INVALID_SIGNATURE` | Caught (Go == Py) |
| `ATK-12` | `ai_governance_boundary` | `governance` | `ERR_AI_VOTING_RULE_FORBIDDEN` | Caught (Go == Py) |
| `ATK-13` | `ai_governance_boundary` | `governance` | `ERR_AI_TREASURY_FORBIDDEN` | Caught (Go == Py) |
| `ATK-14` | `ai_governance_boundary` | `exchange` | `ERR_AI_SELF_CERTIFY_FORBIDDEN` | Caught (Go == Py) |
| `ATK-15` | `scientific_verification` | `exchange` | `ERR_EVAL_REPLAY_MISMATCH` | Caught (Go == Py) |
| `ATK-16` | `scientific_verification` | `exchange` | `ERR_QUALITY_REGRESSION` | Caught (Go == Py) |
| `ATK-17` | `safety_verification` | `exchange` | `ERR_SAFETY_FLOOR_VIOLATION` | Caught (Go == Py) |
| `ATK-18` | `licensing` | `exchange` | `ERR_LICENSE_INCOMPATIBLE` | Caught (Go == Py) |
| `ATK-19` | `acl_isolation` | `fork` | `ERR_REDACTION_PROOF_INVALID` | Caught (Go == Py) |
| `POS-20` | `ai_governance_boundary` | `advisory` | `OK` (Valid non-binding AI estimate) | Accepted (Go == Py) |

---

## 5. Dual-Language Parity & Measured Verification Latency

Measured on Linux `amd64` (2-vCPU Xeon @ 2.30 GHz) with Go 1.24.3 (`go test -bench=. -benchmem`) and pure-Python 3.12.16 (stdlib-only pure-Python RFC 8032 Ed25519):

| Operation | Go 1.24 Latency | Go Allocs / Bytes | Pure-Python 3.12 Latency | Go ↔ Python Output Diff |
|---|---:|---:|---:|---|
| `VerifyOrgSnapshot` | `1.69 ms/op` | `2,143` / `159 KB` | `82.08 ms/op` | `0` bytes diff |
| `VerifyForkBoundary` | `0.98 ms/op` | `1,370` / `104 KB` | `44.93 ms/op` | `0` bytes diff |
| `VerifyExchangeBundle` | `1.11 ms/op` | `2,017` / `142 KB` | `54.09 ms/op` | `0` bytes diff |
| `VerifySuite` (Full 9 stages + 20 cases) | `25.67 ms/op` | `41,067` / `3.05 MB` | `1,057.80 ms/op` | `0` bytes diff |

---

## 6. Exact Reproduction Commands

```bash
# 1. Regenerate deterministic fixture & results.json (--seed 1352)
(cd go && go run ./cmd/fork-bench --seed 1352)

# 2. Run Go format, vet, race-detector tests, and latency benchmarks
(cd go && gofmt -l . && go vet ./... && go test -race -v -count=1 ./... && go test -bench=. -benchmem -run=^$ ./...)

# 3. Run zero-dependency pure-Python verifier, RFC 8032 Ed25519 vectors, and Go parity tests
(cd python && python3 -m unittest discover -s tests -v)

# 4. Direct bit-identical CLI diff between Go and Python verifiers
diff -u \
  <(cd go && go run ./cmd/fork-verify --fixture ../fixtures/fork-exchange-suite.v1.json --compact) \
  <(cd python && python3 -m forkorg_py.cli --fixture ../fixtures/fork-exchange-suite.v1.json --compact)
```

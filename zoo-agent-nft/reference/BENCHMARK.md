# Benchmark & Threat-Model Evaluation (`agent-identity-delegation.v1`)

All figures below are **directly measured** on the local Linux x86_64 environment (Go `1.24.3`, Python `3.12.16`, zero third-party dependencies) using deterministic `--seed 1352` and saved verbatim in [`results.json`](results.json).

- **Canonical RFC 6962 `audit_merkle_root`**:
  `cf1dcd70cbeca43542732d9d63d4831f93f1d9e2f8665ae6862cd8e3d6e7e747`
- **Go ↔ Python CLI Parity**: `0` bytes diff (`diff -u` between `go run ./cmd/id-verify --compact` and `python3 -m agentid_py.cli --compact`)
- **Positive Lifecycle Stages**: **`5 / 5` (`100%`)** verified offline
- **Threat-Model Score**: **`24 / 24` (`100%`)** attacks caught fail-closed + **`1 / 1`** positive AI advisory control accepted

---

## 1. Offline Verification Latency & Throughput Across Delegation Chain Depths (`1, 2, 4, 8, 16`)

Measured against a full W3C `131,072`-bit (`16 KB` raw) gzipped `BitstringStatusListCredential` + signed `RevocationSnapshot` + self-certifying `did:key:` leaf session.

- **Warm-Epoch Mode**: DID documents, key rotations, `RevocationSnapshot`, and `BitstringStatusListCredential` are verified once per sync epoch; every request verifies all `depth` delegation VCs (`depth` Ed25519 checks + monotonic attenuation + O(1) bitstring lookup per hop) plus the leaf `HolderProof` (`+1` Ed25519 check) = `depth + 1` signatures per request.
- **Cold-Snapshot Mode**: Re-verifies every portable DID document, the `RevocationSnapshot`, the `131,072`-bit gzipped `BitstringStatusListCredential`, the full chain, and the `HolderProof` from scratch on every call.

### 1.1 Go (`crypto/ed25519`, 200 warm iterations / 100 cold iterations per depth)

| Chain Depth | Warm Sigs | Warm Mean (µs) | Warm p50 (µs) | Warm p95 (µs) | Warm Ops/s | Scaling vs Depth 1 | Cold Sigs | Cold Mean (µs) | Cold Ops/s |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **1** | 2 | 432.81 | 369.67 | 1,443.09 | 2,310.46 | 1.00× | 6 | 1,112.88 | 898.57 |
| **2** | 3 | 844.13 | 706.40 | 2,197.11 | 1,184.65 | 1.95× | 8 | 1,764.56 | 566.71 |
| **4** | 5 | 1,436.20 | 1,262.46 | 3,168.37 | 696.28 | 3.32× | 12 | 2,563.50 | 390.09 |
| **8** | 9 | 2,713.50 | 2,393.77 | 7,010.08 | 368.53 | 6.27× | 20 | 4,459.99 | 224.22 |
| **16** | 17 | 5,373.85 | 4,815.45 | 9,441.82 | 186.09 | 12.42× | 36 | 8,181.82 | 122.22 |

### 1.2 Pure-Python 3 (Zero-Dependency Stdlib RFC 8032 Ed25519)

| Chain Depth | Warm Sigs | Warm Mean (µs) | Warm p50 (µs) | Warm p95 (µs) | Warm Ops/s | Cold Mean (µs) | Go Speedup (Warm) |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **1** | 2 | 15,009.84 | 15,074.34 | 15,078.42 | 66.62 | 45,329.35 | 34.7× |
| **2** | 3 | 23,009.02 | 22,676.95 | 22,966.37 | 43.46 | 60,355.49 | 27.3× |
| **4** | 5 | 37,096.91 | 37,148.57 | 37,236.62 | 26.96 | 92,292.84 | 25.8× |
| **8** | 9 | 67,055.62 | 66,906.72 | 67,253.89 | 14.91 | 148,443.58 | 24.7× |
| **16** | 17 | 127,284.13 | 127,018.44 | 127,621.60 | 7.86 | 273,129.00 | 23.7× |

---

## 2. W3C `BitstringStatusListCredential` Size & Revocation Lookup Scaling (`1K`, `16K`, `131K`)

Measured on a 4-hop delegation chain under sparse (`0.1%` revoked) vs dense (`50%` random revoked) occupancy:

| Bit Length | Raw Bytes | Density | Revoked Count | `gzip_base64url` Bytes | `raw_base64url` Bytes | Compression Ratio | Go Cold Verify (µs) | Go Warm O(1) Lookup (µs) | Python Decode (µs) | Python Warm O(1) Lookup (µs) |
| ---: | ---: | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **1,024** | 128 | `sparse_0.1pct` | 1 | 40 | 171 | 4.28× | 2,409.89 | 0.0150 | 171.37 | 0.4157 |
| **1,024** | 128 | `dense_50pct` | 512 | 208 | 171 | **0.82×** | 2,522.62 | 0.0121 | — | — |
| **16,384** | 2,048 | `sparse_0.1pct` | 16 | 100 | 2,731 | 27.31× | 2,601.54 | 0.0121 | 99.18 | 0.4721 |
| **16,384** | 2,048 | `dense_50pct` | 8,192 | 2,768 | 2,731 | **0.99×** | 2,717.04 | 0.0121 | — | — |
| **131,072** | 16,384 | `sparse_0.1pct` | 131 | 430 | 21,846 | 50.80× | 2,506.74 | 0.0121 | 124.06 | 0.4767 |
| **131,072** | 16,384 | `dense_50pct` | 65,536 | 21,883 | 21,846 | **1.00×** | 3,515.32 | 0.0149 | — | — |

Key empirical finding: once decoded per sync epoch, bitstring revocation checks are strictly **$O(1)$ (`~12–15 ns` in Go, `~470 ns` in Python)** across a `128×` growth from `1,024` to `131,072` credentials.

---

## 3. Honest Negative Regimes

### 3.1 Offline Revocation Staleness Window vs Sync Bandwidth (`131,072`-Entry List)

Offline verification eliminates live RPC dependencies, but creates an irreducible **staleness window** $\Delta_{\text{stale}} = \text{valid\_until} - t_{\text{revoke}}$ during which a recently revoked agent can still pass verification until the offline verifier refreshes its `BitstringStatusListCredential`:

| Sync Interval (`valid_until` TTL) | Max Staleness Window | Daily Syncs | Sparse (`0.1%`, 430 B) Avg Bandwidth | Dense (`50%`, 21,883 B) Avg Bandwidth |
| ---: | ---: | ---: | ---: | ---: |
| `60 s` | 60 s | 1,440 | `7.17 B/s` | `364.72 B/s` |
| `300 s` | 300 s | 288 | `1.43 B/s` | `72.94 B/s` |
| `900 s` | 900 s | 96 | `0.48 B/s` | `24.31 B/s` |
| `3,600 s` | 3,600 s | 24 | `0.12 B/s` | `6.08 B/s` |
| `86,400 s` | 86,400 s | 1 | `0.005 B/s` | `0.25 B/s` |

### 3.2 Deep-Chain Linear Verification Scaling (`O(depth)`) vs Flat Direct Delegation

Verifying a chain of depth $d$ requires $d + 1$ Ed25519 signature verifications plus $d$ canonical JSON hashes and attenuation checks. Moving from depth `1` to depth `16` increases Go warm latency by **`12.42×`** (`432.81 µs` → `5,373.85 µs`, dropping throughput from `2,310` to `186 ops/s`) and Pure-Python warm latency by **`8.48×`** (`15.01 ms` → `127.28 ms`, dropping throughput to `7.86 ops/s`). Production deployments should bound `max_sub_depth <= 4` and reserve pure-Python stdlib Ed25519 for independent offline audit verification rather than high-QPS hot paths.

### 3.3 High-Entropy Gzip Expansion on Dense Revocation Lists

At `0.1%` revocation density, W3C `gzip_base64url` achieves a **`50.80×`** compression ratio on a `131,072`-bit list (`430 B` vs `21,846 B` raw base64url). At `50%` uniform random revocation density, gzip provides **zero compression** (`21,883 B` vs `21,846 B` raw—and `208 B` vs `171 B` at `1K` bits due to deflate framing) while increasing cold verification latency by **`+1.01 ms`** (`3,515.32 µs` vs `2,506.74 µs`). Operators with high churn should rotate fresh bitstring lists per epoch rather than accumulating `>25%` dense revocations in a single list.

---

## 4. Threat-Model & Constitutional Verification Matrix (`25/25` Pass, `24/24` Attacks Caught)

| Case ID | Category | Scenario | Expected | Go | Python |
| :--- | :--- | :--- | :--- | :---: | :---: |
| `ATK-01` | Impersonation | Bearer credential theft (missing `HolderProof`) | `ERR_HOLDER_PROOF_MISSING` | PASS | PASS |
| `ATK-02` | Impersonation | Wrong holder DID impersonating leaf session | `ERR_HOLDER_DID_MISMATCH` | PASS | PASS |
| `ATK-03` | Impersonation | Forged Ed25519 signature in `HolderProof` | `ERR_HOLDER_SIGNATURE_INVALID` | PASS | PASS |
| `ATK-04` | Impersonation | `did:key:` public key substitution / DID spoofing | `ERR_DID_KEY_BINDING_MISMATCH` | PASS | PASS |
| `ATK-05` | Impersonation | Unauthorized DID key rotation (bad controller co-sig) | `ERR_KEY_ROTATION_INVALID` | PASS | PASS |
| `ATK-06` | Impersonation | Cross-audience presentation replay | `ERR_AUDIENCE_MISMATCH` | PASS | PASS |
| `ATK-07` | Impersonation | Replayed action challenge nonce | `ERR_NONCE_REPLAY` | PASS | PASS |
| `ATK-08` | Delegation | Broken `parent_vc_digest` cryptographic link | `ERR_PARENT_DIGEST_MISMATCH` | PASS | PASS |
| `ATK-09` | Delegation | Forged / tampered `DelegationVC` issuer signature | `ERR_VC_SIGNATURE_INVALID` | PASS | PASS |
| `ATK-10` | Delegation | Depth overflow beyond `parent.max_sub_depth = 0` | `ERR_DEPTH_OVERFLOW` | PASS | PASS |
| `ATK-11` | Delegation | Scope escalation (child adds permission absent from parent) | `ERR_SCOPE_ESCALATION` | PASS | PASS |
| `ATK-12` | Delegation | Resource prefix escape (`zoo://datasets/ecology/2026-private/`) | `ERR_RESOURCE_ESCALATION` | PASS | PASS |
| `ATK-13` | Delegation | TTL extension (`child.valid_until > parent.valid_until`) | `ERR_TTL_EXTENSION` | PASS | PASS |
| `ATK-14` | Delegation | Expired leaf delegation VC (`eval_time > valid_until`) | `ERR_VC_EXPIRED` | PASS | PASS |
| `ATK-15` | Delegation | Not-yet-valid delegation VC (`eval_time < valid_from`) | `ERR_VC_NOT_YET_VALID` | PASS | PASS |
| `ATK-16` | Delegation | Cyclic delegation graph (`Lead -> Sub -> Lead`) | `ERR_CYCLIC_DELEGATION` | PASS | PASS |
| `ATK-17` | Revocation | Direct leaf VC revoked in W3C BitstringStatusList (index 103) | `ERR_VC_REVOKED_BITSTRING` | PASS | PASS |
| `ATK-18` | Revocation | Transitive cascade revocation (intermediate parent revoked) | `ERR_CASCADE_PARENT_REVOKED` | PASS | PASS |
| `ATK-19` | Revocation | Key compromise epoch cutoff (`revoked_before`) | `ERR_KEY_REVOKED_BEFORE_CUTOFF` | PASS | PASS |
| `ATK-20` | Revocation | Stale pre-revocation `BitstringStatusList` replay | `ERR_STATUS_LIST_STALE` | PASS | PASS |
| `ATK-21` | Revocation | Tampered `BitstringStatusList` payload (invalid signature) | `ERR_STATUS_LIST_SIGNATURE_INVALID` | PASS | PASS |
| `ATK-22` | Constitutional | AI agent attempting `governance:vote_rules` | `ERR_CONSTITUTIONAL_AI_GOVERNANCE_FORBIDDEN` | PASS | PASS |
| `ATK-23` | Constitutional | AI agent attempting `treasury:authorize` | `ERR_CONSTITUTIONAL_AI_GOVERNANCE_FORBIDDEN` | PASS | PASS |
| `ATK-24` | Constitutional | AI agent attempting `experiment:certify` | `ERR_CONSTITUTIONAL_AI_GOVERNANCE_FORBIDDEN` | PASS | PASS |
| `POS-25` | Constitutional | Positive control: AI agent non-binding `value:estimate` | `VALID` | PASS | PASS |

---

## 5. Reproduction Commands

```bash
# 1. Go format, vet, and race-tested unit + concurrency suite
(cd go && gofmt -l . && go vet ./... && go test -race -v -count=1 ./...)

# 2. Pure-Python verifier, RFC 8032 Ed25519 vectors, and Go<->Python parity test
(cd python && python3 -m unittest discover -s tests -v)

# 3. Byte-exact Go<->Python CLI parity check (must emit 0 bytes diff)
diff -u \
  <(cd go && go run ./cmd/id-verify --fixture ../fixtures/identity-delegation-suite.v1.json --compact) \
  <(cd python && python3 -m agentid_py.cli --fixture ../fixtures/identity-delegation-suite.v1.json --compact)

# 4. Regenerate deterministic fixture & Go+Python benchmark results (--seed 1352)
(cd go && go run ./cmd/id-bench --seed 1352 --iters 200 \
  --fixture-out ../fixtures/identity-delegation-suite.v1.json \
  --results-out ../results.json \
  --export-bench /tmp/agentid-bench-bundle.json > /dev/null)
(cd python && python3 -m agentid_py.bench --bundle /tmp/agentid-bench-bundle.json --iters 5 --merge-results ../results.json)
rm -f /tmp/agentid-bench-bundle.json
```

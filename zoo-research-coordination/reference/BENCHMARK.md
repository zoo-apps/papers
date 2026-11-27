# Reproducible Benchmark Report (`federated-a2a.v1`, `--seed 1352`)

All metrics below are generated from a **real live two-deployment loopback HTTP/JSON-RPC 2.0 + SSE exchange** (`OrgAlpha` and `OrgBeta`, each running an independent `net/http` server on `127.0.0.1:0` with completely isolated credential stores, memory vaults, Ed25519 keys, nonce caches, and fail-closed Egress Boundary Firewalls) via `go run ./cmd/a2a-bench --seed 1352`, and independently verified byte-for-byte by both the Go 1.24 verifier (`a2a-verify`) and the zero-dependency pure-Python 3.12 verifier (`python3 -m feda2a_py.cli`).

- **Canonical Fixture**: [`fixtures/a2a-exchange-suite.v1.json`](fixtures/a2a-exchange-suite.v1.json)
- **Machine-Readable Results**: [`results.json`](results.json)
- **Wire Transcript Root (RFC 6962)**: `2e239c787ac5c41ebc13f3ef9840ba685736df867b8fe92783b45a8704001115` (`8` live HTTP frames, `21,650` total wire bytes)
- **Audit Merkle Root (RFC 6962, Go == Python)**: `b89d26031a589c29aaca4822c2e6155e3f780f4af8b5c3b5ac8cd8e115c4a3d8`
- **Boundary Isolation**: `credential_leak_bytes = 0`, `private_memory_leak_bytes = 0`, `raw_trace_leak_bytes = 0`

---

## 1. End-to-End Live Two-Deployment A2A Exchange (`7/7` Stages Pass)

| Stage | Transport / Method | Task State | Wire Frames | Cred / PrivMem / Trace Leak Bytes | Independent Recompute | Result |
|---|---|---|---:|---:|---|---|
| `1_discover_agent_cards` | Live `GET /.well-known/agent.json` (both ways) | `discovered` | `2` | `0` / `0` / `0` | — | `OK` |
| `2_alpha_to_beta_compare_task` | Live `POST /a2a/rpc` (`tasks/send`, `ZHL COMPARE`) | `completed` | `1` | `0` / `0` / `0` | `true` | `OK` |
| `3_alpha_polls_and_verifies_result` | Live `POST /a2a/rpc` (`tasks/get`) + AI advisory + `HUMAN_REVIEWER` accept | `completed` | `1` | `0` / `0` / `0` | `true` | `OK` |
| `4_beta_to_alpha_correlate_sse` | Live `POST /a2a/rpc` (`tasks/sendSubscribe`, `text/event-stream`, `4` SSE frames, `ZHL CORRELATE`) | `completed` | `1` | `0` / `0` / `0` | `true` | `OK` |
| `5_live_prompt_injection_egress_block` | Live `POST /a2a/rpc` (`tasks/send`, exfiltration prompt blocked fail-closed -> HTTP `403`) | `rejected` (`ERR_EGRESS_CREDENTIAL_BLOCKED`) | `1` | `0` / `0` / `0` | — | `OK` |
| `6_live_task_cancel_lifecycle` | Live `POST /a2a/rpc` (`tasks/send` deferred -> `tasks/cancel`) | `canceled` | `2` | `0` / `0` / `0` | — | `OK` |
| `7_wire_transcript_boundary_audit` | Complete byte-level audit across all `8` frames (`21,650` bytes) | `audited` | `8` | `0` / `0` / `0` | — | `OK` |

### Verified Scientific Outputs (Deterministic Fixed-Point `MICRO = 1_000_000`)
- **Stage 2 & 3 (`OrgAlpha -> OrgBeta`, `ZHL COMPARE`, $n = 48$)**: $\bar{a} = 2.174778$, $\bar{b} = 2.599528$, effect size $\Delta = +0.424750$ (`+424,750` micro, $\ge \delta_{\min} = 0.25$), Welch $t = 12.215639$, `significant = true`. Independently recomputed bit-for-bit on `OrgAlpha` and signed by `org-alpha-reviewer` (`HUMAN_REVIEWER`).
- **Stage 4 (`OrgBeta -> OrgAlpha`, live HTTP SSE `ZHL CORRELATE`, $n = 20$)**: $\bar{x} = 2.913984$, $\bar{y} = 3.012914$, Pearson $r = 0.994385$ (`994,385` micro, $\ge \delta_{\min} = 0.70$), `significant = true`. Streamed over `4` live SSE frames (`submitted`, `working`, `completed`, `artifact`), independently recomputed on `OrgBeta`, and signed by `org-beta-reviewer` (`HUMAN_REVIEWER`).
- **Stage 5 (Live Egress Boundary Firewall Demonstration)**: Prompt-injection task attempting to exfiltrate `OrgBeta`'s `INTERNAL_DB_DSN` and `BETA_CANARY_PATIENT_COHORT_6620_RESTRICTED` triggered `OrgBeta`'s live Egress Boundary Firewall before writing to TCP (`wire_bytes_sent = 0`), emitting a signed `EgressBlockEvent` (`ERR_EGRESS_CREDENTIAL_BLOCKED`) with HTTP `403 Forbidden` and **0 leaked bytes on the wire**.

---

## 2. Live Two-Deployment HTTP Latency, Throughput & Honest Negative Regime

Directly measured on Linux `amd64` (2-vCPU Intel Xeon @ 2.30 GHz, Go 1.24.3, `60` live loopback HTTP iterations per payload size) comparing **Unverified Passthrough** (`POST /a2a/passthrough`: raw JSON-RPC + compute, no Ed25519, no Egress DLP, no recomputation) against **Full Federated A2A Boundary** (`POST /a2a/rpc`: Ed25519 envelope + receipt signing & verification, nonce replay check, multi-encoding raw/lowercase/Base64/hex Egress Boundary Firewall, and independent scientific recomputation):

| Payload Samples ($n$) | Request Size | Passthrough Median RTT | Passthrough P95 RTT | Passthrough Throughput | Full Boundary Median RTT | Full Boundary P95 RTT | Full Boundary Throughput | Overhead Factor | Regime |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `16` | `1,541` B | `267 µs` | `4,870 µs` | `3,331` tasks/s | `1,164 µs` | `5,979 µs` | `654` tasks/s | `4.36×` | `bounded_security_overhead` |
| `128` | `3,338` B | `197 µs` | `421 µs` | `3,212` tasks/s | `1,934 µs` | `6,506 µs` | `457` tasks/s | `9.82×` | `bounded_security_overhead` |
| `512` | `9,482` B | `497 µs` | `5,159 µs` | `1,527` tasks/s | `5,120 µs` | `11,403 µs` | `184` tasks/s | **`10.30×`** | **`honest_negative_linear_dlp_and_canonical_overhead`** |

**Honest Negative Regime Analysis**:
- Full cryptographic boundary enforcement delivers sub-2 ms median RTT (`457–654` tasks/s) for compact scientific task envelopes (`1.5–3.3 KB`), which is well within interactive research coordination budgets.
- At `n = 512` (`9.5 KB`), canonical JSON re-serialization + multi-encoding (raw, case-folded, Base64, hex) DLP scanning on both client outbound and server egress + Ed25519 signing/verification + independent recomputation reaches **`10.30×` latency overhead (`5.12 ms` median, `184` tasks/s)** relative to unverified passthrough.
- Because inline wire DLP scales linearly with serialized payload bytes $\times$ secret-probe count, bulk multi-megabyte dataset or tensor transfers MUST use out-of-band content-addressed blob storage with pre-vetted tier digests rather than inline JSON payload scanning.

---

## 3. Adversarial & Constitutional Security Matrix (`18/18` Attacks Caught + `1/1` Positive AI Advisory)

Every case below is verified identically by both Go and pure-Python 3:

| Case ID | Category | Target | Expected & Actual Code | Result |
|---|---|---|---|---|
| `ATK-01` | `egress_credential_leak` | `receipt` | `ERR_CREDENTIAL_LEAK_DETECTED` | Caught (Go == Py) |
| `ATK-02` | `egress_memory_leak` | `receipt` | `ERR_PRIVATE_MEMORY_LEAK` | Caught (Go == Py) |
| `ATK-03` | `egress_raw_trace_leak` | `receipt` | `ERR_RAW_TRACE_LEAK` | Caught (Go == Py) |
| `ATK-04` | `ingress_memory_smuggling` | `envelope` | `ERR_PRIVATE_MEMORY_REF_FORBIDDEN` | Caught (Go == Py) |
| `ATK-05` | `encoded_exfiltration` | `receipt` | `ERR_ENCODED_SECRET_LEAK` | Caught (Go == Py) |
| `ATK-06` | `agent_card_forgery` | `agent_card` | `ERR_AGENT_CARD_SIG_INVALID` | Caught (Go == Py) |
| `ATK-07` | `agent_card_cred_leak` | `agent_card` | `ERR_AGENT_CARD_CRED_LEAK` | Caught (Go == Py) |
| `ATK-08` | `envelope_sig_tampered` | `envelope` | `ERR_ENVELOPE_SIG_INVALID` | Caught (Go == Py) |
| `ATK-09` | `spoofed_org_identity` | `envelope` | `ERR_SPOOFED_ORG_IDENTITY` | Caught (Go == Py) |
| `ATK-10` | `cross_org_audience_replay` | `envelope` | `ERR_AUDIENCE_MISMATCH` | Caught (Go == Py) |
| `ATK-11` | `expired_envelope` | `envelope` | `ERR_ENVELOPE_EXPIRED` | Caught (Go == Py) |
| `ATK-12` | `nonce_replay` | `envelope` | `ERR_NONCE_REPLAY` | Caught (Go == Py) |
| `ATK-13` | `scope_escalation` | `envelope` | `ERR_SCOPE_ESCALATION` | Caught (Go == Py) |
| `ATK-14` | `ai_governance_boundary` | `governance` | `ERR_AI_VOTING_RULE_FORBIDDEN` | Caught (Go == Py) |
| `ATK-15` | `ai_governance_boundary` | `governance` | `ERR_AI_TREASURY_FORBIDDEN` | Caught (Go == Py) |
| `ATK-16` | `ai_governance_boundary` | `receipt` | `ERR_AI_SELF_CERTIFY_FORBIDDEN` | Caught (Go == Py) |
| `ATK-17` | `scientific_verification` | `receipt` | `ERR_RESULT_RECOMPUTE_MISMATCH` | Caught (Go == Py) |
| `ATK-18` | `licensing` | `envelope` | `ERR_LICENSE_UNREVIEWED` | Caught (Go == Py) |
| `POS-19` | `ai_governance_boundary` | `advisory` | `OK` (Valid non-binding AI review) | Accepted (Go == Py) |

---

## 4. Dual-Language Offline Verifier Latency & Parity

Measured on Linux `amd64` (2-vCPU Xeon @ 2.30 GHz) with Go 1.24.3 (`go test -bench=. -benchmem`) and zero-dependency pure-Python 3.12.16 (stdlib-only pure-Python RFC 8032 Ed25519):

| Operation | Go 1.24 Latency | Go Allocs / Bytes | Pure-Python 3.12 Latency | Go ↔ Python Output Diff |
|---|---:|---:|---:|---|
| `VerifyAgentCard` | `0.48 ms/op` | `865` / `95.1 KB` | `7.84 ms/op` | `0` bytes diff |
| `VerifyWireTranscript` (`8` frames, `21.6 KB`) | `1.14 ms/op` | `2,103` / `196.1 KB` | `1.14 ms/op` | `0` bytes diff |
| `VerifySuite` (Full `7` stages + `8` wire frames + `19` cases) | `13.71 ms/op` | `28,849` / `2.27 MB` | `213.58 ms/op` | `0` bytes diff |

---

## 5. Exact Reproduction Commands

```bash
# 1. Regenerate live two-server fixture & results.json (--seed 1352)
(cd go && go run ./cmd/a2a-bench --seed 1352)

# 2. Run Go format, vet, race-detector live HTTP tests, and micro-benchmarks
(cd go && gofmt -l . && go vet ./... && go test -race -v -count=1 ./... && go test -bench=. -benchmem -run=^$ ./...)

# 3. Run zero-dependency pure-Python verifier, RFC 8032 Ed25519 vectors, and Go parity tests
(cd python && python3 -m unittest discover -s tests -v)

# 4. Direct bit-identical CLI diff between Go and Python verifiers
diff -u \
  <(cd go && go run ./cmd/a2a-verify --fixture ../fixtures/a2a-exchange-suite.v1.json --compact) \
  <(cd python && python3 -m feda2a_py.cli --fixture ../fixtures/a2a-exchange-suite.v1.json --compact)
```

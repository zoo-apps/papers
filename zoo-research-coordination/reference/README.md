# Federated Agent Organizations over A2A Reference (`federated-a2a.v1`)

Clean-room Apache-2.0 reference implementation, versioned specification (`v1.0.0`), JSON Schema Draft 2020-12, live two-deployment loopback HTTP/JSON-RPC 2.0 + SSE fixture (`7` live stages + `8` captured HTTP wire frames + `19` adversarial/constitutional checks), reproducible benchmark (`--seed 1352`), and dual independent zero-dependency **Go 1.24 + pure-Python 3** verifiers for **`zoo-apps/papers#4`** (HIP-1352).

Grounds [`../zoo-research-coordination.tex`](../zoo-research-coordination.tex) (ZooCoord / ZIP-008) over the Apache-2.0 Agent-to-Agent (A2A) protocol (`/.well-known/agent.json` `AgentCard`, JSON-RPC 2.0 `tasks/send`, `tasks/sendSubscribe` SSE, `tasks/get`, `tasks/cancel`).

## Highlights

- **Real Two-Deployment Live HTTP Exchange**: `OrgAlpha` and `OrgBeta` each run an independent `net/http` server on loopback (`127.0.0.1:0`) with completely isolated credential stores, tiered memory vaults, Ed25519 keys, internal HMAC capability secrets, nonce replay caches, and fail-closed Egress Boundary Firewalls—zero shared database, zero shared credentials, zero shared memory.
- **Demonstrated Credential & Private-Memory Isolation**: Every HTTP request, response, `AgentCard`, and SSE frame (`8` live frames, `21,650` bytes) is recorded and independently audited by both Go and Python verifiers proving **`0` internal credential bytes**, **`0` private memory bytes**, and **`0` raw reasoning trace bytes** on the wire (`wire_transcript_root = 2e239c787ac5c41ebc13f3ef9840ba685736df867b8fe92783b45a8704001115`).
- **Live Prompt-Injection Egress Block**: Stage 5 sends a live HTTP prompt-injection exfiltration task to `OrgBeta`; `OrgBeta`'s live Egress Boundary Firewall intercepts the draft response fail-closed *before* writing to TCP (`wire_bytes_sent = 0`), logs a signed `EgressBlockEvent`, and returns HTTP `403` (`ERR_EGRESS_CREDENTIAL_BLOCKED`).
- **Zero Third-Party Dependencies & 100.0% Bit-Exact Go ↔ Python Parity**: Both Go (`go/go.mod`, stdlib only) and Python (`python/feda2a_py/`, stdlib only including clean-room pure-Python RFC 8032 Ed25519 verification) produce byte-identical JSON reports (`diff -u` = `0` bytes) and RFC 6962 `audit_merkle_root`:
  `b89d26031a589c29aaca4822c2e6155e3f780f4af8b5c3b5ac8cd8e115c4a3d8`
- **Independent Scientific Verification & Constitutional AI Boundaries**: Both organizations independently recompute deterministic fixed-point ZooCoord ZHL (`COMPARE` and `CORRELATE`) outputs before `HUMAN_REVIEWER` acceptance. `AI_AGENT` principals can emit non-binding advisory assessments (`POS-19`), while attempts to redefine voting rules (`ATK-14`), authorize treasury spending (`ATK-15`), or self-certify experiment validity (`ATK-16`)—alongside credential/memory/trace/Base64 leaks, forged AgentCards, spoofed identities, wrong-audience/expired/nonce replay, scope escalation, tampered results, and unreviewed licenses—are caught **`18/18` (`100%`)**.

## Layout

```
zoo-research-coordination/reference/
├── README.md                              # Overview and quickstart
├── SPEC.md                                # Normative federated-a2a.v1 (v1.0.0) spec + What Remains Unproven
├── BENCHMARK.md                           # Live 2-server HTTP latency/throughput, honest negative regime & matrix
├── results.json                           # Deterministic machine-readable benchmark output (--seed 1352)
├── schema/
│   └── federated-a2a.v1.schema.json       # JSON Schema Draft 2020-12
├── fixtures/
│   └── a2a-exchange-suite.v1.json         # Live 2-server HTTP/SSE transcript (7 stages, 8 frames) + 19 cases
├── go/                                    # Zero-dependency Go 1.24 implementation, CLIs & race-tested suite
│   ├── go.mod
│   ├── feda2a/
│   └── cmd/{a2a-verify,a2a-bench}/
└── python/                                # Zero-dependency pure-Python 3 verifier (incl. RFC 8032 Ed25519)
    ├── feda2a_py/
    └── tests/
```

## Quick Verification

```bash
# Go format, vet, and race-tested live two-deployment HTTP/SSE suite
(cd go && gofmt -l . && go vet ./... && go test -race -v -count=1 ./...)

# Pure-Python verifier, RFC 8032 Ed25519 vectors, and live Go↔Python parity check
(cd python && python3 -m unittest discover -s tests -v)

# Re-run live two-deployment exchange & regenerate fixture + results.json (--seed 1352)
(cd go && go run ./cmd/a2a-bench --seed 1352)

# Verify byte-identical CLI output across Go and Python (0 bytes diff)
diff -u \
  <(cd go && go run ./cmd/a2a-verify --fixture ../fixtures/a2a-exchange-suite.v1.json --compact) \
  <(cd python && python3 -m feda2a_py.cli --fixture ../fixtures/a2a-exchange-suite.v1.json --compact)
```

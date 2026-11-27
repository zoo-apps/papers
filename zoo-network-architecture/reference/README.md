# Open Decentralized Inference Network (`zoo-apps/papers#12`)

Zero-dependency, Apache-2.0 reference implementation, versioned specification (`inference-net.v1`), JSON Schema, dual independent Go/Python verifiers, live loopback TCP/HTTP failover cluster, and grounded reproducible benchmark for **`zoo-apps/papers#12` (`HIP-1350`)**, aligned with [`zoo-network-architecture`](../zoo-network-architecture.tex) (`08-inference-router.tex`, `09-gpu-compute-nodes.tex`, `11-security-and-byzantine-robustness.tex`, `12-comparison-with-centralized-platforms.tex`).

- **License**: Apache-2.0
- **External Dependencies**: **Zero** (Go 1.24 stdlib + Pure Python 3.12 stdlib, including pure-Python RFC 8032 Ed25519)
- **Topologies Benchmarked**: `centralized_datacenter_baseline`, `decentralized_replica_dynamo` (NVIDIA Dynamo-inspired disaggregated prefill/decode + KV-prefix affinity), `decentralized_pipeline_petals` (Petals-style 4-hop WAN layer-sharded pipeline), and `decentralized_privacy_strict_tee` (`TEE_ATTESTED` / `LOCAL_PRIVATE` hard boundary)
- **Constitutional Locks**: `proves_scientific_truth: false` and `authorizes_treasury_spend: false` (`"const": false` enforced in JSON Schema and both verifiers)

## Repository Layout

```text
zoo-network-architecture/reference/
├── README.md                              # Overview, quickstart & headline results
├── SPEC.md                                # Versioned protocol specification (inference-net.v1, v1.0.0)
├── BENCHMARK.md                           # Measured comparison vs centralized baseline, 3 negative regimes & What Remains Unproven
├── corpus-manifest.json                   # Pinned SHA-256 digests of 8 real zoo-apps/papers .tex sources
├── results.json                           # Machine-readable benchmark output (--seed 1350, 1,120 requests)
├── schema/
│   └── inference-net.v1.schema.json       # JSON Schema Draft 2020-12 with const-locked constitutional fields
├── fixtures/
│   └── parity-suite.v1.json               # 18 canonical cases for Go <-> Python bit-identical parity
├── go/                                    # Pure Go 1.24 stdlib router, capacity accountant, loopback HTTP cluster & CLIs (0 deps)
│   ├── go.mod
│   ├── infnet/
│   │   ├── types.go                       # Wire types, canonical binary encodings, Ed25519 & SHA-256 Merkle trees
│   │   ├── discovery.go                   # Permissionless worker registry (Ed25519, key pinning, monotonic heartbeat_epoch)
│   │   ├── capacity.go                    # Atomic VRAM + KV-slot accountant, zero-leak ledger & conservation replay
│   │   ├── router.go                      # Privacy-boundary enforcer, Dynamo vs Petals routing & failover recovery
│   │   ├── transport.go                   # Live loopback TCP HTTP/1.1 heterogeneous worker cluster with live failover
│   │   ├── verify.go                      # Independent Go verifier for ParityCase & ParitySuite
│   │   ├── benchmark.go                   # Grounded corpus benchmark, failure sweeps & 3 honest negative regimes
│   │   └── infnet_test.go                 # 15 -race tests (concurrency stress, live HTTP failover, privacy, tampering)
│   └── cmd/
│       ├── infnet-bench/main.go           # Reproducible benchmark + parity fixture generator CLI
│       └── infnet-verify/main.go          # Independent Go parity & audit_merkle_root verifier CLI
└── python/                                # Independent Pure Python 3.12 stdlib verifier (0 deps)
    ├── infnet_verifier/
    │   ├── ed25519.py                     # Pure-Python RFC 8032 Ed25519 signature verifier
    │   ├── canonical.py                   # Canonical binary payloads & SHA-256 Merkle trees matching Go bit-for-bit
    │   ├── verifier.py                    # Independent advertisement, receipt, privacy, capacity & constitutional verifier
    │   └── cli.py                         # Parity & results cross-check CLI
    └── tests/
        └── test_infnet_verifier.py        # 12 unittest cases asserting 100% Go <-> Python bit-identical parity
```

## Quickstart & Verification

```bash
cd zoo-network-architecture/reference

# Go vet + race-detector test suite (15 tests, 0 races)
(cd go && go vet ./... && go test -v -race -count=1 ./...)

# Pure-Python unittest suite (12 tests, 0 external packages)
(cd python && PYTHONPATH=. python3 -m unittest discover -s tests -v)

# Reproduce grounded benchmark (--seed 1350) and assert 100% Go <-> Python parity
(cd go && go run ./cmd/infnet-bench --repo ../../.. --manifest ../corpus-manifest.json --seed 1350 --requests 80 --out ../results.json --fixtures ../fixtures/parity-suite.v1.json)
(cd go && go run ./cmd/infnet-verify --suite ../fixtures/parity-suite.v1.json --results ../results.json)
(cd python && PYTHONPATH=. python3 -m infnet_verifier.cli parity --suite ../fixtures/parity-suite.v1.json --go-results ../results.json)
```

## Headline Benchmark Results (`--seed 1350`)

- **Cross-Language Parity**: **18 / 18 (100.00%) Go ↔ Python bit-identical** verdicts, error codes, verdict digests, and `audit_merkle_root` (`001b69f9e108c41f8510190f80e20f57666eeaa33c234ec9d0ed6ee7a7360661`).
- **Safety & Conservation Across All 1,120 Executed Requests**: **0 privacy boundary leaks**, **0 leaked VRAM MiB / KV slots**, and **640 / 640 (100.00%)** core-scenario receipts cryptographically verified.
- **Throughput / Latency vs Centralized Baseline (`centralized_datacenter_baseline`: `1298.31 tok/s`, `TTFT p50 = 103.19 ms`, `TPOT p50 = 11.67 ms`, `Batch = 91.00%`)**:
  - `decentralized_replica_dynamo_fail0`: `746.83 tok/s` (`58%` of baseline), `TTFT p50 = 1333.95 ms`, `TPOT p50 = 19.79 ms` (`1.70×`), `Batch = 77.10%`, `Prefix Hit = 66.25%`, `Comp = 100.00%`.
  - `decentralized_replica_dynamo_fail10` / `fail25`: `713.47` / `541.54 tok/s`, `Comp = 100.00%` / `98.75%`, `Avg Recovery = 1090.08` / `1146.61 ms`, `0` capacity leaks.
  - `decentralized_pipeline_petals_fail0` / `fail10`: `188.98` / `173.68 tok/s`, `TPOT p50 = 182.44 ms` (`15.63×` slower), `Batch = 31.58%` / `29.25%`, `Comp = 100.00%` / `96.25%` (compounded 4-hop crash exposure).
  - `decentralized_privacy_strict_tee_balanced`: `798.96 tok/s`, `TPOT p50 = 17.12 ms`, `Comp = 100.00%`, **0 privacy leaks**.
- **3 Explicit Honest Negative Regimes** (detailed in [`BENCHMARK.md`](BENCHMARK.md)):
  1. `neg_petals_wan_pipeline_latency_loss`: Petals 4-hop WAN pipeline is **`15.63×` slower in TPOT**, **`55.41×` slower in TTFT**, transfers **`4,139×` more bytes/req**, and loses **`59.37` pct pts** of batching utilization vs centralized datacenter inference.
  2. `neg_high_churn_cascade_recovery`: At **`35%` simultaneous worker churn**, `p99 TTFT` spikes **`6.92×`**, completion drops to **`91.25%`** (vs `100.00%` HA baseline), and throughput drops to **`36%`** with `0` leaked capacity slots.
  3. `neg_privacy_strict_capacity_bottleneck`: Under **`20%` TEE supply vs `80%` `PRIVACY_STRICT` demand**, `p50`/`p99 TTFT` inflate **`7.97×`** / **`9.34×`** (`3446.65 ms` mean queue wait) and throughput drops to **`34%`** with strictly **`0` privacy leaks**.

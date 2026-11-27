# Reproducible Benchmark Report: Open Decentralized Inference Network (`zoo-apps/papers#12`)

- **Protocol / Schema**: `inference-net.v1` (`v1.0.0`, [`SPEC.md`](SPEC.md), [`schema/inference-net.v1.schema.json`](schema/inference-net.v1.schema.json))
- **Issue / HIP**: `zoo-apps/papers#12` (`HIP-1350`)
- **Seed**: `1350` (`--requests 80` grounded requests per scenario, `1,120` total executed requests across 8 core scenarios + 3 paired negative-regime studies)
- **Grounded Corpus**: 8 real `zoo-apps/papers` `.tex` files pinned by SHA-256 in [`corpus-manifest.json`](corpus-manifest.json) (`corpus_root_sha256 = 75364da7dd670e2367001b3e34361d09fb133f45b1c5520abb3a367a31b5190e`)
- **Machine-Readable Artifact**: [`results.json`](results.json)
- **Cross-Language Parity Suite**: [`fixtures/parity-suite.v1.json`](fixtures/parity-suite.v1.json) — **18 / 18 (100.00%) Go ↔ Python bit-identical** verdicts & `audit_merkle_root = 001b69f9e108c41f8510190f80e20f57666eeaa33c234ec9d0ed6ee7a7360661`
- **Constitutional Locks**: `proves_scientific_truth: false`, `authorizes_treasury_spend: false`

---

## 1. Experimental Setup & Corpus Grounding

All inference prompts and shared KV-cache prefixes are deterministically sliced from 8 verified LaTeX sources in this repository (`48,293` bytes total, SHA-256 checked at load time):

- `zoo-network-architecture/sections/03-layered-architecture.tex`
- `zoo-network-architecture/sections/08-inference-router.tex`
- `zoo-network-architecture/sections/09-gpu-compute-nodes.tex`
- `zoo-network-architecture/sections/11-security-and-byzantine-robustness.tex`
- `zoo-network-architecture/sections/12-comparison-with-centralized-platforms.tex`
- `zoo-mobile-inference/sections/05-condition-aware-inference.tex`
- `zoo-fhe-ai/zoo-fhe-ai.tex`
- `zoo-gym-orchestrator/zoo-gym-orchestrator.tex`

**Target Model Profile**: 32-layer, 4096-hidden-dim GQA-8 FP16 transformer (`zoo-qwen3-14b-instruct`, `128 KiB/token` KV cache, `8 KiB/token` FP16 hidden-state activation).
**Heterogeneous Hardware Profiles**: `H100-80GB` (datacenter NVLink 0.2 ms / 400 Gbps or WAN 18–24 ms / 5–10 Gbps), `RTX-4090-24GB` (WAN 22–34 ms / 0.8–1 Gbps), `Mac-M4-Max-64GB` (WAN 28–38 ms / 500 Mbps, `LOCAL_PRIVATE`), and `Consumer-12GB` (WAN 32–48.5 ms / 150 Mbps, 8-layer Petals pipeline shards).

---

## 2. Core Comparative Results vs Centralized Datacenter Baseline (`--seed 1350`)

Every single generated `DeliveryReceipt` across all 8 scenarios (`640 / 640`, **100.00%**) passed independent cryptographic Ed25519 signature, output-token Merkle root, privacy-boundary, and capacity-conservation verification with **0 privacy leaks** and **0 leaked VRAM/KV slots**.

| Scenario | Topology | Fail % | Tok/s | Req/s | TTFT p50 (ms) | TTFT p95 (ms) | TTFT p99 (ms) | TPOT p50 (ms) | TPOT p95 (ms) | Net Bytes / Req | Batch Util % | Prefix Hit % | Comp % | Failovers | Avg Recov (ms) | Privacy Leaks | Cap Leaks |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `centralized_datacenter_baseline` | Centralized 8×H100 | 0% | **1298.31** | **14.95** | **103.19** | 264.30 | **303.07** | **11.67** | 11.67 | **3,118** | **91.00%** | 65.00% | **100.00%** | 0 | 0.00 | 0 | 0 |
| `centralized_datacenter_fail10` | Centralized 8×H100 HA | 10% | 1317.82 | 15.17 | 103.19 | 616.62 | 824.62 | 11.67 | 11.67 | 3,318 | 90.53% | 66.25% | 100.00% | 5 | 536.56 | 0 | 0 |
| `decentralized_replica_dynamo_fail0` | Dynamo Disagg/Replica | 0% | 746.83 | 8.60 | 1333.95 | 2810.59 | 3002.88 | 19.79 | 24.25 | 8,526,894 | 77.10% | 66.25% | 100.00% | 0 | 0.00 | 0 | 0 |
| `decentralized_replica_dynamo_fail10` | Dynamo Disagg/Replica | 10% | 713.47 | 8.21 | 1464.65 | 3342.00 | 4102.10 | 19.79 | 24.25 | 10,328,599 | 76.68% | 66.25% | 100.00% | 7 | 1090.08 | 0 | 0 |
| `decentralized_replica_dynamo_fail25` | Dynamo Disagg/Replica | 25% | 541.54 | 6.25 | 1992.62 | 4797.76 | 6480.92 | 19.98 | 25.16 | 12,920,412 | 75.42% | 60.76% | 98.75% | 19 | 1146.61 | 0 | 0 |
| `decentralized_pipeline_petals_fail0` | Petals 4-Hop WAN | 0% | 188.98 | 2.18 | 7097.52 | 10961.31 | 11600.32 | 182.44 | 184.94 | 12,874,184 | 31.58% | 0.00% | 100.00% | 0 | 0.00 | 0 | 0 |
| `decentralized_pipeline_petals_fail10` | Petals 4-Hop WAN | 10% | 173.68 | 1.99 | 7200.91 | 12226.56 | 12770.49 | 182.44 | 189.93 | 18,234,414 | 29.25% | 0.00% | 96.25% | 27 | 3465.33 | 0 | 0 |
| `decentralized_privacy_strict_tee_balanced` | Strict TEE / Local (60%) | 0% | 798.96 | 9.20 | 1386.68 | 2304.23 | 2486.74 | 17.12 | 24.84 | 3,118 | 71.66% | 50.00% | 100.00% | 0 | 0.00 | **0** | 0 |

### Key Takeaways
1. **Dynamo-style heterogeneous replicas beat Petals-style WAN pipelines by ~4× in throughput and ~9.2× in TPOT**: Keeping full model weights on each replica (or disaggregating prefill → decode across high-bandwidth links with KV-prefix cache hits at `66.25%`) keeps `TPOT p50 = 19.79 ms/tok` (`1.70×` centralized `11.67 ms/tok`), whereas Petals 4-hop WAN pipelining degrades to `182.44 ms/tok` (`15.63×` slower!).
2. **Centralized datacenters still dominate interactive latency & batch packing**: Even well-routed decentralized Dynamo replicas pay WAN RTT, KV-cache wire transfer (`8.53 MB/req` vs `3.1 KB/req`), and `13.9` percentage points of batching efficiency loss (`77.10%` vs `91.00%`).
3. **Compounded Multi-Hop Reliability Risk**: At `10%` per-node mid-request crash probability, single/disaggregated replicas sustain `100.0%` completion (7 failovers, `1.09 s` mean recovery), while 4-hop Petals pipelines expose every request to 4 independent failure points (`1 - 0.9^4 = 34.4%` per-attempt crash probability), causing 27 failovers, `3.47 s` mean recovery, `18.23 MB/req` network retransmission, and `96.25%` completion.
4. **Zero-Leak Invariants Under Failure**: Across all `1,120` requests including `0%`, `10%`, `25%`, and `35%` failure injection, **0 MiB of VRAM and 0 KV slots were leaked** and **0 privacy boundary violations occurred**.

---

## 3. Three Explicit Honest Negative Regimes

Directly testing `zoo-apps/papers#12`'s core thesis — *"peer-to-peer execution will not beat centralized inference for every workload"* — we quantify three explicit regimes where decentralized execution demonstrably loses to centralized baselines:

### Negative Regime 1: Petals-Style Multi-Hop WAN Pipeline Latency & Batching Loss (`neg_petals_wan_pipeline_latency_loss`)
- **Workload**: 80 grounded interactive requests (`64` output tokens), 4-hop WAN pipeline (`32–48.5 ms` RTT/hop, `150–250 Mbps`) vs `centralized_datacenter_baseline`.
- **Measured Result**:
  - **TPOT p50 slowdown**: **`15.63×` slower** (`182.44 ms/tok` vs `11.67 ms/tok`) because every single generated token pays the full 4-hop WAN RTT ring plus FP16 hidden-state transfer.
  - **TTFT p50 slowdown**: **`55.41×` slower** (`6099.87 ms` vs `110.08 ms`) due to prompt hidden-state activation transfers across 3 WAN links, pipeline fill bubbles, and bottleneck-stage queuing.
  - **Network transfer blowup**: **`4,138.99×` more bytes/request** (`12,979,878 B` vs `3,136 B`).
  - **Batching utilization collapse**: drops **`59.37` percentage points** (`31.63%` vs `91.00%`).
  - **Throughput retention**: only **`18%`** of centralized baseline (`198.76 tok/s` vs `1076.08 tok/s`).
- **Conclusion**: Petals-style WAN layer-sharding is viable for democratizing access to models that exceed single-node VRAM on latency-tolerant batch tasks, **not** as a drop-in replacement for centralized interactive serving.

### Negative Regime 2: Rapid-Churn Failure Storm (`neg_high_churn_cascade_recovery`)
- **Workload**: 80 grounded requests (`30 ms` inter-arrival) under **`35%` simultaneous mid-request worker drop rate** (interactive retry budget = `1`) on decentralized heterogeneous replicas vs centralized HA cluster (`5%` transient fault rate, retry budget = `2`).
- **Measured Result**:
  - **TTFT p99 spike**: **`6.92×` worse** (`4688.34 ms` vs `677.76 ms`); total latency p99 spikes **`4.38×`**.
  - **Failover recovery tax**: average recovery adds **`785.04 ms`** per failover (`17` requests recovered via failover).
  - **Reliability degradation**: completion rate drops to **`91.25%`** (`7 / 80` requests failed/exhausted) vs **`100.00%`** on centralized HA.
  - **Throughput retention**: **`36%`** of HA baseline (`527.73 tok/s` vs `1470.10 tok/s`).
  - **Safety**: `0` leaked VRAM MiB and `0` leaked KV slots despite 24 mid-flight aborts.

### Negative Regime 3: Strict Privacy Pool Scarcity (`neg_privacy_strict_capacity_bottleneck`)
- **Workload**: Same 10-node decentralized fleet where only **`20%`** of nodes (`2 / 10`) are `TEE_ATTESTED` / `LOCAL_PRIVATE` and `80%` are `PUBLIC_RELAY`, comparing **`80%` `PRIVACY_STRICT` demand** against unconstrained `PUBLIC_OK` routing.
- **Measured Result**:
  - **TTFT p50 inflation**: **`7.97×` worse** (`3568.49 ms` vs `447.48 ms`).
  - **TTFT p99 inflation**: **`9.34×` worse** (`8161.34 ms` vs `873.60 ms`).
  - **Mean queue wait explosion**: **`3446.65 ms`** vs **`136.68 ms`** (`25.2×` higher queuing delay) because hard privacy boundaries forbid spilling `PRIVACY_STRICT` prompts onto the 8 idle `PUBLIC_RELAY` nodes.
  - **Throughput retention**: **`34%`** of unconstrained routing (`402.88 tok/s` vs `1171.29 tok/s`).
  - **Privacy guarantee**: strictly **`0` plaintext leaks** — quantifying the exact privacy-vs-latency Pareto frontier.

---

## 4. Go ↔ Python Bit-Identical Parity Verification

The canonical [`fixtures/parity-suite.v1.json`](fixtures/parity-suite.v1.json) contains **18 end-to-end test cases** (7 valid topologies/failovers/epoch refreshes + 11 adversarial rejections covering forged Ed25519 receipt signatures, output Merkle chunk tampering, `PUBLIC_RELAY` leaks on active and failed hops, VRAM/KV capacity leaks, VRAM oversubscription, stale heartbeat epoch replays, key-rotation spoofing, forged node advertisements, and both constitutional lock violations).

- **Go Verifier (`infnet-verify`)**: `18 / 18 PASS`, `audit_merkle_root = 001b69f9e108c41f8510190f80e20f57666eeaa33c234ec9d0ed6ee7a7360661`
- **Pure-Python 3.12 Verifier (`infnet_verifier`)**: `18 / 18 PASS` (**100.00% bit-identical** error codes, boolean flags, per-case verdict digests, and `audit_merkle_root`)

---

## 5. Reproduction Commands

```bash
cd zoo-network-architecture/reference

# 1. Go static analysis + race-detector test suite (15 tests, including live loopback HTTP failover)
(cd go && go vet ./... && go test -v -race -count=1 ./...)

# 2. Reproduce full grounded benchmark (--seed 1350) and canonical parity suite
(cd go && go run ./cmd/infnet-bench --repo ../../.. --manifest ../corpus-manifest.json --seed 1350 --requests 80 --out ../results.json --fixtures ../fixtures/parity-suite.v1.json)

# 3. Independent Go verification
(cd go && go run ./cmd/infnet-verify --suite ../fixtures/parity-suite.v1.json --results ../results.json)

# 4. Independent Pure-Python 3.12 stdlib verification + 12-test unittest suite (0 external packages)
(cd python && PYTHONPATH=. python3 -m unittest discover -s tests -v)
(cd python && PYTHONPATH=. python3 -m infnet_verifier.cli parity --suite ../fixtures/parity-suite.v1.json --go-results ../results.json)
```

---

## 6. What Remains Unproven

1. **Real GPU Kernel Execution (`CUDA` / `vLLM` / `SGLang` / `llama.cpp`)**: Throughput, continuous batching utilization, and KV-cache eviction are modeled from analytical hardware profiles rather than measured on live physical GPU clusters.
2. **Real Multi-Region WAN Internet Transport**: While [`go/infnet/transport.go`](go/infnet/transport.go) executes live HTTP/1.1 failover over loopback TCP (`127.0.0.1`), live cross-continent BGP jitter, TCP/QUIC congestion control, residential NAT traversal, and asymmetric ISP packet loss remain unmeasured.
3. **Activation-Level Cryptographic Privacy for Split-Layer Inference**: Hard routing boundaries stop plaintext prompts from touching `PUBLIC_RELAY` nodes, but defending intermediate hidden states in split-layer pipelines against activation inversion requires MPC/FHE (`zoo-fhe-ai`), which is not implemented here.
4. **Hardware Remote Attestation Chain Validation**: Verifying real Intel TDX / AMD SEV-SNP / NVIDIA Hopper Confidential Computing hardware attestation certificates against vendor root CAs is outside this zero-dependency stdlib reference.
5. **Byzantine Output Correctness & On-Chain Economic Settlement**: `DeliveryReceipt` proves signed provider delivery and accounting, not faithful weight execution (which pairs with `zoo-poai-consensus` Freivalds/zkML verification), Sybil-resistant stake slashing, or live payment channels.

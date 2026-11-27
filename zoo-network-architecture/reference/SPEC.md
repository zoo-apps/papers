# Open Decentralized Inference Network Specification (`inference-net.v1`)

- **Specification Version**: `1.0.0`
- **Schema Identifier**: `inference-net.v1` ([`schema/inference-net.v1.schema.json`](schema/inference-net.v1.schema.json))
- **Issue / HIP**: `zoo-apps/papers#12` (`HIP-1350`)
- **License**: Apache-2.0
- **Aligned Papers**: [`zoo-network-architecture`](../zoo-network-architecture.tex) (`08-inference-router.tex`, `09-gpu-compute-nodes.tex`, `11-security-and-byzantine-robustness.tex`, `12-comparison-with-centralized-platforms.tex`), [`zoo-mobile-inference`](../../zoo-mobile-inference/zoo-mobile-inference.tex), [`zoo-fhe-ai`](../../zoo-fhe-ai/zoo-fhe-ai.tex), [`zoo-gym-orchestrator`](../../zoo-gym-orchestrator/zoo-gym-orchestrator.tex)
- **Prior Art Grounding**: Petals collaborative layer-sharded inference (Borzunov et al.) and NVIDIA Dynamo disaggregated prefill/decode serving.

---

## 1. Design Goals & Scope

`inference-net.v1` specifies a verifiable, zero-dependency protocol for routing LLM inference across heterogeneous decentralized compute nodes with:

1. **Permissionless Worker Discovery**: RFC 8032 Ed25519-signed capability advertisements (`NodeAdvertisement`) supporting heterogeneous hardware (`H100-80GB`, `RTX-4090-24GB`, `Mac-M4-Max-64GB`, `Consumer-12GB`), key pinning, and strictly monotonic heartbeat epochs.
2. **Strict Capacity Accounting**: Atomic VRAM (MiB) and KV-cache slot reservation/release with an append-only `CapacityEvent` ledger and a deterministic conservation replay check enforcing **zero oversubscription** and **zero capacity leaks** under concurrency or mid-request crashes.
3. **Congestion- & Locality-Aware Routing**: Unified comparison across four concrete execution topologies:
   - `centralized_datacenter_baseline` (co-located homogeneous `H100-80GB` NVLink/RDMA cluster)
   - `decentralized_replica_dynamo` (heterogeneous whole-model & disaggregated prefill/decode replicas with KV-prefix cache affinity over WAN)
   - `decentralized_pipeline_petals` (4-hop WAN layer-sharded pipeline across consumer GPUs)
   - `decentralized_privacy_strict_tee` (hard privacy-bounded routing restricted exclusively to `TEE_ATTESTED` / `LOCAL_PRIVATE` workers)
4. **Failure Recovery & Verified Output Delivery**: Mid-generation crash detection, zero-leak abort release, privacy-preserving warm-standby failover with KV-state replay, and cryptographically signed `DeliveryReceipt` records binding prompt digest, output-token SHA-256 Merkle root, network bytes, latency/recovery accounting, and privacy compliance.
5. **Dual-Language Bit-Identical Verification**: Deterministic binary serialization and error-code precedence ensuring independent Go 1.24 and Pure Python 3.12 stdlib verifiers produce 100% bit-identical verdicts and `audit_merkle_root`.

---

## 2. Cryptographic & Canonical Wire Primitives

To eliminate floating-point formatting or JSON whitespace ambiguity across implementations, all cryptographic signatures and audit digests operate over fixed-width big-endian integer fields and length-prefixed UTF-8 strings:

- `u32(x)`: 4-byte unsigned big-endian integer.
- `u64(x)`: 8-byte unsigned big-endian integer.
- `bool(b)`: `0x01` if `true`, `0x00` if `false`.
- `lp_str(s)`: `u32(len(utf8(s))) || utf8(s)`.
- `lp_str_slice(xs)`: `u32(len(xs)) || lp_str(xs[0]) || ... || lp_str(xs[n-1])`.

### 2.1 `NodeAdvertisement` Signing Payload

Domain tag: `"ZOO-INFNET-V1-NODE-ADV\x00"` (23 bytes), followed in exact order by:

1. `lp_str(schema_version)` (`"inference-net.v1"`)
2. `lp_str(node_id)`
3. `lp_str(public_key_hex)` (64 lowercase hex chars, 32-byte Ed25519 public key)
4. `lp_str(hardware_profile)` ∈ `{H100-80GB, RTX-4090-24GB, Mac-M4-Max-64GB, Consumer-12GB}`
5. `lp_str(model_id)`
6. `lp_str(execution_role)` ∈ `{WHOLE_MODEL, PREFILL, DECODE, PIPELINE_STAGE}`
7. `u32(layer_start)`, `u32(layer_end)`, `u32(total_layers)`
8. `u64(vram_total_mib)`, `u64(vram_reserved_base_mib)`
9. `u32(kv_slots_total)`, `u32(prefill_tps)`, `u32(decode_tps)`
10. `u64(wan_rtt_us)`, `u64(bandwidth_kbps)`
11. `lp_str(privacy_tier)` ∈ `{TEE_ATTESTED, LOCAL_PRIVATE, PUBLIC_RELAY}`
12. `lp_str(tee_attestation_sha256)` (64 lowercase hex chars required when `privacy_tier == TEE_ATTESTED`, empty otherwise)
13. `u64(heartbeat_epoch)`, `u64(timestamp_unix_s)`

The worker signs this exact byte sequence with RFC 8032 Ed25519 and stores the 64-byte signature in `signature_hex`.

### 2.2 Output-Token SHA-256 Binary Merkle Tree

For ordered output token chunks $c_0, \dots, c_{m-1}$:

- If $m = 0$: $\text{root} = \text{SHA256}(\text{"ZOO-INFNET-V1-EMPTY-MERKLE"})$.
- Leaf $i$: $L_i = \text{SHA256}(\text{0x00} \parallel \text{u32}(i) \parallel \text{utf8}(c_i))$.
- Internal node: $P = \text{SHA256}(\text{0x01} \parallel \text{left}_{32} \parallel \text{right}_{32})$, duplicating the last node when a tree level has odd cardinality.

### 2.3 `DeliveryReceipt` Signing Payload

Domain tag: `"ZOO-INFNET-V1-RECEIPT\x00"` (22 bytes), followed in exact order by:

1. `lp_str(schema_version)`, `lp_str(receipt_id)`, `lp_str(request_id)`
2. `lp_str(topology_mode)`, `lp_str(model_id)`
3. `lp_str(prompt_sha256)`, `lp_str(prompt_prefix_sha256)`
4. `u32(prompt_tokens)`, `u32(output_tokens)`, `lp_str(output_merkle_root)`
5. `lp_str(privacy_requirement)`, `lp_str(effective_privacy_tier)`
6. `lp_str_slice(route_node_ids)`, `lp_str(primary_provider_id)`, `lp_str(provider_public_key_hex)`
7. `lp_str(prefill_node_id)`, `lp_str_slice(decode_node_ids)`
8. `u32(kv_slots_reserved)`, `u64(vram_reserved_mib)`, `u64(network_bytes_transferred)`
9. `u64(ttft_us)`, `u64(tpot_us)`, `u64(total_latency_us)`, `u64(recovery_latency_us)`
10. `u32(failover_attempts)`, `lp_str_slice(failed_node_ids)`
11. `u32(batch_size_effective)`, `u32(batch_utilization_bps)` (`0..10000`)
12. `lp_str(status)` ∈ `{COMPLETED, COMPLETED_WITH_FAILOVER, REJECTED_PRIVACY, FAILED_EXHAUSTED}`
13. `bool(proves_scientific_truth)`, `bool(authorizes_treasury_spend)`

Signed with RFC 8032 Ed25519 by `primary_provider_id`'s private key.

### 2.4 Verdict Digest & `audit_merkle_root`

Each verified case yields:
```text
verdict_digest = SHA256(
    "ZOO-INFNET-V1-VERDICT\x00"
    || lp_str(case_id)
    || bool(valid)
    || lp_str(error_code)
    || bool(signature_valid)
    || bool(privacy_compliant)
    || bool(capacity_conserved)
    || bool(constitutional_valid)
    || lp_str(receipt.output_merkle_root)
)
```
`audit_merkle_root` is the binary SHA-256 Merkle root over the ordered list of `verdict_digest` values across all cases in a suite.

---

## 3. Protocol Safety Invariants

### 3.1 Worker Discovery Invariants
- **Signature Authenticity**: Every advertisement MUST verify under RFC 8032 Ed25519 before admission.
- **Structural Bounds**: `vram_reserved_base_mib <= vram_total_mib`, `0 <= layer_start < layer_end <= total_layers`; `WHOLE_MODEL` requires `[0, total_layers)`; `TEE_ATTESTED` requires a 64-hex `tee_attestation_sha256`.
- **Key Pinning**: Re-advertising an existing `node_id` with a different `public_key_hex` is rejected with `ERR_KEY_MISMATCH`.
- **Anti-Replay Monotonicity**: Re-advertising an existing `node_id` with `heartbeat_epoch <= current_epoch` is rejected with `ERR_STALE_HEARTBEAT_EPOCH`.

### 3.2 Capacity Conservation Invariants
For every node $v$ and every prefix of the `CapacityEvent` ledger:
1. Event sequence numbers `seq` are strictly increasing.
2. $\text{vram\_reserved\_base}(v) + \text{vram\_in\_use}(v) \le \text{vram\_total}(v)$ at all times.
3. $\text{kv\_slots\_in\_use}(v) \le \text{kv\_slots\_total}(v)$ at all times.
4. Every `RELEASE` matches an active, unreleased `RESERVE` with identical `(node_id, vram_mib, kv_slots)` (no double-release or underflow).
5. Upon request completion **or mid-request failover/abort**, all reservations are released so terminal leaked VRAM = `0 MiB` and terminal leaked KV slots = `0`.

### 3.3 Privacy-Boundary Invariants
- `PUBLIC_OK` requests may route across `TEE_ATTESTED`, `LOCAL_PRIVATE`, or `PUBLIC_RELAY`.
- `PRIVACY_STRICT` requests MUST route **exclusively** to `TEE_ATTESTED` or `LOCAL_PRIVATE` nodes across every hop (`route_node_ids`, `prefill_node_id`, `decode_node_ids`, **and** `failed_node_ids` on failover).
- Any attempt to place or fail over a `PRIVACY_STRICT` request onto a `PUBLIC_RELAY` node MUST fail closed with `ERR_PRIVACY_BOUNDARY_VIOLATION` (**0 plaintext relay leaks**).
- `effective_privacy_tier` MUST equal the weakest confidentiality tier among all touched nodes (`TEE_ATTESTED > LOCAL_PRIVATE > PUBLIC_RELAY`).

### 3.4 Failure Recovery Protocol
1. Upon worker timeout (`DCFailDetectTimeoutUs = 25 ms`, `WANFailDetectTimeoutUs = 180 ms`) or HTTP 503/transport error during live RPC, the router immediately releases the failed node's VRAM + KV-slot reservation (`reason = "FAILOVER_ABORT"` or `"PIPELINE_FAILOVER_ABORT"`).
2. The failed node is excluded from retry candidates; standby selection re-applies the identical `PrivacyRequirement` filter.
3. The standby replays the prompt plus previously emitted tokens (KV-state recomputation) and resumes generation.
4. If retries are exhausted (or no compliant healthy standby exists), the request terminates cleanly with `FAILED_EXHAUSTED` (or `REJECTED_PRIVACY`) and **0 leaked capacity slots**.

---

## 4. Canonical Verification Error Precedence

Both Go and Python verifiers MUST evaluate all 4 audit flags (`signature_valid`, `privacy_compliant`, `capacity_conserved`, `constitutional_valid`) and assign `error_code` in this exact priority order:

| Priority | Error Code | Trigger Condition |
|---:|---|---|
| 1 | `ERR_SCHEMA_INVALID` | Invalid `schema_version`, enum value, or `batch_utilization_bps > 10000` |
| 2 | `ERR_CONSTITUTIONAL_VIOLATION` | `proves_scientific_truth == true` OR `authorizes_treasury_spend == true` |
| 3 | `ERR_INVALID_NODE_ADVERTISEMENT` / `ERR_STALE_HEARTBEAT_EPOCH` / `ERR_KEY_MISMATCH` | Node advertisement registration failure |
| 4 | `ERR_MISSING_PROVIDER_NODE` | `primary_provider_id` not registered or `provider_public_key_hex` mismatch |
| 5 | `ERR_INVALID_RECEIPT_SIGNATURE` | Ed25519 signature over canonical `DeliveryReceipt` fails |
| 6 | `ERR_OUTPUT_MERKLE_MISMATCH` | Recomputed output Merkle root != `output_merkle_root` or chunk count != `output_tokens` |
| 7 | `ERR_PRIVACY_BOUNDARY_VIOLATION` | Any touched/failed node violates `privacy_requirement` or `effective_privacy_tier` mismatch |
| 8 | `ERR_CAPACITY_CONSERVATION` | Capacity ledger leak, oversubscription, non-monotonic `seq`, or release mismatch |
| 9 | `OK` | All checks pass (`valid = true`) |

---

## 5. Constitutional Governance Boundaries

In accordance with the Zoo × Hanzo open research program charter:

- Every `DeliveryReceipt` and `BenchmarkReport` MUST carry `"proves_scientific_truth": false` and `"authorizes_treasury_spend": false` (schema-enforced via `"const": false`).
- A valid `DeliveryReceipt` proves only **cryptographic provider attribution, output-chunk Merkle integrity, capacity conservation, and routing privacy-boundary compliance** within the modeled protocol.
- It NEVER declares scientific truth, validates model correctness/alignment, redefines DAO voting rules, or authorizes treasury spending.

---

## 6. What Remains Unproven

This reference implementation and benchmark intentionally isolate protocol, routing, capacity-accounting, failure-recovery, and privacy-boundary mechanics without overclaiming production hardware or cryptographic properties. The following remain **unproven** and require follow-on empirical work:

1. **Real GPU / CUDA / vLLM / SGLang Execution**: Compute timings (`prefill_tps`, `decode_tps`, batching amortization, and KV-cache sizing) are parameterized from analytical hardware profiles rather than live CUDA kernel profiling on physical H100, RTX 4090, Apple M4 Max, and 12 GB consumer GPUs.
2. **Real Multi-Region WAN Transport**: While `transport.go` executes live HTTP/1.1 failover over loopback TCP (`127.0.0.1`), cross-continent BGP jitter, TCP congestion control / QUIC head-of-line blocking, residential NAT traversal, and asymmetric ISP packet loss are not measured over live internet links.
3. **Cryptographic Activation-Level Privacy (Split-Layer MPC / FHE)**: Privacy-boundary enforcement prevents routing plaintext prompts to `PUBLIC_RELAY` nodes, but does NOT protect against activation inversion attacks on intermediate hidden states in split-layer Petals pipelines; cryptographic privacy across untrusted pipeline hops requires FHE/MPC (cf. `zoo-fhe-ai`), which carries orders-of-magnitude overhead.
4. **Hardware Remote Attestation Verification**: `tee_attestation_sha256` binds a 32-byte digest into signed advertisements, but full cryptographic verification of live Intel TDX, AMD SEV-SNP, or NVIDIA Hopper Confidential Computing quote chains against hardware vendor root CAs is outside this zero-dependency stdlib scope.
5. **Byzantine Output Equivalence & Sybil-Resistant Economics**: `DeliveryReceipt` proves which provider signed which output tokens, NOT that the tokens were faithfully sampled from exact model weights (which requires coupling with `zoo-poai-consensus` Freivalds/zkML verification), nor does it implement on-chain stake slashing, Sybil resistance, or live payment channels.

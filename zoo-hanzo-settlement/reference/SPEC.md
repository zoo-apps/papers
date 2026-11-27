# Useful-Work Receipt & Contribution Settlement Specification (`settlement-receipt.v1`)

- **Version**: `1.0.0`
- **Protocol ID**: `settlement-receipt.v1`
- **Issue / HIP**: `zoo-apps/papers#15` (`HIP-1350`)
- **References**:
  - Zoo Labs Foundation, *Zoo <-> Hanzo Settlement Integration: AI Compute Payments from Zoo Applications* (`zoo-hanzo-settlement.tex`, ZIP-0801 / ZIP-0700 / ZIP-0800)
  - Ethereum Attestation Service (EAS) structured off-chain / on-chain attestation UID semantics
- **License**: Apache-2.0

---

## 1. Purpose & Design Invariants

This specification defines a deterministic, zero-dependency, three-layer useful-work receipt and contribution settlement protocol for a multi-node test network. It implements the five-stage lifecycle:

```
Admit -> Perform -> Verify -> IssueReceipt -> AuthorizeReward
```

while enforcing four strict invariants:

1. **Chain-of-Authority Separation**: Validation (`Layer 1`), receipt settlement & nullifier accounting (`Layer 2`), and finality-gated reward authorization (`Layer 3`) are isolated authority domains with disjoint cryptographic key sets.
2. **Read-Only Application Consumption**: Applications (`APPLICATION`) consume verified receipts read-only and **never** issue receipts or authorize token disbursement (`ERR_APP_ISSUANCE_FORBIDDEN`).
3. **Constitutional AI Governance Locks**: AI agents (`AI_AGENT`) may recommend, estimate value, and flag conflicts, but **cannot** mutate quorum/cap/finality policy (`ERR_AI_POLICY_MUTATION_FORBIDDEN`), self-verify their own work (`ERR_SELF_VERIFICATION_FORBIDDEN`), or authorize treasury disbursement (`ERR_AI_ISSUANCE_FORBIDDEN`).
4. **Zero Double Claims & Exact Integer Conservation**: Every settled work unit produces a unique domain-separated nullifier persisted via crash-safe `fsync` WAL; all accounting uses exact 64-bit signed integer micro-ZOO (`1 ZOO = 1,000,000 micro-ZOO`) with zero floating-point rounding drift.

---

## 2. Role Taxonomy & Cryptographic Key Separation

Every network participant is registered with an immutable `(id, role, public_key_hex)` tuple, where `public_key_hex` is a 32-byte RFC 8032 Ed25519 public key encoded as 64 lowercase hex characters:

| Role | Layer | Permitted Operations | Hard-Blocked Operations |
| :--- | :---: | :--- | :--- |
| `PAYER` | L1 input | Escrow budget & submit `AdmittedJob` | Attest, settle, authorize rewards, mutate policy |
| `PROVIDER` | L1 compute | Execute workload & emit `WorkResult` | Self-verify (`ERR_SELF_VERIFICATION_FORBIDDEN`), settle, authorize |
| `VALIDATOR` | **Layer 1** | Independently verify `WorkResult` and sign `EASAttestation` | Hold treasury keys, self-verify own work, authorize rewards (`ERR_UNAUTHORIZED_TREASURY`) |
| `SETTLEMENT_NODE` | **Layer 2** | Consume quorum attestations, maintain nullifier WAL & Merkle tree, issue `UsefulWorkReceipt` | Sign validator attestations, authorize treasury disbursement (`ERR_UNAUTHORIZED_TREASURY`) |
| `GOVERNANCE_TREASURY` | **Layer 3** | Verify finalized epoch, Merkle proof, quorum & cap; sign `RewardAuthorization`; update policy caps | Sign validator attestations for its own disbursements |
| `APPLICATION` | Consumer | Read-only query of settled/finalized receipts | Issue receipts (`ERR_APP_ISSUANCE_FORBIDDEN`), authorize rewards (`ERR_APP_ISSUANCE_FORBIDDEN`), mutate policy |
| `AI_AGENT` | Advisory | Read-only audit, conflict flagging, estimation | Authorize rewards (`ERR_AI_ISSUANCE_FORBIDDEN`), mutate treasury caps/quorum (`ERR_AI_POLICY_MUTATION_FORBIDDEN`) |

### Key Separation Invariant (`ERR_KEY_ROLE_CONFLICT`)
The Ed25519 public keys across registered principals MUST be pairwise distinct (`public_key(a) != public_key(b)` for all `a != b`). In particular, no `VALIDATOR` may share a signing key with any `GOVERNANCE_TREASURY`, `PROVIDER`, `SETTLEMENT_NODE`, `APPLICATION`, or `AI_AGENT`.

---

## 3. Three-Layer Architecture & Five-Stage Lifecycle

```
Layer 1: Admission & Validation (ValidatorCommittee)
  [1. Admit]   Payer escrows max_budget_micro_zoo for work spec grounded in corpus paper SHA-256
  [2. Perform] Provider computes deterministic output_digest, tokens_processed, compute_units
  [3. Verify]  Independent ValidatorCommittee (n=5, quorum q=3) verifies work & signs EASAttestations
               (Provider != Validator; Validators hold NO treasury keys)
                    |
                    v
Layer 2: Receipt Settlement & Nullifier Ledger (SettlementEngine)
  [4. IssueReceipt]
    - Verifies >= q distinct valid Ed25519 EASAttestations agreeing on (job_id, work_hash, provider, epoch, consumed)
    - Computes exact integer micro-ZOO split (provider, conservation, protocol, refund)
    - Checks nullifier & job_id against fsync WAL-backed Nullifier Set (blocks ALL double-claims & races)
    - Persists receipt to append-only hash-chained WAL with fsync
    - Commits epoch settled receipts into binary Merkle tree -> receipts_merkle_root
    - Exposes read-only receipt view to APPLICATION consumers
                    |
                    v  (Epoch finality delay: finalized_epoch >= receipt_epoch + K)
Layer 3: Finality & Authorized Reward Issuance (FinalityTreasuryGate)
  [5. AuthorizeReward]
    - Requires authority_role == GOVERNANCE_TREASURY (blocks APPLICATION, AI_AGENT, VALIDATOR, SETTLEMENT_NODE)
    - Verifies finality delay (K epochs) and non-expiration (claim window W epochs)
    - Independently re-verifies validator quorum Ed25519 attestations & Merkle inclusion proof
    - Independently checks Layer 3 nullifier set (prevents cross-epoch / replay double-claims)
    - Enforces epoch_authorized_micro_zoo[epoch] + consumed <= epoch_treasury_cap_micro_zoo
    - Emits Ed25519-signed RewardAuthorization & updates deterministic integer BalanceSheet
```

---

## 4. Canonical Cryptographic Encodings

All digests use **SHA-256** encoded as 64 lowercase ASCII hex characters. All signatures use **RFC 8032 Ed25519** (pure Ed25519) encoded as 128 lowercase ASCII hex characters. All identifiers MUST match `^[A-Za-z0-9_.:-]+$` (forbidding the delimiter `|`). Integers are encoded as canonical base-10 ASCII strings without leading zeros (except `"0"`).

### 4.1 EAS-Compatible Schema UID
```
EAS_SCHEMA_STRING = "settlement-receipt.v1|bytes32 job_id,bytes32 work_hash,address provider_id,uint64 epoch,uint64 tokens_processed,uint64 compute_units,int64 consumed_micro_zoo"
SCHEMA_UID        = SHA256("eas-schema:v1|" || EAS_SCHEMA_STRING)
```

### 4.2 Reference UID & Work Hash
```
REF_UID   = SHA256("job:v1|" || job_id)
WORK_HASH = SHA256("work:v1|" || job_id || "|" || corpus_paper_sha256 || "|" || work_spec_hash || "|" || output_digest || "|" || tokens_processed || "|" || compute_units)
```

### 4.3 EAS-Compatible Attestation UID & Validator Signature
```
ATTESTATION_UID = SHA256("eas-attestation:v1|" || schema_uid || "|" || ref_uid || "|" || recipient || "|" || attester || "|" || work_hash || "|" || epoch || "|" || nonce)

VALIDATOR_SIG_MSG = "eas-sig:v1|" || attestation_uid || "|" || job_id || "|" || recipient || "|" || attester || "|" || work_hash || "|" || epoch || "|" || nonce || "|" || consumed_micro_zoo || "|" || tokens_processed || "|" || compute_units
```
`signature_hex = Ed25519.Sign(validator_privkey, UTF8(VALIDATOR_SIG_MSG))`.

### 4.4 Canonical Receipt ID & Nullifier
Let `sorted_att_uids` be the lexicographically sorted `attestation_uid` values of the accepted quorum attestations joined by `,`:
```
RECEIPT_ID = SHA256("receipt:v1|" || job_id || "|" || provider_id || "|" || payer_id || "|" || work_hash || "|" || epoch || "|" || max_budget_micro_zoo || "|" || consumed_micro_zoo || "|" || conservation_bps || "|" || protocol_bps || "|" || sorted_att_uids)

NULLIFIER  = SHA256("nullifier:v1|" || job_id || "|" || receipt_id || "|" || work_hash)
```
Uniqueness is enforced on **both** `nullifier` and `job_id` at Layer 2 and Layer 3, preventing exact replays, cross-epoch replays, and re-attestation replays with mutated validator nonces.

### 4.5 Binary Merkle Tree & Inclusion Proofs
- Empty tree root: `SHA256("merkle-empty:v1")`
- Receipt leaf hash: `SHA256("merkle-leaf:v1|" || receipt_id || "|" || nullifier || "|" || consumed_micro_zoo)`
- Internal node hash: `SHA256("merkle-node:v1|" || left_hex || "|" || right_hex)`
- Odd level rule: if a level has an odd number of nodes, duplicate the last node as its right sibling before pairing.
- Each proof step carries `(sibling_hex, position)` where `position` is `"left"` if `sibling_hex` is concatenated on the left (`merkle-node:v1|sibling|current`) or `"right"` if on the right (`merkle-node:v1|current|sibling`).

### 4.6 Finalized Reward Authorization ID & Treasury Signature
```
AUTH_ID = SHA256("reward-auth:v1|" || receipt_id || "|" || nullifier || "|" || job_id || "|" || provider_id || "|" || receipt_epoch || "|" || finalized_epoch || "|" || provider_share_micro_zoo || "|" || conservation_share_micro_zoo || "|" || protocol_fee_micro_zoo || "|" || refund_micro_zoo || "|" || epoch_merkle_root)

TREASURY_SIG_MSG = "treasury-auth:v1|" || auth_id || "|" || authority_id || "|" || authority_role || "|" || finalized_epoch
```
`treasury_sig_hex = Ed25519.Sign(treasury_privkey, UTF8(TREASURY_SIG_MSG))`.

### 4.7 Audit Merkle Root (`audit_merkle_root`)
For any trace bundle containing ordered cases $c_1, \dots, c_m$:
- Each case produces leaf:
  ```
  SHA256("audit-leaf:v1|" || case_id || "|" || stage || "|" || verdict || "|" || error_code || "|" || receipt_id || "|" || nullifier || "|" || provider_share || "|" || conservation_share || "|" || protocol_fee || "|" || refund)
  ```
- One final balance-sheet leaf is appended:
  ```
  SHA256("balance-sheet:v1|escrow=" || total_escrow || "|authorized=" || total_authorized || "|provider=" || total_provider || "|conservation=" || total_conservation || "|protocol=" || total_protocol || "|refund=" || total_refund || "|" || sorted_provider_pairs)
  ```
  where `sorted_provider_pairs` joins `provider_id:balance` in ascending ASCII order of `provider_id` separated by `,`.
- The binary Merkle root of these $m+1$ leaves is `audit_merkle_root`. Both Go and Python verifiers MUST reproduce the exact same 64-hex `audit_merkle_root`.

---

## 5. Exact Integer Micro-ZOO Accounting (`int64`)

All amounts are non-negative `int64` micro-ZOO (`1 ZOO = 1,000,000 micro-ZOO`). Floating-point arithmetic is strictly forbidden in settlement and treasury paths.

Given `max_budget`, `consumed`, `conservation_bps` (default `200`, 2%), and `protocol_bps` (default `100`, 1%) with `0 <= conservation_bps + protocol_bps <= 10000` and `0 < consumed <= max_budget`:

```
conservation_share = (consumed * conservation_bps) / 10000    // integer floor division
protocol_fee       = (consumed * protocol_bps) / 10000        // integer floor division
provider_share     = consumed - conservation_share - protocol_fee
refund             = max_budget - consumed
```

**Conservation Theorem (Dust-Free Exactness)**:
By subtracting `conservation_share` and `protocol_fee` from `consumed`, any sub-basis-point remainder (`0` or `1` micro-ZOO) accrues deterministically to `provider_share`, guaranteeing:
1. `provider_share + conservation_share + protocol_fee == consumed` (exact identity)
2. `consumed + refund == max_budget` (exact identity)
3. Across all authorized receipts in any arrival permutation:
   - `sum(provider_balances) + conservation_fund + protocol_fee_pool == total_authorized_payout`
   - `total_authorized_payout + total_payer_refunds == total_finalized_escrow`

---

## 6. Crash-Safe WAL & Deterministic Cold-Restart Recovery

Layer 2 (`SettlementEngine`) and Layer 3 (`FinalityTreasuryGate`) persist every state transition (receipt settlement, epoch Merkle seal, reward authorization) to an append-only JSON-lines Write-Ahead Log (WAL) with:
- Sequential monotonic `seq` index (`1, 2, ...`),
- `prev_hash` linking to the previous WAL record's `entry_hash` (genesis `0000...0000`),
- `entry_hash = SHA256("wal:v1|" || seq || "|" || prev_hash || "|" || kind || "|" || payload_sha256)`,
- Explicit `file.Sync()` (`fsync`) before acknowledging the HTTP/RPC response to the caller.

On cold restart, replaying the WAL verifies the hash chain and reconstructs the exact nullifier set, settled receipts, epoch Merkle commitments, and integer balance sheet. Truncated trailing partial writes (crash mid-line) are detected and rejected cleanly rather than silently corrupting balances.

---

## 7. Canonical Error Codes

| Error Code | Trigger Condition |
| :--- | :--- |
| `ERR_INVALID_SCHEMA` | Missing/malformed fields, invalid hex/ID, wrong `schema_uid`, non-positive budget/consumption, or invalid `bps` sum |
| `ERR_BUDGET_OVERFLOW` | `consumed_micro_zoo > max_budget_micro_zoo` |
| `ERR_SELF_VERIFICATION_FORBIDDEN` | `attester == recipient` (`validator_id == provider_id`) or identical public key |
| `ERR_UNAUTHORIZED_VALIDATOR` | Attester is unknown or does not hold role `VALIDATOR` |
| `ERR_INVALID_ATTESTATION_UID` | Recomputed EAS `attestation_uid` or `ref_uid` or `work_hash` does not match |
| `ERR_INVALID_SIGNATURE` | Ed25519 signature verification fails (validator attestation or treasury authorization) |
| `ERR_DUPLICATE_VALIDATOR` | Same validator attests more than once in the same receipt quorum |
| `ERR_INSUFFICIENT_QUORUM` | Fewer than `policy.validator_quorum` valid distinct validator attestations |
| `ERR_ATTESTATION_MISMATCH` | Quorum attestations disagree on `job_id`, `work_hash`, `recipient`, `epoch`, or `consumed_micro_zoo` |
| `ERR_DOUBLE_CLAIM` | `nullifier` or `job_id` has already been settled (Layer 2) or authorized (Layer 3) |
| `ERR_INVALID_RECEIPT_ID` | Recomputed canonical `receipt_id` does not match |
| `ERR_INVALID_NULLIFIER` | Recomputed canonical `nullifier` does not match |
| `ERR_ACCOUNTING_MISMATCH` | Micro-ZOO split fields violate exact integer conservation |
| `ERR_INVALID_MERKLE_PROOF` | Merkle inclusion proof fails against the committed `epoch_merkle_root` |
| `ERR_UNFINALIZED_EPOCH` | `finalized_epoch < receipt_epoch + policy.finality_delay_epochs` |
| `ERR_EPOCH_EXPIRED` | `finalized_epoch > receipt_epoch + policy.claim_window_epochs` |
| `ERR_APP_ISSUANCE_FORBIDDEN` | `APPLICATION` role attempted to issue a receipt or authorize a reward |
| `ERR_AI_ISSUANCE_FORBIDDEN` | `AI_AGENT` role attempted to issue a receipt or authorize a reward |
| `ERR_AI_POLICY_MUTATION_FORBIDDEN` | `AI_AGENT` or `APPLICATION` attempted to modify treasury caps, quorum, or finality policy |
| `ERR_UNAUTHORIZED_TREASURY` | Non-`GOVERNANCE_TREASURY` role (`VALIDATOR`, `SETTLEMENT_NODE`, `PROVIDER`, `PAYER`) attempted reward authorization |
| `ERR_TREASURY_CAP_EXCEEDED` | `epoch_authorized_micro_zoo[receipt_epoch] + consumed_micro_zoo > epoch_treasury_cap_micro_zoo` |
| `ERR_KEY_ROLE_CONFLICT` | Same Ed25519 public key registered across multiple principals / authority layers |

---

## 8. What Remains Unproven

This reference specification and test-network implementation establish cryptographic, state-machine, concurrency, and accounting invariants on a local multi-node loopback test network. The following remain **explicitly unproven** and out of scope for v1.0.0:

1. **On-Chain EVM / Lux C-Chain / Zoo L2 Smart Contract Deployment & Gas Economics**: `ISettlementVault`, `ISettlementLedger`, and `IComputeOracle` are modeled as separated HTTP/JSON-RPC services with integer accounting, not deployed Solidity contracts; EVM gas costs, calldata compression, and L2-to-Lux bridge message fees (ZIP-0800) are not measured on a live chain.
2. **Live Ethereum Attestation Service (`EAS.sol`) Contract Calls**: Attestations follow EAS structured UID, `schemaUID`, `refUID`, `recipient`, and `attester` semantics using RFC 8032 Ed25519 signatures, rather than EIP-712 secp256k1 signatures verified inside deployed `EAS.sol` on Ethereum/Lux EVM.
3. **Economic Slashing, Stake Bonding & >67% Validator Collusion**: The reference implementation enforces cryptographic quorum (`q`-of-`n`) and non-self-verification (`validator != provider`), but does not model stake-weighted slashing, bond confiscation, or sybil collusion where a dishonest supermajority ($\ge q$ of $n$) signs fabricated off-chain compute reports.
4. **Cross-Chain Bridge Finality Reorgs & Byzantine Network Partitions**: Finality delay is modeled as a deterministic epoch offset (`K` epochs). Real-world L2 sequencer reorgs, bridge relayer censorship, and asynchronous WAN Byzantine network partitions are not simulated.
5. **Real GPU/LLM Inference Verification**: Useful-work execution uses deterministic digest verification grounded in real `.tex` corpus chunks rather than end-to-end GPU tensor verification (which is addressed separately by Freivalds PoAI in `zoo-poai-consensus/reference/`).
6. **Legal, Tax, and Regulatory Compliance**: Jurisdictional classification of reward issuance, conservation-credit tax treatment, and KYC/AML obligations for token disbursement are outside the technical protocol scope.

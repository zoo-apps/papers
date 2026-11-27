# Constitutional Governance Formal Verification Benchmark (`constitutional-gov.v1`)

- **Seed**: `1352`
- **Schema / Spec**: `constitutional-gov.v1` / `1.0.0`
- **Results Artifact**: `results.json`
- **Audit Merkle Root (Go & Python bit-identical)**: `ed49e853940e0cb730b6077710ac06a1cea9c9409981aef787e76e479acf0e96`
- **Rego v1 Bundle SHA-256 (Go & Python bit-identical)**: `d4c33c5ce1faa8d102858b75edf646018dcd5d753d5b0a49c283dad5b31cbdd0`

---

## 1. Exact Reproduction Commands

All verification steps use **zero external dependencies** (Go 1.24 stdlib and Python 3.12 stdlib).

```bash
# 1. Run Go vet + 17 race-detector tests (adversarial suite, 63,830-step model checker, 10/10 mutation audit, 3 negative regimes)
cd zoo-dao-emergency-protocol/reference/go
go vet ./...
go test -v -race -count=1 ./...

# 2. Regenerate results.json deterministically (seed=1352) and verify in Go
go run ./cmd/govcheck-bench --seed 1352 --rego-dir ../rego --out ../results.json
go run ./cmd/govcheck-verify --in ../results.json --rego-dir ../rego

# 3. Independently verify all 47 Ed25519-signed cases, ConflictWitness records, Rego v1 bundle, and audit_merkle_root in pure Python
cd ../python
python3 -m unittest discover -v
python3 -m govcheck_verifier.cli --in ../results.json --rego-dir ../rego

# 4. Optional (on hosts with Open Policy Agent CLI installed; opa_cli_available=false in this VM):
cd ..
opa test rego/ -v
```

> **OPA CLI Note**: In this verification environment, `opa` is not preinstalled (`results.json` records `"opa_cli_available": false`). Every `.rego` file is written in strict OPA Rego v1 (`import rego.v1`), structurally verified (balanced delimiters, package declarations, `rego.v1` imports, `>= 6` unit test rules in `rego/constitution_test.rego`), SHA-256 pinned across Go and Python, and ready to execute verbatim with `opa test rego/ -v`.

---

## 2. Adversarial Rule-Conflict & Governance Attack Suite (`47 / 47` Passed)

Every case in `results.json` contains a complete initial state and Ed25519-signed action sequence verified independently by Go (`crypto/ed25519`) and pure Python (`govcheck_verifier/ed25519.py`).

| Invariant | Domain | Total Cases | Adversarial `DENY` | Positive `ALLOW` | Go/Python Parity |
| --- | --- | ---: | ---: | ---: | ---: |
| `INV-01` | AI Constitutional Boundary | 6 | 5 | 1 | `100.0%` |
| `INV-02` | Acyclic Bounded Delegation & Scope/Expiry Attenuation | 6 | 5 | 1 | `100.0%` |
| `INV-03` | Immediate Transitive Revocation | 4 | 4 | 0 | `100.0%` |
| `INV-04` | Quorum & Supermajority Monotonicity / Anti-Shrinking | 6 | 5 | 1 | `100.0%` |
| `INV-05` | Bounded DEFCON-1 Suspension & 72h Auto-Sunset (ZIP-0027) | 6 | 5 | 1 | `100.0%` |
| `INV-06` | Appeal Due-Process Freeze & Zero Self-Adjudication | 5 | 4 | 1 | `100.0%` |
| `INV-07` | 4-Tier Rule Precedence & Fail-Closed `ConflictWitness` | 5 | 4 | 1 | `100.0%` |
| `INV-08` | Timelock Non-Bypassability (incl. Emergency Claims) | 3 | 3 | 0 | `100.0%` |
| `INV-09` | RFC 8032 Ed25519 Provenance, Nonce Replay & Epoch Guard | 3 | 3 | 0 | `100.0%` |
| `INV-10` | Concurrent Interleaving Non-Escalation (incl. Fuzzer Regression `adv_47`) | 3 | 3 | 0 | `100.0%` |
| **Total** | **All 10 Constitutional Invariants** | **47** | **41** | **6** | **`47 / 47` (`100.0%`)** |

---

## 3. Bounded State-Space Model Checker & Mutation Self-Audit

### Reachable-State Exploration (`seed=1352`)

| Phase | Metric | Observed Value |
| --- | --- | ---: |
| Bounded BFS Explorer (`max_depth = 6`) | Distinct reachable states explored | `2,500` |
| Bounded BFS Explorer (`max_depth = 6`) | State transitions invariant-checked | `10,130` |
| Seeded Property-Based Fuzzer (`1,600` traces × `32` steps) | Interleaved transitions checked | `51,200` |
| **Combined Total** | **States + Transitions Checked (`INV-01..INV-10`)** | **`63,830`** |
| **Sound Engine Verification** | **Invariant Violations Detected** | **`0`** |

> **Real Bug Discovered During Development**: Before the final specification fix, the fuzzer discovered `trace=1095` (a 15-step interleaving where suspending an intermediate actor hid dormant delegation edges, allowing a new delegation whose subsequent appeal overturn resurrected a 3-hop cycle). Fixing cycle/depth checking over non-revoked dormant edges eliminated all violations (0 / 63,830) and is permanently encoded as `adv_47_dormant_suspension_cycle_resurrection`.

### Mutation Self-Audit (`10 / 10` Mutants Killed — `100.0%` Kill Rate)

To prove the model checker and invariant predicates are non-vacuous, one targeted safety guard is disabled per mutant (`MUT-01`..`MUT-10`):

| Mutant | Target | Fault Injected | Killed | Violated | Counterexample Depth | Minimal Trace |
| --- | --- | --- | :---: | :---: | ---: | --- |
| `MUT-01` | `INV-01` | Disable AI boundary guard | YES | `INV-01` | 1 | `DELEGATE(council_1->ai_agent_1):OK` |
| `MUT-02` | `INV-02` | Disable cycle/depth/scope check | YES | `INV-02` | 1 | `DELEGATE(council_1->council_1):OK` |
| `MUT-03` | `INV-03` | Disable transitive revocation | YES | `INV-03` | 2 | `DELEGATE(council_1->human_1)` → `REVOKE_ACTOR(council_1->human_1):OK` |
| `MUT-04` | `INV-04` | Disable duplicate-signer guard | YES | `INV-04` | 1 | `EMERGENCY_PAUSE(council_1->bridge):OK` |
| `MUT-05` | `INV-05` | Disable DEFCON-1 pause/self-renew guard | YES | `INV-05` | 2 | `EMERGENCY_PAUSE` → `EMERGENCY_PAUSE:OK` |
| `MUT-06` | `INV-06` | Disable zero self-adjudication | YES | `INV-06` | 3 | `SUSPEND_ACTOR` → `APPEAL_FILE` → `APPEAL_RESOLVE:OK` |
| `MUT-07` | `INV-07` | Replace fail-closed with first-match | YES | `INV-07` | 1 | `ADVISORY_RECOMMEND(council_1->conflict_target):OK` |
| `MUT-08` | `INV-08` | Disable timelock enforcement | YES | `INV-08` | 1 | `TREASURY_EXECUTE(council_1->grant_mut):OK` |
| `MUT-09` | `INV-09` | Disable monotonic nonce replay guard | YES | `INV-09` | 1 | `ADVISORY_RECOMMEND(council_1->replay_memo):OK` |
| `MUT-10` | `INV-10` | Allow suspended actor execution during appeal | YES | `INV-10` | 3 | `SUSPEND_ACTOR` → `APPEAL_FILE` → `ADVISORY_RECOMMEND:OK` |

---

## 4. Three Explicit Honest Negative Regimes (`seed=1352`)

### Negative Regime 1: First-Match Precedence Bug vs. Fail-Closed Conflict Detection (`neg_first_match_masks_rule_conflict`)

Across `200` randomized same-tier `CHARTER_STATUTE` conflict configurations (simultaneous `ALLOW` and `DENY` clauses with randomized registration order):

| Evaluator | Trials | Unsafe Allows | Blocked | Conflict Witnesses |
| --- | ---: | ---: | ---: | ---: |
| Naive First-Match Policy List | 200 | **98 (`49.00%` / `4900 bps`)** | 102 (`51.00%`) | 0 |
| Constitutional `INV-07` Fail-Closed Engine | 200 | **0 (`0.00%`)** | **200 (`100.00%` / `10000 bps`)** | **200** |

**Takeaway**: Any sequential first-match rule engine silently authorizes nearly half of ambiguous conflicting treasury spends depending purely on rule registration order. Fail-closed conflict aggregation is mandatory.

### Negative Regime 2: Fail-Closed Liveness Deadlock Under Ambiguous Rules / Emergency Freeze (`neg_fail_closed_liveness_deadlock`)

Evaluating `100` urgent valid conservation-grant executions under (a) an unresolved same-tier charter conflict and (b) an active 72h DEFCON-1 emergency freeze:

| Condition | Urgent Valid Ops | Executed | Execution Liveness | Safety Violations | Recovery Mechanism |
| --- | ---: | ---: | ---: | ---: | --- |
| Unresolved Same-Tier Charter Conflict | 100 | **0** | **`0.00%` (`0 bps`)** | **0** | Requires human meta-governance amendment |
| Active DEFCON-1 Emergency Freeze | 100 | **0** | **`0.00%` (`0 bps`)** | **0** | Mandatory auto-sunset after `259,200s` (72h) |

**Honest Trade-Off**: Constitutional fail-closed governance intentionally trades liveness for safety. Urgent valid disbursements experience complete halt (`0%` liveness) while a charter contradiction remains unresolved or during an active DEFCON-1 pause.

### Negative Regime 3: Bounded Model-Checking State-Space Horizon Limit (`neg_bounded_mc_depth_horizon`)

Probing a planted `depth = 8` multi-step delegation + queue + suspension + appeal-overturn + DEFCON-1 cooldown-reset vulnerability at increasing BFS horizons:

| `max_depth` | States Explored | Bug Detected? | Counterexample Length | Interpretation |
| ---: | ---: | :---: | ---: | --- |
| `2` | 6 | **NO** | `0` | False negative (below horizon) |
| `4` | 12 | **NO** | `0` | False negative (below horizon) |
| `6` | 17 | **NO** | `0` | False negative (below horizon) |
| `8` | 20 | **YES** | `8` | Minimal 8-step counterexample discovered |
| `10` | 20 | **YES** | `8` | Minimal 8-step counterexample discovered |

**Takeaway**: Bounded model checking (`depth <= 6` in our BFS phase) is highly effective for shallow bugs and mutation catching, but **cannot guarantee absence of deeper multi-step exploits**. Unbounded safety requires interactive theorem proving (`Lean 4` / `TLA+` / `Coq`).

---

## 5. What Remains Unproven

1. **Unbounded Inductive Proofs**: Safety beyond bounded BFS depth (`depth = 6`) and finite fuzzer traces (`51,200` steps) is empirically supported, not inductively proven for arbitrary $|A|, |R|, |D|$ or infinite horizons.
2. **Native OPA Runtime Execution**: While the 5-file Rego v1 policy bundle is syntax-checked and SHA-256 pinned, `opa test rego/ -v` was not executed inside this VM because `opa` is not installed (`opa_cli_available: false`).
3. **Human & Cryptographic Assumptions**: Council key security, honest supermajorities, accurate block timestamps, and protection against off-chain bribery remain external trust assumptions outside the verified transition system.

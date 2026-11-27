# Constitutional Governance & Formal Protocol Verification Specification (`constitutional-gov.v1`)

- **Schema Version**: `constitutional-gov.v1`
- **Specification Version**: `1.0.0`
- **License**: Apache-2.0
- **Tracking Issue**: `zoo-apps/papers#16` (`HIP-1352`)
- **Companion Paper**: `zoo-dao-emergency-protocol.tex` (ZIP-0027 Emergency Governance Protocol, ZIP-0017 DAO Governance Framework, ZIP-0026 Ecosystem Reputation System)

---

## 1. Purpose & Scope

This specification formally defines the constitutional governance state machine, ten machine-checked safety and due-process invariants (`INV-01` through `INV-10`), a four-tier deterministic rule-precedence and fail-closed conflict-resolution calculus, an Open Policy Agent (OPA) Rego v1 policy bundle, and canonical RFC 8032 Ed25519 cryptographic provenance rules.

Governance decisions require authorized human decision-makers. Autonomous AI agents (`role = AI_AGENT`) may recommend, flag rule conflicts, estimate value, and prepare plans, but are constitutionally barred from redefining voting rules, authorizing treasury spending, activating or renewing emergency suspensions, adjudicating appeals, or declaring their own experimental claims valid.

---

## 2. Formal State Machine

A governance state $S$ at monotonic integer epoch $t \in \mathbb{Z}_{\ge 0}$ (seconds) is a tuple:

$$S = \langle t,\; T,\; W_0,\; A,\; D,\; R,\; Q,\; C,\; E,\; N \rangle$$

where:
- $t \in \mathbb{Z}_{\ge 0}$: monotonic protocol clock (seconds).
- $T \in \mathbb{Z}_{\ge 0}$: treasury balance (integer units; all ratios use integer basis points $\text{bps} \in [0, 10000]$ to guarantee cross-language determinism without floating-point drift).
- $W_0 \in \mathbb{Z}_{\ge 0}$: genesis active human voting weight, anchoring the constitutional quorum floor ($5000\text{ bps} = 50\%$).
- $A$: finite set of actors $a = \langle \text{id}, \text{role}, \text{pk}, w, \text{status}, t_{\text{rev}}, \text{last\_nonce}, \Sigma_{\text{base}} \rangle$, with $\text{role} \in \{\text{HUMAN\_MEMBER}, \text{COUNCIL\_MEMBER}, \text{APPEAL\_JUDGE}, \text{AI\_AGENT}\}$ and $\text{status} \in \{\text{ACTIVE}, \text{SUSPENDED}, \text{REVOKED}\}$.
- $D$: finite set of directed delegation edges $d = \langle \text{id}, u, v, \Sigma_d, t_{\text{create}}, t_{\text{exp}}, \text{revoked}, t_{\text{rev}} \rangle$.
- $R$: finite list of policy rules $r = \langle \text{id}, \tau, \text{action\_type}, \text{target}, e, \text{cond}, \text{rationale} \rangle$ with tier $\tau \in \{\text{CONSTITUTIONAL}(4), \text{EMERGENCY\_SAFETY}(3), \text{CHARTER\_STATUTE}(2), \text{ADVISORY\_POLICY}(1)\}$ and effect $e \in \{\text{ALLOW}, \text{DENY}\}$.
- $Q$: timelocked queued actions (treasury disbursements and rule amendments).
- $C$: contested disciplinary actions (suspensions, vetoes, slashes) with appeal windows and adjudication records.
- $E$: ZIP-0027 DEFCON-1 emergency suspension state $\langle \text{paused}, t_{\text{start}}, t_{\text{exp}}, \text{last\_triggerers}, \text{renewals}, \text{unreviewed} \rangle$.
- $N$: set of consumed $(\text{actor\_id}, \text{nonce})$ replay-defense records.

Every state transition $\delta(S, \alpha) \to (S', \text{verdict}, \text{code}, \omega)$ is **atomic**: when $\text{verdict} = \text{DENY}$, $S' = S$ with zero partial mutation.

### Constitutional Constants

| Constant | Value | Meaning |
| --- | ---: | --- |
| `max_delegation_depth` | `3` | Maximum directed delegation chain length (`INV-02`) |
| `max_emergency_duration_sec` | `259200` (72h) | Maximum DEFCON-1 pause duration before auto-sunset (`INV-05`, ZIP-0027) |
| `renewal_cooldown_sec` | `86400` (24h) | Mandatory post-sunset cooldown prior to renewal (`INV-05`) |
| `appeal_window_sec` | `172800` (48h) | Deterministic appeal filing window for contested actions (`INV-06`) |
| `min_timelock_treasury_sec` | `86400` (24h) | Non-bypassable treasury execution timelock (`INV-08`) |
| `min_timelock_rule_amend_sec` | `172800` (48h) | Non-bypassable rule-amendment timelock (`INV-08`) |
| `quorum_standard_bps` | `1500` (15%) | Standard treasury-queue quorum threshold (`INV-04`) |
| `quorum_meta_gov_bps` | `2500` (25%) | Meta-governance quorum threshold (`INV-04`) |
| `quorum_floor_bps` | `5000` (50%) | Constitutional denominator floor blocking mass self-suspension (`INV-04`) |
| `supermajority_emergency_bps` | `6700` (67%) | DEFCON-1 council supermajority (`INV-04`, `INV-05`) |
| `supermajority_meta_gov_bps` | `7500` (75%) | Meta-governance & independent human pause-renewal supermajority (`INV-04`, `INV-05`) |
| `treasury_emergency_cap_bps` | `500` (5%) | ZIP-0027 emergency treasury cap (`AMOUNT_GT_CAP` predicate) |

---

## 3. Ten Machine-Checked Invariants (`INV-01`..`INV-10`)

Let $\Sigma_{\text{sov}} = \{\text{TREASURY\_SPEND}, \text{RULE\_AMEND}, \text{EMERGENCY\_PAUSE}, \text{EMERGENCY\_SPEND}, \text{EXPERIMENT\_VALIDATE}, \text{APPEAL\_ADJUDICATE}, \text{REVOKE\_MEMBER}\}$.

1. **`INV-01` (AI Constitutional Boundary)**:
   For all reachable states $S$ and all $a \in A$ with $a.\text{role} = \text{AI\_AGENT}$:
   - $\Sigma_{\text{base}}(a) \cap \Sigma_{\text{sov}} = \emptyset$ and no active delegation edge $d \in D$ with $d.\text{to} = a.\text{id}$ grants any $s \in \Sigma_{\text{sov}}$.
   - No transition $\alpha$ with $\alpha.\text{actor\_id} = a.\text{id}$ or $a.\text{id} \in \text{signers}(\alpha)$ may succeed for sovereign actions (`TREASURY_*`, `RULE_AMEND_*`, `EMERGENCY_*`, `EXPERIMENT_VALIDATE`, `APPEAL_RESOLVE`, `REVOKE_ACTOR`, `SUSPEND_ACTOR`, `FINALIZE_CONTESTED`). Violations reject with `ERR_AI_CONSTITUTIONAL_VIOLATION`.

2. **`INV-02` (Acyclic Bounded Delegation & Scope Attenuation)**:
   Let $D_{\text{nr}}(S, t)$ denote all non-revoked, non-expired delegation edges whose endpoints are not `REVOKED` (specifically **including dormant edges touching `SUSPENDED` actors**, refined after our state-space fuzzer discovered a suspension+appeal cycle-resurrection trace; see Section 5).
   - $G = (A, D_{\text{nr}}(S, t))$ is a strict DAG (no self-loops, no cycles: `ERR_DELEGATION_CYCLE`).
   - Longest directed path in $G$ has length $\le 3$ (`ERR_DELEGATION_DEPTH_EXCEEDED`).
   - Every edge $(u \to v)$ grants $\Sigma_d \subseteq \text{EffectiveScopes}(u, t)$ (`ERR_DELEGATION_SCOPE_ESCALATION`) and, for any non-base scope $s \notin \Sigma_{\text{base}}(u)$, satisfies $t_{\text{exp}} \le \max \{ p.t_{\text{exp}} \mid p \text{ authorizes } u \text{ for } s \}$ (`ERR_DELEGATION_EXPIRY_ESCALATION`).

3. **`INV-03` (Immediate Transitive Revocation)**:
   Revoking actor $x$ (or edge $d$) at epoch $t_{\text{rev}}$ immediately marks all transitively reachable downstream delegation edges revoked at $t_{\text{rev}}$ and invalidates every unexecuted queued action $q \in Q$ whose proposer, delegation edge, or root delegation origin depends on $x$ or $d$. Any subsequent execution attempt at $t \ge t_{\text{rev}}$ rejects with `ERR_ACTOR_REVOKED`, `ERR_DELEGATION_REVOKED`, or `ERR_PROPOSER_AUTHORITY_REVOKED`.

4. **`INV-04` (Quorum & Supermajority Monotonicity)**:
   - Active voting weight $W_{\text{active}} = \sum \{ a.w \mid a.\text{status} = \text{ACTIVE} \land a.\text{role} \neq \text{AI\_AGENT} \}$ strictly excludes `REVOKED`, `SUSPENDED`, and `AI_AGENT` actors.
   - Anti-quorum-shrinking floor: proposals fail with `ERR_QUORUM_FLOOR_BREACHED` whenever $W_{\text{active}} < \lfloor 0.50 \cdot W_0 \rfloor$.
   - Duplicate signers reject with `ERR_DUPLICATE_SIGNER`; simultaneous signing by both endpoints of an active delegation rejects with `ERR_DOUBLE_VOTE_DELEGATION`.
   - Emergency pause requires $\ge 67\%$ active council weight ($\ge 2$ distinct council signers); meta-governance amendments require $\ge 75\%$ of $\max(W_{\text{active}}, \text{floor})$ ($\ge 2$ distinct human signers).

5. **`INV-05` (Bounded Emergency Suspension & Mandatory Auto-Sunset, ZIP-0027)**:
   - Active DEFCON-1 pause satisfies $0 < t_{\text{exp}} - t_{\text{start}} \le 259200\text{s}$ (`ERR_EMERGENCY_DURATION_EXCEEDED`).
   - Effective pause predicate is $\text{IsPaused}(S, t) \iff E.\text{paused} \land t < E.t_{\text{exp}}$; expiration is automatic at $t \ge E.t_{\text{exp}}$.
   - While $\text{IsPaused}(S, t)$ holds, all treasury queues/executions and rule amendments fail (`ERR_PAUSED_ACTION_FORBIDDEN` or `ERR_POLICY_DENY`), and self-renewal fails (`ERR_EMERGENCY_SELF_RENEWAL`).
   - Post-sunset renewal requires $t \ge E.t_{\text{exp}} + 86400\text{s}$ (`ERR_EMERGENCY_COOLDOWN_ACTIVE`), $\ge 75\%$ independent human supermajority ($\ge 3$ distinct human signers), and at least one active human signer not in `last_triggerers`.

6. **`INV-06` (Appeal & Due-Process Determinism)**:
   - Every contested suspension/slash creates $c \in C$ with $c.\text{appeal\_deadline} = t_{\text{create}} + 172800\text{s}$.
   - Finalization before $c.\text{appeal\_deadline}$ (`ERR_APPEAL_WINDOW_OPEN`) or while $c.\text{appeal\_status} = \text{PENDING}$ (`ERR_APPEAL_FREEZE_ACTIVE`) is forbidden.
   - Appeal adjudication requires $\ge 2$ independent active `APPEAL_JUDGE` (or `APPEAL_ADJUDICATE`) human signers and strictly forbids $c.\text{initiator\_id}$ and $c.\text{target\_actor\_id}$ from adjudicating (`ERR_SELF_ADJUDICATION`).

7. **`INV-07` (Deterministic Rule-Precedence Hierarchy & Fail-Closed Conflict Resolution)**:
   Let $M(S, \alpha) \subseteq R$ be all rules matching $\alpha$'s action type, target (exact or `*`), and state predicate (`ALWAYS`, `WHEN_PAUSED`, `ACTOR_IS_AI`, `AMOUNT_GT_CAP`, `NO_TIMELOCK`, `UNREVIEWED_EMERGENCY`). Let $\tau^* = \max \{ \text{rank}(r.\tau) \mid r \in M \}$ and $M^* = \{ r \in M \mid \text{rank}(r.\tau) = \tau^* \}$.
   - If $\exists r_1, r_2 \in M^*$ with $r_1.\text{effect} = \text{ALLOW}$ and $r_2.\text{effect} = \text{DENY}$, evaluation **MUST fail closed** with `ERR_DENY_RULE_CONFLICT` and emit a canonical `ConflictWitness` containing sorted `allow_rule_ids`, sorted `deny_rule_ids`, `tier`, `action_id`, `action_type`, `target`, `epoch`, and `resolution: "DENY_RULE_CONFLICT"`.
   - If all rules in $M^*$ are `DENY`, evaluation rejects (`ERR_CONSTITUTIONAL_OVERRIDE_BLOCKED` when $\tau^* = \text{CONSTITUTIONAL}$ overrides a lower-tier `ALLOW`; otherwise `ERR_POLICY_DENY`).
   - First-match sequential short-circuiting is explicitly forbidden.

8. **`INV-08` (Timelock Non-Bypassability)**:
   Executing any queued treasury transfer or rule amendment requires $t \ge q.\text{queued\_at} + q.\text{min\_timelock\_sec}$ (`ERR_TIMELOCK_NOT_ELAPSED`), ignoring any `emergency_bypass` flag.

9. **`INV-09` (Cryptographic Provenance & Replay Defense)**:
   - Every transition requires $\ge 1$ valid RFC 8032 Ed25519 signature over `"constitutional-gov.v1:sign:" || \text{CanonicalJSON}(\text{signable}(\alpha, \text{signer\_id}, \text{nonce}))$ (`ERR_INVALID_SIGNATURE`).
   - Each signer's nonce must satisfy $\text{nonce} > a.\text{last\_nonce}$ and $(\text{signer\_id}, \text{nonce}) \notin N$ (`ERR_REPLAY_NONCE`).
   - Action epoch must satisfy $\alpha.\text{epoch} \ge S.t$ (`ERR_EPOCH_REGRESSION`).

10. **`INV-10` (Non-Escalation Under Concurrent Appeals & Suspensions)**:
    No interleaving of delegation, suspension, appeal filing/overturn, revocation, timelock queuing, and DEFCON-1 pause transitions may violate `INV-01`..`INV-09` or allow a `SUSPENDED` actor to execute sovereign/advisory actions during a pending appeal window (`ERR_ACTOR_SUSPENDED`).

---

## 4. Canonical Encoding, Merkle Audit Root & OPA Rego v1 Mapping

- **Canonical JSON**: Compact UTF-8 JSON with lexicographically sorted keys, no whitespace, and no HTML escaping.
- **Case Digest**: $\text{SHA-256}(\texttt{"constitutional-gov.v1:case:"} \parallel \text{CanonicalJSON}(\text{verdict\_projection}))$.
- **Audit Merkle Root**: Binary SHA-256 Merkle tree over case digests ordered by `case_id`, with leaf domain prefix `0x00` and internal node prefix `0x01` (odd nodes duplicated).
- **OPA Rego v1 Bundle (`rego/`)**:
  - `rego/constitution.rego` (`INV-01, INV-04, INV-06, INV-08, INV-09, INV-10`)
  - `rego/delegation.rego` (`INV-02, INV-03`)
  - `rego/emergency.rego` (`INV-05`)
  - `rego/conflict.rego` (`INV-07`)
  - `rego/constitution_test.rego` (OPA Rego v1 unit tests runnable via `opa test rego/ -v`)

---

## 5. Fuzzer-Discovered Interleaving Refinement (`INV-02` + `INV-10`)

During bounded state-space fuzzing (`seed=1352`), the randomized trace explorer discovered a genuine multi-step interleaving bug (`trace=1095`, 15 steps) in an earlier draft where cycle detection only inspected edges between `ACTIVE` actors:
1. `human_1 -> human_2 -> council_1` existed.
2. `council_1` suspended `human_2` (making `human_2`'s edges dormant).
3. `council_1` delegated `council_1 -> human_1` (passing the naive active-only cycle check).
4. Independent judges overturned `human_2`'s suspension, resurrecting `human_1 -> human_2 -> council_1` and instantaneously forming a 3-hop cycle!

This specification permanently fixes that class of attack by defining `INV-02` acyclicity and depth bounds over **all non-revoked, non-expired edges** ($D_{\text{nr}}(S, t)$), including dormant edges of `SUSPENDED` actors, across Go, Python, and `rego/delegation.rego`, and captures it as regression case `adv_47_dormant_suspension_cycle_resurrection`.

---

## 6. What Remains Unproven

In accordance with the Zoo x Hanzo open research standard, we state clearly what this artifact **does** and **does not** prove:

1. **Bounded vs. Unbounded State Spaces**: Our bounded BFS explorer and trace fuzzer verify 63,830 concrete states/transitions with 0 violations and kill 10/10 single-invariant mutants, **but** bounded exploration cannot prove unbounded inductive safety for arbitrary actor counts $|A| \to \infty$, arbitrary rule set sizes $|R| \to \infty$, or arbitrary trace depths (demonstrated directly in Negative Regime 3, where a depth-8 bug escapes depth $\le 6$ search). Full unbounded inductive verification requires encoding this state machine in a theorem prover (`Lean 4`, `Coq`, or `TLA+/TLAPS`).
2. **OPA Binary Execution vs. Structural Validation**: The build environment does not include the `opa` CLI binary (`opa_cli_available: false`); therefore, the Rego v1 bundle is validated via our deterministic structural/syntax checker and SHA-256 pinning while semantic parity is cross-verified between independent Go and Python engines. Direct execution of `opa test rego/ -v` on a host with OPA installed remains an external verification step.
3. **Off-Protocol & Economic Adversaries**: Formal invariants guarantee protocol-level safety assuming cryptographic hardness of Ed25519, accurate monotonic block timestamps, and honest supermajorities ($\ge 67\%$ council / $\ge 75\%$ human pool). Bribery, out-of-band collusion of $> 67\%$ council members, key compromise of hardware wallets, or L1/L2 consensus censorship are outside the formal state-machine boundary.
4. **Liveness Under Persistent Deadlock**: As demonstrated in Negative Regime 2, fail-closed safety intentionally sacrifices liveness (`0%` throughput) during unresolved same-tier charter conflicts or active DEFCON-1 pauses; social/human governance recovery is required to resolve conflicting charter statutes.

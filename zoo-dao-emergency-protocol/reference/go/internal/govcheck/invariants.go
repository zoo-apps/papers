// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package govcheck

import "fmt"

// InvariantViolation describes a concrete violation of one of INV-01..INV-10.
type InvariantViolation struct {
	InvariantID string
	Reason      string
}

var AllInvariantIDs = []string{
	"INV-01", "INV-02", "INV-03", "INV-04", "INV-05",
	"INV-06", "INV-07", "INV-08", "INV-09", "INV-10",
}

// CheckAllInvariants independently inspects a governance transition (pre -> post)
// and verifies all 10 constitutional safety/liveness invariants (INV-01..INV-10).
func CheckAllInvariants(pre *GovernanceState, act GovernanceAction, res TransitionResult, post *GovernanceState) *InvariantViolation {
	// INV-01: AI Constitutional Boundary.
	for _, a := range post.Actors {
		if a.Role == RoleAIAgent {
			for _, sc := range a.BaseScopes {
				if IsSovereignScope(sc) {
					return &InvariantViolation{"INV-01", fmt.Sprintf("AI actor %s holds sovereign base scope %s", a.ID, sc)}
				}
			}
			for _, d := range post.ActiveDelegationsAt(post.Epoch) {
				if d.To == a.ID {
					for _, sc := range d.Scopes {
						if IsSovereignScope(sc) {
							return &InvariantViolation{"INV-01", fmt.Sprintf("AI actor %s received sovereign delegated scope %s", a.ID, sc)}
						}
					}
				}
			}
		}
	}
	if res.Verdict == VerdictAllow {
		if actor, ok := pre.FindActor(act.ActorID); ok && actor.Role == RoleAIAgent && IsAIForbiddenAction(act.Type) {
			return &InvariantViolation{"INV-01", fmt.Sprintf("AI actor %s executed forbidden action %s", actor.ID, act.Type)}
		}
		for _, sig := range act.Signers {
			if sa, ok := pre.FindActor(sig.ActorID); ok && sa.Role == RoleAIAgent && IsAIForbiddenAction(act.Type) {
				return &InvariantViolation{"INV-01", fmt.Sprintf("AI signer %s authorized forbidden action %s", sa.ID, act.Type)}
			}
		}
	}

	// INV-02: Acyclic Bounded Delegation & Scope Attenuation.
	activeDels := post.ActiveDelegationsAt(post.Epoch)
	adj := make(map[string][]string)
	for _, d := range activeDels {
		if d.From == d.To {
			return &InvariantViolation{"INV-02", fmt.Sprintf("self-delegation edge on %s", d.From)}
		}
		adj[d.From] = append(adj[d.From], d.To)
	}
	// Cycle detection via 3-color DFS.
	color := make(map[string]int) // 0=unvisited, 1=visiting, 2=done
	var hasCycle func(u string) bool
	hasCycle = func(u string) bool {
		color[u] = 1
		for _, v := range adj[u] {
			if color[v] == 1 {
				return true
			}
			if color[v] == 0 && hasCycle(v) {
				return true
			}
		}
		color[u] = 2
		return false
	}
	for _, a := range post.Actors {
		if color[a.ID] == 0 && hasCycle(a.ID) {
			return &InvariantViolation{"INV-02", fmt.Sprintf("cycle detected in active delegation graph from %s", a.ID)}
		}
		if post.MaxIncomingDepth(a.ID, post.Epoch) > MaxDelegationDepth {
			return &InvariantViolation{"INV-02", fmt.Sprintf("delegation depth exceeded %d at actor %s", MaxDelegationDepth, a.ID)}
		}
	}
	// Scope attenuation check for every active delegation.
	for _, d := range activeDels {
		held := post.EffectiveScopes(d.From, post.Epoch)
		for _, sc := range d.Scopes {
			if !held[sc] {
				return &InvariantViolation{"INV-02", fmt.Sprintf("delegation %s escalated scope %s beyond delegator %s", d.ID, sc, d.From)}
			}
		}
	}

	// INV-03: Immediate Transitive Revocation.
	for _, d := range post.Delegations {
		if d.Revoked {
			continue
		}
		if from, ok := post.FindActor(d.From); ok && from.Status == StatusRevoked {
			return &InvariantViolation{"INV-03", fmt.Sprintf("delegation %s still active after delegator %s revoked", d.ID, d.From)}
		}
		if to, ok := post.FindActor(d.To); ok && to.Status == StatusRevoked {
			return &InvariantViolation{"INV-03", fmt.Sprintf("delegation %s still active after delegatee %s revoked", d.ID, d.To)}
		}
	}
	for _, q := range post.QueuedActions {
		if q.Executed || q.Invalidated {
			continue
		}
		if prop, ok := post.FindActor(q.ProposerID); ok && prop.Status == StatusRevoked {
			return &InvariantViolation{"INV-03", fmt.Sprintf("queued action %s not invalidated after proposer %s revoked", q.ID, q.ProposerID)}
		}
		if q.DelegationID != "" {
			if d, ok := post.FindDelegation(q.DelegationID); ok && d.Revoked {
				return &InvariantViolation{"INV-03", fmt.Sprintf("queued action %s not invalidated after delegation %s revoked", q.ID, q.DelegationID)}
			}
		}
	}

	// INV-04: Quorum & Supermajority Monotonicity (no duplicate signers or double-counted delegations).
	if res.Verdict == VerdictAllow {
		seen := make(map[string]bool, len(act.Signers))
		for _, sig := range act.Signers {
			if seen[sig.ActorID] {
				return &InvariantViolation{"INV-04", fmt.Sprintf("duplicate signer %s accepted in %s", sig.ActorID, act.ID)}
			}
			seen[sig.ActorID] = true
		}
		if act.Type == ActionTreasuryQueue || act.Type == ActionRuleAmendQueue {
			if pre.hasDelegationOverlap(seen, act.Epoch) {
				return &InvariantViolation{"INV-04", fmt.Sprintf("double vote via delegator+delegatee overlap in %s", act.ID)}
			}
		}
	}

	// INV-05: Bounded Emergency Suspension & Mandatory Auto-Sunset.
	if post.Emergency.Paused {
		if post.Emergency.PauseExpiresAt-post.Emergency.PauseStartedAt > MaxEmergencyDurationSec {
			return &InvariantViolation{"INV-05", fmt.Sprintf("emergency pause duration %ds exceeds 72h cap", post.Emergency.PauseExpiresAt-post.Emergency.PauseStartedAt)}
		}
	}
	if res.Verdict == VerdictAllow && pre.IsPausedAt(act.Epoch) {
		switch act.Type {
		case ActionTreasuryQueue, ActionTreasuryExecute, ActionRuleAmendQueue, ActionRuleAmendExecute:
			return &InvariantViolation{"INV-05", fmt.Sprintf("action %s allowed while DEFCON-1 pause active", act.Type)}
		case ActionEmergencyPause, ActionEmergencyRenew:
			return &InvariantViolation{"INV-05", fmt.Sprintf("self-renewal %s allowed while pause still active", act.Type)}
		}
	}

	// INV-06: Appeal & Due-Process Determinism (zero self-adjudication, appeal freeze).
	for _, c := range post.ContestedActions {
		for _, j := range c.Judges {
			if j == c.InitiatorID || j == c.TargetActorID {
				return &InvariantViolation{"INV-06", fmt.Sprintf("self-adjudication by %s on contested action %s", j, c.ID)}
			}
		}
		if c.Finalized && c.AppealStatus == "PENDING" {
			return &InvariantViolation{"INV-06", fmt.Sprintf("contested action %s finalized while appeal PENDING", c.ID)}
		}
	}

	// INV-07: Deterministic Rule-Precedence & Fail-Closed Conflict Resolution.
	if res.Verdict == VerdictAllow {
		eval := EvaluatePolicyHierarchy(pre, act)
		if !eval.Allowed {
			return &InvariantViolation{"INV-07", fmt.Sprintf("action %s allowed despite policy violation %s", act.ID, eval.ErrorCode)}
		}
	}

	// INV-08: Timelock Non-Bypassability.
	if res.Verdict == VerdictAllow && (act.Type == ActionTreasuryExecute || act.Type == ActionRuleAmendExecute) {
		for _, q := range pre.QueuedActions {
			if q.ID == act.ProposalID {
				if act.Epoch < q.QueuedAt+q.MinTimelockSec {
					return &InvariantViolation{"INV-08", fmt.Sprintf("timelock bypassed on %s: elapsed %ds < %ds", q.ID, act.Epoch-q.QueuedAt, q.MinTimelockSec)}
				}
			}
		}
	}

	// INV-09: Cryptographic Provenance & Replay Defense.
	if res.Verdict == VerdictAllow {
		if act.Epoch < pre.Epoch {
			return &InvariantViolation{"INV-09", fmt.Sprintf("epoch regression accepted: %d < %d", act.Epoch, pre.Epoch)}
		}
		for _, sig := range act.Signers {
			if preActor, ok := pre.FindActor(sig.ActorID); ok {
				if sig.Nonce <= preActor.LastNonce || pre.hasUsedNonce(sig.ActorID, sig.Nonce) {
					return &InvariantViolation{"INV-09", fmt.Sprintf("replayed/non-monotonic nonce %d for %s accepted", sig.Nonce, sig.ActorID)}
				}
			}
		}
	}

	// INV-10: Non-Escalation Under Concurrent Appeals & Suspensions.
	if res.Verdict == VerdictAllow {
		if preActor, ok := pre.FindActor(act.ActorID); ok {
			if preActor.Status == StatusSuspended && act.Type != ActionAppealFile && act.Type != ActionAdvanceClock {
				return &InvariantViolation{"INV-10", fmt.Sprintf("suspended actor %s escalated authority via %s during appeal/suspension window", preActor.ID, act.Type)}
			}
		}
	}

	return nil
}

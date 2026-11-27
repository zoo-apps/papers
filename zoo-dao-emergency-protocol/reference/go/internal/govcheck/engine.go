// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package govcheck

import (
	"fmt"
	"sort"
)

// EngineConfig configures verification strictness and optional fault injection
// (used strictly for mutation self-testing of the bounded model checker).
type EngineConfig struct {
	SkipSigVerify bool
	Mutant        string
}

// Clone deep-copies GovernanceState for atomic rollback and BFS state branching.
func (s *GovernanceState) Clone() *GovernanceState {
	cp := *s
	cp.Actors = make([]Actor, len(s.Actors))
	for i, a := range s.Actors {
		a.BaseScopes = append([]string(nil), a.BaseScopes...)
		cp.Actors[i] = a
	}
	cp.Delegations = make([]Delegation, len(s.Delegations))
	for i, d := range s.Delegations {
		d.Scopes = append([]string(nil), d.Scopes...)
		cp.Delegations[i] = d
	}
	cp.Rules = append([]PolicyRule(nil), s.Rules...)
	cp.QueuedActions = make([]QueuedAction, len(s.QueuedActions))
	for i, q := range s.QueuedActions {
		if q.NewRule != nil {
			r := *q.NewRule
			q.NewRule = &r
		}
		cp.QueuedActions[i] = q
	}
	cp.ContestedActions = make([]ContestedAction, len(s.ContestedActions))
	for i, c := range s.ContestedActions {
		c.Judges = append([]string(nil), c.Judges...)
		cp.ContestedActions[i] = c
	}
	cp.Emergency = s.Emergency
	cp.Emergency.LastTriggerers = append([]string(nil), s.Emergency.LastTriggerers...)
	cp.UsedNonces = append([]string(nil), s.UsedNonces...)
	cp.ExecutedLog = make([]ExecutionRecord, len(s.ExecutedLog))
	for i, rec := range s.ExecutedLog {
		rec.Signers = append([]string(nil), rec.Signers...)
		cp.ExecutedLog[i] = rec
	}
	return &cp
}

func (s *GovernanceState) FindActor(id string) (*Actor, bool) {
	for i := range s.Actors {
		if s.Actors[i].ID == id {
			return &s.Actors[i], true
		}
	}
	return nil, false
}

func (s *GovernanceState) IsPausedAt(epoch int64) bool {
	return s.Emergency.Paused && epoch < s.Emergency.PauseExpiresAt
}

func (s *GovernanceState) ActiveDelegationsAt(epoch int64) []Delegation {
	out := make([]Delegation, 0, len(s.Delegations))
	for _, d := range s.Delegations {
		if d.Revoked || d.ExpiresAt <= epoch {
			continue
		}
		from, ok1 := s.FindActor(d.From)
		to, ok2 := s.FindActor(d.To)
		if !ok1 || !ok2 || from.Status != StatusActive || to.Status != StatusActive {
			continue
		}
		out = append(out, d)
	}
	return out
}

// EffectiveScopes returns the union of an active actor's base scopes and scopes
// inherited via active, non-revoked, non-expired delegations.
func (s *GovernanceState) EffectiveScopes(actorID string, epoch int64) map[string]bool {
	res := make(map[string]bool)
	actor, ok := s.FindActor(actorID)
	if !ok || actor.Status != StatusActive {
		return res
	}
	for _, sc := range actor.BaseScopes {
		res[sc] = true
	}
	for _, d := range s.ActiveDelegationsAt(epoch) {
		if d.To == actorID {
			for _, sc := range d.Scopes {
				res[sc] = true
			}
		}
	}
	return res
}

// NonRevokedDelegationsAt returns all non-revoked, non-expired delegations whose
// endpoints are ACTIVE or SUSPENDED (excluding only permanently REVOKED actors).
// Cycle and depth invariants MUST hold over this superset so that overturning a
// temporary suspension via INV-06 appeal can never resurrect a cycle or exceed max_depth=3.
func (s *GovernanceState) NonRevokedDelegationsAt(epoch int64) []Delegation {
	out := make([]Delegation, 0, len(s.Delegations))
	for _, d := range s.Delegations {
		if d.Revoked || d.ExpiresAt <= epoch {
			continue
		}
		from, ok1 := s.FindActor(d.From)
		to, ok2 := s.FindActor(d.To)
		if !ok1 || !ok2 || from.Status == StatusRevoked || to.Status == StatusRevoked {
			continue
		}
		out = append(out, d)
	}
	return out
}

// DelegationCreatesCycle returns true if adding from -> to introduces a cycle
// in the non-revoked delegation graph (including dormant edges of suspended actors).
func (s *GovernanceState) DelegationCreatesCycle(from, to string, epoch int64) bool {
	if from == to {
		return true
	}
	adj := make(map[string][]string)
	for _, d := range s.NonRevokedDelegationsAt(epoch) {
		adj[d.From] = append(adj[d.From], d.To)
	}
	visited := map[string]bool{to: true}
	queue := []string{to}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, nxt := range adj[cur] {
			if nxt == from {
				return true
			}
			if !visited[nxt] {
				visited[nxt] = true
				queue = append(queue, nxt)
			}
		}
	}
	return false
}

// MaxIncomingDepth returns the longest non-revoked delegation path length ending at node.
func (s *GovernanceState) MaxIncomingDepth(node string, epoch int64) int {
	rev := make(map[string][]string)
	for _, d := range s.NonRevokedDelegationsAt(epoch) {
		rev[d.To] = append(rev[d.To], d.From)
	}
	var dfs func(cur string, seen map[string]bool) int
	dfs = func(cur string, seen map[string]bool) int {
		best := 0
		for _, parent := range rev[cur] {
			if seen[parent] {
				continue
			}
			seen[parent] = true
			d := 1 + dfs(parent, seen)
			delete(seen, parent)
			if d > best {
				best = d
			}
		}
		return best
	}
	return dfs(node, map[string]bool{node: true})
}

func (s *GovernanceState) FindDelegation(id string) (*Delegation, bool) {
	for i := range s.Delegations {
		if s.Delegations[i].ID == id {
			return &s.Delegations[i], true
		}
	}
	return nil, false
}

func (s *GovernanceState) DelegationRootOrigin(delID string) string {
	visited := make(map[string]bool)
	curID := delID
	origin := ""
	for curID != "" && !visited[curID] {
		visited[curID] = true
		d, ok := s.FindDelegation(curID)
		if !ok {
			break
		}
		origin = d.From
		// Walk upstream if delegator received scope from another delegation.
		nextID := ""
		for _, up := range s.Delegations {
			if up.To == d.From && !up.Revoked {
				nextID = up.ID
				break
			}
		}
		curID = nextID
	}
	return origin
}

// TransitiveRevokeActor revokes targetID and transitively invalidates all
// downstream delegations and dependent queued actions at epoch.
func (s *GovernanceState) TransitiveRevokeActor(targetID string, epoch int64) {
	affectedActors := map[string]bool{targetID: true}
	revokedDelIDs := make(map[string]bool)

	changed := true
	for changed {
		changed = false
		for i := range s.Delegations {
			d := &s.Delegations[i]
			if d.Revoked {
				continue
			}
			if affectedActors[d.From] || d.To == targetID {
				d.Revoked = true
				d.RevokedAt = epoch
				revokedDelIDs[d.ID] = true
				if !affectedActors[d.To] {
					affectedActors[d.To] = true
				}
				changed = true
			}
		}
	}

	for i := range s.QueuedActions {
		q := &s.QueuedActions[i]
		if q.Executed || q.Invalidated {
			continue
		}
		if q.ProposerID == targetID || q.DelegationOrigin == targetID || revokedDelIDs[q.DelegationID] {
			q.Invalidated = true
			q.InvalidatedAt = epoch
		}
	}
}

// TransitiveRevokeDelegation revokes delegation delID and all downstream
// sub-delegations and pending queued actions derived from it.
func (s *GovernanceState) TransitiveRevokeDelegation(delID string, epoch int64) {
	d, ok := s.FindDelegation(delID)
	if !ok {
		return
	}
	d.Revoked = true
	d.RevokedAt = epoch
	revokedDelIDs := map[string]bool{delID: true}
	affectedDelegatees := map[string]bool{d.To: true}

	changed := true
	for changed {
		changed = false
		for i := range s.Delegations {
			sub := &s.Delegations[i]
			if sub.Revoked {
				continue
			}
			if affectedDelegatees[sub.From] {
				// Revoke if sub-delegator no longer holds all sub.Scopes from base_scopes or another active delegation.
				held := s.EffectiveScopes(sub.From, epoch)
				missing := false
				for _, sc := range sub.Scopes {
					if !held[sc] {
						missing = true
						break
					}
				}
				if missing {
					sub.Revoked = true
					sub.RevokedAt = epoch
					revokedDelIDs[sub.ID] = true
					affectedDelegatees[sub.To] = true
					changed = true
				}
			}
		}
	}

	for i := range s.QueuedActions {
		q := &s.QueuedActions[i]
		if q.Executed || q.Invalidated {
			continue
		}
		if revokedDelIDs[q.DelegationID] {
			q.Invalidated = true
			q.InvalidatedAt = epoch
		}
	}
}

func hasScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}

func (s *GovernanceState) hasUsedNonce(actorID string, nonce uint64) bool {
	key := fmt.Sprintf("%s:%d", actorID, nonce)
	for _, k := range s.UsedNonces {
		if k == key {
			return true
		}
	}
	return false
}

func (s *GovernanceState) activeHumanWeight() int64 {
	var total int64
	for _, a := range s.Actors {
		if a.Status == StatusActive && a.Role != RoleAIAgent {
			total += a.VotingWeight
		}
	}
	return total
}

func (s *GovernanceState) activeCouncilWeight() int64 {
	var total int64
	for _, a := range s.Actors {
		if a.Status == StatusActive && a.Role == RoleCouncilMember {
			total += a.VotingWeight
		}
	}
	return total
}

func (s *GovernanceState) hasDelegationOverlap(signerSet map[string]bool, epoch int64) bool {
	for _, d := range s.ActiveDelegationsAt(epoch) {
		if signerSet[d.From] && signerSet[d.To] {
			return true
		}
	}
	return false
}

func (s *GovernanceState) signedWeightWithDelegation(signerSet map[string]bool, epoch int64) (int64, int) {
	counted := make(map[string]bool)
	var weight int64
	distinctHumans := 0
	for id := range signerSet {
		a, ok := s.FindActor(id)
		if !ok || a.Status != StatusActive || a.Role == RoleAIAgent {
			continue
		}
		if !counted[id] {
			counted[id] = true
			weight += a.VotingWeight
			distinctHumans++
		}
	}
	// Include active delegators who delegated VOTE_STANDARD to a signer and did not sign themselves.
	for _, d := range s.ActiveDelegationsAt(epoch) {
		if signerSet[d.To] && !counted[d.From] && hasScope(d.Scopes, ScopeVoteStandard) {
			from, ok := s.FindActor(d.From)
			if ok && from.Status == StatusActive && from.Role != RoleAIAgent {
				counted[d.From] = true
				weight += from.VotingWeight
			}
		}
	}
	return weight, distinctHumans
}

// Apply evaluates and atomically applies act onto state. If DENY, state is not mutated.
func Apply(state *GovernanceState, act GovernanceAction, cfg EngineConfig) TransitionResult {
	// Work on a clone so DENY never leaves partial state mutations.
	next := state.Clone()
	res := applyInPlace(next, act, cfg)
	if res.Verdict == VerdictAllow {
		*state = *next
	}
	return res
}

func applyInPlace(s *GovernanceState, act GovernanceAction, cfg EngineConfig) TransitionResult {
	// 1. Monotonic epoch check (INV-09).
	if act.Epoch < s.Epoch {
		return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeEpochRegression}
	}

	// Mandatory auto-sunset if previous DEFCON-1 pause expired before or at act.Epoch (INV-05).
	effectivelyPaused := s.IsPausedAt(act.Epoch)
	if cfg.Mutant == "MUT-05" && s.Emergency.Paused {
		// Fault injection: fails to auto-sunset or fails to enforce pause guard (handled below).
		effectivelyPaused = false
	} else if s.Emergency.Paused && act.Epoch >= s.Emergency.PauseExpiresAt {
		s.Emergency.Paused = false
		effectivelyPaused = false
	}

	// 2. Cryptographic provenance, signature, duplicate signer, and replay nonce defense (INV-09 & INV-04).
	if len(act.Signers) == 0 {
		return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeInvalidSignature}
	}

	signerSet := make(map[string]bool, len(act.Signers))
	signerIDs := make([]string, 0, len(act.Signers))
	for _, sig := range act.Signers {
		if signerSet[sig.ActorID] {
			if cfg.Mutant != "MUT-04" {
				return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeDuplicateSigner}
			}
		}
		signerSet[sig.ActorID] = true
		signerIDs = append(signerIDs, sig.ActorID)

		signerActor, ok := s.FindActor(sig.ActorID)
		if !ok {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeActorNotFound}
		}
		if !cfg.SkipSigVerify {
			if !VerifySignerSig(act, sig, signerActor.PubKeyHex) {
				return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeInvalidSignature}
			}
		}
		if cfg.Mutant != "MUT-09" {
			if sig.Nonce <= signerActor.LastNonce || s.hasUsedNonce(sig.ActorID, sig.Nonce) {
				return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeReplayNonce}
			}
		}
	}

	// 3. Primary actor lookup and INV-01 AI Constitutional Boundary.
	actor, ok := s.FindActor(act.ActorID)
	if !ok {
		return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeActorNotFound}
	}

	if cfg.Mutant != "MUT-01" {
		if actor.Role == RoleAIAgent && IsAIForbiddenAction(act.Type) {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeAIConstitutionalViolation}
		}
		for _, sig := range act.Signers {
			sa, _ := s.FindActor(sig.ActorID)
			if sa.Role == RoleAIAgent && IsAIForbiddenAction(act.Type) {
				return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeAIConstitutionalViolation}
			}
		}
		if act.Type == ActionDelegate {
			if target, tok := s.FindActor(act.Target); tok && target.Role == RoleAIAgent {
				for _, sc := range act.Scopes {
					if IsSovereignScope(sc) {
						return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeAIConstitutionalViolation}
					}
				}
			}
		}
	}

	// 4. Actor status checks (INV-03 & INV-10).
	if actor.Status == StatusRevoked {
		return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeActorRevoked}
	}
	if actor.Status == StatusSuspended && act.Type != ActionAppealFile && act.Type != ActionAdvanceClock {
		if cfg.Mutant != "MUT-10" {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeActorSuspended}
		}
	}

	// Check explicitly referenced delegation edge (INV-03) when consuming an existing delegation.
	if act.DelegationID != "" && act.Type != ActionDelegate && act.Type != ActionRevokeDelegation && cfg.Mutant != "MUT-03" {
		d, dok := s.FindDelegation(act.DelegationID)
		if !dok || d.Revoked || d.ExpiresAt <= act.Epoch {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeDelegationRevoked}
		}
		fromActor, fok := s.FindActor(d.From)
		if !fok || fromActor.Status != StatusActive {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeDelegationRevoked}
		}
	}

	// 5. Rule-Precedence Hierarchy & Fail-Closed Conflict Detection (INV-07).
	var polEval PolicyEvaluation
	if cfg.Mutant == "MUT-07" {
		polEval = EvaluateNaiveFirstMatch(s, act)
	} else {
		polEval = EvaluatePolicyHierarchy(s, act)
	}
	if !polEval.Allowed {
		return TransitionResult{
			Verdict:         VerdictDeny,
			ErrorCode:       polEval.ErrorCode,
			ConflictWitness: polEval.ConflictWitness,
		}
	}

	// 6. Emergency Pause Guard (INV-05, ZIP-0027 spend cap = 0, no rule edits).
	if effectivelyPaused {
		switch act.Type {
		case ActionTreasuryQueue, ActionTreasuryExecute, ActionRuleAmendQueue, ActionRuleAmendExecute:
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodePausedActionForbidden}
		}
	}

	// 7. Action-specific state-machine semantics.
	var execQueuedAt int64
	var execMinTimelock int64

	switch act.Type {
	case ActionAdvanceClock:
		// Pure clock progression; state.Epoch advances below.

	case ActionAdvisoryRecommend, ActionFlagConflict:
		held := s.EffectiveScopes(actor.ID, act.Epoch)
		if !held[ScopeAdvisoryRecommend] && !held[ScopeFlagConflict] && actor.Role != RoleCouncilMember && actor.Role != RoleHumanMember {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeInsufficientScope}
		}

	case ActionDelegate:
		target, tok := s.FindActor(act.Target)
		if !tok {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeActorNotFound}
		}
		if target.Status != StatusActive {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeActorRevoked}
		}
		if len(act.Scopes) == 0 || act.DurationSec <= 0 {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeDelegationScopeEscalation}
		}
		if cfg.Mutant != "MUT-02" {
			if s.DelegationCreatesCycle(act.ActorID, act.Target, act.Epoch) {
				return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeDelegationCycle}
			}
			if s.MaxIncomingDepth(act.ActorID, act.Epoch)+1 > MaxDelegationDepth {
				return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeDelegationDepthExceeded}
			}
			held := s.EffectiveScopes(act.ActorID, act.Epoch)
			reqExpiry := act.Epoch + act.DurationSec
			for _, sc := range act.Scopes {
				if !held[sc] {
					return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeDelegationScopeEscalation}
				}
				if !hasScope(actor.BaseScopes, sc) {
					// Must be backed by an active incoming delegation with ExpiresAt >= reqExpiry.
					var maxParentExpiry int64
					for _, d := range s.ActiveDelegationsAt(act.Epoch) {
						if d.To == act.ActorID && hasScope(d.Scopes, sc) && d.ExpiresAt > maxParentExpiry {
							maxParentExpiry = d.ExpiresAt
						}
					}
					if reqExpiry > maxParentExpiry {
						return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeDelegationExpiryEscalation}
					}
				}
			}
		}
		delID := act.DelegationID
		if delID == "" {
			delID = fmt.Sprintf("del-%s-%s-%d", act.ActorID, act.Target, len(s.Delegations)+1)
		}
		scopesCopy := append([]string(nil), act.Scopes...)
		sort.Strings(scopesCopy)
		s.Delegations = append(s.Delegations, Delegation{
			ID:        delID,
			From:      act.ActorID,
			To:        act.Target,
			Scopes:    scopesCopy,
			CreatedAt: act.Epoch,
			ExpiresAt: act.Epoch + act.DurationSec,
			Revoked:   false,
		})

	case ActionRevokeActor:
		held := s.EffectiveScopes(actor.ID, act.Epoch)
		if !held[ScopeRevokeMember] && actor.Role != RoleCouncilMember {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeInsufficientScope}
		}
		target, tok := s.FindActor(act.Target)
		if !tok {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeActorNotFound}
		}
		target.Status = StatusRevoked
		target.RevokedAt = act.Epoch
		if cfg.Mutant != "MUT-03" {
			s.TransitiveRevokeActor(target.ID, act.Epoch)
		}

	case ActionRevokeDelegation:
		d, dok := s.FindDelegation(act.DelegationID)
		if !dok {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeDelegationRevoked}
		}
		if d.From != actor.ID && !s.EffectiveScopes(actor.ID, act.Epoch)[ScopeRevokeMember] {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeInsufficientScope}
		}
		if cfg.Mutant == "MUT-03" {
			d.Revoked = true
			d.RevokedAt = act.Epoch
		} else {
			s.TransitiveRevokeDelegation(act.DelegationID, act.Epoch)
		}

	case ActionSuspendActor:
		held := s.EffectiveScopes(actor.ID, act.Epoch)
		if !held[ScopeRevokeMember] && actor.Role != RoleCouncilMember {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeInsufficientScope}
		}
		target, tok := s.FindActor(act.Target)
		if !tok {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeActorNotFound}
		}
		target.Status = StatusSuspended
		cid := act.ContestedID
		if cid == "" {
			cid = fmt.Sprintf("cont-%d", len(s.ContestedActions)+1)
		}
		s.ContestedActions = append(s.ContestedActions, ContestedAction{
			ID:             cid,
			Kind:           "SUSPEND",
			InitiatorID:    act.ActorID,
			TargetActorID:  target.ID,
			CreatedAt:      act.Epoch,
			AppealDeadline: act.Epoch + AppealWindowSec,
			AppealFiled:    false,
			AppealStatus:   "NONE",
			Finalized:      false,
		})

	case ActionSelfSuspend:
		actor.Status = StatusSuspended

	case ActionAppealFile:
		var found *ContestedAction
		for i := range s.ContestedActions {
			if s.ContestedActions[i].ID == act.ContestedID {
				found = &s.ContestedActions[i]
				break
			}
		}
		if found == nil || found.Finalized {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeAppealNotFound}
		}
		if act.Epoch > found.AppealDeadline {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeAppealWindowClosed}
		}
		found.AppealFiled = true
		found.AppealStatus = "PENDING"

	case ActionAppealResolve:
		var found *ContestedAction
		for i := range s.ContestedActions {
			if s.ContestedActions[i].ID == act.ContestedID {
				found = &s.ContestedActions[i]
				break
			}
		}
		if found == nil || found.AppealStatus != "PENDING" {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeAppealNotFound}
		}
		validJudges := 0
		judges := make([]string, 0, len(act.Signers))
		for _, sig := range act.Signers {
			if cfg.Mutant != "MUT-06" {
				if sig.ActorID == found.InitiatorID || sig.ActorID == found.TargetActorID {
					return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeSelfAdjudication}
				}
			}
			sa, _ := s.FindActor(sig.ActorID)
			if sa.Status == StatusActive && (sa.Role == RoleAppealJudge || hasScope(sa.BaseScopes, ScopeAppealAdjudicate) || cfg.Mutant == "MUT-06") {
				validJudges++
				judges = append(judges, sig.ActorID)
			}
		}
		if cfg.Mutant != "MUT-06" && validJudges < 2 {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeInsufficientJudges}
		}
		sort.Strings(judges)
		found.Judges = judges
		outcome := act.AppealOutcome
		if outcome != "OVERTURNED" {
			outcome = "UPHELD"
		}
		found.AppealStatus = outcome
		if outcome == "OVERTURNED" {
			if target, tok := s.FindActor(found.TargetActorID); tok && target.Status == StatusSuspended {
				target.Status = StatusActive
			}
			found.Finalized = true
		}

	case ActionFinalizeContested:
		var found *ContestedAction
		for i := range s.ContestedActions {
			if s.ContestedActions[i].ID == act.ContestedID {
				found = &s.ContestedActions[i]
				break
			}
		}
		if found == nil {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeAppealNotFound}
		}
		if found.AppealStatus == "PENDING" {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeAppealFreezeActive}
		}
		if found.AppealStatus == "NONE" && act.Epoch < found.AppealDeadline {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeAppealWindowOpen}
		}
		found.Finalized = true
		if found.AppealStatus != "OVERTURNED" {
			if target, tok := s.FindActor(found.TargetActorID); tok {
				target.Status = StatusRevoked
				target.RevokedAt = act.Epoch
				if cfg.Mutant != "MUT-03" {
					s.TransitiveRevokeActor(target.ID, act.Epoch)
				}
			}
		}

	case ActionTreasuryQueue:
		if cfg.Mutant != "MUT-04" && s.hasDelegationOverlap(signerSet, act.Epoch) {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeDoubleVoteDelegation}
		}
		activeW := s.activeHumanWeight()
		floorW := (s.GenesisActiveWeight * QuorumFloorBps) / 10000
		if activeW < floorW {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeQuorumFloorBreached}
		}
		signedW, _ := s.signedWeightWithDelegation(signerSet, act.Epoch)
		if cfg.Mutant == "MUT-04" {
			// Buggy counting: counts duplicate signer entries directly.
			signedW = 0
			for _, sig := range act.Signers {
				if sa, ok := s.FindActor(sig.ActorID); ok {
					signedW += sa.VotingWeight
				}
			}
		}
		if activeW == 0 || signedW*10000 < activeW*QuorumStandardBps {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeQuorumNotMet}
		}
		if !s.EffectiveScopes(actor.ID, act.Epoch)[ScopeTreasurySpend] {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeInsufficientScope}
		}
		if act.Amount > s.TreasuryBalance {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeTreasuryInsufficient}
		}
		pid := act.ProposalID
		if pid == "" {
			pid = fmt.Sprintf("prop-%d", len(s.QueuedActions)+1)
		}
		origin := ""
		if act.DelegationID != "" {
			origin = s.DelegationRootOrigin(act.DelegationID)
		}
		s.QueuedActions = append(s.QueuedActions, QueuedAction{
			ID:               pid,
			Kind:             "TREASURY",
			ProposerID:       act.ActorID,
			Target:           act.Target,
			Amount:           act.Amount,
			QueuedAt:         act.Epoch,
			MinTimelockSec:   MinTimelockTreasurySec,
			DelegationID:     act.DelegationID,
			DelegationOrigin: origin,
		})

	case ActionTreasuryExecute:
		var q *QueuedAction
		for i := range s.QueuedActions {
			if s.QueuedActions[i].ID == act.ProposalID && s.QueuedActions[i].Kind == "TREASURY" {
				q = &s.QueuedActions[i]
				break
			}
		}
		if q == nil || q.Executed {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeProposalNotFound}
		}
		if cfg.Mutant != "MUT-03" {
			if q.Invalidated {
				return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeProposerAuthorityRevoked}
			}
			if prop, pok := s.FindActor(q.ProposerID); !pok || prop.Status == StatusRevoked {
				return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeProposerAuthorityRevoked}
			}
			if q.DelegationOrigin != "" {
				if orig, ook := s.FindActor(q.DelegationOrigin); !ook || orig.Status == StatusRevoked {
					return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeProposerAuthorityRevoked}
				}
			}
		}
		if cfg.Mutant != "MUT-08" {
			if act.Epoch < q.QueuedAt+q.MinTimelockSec {
				return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeTimelockNotElapsed}
			}
		}
		if q.Amount > s.TreasuryBalance {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeTreasuryInsufficient}
		}
		s.TreasuryBalance -= q.Amount
		q.Executed = true
		execQueuedAt = q.QueuedAt
		execMinTimelock = q.MinTimelockSec

	case ActionRuleAmendQueue:
		if cfg.Mutant != "MUT-04" && s.hasDelegationOverlap(signerSet, act.Epoch) {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeDoubleVoteDelegation}
		}
		activeW := s.activeHumanWeight()
		floorW := (s.GenesisActiveWeight * QuorumFloorBps) / 10000
		if activeW < floorW {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeQuorumFloorBreached}
		}
		signedW, distinctHumans := s.signedWeightWithDelegation(signerSet, act.Epoch)
		if cfg.Mutant == "MUT-04" {
			signedW = 0
			for _, sig := range act.Signers {
				if sa, ok := s.FindActor(sig.ActorID); ok {
					signedW += sa.VotingWeight
				}
			}
			distinctHumans = len(act.Signers)
		}
		denom := activeW
		if floorW > denom {
			denom = floorW
		}
		if denom == 0 || signedW*10000 < denom*SupermajorityMetaGovBps || distinctHumans < 2 {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeSupermajorityNotMet}
		}
		pid := act.ProposalID
		if pid == "" {
			pid = fmt.Sprintf("amend-%d", len(s.QueuedActions)+1)
		}
		var ruleCopy *PolicyRule
		if act.NewRule != nil {
			r := *act.NewRule
			ruleCopy = &r
		}
		s.QueuedActions = append(s.QueuedActions, QueuedAction{
			ID:             pid,
			Kind:           "RULE_AMEND",
			ProposerID:     act.ActorID,
			Target:         act.Target,
			NewRule:        ruleCopy,
			QueuedAt:       act.Epoch,
			MinTimelockSec: MinTimelockRuleAmendSec,
		})

	case ActionRuleAmendExecute:
		var q *QueuedAction
		for i := range s.QueuedActions {
			if s.QueuedActions[i].ID == act.ProposalID && s.QueuedActions[i].Kind == "RULE_AMEND" {
				q = &s.QueuedActions[i]
				break
			}
		}
		if q == nil || q.Executed {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeProposalNotFound}
		}
		if cfg.Mutant != "MUT-03" && q.Invalidated {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeProposerAuthorityRevoked}
		}
		if cfg.Mutant != "MUT-08" && act.Epoch < q.QueuedAt+q.MinTimelockSec {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeTimelockNotElapsed}
		}
		if q.NewRule != nil {
			s.Rules = append(s.Rules, *q.NewRule)
		}
		q.Executed = true
		execQueuedAt = q.QueuedAt
		execMinTimelock = q.MinTimelockSec

	case ActionEmergencyPause:
		if cfg.Mutant != "MUT-05" {
			if act.DurationSec <= 0 || act.DurationSec > MaxEmergencyDurationSec {
				return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeEmergencyDurationExceeded}
			}
			if effectivelyPaused {
				return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeEmergencySelfRenewal}
			}
		}
		// Council supermajority >= 67% with >= 2 distinct active council members.
		councilW := s.activeCouncilWeight()
		var signedCouncilW int64
		councilSigners := 0
		for id := range signerSet {
			sa, ok := s.FindActor(id)
			if ok && sa.Status == StatusActive && sa.Role == RoleCouncilMember {
				signedCouncilW += sa.VotingWeight
				councilSigners++
			}
		}
		if cfg.Mutant == "MUT-04" {
			signedCouncilW = 0
			councilSigners = 0
			for _, sig := range act.Signers {
				if sa, ok := s.FindActor(sig.ActorID); ok && sa.Role == RoleCouncilMember {
					signedCouncilW += sa.VotingWeight
					councilSigners++
				}
			}
		}
		if councilW == 0 || councilSigners < 2 || signedCouncilW*10000 < councilW*SupermajorityEmergencyBp {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeSupermajorityNotMet}
		}
		sort.Strings(signerIDs)
		s.Emergency.Paused = true
		s.Emergency.PauseStartedAt = act.Epoch
		s.Emergency.PauseExpiresAt = act.Epoch + act.DurationSec
		s.Emergency.LastTriggerers = append([]string(nil), signerIDs...)
		s.Emergency.UnreviewedCount++

	case ActionEmergencyRenew:
		if cfg.Mutant != "MUT-05" {
			if act.DurationSec <= 0 || act.DurationSec > MaxEmergencyDurationSec {
				return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeEmergencyDurationExceeded}
			}
			if effectivelyPaused {
				return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeEmergencySelfRenewal}
			}
			if s.Emergency.PauseExpiresAt > 0 && act.Epoch < s.Emergency.PauseExpiresAt+RenewalCooldownSec {
				return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeEmergencyCooldownActive}
			}
		}
		// Require independent human supermajority (>= 75%) AND at least one fresh human signer.
		activeW := s.activeHumanWeight()
		signedW, distinctHumans := s.signedWeightWithDelegation(signerSet, act.Epoch)
		prevSet := make(map[string]bool, len(s.Emergency.LastTriggerers))
		for _, prev := range s.Emergency.LastTriggerers {
			prevSet[prev] = true
		}
		hasFreshHuman := false
		for id := range signerSet {
			if !prevSet[id] {
				if sa, ok := s.FindActor(id); ok && sa.Status == StatusActive && sa.Role != RoleAIAgent {
					hasFreshHuman = true
				}
			}
		}
		if cfg.Mutant != "MUT-05" {
			if !hasFreshHuman {
				return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeEmergencySelfRenewal}
			}
			if activeW == 0 || distinctHumans < 3 || signedW*10000 < activeW*SupermajorityMetaGovBps {
				return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeEmergencyRenewalQuorum}
			}
		}
		sort.Strings(signerIDs)
		s.Emergency.Paused = true
		s.Emergency.PauseStartedAt = act.Epoch
		s.Emergency.PauseExpiresAt = act.Epoch + act.DurationSec
		s.Emergency.LastTriggerers = append([]string(nil), signerIDs...)
		s.Emergency.RenewalCount++
		s.Emergency.UnreviewedCount++

	case ActionExperimentValidate:
		if !s.EffectiveScopes(actor.ID, act.Epoch)[ScopeExperimentValidate] && actor.Role != RoleCouncilMember {
			return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeInsufficientScope}
		}

	default:
		return TransitionResult{Verdict: VerdictDeny, ErrorCode: CodeUnknownAction}
	}

	// Commit monotonic epoch, nonces, and execution audit record.
	s.Epoch = act.Epoch
	for _, sig := range act.Signers {
		sa, _ := s.FindActor(sig.ActorID)
		if sig.Nonce > sa.LastNonce {
			sa.LastNonce = sig.Nonce
		}
		s.UsedNonces = append(s.UsedNonces, fmt.Sprintf("%s:%d", sig.ActorID, sig.Nonce))
	}
	sort.Strings(signerIDs)
	// Check if a conflict existed despite mutant allowing it (for INV-07 checker).
	realPol := EvaluatePolicyHierarchy(s, act)
	s.ExecutedLog = append(s.ExecutedLog, ExecutionRecord{
		ActionID:       act.ID,
		ActionType:     act.Type,
		ActorID:        actor.ID,
		ActorRole:      actor.Role,
		Epoch:          act.Epoch,
		QueuedAt:       execQueuedAt,
		MinTimelockSec: execMinTimelock,
		WasPaused:      s.Emergency.Paused && act.Epoch < s.Emergency.PauseExpiresAt && (act.Type == ActionTreasuryExecute || act.Type == ActionRuleAmendExecute),
		Signers:        signerIDs,
		HadConflict:    realPol.ConflictWitness != nil,
	})
	return TransitionResult{Verdict: VerdictAllow, ErrorCode: CodeOK}
}

// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package govcheck

import "sort"

// PolicyEvaluation captures the deterministic result of evaluating the
// 4-tier rule hierarchy (INV-07).
type PolicyEvaluation struct {
	Allowed                       bool
	ErrorCode                     string
	ConflictWitness               *ConflictWitness
	HighestMatchedTier            RuleTier
	OverriddenLowerTierAllowRules []string
}

func evalRuleCondition(cond string, state *GovernanceState, act GovernanceAction) bool {
	switch cond {
	case "ALWAYS", "":
		return true
	case "WHEN_PAUSED":
		return state.IsPausedAt(act.Epoch)
	case "ACTOR_IS_AI":
		if a, ok := state.FindActor(act.ActorID); ok && a.Role == RoleAIAgent {
			return true
		}
		for _, s := range act.Signers {
			if a, ok := state.FindActor(s.ActorID); ok && a.Role == RoleAIAgent {
				return true
			}
		}
		return false
	case "AMOUNT_GT_CAP":
		capAmt := (state.TreasuryBalance * TreasuryEmergencyCapBps) / 10000
		return act.Amount > capAmt
	case "NO_TIMELOCK":
		return act.EmergencyBypass
	case "UNREVIEWED_EMERGENCY":
		return state.Emergency.UnreviewedCount > 0
	default:
		return false
	}
}

func ruleMatchesAction(r PolicyRule, state *GovernanceState, act GovernanceAction) bool {
	if r.ActionType != "*" && r.ActionType != act.Type {
		return false
	}
	if r.Target != "*" && r.Target != act.Target {
		return false
	}
	return evalRuleCondition(r.Condition, state, act)
}

// EvaluatePolicyHierarchy enforces INV-07:
// Strict tier precedence: CONSTITUTIONAL > EMERGENCY_SAFETY > CHARTER_STATUTE > ADVISORY_POLICY.
// Any same-tier ALLOW/DENY contradiction resolves fail-closed (ERR_DENY_RULE_CONFLICT)
// and emits a structured ConflictWitness.
func EvaluatePolicyHierarchy(state *GovernanceState, act GovernanceAction) PolicyEvaluation {
	matched := make([]PolicyRule, 0)
	highestRank := 0
	var highestTier RuleTier

	for _, r := range state.Rules {
		if !ruleMatchesAction(r, state, act) {
			continue
		}
		matched = append(matched, r)
		rank := TierRank(r.Tier)
		if rank > highestRank {
			highestRank = rank
			highestTier = r.Tier
		}
	}

	if len(matched) == 0 {
		// No explicit policy rule matched; pass to structural/constitutional checks.
		return PolicyEvaluation{Allowed: true, ErrorCode: CodeOK}
	}

	var allows []string
	var denies []string
	var lowerAllows []string

	for _, r := range matched {
		rank := TierRank(r.Tier)
		if rank == highestRank {
			if r.Effect == EffectAllow {
				allows = append(allows, r.ID)
			} else if r.Effect == EffectDeny {
				denies = append(denies, r.ID)
			}
		} else if rank < highestRank && r.Effect == EffectAllow {
			lowerAllows = append(lowerAllows, r.ID)
		}
	}

	sort.Strings(allows)
	sort.Strings(denies)
	sort.Strings(lowerAllows)

	// Same-tier contradiction => fail-closed with deterministic ConflictWitness.
	if len(allows) > 0 && len(denies) > 0 {
		return PolicyEvaluation{
			Allowed:            false,
			ErrorCode:          CodeDenyRuleConflict,
			HighestMatchedTier: highestTier,
			ConflictWitness: &ConflictWitness{
				Tier:         highestTier,
				AllowRuleIDs: allows,
				DenyRuleIDs:  denies,
				ActionID:     act.ID,
				ActionType:   act.Type,
				Target:       act.Target,
				Epoch:        act.Epoch,
				Resolution:   "DENY_RULE_CONFLICT",
			},
		}
	}

	if len(denies) > 0 {
		code := CodePolicyDeny
		if highestTier == TierConstitutional && len(lowerAllows) > 0 {
			code = CodeConstitutionalOverrideBlocked
		}
		return PolicyEvaluation{
			Allowed:                       false,
			ErrorCode:                     code,
			HighestMatchedTier:            highestTier,
			OverriddenLowerTierAllowRules: lowerAllows,
		}
	}

	return PolicyEvaluation{
		Allowed:            true,
		ErrorCode:          CodeOK,
		HighestMatchedTier: highestTier,
	}
}

// EvaluateNaiveFirstMatch intentionally models the buggy first-match policy evaluator
// used in Negative Regime 1 (neg_first_match_masks_rule_conflict) to prove that naive
// ordering silently masks same-tier contradictions.
func EvaluateNaiveFirstMatch(state *GovernanceState, act GovernanceAction) PolicyEvaluation {
	for _, r := range state.Rules {
		if !ruleMatchesAction(r, state, act) {
			continue
		}
		if r.Effect == EffectAllow {
			return PolicyEvaluation{Allowed: true, ErrorCode: CodeOK, HighestMatchedTier: r.Tier}
		}
		return PolicyEvaluation{Allowed: false, ErrorCode: CodePolicyDeny, HighestMatchedTier: r.Tier}
	}
	return PolicyEvaluation{Allowed: true, ErrorCode: CodeOK}
}

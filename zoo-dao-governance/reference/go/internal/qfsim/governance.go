// SPDX-License-Identifier: Apache-2.0

package qfsim

// Constitutional actor roles and governance action constants (HIP-1352).
const (
	RoleAIAgent      = "ai_agent"
	RoleHumanSteward = "human_steward"
	RoleHumanCouncil = "human_research_council"

	ActionRecommendAllocation = "recommend_allocation_plan"
	ActionFlagConflict        = "flag_collusion_conflict"
	ActionEstimateValue       = "estimate_proposal_value"
	ActionRedefineVotingRules = "redefine_voting_rules"
	ActionAuthorizeTreasury   = "authorize_treasury_disbursement"
	ActionValidateExperiment  = "declare_experiment_valid"

	ReasonAllowedAdvisory      = "ALLOWED_ADVISORY_ONLY"
	ReasonAllowedHumanQuorum   = "ALLOWED_HUMAN_QUORUM_MET"
	ReasonDeniedAIRuleMutation = "ERR_AI_RULE_MUTATION_FORBIDDEN"
	ReasonDeniedAITreasuryAuth = "ERR_AI_TREASURY_AUTH_FORBIDDEN"
	ReasonDeniedAISelfValidate = "ERR_AI_SELF_VALIDATION_FORBIDDEN"
	ReasonDeniedInsufficientQ  = "ERR_INSUFFICIENT_HUMAN_QUORUM"
	ReasonDeniedLowZooRep      = "ERR_INSUFFICIENT_STEWARD_ZOOREP"

	PlanStatusRequiresHumanSignOff = "PROPOSED_REQUIRES_HUMAN_SIGN_OFF"
)

// EvaluateGovernanceAction enforces HIP-1352 constitutional boundaries:
// AI agents may recommend, flag conflicts, estimate value, and prepare plans,
// but MUST NOT redefine voting rules, authorize treasury spending, or declare
// their own experiments valid.
func EvaluateGovernanceAction(
	checkID string,
	actorID string,
	actorRole string,
	actorZooRep int64,
	action string,
	humanSigners int,
) GovernanceCheck {
	check := GovernanceCheck{
		CheckID:      checkID,
		ActorID:      actorID,
		ActorRole:    actorRole,
		ActorZooRep:  actorZooRep,
		Action:       action,
		HumanSigners: humanSigners,
	}

	if actorRole == RoleAIAgent {
		switch action {
		case ActionRecommendAllocation, ActionFlagConflict, ActionEstimateValue:
			check.Allowed = true
			check.ReasonCode = ReasonAllowedAdvisory
		case ActionRedefineVotingRules:
			check.Allowed = false
			check.ReasonCode = ReasonDeniedAIRuleMutation
		case ActionAuthorizeTreasury:
			check.Allowed = false
			check.ReasonCode = ReasonDeniedAITreasuryAuth
		case ActionValidateExperiment:
			check.Allowed = false
			check.ReasonCode = ReasonDeniedAISelfValidate
		default:
			check.Allowed = false
			check.ReasonCode = ReasonDeniedAIRuleMutation
		}
		return check
	}

	// Human stewards / council members must meet ZooRep and 3-of-5 quorum thresholds.
	switch action {
	case ActionRecommendAllocation, ActionFlagConflict, ActionEstimateValue:
		check.Allowed = true
		check.ReasonCode = ReasonAllowedAdvisory
	case ActionAuthorizeTreasury:
		if actorZooRep < TreasuryStewardMinZooRep {
			check.Allowed = false
			check.ReasonCode = ReasonDeniedLowZooRep
		} else if humanSigners < TreasuryCommitteeQuorum {
			check.Allowed = false
			check.ReasonCode = ReasonDeniedInsufficientQ
		} else {
			check.Allowed = true
			check.ReasonCode = ReasonAllowedHumanQuorum
		}
	case ActionRedefineVotingRules:
		// Constitutional rule change requires Guardian/Research Council (>= 500 ZooRep) + quorum.
		if actorZooRep < 500 {
			check.Allowed = false
			check.ReasonCode = ReasonDeniedLowZooRep
		} else if humanSigners < TreasuryCommitteeQuorum {
			check.Allowed = false
			check.ReasonCode = ReasonDeniedInsufficientQ
		} else {
			check.Allowed = true
			check.ReasonCode = ReasonAllowedHumanQuorum
		}
	case ActionValidateExperiment:
		// Independent human peer review board (>= 200 ZooRep) + quorum.
		if actorZooRep < TreasuryStewardMinZooRep {
			check.Allowed = false
			check.ReasonCode = ReasonDeniedLowZooRep
		} else if humanSigners < TreasuryCommitteeQuorum {
			check.Allowed = false
			check.ReasonCode = ReasonDeniedInsufficientQ
		} else {
			check.Allowed = true
			check.ReasonCode = ReasonAllowedHumanQuorum
		}
	default:
		check.Allowed = false
		check.ReasonCode = ReasonDeniedInsufficientQ
	}
	return check
}

// DefaultGovernanceSignOffRecord returns the unexecuted, advisory-only disbursement
// plan gate state attached to every simulated round.
func DefaultGovernanceSignOffRecord() GovernanceSignOffRecord {
	return GovernanceSignOffRecord{
		PlanStatus:               PlanStatusRequiresHumanSignOff,
		RequiredHumanQuorum:      TreasuryCommitteeQuorum,
		TreasuryCommitteeSize:    TreasuryCommitteeSize,
		MinStewardZooRep:         TreasuryStewardMinZooRep,
		HumanSignaturesCollected: 0,
		AIRuleMutationBlocked:    true,
		AITreasuryAuthBlocked:    true,
		AISelfValidationBlocked:  true,
	}
}

// StandardConstitutionalAuditSuite runs the canonical 8-check HIP-1352 constitutional audit.
func StandardConstitutionalAuditSuite() []GovernanceCheck {
	return []GovernanceCheck{
		EvaluateGovernanceAction("gov-01-ai-recommend", "agent-qf-advisor-01", RoleAIAgent, 0, ActionRecommendAllocation, 0),
		EvaluateGovernanceAction("gov-02-ai-flag-conflict", "agent-qf-advisor-01", RoleAIAgent, 0, ActionFlagConflict, 0),
		EvaluateGovernanceAction("gov-03-ai-estimate-value", "agent-qf-advisor-01", RoleAIAgent, 0, ActionEstimateValue, 0),
		EvaluateGovernanceAction("gov-04-ai-redefine-rules-denied", "agent-qf-advisor-01", RoleAIAgent, 0, ActionRedefineVotingRules, 5),
		EvaluateGovernanceAction("gov-05-ai-treasury-auth-denied", "agent-qf-advisor-01", RoleAIAgent, 0, ActionAuthorizeTreasury, 5),
		EvaluateGovernanceAction("gov-06-ai-self-validate-denied", "agent-qf-advisor-01", RoleAIAgent, 0, ActionValidateExperiment, 5),
		EvaluateGovernanceAction("gov-07-human-quorum-2of5-denied", "steward-human-01", RoleHumanSteward, 320, ActionAuthorizeTreasury, 2),
		EvaluateGovernanceAction("gov-08-human-quorum-3of5-allowed", "steward-human-01", RoleHumanSteward, 320, ActionAuthorizeTreasury, 3),
	}
}

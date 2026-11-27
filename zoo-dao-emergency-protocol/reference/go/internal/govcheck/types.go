// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package govcheck

const (
	SchemaVersion = "constitutional-gov.v1"
	SpecVersion   = "1.0.0"

	MaxDelegationDepth       = 3
	MaxEmergencyDurationSec  = 72 * 3600 // 259200s (ZIP-0027)
	RenewalCooldownSec       = 24 * 3600 // 86400s
	AppealWindowSec          = 48 * 3600 // 172800s
	MinTimelockTreasurySec   = 24 * 3600 // 86400s
	MinTimelockRuleAmendSec  = 48 * 3600 // 172800s
	QuorumStandardBps        = 1500      // 15%
	QuorumMetaGovBps         = 2500      // 25%
	QuorumFloorBps           = 5000      // 50% constitutional denominator floor
	SupermajorityEmergencyBp = 6700      // 67% DEFCON-1 council supermajority
	SupermajorityMetaGovBps  = 7500      // 75% meta-governance / renewal supermajority
	TreasuryEmergencyCapBps  = 500       // 5% cap per ZIP-0027
)

type ActorRole string

const (
	RoleHumanMember   ActorRole = "HUMAN_MEMBER"
	RoleCouncilMember ActorRole = "COUNCIL_MEMBER"
	RoleAppealJudge   ActorRole = "APPEAL_JUDGE"
	RoleAIAgent       ActorRole = "AI_AGENT"
)

type ActorStatus string

const (
	StatusActive    ActorStatus = "ACTIVE"
	StatusSuspended ActorStatus = "SUSPENDED"
	StatusRevoked   ActorStatus = "REVOKED"
)

type RuleTier string

const (
	TierConstitutional  RuleTier = "CONSTITUTIONAL"
	TierEmergencySafety RuleTier = "EMERGENCY_SAFETY"
	TierCharterStatute  RuleTier = "CHARTER_STATUTE"
	TierAdvisoryPolicy  RuleTier = "ADVISORY_POLICY"
)

func TierRank(t RuleTier) int {
	switch t {
	case TierConstitutional:
		return 4
	case TierEmergencySafety:
		return 3
	case TierCharterStatute:
		return 2
	case TierAdvisoryPolicy:
		return 1
	default:
		return 0
	}
}

type RuleEffect string

const (
	EffectAllow RuleEffect = "ALLOW"
	EffectDeny  RuleEffect = "DENY"
)

type Verdict string

const (
	VerdictAllow Verdict = "ALLOW"
	VerdictDeny  Verdict = "DENY"
)

// Error codes (canonical across Go, Python, and OPA Rego v1).
const (
	CodeOK                             = "OK"
	CodeAIConstitutionalViolation      = "ERR_AI_CONSTITUTIONAL_VIOLATION"
	CodeDelegationCycle                = "ERR_DELEGATION_CYCLE"
	CodeDelegationDepthExceeded        = "ERR_DELEGATION_DEPTH_EXCEEDED"
	CodeDelegationScopeEscalation      = "ERR_DELEGATION_SCOPE_ESCALATION"
	CodeDelegationExpiryEscalation     = "ERR_DELEGATION_EXPIRY_ESCALATION"
	CodeDelegationRevoked              = "ERR_DELEGATION_REVOKED"
	CodeActorRevoked                   = "ERR_ACTOR_REVOKED"
	CodeActorSuspended                 = "ERR_ACTOR_SUSPENDED"
	CodeActorNotFound                  = "ERR_ACTOR_NOT_FOUND"
	CodeProposerAuthorityRevoked       = "ERR_PROPOSER_AUTHORITY_REVOKED"
	CodeDuplicateSigner                = "ERR_DUPLICATE_SIGNER"
	CodeDoubleVoteDelegation           = "ERR_DOUBLE_VOTE_DELEGATION"
	CodeQuorumNotMet                   = "ERR_QUORUM_NOT_MET"
	CodeQuorumFloorBreached            = "ERR_QUORUM_FLOOR_BREACHED"
	CodeSupermajorityNotMet            = "ERR_SUPERMAJORITY_NOT_MET"
	CodeEmergencyDurationExceeded      = "ERR_EMERGENCY_DURATION_EXCEEDED"
	CodeEmergencySelfRenewal           = "ERR_EMERGENCY_SELF_RENEWAL"
	CodeEmergencyCooldownActive        = "ERR_EMERGENCY_COOLDOWN_ACTIVE"
	CodeEmergencyRenewalQuorum         = "ERR_EMERGENCY_RENEWAL_QUORUM"
	CodePausedActionForbidden          = "ERR_PAUSED_ACTION_FORBIDDEN"
	CodeAppealWindowOpen               = "ERR_APPEAL_WINDOW_OPEN"
	CodeAppealFreezeActive             = "ERR_APPEAL_FREEZE_ACTIVE"
	CodeAppealNotFound                 = "ERR_APPEAL_NOT_FOUND"
	CodeAppealWindowClosed             = "ERR_APPEAL_WINDOW_CLOSED"
	CodeSelfAdjudication               = "ERR_SELF_ADJUDICATION"
	CodeInsufficientJudges             = "ERR_INSUFFICIENT_JUDGES"
	CodeDenyRuleConflict               = "ERR_DENY_RULE_CONFLICT"
	CodeConstitutionalOverrideBlocked  = "ERR_CONSTITUTIONAL_OVERRIDE_BLOCKED"
	CodePolicyDeny                     = "ERR_POLICY_DENY"
	CodeTimelockNotElapsed             = "ERR_TIMELOCK_NOT_ELAPSED"
	CodeProposalNotFound               = "ERR_PROPOSAL_NOT_FOUND"
	CodeInvalidSignature               = "ERR_INVALID_SIGNATURE"
	CodeReplayNonce                    = "ERR_REPLAY_NONCE"
	CodeEpochRegression                = "ERR_EPOCH_REGRESSION"
	CodeInsufficientScope              = "ERR_INSUFFICIENT_SCOPE"
	CodeUnknownAction                  = "ERR_UNKNOWN_ACTION"
	CodeTreasuryInsufficient           = "ERR_TREASURY_INSUFFICIENT"
)

// Action types.
const (
	ActionAdvisoryRecommend  = "ADVISORY_RECOMMEND"
	ActionFlagConflict       = "FLAG_CONFLICT"
	ActionDelegate           = "DELEGATE"
	ActionRevokeActor        = "REVOKE_ACTOR"
	ActionRevokeDelegation   = "REVOKE_DELEGATION"
	ActionSuspendActor       = "SUSPEND_ACTOR"
	ActionSelfSuspend        = "SELF_SUSPEND"
	ActionAppealFile         = "APPEAL_FILE"
	ActionAppealResolve      = "APPEAL_RESOLVE"
	ActionFinalizeContested  = "FINALIZE_CONTESTED"
	ActionTreasuryQueue      = "TREASURY_QUEUE"
	ActionTreasuryExecute    = "TREASURY_EXECUTE"
	ActionRuleAmendQueue     = "RULE_AMEND_QUEUE"
	ActionRuleAmendExecute   = "RULE_AMEND_EXECUTE"
	ActionEmergencyPause     = "EMERGENCY_PAUSE"
	ActionEmergencyRenew     = "EMERGENCY_RENEW"
	ActionExperimentValidate = "EXPERIMENT_VALIDATE"
	ActionAdvanceClock       = "ADVANCE_CLOCK"
)

// Permission scopes.
const (
	ScopeAdvisoryRecommend  = "ADVISORY_RECOMMEND"
	ScopeFlagConflict       = "FLAG_CONFLICT"
	ScopeEstimateValue      = "ESTIMATE_VALUE"
	ScopePreparePlan        = "PREPARE_PLAN"
	ScopeVoteStandard       = "VOTE_STANDARD"
	ScopeTreasurySpend      = "TREASURY_SPEND"
	ScopeRuleAmend          = "RULE_AMEND"
	ScopeEmergencyPause     = "EMERGENCY_PAUSE"
	ScopeEmergencySpend     = "EMERGENCY_SPEND"
	ScopeExperimentValidate = "EXPERIMENT_VALIDATE"
	ScopeAppealAdjudicate   = "APPEAL_ADJUDICATE"
	ScopeRevokeMember       = "REVOKE_MEMBER"
)

func IsSovereignScope(scope string) bool {
	switch scope {
	case ScopeTreasurySpend,
		ScopeRuleAmend,
		ScopeEmergencyPause,
		ScopeEmergencySpend,
		ScopeExperimentValidate,
		ScopeAppealAdjudicate,
		ScopeRevokeMember:
		return true
	default:
		return false
	}
}

func IsAIForbiddenAction(actionType string) bool {
	switch actionType {
	case ActionTreasuryQueue,
		ActionTreasuryExecute,
		ActionRuleAmendQueue,
		ActionRuleAmendExecute,
		ActionEmergencyPause,
		ActionEmergencyRenew,
		ActionExperimentValidate,
		ActionAppealResolve,
		ActionRevokeActor,
		ActionSuspendActor,
		ActionFinalizeContested:
		return true
	default:
		return false
	}
}

type Actor struct {
	ID           string      `json:"id"`
	Role         ActorRole   `json:"role"`
	PubKeyHex    string      `json:"pubkey_hex"`
	VotingWeight int64       `json:"voting_weight"`
	Status       ActorStatus `json:"status"`
	RevokedAt    int64       `json:"revoked_at"`
	LastNonce    uint64      `json:"last_nonce"`
	BaseScopes   []string    `json:"base_scopes"`
}

type Delegation struct {
	ID        string   `json:"id"`
	From      string   `json:"from"`
	To        string   `json:"to"`
	Scopes    []string `json:"scopes"`
	CreatedAt int64    `json:"created_at"`
	ExpiresAt int64    `json:"expires_at"`
	Revoked   bool     `json:"revoked"`
	RevokedAt int64    `json:"revoked_at"`
}

type PolicyRule struct {
	ID         string     `json:"id"`
	Tier       RuleTier   `json:"tier"`
	ActionType string     `json:"action_type"`
	Target     string     `json:"target"`
	Effect     RuleEffect `json:"effect"`
	Condition  string     `json:"condition"`
	Rationale  string     `json:"rationale"`
}

type QueuedAction struct {
	ID               string      `json:"id"`
	Kind             string      `json:"kind"` // TREASURY or RULE_AMEND
	ProposerID       string      `json:"proposer_id"`
	Target           string      `json:"target"`
	Amount           int64       `json:"amount"`
	NewRule          *PolicyRule `json:"new_rule,omitempty"`
	QueuedAt         int64       `json:"queued_at"`
	MinTimelockSec   int64       `json:"min_timelock_sec"`
	DelegationID     string      `json:"delegation_id"`
	DelegationOrigin string      `json:"delegation_origin"`
	Executed         bool        `json:"executed"`
	Invalidated      bool        `json:"invalidated"`
	InvalidatedAt    int64       `json:"invalidated_at"`
}

type ContestedAction struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"` // SUSPEND, VETO, SLASH
	InitiatorID    string `json:"initiator_id"`
	TargetActorID  string `json:"target_actor_id"`
	CreatedAt      int64  `json:"created_at"`
	AppealDeadline int64  `json:"appeal_deadline"`
	AppealFiled    bool   `json:"appeal_filed"`
	AppealStatus   string `json:"appeal_status"` // NONE, PENDING, UPHELD, OVERTURNED
	Judges         []string `json:"judges"`
	Finalized      bool   `json:"finalized"`
}

type EmergencyState struct {
	Paused          bool     `json:"paused"`
	PauseStartedAt  int64    `json:"pause_started_at"`
	PauseExpiresAt  int64    `json:"pause_expires_at"`
	LastTriggerers  []string `json:"last_triggerers"`
	RenewalCount    int      `json:"renewal_count"`
	UnreviewedCount int      `json:"unreviewed_count"`
}

type SignerSig struct {
	ActorID      string `json:"actor_id"`
	Nonce        uint64 `json:"nonce"`
	SignatureHex string `json:"signature_hex"`
}

type GovernanceAction struct {
	ID                 string      `json:"id"`
	Type               string      `json:"type"`
	ActorID            string      `json:"actor_id"`
	Target             string      `json:"target"`
	Epoch              int64       `json:"epoch"`
	Amount             int64       `json:"amount,omitempty"`
	DurationSec        int64       `json:"duration_sec,omitempty"`
	Scopes             []string    `json:"scopes,omitempty"`
	DelegationID       string      `json:"delegation_id,omitempty"`
	ProposalID         string      `json:"proposal_id,omitempty"`
	ContestedID        string      `json:"contested_id,omitempty"`
	ExperimentAuthorID string      `json:"experiment_author_id,omitempty"`
	AppealOutcome      string      `json:"appeal_outcome,omitempty"`
	EmergencyBypass    bool        `json:"emergency_bypass,omitempty"`
	NewRule            *PolicyRule `json:"new_rule,omitempty"`
	Signers            []SignerSig `json:"signers"`
}

type ConflictWitness struct {
	Tier         RuleTier `json:"tier"`
	AllowRuleIDs []string `json:"allow_rule_ids"`
	DenyRuleIDs  []string `json:"deny_rule_ids"`
	ActionID     string   `json:"action_id"`
	ActionType   string   `json:"action_type"`
	Target       string   `json:"target"`
	Epoch        int64    `json:"epoch"`
	Resolution   string   `json:"resolution"`
}

type ExecutionRecord struct {
	ActionID       string   `json:"action_id"`
	ActionType     string   `json:"action_type"`
	ActorID        string   `json:"actor_id"`
	ActorRole      ActorRole `json:"actor_role"`
	Epoch          int64    `json:"epoch"`
	QueuedAt       int64    `json:"queued_at"`
	MinTimelockSec int64    `json:"min_timelock_sec"`
	WasPaused      bool     `json:"was_paused"`
	Signers        []string `json:"signers"`
	HadConflict    bool     `json:"had_conflict"`
}

type GovernanceState struct {
	Epoch               int64              `json:"epoch"`
	TreasuryBalance     int64              `json:"treasury_balance"`
	GenesisActiveWeight int64              `json:"genesis_active_weight"`
	Actors              []Actor            `json:"actors"`
	Delegations         []Delegation       `json:"delegations"`
	Rules               []PolicyRule       `json:"rules"`
	QueuedActions       []QueuedAction     `json:"queued_actions"`
	ContestedActions    []ContestedAction  `json:"contested_actions"`
	Emergency           EmergencyState     `json:"emergency"`
	UsedNonces          []string           `json:"used_nonces"`
	ExecutedLog         []ExecutionRecord  `json:"-"`
}

type TransitionResult struct {
	Verdict         Verdict          `json:"verdict"`
	ErrorCode       string           `json:"error_code"`
	ConflictWitness *ConflictWitness `json:"conflict_witness,omitempty"`
}

type ConstantsSummary struct {
	MaxDelegationDepth       int   `json:"max_delegation_depth"`
	MaxEmergencyDurationSec  int64 `json:"max_emergency_duration_sec"`
	RenewalCooldownSec       int64 `json:"renewal_cooldown_sec"`
	AppealWindowSec          int64 `json:"appeal_window_sec"`
	MinTimelockTreasurySec   int64 `json:"min_timelock_treasury_sec"`
	MinTimelockRuleAmendSec  int64 `json:"min_timelock_rule_amend_sec"`
	QuorumStandardBps        int64 `json:"quorum_standard_bps"`
	QuorumMetaGovBps         int64 `json:"quorum_meta_gov_bps"`
	QuorumFloorBps           int64 `json:"quorum_floor_bps"`
	SupermajorityEmergencyBp int64 `json:"supermajority_emergency_bps"`
	SupermajorityMetaGovBps  int64 `json:"supermajority_meta_gov_bps"`
	TreasuryEmergencyCapBps  int64 `json:"treasury_emergency_cap_bps"`
}

type AdversarialCase struct {
	CaseID            string             `json:"case_id"`
	InvariantID       string             `json:"invariant_id"`
	Description       string             `json:"description"`
	InitialState      GovernanceState    `json:"initial_state"`
	Actions           []GovernanceAction `json:"actions"`
	ExpectedVerdict   Verdict            `json:"expected_verdict"`
	ExpectedErrorCode string             `json:"expected_error_code"`
	ActualVerdict     Verdict            `json:"actual_verdict"`
	ActualErrorCode   string             `json:"actual_error_code"`
	ConflictWitness   *ConflictWitness   `json:"conflict_witness,omitempty"`
	Passed            bool               `json:"passed"`
	CaseDigest        string             `json:"case_digest"`
}

type AdversarialSuiteReport struct {
	TotalCases           int               `json:"total_cases"`
	AdversarialDenyCases int               `json:"adversarial_deny_cases"`
	PositiveAllowCases   int               `json:"positive_allow_cases"`
	Passed               int               `json:"passed"`
	Failed               int               `json:"failed"`
	Cases                []AdversarialCase `json:"cases"`
}

type ModelCheckerReport struct {
	BFSMaxDepth               int      `json:"bfs_max_depth"`
	BFSStatesExplored         int      `json:"bfs_states_explored"`
	BFSTransitionsChecked     int      `json:"bfs_transitions_checked"`
	FuzzTraces                int      `json:"fuzz_traces"`
	FuzzStepsChecked          int      `json:"fuzz_steps_checked"`
	TotalStatesAndTransitions int      `json:"total_states_and_transitions"`
	InvariantViolations       int      `json:"invariant_violations"`
	InvariantsChecked         []string `json:"invariants_checked"`
}

type MutationResult struct {
	MutantID            string   `json:"mutant_id"`
	TargetInvariant     string   `json:"target_invariant"`
	Description         string   `json:"description"`
	Killed              bool     `json:"killed"`
	CounterexampleDepth int      `json:"counterexample_depth"`
	CounterexampleSteps []string `json:"counterexample_steps"`
	ViolatedInvariant   string   `json:"violated_invariant"`
}

type MutationAuditReport struct {
	TotalMutants  int              `json:"total_mutants"`
	MutantsKilled int              `json:"mutants_killed"`
	KillRateBps   int64            `json:"kill_rate_bps"`
	Mutants       []MutationResult `json:"mutants"`
}

type NegFirstMatchReport struct {
	Trials                     int   `json:"trials"`
	NaiveFirstMatchUnsafeAllow int   `json:"naive_first_match_unsafe_allows"`
	NaiveUnsafeAllowBps        int64 `json:"naive_unsafe_allow_bps"`
	FailClosedBlocked          int   `json:"fail_closed_blocked"`
	FailClosedBlockBps         int64 `json:"fail_closed_block_bps"`
	ConflictWitnessesEmitted   int   `json:"conflict_witnesses_emitted"`
}

type NegLivenessDeadlockReport struct {
	UrgentValidOps               int   `json:"urgent_valid_ops"`
	ExecutedUnderCharterConflict int   `json:"executed_under_charter_conflict"`
	ExecutedUnderDefcon1Pause    int   `json:"executed_under_defcon1_pause"`
	LivenessUnderConflictBps     int64 `json:"liveness_under_conflict_bps"`
	LivenessUnderPauseBps        int64 `json:"liveness_under_pause_bps"`
	SafetyViolations             int   `json:"safety_violations"`
	AutoSunsetRecoverySec        int64 `json:"auto_sunset_recovery_sec"`
}

type DepthProbe struct {
	MaxDepth          int  `json:"max_depth"`
	StatesExplored    int  `json:"states_explored"`
	BugDetected       bool `json:"bug_detected"`
	CounterexampleLen int  `json:"counterexample_len"`
}

type NegDepthHorizonReport struct {
	PlantedBugMinDepth     int          `json:"planted_bug_min_depth"`
	UnboundedProofRequired bool         `json:"unbounded_proof_required"`
	DepthProbes            []DepthProbe `json:"depth_probes"`
}

type NegativeRegimesReport struct {
	FirstMatchMasksRuleConflict NegFirstMatchReport       `json:"neg_first_match_masks_rule_conflict"`
	FailClosedLivenessDeadlock  NegLivenessDeadlockReport `json:"neg_fail_closed_liveness_deadlock"`
	BoundedMCDepthHorizon       NegDepthHorizonReport     `json:"neg_bounded_mc_depth_horizon"`
}

type RegoBundleReport struct {
	RegoVersion     string   `json:"rego_version"`
	Files           []string `json:"files"`
	OPACLIAvailable bool     `json:"opa_cli_available"`
	BundleSHA256    string   `json:"bundle_sha256"`
}

type BenchmarkResults struct {
	SchemaVersion    string                 `json:"schema_version"`
	SpecVersion      string                 `json:"spec_version"`
	Seed             int64                  `json:"seed"`
	Constants        ConstantsSummary       `json:"constants"`
	AdversarialSuite AdversarialSuiteReport `json:"adversarial_suite"`
	ModelChecker     ModelCheckerReport     `json:"model_checker"`
	MutationAudit    MutationAuditReport    `json:"mutation_audit"`
	NegativeRegimes  NegativeRegimesReport  `json:"negative_regimes"`
	RegoBundle       RegoBundleReport       `json:"rego_bundle"`
	AuditMerkleRoot  string                 `json:"audit_merkle_root"`
}

func DefaultConstants() ConstantsSummary {
	return ConstantsSummary{
		MaxDelegationDepth:       MaxDelegationDepth,
		MaxEmergencyDurationSec:  MaxEmergencyDurationSec,
		RenewalCooldownSec:       RenewalCooldownSec,
		AppealWindowSec:          AppealWindowSec,
		MinTimelockTreasurySec:   MinTimelockTreasurySec,
		MinTimelockRuleAmendSec:  MinTimelockRuleAmendSec,
		QuorumStandardBps:        QuorumStandardBps,
		QuorumMetaGovBps:         QuorumMetaGovBps,
		QuorumFloorBps:           QuorumFloorBps,
		SupermajorityEmergencyBp: SupermajorityEmergencyBp,
		SupermajorityMetaGovBps:  SupermajorityMetaGovBps,
		TreasuryEmergencyCapBps:  TreasuryEmergencyCapBps,
	}
}

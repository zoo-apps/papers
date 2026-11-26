// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation & Open ResearchDAO Contributors.

package daoos

import (
	"errors"
	"fmt"
)

const (
	// SpecVersion pins the wire format, canonical serialization, and state-machine rules.
	SpecVersion = "researchdao-os.v1"

	// GenesisPrevHash is the 32-byte all-zero predecessor hash for seq=1.
	GenesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000"

	// MaxEmergencyDurationSeconds enforces ZIP-0027 Temporal Bound (72 hours).
	MaxEmergencyDurationSeconds int64 = 72 * 3600

	// HoldbackBps enforces ZIP-0023 10% holdback until independent acceptance.
	HoldbackBps int64 = 1000
)

// ActorKind distinguishes authorized human/institutional decision-makers from AI agents.
type ActorKind string

const (
	ActorKindHuman   ActorKind = "HUMAN"
	ActorKindAIAgent ActorKind = "AI_AGENT"
)

// Role enumerates institutional authority roles aligned with ZIP-0017, ZIP-0023, ZIP-0027, ZIP-0603/0604.
type Role string

const (
	RoleResearcher          Role = "RESEARCHER"
	RolePeerReviewer        Role = "PEER_REVIEWER"
	RoleMilestoneCommittee  Role = "MILESTONE_COMMITTEE"
	RoleTreasurySteward     Role = "TREASURY_STEWARD"
	RoleIndependentVerifier Role = "INDEPENDENT_VERIFIER"
	RoleBoardGuardian       Role = "BOARD_GUARDIAN"
	RoleEmergencyCouncil    Role = "EMERGENCY_COUNCIL"
	RoleMetaGovernor        Role = "META_GOVERNOR"
	RoleAIAdvisor           Role = "AI_ADVISOR"
)

// ProposalCategory maps to ZIP-0023 grant categories.
type ProposalCategory string

const (
	CategoryConservationResearch  ProposalCategory = "CONSERVATION_RESEARCH"
	CategoryOpenSourceDev         ProposalCategory = "OPEN_SOURCE_DEV"
	CategoryCitizenScience        ProposalCategory = "CITIZEN_SCIENCE"
	CategoryEducation             ProposalCategory = "EDUCATION"
	CategoryEmergencyConservation ProposalCategory = "EMERGENCY_CONSERVATION"
)

// ProposalStatus tracks the 5-stage executable research lifecycle plus governance outcomes.
type ProposalStatus string

const (
	StatusSubmitted         ProposalStatus = "SUBMITTED"
	StatusUnderReview       ProposalStatus = "UNDER_REVIEW"
	StatusPeerReviewed      ProposalStatus = "PEER_REVIEWED"
	StatusReviewRejected    ProposalStatus = "REVIEW_REJECTED"
	StatusMilestoneApproved ProposalStatus = "MILESTONE_APPROVED"
	StatusFundingQueued     ProposalStatus = "FUNDING_QUEUED"
	StatusFundingAuthorized ProposalStatus = "FUNDING_AUTHORIZED"
	StatusVetoed            ProposalStatus = "VETOED"
	StatusAccepted          ProposalStatus = "ACCEPTED"
	StatusAcceptanceFailed  ProposalStatus = "ACCEPTANCE_FAILED"
)

// EventType enumerates all signed transition envelopes in researchdao-os.v1.
type EventType string

const (
	EventProposalSubmitted             EventType = "ProposalSubmitted"
	EventAdvisoryRecorded              EventType = "AdvisoryRecorded"
	EventPeerReviewRecorded            EventType = "PeerReviewRecorded"
	EventMilestoneApproved             EventType = "MilestoneApproved"
	EventFundingQueued                 EventType = "FundingQueued"
	EventFundingCosigned               EventType = "FundingCosigned"
	EventFundingAuthorized             EventType = "FundingAuthorized"
	EventBoardVetoRecorded             EventType = "BoardVetoRecorded"
	EventIndependentAcceptanceRecorded EventType = "IndependentAcceptanceRecorded"
	EventEmergencyPauseSigned          EventType = "EmergencyPauseSigned"
	EventEmergencyPauseLifted          EventType = "EmergencyPauseLifted"
	EventGovernanceRuleAmended         EventType = "GovernanceRuleAmended"
	EventActorRevoked                  EventType = "ActorRevoked"
)

// ErrorCode provides stable, cross-language machine-verifiable rejection codes.
type ErrorCode string

const (
	ErrUnknownActor            ErrorCode = "ERR_UNKNOWN_ACTOR"
	ErrActorRevoked            ErrorCode = "ERR_ACTOR_REVOKED"
	ErrActorExpired            ErrorCode = "ERR_ACTOR_EXPIRED"
	ErrInvalidSignature        ErrorCode = "ERR_INVALID_SIGNATURE"
	ErrNonceReplay             ErrorCode = "ERR_NONCE_REPLAY"
	ErrChainBroken             ErrorCode = "ERR_CHAIN_BROKEN"
	ErrInvalidSequence         ErrorCode = "ERR_INVALID_SEQUENCE"
	ErrTimestampRegression     ErrorCode = "ERR_TIMESTAMP_REGRESSION"
	ErrInvalidPayload          ErrorCode = "ERR_INVALID_PAYLOAD"
	ErrUnauthorizedRole        ErrorCode = "ERR_UNAUTHORIZED_ROLE"
	ErrAITreasuryForbidden     ErrorCode = "ERR_AI_TREASURY_FORBIDDEN"
	ErrAIRuleChangeForbidden   ErrorCode = "ERR_AI_RULE_CHANGE_FORBIDDEN"
	ErrAIValidationForbidden   ErrorCode = "ERR_AI_VALIDATION_FORBIDDEN"
	ErrAIGovernanceForbidden   ErrorCode = "ERR_AI_GOVERNANCE_FORBIDDEN"
	ErrSelfReviewForbidden     ErrorCode = "ERR_SELF_REVIEW_FORBIDDEN"
	ErrSelfApprovalForbidden   ErrorCode = "ERR_SELF_APPROVAL_FORBIDDEN"
	ErrCOIConflict             ErrorCode = "ERR_COI_CONFLICT"
	ErrDuplicateReview         ErrorCode = "ERR_DUPLICATE_REVIEW"
	ErrDuplicateApproval       ErrorCode = "ERR_DUPLICATE_APPROVAL"
	ErrDuplicateProposal       ErrorCode = "ERR_DUPLICATE_PROPOSAL"
	ErrProposalNotFound        ErrorCode = "ERR_PROPOSAL_NOT_FOUND"
	ErrInvalidTransition       ErrorCode = "ERR_INVALID_TRANSITION"
	ErrQuorumNotMet            ErrorCode = "ERR_QUORUM_NOT_MET"
	ErrTimelockNotElapsed      ErrorCode = "ERR_TIMELOCK_NOT_ELAPSED"
	ErrBudgetCapExceeded       ErrorCode = "ERR_BUDGET_CAP_EXCEEDED"
	ErrTrancheAlreadyDisbursed ErrorCode = "ERR_TRANCHE_ALREADY_DISBURSED"
	ErrSystemPaused            ErrorCode = "ERR_SYSTEM_PAUSED"
	ErrProposalVetoed          ErrorCode = "ERR_PROPOSAL_VETOED"
	ErrVerifierNotIndependent  ErrorCode = "ERR_VERIFIER_NOT_INDEPENDENT"
	ErrEvidenceMismatch        ErrorCode = "ERR_EVIDENCE_MISMATCH"
	ErrWALTampered             ErrorCode = "ERR_WAL_TAMPERED"
)

// TransitionError wraps a deterministic ErrorCode with human-readable context.
type TransitionError struct {
	Code    ErrorCode
	Message string
}

func (e *TransitionError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// NewTransitionError constructs a typed TransitionError.
func NewTransitionError(code ErrorCode, msg string) *TransitionError {
	return &TransitionError{Code: code, Message: msg}
}

// ErrorCodeOf extracts the ErrorCode from an error, or empty string if none.
func ErrorCodeOf(err error) ErrorCode {
	var te *TransitionError
	if errors.As(err, &te) {
		return te.Code
	}
	return ""
}

// GovernanceConfig defines parameterized governance thresholds aligned with ZIP-0017, ZIP-0023, ZIP-0027, ZIP-0604.
type GovernanceConfig struct {
	MinPeerReviews          int   `json:"min_peer_reviews"`
	MinReviewScoreBps       int64 `json:"min_review_score_bps"`
	MilestoneQuorum         int   `json:"milestone_quorum"`
	TreasuryQuorum          int   `json:"treasury_quorum"`
	EmergencyPauseQuorum    int   `json:"emergency_pause_quorum"`
	MetaGovernanceQuorum    int   `json:"meta_governance_quorum"`
	TimelockSeconds         int64 `json:"timelock_seconds"`
	EpochDurationSeconds    int64 `json:"epoch_duration_seconds"`
	EpochSpendCapBps        int64 `json:"epoch_spend_cap_bps"`
	MaxEmergencyDurationSec int64 `json:"max_emergency_duration_sec"`
	HoldbackBps             int64 `json:"holdback_bps"`
}

// DefaultGovernanceConfig returns defaults grounded in the Zoo DAO papers:
// - 3 peer reviews with >= 6.0/10 (6000 bps) mean score (ZIP-0023 §7)
// - 2-of-N milestone committee approvals (ZIP-0023)
// - 2-of-3 treasury steward multi-sig + 72h timelock (ZIP-0017 Table 1)
// - 2-of-3 DEFCON 1 emergency pause with 72h max duration (ZIP-0027 Table 2)
// - 10% per-30-day-epoch treasury spend cap (ZIP-0017 §6.2)
// - 10% holdback until independent acceptance (ZIP-0023 §4.3)
func DefaultGovernanceConfig() GovernanceConfig {
	return GovernanceConfig{
		MinPeerReviews:          3,
		MinReviewScoreBps:       6000,
		MilestoneQuorum:         2,
		TreasuryQuorum:          2,
		EmergencyPauseQuorum:    2,
		MetaGovernanceQuorum:    3,
		TimelockSeconds:         72 * 3600,
		EpochDurationSeconds:    30 * 24 * 3600,
		EpochSpendCapBps:        1000,
		MaxEmergencyDurationSec: MaxEmergencyDurationSeconds,
		HoldbackBps:             HoldbackBps,
	}
}

// Actor defines an identity registered in the ResearchDAO OS.
type Actor struct {
	ID             string    `json:"id"`
	PubKeyHex      string    `json:"pubkey_hex"`
	Kind           ActorKind `json:"kind"`
	Roles          []Role    `json:"roles"`
	Affiliations   []string  `json:"affiliations"`
	Reputation     int64     `json:"reputation"`
	Active         bool      `json:"active"`
	EffectiveUntil int64     `json:"effective_until"` // 0 means no expiry
	RevokedAt      int64     `json:"revoked_at"`      // 0 means not revoked
	LastNonce      uint64    `json:"last_nonce"`
}

// HasRole checks if the actor holds the requested role.
func (a *Actor) HasRole(r Role) bool {
	for _, role := range a.Roles {
		if role == r {
			return true
		}
	}
	return false
}

// Genesis captures the immutable starting configuration of a ResearchDAO OS instance.
type Genesis struct {
	SpecVersion            string           `json:"spec_version"`
	ChainID                string           `json:"chain_id"`
	CreatedAt              int64            `json:"created_at"`
	InitialTreasuryBalance int64            `json:"initial_treasury_balance"`
	Config                 GovernanceConfig `json:"config"`
	Actors                 []Actor          `json:"actors"`
}

// Envelope is the signed, hash-chained unit of state transition persisted to the WAL.
type Envelope struct {
	SpecVersion   string         `json:"spec_version"`
	Seq           uint64         `json:"seq"`
	PrevEventHash string         `json:"prev_event_hash"`
	Timestamp     int64          `json:"timestamp"`
	ActorID       string         `json:"actor_id"`
	Nonce         uint64         `json:"nonce"`
	Type          EventType      `json:"type"`
	Payload       map[string]any `json:"payload"`
	SignatureHex  string         `json:"signature_hex"`
}

// AdvisoryNote records strictly non-binding AI analysis attached to a proposal.
type AdvisoryNote struct {
	Seq            uint64   `json:"seq"`
	AdvisorID      string   `json:"advisor_id"`
	Timestamp      int64    `json:"timestamp"`
	AdvisoryOnly   bool     `json:"advisory_only"`
	AnalysisHash   string   `json:"analysis_hash"`
	Summary        string   `json:"summary"`
	ConflictFlags  []string `json:"conflict_flags"`
	EstimatedValue int64    `json:"estimated_value"`
}

// PeerReview records an authorized independent reviewer's evaluation.
type PeerReview struct {
	ReviewerID  string `json:"reviewer_id"`
	Timestamp   int64  `json:"timestamp"`
	ScoreBps    int64  `json:"score_bps"`
	ReportHash  string `json:"report_hash"`
	Recommend   bool   `json:"recommend"`
	COIDeclared bool   `json:"coi_declared"`
}

// MilestoneApproval records an authorized committee member's sign-off on verifiable evidence.
type MilestoneApproval struct {
	ApproverID   string `json:"approver_id"`
	Timestamp    int64  `json:"timestamp"`
	EvidenceHash string `json:"evidence_hash"`
	NotesHash    string `json:"notes_hash"`
}

// FundingRecord tracks timelocked multi-sig treasury authorization and holdback escrow.
type FundingRecord struct {
	Amount              int64    `json:"amount"`
	InitialTranche      int64    `json:"initial_tranche"`
	HoldbackTranche     int64    `json:"holdback_tranche"`
	QueuedAt            int64    `json:"queued_at"`
	TimelockReadyAt     int64    `json:"timelock_ready_at"`
	AuthorizedAt        int64    `json:"authorized_at"`
	StewardSigners      []string `json:"steward_signers"`
	InitialTrancheID    string   `json:"initial_tranche_id"`
	HoldbackTrancheID   string   `json:"holdback_tranche_id"`
	InitialDisbursed    bool     `json:"initial_disbursed"`
	HoldbackDisbursed   bool     `json:"holdback_disbursed"`
	HoldbackClawedBack  bool     `json:"holdback_clawed_back"`
}

// BoardVetoRecord captures a narrow 501(c)(3) compliance veto during timelock.
type BoardVetoRecord struct {
	GuardianID    string `json:"guardian_id"`
	Timestamp     int64  `json:"timestamp"`
	Justification string `json:"justification"`
}

// AcceptanceRecord captures independent third-party reproducibility verification.
type AcceptanceRecord struct {
	VerifierID        string `json:"verifier_id"`
	Timestamp         int64  `json:"timestamp"`
	BoundEvidenceHash string `json:"bound_evidence_hash"`
	ReproCheckHash    string `json:"repro_check_hash"`
	Verdict           string `json:"verdict"` // "ACCEPTED" or "FAILED_REPRO"
}

// Proposal represents the full auditable lifecycle state of a research grant proposal.
type Proposal struct {
	ID                    string              `json:"id"`
	Title                 string              `json:"title"`
	Category              ProposalCategory    `json:"category"`
	ProposerID            string              `json:"proposer_id"`
	PlanHash              string              `json:"plan_hash"`
	SourcePaper           string              `json:"source_paper"`
	RequestedAmount       int64               `json:"requested_amount"`
	DeclaredCOIActors     []string            `json:"declared_coi_actors"`
	Status                ProposalStatus      `json:"status"`
	SubmittedAt           int64               `json:"submitted_at"`
	Advisories            []AdvisoryNote      `json:"advisories"`
	Reviews               []PeerReview        `json:"reviews"`
	ReviewMeanScoreBps    int64               `json:"review_mean_score_bps"`
	MilestoneIndex        int64               `json:"milestone_index"`
	MilestoneEvidenceHash string              `json:"milestone_evidence_hash"`
	MilestoneApprovals    []MilestoneApproval `json:"milestone_approvals"`
	Funding               *FundingRecord      `json:"funding,omitempty"`
	Veto                  *BoardVetoRecord    `json:"veto,omitempty"`
	Acceptance            *AcceptanceRecord   `json:"acceptance,omitempty"`
}

// TreasuryState tracks available funds, locked holdback escrow, epoch spend caps, and tranche replay guards.
type TreasuryState struct {
	Balance           int64            `json:"balance"`
	EscrowedTotal     int64            `json:"escrowed_total"`
	TotalDisbursed    int64            `json:"total_disbursed"`
	EpochSpent        map[string]int64 `json:"epoch_spent"`
	DisbursedTranches map[string]bool  `json:"disbursed_tranches"`
}

// EmergencyPauseState enforces ZIP-0027 DEFCON 1 defensive circuit breaker.
type EmergencyPauseState struct {
	Active         bool                `json:"active"`
	ActionID       string              `json:"action_id"`
	Reason         string              `json:"reason"`
	ActivatedAt    int64               `json:"activated_at"`
	ExpiresAt      int64               `json:"expires_at"`
	Signers        []string            `json:"signers"`
	PendingPauses  map[string][]string `json:"pending_pauses"`
	PendingReasons map[string]string   `json:"pending_reasons"`
	PendingDurs    map[string]int64    `json:"pending_durs"`
	PendingLifts   map[string][]string `json:"pending_lifts"`
	LastReviewHash string              `json:"last_review_hash"`
}

// PendingRuleChange accumulates multi-sig META_GOVERNOR approvals for a parameter amendment.
type PendingRuleChange struct {
	ChangeID       string   `json:"change_id"`
	Parameter      string   `json:"parameter"`
	NewValue       int64    `json:"new_value"`
	Signers        []string `json:"signers"`
	Executed       bool     `json:"executed"`
	ExecutedAt     int64    `json:"executed_at"`
	ProposedAt     int64    `json:"proposed_at"`
}

// State is the complete deterministic state of the ResearchDAO Operating System.
type State struct {
	SpecVersion        string                        `json:"spec_version"`
	ChainID            string                        `json:"chain_id"`
	GenesisHash        string                        `json:"genesis_hash"`
	Seq                uint64                        `json:"seq"`
	LastTimestamp      int64                         `json:"last_timestamp"`
	LastEventHash      string                        `json:"last_event_hash"`
	Config             GovernanceConfig              `json:"config"`
	Treasury           TreasuryState                 `json:"treasury"`
	EmergencyPause     EmergencyPauseState           `json:"emergency_pause"`
	Actors             map[string]*Actor             `json:"actors"`
	Proposals          map[string]*Proposal          `json:"proposals"`
	PendingRuleChanges map[string]*PendingRuleChange `json:"pending_rule_changes"`
}

// Checkpoint is a durable snapshot of state at sequence Seq for fast cold-restart replay.
type Checkpoint struct {
	SpecVersion     string   `json:"spec_version"`
	GenesisHash     string   `json:"genesis_hash"`
	Seq             uint64   `json:"seq"`
	LastEventHash   string   `json:"last_event_hash"`
	StateRootHash   string   `json:"state_root_hash"`
	AuditMerkleRoot string   `json:"audit_merkle_root"`
	EventHashes     []string `json:"event_hashes"`
	State           State    `json:"state"`
}

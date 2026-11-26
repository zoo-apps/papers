// SPDX-License-Identifier: Apache-2.0

package ledger

const (
	SchemaVersion      = "zoo-experience-ledger/v1"
	SigningDomainEvent = "zoo-experience-ledger/v1:event:"
	EmptyMerkleDomain  = "zoo-experience-ledger/v1:empty-merkle"
)

// Principal roles enforcing constitutional separation.
const (
	RoleHumanResearcher = "human_researcher"
	RoleAIAgent         = "ai_agent"
	RoleSteward         = "steward"
)

// Event types.
const (
	EventTypeExperienceEntry    = "experience_entry"
	EventTypeRevocationRecord   = "revocation_record"
	EventTypeConflictFlag       = "conflict_flag"
	EventTypeResolutionDecision = "resolution_decision"
)

// Entry statuses in reconstructed state.
const (
	EntryStatusActive     = "active"
	EntryStatusConflicted = "conflicted"
	EntryStatusSuperseded = "superseded"
	EntryStatusTainted    = "tainted"
	EntryStatusRevoked    = "revoked"
)

// ConflictSet statuses.
const (
	ConflictStatusOpen                       = "open"
	ConflictStatusResolved                   = "resolved"
	ConflictStatusEscalatedStewardDisagree   = "escalated_steward_disagreement"
)

// Resolution outcomes.
const (
	OutcomeSelectCanonical = "select_canonical"
	OutcomeRejectAll       = "reject_all"
	OutcomeKeepBothScoped  = "keep_both_scoped"
)

// Revocation reason codes.
const (
	ReasonRetractedByAuthor = "retracted_by_author"
	ReasonCorruptedArtifact = "corrupted_artifact"
	ReasonFalsifiedClaim    = "falsified_claim"
	ReasonPolicyViolation   = "policy_violation"
	ReasonSuperseded        = "superseded"
)

// Error / rejection codes.
const (
	ErrInvalidSchema             = "ERR_INVALID_SCHEMA"
	ErrEventIDMismatch           = "ERR_EVENT_ID_MISMATCH"
	ErrUnknownPrincipal          = "ERR_UNKNOWN_PRINCIPAL"
	ErrInvalidSignature          = "ERR_INVALID_SIGNATURE"
	ErrAIAgentResolutionForbid   = "ERR_AI_AGENT_RESOLUTION_FORBIDDEN"
	ErrUnauthorizedResolution    = "ERR_UNAUTHORIZED_RESOLUTION"
	ErrUnauthorizedRevocation    = "ERR_UNAUTHORIZED_REVOCATION"
	ErrSelfValidationForbidden   = "ERR_SELF_VALIDATION_FORBIDDEN"
	ErrInvalidResolutionTarget   = "ERR_INVALID_RESOLUTION_TARGET"
	ErrCycleDetected             = "ERR_CYCLE_DETECTED"
)

// Principal describes a registered Ed25519 identity and its role.
type Principal struct {
	PrincipalID  string `json:"principal_id"`
	Role         string `json:"role"`
	PublicKeyHex string `json:"public_key_hex"`
	Active       bool   `json:"active"`
}

// Policy defines the trust anchor and principal registry for a ledger.
type Policy struct {
	SchemaVersion string      `json:"schema_version"`
	PolicyID      string      `json:"policy_id"`
	Principals    []Principal `json:"principals"`
	PolicySHA256  string      `json:"policy_sha256"`
}

// Event is the unified wire representation of any of the 4 ledger event types.
// Unused fields for a given event_type are omitted during canonicalization.
type Event struct {
	SchemaVersion string `json:"schema_version"`
	EventType     string `json:"event_type"`
	CreatedAtUnix int64  `json:"created_at_unix"`
	EventID       string `json:"event_id"`
	SignatureHex  string `json:"signature_hex"`

	// experience_entry fields
	ContributorID     string   `json:"contributor_id,omitempty"`
	Domain            string   `json:"domain,omitempty"`
	ClaimKey          string   `json:"claim_key,omitempty"`
	ClaimValueHash    string   `json:"claim_value_hash,omitempty"`
	Summary           string   `json:"summary,omitempty"`
	ConfidenceBps     int64    `json:"confidence_bps,omitempty"`
	ArtifactSHA256    string   `json:"artifact_sha256,omitempty"`
	ArtifactURI       string   `json:"artifact_uri,omitempty"`
	ArtifactSizeBytes int64    `json:"artifact_size_bytes,omitempty"`
	ExternalURIs      []string `json:"external_uris,omitempty"`
	ParentHashes      []string `json:"parent_hashes,omitempty"`
	ReceiptHash       string   `json:"receipt_hash,omitempty"`
	Nonce             string   `json:"nonce,omitempty"`

	// revocation_record fields
	IssuerID       string `json:"issuer_id,omitempty"`
	TargetEventID  string `json:"target_event_id,omitempty"`
	ReasonCode     string `json:"reason_code,omitempty"`
	Reason         string `json:"reason,omitempty"`
	EvidenceSHA256 string `json:"evidence_sha256,omitempty"`
	EvidenceURI    string `json:"evidence_uri,omitempty"`

	// conflict_flag fields
	FlaggerID           string   `json:"flagger_id,omitempty"`
	ConflictingEventIDs []string `json:"conflicting_event_ids,omitempty"`
	Rationale           string   `json:"rationale,omitempty"`

	// resolution_decision fields
	StewardID       string   `json:"steward_id,omitempty"`
	ReviewedEventIDs []string `json:"reviewed_event_ids,omitempty"`
	Outcome         string   `json:"outcome,omitempty"`
	WinningEventID  string   `json:"winning_event_id,omitempty"`
	RationaleSHA256 string   `json:"rationale_sha256,omitempty"`
	RationaleURI    string   `json:"rationale_uri,omitempty"`
	GovernanceRef   string   `json:"governance_ref,omitempty"`
}

// LedgerBundle is the portable JSON document containing a Policy and Event log.
type LedgerBundle struct {
	SchemaVersion string  `json:"schema_version"`
	Policy        Policy  `json:"policy"`
	Events        []Event `json:"events"`
}

// EntryState captures the reconstructed status of one ExperienceEntry.
type EntryState struct {
	EventID            string   `json:"event_id"`
	ContributorID      string   `json:"contributor_id"`
	Domain             string   `json:"domain"`
	ClaimKey           string   `json:"claim_key"`
	ClaimValueHash     string   `json:"claim_value_hash"`
	ArtifactSHA256     string   `json:"artifact_sha256"`
	ArtifactURI        string   `json:"artifact_uri"`
	Status             string   `json:"status"`
	RevokedBy          []string `json:"revoked_by"`
	TaintedByAncestors []string `json:"tainted_by_ancestors"`
	UnresolvedParents  []string `json:"unresolved_parents"`
}

// ConflictSet captures explicit competing claims on a (domain, claim_key) slot.
type ConflictSet struct {
	Slot              string   `json:"slot"`
	Domain            string   `json:"domain"`
	ClaimKey          string   `json:"claim_key"`
	Status            string   `json:"status"`
	CompetingEventIDs []string `json:"competing_event_ids"`
	FlagIDs           []string `json:"flag_ids"`
	ResolutionIDs     []string `json:"resolution_ids"`
	CanonicalEventID  string   `json:"canonical_event_id"`
}

// RejectedEvent records a deterministically rejected event and reason code.
type RejectedEvent struct {
	EventID   string `json:"event_id"`
	EventType string `json:"event_type"`
	ErrorCode string `json:"error_code"`
}

// StateCommitment is the canonical hash-committed projection of reconstructed state.
type StateCommitment struct {
	SchemaVersion      string          `json:"schema_version"`
	PolicySHA256       string          `json:"policy_sha256"`
	ActiveMerkleRoot   string          `json:"active_merkle_root"`
	EntryStates        []EntryState    `json:"entry_states"`
	Conflicts          []ConflictSet   `json:"conflicts"`
	PendingRevocations []string        `json:"pending_revocations"`
	RejectedEvents     []RejectedEvent `json:"rejected_events"`
}

// ReconstructedState is the complete output of Replay.
type ReconstructedState struct {
	StateRootHash   string          `json:"state_root_hash"`
	Commitment      StateCommitment `json:"commitment"`
	ActiveEventIDs  []string        `json:"active_event_ids"`
	TotalInputCount int             `json:"total_input_count"`
	UniqueAccepted  int             `json:"unique_accepted"`
	DuplicateCount  int             `json:"duplicate_count"`
}

// CheckpointSnapshot persists verified event state in VFS/S3 for bounded-latency incremental replay.
type CheckpointSnapshot struct {
	SchemaVersion   string          `json:"schema_version"`
	PolicySHA256    string          `json:"policy_sha256"`
	StateRootHash   string          `json:"state_root_hash"`
	Commitment      StateCommitment `json:"commitment"`
	IncludedEvents  []Event         `json:"included_events"`
	CheckpointHash  string          `json:"checkpoint_hash"`
	CheckpointURI   string          `json:"checkpoint_uri"`
}

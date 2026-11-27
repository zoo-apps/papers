// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

// Package feda2a implements the federated-a2a.v1 reference protocol for
// cross-organizational AI agent research exchange over Apache-2.0 A2A
// (AgentCard + JSON-RPC 2.0 Tasks/Artifacts/SSE) with strict credential
// and private-memory isolation boundaries (zoo-apps/papers#4, HIP-1352).
package feda2a

const (
	SchemaVersion  = "federated-a2a.v1"
	SpecVersion    = "1.0.0"
	A2AProtocolVer = "a2a/0.2+federated-a2a.v1"
	MicroScale     = int64(1_000_000)
	BpsScale       = int64(10_000)
	BaseEpochSec   = int64(1764201600) // 2025-11-27T00:00:00Z deterministic clock base
	EnvelopeTTLSec = int64(300)        // 5-minute envelope validity window
	DefaultSeed    = int64(1352)       // HIP-1352 canonical benchmark seed
)

// Domain separation prefixes for SHA-256 hashing and Ed25519 signing.
const (
	DomainAgentCard        = "federated-a2a.v1:agent_card"
	DomainOrgPolicy        = "federated-a2a.v1:org_policy"
	DomainEnvelope         = "federated-a2a.v1:envelope"
	DomainCommitment       = "federated-a2a.v1:commitment"
	DomainResultArtifact   = "federated-a2a.v1:result_artifact"
	DomainTaskReceipt      = "federated-a2a.v1:task_receipt"
	DomainEgressBlock      = "federated-a2a.v1:egress_block"
	DomainGovernanceAction = "federated-a2a.v1:governance_action"
	DomainAdvisory         = "federated-a2a.v1:advisory"
	DomainAcceptance       = "federated-a2a.v1:acceptance"
	DomainWireFrame        = "federated-a2a.v1:wire_frame"
	DomainAuditLeaf        = "federated-a2a.v1:audit_leaf"
)

// Principal roles within an organization.
const (
	RoleOrgGateway    = "ORG_GATEWAY"
	RoleHumanReviewer = "HUMAN_REVIEWER"
	RoleCouncilMember = "COUNCIL_MEMBER"
	RoleAIAgent       = "AI_AGENT"
)

// Memory / artifact access tiers.
const (
	TierPublicArtifact    = "public_artifact"
	TierSharedExchange    = "shared_exchange"
	TierPrivateMemory     = "private_memory"
	TierRestrictedPII     = "restricted_pii"
	TierRawReasoningTrace = "raw_reasoning_trace"
)

// A2A task lifecycle states.
const (
	TaskStateSubmitted = "submitted"
	TaskStateWorking   = "working"
	TaskStateCompleted = "completed"
	TaskStateFailed    = "failed"
	TaskStateRejected  = "rejected"
	TaskStateCanceled  = "canceled"
)

// Research skills exposed over A2A.
const (
	SkillZHLCompare   = "research.zhl_compare"
	SkillZHLCorrelate = "research.zhl_correlate"
	SkillReproAudit   = "research.reproducibility_audit"
)

// Forbidden cross-org or AI-agent scopes.
const (
	ScopeTreasurySpend     = "treasury_spend"
	ScopeGovernanceRuleChg = "governance_rule_change"
	ScopeCredentialRead    = "credential_read"
	ScopePrivateMemoryDump = "private_memory_dump"
)

// Canonical verification & rejection error codes (Go == Python).
const (
	CodeOK                        = "OK"
	CodeCredentialLeakDetected    = "ERR_CREDENTIAL_LEAK_DETECTED"
	CodePrivateMemoryLeak         = "ERR_PRIVATE_MEMORY_LEAK"
	CodeRawTraceLeak              = "ERR_RAW_TRACE_LEAK"
	CodePrivateMemoryRefForbidden = "ERR_PRIVATE_MEMORY_REF_FORBIDDEN"
	CodeEncodedSecretLeak         = "ERR_ENCODED_SECRET_LEAK"
	CodeAgentCardSigInvalid       = "ERR_AGENT_CARD_SIG_INVALID"
	CodeAgentCardCredLeak         = "ERR_AGENT_CARD_CRED_LEAK"
	CodeEnvelopeSigInvalid        = "ERR_ENVELOPE_SIG_INVALID"
	CodeSpoofedOrgIdentity        = "ERR_SPOOFED_ORG_IDENTITY"
	CodeAudienceMismatch          = "ERR_AUDIENCE_MISMATCH"
	CodeEnvelopeExpired           = "ERR_ENVELOPE_EXPIRED"
	CodeNonceReplay               = "ERR_NONCE_REPLAY"
	CodeScopeEscalation           = "ERR_SCOPE_ESCALATION"
	CodeAIVotingRuleForbidden     = "ERR_AI_VOTING_RULE_FORBIDDEN"
	CodeAITreasuryForbidden       = "ERR_AI_TREASURY_FORBIDDEN"
	CodeAISelfCertifyForbidden    = "ERR_AI_SELF_CERTIFY_FORBIDDEN"
	CodeResultRecomputeMismatch   = "ERR_RESULT_RECOMPUTE_MISMATCH"
	CodeLicenseUnreviewed         = "ERR_LICENSE_UNREVIEWED"
	CodeEgressCredentialBlocked   = "ERR_EGRESS_CREDENTIAL_BLOCKED"
	CodeEgressMemoryBlocked       = "ERR_EGRESS_MEMORY_BLOCKED"
	CodeReceiptSigInvalid         = "ERR_RECEIPT_SIG_INVALID"
	CodeTaskStateInvalid          = "ERR_TASK_STATE_INVALID"
)

// Principal identifies an Ed25519-authenticated actor within a single organization.
type Principal struct {
	ID           string `json:"id"`
	OrgID        string `json:"org_id"`
	Role         string `json:"role"`
	PublicKeyHex string `json:"public_key_hex"`
}

// A2ASkill describes a research capability advertised in an AgentCard.
type A2ASkill struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	AllowedTiers    []string `json:"allowed_tiers"`
	Deterministic   bool     `json:"deterministic"`
	MaxPayloadBytes int64    `json:"max_payload_bytes"`
}

// A2ACapabilities mirrors the Apache-2.0 A2A AgentCard capabilities block.
type A2ACapabilities struct {
	Streaming              bool `json:"streaming"`
	PushNotifications      bool `json:"push_notifications"`
	StateTransitionHistory bool `json:"state_transition_history"`
}

// OrgGovernancePolicy declares the constitutional rules and license whitelist
// of an independently administered organization.
type OrgGovernancePolicy struct {
	OrgID                    string      `json:"org_id"`
	PolicyVersion            string      `json:"policy_version"`
	AllowedSkills            []string    `json:"allowed_skills"`
	AllowedLicenses          []string    `json:"allowed_licenses"`
	AllowedExchangeTiers     []string    `json:"allowed_exchange_tiers"`
	DeniedScopes             []string    `json:"denied_scopes"`
	AIAgentCanRedefineVoting bool        `json:"ai_agent_can_redefine_voting"`
	AIAgentCanAuthorizeSpend bool        `json:"ai_agent_can_authorize_spend"`
	AIAgentCanSelfCertify    bool        `json:"ai_agent_can_self_certify"`
	Principals               []Principal `json:"principals"`
	PolicyHash               string      `json:"policy_hash"`
}

// BoundaryCommitment commits to an organization's isolated credential store and
// private memory vault via RFC 6962 Merkle roots without exposing any secret bytes.
type BoundaryCommitment struct {
	OrgID                  string `json:"org_id"`
	CredentialCount        int64  `json:"credential_count"`
	CredentialVaultRoot    string `json:"credential_vault_root"`
	PrivateMemoryCount     int64  `json:"private_memory_count"`
	PrivateMemoryVaultRoot string `json:"private_memory_vault_root"`
	RawTraceCount          int64  `json:"raw_trace_count"`
	RawTraceVaultRoot      string `json:"raw_trace_vault_root"`
	EgressFirewallEnforced bool   `json:"egress_firewall_enforced"`
}

// AgentCard is the signed Apache-2.0 A2A discovery document served at
// GET /.well-known/agent.json. It MUST NEVER contain internal credentials or
// private memory records.
type AgentCard struct {
	SchemaVersion      string             `json:"schema_version"`
	ProtocolVersion    string             `json:"protocol_version"`
	OrgID              string             `json:"org_id"`
	Name               string             `json:"name"`
	Description        string             `json:"description"`
	LogicalURL         string             `json:"logical_url"`
	GatewayPrincipal   Principal          `json:"gateway_principal"`
	Capabilities       A2ACapabilities    `json:"capabilities"`
	Skills             []A2ASkill         `json:"skills"`
	PolicyDigest       string             `json:"policy_digest"`
	BoundaryCommitment BoundaryCommitment `json:"boundary_commitment"`
	CardHash           string             `json:"card_hash"`
	OrgSignatureHex    string             `json:"org_signature_hex"`
}

// LicenseAttachment tracks explicit license review status for any dataset,
// trace, or external artifact exchanged across organizational boundaries.
type LicenseAttachment struct {
	ArtifactID      string `json:"artifact_id"`
	ArtifactKind    string `json:"artifact_kind"` // "dataset", "code", "artifact", "reasoning_trace"
	LicenseID       string `json:"license_id"`
	LicenseReviewed bool   `json:"license_reviewed"`
	ReviewerID      string `json:"reviewer_id"`
}

// ExperimentCommitment binds a ZooCoord ZHL research task to its hypothesis,
// deterministic method, and content-addressed public/shared input data.
type ExperimentCommitment struct {
	CommitmentID    string   `json:"commitment_id"`
	ZHLTemplate     string   `json:"zhl_template"` // "COMPARE" or "CORRELATE"
	Hypothesis      string   `json:"hypothesis"`
	AlphaBps        int64    `json:"alpha_bps"`
	MinEffectMicro  int64    `json:"min_effect_micro"`
	InputTier       string   `json:"input_tier"`
	InputRecordRefs []string `json:"input_record_refs"`
	GroupAMicro     []int64  `json:"group_a_micro"`
	GroupBMicro     []int64  `json:"group_b_micro"`
	CommitmentHash  string   `json:"commitment_hash"`
}

// TaskPayload is the domain payload carried inside a signed A2A envelope.
type TaskPayload struct {
	TaskID          string               `json:"task_id"`
	SkillID         string               `json:"skill_id"`
	PromptNote      string               `json:"prompt_note"`
	ActorID         string               `json:"actor_id"`
	ActorRole       string               `json:"actor_role"`
	SelfCertified   bool                 `json:"self_certified"`
	DeferCompletion bool                 `json:"defer_completion"`
	Commitment      ExperimentCommitment `json:"commitment"`
	Licenses        []LicenseAttachment  `json:"licenses"`
}

// SignedA2AEnvelope wraps a cross-org A2A task or cancellation request with
// explicit audience, expiry, nonce, scope, and Ed25519 authenticity.
type SignedA2AEnvelope struct {
	EnvelopeID    string      `json:"envelope_id"`
	Method        string      `json:"method"` // "tasks/send", "tasks/sendSubscribe", "tasks/get", "tasks/cancel"
	SenderOrgID   string      `json:"sender_org_id"`
	AudienceOrgID string      `json:"audience_org_id"`
	SignerID      string      `json:"signer_id"`
	Scope         string      `json:"scope"`
	TaskNonce     string      `json:"task_nonce"`
	IssuedAt      int64       `json:"issued_at"`
	ExpiresAt     int64       `json:"expires_at"`
	Payload       TaskPayload `json:"payload"`
	EnvelopeHash  string      `json:"envelope_hash"`
	OrgSigHex     string      `json:"org_sig_hex"`
}

// ScientificResult holds the exact 64-bit fixed-point output of a deterministic
// ZooCoord ZHL computation so the requesting org can independently recompute it.
type ScientificResult struct {
	TaskID          string `json:"task_id"`
	CommitmentHash  string `json:"commitment_hash"`
	ZHLTemplate     string `json:"zhl_template"`
	SampleCount     int64  `json:"sample_count"`
	MeanAMicro      int64  `json:"mean_a_micro"`
	MeanBMicro      int64  `json:"mean_b_micro"`
	VarAMicro       int64  `json:"var_a_micro"`
	VarBMicro       int64  `json:"var_b_micro"`
	EffectSizeMicro int64  `json:"effect_size_micro"` // COMPARE: mean_b - mean_a; CORRELATE: Pearson r * 1e6
	StatMicro       int64  `json:"stat_micro"`        // COMPARE: scaled Welch t * 1e6; CORRELATE: |r| * 1e6
	Significant     bool   `json:"significant"`
	OutputTier      string `json:"output_tier"`
	SummaryNote     string `json:"summary_note"`
	ResultHash      string `json:"result_hash"`
}

// StateTransition records a timestamped A2A task lifecycle step.
type StateTransition struct {
	State     string `json:"state"`
	Timestamp int64  `json:"timestamp"`
	Note      string `json:"note"`
}

// EgressBlockEvent records a fail-closed Egress Boundary Firewall intervention.
type EgressBlockEvent struct {
	EventID       string `json:"event_id"`
	OrgID         string `json:"org_id"`
	TaskID        string `json:"task_id"`
	Timestamp     int64  `json:"timestamp"`
	ReasonCode    string `json:"reason_code"`
	BlockedClass  string `json:"blocked_class"`  // "credential", "private_memory", "raw_reasoning_trace", "encoded_secret"
	BlockedDigest string `json:"blocked_digest"` // SHA-256 of blocked payload (never plaintext!)
	BytesBlocked  int64  `json:"bytes_blocked"`
	WireBytesSent int64  `json:"wire_bytes_sent"`
	EventSigHex   string `json:"event_sig_hex"`
}

// TaskResultReceipt is the signed A2A response artifact returned by the
// executing organization after passing its Egress Boundary Firewall.
type TaskResultReceipt struct {
	ReceiptID         string            `json:"receipt_id"`
	TaskID            string            `json:"task_id"`
	ExecutorOrgID     string            `json:"executor_org_id"`
	RequesterOrgID    string            `json:"requester_org_id"`
	SignerID          string            `json:"signer_id"`
	State             string            `json:"state"`
	ErrorCode         string            `json:"error_code"`
	CompletedAt       int64             `json:"completed_at"`
	Transitions       []StateTransition `json:"transitions"`
	Result            *ScientificResult `json:"result,omitempty"`
	EgressBlock       *EgressBlockEvent `json:"egress_block,omitempty"`
	EgressAuditPassed bool              `json:"egress_audit_passed"`
	ReceiptHash       string            `json:"receipt_hash"`
	ExecutorSigHex    string            `json:"executor_sig_hex"`
}

// AdvisoryAssessment is a non-binding recommendation created by an AI_AGENT.
type AdvisoryAssessment struct {
	AdvisoryID        string   `json:"advisory_id"`
	OrgID             string   `json:"org_id"`
	AgentID           string   `json:"agent_id"`
	TaskID            string   `json:"task_id"`
	Binding           bool     `json:"binding"` // MUST be false
	Recommendation    string   `json:"recommendation"`
	EstimatedValueBps int64    `json:"estimated_value_bps"`
	ConflictFlags     []string `json:"conflict_flags"`
	SignatureHex      string   `json:"signature_hex"`
}

// ExperimentAcceptance is an authoritative acceptance record signed by an
// authorized HUMAN_REVIEWER or COUNCIL_MEMBER after independent recomputation.
type ExperimentAcceptance struct {
	AcceptanceID     string `json:"acceptance_id"`
	OrgID            string `json:"org_id"`
	TaskID           string `json:"task_id"`
	ReceiptHash      string `json:"receipt_hash"`
	RecomputedHash   string `json:"recomputed_hash"`
	ReviewerID       string `json:"reviewer_id"`
	ReviewerRole     string `json:"reviewer_role"`
	AcceptedAt       int64  `json:"accepted_at"`
	AdvisoryRefID    string `json:"advisory_ref_id"`
	AcceptanceSigHex string `json:"acceptance_sig_hex"`
}

// GovernanceAction represents a privileged governance or treasury decision.
type GovernanceAction struct {
	ActionID     string `json:"action_id"`
	OrgID        string `json:"org_id"`
	ActionType   string `json:"action_type"` // "voting_rule_change", "treasury_spend", "policy_update"
	ProposerID   string `json:"proposer_id"`
	ProposerRole string `json:"proposer_role"`
	AmountMicro  int64  `json:"amount_micro"`
	Summary      string `json:"summary"`
	SignatureHex string `json:"signature_hex"`
}

// JSON-RPC 2.0 wire types for live A2A HTTP transport.
type JSONRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      string        `json:"id"`
	Result  any           `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

// WireFrame captures the exact HTTP request and response payload bytes exchanged
// between the two live loopback deployments for independent offline audit.
type WireFrame struct {
	FrameID        string `json:"frame_id"`
	Stage          string `json:"stage"`
	FromOrgID      string `json:"from_org_id"`
	ToOrgID        string `json:"to_org_id"`
	HTTPMethod     string `json:"http_method"`
	Path           string `json:"path"`
	ContentType    string `json:"content_type"`
	HTTPStatus     int64  `json:"http_status"`
	RequestBody    string `json:"request_body"`
	ResponseBody   string `json:"response_body"`
	RequestSHA256  string `json:"request_sha256"`
	ResponseSHA256 string `json:"response_sha256"`
	RequestBytes   int64  `json:"request_bytes"`
	ResponseBytes  int64  `json:"response_bytes"`
}

// BoundaryProbeSpec holds synthetic test-fixture probes strictly for offline
// zero-leak verification over the captured wire transcript.
type BoundaryProbeSpec struct {
	OrgID               string   `json:"org_id"`
	CredentialProbes    []string `json:"credential_probes"`
	PrivateMemoryProbes []string `json:"private_memory_probes"`
	PrivateMemoryRefIDs []string `json:"private_memory_ref_ids"`
	RawTraceProbes      []string `json:"raw_trace_probes"`
}

// LiveExchangeStage bundles one live two-deployment workflow step.
type LiveExchangeStage struct {
	Stage             string                `json:"stage"`
	Description       string                `json:"description"`
	VerifiedAt        int64                 `json:"verified_at"`
	Envelope          *SignedA2AEnvelope    `json:"envelope,omitempty"`
	Receipt           *TaskResultReceipt    `json:"receipt,omitempty"`
	Advisory          *AdvisoryAssessment   `json:"advisory,omitempty"`
	Acceptance        *ExperimentAcceptance `json:"acceptance,omitempty"`
	ExpectedState     string                `json:"expected_state"`
	ExpectedErrorCode string                `json:"expected_error_code"`
	WireFrameIDs      []string              `json:"wire_frame_ids"`
}

// AdversarialCase defines one deterministic security/constitutional test case.
type AdversarialCase struct {
	CaseID           string                `json:"case_id"`
	Category         string                `json:"category"`
	Target           string                `json:"target"` // "agent_card", "envelope", "receipt", "governance", "advisory"
	Description      string                `json:"description"`
	VerifiedAt       int64                 `json:"verified_at"`
	ExpectedValid    bool                  `json:"expected_valid"`
	ExpectedCode     string                `json:"expected_code"`
	ReceiverOrgID    string                `json:"receiver_org_id,omitempty"`
	PriorNonces      []string              `json:"prior_nonces,omitempty"`
	AgentCard        *AgentCard            `json:"agent_card,omitempty"`
	Envelope         *SignedA2AEnvelope    `json:"envelope,omitempty"`
	Receipt          *TaskResultReceipt    `json:"receipt,omitempty"`
	Acceptance       *ExperimentAcceptance `json:"acceptance,omitempty"`
	GovernanceAction *GovernanceAction     `json:"governance_action,omitempty"`
	Advisory         *AdvisoryAssessment   `json:"advisory,omitempty"`
}

// ExchangeSuite is the canonical serialized fixture (fixtures/a2a-exchange-suite.v1.json).
type ExchangeSuite struct {
	SchemaVersion  string                `json:"schema_version"`
	SpecVersion    string                `json:"spec_version"`
	Seed           int64                 `json:"seed"`
	GeneratedFrom  string                `json:"generated_from"`
	OrgPolicies    []OrgGovernancePolicy `json:"org_policies"`
	AgentCards     []AgentCard           `json:"agent_cards"`
	BoundaryProbes []BoundaryProbeSpec   `json:"boundary_probes"`
	WireTranscript []WireFrame           `json:"wire_transcript"`
	LiveStages     []LiveExchangeStage   `json:"live_stages"`
	Adversarial    []AdversarialCase     `json:"adversarial_cases"`
}

// Verification outcomes (exact schema shared bit-for-bit by Go and Python).

type StageOutcome struct {
	Stage               string `json:"stage"`
	Valid               bool   `json:"valid"`
	Code                string `json:"code"`
	TaskState           string `json:"task_state"`
	WireFramesChecked   int64  `json:"wire_frames_checked"`
	CredentialLeakBytes int64  `json:"credential_leak_bytes"`
	PrivateMemLeakBytes int64  `json:"private_memory_leak_bytes"`
	RawTraceLeakBytes   int64  `json:"raw_trace_leak_bytes"`
	RecomputeVerified   bool   `json:"recompute_verified"`
}

type AdversarialOutcome struct {
	CaseID        string `json:"case_id"`
	Category      string `json:"category"`
	ExpectedValid bool   `json:"expected_valid"`
	ActualValid   bool   `json:"actual_valid"`
	ExpectedCode  string `json:"expected_code"`
	ActualCode    string `json:"actual_code"`
	Matched       bool   `json:"matched"`
}

type WireAuditSummary struct {
	TotalFrames            int64  `json:"total_frames"`
	TotalWireBytes         int64  `json:"total_wire_bytes"`
	CredentialLeakBytes    int64  `json:"credential_leak_bytes"`
	PrivateMemoryLeakBytes int64  `json:"private_memory_leak_bytes"`
	RawTraceLeakBytes      int64  `json:"raw_trace_leak_bytes"`
	WireTranscriptRoot     string `json:"wire_transcript_root"`
	AllFrameHashesValid    bool   `json:"all_frame_hashes_valid"`
	ZeroBoundaryLeakage    bool   `json:"zero_boundary_leakage"`
}

type VerificationReport struct {
	SchemaVersion      string               `json:"schema_version"`
	SpecVersion        string               `json:"spec_version"`
	Seed               int64                `json:"seed"`
	AllStagesValid     bool                 `json:"all_stages_valid"`
	AllAdversarialPass bool                 `json:"all_adversarial_pass"`
	AttacksDetected    int64                `json:"attacks_detected"`
	AttacksTotal       int64                `json:"attacks_total"`
	PositiveCasesPass  int64                `json:"positive_cases_pass"`
	WireAudit          WireAuditSummary     `json:"wire_audit"`
	StageOutcomes      []StageOutcome       `json:"stage_outcomes"`
	AdversarialResults []AdversarialOutcome `json:"adversarial_results"`
	AuditMerkleRoot    string               `json:"audit_merkle_root"`
}

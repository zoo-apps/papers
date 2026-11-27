// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package forkorg

// Protocol constants for forkable-org.v1 (HIP-1352, zoo-apps/papers#5).
const (
	SchemaVersion = "forkable-org.v1"
	SpecVersion   = "1.0.0"

	MicroScale = int64(1_000_000)
	BpsScale   = int64(10_000)

	// Domain separation prefixes for SHA-256 hashing and Ed25519 signing.
	DomainModelBase        = "forkable-org.v1:base-model"
	DomainBitDelta         = "forkable-org.v1:bitdelta"
	DomainDeltaSoup        = "forkable-org.v1:deltasoup"
	DomainResearchRecord   = "forkable-org.v1:research-record"
	DomainRedaction        = "forkable-org.v1:redaction-tombstone"
	DomainPolicyManifest   = "forkable-org.v1:policy-manifest"
	DomainACLPolicy        = "forkable-org.v1:acl-policy"
	DomainGovernanceAction = "forkable-org.v1:governance-action"
	DomainAdvisoryProposal = "forkable-org.v1:advisory-proposal"
	DomainEvalReceipt      = "forkable-org.v1:eval-receipt"
	DomainEvalDataset      = "forkable-org.v1:eval-dataset"
	DomainOrgSnapshot      = "forkable-org.v1:org-snapshot"
	DomainForkAttestation  = "forkable-org.v1:fork-attestation"
	DomainExchangeBundle   = "forkable-org.v1:exchange-bundle"
	DomainAdoptionResult   = "forkable-org.v1:adoption-result"
	DomainAuditLeaf        = "forkable-org.v1:audit-leaf"
)

// Role enumerates principal roles with strict constitutional boundaries.
const (
	RoleHumanCouncil = "HUMAN_COUNCIL"
	RoleEvaluator    = "EVALUATOR"
	RoleTrainer      = "TRAINER"
	RoleAIAgent      = "AI_AGENT"
)

// ACLTier enumerates capability-scoped access control tiers.
const (
	TierPublic     = "public"
	TierInternal   = "org_internal"
	TierRestricted = "restricted_pii_or_partner"
)

// Governance action types.
const (
	ActionUpdateVotingRules      = "update_voting_rules"
	ActionAuthorizeTreasurySpend = "authorize_treasury_spend"
	ActionApproveFork            = "approve_fork"
	ActionApproveAdoption        = "approve_adoption"
	ActionRegisterModel          = "register_model"
)

// Advisory proposal kinds permitted for AI_AGENT principals.
const (
	AdvisoryRecommendAdoption = "recommend_adoption"
	AdvisoryFlagConflict      = "flag_conflict"
	AdvisoryEstimateValue     = "estimate_value"
	AdvisoryPrepareMergePlan  = "prepare_merge_plan"
)

// Normative verification error codes (identical across Go and Python verifiers).
const (
	ErrOK                       = "OK"
	ErrLineageBroken            = "ERR_LINEAGE_BROKEN"
	ErrDeltaHashMismatch        = "ERR_DELTA_HASH_MISMATCH"
	ErrHistoryChainBroken       = "ERR_HISTORY_CHAIN_BROKEN"
	ErrMerkleRootMismatch       = "ERR_MERKLE_ROOT_MISMATCH"
	ErrACLLeakRestricted        = "ERR_ACL_LEAK_RESTRICTED"
	ErrACLLeakGrant             = "ERR_ACL_LEAK_GRANT"
	ErrACLTaintRestricted       = "ERR_ACL_TAINT_RESTRICTED"
	ErrKeyRotationRequired      = "ERR_KEY_ROTATION_REQUIRED"
	ErrCrossOrgReplay           = "ERR_CROSS_ORG_REPLAY"
	ErrUnauthorizedSigner       = "ERR_UNAUTHORIZED_SIGNER"
	ErrInvalidSignature         = "ERR_INVALID_SIGNATURE"
	ErrAIVotingRuleForbidden    = "ERR_AI_VOTING_RULE_FORBIDDEN"
	ErrAITreasuryForbidden      = "ERR_AI_TREASURY_FORBIDDEN"
	ErrAISelfCertifyForbidden   = "ERR_AI_SELF_CERTIFY_FORBIDDEN"
	ErrAIBindingProposalForbid  = "ERR_AI_BINDING_PROPOSAL_FORBIDDEN"
	ErrEvalReplayMismatch       = "ERR_EVAL_REPLAY_MISMATCH"
	ErrQualityRegression        = "ERR_QUALITY_REGRESSION"
	ErrSafetyFloorViolation     = "ERR_SAFETY_FLOOR_VIOLATION"
	ErrLicenseIncompatible      = "ERR_LICENSE_INCOMPATIBLE"
	ErrRedactionProofInvalid    = "ERR_REDACTION_PROOF_INVALID"
	ErrInsufficientQuorum       = "ERR_INSUFFICIENT_QUORUM"
	ErrSnapshotHashMismatch     = "ERR_SNAPSHOT_HASH_MISMATCH"
	ErrPolicyHashMismatch       = "ERR_POLICY_HASH_MISMATCH"
	ErrBundleHashMismatch       = "ERR_BUNDLE_HASH_MISMATCH"
	ErrByzantineThresholdExceed = "ERR_BYZANTINE_THRESHOLD_EXCEEDED"
)

// Principal identifies a cryptographic actor scoped to an organization and role.
type Principal struct {
	ID           string `json:"id"`
	OrgID        string `json:"org_id"`
	Role         string `json:"role"`
	PublicKeyHex string `json:"public_key_hex"`
}

// SignerSignature binds an Ed25519 signature to a principal ID.
type SignerSignature struct {
	SignerID     string `json:"signer_id"`
	SignatureHex string `json:"signature_hex"`
}

// AIAgentBoundaries encodes constitutional limits on AI_AGENT principals.
type AIAgentBoundaries struct {
	ForbidVotingRuleMutation    bool `json:"forbid_voting_rule_mutation"`
	ForbidTreasuryAuthorization bool `json:"forbid_treasury_authorization"`
	ForbidSelfCertifiedExps     bool `json:"forbid_self_certified_experiments"`
	AllowAdvisoryProposals      bool `json:"allow_advisory_proposals"`
}

// PolicyManifest defines constitutional governance rules and authorized principals.
type PolicyManifest struct {
	OrgID                   string            `json:"org_id"`
	PolicyVersion           int64             `json:"policy_version"`
	VotingQuorumBps         int64             `json:"voting_quorum_bps"`
	MinCouncilApprovals     int64             `json:"min_council_approvals"`
	ConservationTitheBps    int64             `json:"conservation_tithe_bps"`
	TreasurySpendLimitMicro int64             `json:"treasury_spend_limit_micro"`
	MinSafetyBps            int64             `json:"min_safety_bps"`
	MinAccuracyGainBps      int64             `json:"min_accuracy_gain_bps"`
	AllowedLicenses         []string          `json:"allowed_licenses"`
	AIAgentBoundaries       AIAgentBoundaries `json:"ai_agent_boundaries"`
	AuthorizedPrincipals    []Principal       `json:"authorized_principals"`
	PolicyHash              string            `json:"policy_hash"`
}

// AccessGrant models a capability-scoped access control entry.
type AccessGrant struct {
	GrantID            string `json:"grant_id"`
	OrgID              string `json:"org_id"`
	SubjectID          string `json:"subject_id"`
	ResourceID         string `json:"resource_id"`
	Tier               string `json:"tier"`
	InheritableOnFork  bool   `json:"inheritable_on_fork"`
	OrgScopedTokenHash string `json:"org_scoped_token_hash"`
}

// DelegationGrant explicitly authorizes cross-org sharing of an org_internal resource.
type DelegationGrant struct {
	DelegationID string `json:"delegation_id"`
	FromOrgID    string `json:"from_org_id"`
	ToOrgID      string `json:"to_org_id"`
	ResourceID   string `json:"resource_id"`
	Tier         string `json:"tier"`
	Revoked      bool   `json:"revoked"`
	SignerID     string `json:"signer_id"`
	SignatureHex string `json:"signature_hex"`
}

// AccessControlPolicy holds capability-scoped ACL grants and fork-redaction rules.
type AccessControlPolicy struct {
	OrgID               string            `json:"org_id"`
	DefaultTier         string            `json:"default_tier"`
	StripTiersOnFork    []string          `json:"strip_tiers_on_fork"`
	RequireKeyRotation  bool              `json:"require_key_rotation"`
	Grants              []AccessGrant     `json:"grants"`
	CrossOrgDelegations []DelegationGrant `json:"cross_org_delegations"`
	ACLPolicyHash       string            `json:"acl_policy_hash"`
}

// RedactionTombstone proves inclusion of a stripped parent record without leaking plaintext.
type RedactionTombstone struct {
	SlotIndex          int64  `json:"slot_index"`
	OriginalLeafHash   string `json:"original_leaf_hash"`
	RedactedTier       string `json:"redacted_tier"`
	RedactionReason    string `json:"redaction_reason"`
	CommitmentSaltHash string `json:"commitment_salt_hash"`
}

// ResearchRecord is a hash-chained research event, dataset ingestion, or evaluation proof.
type ResearchRecord struct {
	RecordID        string `json:"record_id"`
	Seq             int64  `json:"seq"`
	ParentSlotIndex int64  `json:"parent_slot_index"`
	OrgID           string `json:"org_id"`
	PrevHash        string `json:"prev_hash"`
	Kind            string `json:"kind"`
	ACLTier         string `json:"acl_tier"`
	LicenseID       string `json:"license_id"`
	LicenseReviewed bool   `json:"license_reviewed"`
	PayloadSummary  string `json:"payload_summary"`
	PayloadHash     string `json:"payload_hash"`
	AuthorID        string `json:"author_id"`
	SignatureHex    string `json:"signature_hex"`
	RecordHash      string `json:"record_hash"`
}

// ResearchHistory tracks an organization's hash-chained records and fork redaction proofs.
type ResearchHistory struct {
	OrgID               string               `json:"org_id"`
	ParentTotalSlots    int64                `json:"parent_total_slots"`
	InheritedParentRoot string               `json:"inherited_parent_root"`
	Records             []ResearchRecord     `json:"records"`
	RedactionTombstones []RedactionTombstone `json:"redaction_tombstones"`
	ResearchMerkleRoot  string               `json:"research_merkle_root"`
}

// BaseModelSpec is an immutable fixed-point base model weight matrix.
type BaseModelSpec struct {
	ModelID         string  `json:"model_id"`
	Dim             int64   `json:"dim"`
	NumClasses      int64   `json:"num_classes"`
	NumFeatures     int64   `json:"num_features"`
	WeightsMicro    []int64 `json:"weights_micro"`
	LicenseID       string  `json:"license_id"`
	LicenseReviewed bool    `json:"license_reviewed"`
	WeightsHash     string  `json:"weights_hash"`
}

// BitDeltaArtifact is a 1-bit sign matrix + per-tensor scale adapter (BitDelta).
type BitDeltaArtifact struct {
	DeltaID            string   `json:"delta_id"`
	OrgID              string   `json:"org_id"`
	BaseModelID        string   `json:"base_model_id"`
	ParentDeltaID      string   `json:"parent_delta_id"`
	BaseCheckpointHash string   `json:"base_checkpoint_hash"`
	Dim                int64    `json:"dim"`
	SignBitsHex        string   `json:"sign_bits_hex"`
	ScaleMicro         int64    `json:"scale_micro"`
	TrainingRecordIDs  []string `json:"training_record_ids"`
	ACLTier            string   `json:"acl_tier"`
	LicenseID          string   `json:"license_id"`
	LicenseReviewed    bool     `json:"license_reviewed"`
	ContributorID      string   `json:"contributor_id"`
	SignatureHex       string   `json:"signature_hex"`
	DeltaHash          string   `json:"delta_hash"`
}

// RoyaltyShare records a DeltaSoup contributor's basis-point royalty weight.
type RoyaltyShare struct {
	ContributorID string `json:"contributor_id"`
	DeltaHash     string `json:"delta_hash"`
	WeightBps     int64  `json:"weight_bps"`
}

// DeltaSoupArtifact records a Byzantine-robust trimmed-mean + greedy soup merge.
type DeltaSoupArtifact struct {
	SoupID                 string           `json:"soup_id"`
	OrgID                  string           `json:"org_id"`
	BaseModelID            string           `json:"base_model_id"`
	BaseCheckpointHash     string           `json:"base_checkpoint_hash"`
	TrimBps                int64            `json:"trim_bps"`
	StepBps                int64            `json:"step_bps"`
	ContributorDeltaIDs    []string         `json:"contributor_delta_ids"`
	AcceptedContributorIDs []string         `json:"accepted_contributor_ids"`
	RoyaltyShares          []RoyaltyShare   `json:"royalty_shares"`
	ResultDelta            BitDeltaArtifact `json:"result_delta"`
	SoupHash               string           `json:"soup_hash"`
}

// ModelRegistry holds base models, BitDelta adapters, DeltaSoup reference adapters, and active head.
type ModelRegistry struct {
	OrgID             string              `json:"org_id"`
	BaseModel         BaseModelSpec       `json:"base_model"`
	ActiveDeltaID     string              `json:"active_delta_id"`
	Deltas            []BitDeltaArtifact  `json:"deltas"`
	Soups             []DeltaSoupArtifact `json:"soups"`
	ModelRegistryRoot string              `json:"model_registry_root"`
}

// GovernanceAction is a binding governance decision requiring authorized human/council quorum.
type GovernanceAction struct {
	ActionID       string            `json:"action_id"`
	OrgID          string            `json:"org_id"`
	ActionType     string            `json:"action_type"`
	ProposerID     string            `json:"proposer_id"`
	PayloadSummary string            `json:"payload_summary"`
	PayloadHash    string            `json:"payload_hash"`
	AmountMicro    int64             `json:"amount_micro"`
	Epoch          int64             `json:"epoch"`
	Signatures     []SignerSignature `json:"signatures"`
}

// AdvisoryProposal is a non-binding AI_AGENT recommendation, conflict flag, estimate, or plan.
type AdvisoryProposal struct {
	ProposalID       string   `json:"proposal_id"`
	OrgID            string   `json:"org_id"`
	AgentID          string   `json:"agent_id"`
	Kind             string   `json:"kind"`
	TargetRef        string   `json:"target_ref"`
	EstimatedGainBps int64    `json:"estimated_gain_bps"`
	ConflictFlags    []string `json:"conflict_flags"`
	Summary          string   `json:"summary"`
	Binding          bool     `json:"binding"`
	SignatureHex     string   `json:"signature_hex"`
}

// EvaluationReceipt is an independently signed deterministic benchmark evaluation.
type EvaluationReceipt struct {
	ReceiptID       string `json:"receipt_id"`
	OrgID           string `json:"org_id"`
	ModelRefID      string `json:"model_ref_id"`
	DeltaHash       string `json:"delta_hash"`
	BaseModelHash   string `json:"base_model_hash"`
	EvalDatasetHash string `json:"eval_dataset_hash"`
	AccuracyBps     int64  `json:"accuracy_bps"`
	MeanLossMicro   int64  `json:"mean_loss_micro"`
	SafetyBps       int64  `json:"safety_bps"`
	NumSamples      int64  `json:"num_samples"`
	EvaluatorID     string `json:"evaluator_id"`
	SignatureHex    string `json:"signature_hex"`
}

// ForkAttestation binds a forked child org to its parent checkpoint and redaction count.
type ForkAttestation struct {
	ParentOrgID          string            `json:"parent_org_id"`
	ChildOrgID           string            `json:"child_org_id"`
	ParentSnapshotID     string            `json:"parent_snapshot_id"`
	ParentSnapshotHash   string            `json:"parent_snapshot_hash"`
	RedactedRecordCount  int64             `json:"redacted_record_count"`
	StrippedGrantCount   int64             `json:"stripped_grant_count"`
	KeysRotated          bool              `json:"keys_rotated"`
	ChildAuthorityPubKey string            `json:"child_authority_pub_key"`
	ChildCouncilSigs     []SignerSignature `json:"child_council_sigs"`
}

// OrgSnapshot is the canonical immutable state checkpoint of an organization.
type OrgSnapshot struct {
	SnapshotID               string              `json:"snapshot_id"`
	OrgID                    string              `json:"org_id"`
	Epoch                    int64               `json:"epoch"`
	ParentSnapshotHash       string              `json:"parent_snapshot_hash"`
	ForkAncestorSnapshotHash string              `json:"fork_ancestor_snapshot_hash"`
	ModelRegistry            ModelRegistry       `json:"model_registry"`
	ResearchHistory          ResearchHistory     `json:"research_history"`
	PolicyManifest           PolicyManifest      `json:"policy_manifest"`
	ACLPolicy                AccessControlPolicy `json:"acl_policy"`
	GovernanceActions        []GovernanceAction  `json:"governance_actions"`
	AdvisoryProposals        []AdvisoryProposal  `json:"advisory_proposals"`
	ForkAttestation          *ForkAttestation    `json:"fork_attestation"`
	SnapshotHash             string              `json:"snapshot_hash"`
	CouncilSignatures        []SignerSignature   `json:"council_signatures"`
}

// LineageLink proves a hash-chained checkpoint step from a fork ancestor.
type LineageLink struct {
	SnapshotID         string `json:"snapshot_id"`
	OrgID              string `json:"org_id"`
	Epoch              int64  `json:"epoch"`
	ParentSnapshotHash string `json:"parent_snapshot_hash"`
	SnapshotHash       string `json:"snapshot_hash"`
}

// LicenseEntry pins SPDX license metadata and review status for an artifact.
type LicenseEntry struct {
	ArtifactID      string `json:"artifact_id"`
	ArtifactKind    string `json:"artifact_kind"`
	LicenseID       string `json:"license_id"`
	LicenseReviewed bool   `json:"license_reviewed"`
}

// RedactionAttestation summarizes ACL boundary compliance for a cross-fork export.
type RedactionAttestation struct {
	SourceOrgID         string   `json:"source_org_id"`
	RedactedCount       int64    `json:"redacted_count"`
	RestrictedTaintFree bool     `json:"restricted_taint_free"`
	StrippedTiers       []string `json:"stripped_tiers"`
}

// ExchangeBundle packages a verified improvement for cross-fork adoption.
type ExchangeBundle struct {
	BundleID                 string               `json:"bundle_id"`
	SourceOrgID              string               `json:"source_org_id"`
	TargetOrgID              string               `json:"target_org_id"`
	ForkAncestorSnapshotHash string               `json:"fork_ancestor_snapshot_hash"`
	SourceSnapshotHash       string               `json:"source_snapshot_hash"`
	LineageChain             []LineageLink        `json:"lineage_chain"`
	ExportedDelta            BitDeltaArtifact     `json:"exported_delta"`
	SupportingResearch       []ResearchRecord     `json:"supporting_research"`
	RedactionAttestation     RedactionAttestation `json:"redaction_attestation"`
	LicenseManifest          []LicenseEntry       `json:"license_manifest"`
	EvaluationReceipt        EvaluationReceipt    `json:"evaluation_receipt"`
	MergeStepBps             int64                `json:"merge_step_bps"`
	SourceExportSignatures   []SignerSignature    `json:"source_export_signatures"`
	TargetAdoptionAction     GovernanceAction     `json:"target_adoption_action"`
	BundleHash               string               `json:"bundle_hash"`
}

// EvalSample is a single fixed-point labeled feature vector.
type EvalSample struct {
	FeaturesMicro []int64 `json:"features_micro"`
	Label         int64   `json:"label"`
}

// EvalDataset is the deterministic held-out evaluation and safety probe dataset.
type EvalDataset struct {
	DatasetID    string       `json:"dataset_id"`
	Seed         int64        `json:"seed"`
	NumClasses   int64        `json:"num_classes"`
	NumFeatures  int64        `json:"num_features"`
	Samples      []EvalSample `json:"samples"`
	SafetyProbes []EvalSample `json:"safety_probes"`
	DatasetHash  string       `json:"dataset_hash"`
}

// EvalMetrics holds exact deterministic evaluation metrics.
type EvalMetrics struct {
	AccuracyBps   int64 `json:"accuracy_bps"`
	MeanLossMicro int64 `json:"mean_loss_micro"`
	SafetyBps     int64 `json:"safety_bps"`
	NumSamples    int64 `json:"num_samples"`
}

// AdversarialCase defines a single positive or adversarial verification test case.
type AdversarialCase struct {
	CaseID           string            `json:"case_id"`
	Name             string            `json:"name"`
	Category         string            `json:"category"`
	TargetCheck      string            `json:"target_check"`
	ExpectedValid    bool              `json:"expected_valid"`
	ExpectedCode     string            `json:"expected_code"`
	Snapshot         *OrgSnapshot      `json:"snapshot"`
	ParentSnapshot   *OrgSnapshot      `json:"parent_snapshot"`
	ExchangeBundle   *ExchangeBundle   `json:"exchange_bundle"`
	SourceSnapshot   *OrgSnapshot      `json:"source_snapshot"`
	TargetSnapshot   *OrgSnapshot      `json:"target_snapshot"`
	GovernanceAction *GovernanceAction `json:"governance_action"`
	AdvisoryProposal *AdvisoryProposal `json:"advisory_proposal"`
	PolicyContext    *PolicyManifest   `json:"policy_context"`
}

// ForkExchangeSuite is the complete canonical fixture verified identically by Go and Python.
type ForkExchangeSuite struct {
	SchemaVersion     string            `json:"schema_version"`
	SpecVersion       string            `json:"spec_version"`
	Seed              int64             `json:"seed"`
	EvalDataset       EvalDataset       `json:"eval_dataset"`
	OrgASnap0         OrgSnapshot       `json:"org_a_snap_0"`
	OrgASnap1         OrgSnapshot       `json:"org_a_snap_1"`
	OrgBForkSnap1     OrgSnapshot       `json:"org_b_fork_snap_1"`
	OrgADivergedSnap2 OrgSnapshot       `json:"org_a_diverged_snap_2"`
	OrgBDivergedSnap2 OrgSnapshot       `json:"org_b_diverged_snap_2"`
	BundleBToA        ExchangeBundle    `json:"bundle_b_to_a"`
	BundleAToB        ExchangeBundle    `json:"bundle_a_to_b"`
	OrgAAdoptedSnap3  OrgSnapshot       `json:"org_a_adopted_snap_3"`
	OrgBAdoptedSnap3  OrgSnapshot       `json:"org_b_adopted_snap_3"`
	AdversarialCases  []AdversarialCase `json:"adversarial_cases"`
}

// CaseOutcome is the deterministic verification output for a single check/case.
type CaseOutcome struct {
	CaseID        string `json:"case_id"`
	Category      string `json:"category"`
	ExpectedValid bool   `json:"expected_valid"`
	ActualValid   bool   `json:"actual_valid"`
	ExpectedCode  string `json:"expected_code"`
	ActualCode    string `json:"actual_code"`
	Matched       bool   `json:"matched"`
}

// WorkflowCheckOutcome captures a single end-to-end lifecycle verification stage.
type WorkflowCheckOutcome struct {
	Stage         string `json:"stage"`
	Valid         bool   `json:"valid"`
	Code          string `json:"code"`
	AccuracyBps   int64  `json:"accuracy_bps"`
	MeanLossMicro int64  `json:"mean_loss_micro"`
	SafetyBps     int64  `json:"safety_bps"`
	DeltaGainBps  int64  `json:"delta_gain_bps"`
}

// VerificationReport is the canonical verifier output compared bit-for-bit across Go and Python.
type VerificationReport struct {
	SchemaVersion         string                 `json:"schema_version"`
	SpecVersion           string                 `json:"spec_version"`
	Seed                  int64                  `json:"seed"`
	EvalDatasetHash       string                 `json:"eval_dataset_hash"`
	AllWorkflowPassed     bool                   `json:"all_workflow_passed"`
	AllAdversarialMatched bool                   `json:"all_adversarial_matched"`
	WorkflowChecks        []WorkflowCheckOutcome `json:"workflow_checks"`
	AdversarialOutcomes   []CaseOutcome          `json:"adversarial_outcomes"`
	AdversarialTotal      int64                  `json:"adversarial_total"`
	AdversarialCaught     int64                  `json:"adversarial_caught"`
	AuditMerkleRoot       string                 `json:"audit_merkle_root"`
}

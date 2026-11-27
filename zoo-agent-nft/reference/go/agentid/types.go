// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package agentid

// Schema and protocol identifiers.
const (
	SchemaVersion = "agent-identity-delegation.v1"
	SpecVersion   = "1.0.0"

	// Domain separation tags (domain || 0x00 || CanonicalJSON(payload)).
	DomainDIDDoc      = "zoo.agentid.v1.diddoc"
	DomainKeyRotation = "zoo.agentid.v1.keyrot"
	DomainVC          = "zoo.agentid.v1.vc"
	DomainStatusList  = "zoo.agentid.v1.statuslist"
	DomainRevSnapshot = "zoo.agentid.v1.revsnapshot"
	DomainHolderProof = "zoo.agentid.v1.holderproof"
	DomainAuditLeaf   = "zoo.agentid.v1.auditleaf"

	// Principal types.
	PrincipalHumanCouncil     = "HUMAN_COUNCIL"
	PrincipalOrgController    = "ORG_CONTROLLER"
	PrincipalAIAgent          = "AI_AGENT"
	PrincipalEphemeralSession = "EPHEMERAL_SESSION"

	// Status list encodings.
	EncodingGzipBase64URL = "gzip_base64url"
	EncodingRawBase64URL  = "raw_base64url"

	// Presentation freshness bounds (seconds).
	HolderProofMaxPastSkew   int64 = 300
	HolderProofMaxFutureSkew int64 = 30
)

// Reserved human-only governance capabilities (HIP-1352 constitutional boundary).
// AI_AGENT and EPHEMERAL_SESSION principals MUST NOT hold, delegate, or exercise these.
var ReservedGovernanceScopes = map[string]bool{
	"governance:vote_rules": true,
	"treasury:authorize":    true,
	"experiment:certify":    true,
}

// Allowed AI advisory / execution scopes.
var AllowedAgentScopes = map[string]bool{
	"research:recommend":     true,
	"research:execute_eval":  true,
	"plan:prepare":           true,
	"conflict:flag":          true,
	"value:estimate":         true,
	"artifact:read":          true,
	"artifact:publish_draft": true,
}

// Canonical fail-closed error codes (identical across Go and Python verifiers).
const (
	ErrDIDInvalidFormat                 = "ERR_DID_INVALID_FORMAT"
	ErrDIDKeyBindingMismatch            = "ERR_DID_KEY_BINDING_MISMATCH"
	ErrDIDSignatureInvalid              = "ERR_DID_SIGNATURE_INVALID"
	ErrDIDNotFound                      = "ERR_DID_NOT_FOUND"
	ErrKeyNotFound                      = "ERR_KEY_NOT_FOUND"
	ErrKeyRotationInvalid               = "ERR_KEY_ROTATION_INVALID"
	ErrChainEmpty                       = "ERR_CHAIN_EMPTY"
	ErrUntrustedRoot                    = "ERR_UNTRUSTED_ROOT"
	ErrChainLinkBroken                  = "ERR_CHAIN_LINK_BROKEN"
	ErrParentDigestMismatch             = "ERR_PARENT_DIGEST_MISMATCH"
	ErrCyclicDelegation                 = "ERR_CYCLIC_DELEGATION"
	ErrVCSignatureInvalid               = "ERR_VC_SIGNATURE_INVALID"
	ErrDepthOverflow                    = "ERR_DEPTH_OVERFLOW"
	ErrScopeEscalation                  = "ERR_SCOPE_ESCALATION"
	ErrResourceEscalation               = "ERR_RESOURCE_ESCALATION"
	ErrConstraintEscalation             = "ERR_CONSTRAINT_ESCALATION"
	ErrTTLExtension                     = "ERR_TTL_EXTENSION"
	ErrVCExpired                        = "ERR_VC_EXPIRED"
	ErrVCNotYetValid                    = "ERR_VC_NOT_YET_VALID"
	ErrAudienceMismatch                 = "ERR_AUDIENCE_MISMATCH"
	ErrConstitutionalAIGovForbidden     = "ERR_CONSTITUTIONAL_AI_GOVERNANCE_FORBIDDEN"
	ErrStatusListMissing                = "ERR_STATUS_LIST_MISSING"
	ErrStatusListSignatureInvalid       = "ERR_STATUS_LIST_SIGNATURE_INVALID"
	ErrStatusListStale                  = "ERR_STATUS_LIST_STALE"
	ErrStatusListDigestMismatch         = "ERR_STATUS_LIST_DIGEST_MISMATCH"
	ErrStatusListIndexOutOfBounds       = "ERR_STATUS_LIST_INDEX_OUT_OF_BOUNDS"
	ErrRevocationSnapshotSignature      = "ERR_REVOCATION_SNAPSHOT_SIGNATURE_INVALID"
	ErrRevocationSnapshotStale          = "ERR_REVOCATION_SNAPSHOT_STALE"
	ErrRevocationSnapshotMerkleMismatch = "ERR_REVOCATION_SNAPSHOT_MERKLE_MISMATCH"
	ErrVCRevokedBitstring               = "ERR_VC_REVOKED_BITSTRING"
	ErrCascadeParentRevoked             = "ERR_CASCADE_PARENT_REVOKED"
	ErrKeyRevokedBeforeCutoff           = "ERR_KEY_REVOKED_BEFORE_CUTOFF"
	ErrKeyCompromisedRevoked            = "ERR_KEY_COMPROMISED_REVOKED"
	ErrHolderProofMissing               = "ERR_HOLDER_PROOF_MISSING"
	ErrHolderDIDMismatch                = "ERR_HOLDER_DID_MISMATCH"
	ErrHolderBindingMismatch            = "ERR_HOLDER_BINDING_MISMATCH"
	ErrHolderSignatureInvalid           = "ERR_HOLDER_SIGNATURE_INVALID"
	ErrHolderProofStale                 = "ERR_HOLDER_PROOF_STALE"
	ErrNonceReplay                      = "ERR_NONCE_REPLAY"
	ErrActionScopeDenied                = "ERR_ACTION_SCOPE_DENIED"
	ErrActionResourceDenied             = "ERR_ACTION_RESOURCE_DENIED"
)

// DataIntegrityProof represents a W3C Data Integrity EdDSA proof.
type DataIntegrityProof struct {
	Type               string `json:"type"`
	Cryptosuite        string `json:"cryptosuite"`
	VerificationMethod string `json:"verification_method"`
	Created            int64  `json:"created"`
	SignatureB64       string `json:"signature_b64"`
}

// VerificationMethod represents an Ed25519 key in a portable DID document.
type VerificationMethod struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Controller   string `json:"controller"`
	PublicKeyB64 string `json:"public_key_b64"`
	ValidFrom    int64  `json:"valid_from"`
	ValidUntil   int64  `json:"valid_until"`
}

// KeyRotationProof cryptographically links an outgoing key to a new key,
// co-signed by both the outgoing key and the identity's controller.
type KeyRotationProof struct {
	DID              string `json:"did"`
	FromKeyID        string `json:"from_key_id"`
	ToKeyID          string `json:"to_key_id"`
	NewPublicKeyB64  string `json:"new_public_key_b64"`
	RotatedAt        int64  `json:"rotated_at"`
	Reason           string `json:"reason"`
	OutgoingSigB64   string `json:"outgoing_sig_b64"`
	ControllerKeyID  string `json:"controller_key_id"`
	ControllerSigB64 string `json:"controller_sig_b64"`
}

// AutonomyBounds mirrors Zoo Agent NFT paper AutonomyParams for offline auditing.
type AutonomyBounds struct {
	MaxTxValueWei      string `json:"max_tx_value_wei"`
	DailySpendLimitWei string `json:"daily_spend_limit_wei"`
	CooldownSeconds    int64  `json:"cooldown_seconds"`
	CapabilityBitmap   string `json:"capability_bitmap_hex"`
}

// AgentNFTBinding links a portable DID to its optional Zoo Agent NFT / ERC-6551 TBA lineage.
type AgentNFTBinding struct {
	ChainID              int64          `json:"chain_id"`
	NFTContract          string         `json:"nft_contract"`
	TokenID              string         `json:"token_id"`
	TBAWalletAddress     string         `json:"tba_wallet_address"`
	ModelHashSHA256      string         `json:"model_hash_sha256"`
	MetadataURI          string         `json:"metadata_uri"`
	AutonomyBounds       AutonomyBounds `json:"autonomy_bounds"`
	PortableExportDigest string         `json:"portable_export_digest"`
}

// DIDDocument is a self-contained portable W3C DID document (`did:zoo:` or `did:key:`).
type DIDDocument struct {
	Context             []string             `json:"@context"`
	ID                  string               `json:"id"`
	PrincipalType       string               `json:"principal_type"`
	Controller          string               `json:"controller"`
	GenesisKeyID        string               `json:"genesis_key_id"`
	GenesisPublicKeyB64 string               `json:"genesis_public_key_b64"`
	ActiveKeyID         string               `json:"active_key_id"`
	VerificationMethods []VerificationMethod `json:"verification_methods"`
	KeyRotations        []KeyRotationProof   `json:"key_rotations"`
	AgentNFTBinding     *AgentNFTBinding     `json:"agent_nft_binding,omitempty"`
	PortableExport      bool                 `json:"portable_export"`
	Proof               DataIntegrityProof   `json:"proof"`
}

// CredentialStatus references an index in a W3C BitstringStatusListCredential.
type CredentialStatus struct {
	ID                   string `json:"id"`
	Type                 string `json:"type"`
	StatusPurpose        string `json:"status_purpose"`
	StatusListIndex      int    `json:"status_list_index"`
	StatusListCredential string `json:"status_list_credential"`
}

// DelegationConstraints bounds execution rate, budget, and holder-binding requirements.
type DelegationConstraints struct {
	MaxCallsPerHour    int  `json:"max_calls_per_hour"`
	MaxBudgetUSDCents  int  `json:"max_budget_usd_cents"`
	RequireHolderProof bool `json:"require_holder_proof"`
}

// DelegationSubject is the W3C VC v2.0 credentialSubject payload for a delegation hop.
type DelegationSubject struct {
	ID                   string                `json:"id"`
	SubjectPrincipalType string                `json:"subject_principal_type"`
	DelegationDepth      int                   `json:"delegation_depth"`
	MaxSubDepth          int                   `json:"max_sub_depth"`
	ParentVCID           string                `json:"parent_vc_id"`
	ParentVCDigest       string                `json:"parent_vc_digest"`
	Audience             string                `json:"audience"`
	Scopes               []string              `json:"scopes"`
	AllowedResources     []string              `json:"allowed_resources"`
	Constraints          DelegationConstraints `json:"constraints"`
	Nonce                string                `json:"nonce"`
}

// DelegationVC is a W3C Verifiable Credential v2.0 signed delegation hop.
type DelegationVC struct {
	Context           []string           `json:"@context"`
	ID                string             `json:"id"`
	Type              []string           `json:"type"`
	Issuer            string             `json:"issuer"`
	IssuerKeyID       string             `json:"issuer_key_id"`
	ValidFrom         int64              `json:"valid_from"`
	ValidUntil        int64              `json:"valid_until"`
	CredentialStatus  CredentialStatus   `json:"credential_status"`
	CredentialSubject DelegationSubject  `json:"credential_subject"`
	Proof             DataIntegrityProof `json:"proof"`
}

// BitstringStatusListSubject is the W3C BitstringStatusList payload.
type BitstringStatusListSubject struct {
	ID            string `json:"id"`
	Type          string `json:"type"`
	StatusPurpose string `json:"status_purpose"`
	BitLength     int    `json:"bit_length"`
	Encoding      string `json:"encoding"`
	EncodedList   string `json:"encoded_list"`
}

// BitstringStatusListCredential is a W3C Bitstring Status List v1.0 credential.
type BitstringStatusListCredential struct {
	Context           []string                   `json:"@context"`
	ID                string                     `json:"id"`
	Type              []string                   `json:"type"`
	Issuer            string                     `json:"issuer"`
	IssuerKeyID       string                     `json:"issuer_key_id"`
	ValidFrom         int64                      `json:"valid_from"`
	ValidUntil        int64                      `json:"valid_until"`
	CredentialSubject BitstringStatusListSubject `json:"credential_subject"`
	Proof             DataIntegrityProof         `json:"proof"`
}

// KeyRevocationEntry revokes a specific key globally (revoke_all) or cuts off
// all signatures/credentials issued prior to revoked_before.
type KeyRevocationEntry struct {
	DID           string `json:"did"`
	KeyID         string `json:"key_id"`
	RevokedBefore int64  `json:"revoked_before"`
	RevokeAll     bool   `json:"revoke_all"`
	Reason        string `json:"reason"`
}

// StatusListDigestPin pins an expected SHA-256 digest for a status list credential.
type StatusListDigestPin struct {
	StatusListID string `json:"status_list_id"`
	DigestSHA256 string `json:"digest_sha256"`
}

// RevocationSnapshot is a signed offline revocation bundle pinning status lists,
// key compromise cutoffs, and an RFC 6962 CRL Merkle root.
type RevocationSnapshot struct {
	SnapshotID        string                `json:"snapshot_id"`
	Issuer            string                `json:"issuer"`
	IssuerKeyID       string                `json:"issuer_key_id"`
	IssuedAt          int64                 `json:"issued_at"`
	ValidUntil        int64                 `json:"valid_until"`
	StatusListDigests []StatusListDigestPin `json:"status_list_digests"`
	KeyRevocations    []KeyRevocationEntry  `json:"key_revocations"`
	RevokedVCIDs      []string              `json:"revoked_vc_ids"`
	CRLMerkleRoot     string                `json:"crl_merkle_root"`
	Proof             DataIntegrityProof    `json:"proof"`
}

// HolderProof binds an action invocation to the leaf delegate's Ed25519 private key.
type HolderProof struct {
	HolderDID             string `json:"holder_did"`
	HolderKeyID           string `json:"holder_key_id"`
	DelegationChainDigest string `json:"delegation_chain_digest"`
	ChallengeNonce        string `json:"challenge_nonce"`
	Audience              string `json:"audience"`
	ActionVerb            string `json:"action_verb"`
	ResourceURI           string `json:"resource_uri"`
	Timestamp             int64  `json:"timestamp"`
	SignatureB64          string `json:"signature_b64"`
}

// ActionPresentation is a Verifiable Presentation / Action Invocation checked offline.
type ActionPresentation struct {
	PresentationID  string         `json:"presentation_id"`
	EvalTime        int64          `json:"eval_time"`
	Audience        string         `json:"audience"`
	ActionVerb      string         `json:"action_verb"`
	ResourceURI     string         `json:"resource_uri"`
	ChallengeNonce  string         `json:"challenge_nonce"`
	DelegationChain []DelegationVC `json:"delegation_chain"`
	HolderProof     *HolderProof   `json:"holder_proof,omitempty"`
}

// VerificationContext bundles all offline verification inputs (zero network RPCs).
type VerificationContext struct {
	TrustedRootDIDs        []string                        `json:"trusted_root_dids"`
	ExpectedAudience       string                          `json:"expected_audience"`
	UsedNonces             []string                        `json:"used_nonces"`
	DIDDocuments           []DIDDocument                   `json:"did_documents"`
	StatusLists            []BitstringStatusListCredential `json:"status_lists"`
	RevocationSnapshot     RevocationSnapshot              `json:"revocation_snapshot"`
	AllowRootDirectActions bool                            `json:"allow_root_direct_actions"`
}

// StageCase is a positive lifecycle stage verified in the suite.
type StageCase struct {
	StageID      string              `json:"stage_id"`
	Name         string              `json:"name"`
	Description  string              `json:"description"`
	Context      VerificationContext `json:"context"`
	Presentation ActionPresentation  `json:"presentation"`
}

// ThreatCase is an adversarial or positive control test case in the threat-model suite.
type ThreatCase struct {
	CaseID        string              `json:"case_id"`
	Category      string              `json:"category"`
	Name          string              `json:"name"`
	ExpectValid   bool                `json:"expect_valid"`
	ExpectedError string              `json:"expected_error"`
	Context       VerificationContext `json:"context"`
	Presentation  ActionPresentation  `json:"presentation"`
}

// IdentityDelegationSuite is the top-level deterministic fixture file.
type IdentityDelegationSuite struct {
	SchemaVersion string       `json:"schema_version"`
	SpecVersion   string       `json:"spec_version"`
	Seed          int64        `json:"seed"`
	GeneratedAt   int64        `json:"generated_at"`
	Stages        []StageCase  `json:"stages"`
	ThreatCases   []ThreatCase `json:"threat_cases"`
}

// PresentationResult is the deterministic offline verification verdict for a single presentation.
type PresentationResult struct {
	Valid                 bool     `json:"valid"`
	ErrorCode             string   `json:"error_code"`
	ErrorDetail           string   `json:"error_detail"`
	ChainDepth            int      `json:"chain_depth"`
	LeafDID               string   `json:"leaf_did"`
	LeafPrincipalType     string   `json:"leaf_principal_type"`
	RootDID               string   `json:"root_did"`
	DelegationChainDigest string   `json:"delegation_chain_digest"`
	EffectiveScopes       []string `json:"effective_scopes"`
	VerifiedDIDCount      int      `json:"verified_did_count"`
	VerifiedRotations     int      `json:"verified_rotations"`
	SignatureChecks       int      `json:"signature_checks"`
}

// StageReport captures the verification verdict for a positive stage.
type StageReport struct {
	StageID               string `json:"stage_id"`
	Name                  string `json:"name"`
	Valid                 bool   `json:"valid"`
	ErrorCode             string `json:"error_code"`
	ChainDepth            int    `json:"chain_depth"`
	DelegationChainDigest string `json:"delegation_chain_digest"`
	VerifiedRotations     int    `json:"verified_rotations"`
	SignatureChecks       int    `json:"signature_checks"`
}

// ThreatReport captures the verification verdict for a threat-model case.
type ThreatReport struct {
	CaseID        string `json:"case_id"`
	Category      string `json:"category"`
	Name          string `json:"name"`
	ExpectValid   bool   `json:"expect_valid"`
	ActualValid   bool   `json:"actual_valid"`
	ExpectedError string `json:"expected_error"`
	ActualError   string `json:"actual_error"`
	Pass          bool   `json:"pass"`
}

// SuiteReport is the deterministic CLI verification report (bit-exact across Go and Python).
type SuiteReport struct {
	SchemaVersion      string         `json:"schema_version"`
	SpecVersion        string         `json:"spec_version"`
	Seed               int64          `json:"seed"`
	TotalStages        int            `json:"total_stages"`
	PassedStages       int            `json:"passed_stages"`
	AllStagesValid     bool           `json:"all_stages_valid"`
	TotalThreatCases   int            `json:"total_threat_cases"`
	AttacksTotal       int            `json:"attacks_total"`
	AttacksCaught      int            `json:"attacks_caught"`
	PositiveControls   int            `json:"positive_controls"`
	PositiveControlsOK int            `json:"positive_controls_ok"`
	AllThreatPass      bool           `json:"all_threat_pass"`
	StageReports       []StageReport  `json:"stage_reports"`
	ThreatReports      []ThreatReport `json:"threat_reports"`
	AuditMerkleRoot    string         `json:"audit_merkle_root"`
}

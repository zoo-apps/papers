// SPDX-License-Identifier: Apache-2.0
//
// Package attrrep implements the clean-room reference verifier and benchmark
// suite for attribution-rep.v1 (HIP-1352, zoo-apps/papers#11):
// Scientific contribution attribution and Sybil-resistant reputation.
package attrrep

const (
	SchemaVersion = "attribution-rep.v1"
	SpecVersion   = "1.0.0"

	// Fixed-point scaling constants (zero floating-point arithmetic in core consensus).
	MicroScale int64 = 1_000_000 // 1.000000 credit = 1,000,000 micro-credits
	BpsScale   int64 = 10_000    // 100.00% = 10,000 basis points

	// Winnowing fingerprint parameters (Schleimer, Wilkerson, Aiken 2003).
	ShingleSize   = 4
	WinnowWindow  = 3

	// Identity roles.
	RoleResearcher = "RESEARCHER"
	RoleSeed       = "SEED_STEWARD"
	RoleAIAgent    = "AI_AGENT"

	// EAS-compatible schema UIDs (deterministic SHA-256 hex identifiers).
	SchemaPeerReview       = "0x1111111111111111111111111111111111111111111111111111111111111101"
	SchemaReplication      = "0x1111111111111111111111111111111111111111111111111111111111111102"
	SchemaReuseEndorsement = "0x1111111111111111111111111111111111111111111111111111111111111103"
	SchemaSimilarityFlag   = "0x1111111111111111111111111111111111111111111111111111111111111104"
	SchemaPolicyMutation   = "0x1111111111111111111111111111111111111111111111111111111111111105"
	SchemaTreasuryAuth     = "0x1111111111111111111111111111111111111111111111111111111111111106"

	// Verdict statuses.
	StatusAccepted = "ACCEPTED"
	StatusRejected = "REJECTED"
	StatusAdvisory = "ADVISORY"

	// Canonical error codes (normative in SPEC.md).
	ErrNone                     = ""
	ErrUnknownIdentity          = "ERR_UNKNOWN_IDENTITY"
	ErrInvalidSignature         = "ERR_INVALID_SIGNATURE"
	ErrContentDigestMismatch    = "ERR_CONTENT_DIGEST_MISMATCH"
	ErrFingerprintMismatch      = "ERR_FINGERPRINT_MISMATCH"
	ErrDuplicateContribution    = "ERR_DUPLICATE_CONTRIBUTION"
	ErrReformattedCopy          = "ERR_REFORMATTED_COPY"
	ErrNearDuplicateCopy        = "ERR_NEAR_DUPLICATE_COPY"
	ErrUndeclaredCopy           = "ERR_UNDECLARED_COPY"
	ErrCausalityCycle           = "ERR_CAUSALITY_CYCLE"
	ErrTimestampBackdate        = "ERR_TIMESTAMP_BACKDATE"
	ErrUnknownParent            = "ERR_UNKNOWN_PARENT"
	ErrAttestationUIDMismatch   = "ERR_ATTESTATION_UID_MISMATCH"
	ErrSelfAttestation          = "ERR_SELF_ATTESTATION"
	ErrRevokedAttestation       = "ERR_REVOKED_ATTESTATION"
	ErrExpiredAttestation       = "ERR_EXPIRED_ATTESTATION"
	ErrAttestationReplay        = "ERR_ATTESTATION_REPLAY"
	ErrRefNotAccepted           = "ERR_REF_NOT_ACCEPTED"
	ErrIssuerRateLimit          = "ERR_ISSUER_RATE_LIMIT"
	ErrAISelfAttestForbidden    = "ERR_AI_SELF_ATTEST_FORBIDDEN"
	ErrAIPolicyMutationForbid   = "ERR_AI_POLICY_MUTATION_FORBIDDEN"
	ErrAITreasuryForbidden      = "ERR_AI_TREASURY_FORBIDDEN"
	ErrCollusionRingDiscounted  = "ERR_COLLUSION_RING_DISCOUNTED"
	ErrSybilClusterCapped       = "ERR_SYBIL_CLUSTER_CAPPED"
)

// Policy configures deterministic thresholds and scoring parameters.
type Policy struct {
	NearDuplicateRejectBps   int64 `json:"near_duplicate_reject_bps"`
	UndeclaredCopyRejectBps  int64 `json:"undeclared_copy_reject_bps"`
	NoveltyOverclaimGapBps   int64 `json:"novelty_overclaim_gap_bps"`
	UpstreamFlowBps          int64 `json:"upstream_flow_bps"`
	MaxClockSkewSec          int64 `json:"max_clock_skew_sec"`
	EigenTrustDampingBps     int64 `json:"eigentrust_damping_bps"`
	EigenTrustIterations     int   `json:"eigentrust_iterations"`
	ReciprocalDiscountBps    int64 `json:"reciprocal_discount_bps"`
	RingDiscountBps          int64 `json:"ring_discount_bps"`
	ClusterSimThresholdBps   int64 `json:"cluster_sim_threshold_bps"`
	ClusterPenaltyBps        int64 `json:"cluster_penalty_bps"`
	TrustFullGateMicro       int64 `json:"trust_full_gate_micro"`
	TrustRepMultiplier       int64 `json:"trust_rep_multiplier"`
	AttrRepMultiplier        int64 `json:"attr_rep_multiplier"`
	MaxAttestationsPerEpoch  int   `json:"max_attestations_per_epoch"`
}

// DefaultPolicy returns the normative v1.0.0 protocol parameters.
func DefaultPolicy() Policy {
	return Policy{
		NearDuplicateRejectBps:  8000, // >= 80.00% Winnowing overlap rejected as near-duplicate copy
		UndeclaredCopyRejectBps: 5000, // >= 50.00% overlap without citing canonical ancestor rejected
		NoveltyOverclaimGapBps:  2500, // claiming >25% more novelty than measured on >=65% overlap rejected
		UpstreamFlowBps:         3000, // 30.00% of verified novel delta flows upstream to canonical parents
		MaxClockSkewSec:         300,  // 5 minutes max clock skew against append-only ledger sequence
		EigenTrustDampingBps:    8500, // alpha = 0.85 seeded trust propagation damping
		EigenTrustIterations:    40,   // fixed deterministic power-iteration horizon
		ReciprocalDiscountBps:   2500, // 75% discount on unseeded mutual-admiration pairs
		RingDiscountBps:         500,  // 95% discount on inward-facing unseeded endorsement rings (0% if isolated)
		ClusterSimThresholdBps:  8000, // >= 80.00% target-set Jaccard defines correlated Sybil cluster
		ClusterPenaltyBps:       1000,  // 90% additional discount on unseeded Sybil cluster combined weight
		TrustFullGateMicro:      10000, // 1.0% of network trust unlocks 100% attribution->reputation conversion
		TrustRepMultiplier:      5000,  // 0.070 EigenTrust -> 350 ZooRep base points
		AttrRepMultiplier:       50,    // 1.0 verified novel contribution -> 50 ZooRep points (at full trust gate)
		MaxAttestationsPerEpoch: 25,    // per-issuer per-epoch cap (ZIP-0026 issuer rate limit)
	}
}

// Identity is a registered participant with an RFC 8032 Ed25519 public key.
type Identity struct {
	ID        string `json:"id"`
	Role      string `json:"role"` // RESEARCHER | SEED_STEWARD | AI_AGENT
	PublicKey string `json:"public_key"`
	Label     string `json:"label,omitempty"`
}

// Contribution represents a content-addressed scientific artifact node in the DAG.
type Contribution struct {
	ContributionID    string   `json:"contribution_id"`
	LedgerSeq         int64    `json:"ledger_seq"`
	Epoch             int64    `json:"epoch"`
	Timestamp         int64    `json:"timestamp"`
	AuthorID          string   `json:"author_id"`
	Category          string   `json:"category"`
	CorpusSource      string   `json:"corpus_source,omitempty"`
	Content           string   `json:"content"`
	RawSHA256         string   `json:"raw_sha256"`
	CanonicalDigest   string   `json:"canonical_digest"`
	WinnowFingerprint []string `json:"winnow_fingerprint"`
	FingerprintDigest string   `json:"fingerprint_digest"`
	Parents           []string `json:"parents"`
	ClaimedNoveltyBps int64    `json:"claimed_novelty_bps"`
	BaseValueMicro    int64    `json:"base_value_micro"`
	SignatureHex      string   `json:"signature_hex"`
	ScenarioTag       string   `json:"scenario_tag,omitempty"`
}

// Attestation represents an EAS-compatible signed peer/replication attestation.
type Attestation struct {
	UID            string `json:"uid"`
	SchemaUID      string `json:"schema_uid"`
	Attester       string `json:"attester"`
	Recipient      string `json:"recipient"`
	RefUID         string `json:"ref_uid"`
	Epoch          int64  `json:"epoch"`
	Time           int64  `json:"time"`
	ExpirationTime int64  `json:"expiration_time"`
	Revocable      bool   `json:"revocable"`
	Revoked        bool   `json:"revoked"`
	Nonce          int64  `json:"nonce"`
	WeightBps      int64  `json:"weight_bps"`
	DataDigest     string `json:"data_digest"`
	SignatureHex   string `json:"signature_hex"`
	ScenarioTag    string `json:"scenario_tag,omitempty"`
}

// AdversarialExpectation pins the expected protocol behavior for an attack test vector.
type AdversarialExpectation struct {
	AttackID         string `json:"attack_id"`
	Category         string `json:"category"` // copy | collusion | causality | crypto | ai_guard
	TargetType       string `json:"target_type"` // contribution | attestation | cluster
	TargetID         string `json:"target_id"`
	ExpectedStatus   string `json:"expected_status"`
	ExpectedErrCode  string `json:"expected_error_code"`
	Description      string `json:"description"`
}

// SuiteBundle is the top-level published verification suite (attribution-rep.v1).
type SuiteBundle struct {
	SchemaVersion           string                   `json:"schema_version"`
	SpecVersion             string                   `json:"spec_version"`
	SuiteName               string                   `json:"suite_name"`
	Seed                    int64                    `json:"seed"`
	EvalTime                int64                    `json:"eval_time"`
	CorpusManifestSHA256    string                   `json:"corpus_manifest_sha256"`
	Policy                  Policy                   `json:"policy"`
	Identities              []Identity               `json:"identities"`
	RevokedUIDs             []string                 `json:"revoked_uids"`
	Contributions           []Contribution           `json:"contributions"`
	Attestations            []Attestation            `json:"attestations"`
	AdversarialExpectations []AdversarialExpectation `json:"adversarial_expectations,omitempty"`
}

// ContributionVerdict records the deterministic attribution verdict for a contribution.
type ContributionVerdict struct {
	ContributionID    string `json:"contribution_id"`
	AuthorID          string `json:"author_id"`
	Status            string `json:"status"`
	ErrorCode         string `json:"error_code"`
	CanonicalOriginID string `json:"canonical_origin_id"`
	BestMatchID       string `json:"best_match_id,omitempty"`
	BestOverlapBps    int64  `json:"best_overlap_bps"`
	NoveltyBps        int64  `json:"novelty_bps"`
	IntrinsicMicro    int64  `json:"intrinsic_micro"`
	SelfCreditMicro   int64  `json:"self_credit_micro"`
	UpstreamFlowMicro int64  `json:"upstream_flow_micro"`
	ScenarioTag       string `json:"scenario_tag,omitempty"`
}

// AttestationVerdict records the deterministic verdict for an EAS attestation.
type AttestationVerdict struct {
	UID                string `json:"uid"`
	Attester           string `json:"attester"`
	Recipient          string `json:"recipient"`
	RefUID             string `json:"ref_uid"`
	Status             string `json:"status"`
	ErrorCode          string `json:"error_code"`
	EffectiveWeightBps int64  `json:"effective_weight_bps"`
	ScenarioTag        string `json:"scenario_tag,omitempty"`
}

// CollusionFinding records a detected collusion ring or correlated Sybil cluster.
type CollusionFinding struct {
	FindingID    string   `json:"finding_id"`
	ErrorCode    string   `json:"error_code"`
	Members      []string `json:"members"`
	DiscountBps  int64    `json:"discount_bps"`
	ExternalIn   int      `json:"external_in"`
	InternalEdge int      `json:"internal_edges"`
}

// IdentitySummary is the deterministic final attribution & reputation state of an identity.
type IdentitySummary struct {
	IdentityID              string `json:"identity_id"`
	Role                    string `json:"role"`
	AcceptedContributions   int    `json:"accepted_contributions"`
	RejectedContributions   int    `json:"rejected_contributions"`
	AttributionMicro        int64  `json:"attribution_micro"`
	NaiveAttributionMicro   int64  `json:"naive_attribution_micro"`
	UpstreamCitationMicro   int64  `json:"upstream_citation_micro"`
	EigenTrustMicro         int64  `json:"eigentrust_micro"`
	TrustGateBps            int64  `json:"trust_gate_bps"`
	ReputationMicro         int64  `json:"reputation_micro"`
	ZooRepPoints            int64  `json:"zoo_rep_points"`
	Tier                    string `json:"tier"`
	TierWeightBps           int64  `json:"tier_weight_bps"`
	NaiveAttestationCount   int    `json:"naive_attestation_count"`
	NaiveReputationPoints   int64  `json:"naive_reputation_points"`
	ReputationRank          int    `json:"reputation_rank"`
	NaiveReputationRank     int    `json:"naive_reputation_rank"`
}

// AdversarialCheckResult records pass/fail against an AdversarialExpectation.
type AdversarialCheckResult struct {
	AttackID        string `json:"attack_id"`
	Category        string `json:"category"`
	TargetID        string `json:"target_id"`
	Passed          bool   `json:"passed"`
	ExpectedStatus  string `json:"expected_status"`
	ActualStatus    string `json:"actual_status"`
	ExpectedErrCode string `json:"expected_error_code"`
	ActualErrCode   string `json:"actual_error_code"`
}

// VerificationReport is the complete deterministic output of both Go and Python verifiers.
type VerificationReport struct {
	SchemaVersion             string                   `json:"schema_version"`
	SpecVersion               string                   `json:"spec_version"`
	SuiteName                 string                   `json:"suite_name"`
	AuditMerkleRoot           string                   `json:"audit_merkle_root"`
	TotalContributions        int                      `json:"total_contributions"`
	AcceptedContributions     int                      `json:"accepted_contributions"`
	RejectedContributions     int                      `json:"rejected_contributions"`
	TotalAttestations         int                      `json:"total_attestations"`
	AcceptedAttestations      int                      `json:"accepted_attestations"`
	AdvisoryAttestations      int                      `json:"advisory_attestations"`
	RejectedAttestations      int                      `json:"rejected_attestations"`
	TotalIntrinsicMicro       int64                    `json:"total_intrinsic_micro"`
	TotalAttributedMicro      int64                    `json:"total_attributed_micro"`
	TotalNaiveAttributedMicro int64                    `json:"total_naive_attributed_micro"`
	ConservationExact         bool                     `json:"conservation_exact"`
	AdversarialPassed         int                      `json:"adversarial_passed"`
	AdversarialTotal          int                      `json:"adversarial_total"`
	ContributionVerdicts      []ContributionVerdict    `json:"contribution_verdicts"`
	AttestationVerdicts       []AttestationVerdict     `json:"attestation_verdicts"`
	CollusionFindings         []CollusionFinding       `json:"collusion_findings"`
	IdentitySummaries         []IdentitySummary        `json:"identity_summaries"`
	AdversarialResults        []AdversarialCheckResult `json:"adversarial_results,omitempty"`
}

// ZooTierForPoints maps integer ZooRep points to ZIP-0026 tier name and weight multiplier (bps).
func ZooTierForPoints(points int64) (string, int64) {
	switch {
	case points >= 1000:
		return "Elder", 250
	case points >= 500:
		return "Guardian", 200
	case points >= 200:
		return "Steward", 150
	case points >= 50:
		return "Contributor", 120
	default:
		return "Observer", 100
	}
}

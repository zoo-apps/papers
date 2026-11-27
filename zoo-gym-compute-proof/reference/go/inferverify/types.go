// Copyright 2026 Zoo Labs Foundation / Hanzo Industries.
// Licensed under the Apache License, Version 2.0.

package inferverify

const (
	SchemaVersion           = "inference-verify.v1"
	SpecVersion             = "1.0.0"
	InTotoStatementTypeV1   = "https://in-toto.io/Statement/v1"
	InferencePredicateType  = "https://zoo.ngo/attestations/inference-verify/v1"
	ChallengePredicateType  = "https://zoo.ngo/attestations/inference-challenge/v1"
	ReexecPredicateType     = "https://zoo.ngo/attestations/inference-reexec/v1"
	DSSEPayloadTypeInToto   = "application/vnd.in-toto+json"
	DefaultModelID          = "zoo-qmlp-32x64x16.v1"
	ChallengeDenominatorBPS = 10000
)

// Verification Regimes
const (
	RegimeSignedAttestationOnly = "signed_attestation_only"
	RegimeIndependentReexec     = "independent_reexecution"
	RegimeRandomChallenge       = "random_challenge_verification"
	RegimeHybridAttestedChal    = "hybrid_attested_plus_challenged"
)

// Normative Verification Verdicts
const (
	VerdictVerified           = "VERIFIED"
	VerdictFraudDetected      = "FRAUD_DETECTED"
	VerdictInvalidAttestation = "INVALID_ATTESTATION"
	VerdictPolicyRejected     = "POLICY_REJECTED"
)

// Actor Roles
const (
	RoleWorker            = "WORKER"
	RoleVerifier          = "VERIFIER"
	RoleChallenger        = "CHALLENGER"
	RoleAIAgent           = "AI_AGENT"
	RoleGovernanceCouncil = "GOVERNANCE_COUNCIL"
)

// Governance Actions
const (
	ActionNone                   = "NONE"
	ActionRecommendChallengeRate = "RECOMMEND_CHALLENGE_RATE"
	ActionFlagSuspiciousWorker   = "FLAG_SUSPICIOUS_WORKER"
	ActionApproveSlashing        = "APPROVE_SLASHING"
	ActionMutatePolicyParams     = "MUTATE_POLICY_PARAMS"
	ActionSelfCertifyInference   = "SELF_CERTIFY_INFERENCE"
)

// Normative Error Codes
const (
	ErrNone                       = "OK"
	ErrInvalidEnvelope            = "ERR_INVALID_ENVELOPE"
	ErrInvalidPayloadType         = "ERR_INVALID_PAYLOAD_TYPE"
	ErrInvalidInTotoType          = "ERR_INVALID_INTOTO_TYPE"
	ErrInvalidPredicateType       = "ERR_INVALID_PREDICATE_TYPE"
	ErrInvalidSchemaVersion       = "ERR_INVALID_SCHEMA_VERSION"
	ErrSubjectDigestMismatch      = "ERR_SUBJECT_DIGEST_MISMATCH"
	ErrModelDigestMismatch        = "ERR_MODEL_DIGEST_MISMATCH"
	ErrInputDigestMismatch        = "ERR_INPUT_DIGEST_MISMATCH"
	ErrRegimeMismatch             = "ERR_REGIME_MISMATCH"
	ErrInvalidDSSESig             = "ERR_INVALID_DSSE_SIG"
	ErrKeyUnregistered            = "ERR_KEY_UNREGISTERED"
	ErrKeyRevoked                 = "ERR_KEY_REVOKED"
	ErrKeyExpired                 = "ERR_KEY_EXPIRED"
	ErrEpochMismatch              = "ERR_EPOCH_MISMATCH"
	ErrEquivocationDetected       = "ERR_EQUIVOCATION_DETECTED"
	ErrMissingTLogProof           = "ERR_MISSING_TLOG_PROOF"
	ErrUntrustedTLogKey           = "ERR_UNTRUSTED_TLOG_KEY"
	ErrInvalidTLogCheckpointSig   = "ERR_INVALID_TLOG_CHECKPOINT_SIG"
	ErrInvalidTLogProof           = "ERR_INVALID_TLOG_PROOF"
	ErrTLogLeafMismatch           = "ERR_TLOG_LEAF_MISMATCH"
	ErrQuorumNotMet               = "ERR_QUORUM_NOT_MET"
	ErrColludingOperatorGroup     = "ERR_COLLUDING_OPERATOR_GROUP"
	ErrInvalidReexecSig           = "ERR_INVALID_REEXEC_SIG"
	ErrOutputMismatchReexec       = "ERR_OUTPUT_MISMATCH_REEXEC"
	ErrMissingRequiredChallenge   = "ERR_MISSING_REQUIRED_CHALLENGE"
	ErrInvalidChallengeSig        = "ERR_INVALID_CHALLENGE_SIG"
	ErrChallengeFraudProven       = "ERR_CHALLENGE_FRAUD_PROVEN"
	ErrChallengeTranscriptInvalid = "ERR_CHALLENGE_TRANSCRIPT_INVALID"
	ErrAISelfCertForbidden        = "ERR_AI_SELF_CERT_FORBIDDEN"
	ErrAIPolicyMutationForbidden  = "ERR_AI_POLICY_MUTATION_FORBIDDEN"
	ErrAISlashApprovalForbidden   = "ERR_AI_SLASH_APPROVAL_FORBIDDEN"
	ErrOverclaimedProofScope      = "ERR_OVERCLAIMED_PROOF_SCOPE"
)

type CorpusFile struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	Role   string `json:"role"`
}

type CorpusManifest struct {
	SchemaVersion  string       `json:"schema_version"`
	Issue          string       `json:"issue"`
	HIP            string       `json:"hip"`
	License        string       `json:"license"`
	Description    string       `json:"description"`
	DerivationRule string       `json:"derivation_rule"`
	Files          []CorpusFile `json:"files"`
}

type KeyEntry struct {
	ActorID         string `json:"actor_id"`
	ActorRole       string `json:"actor_role"`
	OperatorGroup   string `json:"operator_group"`
	PubKeyHex       string `json:"pubkey_hex"`
	ValidFromEpoch  uint64 `json:"valid_from_epoch"`
	ValidUntilEpoch uint64 `json:"valid_until_epoch"`
	Revoked         bool   `json:"revoked"`
}

type TrustRoot struct {
	TLogID        string     `json:"tlog_id"`
	TLogPubKeyHex string     `json:"tlog_pubkey_hex"`
	Keys          []KeyEntry `json:"keys"`
}

type VerificationPolicy struct {
	ReexecQuorumK         int    `json:"reexec_quorum_k"`
	ChallengeBaseBPS      uint64 `json:"challenge_base_bps"`
	ChallengeEscalatedBPS uint64 `json:"challenge_escalated_bps"`
	MinChallengeBPS       uint64 `json:"min_challenge_bps"`
	MaxChallengeBPS       uint64 `json:"max_challenge_bps"`
	ReputationThreshold   int    `json:"reputation_threshold"`
	ProbationJobs         int    `json:"probation_jobs"`
	JobFeeUnits           int64  `json:"job_fee_units"`
	HonestCostUnits       int64  `json:"honest_cost_units"`
	CheatCostUnits        int64  `json:"cheat_cost_units"`
	WorkerBondUnits       int64  `json:"worker_bond_units"`
	SlashPenaltyUnits     int64  `json:"slash_penalty_units"`
	ChallengerRewardUnits int64  `json:"challenger_reward_units"`
}

func DefaultPolicy() VerificationPolicy {
	return VerificationPolicy{
		ReexecQuorumK:         3,
		ChallengeBaseBPS:      500,  // 5.0%
		ChallengeEscalatedBPS: 2500, // 25.0%
		MinChallengeBPS:       100,  // 1.0%
		MaxChallengeBPS:       5000, // 50.0%
		ReputationThreshold:   800,
		ProbationJobs:         20,
		JobFeeUnits:           1000,  // 10.00 units (centi-units for exact int64)
		HonestCostUnits:       500,   // 5.00 units
		CheatCostUnits:        25,    // 0.25 units (95% compute savings)
		WorkerBondUnits:       20000, // 200.00 units
		SlashPenaltyUnits:     15000, // 150.00 units
		ChallengerRewardUnits: 5000,  // 50.00 units
	}
}

type DSSESignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type DSSEEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []DSSESignature `json:"signatures"`
}

type InTotoSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type InferencePredicate struct {
	SchemaVersion                  string `json:"schema_version"`
	JobID                          string `json:"job_id"`
	Epoch                          uint64 `json:"epoch"`
	Regime                         string `json:"regime"`
	ModelID                        string `json:"model_id"`
	ModelDigest                    string `json:"model_digest"`
	DecodeSteps                    int    `json:"decode_steps"`
	InputDigest                    string `json:"input_digest"`
	OutputDigest                   string `json:"output_digest"`
	LogitsDigest                   string `json:"logits_digest"`
	TopToken                       int32  `json:"top_token"`
	WorkerID                       string `json:"worker_id"`
	WorkerOperatorGroup            string `json:"worker_operator_group"`
	WorkerPubKeyHex                string `json:"worker_pubkey_hex"`
	ActorRole                      string `json:"actor_role"`
	GovernanceAction               string `json:"governance_action"`
	AttestsSignedProvenanceOnly    bool   `json:"attests_signed_provenance_only"`
	ProvesHardwareTEEUncompromised bool   `json:"proves_hardware_tee_uncompromised"`
	ProvesScientificTruth          bool   `json:"proves_scientific_truth"`
}

type InTotoStatement struct {
	Type          string             `json:"_type"`
	Subject       []InTotoSubject    `json:"subject"`
	PredicateType string             `json:"predicateType"`
	Predicate     InferencePredicate `json:"predicate"`
}

type ReexecPredicate struct {
	SchemaVersion         string `json:"schema_version"`
	JobID                 string `json:"job_id"`
	Epoch                 uint64 `json:"epoch"`
	ModelDigest           string `json:"model_digest"`
	InputDigest           string `json:"input_digest"`
	ComputedOutputDigest  string `json:"computed_output_digest"`
	ComputedLogitsDigest  string `json:"computed_logits_digest"`
	ComputedTopToken      int32  `json:"computed_top_token"`
	VerifierID            string `json:"verifier_id"`
	VerifierOperatorGroup string `json:"verifier_operator_group"`
	VerifierPubKeyHex     string `json:"verifier_pubkey_hex"`
	ActorRole             string `json:"actor_role"`
	MatchesWorker         bool   `json:"matches_worker"`
}

type ReexecStatement struct {
	Type          string          `json:"_type"`
	Subject       []InTotoSubject `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     ReexecPredicate `json:"predicate"`
}

type ChallengePredicate struct {
	SchemaVersion           string `json:"schema_version"`
	JobID                   string `json:"job_id"`
	Epoch                   uint64 `json:"epoch"`
	EpochBeaconHex          string `json:"epoch_beacon_hex"`
	EffectiveChallengeBPS   uint64 `json:"effective_challenge_bps"`
	ChallengeDrawBPS        uint64 `json:"challenge_draw_bps"`
	ModelDigest             string `json:"model_digest"`
	InputDigest             string `json:"input_digest"`
	WorkerOutputDigest      string `json:"worker_output_digest"`
	RecomputedOutputDigest  string `json:"recomputed_output_digest"`
	RecomputedLogitsDigest  string `json:"recomputed_logits_digest"`
	RecomputedTopToken      int32  `json:"recomputed_top_token"`
	ChallengerID            string `json:"challenger_id"`
	ChallengerOperatorGroup string `json:"challenger_operator_group"`
	ChallengerPubKeyHex     string `json:"challenger_pubkey_hex"`
	ActorRole               string `json:"actor_role"`
	FraudProven             bool   `json:"fraud_proven"`
}

type ChallengeStatement struct {
	Type          string             `json:"_type"`
	Subject       []InTotoSubject    `json:"subject"`
	PredicateType string             `json:"predicateType"`
	Predicate     ChallengePredicate `json:"predicate"`
}

type TransparencyLogBundle struct {
	LogID           string   `json:"log_id"`
	LogPubKeyHex    string   `json:"log_pubkey_hex"`
	LogIndex        int      `json:"log_index"`
	TreeSize        int      `json:"tree_size"`
	RootHash        string   `json:"root_hash"`
	CheckpointEpoch uint64   `json:"checkpoint_epoch"`
	CheckpointSig   string   `json:"checkpoint_sig_b64"`
	LeafEntryDigest string   `json:"leaf_entry_digest"`
	Hashes          []string `json:"hashes"`
}

type ReexecReceipt struct {
	VerifierID string       `json:"verifier_id"`
	Envelope   DSSEEnvelope `json:"envelope"`
}

type ChallengeTranscript struct {
	ChallengerID string       `json:"challenger_id"`
	Envelope     DSSEEnvelope `json:"envelope"`
}

type WorkerRiskContext struct {
	ReputationScore   int  `json:"reputation_score"`
	JobsCompleted     int  `json:"jobs_completed"`
	AIAdvisoryFlagged bool `json:"ai_advisory_flagged"`
}

type VerificationCase struct {
	CaseID                    string                 `json:"case_id"`
	Category                  string                 `json:"category"`
	Description               string                 `json:"description"`
	Regime                    string                 `json:"regime"`
	ExpectedEpoch             uint64                 `json:"expected_epoch"`
	EpochBeaconHex            string                 `json:"epoch_beacon_hex"`
	ChallengeRateBPSOverride  *uint64                `json:"challenge_rate_bps_override,omitempty"`
	InputTokens               []int32                `json:"input_tokens"`
	DecodeSteps               int                    `json:"decode_steps"`
	WorkerRisk                WorkerRiskContext      `json:"worker_risk"`
	WorkerEnvelope            DSSEEnvelope           `json:"worker_envelope"`
	TLogBundle                *TransparencyLogBundle `json:"tlog_bundle"`
	ReexecReceipts            []ReexecReceipt        `json:"reexec_receipts,omitempty"`
	ChallengeTranscript       *ChallengeTranscript   `json:"challenge_transcript,omitempty"`
	SeenJobOutputs            map[string]string      `json:"seen_job_outputs,omitempty"`
	WorkerCheatedGroundTruth  bool                   `json:"worker_cheated_ground_truth"`
	ExpectedVerdict           string                 `json:"expected_verdict"`
	ExpectedErrorCode         string                 `json:"expected_error_code"`
	ExpectedFraudEscaped      bool                   `json:"expected_fraud_escaped"`
}

type VerificationSuite struct {
	SchemaVersion           string             `json:"schema_version"`
	SpecVersion             string             `json:"spec_version"`
	Issue                   string             `json:"issue"`
	HIP                     string             `json:"hip"`
	Seed                    uint64             `json:"seed"`
	CorpusRootSHA256        string             `json:"corpus_root_sha256"`
	ModelID                 string             `json:"model_id"`
	ModelDigest             string             `json:"model_digest"`
	TrustRoot               TrustRoot          `json:"trust_root"`
	Policy                  VerificationPolicy `json:"policy"`
	ExpectedAuditMerkleRoot string             `json:"expected_audit_merkle_root"`
	Cases                   []VerificationCase `json:"cases"`
}

type CaseResult struct {
	CaseID          string `json:"case_id"`
	Category        string `json:"category"`
	Regime          string `json:"regime"`
	Verdict         string `json:"verdict"`
	ErrorCode       string `json:"error_code"`
	Challenged      bool   `json:"challenged"`
	FraudEscaped    bool   `json:"fraud_escaped"`
	ReexecCount     int    `json:"reexec_count"`
	OutputDigest    string `json:"output_digest"`
	TLogRoot        string `json:"tlog_root"`
	AuditLeafDigest string `json:"audit_leaf_digest"`
}

type SuiteAuditResult struct {
	TotalCases      int          `json:"total_cases"`
	GoldenCases     int          `json:"golden_cases"`
	AdversarialCase int          `json:"adversarial_cases"`
	MatchesExpected int          `json:"matches_expected"`
	AuditMerkleRoot string       `json:"audit_merkle_root"`
	Results         []CaseResult `json:"results"`
}

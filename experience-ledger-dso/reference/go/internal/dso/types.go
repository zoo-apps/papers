// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation

package dso

const (
	SchemaVersion = "dso-aggregation.v1"

	// FeatureDim is the deterministic semantic preference vector dimension:
	//   [0..27]  protocol_governance hashed term subspace (28 dims)
	//   [28..55] conservation_science hashed term subspace (28 dims)
	//   [56..61] shared cross-domain DSO structural subspace (6 dims)
	//   [62..63] unmonitored niche backdoor trigger subspace (2 dims)
	FeatureDim = 64

	ProtoStart   = 0
	ProtoEnd     = 28
	ConsStart    = 28
	ConsEnd      = 56
	SharedStart  = 56
	SharedEnd    = 62
	TriggerStart = 62
	TriggerEnd   = 64

	// FixedScale encodes float64 values as deterministic micro-units (1e-6)
	// inside canonical signed JSON payloads for bit-exact Go/Python parity.
	FixedScale = 1_000_000

	DomainProtocol     = "protocol_governance"
	DomainConservation = "conservation_science"

	RoleHonestMajority = "honest_majority"
	RoleHonestMinority = "honest_minority"
	RoleAdversary      = "adversary"

	ScenarioAdversarialSemantic = "adversarial_semantic"
	ScenarioColludingCartel     = "colluding_sybil_cartel"
	ScenarioLowQualityNoisy     = "low_quality_noisy"
	ScenarioHonestDisagreement  = "honest_disagreement_noniid"

	AggMeanBaseline           = "mean_baseline"
	AggCoordMedian            = "coord_median"
	AggTrimmedMean            = "trimmed_mean"
	AggMultiKrum              = "multi_krum"
	AggDSOReputationEvalGated = "dso_reputation_eval_gated"
)

// AllScenarios enumerates the 4 mandatory threat and honest-disagreement scenarios.
var AllScenarios = []string{
	ScenarioAdversarialSemantic,
	ScenarioColludingCartel,
	ScenarioLowQualityNoisy,
	ScenarioHonestDisagreement,
}

// AllAggregators enumerates the 5 head-to-head aggregation rules.
var AllAggregators = []string{
	AggMeanBaseline,
	AggCoordMedian,
	AggTrimmedMean,
	AggMultiKrum,
	AggDSOReputationEvalGated,
}

// AllAdversaryFractions enumerates f in {0%, 10%, 20%, 30%, 40%, 50%}.
var AllAdversaryFractions = []float64{0.0, 0.10, 0.20, 0.30, 0.40, 0.50}

// ExperienceOp models a DSO semantic advantage update from experience-ledger-dso.
type ExperienceOp struct {
	ID              string `json:"id"`
	Op              string `json:"op"`
	Domain          string `json:"domain"`
	Text            string `json:"text"`
	ConfidenceMicro int64  `json:"confidence_micro"`
	PaperPath       string `json:"paper_path"`
	PaperSHA256     string `json:"paper_sha256"`
}

// ContributionBody is the canonical Ed25519-signed payload submitted by one node in a round.
type ContributionBody struct {
	SchemaVersion string       `json:"schema_version"`
	Round         int          `json:"round"`
	NodeID        string       `json:"node_id"`
	PublicKeyHex  string       `json:"public_key_hex"`
	Domain        string       `json:"domain"`
	Experience    ExperienceOp `json:"experience"`
	DeltaMicro    []int64      `json:"delta_micro"`
}

// ContributionEnvelope pairs a signed ContributionBody with its Ed25519 signature and digest.
type ContributionEnvelope struct {
	Body         ContributionBody `json:"body"`
	SignatureHex string           `json:"signature_hex"`
	DigestSHA256 string           `json:"digest_sha256"`
	PayloadBytes int              `json:"payload_bytes"`
	// Non-signed simulation metadata (used only by benchmark harness for ground-truth accounting).
	Role string `json:"role,omitempty"`
}

// PaperDoc represents one grounded real .tex paper from zoo-apps/papers.
type PaperDoc struct {
	RelPath    string   `json:"rel_path"`
	Domain     string   `json:"domain"`
	SHA256     string   `json:"sha256"`
	Paragraphs []string `json:"-"`
}

// Example is a grounded semantic trajectory preference pair derived from real .tex paragraphs.
type Example struct {
	Domain     string
	Features   [FeatureDim]float64
	Label      int // +1 or -1
	PaperPath  string
	HasTrigger bool
}

// CorpusDataset holds the deterministic real-paper dataset splits.
type CorpusDataset struct {
	Papers              []PaperDoc
	CorpusSHA256        string
	ProtocolPaperCount  int
	ConservPaperCount   int
	ProtocolParaCount   int
	ConservParaCount    int
	TrainProtocol       []Example
	TrainConservation   []Example
	ValProtocol         []Example // Independent held-out validation shard (protocol_governance)
	ValConservation     []Example // Independent held-out validation shard (conservation_science)
	TestProtocol        []Example // Unseen test shard (protocol_governance)
	TestConservation    []Example // Unseen test shard (conservation_science)
	TriggerBackdoorTest []Example // Niche unmonitored semantic trigger test shard (absent from Val*)
	TrueWeightsProto    [FeatureDim]float64
	TrueWeightsCons     [FeatureDim]float64
}

// AggregationConfig parameterizes the 5 aggregation rules.
type AggregationConfig struct {
	TrimBeta           float64 `json:"trim_beta"`            // Trimmed mean fraction trimmed from each tail (default 0.25)
	KrumAssumedByz     int     `json:"krum_assumed_byz"`     // Multi-Krum assumed max Byzantine count f_max (default 9 for N=30)
	KrumSelectM        int     `json:"krum_select_m"`        // Multi-Krum number of selected vectors m (default 15 for N=30)
	DSOEvalStep        float64 `json:"dso_eval_step"`        // Evaluation probe step eta for marginal utility check
	DSOMinGain         float64 `json:"dso_min_gain"`         // Minimum domain marginal utility gain tau_min
	DSOSafetyTol       float64 `json:"dso_safety_tol"`       // Cross-domain safety tolerance tau_safety (Theorem 4.1)
	DSOClusterCos      float64 `json:"dso_cluster_cos"`      // Cosine threshold for Sybil collusion cluster discounting
	DSOMaxDeltaNorm    float64 `json:"dso_max_delta_norm"`   // Hard L2 norm sanity cap
	DSOMinorityFloor   float64 `json:"dso_minority_floor"`   // Minimum domain share for active validated minority domain
	AcceptanceWeightTh float64 `json:"acceptance_weight_th"` // Relative weight threshold (0.5/N) for counting a node accepted
}

// DefaultAggregationConfig returns the standard benchmark hyperparameters for N=30 nodes.
func DefaultAggregationConfig() AggregationConfig {
	return AggregationConfig{
		TrimBeta:           0.25,
		KrumAssumedByz:     9,
		KrumSelectM:        15,
		DSOEvalStep:        0.5,
		DSOMinGain:         0.0005,
		DSOSafetyTol:       0.008,
		DSOClusterCos:      0.97,
		DSOMaxDeltaNorm:    5.0,
		DSOMinorityFloor:   0.35,
		AcceptanceWeightTh: 0.5, // threshold = 0.5 / N
	}
}

// AggregationResult holds the deterministic outcome of aggregating one round of N contributions.
type AggregationResult struct {
	Aggregator       string             `json:"aggregator"`
	AggregatedDelta  [FeatureDim]float64 `json:"-"`
	AggDeltaMicro    []int64            `json:"aggregated_delta_micro"`
	Weights          []float64          `json:"-"`
	WeightsMicro     []int64            `json:"weights_micro"`
	Accepted         []bool             `json:"accepted"`
	RejectReasons    []string           `json:"reject_reasons"`
	ClusterSizes     []int              `json:"cluster_sizes"`
	InvalidSigCount  int                `json:"invalid_sig_count"`
	InvalidSchemaCnt int                `json:"invalid_schema_count"`
	DurationMs       float64            `json:"duration_ms"`
}

// CellMetrics captures all required quality, robustness, participation fairness, and overhead metrics.
type CellMetrics struct {
	Scenario                     string  `json:"scenario"`
	AdversaryFraction            float64 `json:"adversary_fraction"`
	Aggregator                   string  `json:"aggregator"`
	NumNodes                     int     `json:"num_nodes"`
	NumRounds                    int     `json:"num_rounds"`
	NumHonestMajority            int     `json:"num_honest_majority"`
	NumHonestMinority            int     `json:"num_honest_minority"`
	NumAdversaries               int     `json:"num_adversaries"`
	GlobalTestAccuracy           float64 `json:"global_test_accuracy"`
	GlobalTestLoss               float64 `json:"global_test_loss"`
	MajorityTestAccuracy         float64 `json:"majority_test_accuracy"`
	MinorityTestAccuracy         float64 `json:"minority_test_accuracy"`
	CleanHonestCeilingAccuracy   float64 `json:"clean_honest_ceiling_accuracy"`
	AttackDegradationDelta       float64 `json:"attack_degradation_delta"`
	AdversarialAdmissionRate     float64 `json:"adversarial_admission_rate"`
	AdversarialWeightShare       float64 `json:"adversarial_weight_share"`
	MajorityHonestAcceptanceRate float64 `json:"majority_honest_acceptance_rate"`
	MinorityHonestAcceptanceRate float64 `json:"minority_honest_acceptance_rate"`
	FairnessRatio                float64 `json:"fairness_ratio"`
	JainsFairnessIndex           float64 `json:"jains_fairness_index"`
	AttributionGini              float64 `json:"attribution_gini"`
	VerificationMsPerRound       float64 `json:"verification_ms_per_round"`
	PayloadBytesPerRound         int     `json:"payload_bytes_per_round"`
	FinalWeightsDigestSHA256     string  `json:"final_weights_digest_sha256"`
}

// NegativeRegime1Entry captures Geometric-Filter Minority Erasure at f=0%.
type NegativeRegime1Entry struct {
	Aggregator                   string  `json:"aggregator"`
	MajorityHonestAcceptanceRate float64 `json:"majority_honest_acceptance_rate"`
	MinorityHonestAcceptanceRate float64 `json:"minority_honest_acceptance_rate"`
	MajorityTestAccuracy         float64 `json:"majority_test_accuracy"`
	MinorityTestAccuracy         float64 `json:"minority_test_accuracy"`
	JainsFairnessIndex           float64 `json:"jains_fairness_index"`
	AttributionGini              float64 `json:"attribution_gini"`
}

// NegativeRegime2Entry captures Semantic Backdoor Blindness on an unmonitored trigger subdomain.
type NegativeRegime2Entry struct {
	Aggregator                 string  `json:"aggregator"`
	AdversaryFraction          float64 `json:"adversary_fraction"`
	CleanGlobalAccuracy        float64 `json:"clean_global_accuracy"`
	UnmonitoredTriggerAccuracy float64 `json:"unmonitored_trigger_accuracy"`
	BackdoorAttackSuccessRate  float64 `json:"backdoor_attack_success_rate"`
	AdversarialAdmissionRate   float64 `json:"adversarial_admission_rate"`
}

// NegativeRegime3Entry captures 50% Byzantine breakdown, decentralized committee voting collapse, and eval overfitting.
type NegativeRegime3Entry struct {
	Mode                   string  `json:"mode"`
	AdversaryFraction      float64 `json:"adversary_fraction"`
	GlobalTestAccuracy     float64 `json:"global_test_accuracy"`
	ValAccuracy            float64 `json:"val_accuracy"`
	GoodhartOverfitGap     float64 `json:"goodhart_overfit_gap"`
	HonestLivenessRate     float64 `json:"honest_liveness_rate"`
	AdversarialApprovalPct float64 `json:"adversarial_approval_pct"`
	Notes                  string  `json:"notes"`
}

// NegativeRegimes bundles all 3 honest negative regime experiments.
type NegativeRegimes struct {
	Regime1MinorityErasureAtZeroAdv []NegativeRegime1Entry `json:"regime_1_minority_erasure_at_zero_adv"`
	Regime2UnmonitoredBackdoor      []NegativeRegime2Entry `json:"regime_2_unmonitored_backdoor"`
	Regime3FiftyPctAndCommittee     []NegativeRegime3Entry `json:"regime_3_fifty_pct_and_committee"`
}

// BenchmarkReport is the top-level reproducible results.json artifact.
type BenchmarkReport struct {
	SchemaVersion      string            `json:"schema_version"`
	Seed               int64             `json:"seed"`
	NumNodes           int               `json:"num_nodes"`
	NumRounds          int               `json:"num_rounds"`
	FeatureDim         int               `json:"feature_dim"`
	CorpusPaperCount   int               `json:"corpus_paper_count"`
	ProtocolPaperCount int               `json:"protocol_paper_count"`
	ConservPaperCount  int               `json:"conservation_paper_count"`
	ProtocolParaCount  int               `json:"protocol_paragraph_count"`
	ConservParaCount   int               `json:"conservation_paragraph_count"`
	CorpusSHA256       string            `json:"corpus_sha256"`
	Config             AggregationConfig `json:"config"`
	Cells              []CellMetrics     `json:"cells"`
	NegativeRegimes    NegativeRegimes   `json:"negative_regimes"`
	AuditMerkleRoot    string            `json:"audit_merkle_root"`
}

// AuditValExample serializes a held-out validation example in micro-units for exact Python parity.
type AuditValExample struct {
	Domain        string  `json:"domain"`
	FeaturesMicro []int64 `json:"features_micro"`
	Label         int     `json:"label"`
}

// AuditScenarioRound exports one complete signed round for independent cross-language Python verification.
type AuditScenarioRound struct {
	Label           string                 `json:"label"`
	Scenario        string                 `json:"scenario"`
	AdvFraction     float64                `json:"adversary_fraction"`
	Round           int                    `json:"round"`
	BaseModelMicro  []int64                `json:"base_model_micro"`
	ReputationMicro []int64                `json:"reputation_micro"`
	Contributions   []ContributionEnvelope `json:"contributions"`
	ExpectedOutputs []AggregationResult    `json:"expected_outputs"`
	RoundMerkleRoot string                 `json:"round_merkle_root"`
}

// AuditTraceArtifact is the compact exported trace verified by the independent Python 3.12 audit verifier.
type AuditTraceArtifact struct {
	SchemaVersion   string               `json:"schema_version"`
	Seed            int64                `json:"seed"`
	CorpusSHA256    string               `json:"corpus_sha256"`
	Config          AggregationConfig    `json:"config"`
	ValProtocol     []AuditValExample    `json:"val_protocol"`
	ValConservation []AuditValExample    `json:"val_conservation"`
	Rounds          []AuditScenarioRound `json:"rounds"`
	TraceMerkleRoot string               `json:"trace_merkle_root"`
	ReportMerkle    string               `json:"report_merkle_root"`
}

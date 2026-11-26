// SPDX-License-Identifier: Apache-2.0

package qfsim

// Protocol constants for deterministic micro-unit integer accounting.
const (
	SpecVersion = "qf-simulator.v1"

	// MicroZOO is 1 ZOO expressed in exact micro-units (10^6 micro-ZOO = 1 ZOO).
	MicroZOO int64 = 1_000_000
	// Scale is the fixed-point denominator (10^6) for normalized weights and roots.
	Scale int64 = 1_000_000
	// BPS is basis points (10,000 = 100.00%).
	BPS int64 = 10_000

	// DefaultMatchingPool is 100,000 ZOO in micro-ZOO (10^11 micro-ZOO).
	DefaultMatchingPool int64 = 100_000 * MicroZOO
	// DefaultDonorCapBPS is 5% of matching pool per donor per project (ZIP-0023 §5.3).
	DefaultDonorCapBPS int64 = 500
	// DefaultProjectCapBPS is 10% of matching pool per project.
	DefaultProjectCapBPS int64 = 1000
	// DefaultPairwiseM is 25 ZOO tuning constant for Buterin Pairwise Bounded QF.
	DefaultPairwiseM int64 = 25 * MicroZOO
	// DefaultCOCMM is 25 ZOO inter-cluster pairwise constant for hybrid COCM.
	DefaultCOCMM int64 = 25 * MicroZOO
	// DefaultCOCMLambdaBPS is 0.85 similarity discount coefficient (zoo-dao-governance §8.2).
	DefaultCOCMLambdaBPS int64 = 8500

	// DefaultMinRepGate is 10 ZooRep matching gate (zoo-dao-grants-program.tex §5.3).
	DefaultMinRepGate int64 = 10
	// DefaultRepMinFP is 0.04 floor weight for unverified accounts (<10 ZooRep).
	DefaultRepMinFP int64 = 40_000
	// StrictMinRepGate is 50 ZooRep Contributor gate (zoo-dao-governance.tex §4.2).
	StrictMinRepGate int64 = 50
	// StrictRepMinFP is 0.00 hard cutoff below StrictMinRepGate (Negative Regime #1).
	StrictRepMinFP int64 = 0

	// DefaultSeed is the canonical HIP-1352 simulation seed.
	DefaultSeed int64 = 1352

	// TreasuryCommitteeQuorum is 3-of-5 human stewards with >=200 ZooRep (zoo-dao-governance.tex §3.2).
	TreasuryCommitteeQuorum  int   = 3
	TreasuryCommitteeSize    int   = 5
	TreasuryStewardMinZooRep int64 = 200
)

// MechanismID identifies one of the six head-to-head allocation mechanisms.
type MechanismID string

const (
	MechLinearTokenMatching       MechanismID = "linear_token_matching"
	MechStandardCLRQF             MechanismID = "standard_clr_qf"
	MechCappedVotingQF            MechanismID = "capped_voting_qf"
	MechPairwiseBoundedQF         MechanismID = "pairwise_bounded_qf"
	MechReputationWeightedQF      MechanismID = "reputation_weighted_qf"
	MechHybridCOCMRepCappedQF     MechanismID = "hybrid_cocm_reputation_capped_qf"
)

// AllMechanisms returns the canonical ordered list of all six allocation mechanisms.
func AllMechanisms() []MechanismID {
	return []MechanismID{
		MechLinearTokenMatching,
		MechStandardCLRQF,
		MechCappedVotingQF,
		MechPairwiseBoundedQF,
		MechReputationWeightedQF,
		MechHybridCOCMRepCappedQF,
	}
}

// MechanismParams configures mechanism parameters deterministically in integer micro-units.
type MechanismParams struct {
	DonorCapBPS   int64 `json:"donor_cap_bps"`
	ProjectCapBPS int64 `json:"project_cap_bps"`
	PairwiseM     int64 `json:"pairwise_m_micro_zoo"`
	COCMM         int64 `json:"cocm_m_micro_zoo"`
	COCMLambdaBPS int64 `json:"cocm_lambda_bps"`
	MinRepGate    int64 `json:"min_rep_gate"`
	RepMinFP      int64 `json:"rep_min_fp"`
}

// DefaultMechanismParams returns the standard Zoo DAO v1 mechanism parameters.
func DefaultMechanismParams() MechanismParams {
	return MechanismParams{
		DonorCapBPS:   DefaultDonorCapBPS,
		ProjectCapBPS: DefaultProjectCapBPS,
		PairwiseM:     DefaultPairwiseM,
		COCMM:         DefaultCOCMM,
		COCMLambdaBPS: DefaultCOCMLambdaBPS,
		MinRepGate:    DefaultMinRepGate,
		RepMinFP:      DefaultRepMinFP,
	}
}

// StrictRepMechanismParams enforces a hard 50-ZooRep Contributor gate with zero floor
// for unverified newcomers (used in Negative Regime #1).
func StrictRepMechanismParams() MechanismParams {
	p := DefaultMechanismParams()
	p.MinRepGate = StrictMinRepGate
	p.RepMinFP = StrictRepMinFP
	return p
}

// GrantArchetype classifies a research proposal's structural funding profile.
type GrantArchetype string

const (
	ArchetypeBroadPublicGood   GrantArchetype = "broad_public_good"
	ArchetypeGrassrootsMinor   GrantArchetype = "grassroots_minority"
	ArchetypeTightlyKnitLab    GrantArchetype = "tightly_knit_lab"
	ArchetypeWhaleNiche        GrantArchetype = "whale_niche"
	ArchetypeAdversarialShell  GrantArchetype = "adversarial_shell"
)

// GrantProposal is a research grant grounded in a real .tex paper in zoo-apps/papers
// (or an adversarial shell proposal in attack scenarios).
type GrantProposal struct {
	ID              string         `json:"id"`
	Title           string         `json:"title"`
	PaperDir        string         `json:"paper_dir"`
	TexPath         string         `json:"tex_path"`
	TexSHA256       string         `json:"tex_sha256"`
	Category        string         `json:"category"`
	Archetype       GrantArchetype `json:"archetype"`
	MeritBPS        int64          `json:"merit_bps"`
	IsAttackerTarget bool          `json:"is_attacker_target"`
	IsNewcomerGrant bool           `json:"is_newcomer_grant"`
	IsLabGrant      bool           `json:"is_lab_grant"`
}

// Donor represents a participant in a quadratic funding round.
type Donor struct {
	ID             string `json:"id"`
	ClusterID      string `json:"cluster_id"`
	ZooRep         int64  `json:"zoo_rep"`
	RepTier        string `json:"rep_tier"`
	IsAttacker     bool   `json:"is_attacker"`
	IsNewcomer     bool   `json:"is_newcomer"`
	IsHonestLab    bool   `json:"is_honest_lab"`
	IsWhale        bool   `json:"is_whale"`
}

// Contribution records a single donor-to-project contribution in micro-ZOO.
type Contribution struct {
	DonorID    string `json:"donor_id"`
	ProjectID  string `json:"project_id"`
	AmountMicro int64 `json:"amount_micro_zoo"`
}

// AttackModel metadata states the exact adversarial assumptions for a scenario.
type AttackModel struct {
	Family              string `json:"family"`
	Description         string `json:"description"`
	AttackerCount       int    `json:"attacker_count"`
	SybilMultiplier     int    `json:"sybil_multiplier"`
	CollusionRingSize   int    `json:"collusion_ring_size"`
	DirectBudgetMicro   int64  `json:"direct_budget_micro_zoo"`
	IdentityCostMicro   int64  `json:"identity_cost_micro_zoo"`
	RepFarmCostMicro    int64  `json:"rep_farm_cost_micro_zoo"`
	BribeOverheadMicro  int64  `json:"bribe_overhead_micro_zoo"`
	TotalAttackCostMicro int64 `json:"total_attack_cost_micro_zoo"`
	ObfuscatedClusters  bool   `json:"obfuscated_clusters"`
}

// ScenarioSpec defines a complete, self-contained, deterministic funding round.
type ScenarioSpec struct {
	ID              string          `json:"id"`
	Title           string          `json:"title"`
	AttackModel     AttackModel     `json:"attack_model"`
	MatchingPool    int64           `json:"matching_pool_micro_zoo"`
	Params          MechanismParams `json:"params"`
	Proposals       []GrantProposal `json:"proposals"`
	Donors          []Donor         `json:"donors"`
	Contributions   []Contribution  `json:"contributions"`
}

// ProjectAllocation records the exact matching and direct funding for a project.
type ProjectAllocation struct {
	ProjectID       string `json:"project_id"`
	DirectMicro     int64  `json:"direct_micro_zoo"`
	MatchMicro      int64  `json:"match_micro_zoo"`
	TotalMicro      int64  `json:"total_micro_zoo"`
	UniqueDonors    int    `json:"unique_donors"`
	MatchShareBPS   int64  `json:"match_share_bps"`
}

// EvaluationMetrics captures exact integer-scaled metrics (in basis points) for a mechanism run.
type EvaluationMetrics struct {
	PoolConserved          bool  `json:"pool_conserved"`
	TotalMatchedMicro      int64 `json:"total_matched_micro_zoo"`
	UnallocatedPoolMicro   int64 `json:"unallocated_pool_micro_zoo"`
	AttackerMatchMicro     int64 `json:"attacker_match_micro_zoo"`
	PoolExtractionBPS      int64 `json:"pool_extraction_bps"`
	DirectCostROIBPS       int64 `json:"direct_cost_roi_bps"`
	NetAttackROIBPS        int64 `json:"net_attack_roi_bps"`
	MeritWelfareBPS        int64 `json:"merit_welfare_bps"`
	GrassrootsShareBPS     int64 `json:"grassroots_share_bps"`
	MinorityShareBPS       int64 `json:"minority_share_bps"`
	HonestGiniBPS          int64 `json:"honest_gini_bps"`
	LabShareBPS            int64 `json:"lab_share_bps"`
	NewcomerShareBPS       int64 `json:"newcomer_share_bps"`
	WhaleNicheShareBPS     int64 `json:"whale_niche_share_bps"`
}

// GovernanceSignOffRecord enforces HIP-1352 constitutional boundaries on AI agents
// and records required 3-of-5 human Treasury Committee sign-off state.
type GovernanceSignOffRecord struct {
	PlanStatus               string `json:"plan_status"`
	RequiredHumanQuorum      int    `json:"required_human_quorum"`
	TreasuryCommitteeSize    int    `json:"treasury_committee_size"`
	MinStewardZooRep         int64  `json:"min_steward_zoo_rep"`
	HumanSignaturesCollected int    `json:"human_signatures_collected"`
	AIRuleMutationBlocked    bool   `json:"ai_rule_mutation_blocked"`
	AITreasuryAuthBlocked    bool   `json:"ai_treasury_auth_blocked"`
	AISelfValidationBlocked  bool   `json:"ai_self_validation_blocked"`
}

// EvaluationResult is the deterministic output of running one mechanism on one scenario.
type EvaluationResult struct {
	ScenarioID      string                  `json:"scenario_id"`
	MechanismID     MechanismID             `json:"mechanism_id"`
	MatchingPool    int64                   `json:"matching_pool_micro_zoo"`
	Allocations     []ProjectAllocation     `json:"allocations"`
	Metrics         EvaluationMetrics       `json:"metrics"`
	GovernanceGate  GovernanceSignOffRecord `json:"governance_gate"`
	LeafHash        string                  `json:"leaf_hash"`
}

// GovernanceCheck audits a single constitutional gate decision.
type GovernanceCheck struct {
	CheckID      string `json:"check_id"`
	ActorID      string `json:"actor_id"`
	ActorRole    string `json:"actor_role"`
	ActorZooRep  int64  `json:"actor_zoo_rep"`
	Action       string `json:"action"`
	Allowed      bool   `json:"allowed"`
	ReasonCode   string `json:"reason_code"`
	HumanSigners int    `json:"human_signers"`
}

// ScenarioSummary provides compact scenario metadata for results.json while full donor
// and contribution matrices live in scenarios.json for independent replay verification.
type ScenarioSummary struct {
	ID                string          `json:"id"`
	Title             string          `json:"title"`
	AttackModel       AttackModel     `json:"attack_model"`
	MatchingPool      int64           `json:"matching_pool_micro_zoo"`
	Params            MechanismParams `json:"params"`
	ProposalCount     int             `json:"proposal_count"`
	DonorCount        int             `json:"donor_count"`
	ContributionCount int             `json:"contribution_count"`
}

// BenchmarkReport is the complete in-memory benchmark output.
type BenchmarkReport struct {
	SpecVersion       string             `json:"spec_version"`
	Seed              int64              `json:"seed"`
	MatchingPoolMicro int64              `json:"matching_pool_micro_zoo"`
	CorpusHash        string             `json:"corpus_hash"`
	GovernanceHash    string             `json:"governance_hash"`
	EvalMerkleRoot    string             `json:"eval_merkle_root"`
	AuditMerkleRoot   string             `json:"audit_merkle_root"`
	CorpusProposals   []GrantProposal    `json:"corpus_proposals"`
	GovernanceChecks  []GovernanceCheck  `json:"governance_checks"`
	Scenarios         []ScenarioSpec     `json:"scenarios"`
	Evaluations       []EvaluationResult `json:"evaluations"`
}

// ResultsArtifact is the human-readable exported results.json schema.
type ResultsArtifact struct {
	SpecVersion       string             `json:"spec_version"`
	Seed              int64              `json:"seed"`
	MatchingPoolMicro int64              `json:"matching_pool_micro_zoo"`
	CorpusHash        string             `json:"corpus_hash"`
	GovernanceHash    string             `json:"governance_hash"`
	EvalMerkleRoot    string             `json:"eval_merkle_root"`
	AuditMerkleRoot   string             `json:"audit_merkle_root"`
	CorpusProposals   []GrantProposal    `json:"corpus_proposals"`
	GovernanceChecks  []GovernanceCheck  `json:"governance_checks"`
	ScenarioSummaries []ScenarioSummary  `json:"scenario_summaries"`
	Evaluations       []EvaluationResult `json:"evaluations"`
}

// ScenariosArtifact is the exported scenarios.json containing complete raw round inputs
// for independent cross-language recomputation.
type ScenariosArtifact struct {
	SpecVersion string         `json:"spec_version"`
	Seed        int64          `json:"seed"`
	Scenarios   []ScenarioSpec `json:"scenarios"`
}

// ToArtifacts splits BenchmarkReport into clean ResultsArtifact and ScenariosArtifact.
func (r BenchmarkReport) ToArtifacts() (ResultsArtifact, ScenariosArtifact) {
	summaries := make([]ScenarioSummary, len(r.Scenarios))
	for i, sc := range r.Scenarios {
		summaries[i] = ScenarioSummary{
			ID:                sc.ID,
			Title:             sc.Title,
			AttackModel:       sc.AttackModel,
			MatchingPool:      sc.MatchingPool,
			Params:            sc.Params,
			ProposalCount:     len(sc.Proposals),
			DonorCount:        len(sc.Donors),
			ContributionCount: len(sc.Contributions),
		}
	}
	res := ResultsArtifact{
		SpecVersion:       r.SpecVersion,
		Seed:              r.Seed,
		MatchingPoolMicro: r.MatchingPoolMicro,
		CorpusHash:        r.CorpusHash,
		GovernanceHash:    r.GovernanceHash,
		EvalMerkleRoot:    r.EvalMerkleRoot,
		AuditMerkleRoot:   r.AuditMerkleRoot,
		CorpusProposals:   r.CorpusProposals,
		GovernanceChecks:  r.GovernanceChecks,
		ScenarioSummaries: summaries,
		Evaluations:       r.Evaluations,
	}
	scs := ScenariosArtifact{
		SpecVersion: r.SpecVersion,
		Seed:        r.Seed,
		Scenarios:   r.Scenarios,
	}
	return res, scs
}

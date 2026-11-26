// SPDX-License-Identifier: Apache-2.0

package qfsim

import (
	"math/big"
	"path/filepath"
	"sync"
	"testing"
)

func repoPapersRoot(t *testing.T) string {
	t.Helper()
	// internal/qfsim -> go -> reference -> zoo-dao-governance -> papers
	abs, err := filepath.Abs(filepath.Join("..", "..", "..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return abs
}

func TestBreadthOverDepthProposition(t *testing.T) {
	// Direct verification of Proposition 1 in zoo-dao-grants-program.tex:
	// 100 donors of 1 ZOO => M = (100*1)^2 - 100 = 9900; 1 donor of 100 ZOO => M = 0.
	proposals := []GrantProposal{
		{ID: "grant-broad", MeritBPS: 9000, Archetype: ArchetypeBroadPublicGood},
		{ID: "grant-single", MeritBPS: 5000, Archetype: ArchetypeWhaleNiche},
	}
	donors := make([]Donor, 0, 101)
	contribs := make([]Contribution, 0, 101)
	for i := 0; i < 100; i++ {
		id := "d-broad-" + string(rune('a'+(i/26))) + string(rune('a'+(i%26)))
		donors = append(donors, Donor{ID: id, ClusterID: id, ZooRep: 50, RepTier: "Contributor"})
		contribs = append(contribs, Contribution{DonorID: id, ProjectID: "grant-broad", AmountMicro: 1 * MicroZOO})
	}
	donors = append(donors, Donor{ID: "d-whale", ClusterID: "d-whale", ZooRep: 50, RepTier: "Contributor"})
	contribs = append(contribs, Contribution{DonorID: "d-whale", ProjectID: "grant-single", AmountMicro: 100 * MicroZOO})

	sc := ScenarioSpec{
		ID:            "test-breadth-over-depth",
		MatchingPool:  10_000 * MicroZOO,
		Params:        DefaultMechanismParams(),
		Proposals:     proposals,
		Donors:        donors,
		Contributions: contribs,
	}

	evCLR, err := EvaluateMechanism(sc, MechStandardCLRQF)
	if err != nil {
		t.Fatalf("standard CLR failed: %v", err)
	}
	if evCLR.Allocations[0].MatchMicro != 10_000*MicroZOO {
		t.Fatalf("expected broad grant to get 100%% of pool under CLR QF, got %d", evCLR.Allocations[0].MatchMicro)
	}
	if evCLR.Allocations[1].MatchMicro != 0 {
		t.Fatalf("expected single-donor grant to get 0 match under CLR QF, got %d", evCLR.Allocations[1].MatchMicro)
	}

	evLin, err := EvaluateMechanism(sc, MechLinearTokenMatching)
	if err != nil {
		t.Fatalf("linear matching failed: %v", err)
	}
	if evLin.Allocations[0].MatchMicro != 5_000*MicroZOO || evLin.Allocations[1].MatchMicro != 5_000*MicroZOO {
		t.Fatalf("expected 50/50 split under linear matching, got %d / %d",
			evLin.Allocations[0].MatchMicro, evLin.Allocations[1].MatchMicro)
	}
}

func TestAllocatePoolHamiltonConservationAndDeterminism(t *testing.T) {
	ids := []string{"p1", "p2", "p3"}
	weights := []*big.Int{big.NewInt(1), big.NewInt(1), big.NewInt(1)}
	alloc, unalloc := AllocatePoolHamilton(100, ids, weights)
	if unalloc != 0 {
		t.Fatalf("expected 0 unallocated, got %d", unalloc)
	}
	if alloc[0]+alloc[1]+alloc[2] != 100 {
		t.Fatalf("pool not conserved: %v", alloc)
	}
	// Tie-break by ID ASC => p1 gets the +1 remainder.
	if alloc[0] != 34 || alloc[1] != 33 || alloc[2] != 33 {
		t.Fatalf("unexpected deterministic tie-break: %v", alloc)
	}
}

func TestAllocatePoolCappedWaterFilling(t *testing.T) {
	ids := []string{"p1", "p2", "p3", "p4"}
	weights := []*big.Int{big.NewInt(1000), big.NewInt(10), big.NewInt(10), big.NewInt(10)}
	alloc, unalloc := AllocatePoolCapped(100, 30, ids, weights)
	if unalloc != 0 {
		t.Fatalf("expected 0 unallocated, got %d", unalloc)
	}
	sum := int64(0)
	for i, a := range alloc {
		if a > 30 {
			t.Fatalf("project %d exceeded cap 30: got %d", i, a)
		}
		sum += a
	}
	if sum != 100 {
		t.Fatalf("pool conservation violated: sum=%d", sum)
	}
	if alloc[0] != 30 {
		t.Fatalf("dominant project should hit exact cap 30, got %d", alloc[0])
	}
}

func TestZooRepTierMappingAlignsWithZIP0026(t *testing.T) {
	cases := []struct {
		rep     int64
		minGate int64
		minFP   int64
		want    int64
		tier    string
	}{
		{0, 10, 40_000, 40_000, "Observer"},
		{9, 10, 40_000, 40_000, "Observer"},
		{10, 10, 40_000, 400_000, "Observer"},
		{50, 10, 40_000, 480_000, "Contributor"},
		{200, 10, 40_000, 600_000, "Steward"},
		{500, 10, 40_000, 800_000, "Guardian"},
		{1000, 10, 40_000, 1_000_000, "Elder"},
		{49, 50, 0, 0, "Observer"},
	}
	for _, tc := range cases {
		if got := RepWeightFP(tc.rep, tc.minGate, tc.minFP); got != tc.want {
			t.Errorf("RepWeightFP(%d, %d, %d) = %d, want %d", tc.rep, tc.minGate, tc.minFP, got, tc.want)
		}
		if gotTier := RepTierName(tc.rep); gotTier != tc.tier {
			t.Errorf("RepTierName(%d) = %s, want %s", tc.rep, gotTier, tc.tier)
		}
	}
}

func TestConstitutionalAIGovernanceGate(t *testing.T) {
	suite := StandardConstitutionalAuditSuite()
	byID := make(map[string]GovernanceCheck, len(suite))
	for _, c := range suite {
		byID[c.CheckID] = c
	}

	// AI advisory actions allowed.
	for _, id := range []string{"gov-01-ai-recommend", "gov-02-ai-flag-conflict", "gov-03-ai-estimate-value"} {
		if !byID[id].Allowed || byID[id].ReasonCode != ReasonAllowedAdvisory {
			t.Fatalf("expected AI advisory action %s allowed, got %+v", id, byID[id])
		}
	}
	// AI rule mutation, treasury authorization, and self-validation MUST be blocked even if humanSigners=5.
	if byID["gov-04-ai-redefine-rules-denied"].Allowed || byID["gov-04-ai-redefine-rules-denied"].ReasonCode != ReasonDeniedAIRuleMutation {
		t.Fatalf("AI rule mutation must be blocked: %+v", byID["gov-04-ai-redefine-rules-denied"])
	}
	if byID["gov-05-ai-treasury-auth-denied"].Allowed || byID["gov-05-ai-treasury-auth-denied"].ReasonCode != ReasonDeniedAITreasuryAuth {
		t.Fatalf("AI treasury authorization must be blocked: %+v", byID["gov-05-ai-treasury-auth-denied"])
	}
	if byID["gov-06-ai-self-validate-denied"].Allowed || byID["gov-06-ai-self-validate-denied"].ReasonCode != ReasonDeniedAISelfValidate {
		t.Fatalf("AI self-validation must be blocked: %+v", byID["gov-06-ai-self-validate-denied"])
	}
	// Human 2-of-5 rejected, 3-of-5 allowed.
	if byID["gov-07-human-quorum-2of5-denied"].Allowed {
		t.Fatalf("2-of-5 quorum must be rejected")
	}
	if !byID["gov-08-human-quorum-3of5-allowed"].Allowed {
		t.Fatalf("3-of-5 human steward quorum must be allowed")
	}
}

func TestFullBenchmarkInvariantsAndNegativeRegimes(t *testing.T) {
	root := repoPapersRoot(t)
	report1, err := RunFullBenchmark(root, DefaultSeed)
	if err != nil {
		t.Fatalf("RunFullBenchmark #1 failed: %v", err)
	}
	report2, err := RunFullBenchmark(root, DefaultSeed)
	if err != nil {
		t.Fatalf("RunFullBenchmark #2 failed: %v", err)
	}

	if report1.AuditMerkleRoot != report2.AuditMerkleRoot {
		t.Fatalf("non-deterministic audit merkle root: %s vs %s", report1.AuditMerkleRoot, report2.AuditMerkleRoot)
	}
	if len(report1.CorpusProposals) != 12 {
		t.Fatalf("expected 12 real .tex corpus proposals, got %d", len(report1.CorpusProposals))
	}
	if len(report1.Scenarios) != 15 {
		t.Fatalf("expected 15 scenarios, got %d", len(report1.Scenarios))
	}
	if len(report1.Evaluations) != 90 {
		t.Fatalf("expected 90 evaluations (15x6), got %d", len(report1.Evaluations))
	}

	evalMap := make(map[string]EvaluationResult, len(report1.Evaluations))
	for _, ev := range report1.Evaluations {
		if !ev.Metrics.PoolConserved {
			t.Fatalf("pool not conserved for %s / %s", ev.ScenarioID, ev.MechanismID)
		}
		if ev.Metrics.UnallocatedPoolMicro != 0 {
			t.Fatalf("unexpected unallocated pool %d for %s / %s", ev.Metrics.UnallocatedPoolMicro, ev.ScenarioID, ev.MechanismID)
		}
		if ev.Metrics.TotalMatchedMicro != ev.MatchingPool {
			t.Fatalf("total matched %d != matching pool %d for %s / %s", ev.Metrics.TotalMatchedMicro, ev.MatchingPool, ev.ScenarioID, ev.MechanismID)
		}
		if !ev.GovernanceGate.AIRuleMutationBlocked || !ev.GovernanceGate.AITreasuryAuthBlocked || !ev.GovernanceGate.AISelfValidationBlocked {
			t.Fatalf("constitutional AI gate flags must all be true for %s / %s", ev.ScenarioID, ev.MechanismID)
		}
		evalMap[ev.ScenarioID+"::"+string(ev.MechanismID)] = ev
	}

	// Negative Regime #3: Identity-costless S=50 Sybil attack drains >70% of pool on uncapped Standard CLR QF.
	clrS50 := evalMap["sybil_identity_splitting_s50::standard_clr_qf"]
	if clrS50.Metrics.PoolExtractionBPS < 7000 {
		t.Fatalf("expected S=50 Sybil extraction >=70%% on uncapped CLR QF, got %.2f%%", float64(clrS50.Metrics.PoolExtractionBPS)/100.0)
	}
	// Hybrid COCM + Reputation + Cap collapses same-cluster Sybils to 0% extraction.
	hybS50 := evalMap["sybil_identity_splitting_s50::hybrid_cocm_reputation_capped_qf"]
	if hybS50.Metrics.PoolExtractionBPS != 0 {
		t.Fatalf("expected S=50 shared-cluster Sybil extraction == 0%% on hybrid COCM, got %d bps", hybS50.Metrics.PoolExtractionBPS)
	}
	// Capped QF bounds single-project extraction to <= 10% (1000 bps).
	capS50 := evalMap["sybil_identity_splitting_s50::capped_voting_qf"]
	if capS50.Metrics.PoolExtractionBPS > 1000 {
		t.Fatalf("expected capped QF extraction <= 1000 bps, got %d bps", capS50.Metrics.PoolExtractionBPS)
	}

	// Whale Plutocracy Capture: Linear token matching hands far more pool to whale than QF/Capped.
	whaleLin := evalMap["whale_plutocracy_capture::linear_token_matching"]
	whaleCap := evalMap["whale_plutocracy_capture::capped_voting_qf"]
	if whaleLin.Metrics.PoolExtractionBPS <= whaleCap.Metrics.PoolExtractionBPS*3 {
		t.Fatalf("expected linear whale capture (%d bps) >> capped QF (%d bps)", whaleLin.Metrics.PoolExtractionBPS, whaleCap.Metrics.PoolExtractionBPS)
	}

	// Sleeper Cartel C=30 exposes limits of pure reputation weighting vs Hybrid COCM.
	sleepRep := evalMap["reputation_farming_sleeper_cartel_c30::reputation_weighted_qf"]
	sleepHyb := evalMap["reputation_farming_sleeper_cartel_c30::hybrid_cocm_reputation_capped_qf"]
	if sleepRep.Metrics.PoolExtractionBPS <= sleepHyb.Metrics.PoolExtractionBPS*2 {
		t.Fatalf("expected sleeper cartel C=30 to extract much more on pure rep QF (%d bps) than hybrid COCM (%d bps)",
			sleepRep.Metrics.PoolExtractionBPS, sleepHyb.Metrics.PoolExtractionBPS)
	}

	// Negative Regime #1: Strict 50-ZooRep gate blocks Sybils to 0%, but starves newcomers to 0%.
	neg1Rep := evalMap["neg_regime_1_strict_rep_newcomer_starvation::reputation_weighted_qf"]
	neg1CLR := evalMap["neg_regime_1_strict_rep_newcomer_starvation::standard_clr_qf"]
	if neg1Rep.Metrics.PoolExtractionBPS != 0 {
		t.Fatalf("strict rep gate should block S=25 Sybils to 0%%, got %d bps", neg1Rep.Metrics.PoolExtractionBPS)
	}
	if neg1Rep.Metrics.NewcomerShareBPS != 0 {
		t.Fatalf("strict rep gate should starve 0-8 ZooRep newcomers to 0%%, got %d bps", neg1Rep.Metrics.NewcomerShareBPS)
	}
	if neg1CLR.Metrics.NewcomerShareBPS == 0 {
		t.Fatalf("standard CLR should fund newcomer grant in Negative Regime #1")
	}

	// Negative Regime #2: Tightly knit honest lab suffers false-positive suppression under Pairwise/COCM vs CLR.
	neg2CLR := evalMap["neg_regime_2_honest_lab_cocm_false_positive::standard_clr_qf"]
	neg2Pair := evalMap["neg_regime_2_honest_lab_cocm_false_positive::pairwise_bounded_qf"]
	neg2Hyb := evalMap["neg_regime_2_honest_lab_cocm_false_positive::hybrid_cocm_reputation_capped_qf"]
	if neg2Pair.Metrics.LabShareBPS >= neg2CLR.Metrics.LabShareBPS {
		t.Fatalf("expected pairwise QF lab share (%d bps) < CLR lab share (%d bps)", neg2Pair.Metrics.LabShareBPS, neg2CLR.Metrics.LabShareBPS)
	}
	if neg2Hyb.Metrics.LabShareBPS >= neg2CLR.Metrics.LabShareBPS {
		t.Fatalf("expected hybrid COCM lab share (%d bps) < CLR lab share (%d bps)", neg2Hyb.Metrics.LabShareBPS, neg2CLR.Metrics.LabShareBPS)
	}
}

func TestConcurrentEvaluationRaceSafety(t *testing.T) {
	root := repoPapersRoot(t)
	corpus, err := LoadGrantCorpus(root)
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	scenarios := BuildBenchmarkScenarios(DefaultSeed, corpus)
	sc := scenarios[0]
	mechs := AllMechanisms()

	var wg sync.WaitGroup
	results := make([]EvaluationResult, len(mechs))
	errs := make([]error, len(mechs))
	for i, m := range mechs {
		wg.Add(1)
		go func(idx int, mech MechanismID) {
			defer wg.Done()
			results[idx], errs[idx] = EvaluateMechanism(sc, mech)
		}(i, m)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent eval %d failed: %v", i, err)
		}
		if !results[i].Metrics.PoolConserved {
			t.Fatalf("concurrent eval %d violated conservation", i)
		}
	}
}

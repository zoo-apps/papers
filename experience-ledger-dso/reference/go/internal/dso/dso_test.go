// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation

package dso

import (
	"math"
	"path/filepath"
	"sync"
	"testing"
)

func repoRootPath(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", "..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return abs
}

func TestEd25519SignVerifyAndTamperRejection(t *testing.T) {
	id := DeriveNodeIdentity(1352, 0)
	paper := PaperDoc{
		RelPath: "zoo-consensus/zoo-consensus.tex",
		Domain:  DomainProtocol,
		SHA256:  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	exp := SynthesizeExperienceOp(paper, DomainProtocol, 1, id.NodeID, "honest_majority", 0.9)
	var delta [FeatureDim]float64
	delta[0] = 0.25
	delta[1] = -0.15

	env := SignContribution(id, ContributionBody{
		Round:      1,
		Domain:     DomainProtocol,
		Experience: exp,
		DeltaMicro: VecToMicro(delta),
	}, RoleHonestMajority)

	if err := VerifyContribution(env); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}

	// Tamper 1: modify delta micro without re-signing
	badDelta := env
	badDelta.Body.DeltaMicro = append([]int64(nil), env.Body.DeltaMicro...)
	badDelta.Body.DeltaMicro[0] += 1
	if err := VerifyContribution(badDelta); err == nil {
		t.Fatal("expected error on tampered delta_micro")
	}

	// Tamper 2: modify experience text
	badText := env
	badText.Body.Experience.Text += " tampered"
	if err := VerifyContribution(badText); err == nil {
		t.Fatal("expected error on tampered experience text")
	}

	// Tamper 3: flip signature byte
	badSig := env
	sigBytes := []byte(badSig.SignatureHex)
	if sigBytes[0] == 'a' {
		sigBytes[0] = 'b'
	} else {
		sigBytes[0] = 'a'
	}
	badSig.SignatureHex = string(sigBytes)
	if err := VerifyContribution(badSig); err == nil {
		t.Fatal("expected error on corrupted signature")
	}
}

func TestValidateExperienceSchema(t *testing.T) {
	valid := ExperienceOp{
		ID:              "exp_sha256_0011223344556677",
		Op:              "Add",
		Domain:          DomainConservation,
		Text:            "When evaluating wildlife habitat trajectories, validate bounded ecological constraints against held-out observations.",
		ConfidenceMicro: 880_000,
		PaperPath:       "zoo-habitat-modeling/zoo-habitat-modeling.tex",
		PaperSHA256:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	if err := ValidateExperienceSchema(valid); err != nil {
		t.Fatalf("valid experience failed schema: %v", err)
	}

	tooLong := valid
	tooLong.Text = "When evaluating one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty twentyone twentytwo twentythree twentyfour twentyfive twentysix twentyseven twentyeight twentynine thirty thirtyone thirtytwo"
	if err := ValidateExperienceSchema(tooLong); err == nil {
		t.Fatal("expected word-count > 32 to fail schema validation")
	}

	nonActionable := valid
	nonActionable.Text = "maybe try random things sometimes and ignore paper details because anything works"
	if err := ValidateExperienceSchema(nonActionable); err == nil {
		t.Fatal("expected non-actionable text to fail schema validation")
	}

	badOp := valid
	badOp.Op = "Overwrite"
	if err := ValidateExperienceSchema(badOp); err == nil {
		t.Fatal("expected invalid op to fail schema validation")
	}

	badDomain := valid
	badDomain.Domain = "unknown_domain"
	if err := ValidateExperienceSchema(badDomain); err == nil {
		t.Fatal("expected invalid domain to fail schema validation")
	}
}

func TestFairnessMetricsMath(t *testing.T) {
	// Equal weights -> Jain = 1.0, Gini = 0.0
	eq := []float64{1, 1, 1, 1, 1}
	if j := JainsFairnessIndex(eq); math.Abs(j-1.0) > 1e-9 {
		t.Fatalf("expected Jain=1.0 for equal weights, got %f", j)
	}
	if g := GiniCoefficient(eq); math.Abs(g-0.0) > 1e-9 {
		t.Fatalf("expected Gini=0.0 for equal weights, got %f", g)
	}

	// Monopoly (1 node has all weight out of 4) -> Jain = 0.25, Gini = 0.75
	mono := []float64{1, 0, 0, 0}
	if j := JainsFairnessIndex(mono); math.Abs(j-0.25) > 1e-9 {
		t.Fatalf("expected Jain=0.25 for 4-node monopoly, got %f", j)
	}
	if g := GiniCoefficient(mono); math.Abs(g-0.75) > 1e-9 {
		t.Fatalf("expected Gini=0.75 for 4-node monopoly, got %f", g)
	}

	// All zero -> Jain = 0.0, Gini = 1.0 (total erasure)
	zeros := []float64{0, 0, 0}
	if j := JainsFairnessIndex(zeros); j != 0.0 {
		t.Fatalf("expected Jain=0.0 for all zeros, got %f", j)
	}
	if g := GiniCoefficient(zeros); g != 1.0 {
		t.Fatalf("expected Gini=1.0 for all zeros, got %f", g)
	}
}

func TestSybilFreeRiderClusterDiscounting(t *testing.T) {
	// Verify that 6 near-identical Sybil clones with positive held-out gain receive
	// discounted per-member weight (total cluster weight ~= 1 independent honest contributor).
	valProto := []Example{
		{Domain: DomainProtocol, Label: 1, Features: [FeatureDim]float64{1.0, 0.2}},
		{Domain: DomainProtocol, Label: -1, Features: [FeatureDim]float64{-1.0, -0.2}},
		{Domain: DomainProtocol, Label: 1, Features: [FeatureDim]float64{0.8, 0.4}},
	}
	valCons := []Example{
		{Domain: DomainConservation, Label: 1, Features: [FeatureDim]float64{0, 0}},
	}
	valCons[0].Features[ConsStart] = 1.0

	var base [FeatureDim]float64
	paper := PaperDoc{
		RelPath: "zoo-consensus/zoo-consensus.tex",
		Domain:  DomainProtocol,
		SHA256:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}

	// 1 independent honest contributor (index 0) + 6 near-identical Sybil clones (indices 1..6)
	var envs []ContributionEnvelope
	reps := make([]float64, 7)
	for i := 0; i < 7; i++ {
		reps[i] = 1.0
		id := DeriveNodeIdentity(99, i)
		var delta [FeatureDim]float64
		if i == 0 {
			// Independent honest direction
			delta[0] = 0.50
			delta[1] = 0.50
		} else {
			// 6 near-identical Sybil clones (cos > 0.999)
			delta[0] = 0.70
			delta[1] = 0.05 + float64(i)*0.0001
		}
		exp := SynthesizeExperienceOp(paper, DomainProtocol, 1, id.NodeID, "honest_majority", 0.9)
		envs = append(envs, SignContribution(id, ContributionBody{
			Round:      1,
			Domain:     DomainProtocol,
			Experience: exp,
			DeltaMicro: VecToMicro(delta),
		}, RoleHonestMajority))
	}

	cfg := DefaultAggregationConfig()
	res := AggregateRound(AggDSOReputationEvalGated, envs, base, reps, valProto, valCons, cfg)

	if res.ClusterSizes[0] != 1 {
		t.Fatalf("expected independent node cluster size 1, got %d", res.ClusterSizes[0])
	}
	var sybilWeightSum float64
	for i := 1; i < 7; i++ {
		if res.ClusterSizes[i] != 6 {
			t.Fatalf("expected Sybil clone %d cluster size 6, got %d", i, res.ClusterSizes[i])
		}
		sybilWeightSum += res.Weights[i]
	}
	// Combined weight of all 6 clones must not exceed ~1.5x the single independent node's weight
	// (without discounting, 6 clones would have ~6x the weight!).
	if sybilWeightSum > res.Weights[0]*1.5 {
		t.Fatalf("Sybil cluster discounting failed: independent=%.4f, 6-clone sum=%.4f", res.Weights[0], sybilWeightSum)
	}
}

var (
	sharedCorpusOnce sync.Once
	sharedCorpusDS   *CorpusDataset
	sharedCorpusErr  error
)

func getSharedCorpus(t *testing.T) *CorpusDataset {
	t.Helper()
	sharedCorpusOnce.Do(func() {
		root := repoRootPath(t)
		sharedCorpusDS, sharedCorpusErr = LoadGroundedCorpus(root, 1352)
		if sharedCorpusErr == nil {
			quantizeExamplesMicro(sharedCorpusDS.ValProtocol)
			quantizeExamplesMicro(sharedCorpusDS.ValConservation)
		}
	})
	if sharedCorpusErr != nil {
		t.Fatalf("LoadGroundedCorpus failed: %v", sharedCorpusErr)
	}
	return sharedCorpusDS
}

func TestInvalidSignatureExclusionAcrossAllAggregators(t *testing.T) {
	ds := getSharedCorpus(t)
	cfg := DefaultAggregationConfig()
	roster := buildNodeRoster(1352, 10, ScenarioAdversarialSemantic, 0.20)
	rng := makeCellRNG(1352, "invalid-sig-exclusion")
	var base [FeatureDim]float64
	envs := generateRoundEnvelopes(ds, roster, ScenarioAdversarialSemantic, 1, base, rng, false)

	// Corrupt signatures on nodes 8 and 9
	envs[8].SignatureHex = "00" + envs[8].SignatureHex[2:]
	envs[9].Body.DeltaMicro[0] += 999_999

	reps := make([]float64, len(envs))
	for i := range reps {
		reps[i] = 1.0
	}

	for _, agg := range AllAggregators {
		res := AggregateRound(agg, envs, base, reps, ds.ValProtocol, ds.ValConservation, cfg)
		if res.InvalidSigCount != 2 {
			t.Fatalf("%s: expected 2 invalid signatures excluded, got %d", agg, res.InvalidSigCount)
		}
		if res.Accepted[8] || res.Accepted[9] {
			t.Fatalf("%s: tampered envelopes must never be accepted", agg)
		}
		if res.Weights[8] != 0 || res.Weights[9] != 0 {
			t.Fatalf("%s: tampered envelopes must receive zero weight", agg)
		}
	}
}

func TestMultiKrumCartelCaptureAtHighCollusion(t *testing.T) {
	ds := getSharedCorpus(t)
	cfg := DefaultAggregationConfig()
	mk50, _ := RunSingleCell(ds, 1352, ScenarioColludingCartel, 0.50, AggMultiKrum, DefaultNumNodes, 6, cfg, 0.84)
	dso50, _ := RunSingleCell(ds, 1352, ScenarioColludingCartel, 0.50, AggDSOReputationEvalGated, DefaultNumNodes, 6, cfg, 0.84)

	if mk50.AdversarialAdmissionRate < 0.90 {
		t.Fatalf("expected Multi-Krum to be captured by 50%% tight Sybil cartel, got advAdm=%.3f", mk50.AdversarialAdmissionRate)
	}
	if dso50.AdversarialAdmissionRate > 0.05 {
		t.Fatalf("expected DSO eval-gated to block 50%% tight Sybil cartel, got advAdm=%.3f", dso50.AdversarialAdmissionRate)
	}
}

func TestCanonicalMerkleRootDeterminism(t *testing.T) {
	empty1 := ComputeMerkleRoot(nil)
	empty2 := ComputeMerkleRoot([]string{})
	if empty1 != empty2 || len(empty1) != 64 {
		t.Fatalf("empty Merkle root mismatch: %s vs %s", empty1, empty2)
	}
	a := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	b := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	c := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	r1 := ComputeMerkleRoot([]string{a, b, c})
	r2 := ComputeMerkleRoot([]string{a, b, c})
	r3 := ComputeMerkleRoot([]string{a, c, b})
	if r1 != r2 {
		t.Fatal("Merkle root must be deterministic")
	}
	if r1 == r3 {
		t.Fatal("Merkle root must be order-sensitive")
	}
}

func TestGroundedCorpusDeterminismAndNegativeRegimes(t *testing.T) {
	ds := getSharedCorpus(t)

	if len(ds.Papers) < 80 {
		t.Fatalf("expected >= 80 grounded .tex papers, got %d", len(ds.Papers))
	}
	if ds.ConservPaperCount < 10 || ds.ProtocolPaperCount < 50 {
		t.Fatalf("unexpected domain paper split: proto=%d cons=%d", ds.ProtocolPaperCount, ds.ConservPaperCount)
	}

	cfg := DefaultAggregationConfig()

	// Determinism check: identical seed produces bit-identical final weights digest & leaf hash.
	c1, _ := RunSingleCell(ds, 1352, ScenarioHonestDisagreement, 0.30, AggDSOReputationEvalGated, DefaultNumNodes, 6, cfg, 0.85)
	c2, _ := RunSingleCell(ds, 1352, ScenarioHonestDisagreement, 0.30, AggDSOReputationEvalGated, DefaultNumNodes, 6, cfg, 0.85)
	if c1.FinalWeightsDigestSHA256 != c2.FinalWeightsDigestSHA256 {
		t.Fatalf("non-deterministic final weights digest: %s != %s", c1.FinalWeightsDigestSHA256, c2.FinalWeightsDigestSHA256)
	}
	if CanonicalCellLeafHash(c1) != CanonicalCellLeafHash(c2) {
		t.Fatalf("non-deterministic canonical cell leaf hash")
	}

	// Negative Regime 1: Minority erasure at f=0% under honest disagreement.
	mk0, _ := RunSingleCell(ds, 1352, ScenarioHonestDisagreement, 0.0, AggMultiKrum, DefaultNumNodes, DefaultNumRounds, cfg, 0.83)
	dso0, _ := RunSingleCell(ds, 1352, ScenarioHonestDisagreement, 0.0, AggDSOReputationEvalGated, DefaultNumNodes, DefaultNumRounds, cfg, 0.83)
	if mk0.MinorityHonestAcceptanceRate > 0.05 {
		t.Fatalf("expected Multi-Krum minority erasure at f=0%%, got %.3f", mk0.MinorityHonestAcceptanceRate)
	}
	if dso0.MinorityHonestAcceptanceRate < 0.90 {
		t.Fatalf("expected DSO eval-gated high minority acceptance at f=0%%, got %.3f", dso0.MinorityHonestAcceptanceRate)
	}
	if dso0.MinorityTestAccuracy <= mk0.MinorityTestAccuracy+0.10 {
		t.Fatalf("expected DSO minority accuracy >> Multi-Krum at f=0%%: dso=%.3f mk=%.3f", dso0.MinorityTestAccuracy, mk0.MinorityTestAccuracy)
	}

	// Negative Regime 2: Unmonitored trigger backdoor fools even eval-gated aggregation.
	neg2 := RunNegativeRegime2(ds, 1352, cfg)
	foundDSOBackdoor := false
	for _, r := range neg2 {
		if r.Aggregator == AggDSOReputationEvalGated && r.AdversaryFraction == 0.20 {
			foundDSOBackdoor = true
			if r.BackdoorAttackSuccessRate < 0.85 {
				t.Fatalf("expected unmonitored trigger backdoor ASR >= 0.85 on eval-gated, got %.3f", r.BackdoorAttackSuccessRate)
			}
		}
	}
	if !foundDSOBackdoor {
		t.Fatal("missing dso_reputation_eval_gated entry in Negative Regime 2")
	}

	// Negative Regime 3: 66% committee liveness collapse at f>=40% and static-eval Goodhart overfitting.
	neg3 := RunNegativeRegime3(ds, 1352, cfg)
	checkedCollapse := false
	checkedOverfit := false
	for _, r := range neg3 {
		if r.Mode == "decentralized_committee_66pct_supermajority" && r.AdversaryFraction == 0.40 {
			checkedCollapse = true
			if r.HonestLivenessRate > 0.05 {
				t.Fatalf("expected 66%% committee liveness collapse at f=40%%, got %.3f", r.HonestLivenessRate)
			}
		}
		if r.Mode == "static_small_eval_goodhart_overfit_30r" {
			checkedOverfit = true
			if r.GoodhartOverfitGap < 0.15 {
				t.Fatalf("expected Goodhart overfit gap >= 0.15, got %.3f", r.GoodhartOverfitGap)
			}
		}
	}
	if !checkedCollapse || !checkedOverfit {
		t.Fatalf("missing Negative Regime 3 assertions: collapse=%v overfit=%v", checkedCollapse, checkedOverfit)
	}
}

func TestConcurrentAggregationRaceFree(t *testing.T) {
	ds := getSharedCorpus(t)
	cfg := DefaultAggregationConfig()

	roster := buildNodeRoster(1352, DefaultNumNodes, ScenarioColludingCartel, 0.30)
	rng := makeCellRNG(1352, "race-test")
	var base [FeatureDim]float64
	envs := generateRoundEnvelopes(ds, roster, ScenarioColludingCartel, 1, base, rng, false)
	reps := make([]float64, DefaultNumNodes)
	for i := range reps {
		reps[i] = 1.0
	}

	var wg sync.WaitGroup
	digests := make([]string, len(AllAggregators))
	for idx, agg := range AllAggregators {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			res := AggregateRound(name, envs, base, reps, ds.ValProtocol, ds.ValConservation, cfg)
			digests[i] = HashVectorMicro(res.AggregatedDelta)
		}(idx, agg)
	}
	wg.Wait()

	for i, d := range digests {
		if len(d) != 64 {
			t.Fatalf("aggregator %s returned invalid digest %q", AllAggregators[i], d)
		}
	}
}

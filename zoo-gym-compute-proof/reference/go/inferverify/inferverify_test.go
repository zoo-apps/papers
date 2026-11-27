// Copyright 2026 Zoo Labs Foundation / Hanzo Industries.
// Licensed under the Apache License, Version 2.0.

package inferverify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

func loadTestCorpus(t *testing.T) *LoadedCorpus {
	t.Helper()
	repoRoot := filepath.Join("..", "..", "..", "..")
	manifestPath := filepath.Join("..", "..", "corpus-manifest.json")
	corpus, err := LoadAndVerifyCorpus(repoRoot, manifestPath)
	if err != nil {
		t.Fatalf("LoadAndVerifyCorpus failed: %v", err)
	}
	return corpus
}

func TestCorpusLoadingAndDeterministicMLP(t *testing.T) {
	corpus := loadTestCorpus(t)
	if len(corpus.Manifest.Files) != 7 {
		t.Fatalf("expected 7 corpus files, got %d", len(corpus.Manifest.Files))
	}
	if len(corpus.Vocab) != ModelVocabSize {
		t.Fatalf("expected vocab size %d, got %d", ModelVocabSize, len(corpus.Vocab))
	}

	m1 := NewQuantizedMLP(corpus.CorpusRootSHA256, DefaultModelID)
	m2 := NewQuantizedMLP(corpus.CorpusRootSHA256, DefaultModelID)
	if m1.ModelDigest != m2.ModelDigest {
		t.Fatalf("non-deterministic model digest: %s != %s", m1.ModelDigest, m2.ModelDigest)
	}

	tokens := corpus.TokenStream[:PromptLen]
	out1 := m1.ForwardHonest("det-job-1", tokens, 2)
	out2 := m2.ForwardHonest("det-job-1", tokens, 2)
	if out1.OutputDigest != out2.OutputDigest || out1.LogitsDigest != out2.LogitsDigest || out1.TopToken != out2.TopToken {
		t.Fatalf("non-deterministic forward pass")
	}

	lazy := m1.ForwardLazyDummy("det-job-1", tokens, 2)
	if lazy.OutputDigest == out1.OutputDigest {
		t.Fatalf("lazy dummy output unexpectedly matched honest MLP output")
	}
}

func TestDSSEPAEAndEd25519TamperDetection(t *testing.T) {
	corpus := loadTestCorpus(t)
	rig := NewTestRig(1350, corpus, DefaultPolicy())
	worker := rig.Actors["worker-alpha-1"]
	tokens := rig.PromptForIndex(3)
	out := rig.Model.ForwardHonest("dsse-job-1", tokens, 1)
	stmt := rig.BuildWorkerStatement("dsse-job-1", 10, RegimeSignedAttestationOnly, 1, out, worker, ActionNone)

	env, err := SignDSSE(stmt, worker.PrivKey)
	if err != nil {
		t.Fatalf("SignDSSE failed: %v", err)
	}
	if _, _, code := VerifyDSSESignature(env, worker.Entry.PubKeyHex); code != ErrNone {
		t.Fatalf("expected valid DSSE sig, got %s", code)
	}

	// Wrong public key must fail
	other := rig.Actors["worker-beta-2"]
	if _, _, code := VerifyDSSESignature(env, other.Entry.PubKeyHex); code != ErrInvalidDSSESig {
		t.Fatalf("expected %s for wrong pubkey, got %s", ErrInvalidDSSESig, code)
	}

	// Wrong payloadType must fail
	badEnv := env
	badEnv.PayloadType = "application/json"
	if _, _, code := VerifyDSSESignature(badEnv, worker.Entry.PubKeyHex); code != ErrInvalidPayloadType {
		t.Fatalf("expected %s for wrong payloadType, got %s", ErrInvalidPayloadType, code)
	}
}

func TestRFC6962InclusionProofsAllTreeSizes(t *testing.T) {
	// Exhaustively test every leaf index for tree sizes 1..65 (powers of two and odd sizes).
	for n := 1; n <= 65; n++ {
		tlog := NewTransparencyLog(1350)
		for i := 0; i < n; i++ {
			sum := sha256.Sum256([]byte(fmt.Sprintf("leaf-%d-%d", n, i)))
			tlog.Append(hex.EncodeToString(sum[:]))
		}
		trust := TrustRoot{TLogID: tlog.LogID, TLogPubKeyHex: tlog.PubKeyHex}
		for idx := 0; idx < n; idx++ {
			bundle, err := tlog.BundleForIndex(idx, 7)
			if err != nil {
				t.Fatalf("n=%d idx=%d BundleForIndex failed: %v", n, idx, err)
			}
			if code := VerifyTransparencyLogBundle(bundle, string(tlog.Leaves[idx]), 7, trust); code != ErrNone {
				t.Fatalf("n=%d idx=%d VerifyTransparencyLogBundle failed: %s", n, idx, code)
			}
			// Mutate root hash and verify rejection
			bad := *bundle
			bad.RootHash = hex.EncodeToString(make([]byte, 32))
			if code := VerifyTransparencyLogBundle(&bad, string(tlog.Leaves[idx]), 7, trust); code != ErrInvalidTLogCheckpointSig {
				t.Fatalf("n=%d idx=%d expected checkpoint sig failure on mutated root, got %s", n, idx, code)
			}
		}
	}
}

func TestEconomicIncentiveCompatibilityBoundary(t *testing.T) {
	// fee=10, honest=5, cheat=0.25 => cheatGain=4.75
	// At p=0.01, S=20 => p*(fee+S) = 0.30 < 4.75 => NOT incentive compatible
	bad := AnalyzeEconomics(0.01, 10.0, 5.0, 0.25, 20.0)
	if bad.IncentiveCompatible {
		t.Fatalf("expected undercollateralized challenge to fail IC")
	}
	if bad.CheatAdvantage <= 0 {
		t.Fatalf("expected positive cheating advantage, got %f", bad.CheatAdvantage)
	}

	// At p=0.05, S=150 => p*(fee+S) = 8.0 > 4.75 => incentive compatible
	good := AnalyzeEconomics(0.05, 10.0, 5.0, 0.25, 150.0)
	if !good.IncentiveCompatible || !good.StrictSlashOnlyIC {
		t.Fatalf("expected well-collateralized challenge to be strictly IC")
	}
	if good.CheatAdvantage >= 0 {
		t.Fatalf("expected strictly negative cheating advantage, got %f", good.CheatAdvantage)
	}
}

func TestHybridRiskAdaptiveEscalation(t *testing.T) {
	policy := DefaultPolicy()
	goodWorker := WorkerRiskContext{ReputationScore: 950, JobsCompleted: 100, AIAdvisoryFlagged: false}
	newWorker := WorkerRiskContext{ReputationScore: 950, JobsCompleted: 5, AIAdvisoryFlagged: false}
	lowRepWorker := WorkerRiskContext{ReputationScore: 500, JobsCompleted: 100, AIAdvisoryFlagged: false}
	flaggedWorker := WorkerRiskContext{ReputationScore: 950, JobsCompleted: 100, AIAdvisoryFlagged: true}

	if got := EffectiveChallengeBPS(RegimeHybridAttestedChal, goodWorker, policy, nil); got != policy.ChallengeBaseBPS {
		t.Fatalf("expected base BPS %d for established honest worker, got %d", policy.ChallengeBaseBPS, got)
	}
	for name, risk := range map[string]WorkerRiskContext{
		"probationary": newWorker,
		"low_rep":      lowRepWorker,
		"ai_flagged":   flaggedWorker,
	} {
		if got := EffectiveChallengeBPS(RegimeHybridAttestedChal, risk, policy, nil); got != policy.ChallengeEscalatedBPS {
			t.Fatalf("%s: expected escalated BPS %d, got %d", name, policy.ChallengeEscalatedBPS, got)
		}
	}
}

func TestParitySuiteAll225CasesAndDeterminism(t *testing.T) {
	corpus := loadTestCorpus(t)
	suite1, audit1, err := BuildParitySuite(1350, corpus)
	if err != nil {
		t.Fatalf("BuildParitySuite(1350) failed: %v", err)
	}
	if audit1.GoldenCases != 200 || audit1.AdversarialCase != 25 || audit1.TotalCases != 225 {
		t.Fatalf("unexpected case counts: golden=%d adv=%d total=%d", audit1.GoldenCases, audit1.AdversarialCase, audit1.TotalCases)
	}
	if audit1.MatchesExpected != audit1.TotalCases {
		for i, r := range audit1.Results {
			c := suite1.Cases[i]
			if r.Verdict != c.ExpectedVerdict || r.ErrorCode != c.ExpectedErrorCode || r.FraudEscaped != c.ExpectedFraudEscaped {
				t.Errorf("case %s mismatch: got (%s,%s,escaped=%v) want (%s,%s,escaped=%v)",
					c.CaseID, r.Verdict, r.ErrorCode, r.FraudEscaped, c.ExpectedVerdict, c.ExpectedErrorCode, c.ExpectedFraudEscaped)
			}
		}
		t.Fatalf("only %d / %d cases matched expected", audit1.MatchesExpected, audit1.TotalCases)
	}

	// Second build must yield bit-identical audit_merkle_root
	_, audit2, err := BuildParitySuite(1350, corpus)
	if err != nil {
		t.Fatalf("second BuildParitySuite failed: %v", err)
	}
	if audit1.AuditMerkleRoot != audit2.AuditMerkleRoot {
		t.Fatalf("non-deterministic audit_merkle_root: %s != %s", audit1.AuditMerkleRoot, audit2.AuditMerkleRoot)
	}
}

func TestConcurrentVerificationRaceFree(t *testing.T) {
	corpus := loadTestCorpus(t)
	suite, expectedAudit, err := BuildParitySuite(1350, corpus)
	if err != nil {
		t.Fatalf("BuildParitySuite failed: %v", err)
	}
	model := NewQuantizedMLP(suite.CorpusRootSHA256, suite.ModelID)

	var wg sync.WaitGroup
	errs := make(chan string, len(suite.Cases))
	for i, tc := range suite.Cases {
		wg.Add(1)
		go func(idx int, c VerificationCase) {
			defer wg.Done()
			res := VerifyCase(c, model, suite.TrustRoot, suite.Policy)
			if res.AuditLeafDigest != expectedAudit.Results[idx].AuditLeafDigest {
				errs <- fmt.Sprintf("case %s leaf digest mismatch under concurrency", c.CaseID)
			}
		}(i, tc)
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Fatal(msg)
	}
}

func TestThreeHonestNegativeRegimes(t *testing.T) {
	corpus := loadTestCorpus(t)
	report, _, err := RunFullBenchmark(1350, corpus)
	if err != nil {
		t.Fatalf("RunFullBenchmark failed: %v", err)
	}
	if len(report.NegativeRegimes) != 3 {
		t.Fatalf("expected 3 negative regimes, got %d", len(report.NegativeRegimes))
	}

	// Neg 1: Attestation-only must have 0% cheat detection against valid-key cheater
	neg1 := report.NegativeRegimes[0]
	if det, ok := neg1.Metrics["cheat_detection_rate_pct"].(float64); !ok || det != 0.0 {
		t.Fatalf("expected 0%% detection in neg1, got %v", neg1.Metrics["cheat_detection_rate_pct"])
	}

	// Neg 2: Undercollateralized challenge must have positive cheating advantage
	neg2 := report.NegativeRegimes[1]
	if adv, ok := neg2.Metrics["cheating_advantage_per_job"].(float64); !ok || adv <= 0.0 {
		t.Fatalf("expected positive cheating advantage in neg2, got %v", neg2.Metrics["cheating_advantage_per_job"])
	}

	// Neg 3: Full k=3 re-execution must incur 3.0x compute multiplier on honest bulk workload
	neg3 := report.NegativeRegimes[2]
	if mult, ok := neg3.Metrics["reexec_k3_compute_multiplier"].(float64); !ok || mult != 3.0 {
		t.Fatalf("expected 3.0x compute multiplier in neg3, got %v", neg3.Metrics["reexec_k3_compute_multiplier"])
	}
}

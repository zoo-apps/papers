// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package forkorg

import (
	"sync"
	"testing"
)

func TestCanonicalJSONDeterminism(t *testing.T) {
	a := map[string]any{"b": int64(2), "a": "x<y>&z", "c": []int64{1, 2, 3}}
	b := map[string]any{"c": []int64{1, 2, 3}, "a": "x<y>&z", "b": int64(2)}
	ja, err := CanonicalJSON(a)
	if err != nil {
		t.Fatalf("CanonicalJSON(a): %v", err)
	}
	jb, err := CanonicalJSON(b)
	if err != nil {
		t.Fatalf("CanonicalJSON(b): %v", err)
	}
	expected := `{"a":"x<y>&z","b":2,"c":[1,2,3]}`
	if string(ja) != expected {
		t.Fatalf("got %s, want %s", string(ja), expected)
	}
	if string(ja) != string(jb) {
		t.Fatalf("non-deterministic canonical JSON: %s != %s", string(ja), string(jb))
	}
}

func TestRFC6962MerkleRoot(t *testing.T) {
	empty := MerkleRootRFC6962(nil)
	if empty != SHA256Hex(nil) {
		t.Fatalf("empty root mismatch: %s", empty)
	}
	r1 := MerkleRootRFC6962([]string{"leaf-a", "leaf-b", "leaf-c"})
	r2 := MerkleRootRFC6962([]string{"leaf-a", "leaf-b", "leaf-c"})
	if r1 != r2 {
		t.Fatalf("merkle root non-deterministic")
	}
	r3 := MerkleRootRFC6962([]string{"leaf-a", "leaf-c", "leaf-b"})
	if r1 == r3 {
		t.Fatalf("merkle root order-insensitive")
	}
}

func TestBitDeltaCompressionAndOptimalScale(t *testing.T) {
	base := make([]int64, DefaultModelDim)
	fine := make([]int64, DefaultModelDim)
	var sumAbs int64
	for i := range base {
		base[i] = int64(i * 1000)
		diff := int64(50_000)
		if i%2 == 1 {
			diff = -30_000
		}
		fine[i] = base[i] + diff
		if diff >= 0 {
			sumAbs += diff
		} else {
			sumAbs += -diff
		}
	}
	signHex, scale := CompressBitDelta(base, fine)
	wantScale := sumAbs / DefaultModelDim
	if scale != wantScale {
		t.Fatalf("scale=%d, want %d", scale, wantScale)
	}
	if len(signHex) != int((DefaultModelDim+7)/8)*2 {
		t.Fatalf("unexpected sign hex len=%d", len(signHex))
	}
	reconstructed, err := ApplyBitDelta(base, BitDeltaArtifact{
		Dim:         DefaultModelDim,
		SignBitsHex: signHex,
		ScaleMicro:  scale,
	})
	if err != nil {
		t.Fatalf("ApplyBitDelta: %v", err)
	}
	for i := range base {
		delta := reconstructed[i] - base[i]
		if i%2 == 0 && delta != scale {
			t.Fatalf("idx %d: got delta %d, want +%d", i, delta, scale)
		}
		if i%2 == 1 && delta != -scale {
			t.Fatalf("idx %d: got delta %d, want -%d", i, delta, scale)
		}
	}
}

func TestDeltaSoupRoyaltiesSumExact10000(t *testing.T) {
	_, royalties := BuildCanonicalSuite(1352)
	if len(royalties) != 7 {
		t.Fatalf("expected 7 honest contributors, got %d", len(royalties))
	}
	var sum int64
	for _, r := range royalties {
		if r.WeightBps <= 0 {
			t.Fatalf("non-positive royalty share for %s: %d", r.ContributorID, r.WeightBps)
		}
		sum += r.WeightBps
	}
	if sum != BpsScale {
		t.Fatalf("royalty sum = %d, want %d", sum, BpsScale)
	}
}

func TestEndToEndForkDivergeExchangeAndAdversarialSuite(t *testing.T) {
	suite, report := RunFullBenchmark(1352)
	if !report.Verification.AllWorkflowPassed {
		t.Fatalf("workflow failed: %+v", report.Verification.WorkflowChecks)
	}
	if !report.Verification.AllAdversarialMatched {
		for _, o := range report.Verification.AdversarialOutcomes {
			if !o.Matched {
				t.Errorf("case %s mismatch: expected (%v, %s), got (%v, %s)",
					o.CaseID, o.ExpectedValid, o.ExpectedCode, o.ActualValid, o.ActualCode)
			}
		}
		t.Fatalf("adversarial suite did not match 100%%")
	}
	if report.Verification.AdversarialTotal != 19 || report.Verification.AdversarialCaught != 19 {
		t.Fatalf("expected 19/19 adversarial caught, got %d/%d",
			report.Verification.AdversarialCaught, report.Verification.AdversarialTotal)
	}

	// Verify genuine bidirectional accuracy improvement over base and over diverged heads.
	checks := report.Verification.WorkflowChecks
	baseAcc := checks[0].AccuracyBps
	orgA2Acc := checks[3].AccuracyBps
	orgB2Acc := checks[4].AccuracyBps
	orgA3Acc := checks[6].AccuracyBps
	orgB3Acc := checks[8].AccuracyBps
	if orgA2Acc <= baseAcc || orgB2Acc <= baseAcc {
		t.Fatalf("expected diverged orgs (%d, %d) > base (%d)", orgA2Acc, orgB2Acc, baseAcc)
	}
	if orgA3Acc <= orgA2Acc || orgB3Acc <= orgB2Acc {
		t.Fatalf("expected adopted heads (%d, %d) > diverged heads (%d, %d)", orgA3Acc, orgB3Acc, orgA2Acc, orgB2Acc)
	}

	// Verify zero ACL leak in fork redaction summary.
	if report.ForkRedactionSummary.RedactedRecords != 2 || report.ForkRedactionSummary.StrippedGrants != 2 || !report.ForkRedactionSummary.KeysRotated {
		t.Fatalf("unexpected fork redaction summary: %+v", report.ForkRedactionSummary)
	}

	// Verify every individual adversarial case as its own subtest.
	for _, c := range suite.AdversarialCases {
		c := c
		t.Run(c.CaseID+"_"+c.ExpectedCode, func(t *testing.T) {
			out := VerifyAdversarialCase(c, suite.EvalDataset)
			if !out.Matched {
				t.Fatalf("case %s (%s): expected (%v, %s), got (%v, %s)",
					c.CaseID, c.Name, c.ExpectedValid, c.ExpectedCode, out.ActualValid, out.ActualCode)
			}
		})
	}
}

func TestByzantineSweepShowsRobustnessAndHonestBreakdown(t *testing.T) {
	_, report := RunFullBenchmark(1352)
	if len(report.ByzantineResilience) != 6 {
		t.Fatalf("expected 6 Byzantine sweep rows, got %d", len(report.ByzantineResilience))
	}
	row30 := report.ByzantineResilience[3]
	if row30.ByzantinePct != 30 {
		t.Fatalf("expected row 3 to be 30%% Byzantine, got %d%%", row30.ByzantinePct)
	}
	if row30.TrimmedAccBps <= row30.NaiveMeanAccBps+2000 {
		t.Fatalf("expected trimmed mean (%d) to massively outperform naive mean (%d) at 30%% Byzantine",
			row30.TrimmedAccBps, row30.NaiveMeanAccBps)
	}
	if row30.TrimmedSafetyBps < 8500 || row30.NaiveMeanSafetyBps >= 8500 {
		t.Fatalf("expected trimmed safety (%d) >= 8500 and naive safety (%d) < 8500 at 30%% Byzantine",
			row30.TrimmedSafetyBps, row30.NaiveMeanSafetyBps)
	}
	row40 := report.ByzantineResilience[4]
	if row40.Regime != "honest_negative_breakdown_above_trim_bound" {
		t.Fatalf("expected honest negative regime at 40%% Byzantine")
	}
	if row40.TrimmedAccBps >= row30.TrimmedAccBps {
		t.Fatalf("expected breakdown above trim bound at 40%% Byzantine")
	}
}

func TestDeterminismAndConcurrentRaceSafety(t *testing.T) {
	suite1, rep1 := RunFullBenchmark(1352)
	_, rep2 := RunFullBenchmark(1352)
	if rep1.Verification.AuditMerkleRoot != rep2.Verification.AuditMerkleRoot {
		t.Fatalf("non-deterministic audit merkle root: %s != %s",
			rep1.Verification.AuditMerkleRoot, rep2.Verification.AuditMerkleRoot)
	}

	const workers = 8
	var wg sync.WaitGroup
	roots := make([]string, workers)
	for i := 0; i < workers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := VerifySuite(suite1)
			roots[i] = r.AuditMerkleRoot
		}()
	}
	wg.Wait()
	for i, root := range roots {
		if root != rep1.Verification.AuditMerkleRoot {
			t.Fatalf("worker %d root mismatch: %s != %s", i, root, rep1.Verification.AuditMerkleRoot)
		}
	}
}

func BenchmarkVerifyOrgSnapshot(b *testing.B) {
	suite, _ := BuildCanonicalSuite(1352)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok, code := VerifyOrgSnapshot(suite.OrgADivergedSnap2, nil); !ok {
			b.Fatalf("unexpected failure: %s", code)
		}
	}
}

func BenchmarkVerifyForkBoundary(b *testing.B) {
	suite, _ := BuildCanonicalSuite(1352)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok, code := VerifyOrgSnapshot(suite.OrgBForkSnap1, &suite.OrgASnap1); !ok {
			b.Fatalf("unexpected failure: %s", code)
		}
	}
}

func BenchmarkVerifyExchangeBundle(b *testing.B) {
	suite, _ := BuildCanonicalSuite(1352)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok, code, _, _ := VerifyExchangeBundle(suite.BundleBToA, suite.OrgBDivergedSnap2, suite.OrgADivergedSnap2, suite.EvalDataset); !ok {
			b.Fatalf("unexpected failure: %s", code)
		}
	}
}

func BenchmarkVerifySuite(b *testing.B) {
	suite, _ := BuildCanonicalSuite(1352)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rep := VerifySuite(suite)
		if !rep.AllWorkflowPassed || !rep.AllAdversarialMatched {
			b.Fatalf("suite verification failed")
		}
	}
}

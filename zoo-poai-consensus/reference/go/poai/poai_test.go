// Copyright 2026 Zoo Labs Foundation & Hanzo Industries.
// SPDX-License-Identifier: Apache-2.0

package poai

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func testRepoPaths(t *testing.T) (string, string) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to locate test file")
	}
	// file = <repo>/zoo-poai-consensus/reference/go/poai/poai_test.go
	refDir := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	repoRoot := filepath.Clean(filepath.Join(refDir, "..", ".."))
	manifestPath := filepath.Join(refDir, "corpus-manifest.json")
	return repoRoot, manifestPath
}

func TestCorpusManifestVerification(t *testing.T) {
	repoRoot, manifestPath := testRepoPaths(t)
	corpus, err := LoadAndVerifyCorpus(repoRoot, manifestPath)
	if err != nil {
		t.Fatalf("LoadAndVerifyCorpus failed: %v", err)
	}
	if len(corpus.Manifest.Files) != 6 {
		t.Fatalf("expected 6 pinned corpus files, got %d", len(corpus.Manifest.Files))
	}
}

func TestExactIntGEMMNoOverflowAndAssociativity(t *testing.T) {
	// Extreme int8 boundary test: all -128 * -128 = +16384 per inner term.
	const dim = 64
	a := NewInt8Matrix(dim, dim)
	b := NewInt8Matrix(dim, dim)
	for i := range a.Data {
		a.Data[i] = -128
		b.Data[i] = -128
	}
	c, err := ExactIntGEMM(a, b)
	if err != nil {
		t.Fatalf("ExactIntGEMM failed: %v", err)
	}
	want := int64(dim) * 128 * 128
	for i, v := range c.Data {
		if v != want {
			t.Fatalf("entry %d = %d, want %d", i, v, want)
		}
	}
	if want >= FieldModulus/2 {
		t.Fatalf("expected %d < (p-1)/2", want)
	}
}

func TestHonestTranscriptBinaryAndFieldModes(t *testing.T) {
	repoRoot, manifestPath := testRepoPaths(t)
	corpus, err := LoadAndVerifyCorpus(repoRoot, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	_, priv := DeriveProviderKeyPair("unit-test", 1350)
	a := DeriveTile(corpus.CorpusRoot, 1350, "unit-A", 24, 32)
	b := DeriveTile(corpus.CorpusRoot, 1350, "unit-B", 32, 20)
	c, err := ExactIntGEMM(a, b)
	if err != nil {
		t.Fatal(err)
	}
	manifestHex := hex.EncodeToString(corpus.ManifestSHA256[:])

	for _, tc := range []struct {
		mode string
		k    int
	}{
		{ChallengeModeBinary, 40},
		{ChallengeModeField, 2},
	} {
		tx, err := BuildTranscript(BuildParams{
			JobID:                "unit-honest-" + tc.mode,
			PolicyEpoch:          1,
			ModelID:              "zoo-zen-int8-ref",
			LayerIndex:           0,
			ChallengeMode:        tc.mode,
			ChallengeSource:      ChallengeSourceExternal,
			ChallengeRoundsK:     tc.k,
			VerifierNonceHex:     DeriveNonceHex(1350, tc.mode),
			CorpusManifestSHA256: manifestHex,
			ProviderPrivKey:      priv,
		}, a, b, c)
		if err != nil {
			t.Fatalf("BuildTranscript(%s) failed: %v", tc.mode, err)
		}
		r := VerifyTranscript(tx, a, b, c)
		if r.ConstitutionalBoundary.ComputeVerdict != VerdictComputeVerified {
			t.Fatalf("mode %s: got verdict %s, errors %v", tc.mode, r.ConstitutionalBoundary.ComputeVerdict, r.ConstitutionalBoundary.ErrorCodes)
		}
		if r.FirstFailingRound != -1 || r.RoundsExecuted != tc.k {
			t.Fatalf("mode %s: unexpected rounds=%d firstFail=%d", tc.mode, r.RoundsExecuted, r.FirstFailingRound)
		}
		if r.ConstitutionalBoundary.ProvesFullModelInference || r.ConstitutionalBoundary.ProvesScientificTruth || r.ConstitutionalBoundary.ProvesWeightProvenance {
			t.Fatalf("constitutional boundary violated: %+v", r.ConstitutionalBoundary)
		}
	}
}

func TestAllFiveCorruptionClassesDetected(t *testing.T) {
	repoRoot, manifestPath := testRepoPaths(t)
	corpus, err := LoadAndVerifyCorpus(repoRoot, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	_, priv := DeriveProviderKeyPair("unit-corrupt", 1350)
	a := DeriveTile(corpus.CorpusRoot, 1350, "corrupt-A", 32, 32)
	b := DeriveTile(corpus.CorpusRoot, 1350, "corrupt-B", 32, 32)
	c, err := ExactIntGEMM(a, b)
	if err != nil {
		t.Fatal(err)
	}
	manifestHex := hex.EncodeToString(corpus.ManifestSHA256[:])

	for idx, class := range AllCorruptionClasses {
		cm, err := InjectCorruption(c, class, idx)
		if err != nil {
			t.Fatalf("InjectCorruption(%s) failed: %v", class, err)
		}
		for _, cfg := range []struct {
			mode string
			k    int
		}{
			{ChallengeModeBinary, 40},
			{ChallengeModeField, 1},
		} {
			tx, err := BuildTranscript(BuildParams{
				JobID:                "corrupt-" + class + "-" + cfg.mode,
				PolicyEpoch:          1,
				ModelID:              "zoo-zen-int8-ref",
				LayerIndex:           uint32(idx),
				ChallengeMode:        cfg.mode,
				ChallengeSource:      ChallengeSourceExternal,
				ChallengeRoundsK:     cfg.k,
				VerifierNonceHex:     DeriveNonceHex(1350, class+cfg.mode),
				CorpusManifestSHA256: manifestHex,
				ProviderPrivKey:      priv,
			}, a, b, cm)
			if err != nil {
				t.Fatalf("BuildTranscript failed: %v", err)
			}
			r := VerifyTranscript(tx, a, b, cm)
			if r.ConstitutionalBoundary.ComputeVerdict != VerdictComputeCorrupted {
				t.Fatalf("class=%s mode=%s: expected COMPUTE_CORRUPTED, got %s (%v)", class, cfg.mode, r.ConstitutionalBoundary.ComputeVerdict, r.ConstitutionalBoundary.ErrorCodes)
			}
			if r.FirstFailingRound < 0 {
				t.Fatalf("class=%s mode=%s: expected FirstFailingRound >= 0", class, cfg.mode)
			}
		}
	}
}

func TestInvalidEd25519SignatureRejected(t *testing.T) {
	repoRoot, manifestPath := testRepoPaths(t)
	corpus, err := LoadAndVerifyCorpus(repoRoot, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	_, priv := DeriveProviderKeyPair("unit-sig", 1350)
	a := DeriveTile(corpus.CorpusRoot, 1350, "sig-A", 16, 16)
	b := DeriveTile(corpus.CorpusRoot, 1350, "sig-B", 16, 16)
	c, _ := ExactIntGEMM(a, b)

	tx, err := BuildTranscript(BuildParams{
		JobID:                "unit-bad-sig",
		PolicyEpoch:          1,
		ModelID:              "zoo-zen-int8-ref",
		LayerIndex:           0,
		ChallengeMode:        ChallengeModeField,
		ChallengeSource:      ChallengeSourceExternal,
		ChallengeRoundsK:     2,
		VerifierNonceHex:     DeriveNonceHex(1350, "sig"),
		CorpusManifestSHA256: hex.EncodeToString(corpus.ManifestSHA256[:]),
		ProviderPrivKey:      priv,
	}, a, b, c)
	if err != nil {
		t.Fatal(err)
	}

	rawSig, _ := hex.DecodeString(tx.Signature.SignatureHex)
	rawSig[len(rawSig)-1] ^= 0x01
	tx.Signature.SignatureHex = hex.EncodeToString(rawSig)

	r := VerifyTranscript(tx, a, b, c)
	if r.ConstitutionalBoundary.ComputeVerdict != VerdictInvalidTranscript {
		t.Fatalf("expected INVALID_TRANSCRIPT, got %s", r.ConstitutionalBoundary.ComputeVerdict)
	}
	found := false
	for _, code := range r.ConstitutionalBoundary.ErrorCodes {
		if code == ErrInvalidSignature {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected %s in error codes, got %v", ErrInvalidSignature, r.ConstitutionalBoundary.ErrorCodes)
	}
}

func TestCommitmentTamperingRejected(t *testing.T) {
	repoRoot, manifestPath := testRepoPaths(t)
	corpus, err := LoadAndVerifyCorpus(repoRoot, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	_, priv := DeriveProviderKeyPair("unit-commit", 1350)
	a := DeriveTile(corpus.CorpusRoot, 1350, "commit-A", 16, 16)
	b := DeriveTile(corpus.CorpusRoot, 1350, "commit-B", 16, 16)
	c, _ := ExactIntGEMM(a, b)

	tx, err := BuildTranscript(BuildParams{
		JobID:                "unit-commit-tamper",
		PolicyEpoch:          1,
		ModelID:              "zoo-zen-int8-ref",
		LayerIndex:           0,
		ChallengeMode:        ChallengeModeField,
		ChallengeSource:      ChallengeSourceExternal,
		ChallengeRoundsK:     2,
		VerifierNonceHex:     DeriveNonceHex(1350, "commit"),
		CorpusManifestSHA256: hex.EncodeToString(corpus.ManifestSHA256[:]),
		ProviderPrivKey:      priv,
	}, a, b, c)
	if err != nil {
		t.Fatal(err)
	}

	// Mutate A, B, C post-commitment individually.
	aBad := a.Clone()
	aBad.Data[0] ^= 1
	rA := VerifyTranscript(tx, aBad, b, c)
	if rA.ConstitutionalBoundary.ComputeVerdict != VerdictInvalidTranscript {
		t.Fatalf("expected INVALID_TRANSCRIPT on tampered A, got %s", rA.ConstitutionalBoundary.ComputeVerdict)
	}

	bBad := b.Clone()
	bBad.Data[0] ^= 1
	rB := VerifyTranscript(tx, a, bBad, c)
	if rB.ConstitutionalBoundary.ComputeVerdict != VerdictInvalidTranscript {
		t.Fatalf("expected INVALID_TRANSCRIPT on tampered B, got %s", rB.ConstitutionalBoundary.ComputeVerdict)
	}

	cBad := c.Clone()
	cBad.Data[0] += 1
	rC := VerifyTranscript(tx, a, b, cBad)
	if rC.ConstitutionalBoundary.ComputeVerdict != VerdictInvalidTranscript {
		t.Fatalf("expected INVALID_TRANSCRIPT on tampered C, got %s", rC.ConstitutionalBoundary.ComputeVerdict)
	}
}

func TestConstitutionalGuardsBlockForbiddenGovernanceAndSemanticClaims(t *testing.T) {
	repoRoot, manifestPath := testRepoPaths(t)
	corpus, err := LoadAndVerifyCorpus(repoRoot, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	_, priv := DeriveProviderKeyPair("unit-policy", 1350)
	a := DeriveTile(corpus.CorpusRoot, 1350, "policy-A", 8, 8)
	b := DeriveTile(corpus.CorpusRoot, 1350, "policy-B", 8, 8)
	c, _ := ExactIntGEMM(a, b)

	for _, action := range []string{"redefine_voting_rules", "authorize_treasury", "self_declare_valid"} {
		tx, err := BuildTranscript(BuildParams{
			JobID:                "policy-" + action,
			PolicyEpoch:          1,
			ModelID:              "zoo-zen-int8-ref",
			LayerIndex:           0,
			ChallengeMode:        ChallengeModeField,
			ChallengeSource:      ChallengeSourceExternal,
			ChallengeRoundsK:     2,
			VerifierNonceHex:     DeriveNonceHex(1350, action),
			CorpusManifestSHA256: hex.EncodeToString(corpus.ManifestSHA256[:]),
			ProviderPrivKey:      priv,
			SemanticMetadata: &SemanticMetadata{
				RequestedGovernanceAction: action,
			},
		}, a, b, c)
		if err != nil {
			t.Fatal(err)
		}
		r := VerifyTranscript(tx, a, b, c)
		if r.ConstitutionalBoundary.ComputeVerdict != VerdictPolicyRejected {
			t.Fatalf("action %s: expected POLICY_REJECTED, got %s", action, r.ConstitutionalBoundary.ComputeVerdict)
		}
	}

	// Also verify attempt to forge proves_scientific_truth=true is blocked.
	tx, err := BuildTranscript(BuildParams{
		JobID:                "policy-semantic-flag",
		PolicyEpoch:          1,
		ModelID:              "zoo-zen-int8-ref",
		LayerIndex:           0,
		ChallengeMode:        ChallengeModeField,
		ChallengeSource:      ChallengeSourceExternal,
		ChallengeRoundsK:     2,
		VerifierNonceHex:     DeriveNonceHex(1350, "sem-flag"),
		CorpusManifestSHA256: hex.EncodeToString(corpus.ManifestSHA256[:]),
		ProviderPrivKey:      priv,
	}, a, b, c)
	if err != nil {
		t.Fatal(err)
	}
	tx.ConstitutionalBoundary.ProvesScientificTruth = true
	r := VerifyTranscript(tx, a, b, c)
	if r.ConstitutionalBoundary.ComputeVerdict != VerdictPolicyRejected {
		t.Fatalf("expected POLICY_REJECTED for proves_scientific_truth=true, got %s", r.ConstitutionalBoundary.ComputeVerdict)
	}
	if r.ConstitutionalBoundary.ProvesScientificTruth {
		t.Fatal("verifier receipt must force ProvesScientificTruth=false")
	}
}

func TestNegativeRegime1FiatShamirGrindingVsExternalNonce(t *testing.T) {
	repoRoot, manifestPath := testRepoPaths(t)
	corpus, err := LoadAndVerifyCorpus(repoRoot, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	_, priv := DeriveProviderKeyPair("unit-grind", 1350)
	a := DeriveTile(corpus.CorpusRoot, 1350, "grind-A", 16, 16)
	b := DeriveTile(corpus.CorpusRoot, 1350, "grind-B", 16, 16)
	c, _ := ExactIntGEMM(a, b)
	cBad, _ := InjectCorruption(c, CorruptionSinglePlusOne, 0)

	// Grind k=3 binary_01 under fiat_shamir (~8 expected attempts).
	found := false
	for ctr := 0; ctr < 2000; ctr++ {
		salt := sha256.Sum256([]byte{byte(ctr >> 8), byte(ctr & 0xFF)})
		tx, err := BuildTranscript(BuildParams{
			JobID:                "grind-test",
			PolicyEpoch:          1,
			ModelID:              "zoo-zen-int8-ref",
			LayerIndex:           0,
			ChallengeMode:        ChallengeModeBinary,
			ChallengeSource:      ChallengeSourceFiatShamir,
			ChallengeRoundsK:     3,
			ProverSaltHex:        hex.EncodeToString(salt[:16]),
			CorpusManifestSHA256: hex.EncodeToString(corpus.ManifestSHA256[:]),
			ProviderPrivKey:      priv,
		}, a, b, cBad)
		if err != nil {
			t.Fatal(err)
		}
		if tx.ConstitutionalBoundary.ComputeVerdict == VerdictComputeVerified {
			if !tx.ConstitutionalBoundary.GrindingRiskWarning {
				t.Fatal("expected GrindingRiskWarning=true for weak fiat_shamir k=3")
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected to find grinding forgery for binary_01 k=3 within 2000 attempts")
	}
}

func TestEmpiricalBinaryDetectionRateMatchesTheory(t *testing.T) {
	repoRoot, manifestPath := testRepoPaths(t)
	corpus, err := LoadAndVerifyCorpus(repoRoot, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	a := DeriveTile(corpus.CorpusRoot, 1350, "emp-A", 24, 24)
	b := DeriveTile(corpus.CorpusRoot, 1350, "emp-B", 24, 24)
	c, _ := ExactIntGEMM(a, b)
	cBad, _ := InjectCorruption(c, CorruptionSinglePlusOne, 0)

	// At k=1, binary_01 detects single-element corruption with exact probability 0.5.
	// Across 1000 trials, empirical rate must fall comfortably inside [0.43, 0.57].
	const trials = 1000
	detectedK1 := 0
	detectedK16 := 0
	for i := 0; i < trials; i++ {
		seed := sha256.Sum256([]byte{byte(i >> 8), byte(i), 0x42})
		ok1, _, _ := FastFreivaldsCheck(a, b, cBad, ChallengeModeBinary, seed, 1)
		if !ok1 {
			detectedK1++
		}
		ok16, _, _ := FastFreivaldsCheck(a, b, cBad, ChallengeModeBinary, seed, 16)
		if !ok16 {
			detectedK16++
		}
	}
	rateK1 := float64(detectedK1) / float64(trials)
	if rateK1 < 0.43 || rateK1 > 0.57 {
		t.Fatalf("k=1 empirical detection rate %.4f outside expected [0.43, 0.57]", rateK1)
	}
	if detectedK16 != trials {
		t.Fatalf("k=16 expected ~100%% detection (theory 99.9985%%), got %d/%d", detectedK16, trials)
	}
}

func TestFieldModulusChallengeVectorUniformityAndBounds(t *testing.T) {
	seed := sha256.Sum256([]byte("poai:v1:vector-bounds-test"))
	vBin, err := DeriveChallengeVector(ChallengeModeBinary, seed, 0, 512)
	if err != nil {
		t.Fatal(err)
	}
	ones := 0
	for _, x := range vBin {
		if x != 0 && x != 1 {
			t.Fatalf("binary vector entry out of {0,1}: %d", x)
		}
		if x == 1 {
			ones++
		}
	}
	if ones < 200 || ones > 312 {
		t.Fatalf("binary vector unexpectedly biased: %d/512 ones", ones)
	}

	vFp, err := DeriveChallengeVector(ChallengeModeField, seed, 0, 512)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range vFp {
		if x < 0 || x >= FieldModulus {
			t.Fatalf("field vector entry out of [0, p-1]: %d", x)
		}
	}
}

func TestConcurrentVerificationRaceFree(t *testing.T) {
	repoRoot, manifestPath := testRepoPaths(t)
	corpus, err := LoadAndVerifyCorpus(repoRoot, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	_, priv := DeriveProviderKeyPair("unit-race", 1350)
	a := DeriveTile(corpus.CorpusRoot, 1350, "race-A", 24, 24)
	b := DeriveTile(corpus.CorpusRoot, 1350, "race-B", 24, 24)
	c, _ := ExactIntGEMM(a, b)
	tx, err := BuildTranscript(BuildParams{
		JobID:                "unit-race",
		PolicyEpoch:          1,
		ModelID:              "zoo-zen-int8-ref",
		LayerIndex:           0,
		ChallengeMode:        ChallengeModeField,
		ChallengeSource:      ChallengeSourceExternal,
		ChallengeRoundsK:     2,
		VerifierNonceHex:     DeriveNonceHex(1350, "race"),
		CorpusManifestSHA256: hex.EncodeToString(corpus.ManifestSHA256[:]),
		ProviderPrivKey:      priv,
	}, a, b, c)
	if err != nil {
		t.Fatal(err)
	}

	expected := VerifyTranscript(tx, a, b, c)
	expectedLeaf := AuditReceiptLeaf(expected)

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for iter := 0; iter < 10; iter++ {
				got := VerifyTranscript(tx, a, b, c)
				if AuditReceiptLeaf(got) != expectedLeaf {
					t.Errorf("concurrent receipt leaf mismatch")
				}
			}
		}()
	}
	wg.Wait()
}

func TestAdversarialExtremeInt64CorruptionNoOverflow(t *testing.T) {
	repoRoot, manifestPath := testRepoPaths(t)
	corpus, err := LoadAndVerifyCorpus(repoRoot, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	_, priv := DeriveProviderKeyPair("unit-extreme", 1350)
	a := DeriveTile(corpus.CorpusRoot, 1350, "ext-A", 16, 16)
	b := DeriveTile(corpus.CorpusRoot, 1350, "ext-B", 16, 16)
	c, _ := ExactIntGEMM(a, b)
	cExtreme := c.Clone()
	// Inject huge negative and positive values near int64 limits; ModP must handle without overflow.
	cExtreme.Data[0] = (1 << 62) - 1
	cExtreme.Data[1] = -(1 << 62) + 7

	tx, err := BuildTranscript(BuildParams{
		JobID:                "unit-extreme-int64",
		PolicyEpoch:          1,
		ModelID:              "zoo-zen-int8-ref",
		LayerIndex:           0,
		ChallengeMode:        ChallengeModeField,
		ChallengeSource:      ChallengeSourceExternal,
		ChallengeRoundsK:     2,
		VerifierNonceHex:     DeriveNonceHex(1350, "extreme"),
		CorpusManifestSHA256: hex.EncodeToString(corpus.ManifestSHA256[:]),
		ProviderPrivKey:      priv,
	}, a, b, cExtreme)
	if err != nil {
		t.Fatal(err)
	}
	r := VerifyTranscript(tx, a, b, cExtreme)
	if r.ConstitutionalBoundary.ComputeVerdict != VerdictComputeCorrupted {
		t.Fatalf("expected COMPUTE_CORRUPTED, got %s", r.ConstitutionalBoundary.ComputeVerdict)
	}
}

func TestDeterministicAuditMerkleRootAcrossRuns(t *testing.T) {
	repoRoot, manifestPath := testRepoPaths(t)
	rep1, suite1, err := RunFullBenchmark(repoRoot, manifestPath, 1350, 50)
	if err != nil {
		t.Fatalf("run 1 failed: %v", err)
	}
	rep2, suite2, err := RunFullBenchmark(repoRoot, manifestPath, 1350, 50)
	if err != nil {
		t.Fatalf("run 2 failed: %v", err)
	}
	if rep1.AuditMerkleRoot != rep2.AuditMerkleRoot {
		t.Fatalf("non-deterministic audit_merkle_root: %s vs %s", rep1.AuditMerkleRoot, rep2.AuditMerkleRoot)
	}
	if len(suite1.Cases) != 16 || len(suite2.Cases) != 16 {
		t.Fatalf("expected 16 parity suite cases, got %d / %d", len(suite1.Cases), len(suite2.Cases))
	}
	if !ed25519.Verify(
		mustHex(t, suite1.Cases[0].Transcript.Header.ProviderPubKeyHex),
		mustHex(t, suite1.Cases[0].Transcript.Signature.HeaderDigestHex),
		mustHex(t, suite1.Cases[0].Transcript.Signature.SignatureHex),
	) {
		t.Fatal("case 0 Ed25519 signature failed direct stdlib check")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package agentid

import (
	"bytes"
	"sync"
	"testing"
)

func TestBase58AndDIDKeyRoundTrip(t *testing.T) {
	kp := DeriveKeyPair(1352, "did-key-roundtrip", "k1")
	did := DIDKeyFromPublicKey(kp.PublicKey)
	if len(did) < 40 || did[:9] != "did:key:z" {
		t.Fatalf("unexpected did:key format: %s", did)
	}
	decoded, err := PublicKeyFromDIDKey(did)
	if err != nil {
		t.Fatalf("PublicKeyFromDIDKey failed: %v", err)
	}
	if !bytes.Equal(decoded, kp.PublicKey) {
		t.Fatalf("decoded public key mismatch")
	}
	if _, err := PublicKeyFromDIDKey("did:key:invalid"); err == nil {
		t.Fatalf("expected error for invalid did:key")
	}
}

func TestBitstringMSBFirstAndGzip(t *testing.T) {
	for _, enc := range []string{EncodingRawBase64URL, EncodingGzipBase64URL} {
		encoded, err := BuildBitstring(131072, []int{0, 7, 8, 103, 131071}, enc)
		if err != nil {
			t.Fatalf("BuildBitstring(%s) failed: %v", enc, err)
		}
		raw, err := DecodeBitstring(encoded, enc, 131072)
		if err != nil {
			t.Fatalf("DecodeBitstring(%s) failed: %v", enc, err)
		}
		// W3C MSB-first check: index 0 -> byte 0 bit 7 (0x80), index 7 -> byte 0 bit 0 (0x01)
		if raw[0] != 0x81 {
			t.Fatalf("expected raw[0]=0x81 for indices {0,7} MSB-first, got 0x%02x", raw[0])
		}
		for _, idx := range []int{0, 7, 8, 103, 131071} {
			rev, err := BitstringIsRevoked(raw, 131072, idx)
			if err != nil || !rev {
				t.Fatalf("expected index %d revoked (enc=%s), got rev=%v err=%v", idx, enc, rev, err)
			}
		}
		for _, idx := range []int{1, 6, 9, 102, 104, 131070} {
			rev, err := BitstringIsRevoked(raw, 131072, idx)
			if err != nil || rev {
				t.Fatalf("expected index %d active (enc=%s), got rev=%v err=%v", idx, enc, rev, err)
			}
		}
		if _, err := BitstringIsRevoked(raw, 131072, 131072); err == nil {
			t.Fatalf("expected out-of-bounds error for index 131072")
		}
	}
}

func TestReferenceSuiteAllStagesAndThreats(t *testing.T) {
	suite, err := BuildReferenceSuite(1352)
	if err != nil {
		t.Fatalf("BuildReferenceSuite failed: %v", err)
	}
	report := VerifySuite(suite)

	if !report.AllStagesValid {
		for _, sr := range report.StageReports {
			if !sr.Valid {
				t.Errorf("stage %s (%s) failed: %s", sr.StageID, sr.Name, sr.ErrorCode)
			}
		}
		t.Fatalf("expected all %d stages valid, passed %d", report.TotalStages, report.PassedStages)
	}
	if report.TotalStages != 5 {
		t.Fatalf("expected 5 positive stages, got %d", report.TotalStages)
	}
	if report.AttacksTotal != 24 || report.AttacksCaught != 24 {
		for _, tr := range report.ThreatReports {
			if !tr.Pass {
				t.Errorf("threat %s (%s) failed: expectValid=%v actualValid=%v expectErr=%s actualErr=%s",
					tr.CaseID, tr.Name, tr.ExpectValid, tr.ActualValid, tr.ExpectedError, tr.ActualError)
			}
		}
		t.Fatalf("expected 24/24 attacks caught, got %d/%d", report.AttacksCaught, report.AttacksTotal)
	}
	if report.PositiveControls != 1 || report.PositiveControlsOK != 1 {
		t.Fatalf("expected 1/1 positive control passed, got %d/%d", report.PositiveControlsOK, report.PositiveControls)
	}
	if !report.AllThreatPass {
		t.Fatalf("expected AllThreatPass=true")
	}
	if len(report.AuditMerkleRoot) != 64 {
		t.Fatalf("expected 64-hex audit_merkle_root, got %q", report.AuditMerkleRoot)
	}
}

func TestDeterministicAuditMerkleRoot(t *testing.T) {
	s1, err := BuildReferenceSuite(1352)
	if err != nil {
		t.Fatalf("BuildReferenceSuite(1) failed: %v", err)
	}
	s2, err := BuildReferenceSuite(1352)
	if err != nil {
		t.Fatalf("BuildReferenceSuite(2) failed: %v", err)
	}
	r1 := VerifySuite(s1)
	r2 := VerifySuite(s2)

	b1, err := CanonicalJSON(r1)
	if err != nil {
		t.Fatalf("CanonicalJSON(r1): %v", err)
	}
	b2, err := CanonicalJSON(r2)
	if err != nil {
		t.Fatalf("CanonicalJSON(r2): %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("non-deterministic suite verification output")
	}
	if r1.AuditMerkleRoot != r2.AuditMerkleRoot {
		t.Fatalf("audit_merkle_root mismatch: %s != %s", r1.AuditMerkleRoot, r2.AuditMerkleRoot)
	}
}

func TestKeyCompromiseGlobalRevocation(t *testing.T) {
	suite, err := BuildReferenceSuite(1352)
	if err != nil {
		t.Fatalf("BuildReferenceSuite failed: %v", err)
	}
	st := suite.Stages[2] // 4-hop chain
	ctx := cloneCtx(st.Context)
	rootKP := DeriveKeyPair(1352, "human-council-root", "did:zoo:council:root-2026#key-1")
	snap, err := SignRevocationSnapshot(
		"urn:zoo:revsnap:global-compromise",
		"did:zoo:council:root-2026",
		rootKP,
		DefaultBaseTime,
		DefaultBaseTime+7200,
		ctx.StatusLists,
		[]KeyRevocationEntry{
			{
				DID:           "did:zoo:agent:lead-researcher-01",
				KeyID:         "did:zoo:agent:lead-researcher-01#key-2",
				RevokedBefore: 0,
				RevokeAll:     true,
				Reason:        "key_material_exfiltrated",
			},
		},
		[]string{},
	)
	if err != nil {
		t.Fatalf("SignRevocationSnapshot failed: %v", err)
	}
	ctx.RevocationSnapshot = snap
	res := VerifyPresentation(ctx, st.Presentation)
	if res.Valid || res.ErrorCode != ErrKeyCompromisedRevoked {
		t.Fatalf("expected %s, got valid=%v err=%s (%s)", ErrKeyCompromisedRevoked, res.Valid, res.ErrorCode, res.ErrorDetail)
	}
}

func TestConstraintAndResourceBoundaryHelpers(t *testing.T) {
	if isResourceWithin("zoo://datasets/ecology-secret/a", "zoo://datasets/ecology") {
		t.Fatalf("sibling prefix attack must NOT match")
	}
	if !isResourceWithin("zoo://datasets/ecology/2026/a", "zoo://datasets/ecology/") {
		t.Fatalf("child path under trailing slash parent must match")
	}
	if isSafeResourceURI("zoo://datasets/ecology/../secret") {
		t.Fatalf("path traversal .. must be rejected")
	}
	if isSafeResourceURI("zoo://datasets/*") {
		t.Fatalf("wildcard resource must be rejected")
	}
}

func TestDepthScaling1To16Offline(t *testing.T) {
	for _, depth := range []int{1, 2, 4, 8, 16} {
		ctx, pres, err := BuildDepthBenchmarkCase(1352, depth, DefaultBitstringLength, []int{1, 7, 4096}, EncodingGzipBase64URL)
		if err != nil {
			t.Fatalf("BuildDepthBenchmarkCase(depth=%d): %v", depth, err)
		}
		res := VerifyPresentation(ctx, pres)
		if !res.Valid {
			t.Fatalf("depth %d offline verification failed: %s (%s)", depth, res.ErrorCode, res.ErrorDetail)
		}
		if res.ChainDepth != depth {
			t.Fatalf("expected chain_depth=%d, got %d", depth, res.ChainDepth)
		}
	}
}

func TestConcurrentOfflineVerificationRace(t *testing.T) {
	suite, err := BuildReferenceSuite(1352)
	if err != nil {
		t.Fatalf("BuildReferenceSuite failed: %v", err)
	}
	st := suite.Stages[2]
	epoch, errCode, errMsg := PrepareEpoch(st.Context, st.Presentation.EvalTime)
	if errCode != "" {
		t.Fatalf("PrepareEpoch failed: %s %s", errCode, errMsg)
	}

	var wg sync.WaitGroup
	errs := make(chan string, 32)
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			if id%2 == 0 {
				rep := VerifySuite(suite)
				if !rep.AllStagesValid || !rep.AllThreatPass {
					errs <- "suite verification failed under concurrency"
				}
			} else {
				res := VerifyPresentationWithEpoch(epoch, st.Context, st.Presentation)
				if !res.Valid {
					errs <- "warm epoch verification failed: " + res.ErrorCode
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

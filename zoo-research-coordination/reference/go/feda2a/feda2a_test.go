// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package feda2a

import (
	"net/http"
	"sync"
	"testing"
)

func TestLiveTwoDeploymentExchangeAndBoundaryIsolation(t *testing.T) {
	suite, sseCount, egressBlocks, err := RunLiveExchangeSuite(DefaultSeed)
	if err != nil {
		t.Fatalf("RunLiveExchangeSuite failed: %v", err)
	}
	if sseCount < 4 {
		t.Fatalf("expected >=4 live SSE events, got %d", sseCount)
	}
	if egressBlocks < 1 {
		t.Fatalf("expected >=1 live egress firewall block, got %d", egressBlocks)
	}

	report := VerifySuite(suite)
	if !report.AllStagesValid {
		for _, s := range report.StageOutcomes {
			if !s.Valid {
				t.Errorf("stage %s failed: code=%s state=%s", s.Stage, s.Code, s.TaskState)
			}
		}
		t.Fatalf("expected all live stages valid")
	}
	if !report.AllAdversarialPass {
		for _, a := range report.AdversarialResults {
			if !a.Matched {
				t.Errorf("adversarial %s mismatch: want (%t,%s) got (%t,%s)",
					a.CaseID, a.ExpectedValid, a.ExpectedCode, a.ActualValid, a.ActualCode)
			}
		}
		t.Fatalf("expected all adversarial cases to match")
	}
	if report.AttacksDetected != 18 || report.AttacksTotal != 18 || report.PositiveCasesPass != 1 {
		t.Fatalf("unexpected adversarial tally: detected=%d/%d positive=%d",
			report.AttacksDetected, report.AttacksTotal, report.PositiveCasesPass)
	}
	if !report.WireAudit.ZeroBoundaryLeakage ||
		report.WireAudit.CredentialLeakBytes != 0 ||
		report.WireAudit.PrivateMemoryLeakBytes != 0 ||
		report.WireAudit.RawTraceLeakBytes != 0 {
		t.Fatalf("boundary leak detected on wire: %+v", report.WireAudit)
	}
	if !report.WireAudit.AllFrameHashesValid || report.WireAudit.TotalFrames != 8 {
		t.Fatalf("unexpected wire transcript integrity: valid=%t frames=%d",
			report.WireAudit.AllFrameHashesValid, report.WireAudit.TotalFrames)
	}
}

func TestDeterminismAcrossLiveRuns(t *testing.T) {
	s1, _, _, err := RunLiveExchangeSuite(DefaultSeed)
	if err != nil {
		t.Fatalf("run 1 failed: %v", err)
	}
	s2, _, _, err := RunLiveExchangeSuite(DefaultSeed)
	if err != nil {
		t.Fatalf("run 2 failed: %v", err)
	}
	r1 := VerifySuite(s1)
	r2 := VerifySuite(s2)
	if r1.AuditMerkleRoot != r2.AuditMerkleRoot {
		t.Fatalf("non-deterministic audit_merkle_root: %s != %s", r1.AuditMerkleRoot, r2.AuditMerkleRoot)
	}
	if r1.WireAudit.WireTranscriptRoot != r2.WireAudit.WireTranscriptRoot {
		t.Fatalf("non-deterministic wire_transcript_root: %s != %s",
			r1.WireAudit.WireTranscriptRoot, r2.WireAudit.WireTranscriptRoot)
	}
}

func TestLiveReplayAndAudienceRejectionOverHTTP(t *testing.T) {
	orgAlpha, orgBeta := BuildOrgPair(DefaultSeed)
	if err := orgAlpha.Start(); err != nil {
		t.Fatalf("start alpha: %v", err)
	}
	defer orgAlpha.Stop()
	if err := orgBeta.Start(); err != nil {
		t.Fatalf("start beta: %v", err)
	}
	defer orgBeta.Stop()

	ts := BaseEpochSec + 200
	orgAlpha.SetClock(ts)
	orgBeta.SetClock(ts)

	if _, _, err := orgAlpha.DiscoverPeer("test", orgBeta.BaseURL(), orgBeta.OrgID); err != nil {
		t.Fatalf("alpha discover beta: %v", err)
	}
	if _, _, err := orgBeta.DiscoverPeer("test", orgAlpha.BaseURL(), orgAlpha.OrgID); err != nil {
		t.Fatalf("beta discover alpha: %v", err)
	}

	gA, gB := deterministicDataset(DefaultSeed+9, 12, 350_000, 10_000)
	env := orgAlpha.SignEnvelope(
		"env-live-replay-1",
		"tasks/send",
		orgBeta.OrgID,
		SkillZHLCompare,
		"nonce-live-replay-1",
		ts,
		ts+EnvelopeTTLSec,
		TaskPayload{
			TaskID:    "task-live-replay-1",
			SkillID:   SkillZHLCompare,
			ActorID:   orgAlpha.ReviewerKey.Principal.ID,
			ActorRole: RoleHumanReviewer,
			Commitment: ExperimentCommitment{
				CommitmentID:    "commit-live-replay-1",
				ZHLTemplate:     "COMPARE",
				Hypothesis:      "Live replay check",
				AlphaBps:        500,
				MinEffectMicro:  200_000,
				InputTier:       TierSharedExchange,
				InputRecordRefs: []string{"mem-alpha-shared-01"},
				GroupAMicro:     gA,
				GroupBMicro:     gB,
			},
			Licenses: []LicenseAttachment{
				{ArtifactID: "mem-alpha-shared-01", ArtifactKind: "dataset", LicenseID: "Apache-2.0", LicenseReviewed: true, ReviewerID: orgAlpha.ReviewerKey.Principal.ID},
			},
		},
	)

	// First submission succeeds over live HTTP.
	rcpt1, _, status1, err := orgAlpha.CallRPC("test", orgBeta.BaseURL(), env)
	if err != nil || status1 != http.StatusOK || rcpt1.State != TaskStateCompleted {
		t.Fatalf("first live call failed: status=%d state=%s err=%v", status1, rcpt1.State, err)
	}

	// Exact replay of same nonce MUST be rejected over live HTTP with ERR_NONCE_REPLAY.
	rcpt2, _, status2, err := orgAlpha.CallRPC("test", orgBeta.BaseURL(), env)
	if err != nil || status2 != http.StatusForbidden || rcpt2.ErrorCode != CodeNonceReplay {
		t.Fatalf("replay expected HTTP 403 %s, got status=%d code=%s err=%v", CodeNonceReplay, status2, rcpt2.ErrorCode, err)
	}

	// Wrong audience envelope MUST be rejected over live HTTP with ERR_AUDIENCE_MISMATCH.
	wrongAud := orgAlpha.SignEnvelope(
		"env-wrong-aud",
		"tasks/send",
		"org-gamma",
		SkillZHLCompare,
		"nonce-wrong-aud",
		ts,
		ts+EnvelopeTTLSec,
		env.Payload,
	)
	rcpt3, _, status3, err := orgAlpha.CallRPC("test", orgBeta.BaseURL(), wrongAud)
	if err != nil || status3 != http.StatusForbidden || rcpt3.ErrorCode != CodeAudienceMismatch {
		t.Fatalf("wrong audience expected HTTP 403 %s, got status=%d code=%s err=%v", CodeAudienceMismatch, status3, rcpt3.ErrorCode, err)
	}
}

func TestLiveClientOutboundEgressBlocksOwnSecrets(t *testing.T) {
	orgAlpha, orgBeta := BuildOrgPair(DefaultSeed)
	if err := orgBeta.Start(); err != nil {
		t.Fatalf("start beta: %v", err)
	}
	defer orgBeta.Stop()

	ts := BaseEpochSec + 300
	orgAlpha.SetClock(ts)
	orgBeta.SetClock(ts)

	gA, gB := deterministicDataset(DefaultSeed+10, 8, 300_000, 10_000)
	leakyEnv := orgAlpha.SignEnvelope(
		"env-outbound-leak",
		"tasks/send",
		orgBeta.OrgID,
		SkillZHLCompare,
		"nonce-outbound-leak",
		ts,
		ts+EnvelopeTTLSec,
		TaskPayload{
			TaskID:     "task-outbound-leak",
			SkillID:    SkillZHLCompare,
			PromptNote: "accidental secret=" + orgAlpha.Credentials.Secrets["INTERNAL_DB_DSN"],
			ActorID:    orgAlpha.ReviewerKey.Principal.ID,
			ActorRole:  RoleHumanReviewer,
			Commitment: ExperimentCommitment{
				CommitmentID:    "commit-outbound-leak",
				ZHLTemplate:     "COMPARE",
				Hypothesis:      "test",
				AlphaBps:        500,
				MinEffectMicro:  100_000,
				InputTier:       TierSharedExchange,
				InputRecordRefs: []string{"mem-alpha-shared-01"},
				GroupAMicro:     gA,
				GroupBMicro:     gB,
			},
			Licenses: []LicenseAttachment{
				{ArtifactID: "mem-alpha-shared-01", ArtifactKind: "dataset", LicenseID: "Apache-2.0", LicenseReviewed: true, ReviewerID: orgAlpha.ReviewerKey.Principal.ID},
			},
		},
	)
	_, _, status, err := orgAlpha.CallRPC("test", orgBeta.BaseURL(), leakyEnv)
	if err == nil || status != http.StatusForbidden {
		t.Fatalf("expected outbound egress firewall block before socket write, got status=%d err=%v", status, err)
	}
	if len(orgAlpha.WireFrames()) != 0 {
		t.Fatalf("blocked outbound request must record 0 wire frames, got %d", len(orgAlpha.WireFrames()))
	}
}

func TestConcurrentLiveTwoDeploymentRequestsRaceSafe(t *testing.T) {
	orgAlpha, orgBeta := BuildOrgPair(DefaultSeed)
	if err := orgAlpha.Start(); err != nil {
		t.Fatalf("start alpha: %v", err)
	}
	defer orgAlpha.Stop()
	if err := orgBeta.Start(); err != nil {
		t.Fatalf("start beta: %v", err)
	}
	defer orgBeta.Stop()

	ts := BaseEpochSec + 400
	orgAlpha.SetClock(ts)
	orgBeta.SetClock(ts)
	if _, _, err := orgAlpha.DiscoverPeer("race", orgBeta.BaseURL(), orgBeta.OrgID); err != nil {
		t.Fatalf("discover beta: %v", err)
	}
	if _, _, err := orgBeta.DiscoverPeer("race", orgAlpha.BaseURL(), orgAlpha.OrgID); err != nil {
		t.Fatalf("discover alpha: %v", err)
	}

	gA, gB := deterministicDataset(DefaultSeed+11, 16, 400_000, 12_000)
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			env := orgAlpha.SignEnvelope(
				"env-race-"+string(rune('a'+idx)),
				"tasks/send",
				orgBeta.OrgID,
				SkillZHLCompare,
				"nonce-race-"+string(rune('a'+idx)),
				ts,
				ts+EnvelopeTTLSec,
				TaskPayload{
					TaskID:    "task-race-" + string(rune('a'+idx)),
					SkillID:   SkillZHLCompare,
					ActorID:   orgAlpha.ReviewerKey.Principal.ID,
					ActorRole: RoleHumanReviewer,
					Commitment: ExperimentCommitment{
						CommitmentID:    "commit-race",
						ZHLTemplate:     "COMPARE",
						Hypothesis:      "Concurrent live exchange test",
						AlphaBps:        500,
						MinEffectMicro:  200_000,
						InputTier:       TierSharedExchange,
						InputRecordRefs: []string{"mem-alpha-shared-01"},
						GroupAMicro:     gA,
						GroupBMicro:     gB,
					},
					Licenses: []LicenseAttachment{
						{ArtifactID: "mem-alpha-shared-01", ArtifactKind: "dataset", LicenseID: "Apache-2.0", LicenseReviewed: true, ReviewerID: orgAlpha.ReviewerKey.Principal.ID},
					},
				},
			)
			rcpt, _, status, err := orgAlpha.CallRPC("race", orgBeta.BaseURL(), env)
			if err != nil || status != http.StatusOK || rcpt.State != TaskStateCompleted {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent live HTTP request failed: %v", err)
	}
}

func TestRFC6962MerkleAndCanonicalJSON(t *testing.T) {
	emptyRoot := MerkleRootRFC6962(nil)
	if emptyRoot != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("unexpected empty Merkle root: %s", emptyRoot)
	}
	raw, err := CanonicalJSON(map[string]any{"b": 2, "a": 1, "c": "<&>"})
	if err != nil {
		t.Fatalf("CanonicalJSON error: %v", err)
	}
	if string(raw) != `{"a":1,"b":2,"c":"<&>"}` {
		t.Fatalf("unexpected canonical JSON: %s", string(raw))
	}
}

func BenchmarkVerifySuite(b *testing.B) {
	suite, _, _, err := RunLiveExchangeSuite(DefaultSeed)
	if err != nil {
		b.Fatalf("setup suite failed: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rep := VerifySuite(suite)
		if !rep.AllStagesValid || !rep.AllAdversarialPass {
			b.Fatalf("verification failed")
		}
	}
}

func BenchmarkVerifyWireTranscript(b *testing.B) {
	suite, _, _, err := RunLiveExchangeSuite(DefaultSeed)
	if err != nil {
		b.Fatalf("setup suite failed: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		summary := VerifyWireTranscript(suite.WireTranscript, suite.BoundaryProbes)
		if !summary.ZeroBoundaryLeakage {
			b.Fatalf("leak detected")
		}
	}
}

func BenchmarkVerifyAgentCard(b *testing.B) {
	suite, _, _, err := RunLiveExchangeSuite(DefaultSeed)
	if err != nil {
		b.Fatalf("setup suite failed: %v", err)
	}
	policies := indexPolicies(suite.OrgPolicies)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, code := VerifyAgentCard(suite.AgentCards[0], policies, suite.BoundaryProbes)
		if !ok || code != CodeOK {
			b.Fatalf("card verify failed: %s", code)
		}
	}
}

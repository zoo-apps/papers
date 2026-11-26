// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation & Open ResearchDAO Contributors.

package daoos

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func mustApplyEnv(t *testing.T, fix *BenchFixture, m *Machine, actorID string, ts int64, evType EventType, payload map[string]any) string {
	t.Helper()
	env, err := fix.SignNext(m, actorID, ts, evType, payload)
	if err != nil {
		t.Fatalf("SignNext(%s, %s): %v", actorID, evType, err)
	}
	h, err := m.Apply(env)
	if err != nil {
		t.Fatalf("Apply(%s, %s): %v", actorID, evType, err)
	}
	return h
}

func expectApplyErr(t *testing.T, fix *BenchFixture, m *Machine, actorID string, ts int64, evType EventType, payload map[string]any, want ErrorCode) {
	t.Helper()
	srBefore, arBefore, err := m.Roots()
	if err != nil {
		t.Fatalf("Roots before: %v", err)
	}
	env, err := fix.SignNext(m, actorID, ts, evType, payload)
	if err != nil {
		t.Fatalf("SignNext(%s, %s): %v", actorID, evType, err)
	}
	_, err = m.Apply(env)
	if err == nil {
		t.Fatalf("expected error %s for (%s, %s), got nil", want, actorID, evType)
	}
	if got := ErrorCodeOf(err); got != want {
		t.Fatalf("expected error code %s, got %s (%v)", want, got, err)
	}
	srAfter, arAfter, err := m.Roots()
	if err != nil {
		t.Fatalf("Roots after: %v", err)
	}
	if srBefore != srAfter || arBefore != arAfter {
		t.Fatalf("rejected transition mutated state roots!")
	}
}

func TestFullFiveStageLifecycleAndConservation(t *testing.T) {
	fix := BuildStandardFixture(1352, "test-lifecycle")
	m, err := NewMachine(fix.Genesis)
	if err != nil {
		t.Fatalf("NewMachine: %v", err)
	}
	ts := fix.BaseTime + 10
	planHash := SHA256Hex([]byte("conservation-genomics-plan"))
	evHash := SHA256Hex([]byte("milestone-1-dataset-artifact"))
	reproHash := SHA256Hex([]byte("independent-berlin-repro-run"))

	// 1. ProposalSubmitted
	mustApplyEnv(t, &fix, m, "pi-01", ts, EventProposalSubmitted, map[string]any{
		"proposal_id":         "GRANT-001",
		"title":               "Genomic Wildlife Monitoring",
		"category":            string(CategoryConservationResearch),
		"plan_hash":           planHash,
		"source_paper":        "zoo-dao-operating-system/zoo-dao-operating-system.tex",
		"requested_amount":    int64(100_000),
		"declared_coi_actors": []string{"rev-05"},
	})

	// Non-binding AI AdvisoryRecorded
	ts += 5
	mustApplyEnv(t, &fix, m, "ai-advisor-01", ts, EventAdvisoryRecorded, map[string]any{
		"proposal_id":     "GRANT-001",
		"advisory_only":   true,
		"analysis_hash":   SHA256Hex([]byte("ai-note-1")),
		"summary":         "Methodologically sound; no hidden COI found beyond declared.",
		"conflict_flags":  []string{"declared:rev-05"},
		"estimated_value": int64(100_000),
	})
	st := m.SnapshotState()
	if st.Proposals["GRANT-001"].Status != StatusSubmitted {
		t.Fatalf("AI advisory must not alter status; got %s", st.Proposals["GRANT-001"].Status)
	}

	// 2. PeerReviewRecorded (3 independent reviewers)
	for i, rev := range []string{"rev-01", "rev-02", "rev-03"} {
		ts += 10
		mustApplyEnv(t, &fix, m, rev, ts, EventPeerReviewRecorded, map[string]any{
			"proposal_id":  "GRANT-001",
			"score_bps":    int64(8000 + i*500),
			"report_hash":  SHA256Hex([]byte("rev-" + rev)),
			"recommend":    true,
			"coi_declared": false,
		})
	}
	st = m.SnapshotState()
	if st.Proposals["GRANT-001"].Status != StatusPeerReviewed {
		t.Fatalf("expected PEER_REVIEWED, got %s", st.Proposals["GRANT-001"].Status)
	}

	// 3. MilestoneApproved (2-of-3 committee)
	for _, mc := range []string{"mc-01", "mc-02"} {
		ts += 10
		mustApplyEnv(t, &fix, m, mc, ts, EventMilestoneApproved, map[string]any{
			"proposal_id":     "GRANT-001",
			"milestone_index": int64(1),
			"evidence_hash":   evHash,
			"notes_hash":      SHA256Hex([]byte("notes-" + mc)),
		})
	}
	st = m.SnapshotState()
	if st.Proposals["GRANT-001"].Status != StatusMilestoneApproved {
		t.Fatalf("expected MILESTONE_APPROVED, got %s", st.Proposals["GRANT-001"].Status)
	}

	// 4. FundingQueued -> FundingCosigned -> Timelock -> FundingAuthorized
	ts += 10
	mustApplyEnv(t, &fix, m, "steward-01", ts, EventFundingQueued, map[string]any{
		"proposal_id": "GRANT-001",
		"amount":      int64(100_000),
	})
	ts += 10
	mustApplyEnv(t, &fix, m, "steward-02", ts, EventFundingCosigned, map[string]any{
		"proposal_id": "GRANT-001",
	})
	ts += fix.Genesis.Config.TimelockSeconds + 1
	mustApplyEnv(t, &fix, m, "steward-01", ts, EventFundingAuthorized, map[string]any{
		"proposal_id": "GRANT-001",
	})
	st = m.SnapshotState()
	if st.Proposals["GRANT-001"].Status != StatusFundingAuthorized {
		t.Fatalf("expected FUNDING_AUTHORIZED, got %s", st.Proposals["GRANT-001"].Status)
	}
	if st.Treasury.EscrowedTotal != 10_000 || st.Treasury.TotalDisbursed != 90_000 {
		t.Fatalf("unexpected 90/10 split: escrow=%d disbursed=%d", st.Treasury.EscrowedTotal, st.Treasury.TotalDisbursed)
	}

	// 5. IndependentAcceptanceRecorded releases 10% holdback
	ts += 100
	mustApplyEnv(t, &fix, m, "verif-01", ts, EventIndependentAcceptanceRecorded, map[string]any{
		"proposal_id":         "GRANT-001",
		"bound_evidence_hash": evHash,
		"repro_check_hash":    reproHash,
		"verdict":             "ACCEPTED",
	})
	st = m.SnapshotState()
	if st.Proposals["GRANT-001"].Status != StatusAccepted {
		t.Fatalf("expected ACCEPTED, got %s", st.Proposals["GRANT-001"].Status)
	}
	if st.Treasury.EscrowedTotal != 0 || st.Treasury.TotalDisbursed != 100_000 {
		t.Fatalf("unexpected final treasury: escrow=%d disbursed=%d", st.Treasury.EscrowedTotal, st.Treasury.TotalDisbursed)
	}
	// Conservation law: InitialBalance == Balance + EscrowedTotal + TotalDisbursed
	if st.Treasury.Balance+st.Treasury.EscrowedTotal+st.Treasury.TotalDisbursed != fix.Genesis.InitialTreasuryBalance {
		t.Fatalf("treasury conservation violated")
	}
}

func TestFailedReproClawsBackHoldback(t *testing.T) {
	fix := BuildStandardFixture(1352, "test-clawback")
	m, err := NewMachine(fix.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	ts := fix.BaseTime + 10
	planHash := SHA256Hex([]byte("clawback-plan"))
	evHash := SHA256Hex([]byte("clawback-evidence"))

	mustApplyEnv(t, &fix, m, "pi-02", ts, EventProposalSubmitted, map[string]any{
		"proposal_id": "CLAW-1", "title": "Non-Reproducible Claim", "category": string(CategoryOpenSourceDev),
		"plan_hash": planHash, "source_paper": "p.tex", "requested_amount": int64(50_000),
	})
	for _, r := range []string{"rev-01", "rev-02", "rev-03"} {
		ts += 2
		mustApplyEnv(t, &fix, m, r, ts, EventPeerReviewRecorded, map[string]any{
			"proposal_id": "CLAW-1", "score_bps": int64(7500), "report_hash": SHA256Hex([]byte(r)), "recommend": true, "coi_declared": false,
		})
	}
	for _, mc := range []string{"mc-01", "mc-02"} {
		ts += 2
		mustApplyEnv(t, &fix, m, mc, ts, EventMilestoneApproved, map[string]any{
			"proposal_id": "CLAW-1", "milestone_index": int64(1), "evidence_hash": evHash, "notes_hash": SHA256Hex([]byte(mc)),
		})
	}
	ts += 2
	mustApplyEnv(t, &fix, m, "steward-01", ts, EventFundingQueued, map[string]any{"proposal_id": "CLAW-1", "amount": int64(50_000)})
	ts += 2
	mustApplyEnv(t, &fix, m, "steward-02", ts, EventFundingCosigned, map[string]any{"proposal_id": "CLAW-1"})
	ts += fix.Genesis.Config.TimelockSeconds + 5
	mustApplyEnv(t, &fix, m, "steward-01", ts, EventFundingAuthorized, map[string]any{"proposal_id": "CLAW-1"})

	ts += 50
	mustApplyEnv(t, &fix, m, "verif-02", ts, EventIndependentAcceptanceRecorded, map[string]any{
		"proposal_id":         "CLAW-1",
		"bound_evidence_hash": evHash,
		"repro_check_hash":    SHA256Hex([]byte("failed-repro-log")),
		"verdict":             "FAILED_REPRO",
	})
	st := m.SnapshotState()
	if st.Proposals["CLAW-1"].Status != StatusAcceptanceFailed {
		t.Fatalf("expected ACCEPTANCE_FAILED, got %s", st.Proposals["CLAW-1"].Status)
	}
	if st.Treasury.EscrowedTotal != 0 || st.Treasury.Balance != fix.Genesis.InitialTreasuryBalance-45_000 {
		t.Fatalf("holdback not returned to balance: balance=%d escrow=%d", st.Treasury.Balance, st.Treasury.EscrowedTotal)
	}
}

func TestGenesisRejectsAIAgentWithAuthorityRole(t *testing.T) {
	fix := BuildStandardFixture(1352, "test-ai-genesis")
	fix.Genesis.Actors = append(fix.Genesis.Actors, Actor{
		ID:        "rogue-ai",
		PubKeyHex: DeriveDeterministicKeypair(1352, "rogue-ai").PubKeyHex,
		Kind:      ActorKindAIAgent,
		Roles:     []Role{RoleTreasurySteward},
		Active:    true,
	})
	_, err := NewMachine(fix.Genesis)
	if ErrorCodeOf(err) != ErrAIGovernanceForbidden {
		t.Fatalf("expected ERR_AI_GOVERNANCE_FORBIDDEN, got %v", err)
	}
}

func TestAdversarialAuthorizationMatrix(t *testing.T) {
	results, err := RunAdversarialMatrix(1352)
	if err != nil {
		t.Fatalf("RunAdversarialMatrix: %v", err)
	}
	if len(results) != 16 {
		t.Fatalf("expected 16 adversarial test cases, got %d", len(results))
	}
	for _, r := range results {
		if !r.Rejected || !r.StateUnchanged || r.ActualErrorCode != r.ExpectedErrorCode {
			t.Errorf("adversarial case %q failed: rejected=%v unchanged=%v want=%s got=%s",
				r.Name, r.Rejected, r.StateUnchanged, r.ExpectedErrorCode, r.ActualErrorCode)
		}
	}
}

func TestRevokedCosignerInvalidatesQuorumAndBoardVeto(t *testing.T) {
	fix := BuildStandardFixture(1352, "test-revoked-quorum")
	m, err := NewMachine(fix.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	ts := fix.BaseTime + 10
	planHash := SHA256Hex([]byte("rev-quorum-plan"))
	evHash := SHA256Hex([]byte("rev-quorum-ev"))

	mustApplyEnv(t, &fix, m, "pi-01", ts, EventProposalSubmitted, map[string]any{
		"proposal_id": "RQ-1", "title": "Revoked Steward Test", "category": string(CategoryEducation),
		"plan_hash": planHash, "source_paper": "p.tex", "requested_amount": int64(20_000),
	})
	for _, r := range []string{"rev-01", "rev-02", "rev-03"} {
		ts += 2
		mustApplyEnv(t, &fix, m, r, ts, EventPeerReviewRecorded, map[string]any{
			"proposal_id": "RQ-1", "score_bps": int64(8000), "report_hash": SHA256Hex([]byte(r)), "recommend": true, "coi_declared": false,
		})
	}
	for _, mc := range []string{"mc-01", "mc-02"} {
		ts += 2
		mustApplyEnv(t, &fix, m, mc, ts, EventMilestoneApproved, map[string]any{
			"proposal_id": "RQ-1", "milestone_index": int64(1), "evidence_hash": evHash, "notes_hash": SHA256Hex([]byte(mc)),
		})
	}
	ts += 2
	mustApplyEnv(t, &fix, m, "steward-01", ts, EventFundingQueued, map[string]any{"proposal_id": "RQ-1", "amount": int64(20_000)})
	ts += 2
	mustApplyEnv(t, &fix, m, "steward-02", ts, EventFundingCosigned, map[string]any{"proposal_id": "RQ-1"})

	// Emergency council revokes steward-02 before execution.
	ts += 5
	mustApplyEnv(t, &fix, m, "ec-01", ts, EventActorRevoked, map[string]any{
		"target_actor_id": "steward-02", "reason": "key compromise",
	})

	// Timelock passes, but active steward count is now only 1 (< 2) -> ERR_QUORUM_NOT_MET.
	ts += fix.Genesis.Config.TimelockSeconds + 10
	expectApplyErr(t, &fix, m, "steward-01", ts, EventFundingAuthorized, map[string]any{"proposal_id": "RQ-1"}, ErrQuorumNotMet)

	// Board guardian vetoes the queued proposal; subsequent authorization must fail with ERR_PROPOSAL_VETOED.
	ts += 5
	mustApplyEnv(t, &fix, m, "board-01", ts, EventBoardVetoRecorded, map[string]any{
		"proposal_id": "RQ-1", "justification": "501(c)(3) private benefit violation",
	})
	expectApplyErr(t, &fix, m, "steward-03", ts+1, EventFundingCosigned, map[string]any{"proposal_id": "RQ-1"}, ErrProposalVetoed)
	expectApplyErr(t, &fix, m, "steward-01", ts+2, EventFundingAuthorized, map[string]any{"proposal_id": "RQ-1"}, ErrProposalVetoed)
}

func TestMetaGovernanceAndEmergencyPauseLift(t *testing.T) {
	fix := BuildStandardFixture(1352, "test-meta-emergency")
	m, err := NewMachine(fix.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	ts := fix.BaseTime + 10

	// 3-of-4 META_GOVERNOR quorum changes timelock_seconds to 3600
	for _, mg := range []string{"meta-01", "meta-02", "meta-03"} {
		ts += 5
		mustApplyEnv(t, &fix, m, mg, ts, EventGovernanceRuleAmended, map[string]any{
			"change_id": "chg-tl-1", "parameter": "timelock_seconds", "new_value": int64(3600),
		})
	}
	if m.SnapshotState().Config.TimelockSeconds != 3600 {
		t.Fatalf("expected timelock_seconds=3600, got %d", m.SnapshotState().Config.TimelockSeconds)
	}

	// Emergency pause duration > 72h must be rejected (ZIP-0027 Temporal Bound)
	expectApplyErr(t, &fix, m, "ec-01", ts+5, EventEmergencyPauseSigned, map[string]any{
		"action_id": "bad-dur", "reason": "too long", "duration_seconds": MaxEmergencyDurationSeconds + 1,
	}, ErrInvalidPayload)

	// Valid 2-of-5 pause + early lift with post_review_hash
	ts += 10
	mustApplyEnv(t, &fix, m, "ec-01", ts, EventEmergencyPauseSigned, map[string]any{
		"action_id": "em-1", "reason": "oracle anomaly", "duration_seconds": int64(7200),
	})
	ts += 2
	mustApplyEnv(t, &fix, m, "ec-02", ts, EventEmergencyPauseSigned, map[string]any{
		"action_id": "em-1", "reason": "oracle anomaly", "duration_seconds": int64(7200),
	})
	if !m.SnapshotState().EmergencyPause.Active {
		t.Fatalf("expected emergency pause active")
	}
	reviewHash := SHA256Hex([]byte("post-emergency-report-em-1"))
	ts += 100
	mustApplyEnv(t, &fix, m, "ec-01", ts, EventEmergencyPauseLifted, map[string]any{
		"action_id": "em-1", "post_review_hash": reviewHash,
	})
	ts += 2
	mustApplyEnv(t, &fix, m, "ec-02", ts, EventEmergencyPauseLifted, map[string]any{
		"action_id": "em-1", "post_review_hash": reviewHash,
	})
	if m.SnapshotState().EmergencyPause.Active {
		t.Fatalf("expected emergency pause lifted")
	}
}

func TestWALColdRestartAndTamperDetection(t *testing.T) {
	dir := t.TempDir()
	fix := BuildStandardFixture(1352, "test-wal-restart")
	m, err := NewMachine(fix.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	wal, err := OpenWAL(dir, &fix.Genesis, true)
	if err != nil {
		t.Fatal(err)
	}
	m.AttachWAL(wal)

	ts := fix.BaseTime + 10
	planHash := SHA256Hex([]byte("wal-plan"))
	evHash := SHA256Hex([]byte("wal-evidence"))

	mustApplyEnv(t, &fix, m, "pi-01", ts, EventProposalSubmitted, map[string]any{
		"proposal_id": "WAL-1", "title": "WAL Persistence Test", "category": string(CategoryConservationResearch),
		"plan_hash": planHash, "source_paper": "p.tex", "requested_amount": int64(30_000),
	})
	for _, r := range []string{"rev-01", "rev-02", "rev-03"} {
		ts += 5
		mustApplyEnv(t, &fix, m, r, ts, EventPeerReviewRecorded, map[string]any{
			"proposal_id": "WAL-1", "score_bps": int64(8500), "report_hash": SHA256Hex([]byte(r)), "recommend": true, "coi_declared": false,
		})
	}

	// Write mid-lifecycle checkpoint at seq=4
	cp, err := m.CreateCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	cpPath, err := wal.WriteCheckpoint(cp)
	if err != nil {
		t.Fatal(err)
	}

	// Continue lifecycle after checkpoint (delta events)
	for _, mc := range []string{"mc-01", "mc-02"} {
		ts += 5
		mustApplyEnv(t, &fix, m, mc, ts, EventMilestoneApproved, map[string]any{
			"proposal_id": "WAL-1", "milestone_index": int64(1), "evidence_hash": evHash, "notes_hash": SHA256Hex([]byte(mc)),
		})
	}
	ts += 5
	mustApplyEnv(t, &fix, m, "steward-01", ts, EventFundingQueued, map[string]any{"proposal_id": "WAL-1", "amount": int64(30_000)})
	ts += 5
	mustApplyEnv(t, &fix, m, "steward-02", ts, EventFundingCosigned, map[string]any{"proposal_id": "WAL-1"})
	ts += fix.Genesis.Config.TimelockSeconds + 5
	mustApplyEnv(t, &fix, m, "steward-01", ts, EventFundingAuthorized, map[string]any{"proposal_id": "WAL-1"})
	ts += 50
	mustApplyEnv(t, &fix, m, "verif-01", ts, EventIndependentAcceptanceRecorded, map[string]any{
		"proposal_id": "WAL-1", "bound_evidence_hash": evHash, "repro_check_hash": SHA256Hex([]byte("wal-repro")), "verdict": "ACCEPTED",
	})

	liveSR, liveAR, err := m.Roots()
	if err != nil {
		t.Fatal(err)
	}
	if err := wal.Close(); err != nil {
		t.Fatal(err)
	}

	// Cold restart 1: full WAL replay
	mFull, err := ReplayFull(dir)
	if err != nil {
		t.Fatalf("ReplayFull: %v", err)
	}
	fullSR, fullAR, _ := mFull.Roots()
	if fullSR != liveSR || fullAR != liveAR {
		t.Fatalf("full replay mismatch: live=(%s,%s) full=(%s,%s)", liveSR, liveAR, fullSR, fullAR)
	}

	// Cold restart 2: checkpoint + delta replay
	mDelta, cpSeq, err := ReplayFromLatestCheckpoint(dir)
	if err != nil {
		t.Fatalf("ReplayFromLatestCheckpoint: %v", err)
	}
	if cpSeq != 4 {
		t.Fatalf("expected checkpoint seq 4, got %d", cpSeq)
	}
	deltaSR, deltaAR, _ := mDelta.Roots()
	if deltaSR != liveSR || deltaAR != liveAR {
		t.Fatalf("checkpoint+delta mismatch: live=(%s,%s) delta=(%s,%s)", liveSR, liveAR, deltaSR, deltaAR)
	}

	// Tamper test 1: corrupt checkpoint state_root_hash -> ERR_WAL_TAMPERED
	cpBytes, _ := os.ReadFile(cpPath)
	tamperedCP := strings.Replace(string(cpBytes), cp.StateRootHash, strings.Repeat("a", 64), 1)
	if err := os.WriteFile(cpPath, []byte(tamperedCP), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReplayFromLatestCheckpoint(dir); ErrorCodeOf(err) != ErrWALTampered {
		t.Fatalf("expected ERR_WAL_TAMPERED on corrupted checkpoint, got %v", err)
	}

	// Tamper test 2: mutate payload inside events.jsonl -> ERR_INVALID_SIGNATURE
	evPath := filepath.Join(dir, "events.jsonl")
	evBytes, _ := os.ReadFile(evPath)
	tamperedWAL := strings.Replace(string(evBytes), `"WAL Persistence Test"`, `"WAL Tampered Title!!"`, 1)
	if err := os.WriteFile(evPath, []byte(tamperedWAL), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayFull(dir); ErrorCodeOf(err) != ErrInvalidSignature {
		t.Fatalf("expected ERR_INVALID_SIGNATURE on tampered WAL line, got %v", err)
	}
}

func TestConcurrentMultiGrantRaceSafety(t *testing.T) {
	dir := t.TempDir()
	fix := BuildStandardFixture(1352, "test-race")
	m, err := NewMachine(fix.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	wal, err := OpenWAL(dir, &fix.Genesis, false)
	if err != nil {
		t.Fatal(err)
	}
	defer wal.Close()
	m.AttachWAL(wal)

	var wg sync.WaitGroup
	// Concurrent readers inspecting snapshots and cryptographic roots continuously
	stopReaders := make(chan struct{})
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopReaders:
					return
				default:
					_, _, _ = m.Roots()
					_ = m.SnapshotState()
				}
			}
		}()
	}

	// Concurrent adversarial probes trying unauthorized AI treasury calls while writers commit valid lifecycles
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			env, err := fix.SignNext(m, "ai-advisor-01", fix.BaseTime+100000+int64(i), EventFundingAuthorized, map[string]any{"proposal_id": "RACE-1"})
			if err == nil {
				_, _ = m.Apply(env) // must always reject (either ERR_AI_TREASURY_FORBIDDEN or seq race)
			}
		}
	}()

	// Serialized writer driving 10 full multi-grant lifecycles concurrently with readers & adversarial probes
	ts := fix.BaseTime + 10
	for i := 1; i <= 10; i++ {
		propID := "RACE-" + string(rune('A'+i))
		planHash := SHA256Hex([]byte("race-plan-" + propID))
		evHash := SHA256Hex([]byte("race-ev-" + propID))
		ts += 5
		mustApplyEnv(t, &fix, m, "pi-01", ts, EventProposalSubmitted, map[string]any{
			"proposal_id": propID, "title": propID, "category": string(CategoryCitizenScience),
			"plan_hash": planHash, "source_paper": "race.tex", "requested_amount": int64(5000),
		})
		for _, rev := range []string{"rev-01", "rev-02", "rev-03"} {
			ts += 2
			mustApplyEnv(t, &fix, m, rev, ts, EventPeerReviewRecorded, map[string]any{
				"proposal_id": propID, "score_bps": int64(8200), "report_hash": SHA256Hex([]byte(propID + rev)), "recommend": true, "coi_declared": false,
			})
		}
		for _, mc := range []string{"mc-01", "mc-02"} {
			ts += 2
			mustApplyEnv(t, &fix, m, mc, ts, EventMilestoneApproved, map[string]any{
				"proposal_id": propID, "milestone_index": int64(1), "evidence_hash": evHash, "notes_hash": SHA256Hex([]byte(propID + mc)),
			})
		}
		ts += 2
		mustApplyEnv(t, &fix, m, "steward-01", ts, EventFundingQueued, map[string]any{"proposal_id": propID, "amount": int64(5000)})
		ts += 2
		mustApplyEnv(t, &fix, m, "steward-02", ts, EventFundingCosigned, map[string]any{"proposal_id": propID})
		ts += fix.Genesis.Config.TimelockSeconds + 5
		mustApplyEnv(t, &fix, m, "steward-01", ts, EventFundingAuthorized, map[string]any{"proposal_id": propID})
		ts += 10
		mustApplyEnv(t, &fix, m, "verif-01", ts, EventIndependentAcceptanceRecorded, map[string]any{
			"proposal_id": propID, "bound_evidence_hash": evHash, "repro_check_hash": SHA256Hex([]byte("repro-" + propID)), "verdict": "ACCEPTED",
		})
	}

	close(stopReaders)
	wg.Wait()

	// Verify WAL cold replay matches live roots after concurrent execution
	liveSR, liveAR, err := m.Roots()
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := ReplayFull(dir)
	if err != nil {
		t.Fatalf("ReplayFull after concurrent run: %v", err)
	}
	repSR, repAR, _ := replayed.Roots()
	if liveSR != repSR || liveAR != repAR {
		t.Fatalf("concurrent replay mismatch")
	}
}

func TestPeerReviewRejectionBlocksMilestone(t *testing.T) {
	fix := BuildStandardFixture(1352, "test-review-reject")
	m, err := NewMachine(fix.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	ts := fix.BaseTime + 10
	planHash := SHA256Hex([]byte("weak-plan"))
	mustApplyEnv(t, &fix, m, "pi-01", ts, EventProposalSubmitted, map[string]any{
		"proposal_id": "LOW-1", "title": "Low Score Proposal", "category": string(CategoryEducation),
		"plan_hash": planHash, "source_paper": "p.tex", "requested_amount": int64(5000),
	})
	for _, r := range []string{"rev-01", "rev-02", "rev-03"} {
		ts += 2
		mustApplyEnv(t, &fix, m, r, ts, EventPeerReviewRecorded, map[string]any{
			"proposal_id": "LOW-1", "score_bps": int64(4500), "report_hash": SHA256Hex([]byte(r)), "recommend": false, "coi_declared": false,
		})
	}
	st := m.SnapshotState()
	if st.Proposals["LOW-1"].Status != StatusReviewRejected {
		t.Fatalf("expected REVIEW_REJECTED, got %s", st.Proposals["LOW-1"].Status)
	}
	expectApplyErr(t, &fix, m, "mc-01", ts+5, EventMilestoneApproved, map[string]any{
		"proposal_id": "LOW-1", "milestone_index": int64(1), "evidence_hash": SHA256Hex([]byte("ev")), "notes_hash": SHA256Hex([]byte("n")),
	}, ErrInvalidTransition)
}

func TestIndependentVerifierConstraintsAndEvidenceBinding(t *testing.T) {
	fix := BuildStandardFixture(1352, "test-verifier-indep")
	// Give pi-01, rev-01, mc-01 also INDEPENDENT_VERIFIER role to prove separation is enforced even with dual roles.
	for i := range fix.Genesis.Actors {
		switch fix.Genesis.Actors[i].ID {
		case "pi-01", "rev-01", "mc-01":
			fix.Genesis.Actors[i].Roles = append(fix.Genesis.Actors[i].Roles, RoleIndependentVerifier)
		}
	}
	m, err := NewMachine(fix.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	ts := fix.BaseTime + 10
	planHash := SHA256Hex([]byte("indep-plan"))
	evHash := SHA256Hex([]byte("indep-ev"))

	mustApplyEnv(t, &fix, m, "pi-01", ts, EventProposalSubmitted, map[string]any{
		"proposal_id": "IND-1", "title": "Independence Check", "category": string(CategoryConservationResearch),
		"plan_hash": planHash, "source_paper": "p.tex", "requested_amount": int64(10_000),
	})
	for _, r := range []string{"rev-01", "rev-02", "rev-03"} {
		ts += 2
		mustApplyEnv(t, &fix, m, r, ts, EventPeerReviewRecorded, map[string]any{
			"proposal_id": "IND-1", "score_bps": int64(8000), "report_hash": SHA256Hex([]byte(r)), "recommend": true, "coi_declared": false,
		})
	}
	for _, mc := range []string{"mc-01", "mc-02"} {
		ts += 2
		mustApplyEnv(t, &fix, m, mc, ts, EventMilestoneApproved, map[string]any{
			"proposal_id": "IND-1", "milestone_index": int64(1), "evidence_hash": evHash, "notes_hash": SHA256Hex([]byte(mc)),
		})
	}
	ts += 2
	mustApplyEnv(t, &fix, m, "steward-01", ts, EventFundingQueued, map[string]any{"proposal_id": "IND-1", "amount": int64(10_000)})
	ts += 2
	mustApplyEnv(t, &fix, m, "steward-02", ts, EventFundingCosigned, map[string]any{"proposal_id": "IND-1"})
	ts += fix.Genesis.Config.TimelockSeconds + 5
	mustApplyEnv(t, &fix, m, "steward-01", ts, EventFundingAuthorized, map[string]any{"proposal_id": "IND-1"})

	reproHash := SHA256Hex([]byte("indep-repro"))
	// Proposer, peer reviewer, and milestone approver must ALL be blocked as non-independent.
	for _, nonIndep := range []string{"pi-01", "rev-01", "mc-01"} {
		expectApplyErr(t, &fix, m, nonIndep, ts+5, EventIndependentAcceptanceRecorded, map[string]any{
			"proposal_id": "IND-1", "bound_evidence_hash": evHash, "repro_check_hash": reproHash, "verdict": "ACCEPTED",
		}, ErrVerifierNotIndependent)
	}
	// Wrong bound_evidence_hash fails
	expectApplyErr(t, &fix, m, "verif-01", ts+5, EventIndependentAcceptanceRecorded, map[string]any{
		"proposal_id": "IND-1", "bound_evidence_hash": SHA256Hex([]byte("wrong")), "repro_check_hash": reproHash, "verdict": "ACCEPTED",
	}, ErrEvidenceMismatch)
	// Reusing evHash as repro_check_hash fails
	expectApplyErr(t, &fix, m, "verif-01", ts+5, EventIndependentAcceptanceRecorded, map[string]any{
		"proposal_id": "IND-1", "bound_evidence_hash": evHash, "repro_check_hash": evHash, "verdict": "ACCEPTED",
	}, ErrEvidenceMismatch)
}

func TestEpochSpendCapAndRollover(t *testing.T) {
	fix := BuildStandardFixture(1352, "test-epoch-cap")
	fix.Genesis.InitialTreasuryBalance = 1_000_000 // 10% epoch cap = 100,000 ZOO
	m, err := NewMachine(fix.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	ts := fix.BaseTime + 10

	prepGrant := func(id string, amt int64) {
		ts += 2
		mustApplyEnv(t, &fix, m, "pi-01", ts, EventProposalSubmitted, map[string]any{
			"proposal_id": id, "title": id, "category": string(CategoryConservationResearch),
			"plan_hash": SHA256Hex([]byte("plan-" + id)), "source_paper": "p.tex", "requested_amount": amt,
		})
		for _, r := range []string{"rev-01", "rev-02", "rev-03"} {
			ts += 2
			mustApplyEnv(t, &fix, m, r, ts, EventPeerReviewRecorded, map[string]any{
				"proposal_id": id, "score_bps": int64(8000), "report_hash": SHA256Hex([]byte(id + r)), "recommend": true, "coi_declared": false,
			})
		}
		for _, mc := range []string{"mc-01", "mc-02"} {
			ts += 2
			mustApplyEnv(t, &fix, m, mc, ts, EventMilestoneApproved, map[string]any{
				"proposal_id": id, "milestone_index": int64(1), "evidence_hash": SHA256Hex([]byte("ev-" + id)), "notes_hash": SHA256Hex([]byte(id + mc)),
			})
		}
	}

	prepGrant("CAP-1", 90_000)
	ts += 2
	mustApplyEnv(t, &fix, m, "steward-01", ts, EventFundingQueued, map[string]any{"proposal_id": "CAP-1", "amount": int64(90_000)})
	ts += 2
	mustApplyEnv(t, &fix, m, "steward-02", ts, EventFundingCosigned, map[string]any{"proposal_id": "CAP-1"})
	ts += fix.Genesis.Config.TimelockSeconds + 5
	mustApplyEnv(t, &fix, m, "steward-01", ts, EventFundingAuthorized, map[string]any{"proposal_id": "CAP-1"})

	// Second grant of 20,000 in the same 30-day epoch exceeds remaining 10% cap (90k + 20k > 91k).
	prepGrant("CAP-2", 20_000)
	expectApplyErr(t, &fix, m, "steward-01", ts+5, EventFundingQueued, map[string]any{
		"proposal_id": "CAP-2", "amount": int64(20_000),
	}, ErrBudgetCapExceeded)

	// Roll over into the next 30-day epoch -> succeeds!
	ts += fix.Genesis.Config.EpochDurationSeconds + 10
	mustApplyEnv(t, &fix, m, "steward-01", ts, EventFundingQueued, map[string]any{
		"proposal_id": "CAP-2", "amount": int64(20_000),
	})
}

func TestEnvelopeReplayChainAndTimestampGuards(t *testing.T) {
	fix := BuildStandardFixture(1352, "test-envelope-guards")
	m, err := NewMachine(fix.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	ts := fix.BaseTime + 100
	env1, err := fix.SignNext(m, "pi-01", ts, EventProposalSubmitted, map[string]any{
		"proposal_id": "G-1", "title": "Guard Test", "category": string(CategoryEducation),
		"plan_hash": SHA256Hex([]byte("g1")), "source_paper": "p.tex", "requested_amount": int64(1000),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(env1); err != nil {
		t.Fatal(err)
	}

	// 1. Sequence mismatch (replaying exact env1)
	if _, err := m.Apply(env1); ErrorCodeOf(err) != ErrInvalidSequence {
		t.Fatalf("expected ERR_INVALID_SEQUENCE, got %v", err)
	}
	// 2. Broken prev_event_hash chain
	badChain := Envelope{
		SpecVersion: SpecVersion, Seq: 2, PrevEventHash: GenesisPrevHash,
		Timestamp: ts + 5, ActorID: "pi-01", Nonce: 2, Type: EventProposalSubmitted,
		Payload: map[string]any{"proposal_id": "G-2", "title": "G2", "category": "EDUCATION", "plan_hash": SHA256Hex([]byte("g2")), "source_paper": "p.tex", "requested_amount": int64(1000)},
	}
	badChain, _ = SignEnvelope(badChain, fix.Keys["pi-01"].PrivateKey)
	if _, err := m.Apply(badChain); ErrorCodeOf(err) != ErrChainBroken {
		t.Fatalf("expected ERR_CHAIN_BROKEN, got %v", err)
	}
	// 3. Timestamp regression
	badTS, _ := fix.SignNext(m, "pi-01", ts-1, EventProposalSubmitted, map[string]any{
		"proposal_id": "G-2", "title": "G2", "category": "EDUCATION", "plan_hash": SHA256Hex([]byte("g2")), "source_paper": "p.tex", "requested_amount": int64(1000),
	})
	if _, err := m.Apply(badTS); ErrorCodeOf(err) != ErrTimestampRegression {
		t.Fatalf("expected ERR_TIMESTAMP_REGRESSION, got %v", err)
	}
	// 4. Nonce replay (valid seq & prev_hash, stale nonce=1)
	badNonce := Envelope{
		SpecVersion: SpecVersion, Seq: 2, PrevEventHash: m.LastEventHash(),
		Timestamp: ts + 5, ActorID: "pi-01", Nonce: 1, Type: EventProposalSubmitted,
		Payload: map[string]any{"proposal_id": "G-2", "title": "G2", "category": "EDUCATION", "plan_hash": SHA256Hex([]byte("g2")), "source_paper": "p.tex", "requested_amount": int64(1000)},
	}
	badNonce, _ = SignEnvelope(badNonce, fix.Keys["pi-01"].PrivateKey)
	if _, err := m.Apply(badNonce); ErrorCodeOf(err) != ErrNonceReplay {
		t.Fatalf("expected ERR_NONCE_REPLAY, got %v", err)
	}
}


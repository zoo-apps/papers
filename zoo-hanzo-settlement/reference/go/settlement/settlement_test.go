// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package settlement

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func testPolicy() NetworkPolicy {
	return NetworkPolicy{
		ValidatorQuorum:          3,
		ValidatorCommitteeSize:   5,
		FinalityDelayEpochs:      2,
		ClaimWindowEpochs:        6,
		ConservationBPS:          DefaultConservationBPS,
		ProtocolBPS:              DefaultProtocolBPS,
		EpochTreasuryCapMicroZOO: 5_000_000_000,
	}
}

func testSampleJobWork(kr actorKeyring, id string, epoch uint64, maxBudget, consumed int64) (AdmittedJob, WorkResult) {
	paperHash := SHA256Hex("paper:" + id)
	specHash := SHA256Hex("spec:" + id)
	outDigest := SHA256Hex("out:" + id)
	job := AdmittedJob{
		JobID:             id,
		PayerID:           kr.payers[0],
		ProviderID:        kr.providers[0],
		Epoch:             epoch,
		ModelTier:         "medium",
		CorpusPaperID:     "zoo-hanzo-settlement",
		CorpusPaperSHA256: paperHash,
		WorkSpecHash:      specHash,
		MaxBudgetMicroZOO: maxBudget,
		ConservationBPS:   DefaultConservationBPS,
		ProtocolBPS:       DefaultProtocolBPS,
	}
	wh := ComputeWorkHash(job.JobID, job.CorpusPaperSHA256, job.WorkSpecHash, outDigest, 4096, 512)
	work := WorkResult{
		JobID:            job.JobID,
		ProviderID:       job.ProviderID,
		OutputDigest:     outDigest,
		TokensProcessed:  4096,
		ComputeUnits:     512,
		ConsumedMicroZOO: consumed,
		WorkHash:         wh,
	}
	return job, work
}

func TestExactMicroZOOSplitAndConservation(t *testing.T) {
	cases := []struct {
		maxBudget, consumed, consBPS, protoBPS int64
	}{
		{1_000_000, 1_000_000, 200, 100},
		{1_000_007, 999_999, 200, 100},   // odd prime-ish remainder dust check
		{50_003, 17_333, 250, 125},       // non-round bps dust check
		{10, 1, 200, 100},                // minimal 1 micro-ZOO unit
		{1_000_000, 500_000, 0, 0},       // zero fees
	}
	for _, tc := range cases {
		split, err := ComputeExactSplit(tc.maxBudget, tc.consumed, tc.consBPS, tc.protoBPS)
		if err != nil {
			t.Fatalf("ComputeExactSplit(%+v) unexpected error: %v", tc, err)
		}
		if split.ProviderShare+split.ConservationShare+split.ProtocolFee != tc.consumed {
			t.Fatalf("conservation violated: %+v vs consumed=%d", split, tc.consumed)
		}
		if tc.consumed+split.Refund != tc.maxBudget {
			t.Fatalf("escrow conservation violated: consumed=%d refund=%d max=%d", tc.consumed, split.Refund, tc.maxBudget)
		}
	}
	if _, err := ComputeExactSplit(1000, 1001, 200, 100); ErrorCodeOf(err) != ErrBudgetOverflow {
		t.Fatalf("expected ERR_BUDGET_OVERFLOW, got %v", err)
	}
	if _, err := ComputeExactSplit(1000, 0, 200, 100); ErrorCodeOf(err) != ErrInvalidSchema {
		t.Fatalf("expected ERR_INVALID_SCHEMA on zero consumed, got %v", err)
	}
}

func TestMerkleTreeAndInclusionProofs(t *testing.T) {
	if got := ComputeMerkleRoot(nil); got != EmptyMerkleRoot() {
		t.Fatalf("empty root mismatch")
	}
	for _, n := range []int{1, 2, 3, 5, 16, 20} {
		leaves := make([]string, n)
		for i := 0; i < n; i++ {
			leaves[i] = ComputeReceiptMerkleLeaf(SHA256Hex("r"+string(rune('a'+i))), SHA256Hex("n"+string(rune('a'+i))), int64(1000+i))
		}
		root := ComputeMerkleRoot(leaves)
		for i := 0; i < n; i++ {
			proof, pRoot, err := BuildMerkleProof(leaves, i)
			if err != nil || pRoot != root {
				t.Fatalf("BuildMerkleProof n=%d i=%d failed: err=%v", n, i, err)
			}
			if !VerifyMerkleProof(leaves[i], proof, root) {
				t.Fatalf("VerifyMerkleProof failed for valid leaf n=%d i=%d", n, i)
			}
			// Tamper leaf -> must fail.
			if VerifyMerkleProof(SHA256Hex("wrong-leaf"), proof, root) {
				t.Fatalf("VerifyMerkleProof accepted wrong leaf")
			}
			// Tamper first sibling -> must fail (for n > 1).
			if len(proof) > 0 {
				bad := make([]MerkleProofStep, len(proof))
				copy(bad, proof)
				b, _ := hex.DecodeString(bad[0].SiblingHex)
				b[0] ^= 0x01
				bad[0].SiblingHex = hex.EncodeToString(b)
				if VerifyMerkleProof(leaves[i], bad, root) {
					t.Fatalf("VerifyMerkleProof accepted tampered sibling")
				}
			}
		}
	}
}

func TestEASAttestationAndEd25519Verification(t *testing.T) {
	kr := buildTestNetKeyring(1350)
	pol := testPolicy()
	pMap, err := ValidatePrincipalKeySeparation(kr.principals)
	if err != nil {
		t.Fatal(err)
	}
	vc, err := NewValidatorCommittee(kr.principals, kr.validators)
	if err != nil {
		t.Fatal(err)
	}
	job, work := testSampleJobWork(kr, "job-eas-01", 1, 2_000_000, 1_500_000)
	if err := vc.AdmitJob(job); err != nil {
		t.Fatal(err)
	}
	atts, err := vc.VerifyAndAttest(job.JobID, work)
	if err != nil {
		t.Fatal(err)
	}
	if len(atts) != 5 {
		t.Fatalf("expected 5 attestations, got %d", len(atts))
	}
	if err := ValidateQuorumAttestations(job, work, atts, pMap, pol); err != nil {
		t.Fatalf("valid quorum rejected: %v", err)
	}
	// Corrupt signature -> ERR_INVALID_SIGNATURE.
	badSig := make([]EASAttestation, len(atts))
	copy(badSig, atts)
	sb, _ := hex.DecodeString(badSig[0].SignatureHex)
	sb[3] ^= 0xff
	badSig[0].SignatureHex = hex.EncodeToString(sb)
	if err := ValidateQuorumAttestations(job, work, badSig, pMap, pol); ErrorCodeOf(err) != ErrInvalidSignature {
		t.Fatalf("expected ERR_INVALID_SIGNATURE, got %v", err)
	}
	// Corrupt AttestationUID -> ERR_INVALID_ATTESTATION_UID.
	badUID := make([]EASAttestation, len(atts))
	copy(badUID, atts)
	ub, _ := hex.DecodeString(badUID[0].AttestationUID)
	ub[0] ^= 0xff
	badUID[0].AttestationUID = hex.EncodeToString(ub)
	if err := ValidateQuorumAttestations(job, work, badUID, pMap, pol); ErrorCodeOf(err) != ErrInvalidAttestationUID {
		t.Fatalf("expected ERR_INVALID_ATTESTATION_UID, got %v", err)
	}
}

func TestPrincipalKeySeparation(t *testing.T) {
	kr := buildTestNetKeyring(1350)
	if _, err := ValidatePrincipalKeySeparation(kr.principals); err != nil {
		t.Fatalf("clean keyring failed separation: %v", err)
	}
	bad := make([]Principal, len(kr.principals))
	copy(bad, kr.principals)
	bad[len(bad)-1].PublicKeyHex = bad[0].PublicKeyHex
	if _, err := ValidatePrincipalKeySeparation(bad); ErrorCodeOf(err) != ErrKeyRoleConflict {
		t.Fatalf("expected ERR_KEY_ROLE_CONFLICT, got %v", err)
	}
}

func TestSelfVerificationForbidden(t *testing.T) {
	kr := buildTestNetKeyring(1350)
	pol := testPolicy()
	pMap, _ := ValidatePrincipalKeySeparation(kr.principals)
	job, work := testSampleJobWork(kr, "job-self-01", 1, 2_000_000, 1_000_000)

	att := EASAttestation{
		SchemaUID:        CanonicalEASSchemaUID(),
		RefUID:           ComputeRefUID(job.JobID),
		JobID:            job.JobID,
		Recipient:        job.ProviderID,
		Attester:         job.ProviderID,
		WorkHash:         work.WorkHash,
		Epoch:            job.Epoch,
		Nonce:            1,
		TokensProcessed:  work.TokensProcessed,
		ComputeUnits:     work.ComputeUnits,
		ConsumedMicroZOO: work.ConsumedMicroZOO,
	}
	att.AttestationUID = ComputeAttestationUID(att.SchemaUID, att.RefUID, att.Recipient, att.Attester, att.WorkHash, att.Epoch, att.Nonce)
	att.SignatureHex = SignEd25519Hex(kr.privKeys[job.ProviderID], ValidatorSignatureMessage(att))
	if err := ValidateQuorumAttestations(job, work, []EASAttestation{att}, pMap, pol); ErrorCodeOf(err) != ErrSelfVerificationForbid {
		t.Fatalf("expected ERR_SELF_VERIFICATION_FORBIDDEN, got %v", err)
	}
}

func TestConstitutionalAppAndAILocks(t *testing.T) {
	kr := buildTestNetKeyring(1350)
	pol := testPolicy()
	vc, _ := NewValidatorCommittee(kr.principals, kr.validators)
	se, _ := NewSettlementEngine(kr.settlementID, pol, kr.principals, "")
	gate, _ := NewFinalityTreasuryGate(pol, kr.principals, kr.authorities, "")

	job, work := testSampleJobWork(kr, "job-lock-01", 1, 2_000_000, 1_000_000)
	_ = vc.AdmitJob(job)
	atts, _ := vc.VerifyAndAttest(job.JobID, work)

	// Application cannot issue receipts.
	if _, err := se.IssueReceipt(kr.apps[0], RoleApplication, job, work, atts); ErrorCodeOf(err) != ErrAppIssuanceForbidden {
		t.Fatalf("expected ERR_APP_ISSUANCE_FORBIDDEN for app receipt issue, got %v", err)
	}
	// AI agent cannot issue receipts.
	if _, err := se.IssueReceipt(kr.aiAgents[0], RoleAIAgent, job, work, atts); ErrorCodeOf(err) != ErrAIIssuanceForbidden {
		t.Fatalf("expected ERR_AI_ISSUANCE_FORBIDDEN for AI receipt issue, got %v", err)
	}

	rec, err := se.IssueReceipt(kr.settlementID, RoleSettlementNode, job, work, atts)
	if err != nil {
		t.Fatal(err)
	}
	comm, proofs, err := se.SealEpoch(1)
	if err != nil {
		t.Fatal(err)
	}
	_ = gate.RegisterEpochCommitment(comm)

	// Read-only application CAN consume verified receipt.
	appClient := &ReadOnlyApplicationClient{AppID: kr.apps[0], Settlement: se}
	if got, ok := appClient.ConsumeVerifiedReceipt(rec.ReceiptID); !ok || got.ReceiptID != rec.ReceiptID {
		t.Fatalf("read-only application failed to read verified receipt")
	}

	// Application CANNOT authorize rewards.
	if _, err := gate.AuthorizeReward(kr.apps[0], RoleApplication, 3, job, work, atts, rec, proofs[rec.ReceiptID]); ErrorCodeOf(err) != ErrAppIssuanceForbidden {
		t.Fatalf("expected ERR_APP_ISSUANCE_FORBIDDEN for app reward auth, got %v", err)
	}
	// AI agent CANNOT authorize rewards.
	if _, err := gate.AuthorizeReward(kr.aiAgents[0], RoleAIAgent, 3, job, work, atts, rec, proofs[rec.ReceiptID]); ErrorCodeOf(err) != ErrAIIssuanceForbidden {
		t.Fatalf("expected ERR_AI_ISSUANCE_FORBIDDEN for AI reward auth, got %v", err)
	}
	// AI agent and Application CANNOT mutate policy.
	if err := gate.UpdatePolicy(PolicyMutationAttempt{ActorID: kr.aiAgents[0], ActorRole: RoleAIAgent, Field: "epoch_treasury_cap_micro_zoo", ProposedValue: 999}); ErrorCodeOf(err) != ErrAIPolicyMutationForbid {
		t.Fatalf("expected ERR_AI_POLICY_MUTATION_FORBIDDEN for AI, got %v", err)
	}
	if err := gate.UpdatePolicy(PolicyMutationAttempt{ActorID: kr.apps[0], ActorRole: RoleApplication, Field: "validator_quorum", ProposedValue: 1}); ErrorCodeOf(err) != ErrAIPolicyMutationForbid {
		t.Fatalf("expected ERR_AI_POLICY_MUTATION_FORBIDDEN for app, got %v", err)
	}
}

func TestLayerSeparationValidatorAndSettlementCannotMint(t *testing.T) {
	kr := buildTestNetKeyring(1350)
	pol := testPolicy()
	vc, _ := NewValidatorCommittee(kr.principals, kr.validators)
	se, _ := NewSettlementEngine(kr.settlementID, pol, kr.principals, "")
	gate, _ := NewFinalityTreasuryGate(pol, kr.principals, kr.authorities, "")

	job, work := testSampleJobWork(kr, "job-sep-01", 1, 2_000_000, 1_000_000)
	_ = vc.AdmitJob(job)
	atts, _ := vc.VerifyAndAttest(job.JobID, work)
	rec, _ := se.IssueReceipt(kr.settlementID, RoleSettlementNode, job, work, atts)
	comm, proofs, _ := se.SealEpoch(1)
	_ = gate.RegisterEpochCommitment(comm)

	if _, err := gate.AuthorizeReward(kr.validators[0].ID, RoleValidator, 3, job, work, atts, rec, proofs[rec.ReceiptID]); ErrorCodeOf(err) != ErrUnauthorizedTreasury {
		t.Fatalf("expected ERR_UNAUTHORIZED_TREASURY for validator mint, got %v", err)
	}
	if _, err := gate.AuthorizeReward(kr.settlementID, RoleSettlementNode, 3, job, work, atts, rec, proofs[rec.ReceiptID]); ErrorCodeOf(err) != ErrUnauthorizedTreasury {
		t.Fatalf("expected ERR_UNAUTHORIZED_TREASURY for settlement node mint, got %v", err)
	}
}

func TestWALPersistenceColdRestartAndTamperDetection(t *testing.T) {
	tmpDir := t.TempDir()
	l2Path := filepath.Join(tmpDir, "l2.wal.jsonl")
	l3Path := filepath.Join(tmpDir, "l3.wal.jsonl")

	kr := buildTestNetKeyring(1350)
	pol := testPolicy()
	vc, _ := NewValidatorCommittee(kr.principals, kr.validators)
	se, err := NewSettlementEngine(kr.settlementID, pol, kr.principals, l2Path)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := NewFinalityTreasuryGate(pol, kr.principals, kr.authorities, l3Path)
	if err != nil {
		t.Fatal(err)
	}

	job, work := testSampleJobWork(kr, "job-wal-01", 1, 3_000_000, 2_250_000)
	_ = vc.AdmitJob(job)
	atts, _ := vc.VerifyAndAttest(job.JobID, work)
	rec, err := se.IssueReceipt(kr.settlementID, RoleSettlementNode, job, work, atts)
	if err != nil {
		t.Fatal(err)
	}
	comm, proofs, err := se.SealEpoch(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.RegisterEpochCommitment(comm); err != nil {
		t.Fatal(err)
	}
	if _, err := gate.AuthorizeReward(kr.authorities[0].ID, RoleGovernanceTreasury, 3, job, work, atts, rec, proofs[rec.ReceiptID]); err != nil {
		t.Fatal(err)
	}
	beforeBS := gate.BalanceSheetSnapshot()
	_ = se.Close()
	_ = gate.Close()

	// Cold restart from fsync WAL files.
	se2, err := NewSettlementEngine(kr.settlementID, pol, kr.principals, l2Path)
	if err != nil {
		t.Fatalf("cold restart L2 failed: %v", err)
	}
	defer se2.Close()
	gate2, err := NewFinalityTreasuryGate(pol, kr.principals, kr.authorities, l3Path)
	if err != nil {
		t.Fatalf("cold restart L3 failed: %v", err)
	}
	defer gate2.Close()

	if !equalBalanceSheets(beforeBS, gate2.BalanceSheetSnapshot()) {
		t.Fatalf("cold restart balance sheet diverged")
	}
	if _, err := se2.IssueReceipt(kr.settlementID, RoleSettlementNode, job, work, atts); ErrorCodeOf(err) != ErrDoubleClaim {
		t.Fatalf("cold restart failed to block L2 double-claim: %v", err)
	}
	if _, err := gate2.AuthorizeReward(kr.authorities[0].ID, RoleGovernanceTreasury, 3, job, work, atts, rec, proofs[rec.ReceiptID]); ErrorCodeOf(err) != ErrDoubleClaim {
		t.Fatalf("cold restart failed to block L3 double-claim: %v", err)
	}

	// Corrupt WAL file and assert tamper detection fails cleanly on reopen.
	raw, _ := os.ReadFile(l2Path)
	corrupted := strings.Replace(string(raw), "job-wal-01", "job-wal-99", 1)
	_ = os.WriteFile(l2Path, []byte(corrupted), 0o600)
	if _, err := NewSettlementEngine(kr.settlementID, pol, kr.principals, l2Path); err == nil {
		t.Fatalf("expected WAL tamper detection error, got nil")
	}
}

func TestConcurrent64GoroutineDoubleClaimRace(t *testing.T) {
	const workers = 64
	kr := buildTestNetKeyring(1350)
	pol := testPolicy()
	vc, _ := NewValidatorCommittee(kr.principals, kr.validators)
	se, _ := NewSettlementEngine(kr.settlementID, pol, kr.principals, "")
	gate, _ := NewFinalityTreasuryGate(pol, kr.principals, kr.authorities, "")

	job, work := testSampleJobWork(kr, "job-race-64", 1, 4_000_000, 3_000_000)
	_ = vc.AdmitJob(job)
	atts, _ := vc.VerifyAndAttest(job.JobID, work)

	var l2OK, l2Dup int32
	var winRec UsefulWorkReceipt
	var mu sync.Mutex
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r, err := se.IssueReceipt(kr.settlementID, RoleSettlementNode, job, work, atts)
			if err == nil {
				atomic.AddInt32(&l2OK, 1)
				mu.Lock()
				winRec = r
				mu.Unlock()
			} else if ErrorCodeOf(err) == ErrDoubleClaim {
				atomic.AddInt32(&l2Dup, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if l2OK != 1 || l2Dup != workers-1 {
		t.Fatalf("L2 64-goroutine race violation: accepted=%d rejected=%d", l2OK, l2Dup)
	}

	comm, proofs, err := se.SealEpoch(1)
	if err != nil {
		t.Fatal(err)
	}
	_ = gate.RegisterEpochCommitment(comm)

	var l3OK, l3Dup int32
	start3 := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start3
			_, err := gate.AuthorizeReward(kr.authorities[0].ID, RoleGovernanceTreasury, 3, job, work, atts, winRec, proofs[winRec.ReceiptID])
			if err == nil {
				atomic.AddInt32(&l3OK, 1)
			} else if ErrorCodeOf(err) == ErrDoubleClaim {
				atomic.AddInt32(&l3Dup, 1)
			}
		}()
	}
	close(start3)
	wg.Wait()

	if l3OK != 1 || l3Dup != workers-1 {
		t.Fatalf("L3 64-goroutine race violation: accepted=%d rejected=%d", l3OK, l3Dup)
	}
	bs := gate.BalanceSheetSnapshot()
	if bs.AuthorizedReceiptCount != 1 || !bs.ConservationExact {
		t.Fatalf("unexpected post-race balance sheet: %+v", bs)
	}
}

func TestLiveLoopbackHTTPMultiNodeLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	kr := buildTestNetKeyring(1350)
	pol := testPolicy()

	vc, _ := NewValidatorCommittee(kr.principals, kr.validators)
	se, _ := NewSettlementEngine(kr.settlementID, pol, kr.principals, filepath.Join(tmpDir, "l2.wal"))
	defer se.Close()
	gate, _ := NewFinalityTreasuryGate(pol, kr.principals, kr.authorities, filepath.Join(tmpDir, "l3.wal"))
	defer gate.Close()

	tn, err := StartLoopbackTestNet(vc, se, gate)
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Close()

	job, work := testSampleJobWork(kr, "job-http-01", 1, 5_000_000, 4_000_000)
	if err := tn.HTTPAdmitJob(job); err != nil {
		t.Fatalf("HTTPAdmitJob failed: %v", err)
	}
	atts, err := tn.HTTPVerifyAndAttest(job.JobID, work)
	if err != nil {
		t.Fatalf("HTTPVerifyAndAttest failed: %v", err)
	}
	// App cannot settle over HTTP.
	if _, err := tn.HTTPIssueReceipt(kr.apps[0], RoleApplication, job, work, atts); ErrorCodeOf(err) != ErrAppIssuanceForbidden {
		t.Fatalf("expected ERR_APP_ISSUANCE_FORBIDDEN over HTTP, got %v", err)
	}
	rec, err := tn.HTTPIssueReceipt(kr.settlementID, RoleSettlementNode, job, work, atts)
	if err != nil {
		t.Fatalf("HTTPIssueReceipt failed: %v", err)
	}
	// Duplicate settle over HTTP -> ERR_DOUBLE_CLAIM.
	if _, err := tn.HTTPIssueReceipt(kr.settlementID, RoleSettlementNode, job, work, atts); ErrorCodeOf(err) != ErrDoubleClaim {
		t.Fatalf("expected ERR_DOUBLE_CLAIM on HTTP replay, got %v", err)
	}
	// Read-only consumer query over HTTP succeeds.
	gotRec, err := tn.HTTPReadReceipt(rec.ReceiptID)
	if err != nil || gotRec.ReceiptID != rec.ReceiptID {
		t.Fatalf("HTTPReadReceipt failed: %v", err)
	}
	comm, proofs, err := tn.HTTPSealEpoch(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := tn.HTTPRegisterEpochCommitment(comm); err != nil {
		t.Fatal(err)
	}
	// AI agent cannot authorize or mutate policy over HTTP.
	if _, err := tn.HTTPAuthorizeReward(kr.aiAgents[0], RoleAIAgent, 3, job, work, atts, rec, proofs[rec.ReceiptID]); ErrorCodeOf(err) != ErrAIIssuanceForbidden {
		t.Fatalf("expected ERR_AI_ISSUANCE_FORBIDDEN over HTTP, got %v", err)
	}
	if err := tn.HTTPUpdatePolicy(PolicyMutationAttempt{ActorID: kr.aiAgents[0], ActorRole: RoleAIAgent, Field: "validator_quorum", ProposedValue: 1}); ErrorCodeOf(err) != ErrAIPolicyMutationForbid {
		t.Fatalf("expected ERR_AI_POLICY_MUTATION_FORBIDDEN over HTTP, got %v", err)
	}
	// Authorized GOVERNANCE_TREASURY succeeds over HTTP.
	auth, err := tn.HTTPAuthorizeReward(kr.authorities[0].ID, RoleGovernanceTreasury, 3, job, work, atts, rec, proofs[rec.ReceiptID])
	if err != nil {
		t.Fatalf("HTTPAuthorizeReward failed: %v", err)
	}
	if auth.ReceiptID != rec.ReceiptID {
		t.Fatalf("unexpected auth receipt_id")
	}
	bs, err := tn.HTTPGetBalances()
	if err != nil || !bs.ConservationExact || bs.TotalAuthorizedPayoutMicroZOO != 4_000_000 || bs.TotalPayerRefundsMicroZOO != 1_000_000 {
		t.Fatalf("unexpected HTTP balance sheet: %+v err=%v", bs, err)
	}
}

func TestFinalityWindowAndExpiration(t *testing.T) {
	kr := buildTestNetKeyring(1350)
	pol := testPolicy()
	vc, _ := NewValidatorCommittee(kr.principals, kr.validators)
	se, _ := NewSettlementEngine(kr.settlementID, pol, kr.principals, "")
	gate, _ := NewFinalityTreasuryGate(pol, kr.principals, kr.authorities, "")

	job, work := testSampleJobWork(kr, "job-fin-01", 2, 2_000_000, 1_000_000)
	_ = vc.AdmitJob(job)
	atts, _ := vc.VerifyAndAttest(job.JobID, work)
	rec, _ := se.IssueReceipt(kr.settlementID, RoleSettlementNode, job, work, atts)
	comm, proofs, _ := se.SealEpoch(2)
	_ = gate.RegisterEpochCommitment(comm)

	// Too early: currentEpoch=3 < 2+2=4 -> ERR_UNFINALIZED_EPOCH.
	if _, err := gate.AuthorizeReward(kr.authorities[0].ID, RoleGovernanceTreasury, 3, job, work, atts, rec, proofs[rec.ReceiptID]); ErrorCodeOf(err) != ErrUnfinalizedEpoch {
		t.Fatalf("expected ERR_UNFINALIZED_EPOCH, got %v", err)
	}
	// Expired: currentEpoch=9 > 2+6=8 -> ERR_EPOCH_EXPIRED.
	if _, err := gate.AuthorizeReward(kr.authorities[0].ID, RoleGovernanceTreasury, 9, job, work, atts, rec, proofs[rec.ReceiptID]); ErrorCodeOf(err) != ErrEpochExpired {
		t.Fatalf("expected ERR_EPOCH_EXPIRED, got %v", err)
	}
	// Exact window [4..8] succeeds.
	if _, err := gate.AuthorizeReward(kr.authorities[0].ID, RoleGovernanceTreasury, 4, job, work, atts, rec, proofs[rec.ReceiptID]); err != nil {
		t.Fatalf("expected valid finalized authorization at epoch 4, got %v", err)
	}
}

func TestEpochTreasuryCapEnforcement(t *testing.T) {
	kr := buildTestNetKeyring(1350)
	pol := testPolicy()
	pol.EpochTreasuryCapMicroZOO = 1_500_000
	vc, _ := NewValidatorCommittee(kr.principals, kr.validators)
	se, _ := NewSettlementEngine(kr.settlementID, pol, kr.principals, "")
	gate, _ := NewFinalityTreasuryGate(pol, kr.principals, kr.authorities, "")

	j1, w1 := testSampleJobWork(kr, "job-cap-01", 1, 1_000_000, 1_000_000)
	j2, w2 := testSampleJobWork(kr, "job-cap-02", 1, 1_000_000, 1_000_000)
	_ = vc.AdmitJob(j1)
	_ = vc.AdmitJob(j2)
	a1, _ := vc.VerifyAndAttest(j1.JobID, w1)
	a2, _ := vc.VerifyAndAttest(j2.JobID, w2)
	r1, _ := se.IssueReceipt(kr.settlementID, RoleSettlementNode, j1, w1, a1)
	r2, _ := se.IssueReceipt(kr.settlementID, RoleSettlementNode, j2, w2, a2)
	comm, proofs, _ := se.SealEpoch(1)
	_ = gate.RegisterEpochCommitment(comm)

	if _, err := gate.AuthorizeReward(kr.authorities[0].ID, RoleGovernanceTreasury, 3, j1, w1, a1, r1, proofs[r1.ReceiptID]); err != nil {
		t.Fatal(err)
	}
	if _, err := gate.AuthorizeReward(kr.authorities[0].ID, RoleGovernanceTreasury, 3, j2, w2, a2, r2, proofs[r2.ReceiptID]); ErrorCodeOf(err) != ErrTreasuryCapExceeded {
		t.Fatalf("expected ERR_TREASURY_CAP_EXCEEDED, got %v", err)
	}
	// Governance authority raises cap legitimately -> j2 now succeeds.
	if err := gate.UpdatePolicy(PolicyMutationAttempt{ActorID: kr.authorities[0].ID, ActorRole: RoleGovernanceTreasury, Field: "epoch_treasury_cap_micro_zoo", ProposedValue: 3_000_000}); err != nil {
		t.Fatal(err)
	}
	if _, err := gate.AuthorizeReward(kr.authorities[0].ID, RoleGovernanceTreasury, 3, j2, w2, a2, r2, proofs[r2.ReceiptID]); err != nil {
		t.Fatalf("expected j2 to succeed after governance cap update: %v", err)
	}
}

func TestOutOfOrderPermutationInvariance(t *testing.T) {
	kr := buildTestNetKeyring(1350)
	pol := testPolicy()
	vc, _ := NewValidatorCommittee(kr.principals, kr.validators)
	se, _ := NewSettlementEngine(kr.settlementID, pol, kr.principals, "")

	type item struct {
		j AdmittedJob
		w WorkResult
		a []EASAttestation
		r UsefulWorkReceipt
	}
	items := make([]item, 10)
	for i := 0; i < 10; i++ {
		j, w := testSampleJobWork(kr, "job-perm-"+string(rune('a'+i)), 1, int64(2_000_000+i*100_003), int64(1_000_000+i*77_777))
		j.ProviderID = kr.providers[i%4]
		w.ProviderID = j.ProviderID
		w.WorkHash = ComputeWorkHash(j.JobID, j.CorpusPaperSHA256, j.WorkSpecHash, w.OutputDigest, w.TokensProcessed, w.ComputeUnits)
		_ = vc.AdmitJob(j)
		a, _ := vc.VerifyAndAttest(j.JobID, w)
		r, err := se.IssueReceipt(kr.settlementID, RoleSettlementNode, j, w, a)
		if err != nil {
			t.Fatal(err)
		}
		items[i] = item{j: j, w: w, a: a, r: r}
	}
	comm, proofs, _ := se.SealEpoch(1)

	runOrder := func(order []int) BalanceSheet {
		g, _ := NewFinalityTreasuryGate(pol, kr.principals, kr.authorities, "")
		_ = g.RegisterEpochCommitment(comm)
		for _, idx := range order {
			it := items[idx]
			if _, err := g.AuthorizeReward(kr.authorities[0].ID, RoleGovernanceTreasury, 3, it.j, it.w, it.a, it.r, proofs[it.r.ReceiptID]); err != nil {
				t.Fatal(err)
			}
		}
		return g.BalanceSheetSnapshot()
	}

	fwd := runOrder([]int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	rev := runOrder([]int{9, 8, 7, 6, 5, 4, 3, 2, 1, 0})
	mix := runOrder([]int{4, 1, 8, 0, 7, 2, 9, 3, 6, 5})

	if !equalBalanceSheets(fwd, rev) || !equalBalanceSheets(fwd, mix) {
		t.Fatalf("out-of-order authorization changed integer balance sheet")
	}
}

func TestCorpusManifestVerification(t *testing.T) {
	repoRoot := filepath.Join("..", "..", "..", "..")
	manifestPath := filepath.Join("..", "..", "corpus-manifest.json")
	manifest, contents, _, err := LoadAndVerifyCorpus(repoRoot, manifestPath)
	if err != nil {
		t.Fatalf("LoadAndVerifyCorpus failed: %v", err)
	}
	if len(manifest.Papers) != 8 || len(contents) != 8 {
		t.Fatalf("expected 8 verified corpus papers, got %d", len(manifest.Papers))
	}
}

func TestFullBenchmarkSeed1350AndAll24AdversarialAttacks(t *testing.T) {
	repoRoot := filepath.Join("..", "..", "..", "..")
	manifestPath := filepath.Join("..", "..", "corpus-manifest.json")
	bundle, results, err := RunFullBenchmark(repoRoot, manifestPath, 1350)
	if err != nil {
		t.Fatalf("RunFullBenchmark failed: %v", err)
	}
	if results.LifecycleJobs != 200 {
		t.Fatalf("expected 200 lifecycle jobs, got %d", results.LifecycleJobs)
	}
	if results.AdversarialSuite.TotalAttacks != 24 || results.AdversarialSuite.BlockedAttacks != 24 {
		t.Fatalf("expected 24/24 adversarial attacks blocked, got %d/%d", results.AdversarialSuite.BlockedAttacks, results.AdversarialSuite.TotalAttacks)
	}
	if !results.DoubleClaimStress.ZeroDoubleClaimsPreserved {
		t.Fatalf("double claim stress invariant violated: %+v", results.DoubleClaimStress)
	}
	if !results.DeterminismAudit.ColdRestartStateIdentical || !results.DeterminismAudit.ColdRestartReplayBlocked || !results.DeterminismAudit.PermutationBalanceExact || results.DeterminismAudit.ConservationDriftMicroZOO != 0 {
		t.Fatalf("determinism audit failed: %+v", results.DeterminismAudit)
	}
	// Negative Regime 1 checks.
	neg1 := results.NegativeRegimes.CollapsedLayerSelfIssuance
	if neg1.CollapsedDrainPct != 100.0 || neg1.ThreeLayerDrainedMicro != 0 || neg1.ThreeLayerBlockedPct != 100.0 {
		t.Fatalf("unexpected neg1 result: %+v", neg1)
	}
	// Negative Regime 2 checks.
	neg2 := results.NegativeRegimes.FinalityEpochLatencyTax
	if len(neg2.Sweep) != 5 || neg2.Sweep[0].FinalityWaitDelaySec != 0 || neg2.Sweep[4].FinalityWaitDelaySec <= neg2.Sweep[1].FinalityWaitDelaySec {
		t.Fatalf("unexpected neg2 result: %+v", neg2)
	}
	// Negative Regime 3 checks.
	neg3 := results.NegativeRegimes.ValidatorQuorumStall
	if len(neg3.Sweep) != 5 || neg3.Sweep[0].LivenessPct != 100.0 || neg3.Sweep[2].LivenessPct != 100.0 || neg3.Sweep[3].LivenessPct != 0.0 || neg3.Sweep[3].UnauthorizedIssuances != 0 {
		t.Fatalf("unexpected neg3 result: %+v", neg3)
	}
	// Independently verify generated bundle.
	report, err := VerifyTraceBundle(bundle)
	if err != nil || !report.AllMatched || !report.ConservationExact || !report.AuditRootMatched {
		t.Fatalf("VerifyTraceBundle failed on generated benchmark bundle: err=%v matched=%v", err, report.AllMatched)
	}
}

func TestVerifyCanonicalFixtureIfPresent(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "fixtures", "settlement-trace.v1.json")
	raw, err := os.ReadFile(fixturePath)
	if os.IsNotExist(err) {
		t.Skip("canonical fixture not yet generated")
	}
	if err != nil {
		t.Fatal(err)
	}
	var bundle SettlementTraceBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	report, err := VerifyTraceBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !report.AllMatched || !report.ConservationExact || !report.AuditRootMatched {
		t.Fatalf("fixture verification failed: matched=%d/%d conservation=%v rootMatched=%v",
			report.MatchedCount, report.TotalCases, report.ConservationExact, report.AuditRootMatched)
	}
}

// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package infnet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func makeTestReq(id string, priv PrivacyRequirement) InferenceRequest {
	body := "Zoo Network decentralized inference test prompt " + id
	pSum := sha256.Sum256([]byte(body))
	preSum := sha256.Sum256([]byte("shared-prefix-doc-01"))
	return InferenceRequest{
		RequestID:          id,
		ModelID:            DefaultModelID,
		PromptText:         body,
		PromptSHA256:       hex.EncodeToString(pSum[:]),
		PromptPrefixSHA256: hex.EncodeToString(preSum[:]),
		PromptTokens:       384,
		MaxOutputTokens:    64,
		PrivacyRequirement: priv,
		ArrivalUs:          0,
		SourcePaper:        "zoo-network-architecture/sections/08-inference-router.tex",
	}
}

func TestNodeAdvertisementSignVerifyAndTamper(t *testing.T) {
	ad, _ := makeSignedNode(1350, "node-alpha", HWProfileH100, RoleWholeModel, 0, 32,
		81920, 28672, 64, 2400, 95, 18000, 10_000_000, PrivacyTEEAttested, 1)
	if code, err := ValidateNodeAdvertisement(ad); err != nil || code != ErrCodeOK {
		t.Fatalf("expected valid advertisement, got code=%s err=%v", code, err)
	}

	tampered := ad
	tampered.DecodeTPS = 9999
	if code, err := ValidateNodeAdvertisement(tampered); err == nil || code != ErrCodeInvalidNodeAdvertisement {
		t.Fatalf("expected tamper rejection, got code=%s err=%v", code, err)
	}

	missingTEE := ad
	missingTEE.TEEAttestationSHA = ""
	if _, err := ValidateNodeAdvertisement(missingTEE); err == nil {
		t.Fatalf("expected missing TEE attestation rejection")
	}
}

func TestDiscoveryMonotonicEpochAndKeyPinning(t *testing.T) {
	reg := NewRegistry()
	ad1, priv1 := makeSignedNode(1350, "node-beta", HWProfileRTX4090, RoleWholeModel, 0, 32,
		24576, 10240, 16, 900, 58, 25000, 1_000_000, PrivacyPublicRelay, 1)
	if err := reg.Register(ad1); err != nil {
		t.Fatalf("register epoch 1 failed: %v", err)
	}

	// Replaying epoch 1 must fail.
	if err := reg.Register(ad1); !errors.Is(err, ErrStaleHeartbeatEpoch) {
		t.Fatalf("expected ErrStaleHeartbeatEpoch on replay, got %v", err)
	}

	// Spoofing node-beta with a different key must fail.
	spoof := ad1
	spoof.HeartbeatEpoch = 2
	_, roguePriv := DeriveNodeKey(9999, "rogue-actor")
	SignNodeAdvertisement(&spoof, roguePriv)
	if err := reg.Register(spoof); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("expected ErrKeyMismatch on key spoof, got %v", err)
	}

	// Valid monotonic epoch increment with pinned key succeeds.
	ad2 := ad1
	ad2.HeartbeatEpoch = 2
	ad2.TimestampUnixS += 15
	SignNodeAdvertisement(&ad2, priv1)
	if err := reg.Register(ad2); err != nil {
		t.Fatalf("expected valid epoch 2 update, got %v", err)
	}
	got, ok := reg.Get("node-beta")
	if !ok || got.Ad.HeartbeatEpoch != 2 {
		t.Fatalf("expected epoch 2 stored, got ok=%v epoch=%d", ok, got.Ad.HeartbeatEpoch)
	}
}

func TestDiscoveryHeterogeneousFiltering(t *testing.T) {
	reg := NewRegistry()
	fs := buildDynamoDecentralizedFleet(1350)
	for _, ad := range fs.ads {
		if err := reg.Register(ad); err != nil {
			t.Fatalf("register %s: %v", ad.NodeID, err)
		}
	}

	strictNodes := reg.Discover(DiscoveryQuery{
		ModelID:            DefaultModelID,
		PrivacyRequirement: PrivacyReqStrict,
		HealthyOnly:        true,
	})
	if len(strictNodes) == 0 {
		t.Fatalf("expected strict-privacy nodes in dynamo fleet")
	}
	for _, n := range strictNodes {
		if n.Ad.PrivacyTier == PrivacyPublicRelay {
			t.Fatalf("PUBLIC_RELAY node %s leaked into PRIVACY_STRICT discovery", n.Ad.NodeID)
		}
	}
}

func TestCapacityConservationConcurrentStress(t *testing.T) {
	ca := NewCapacityAccountant()
	ad, _ := makeSignedNode(1350, "node-stress", HWProfileRTX4090, RoleWholeModel, 0, 32,
		24576, 10240, 8, 900, 58, 20000, 1_000_000, PrivacyPublicRelay, 1)
	ca.TrackNode(ad)

	var wg sync.WaitGroup
	const workers = 48
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			reqID := fmt.Sprintf("stress-req-%03d", idx)
			for j := 0; j < 10; j++ {
				res, err := ca.Reserve("node-stress", reqID, 1024, 1, "prefix-01")
				if err != nil {
					time.Sleep(100 * time.Microsecond)
					continue
				}
				// Verify snapshot never oversubscribes physical limits under race detector.
				snap, ok := ca.Snapshot("node-stress")
				if !ok || snap.VRAMReservedBaseMiB+snap.VRAMInUseMiB > snap.VRAMTotalMiB || snap.KVSlotsInUse > snap.KVSlotsTotal {
					t.Errorf("capacity invariant violated: %+v", snap)
				}
				reason := "COMPLETED"
				if (idx+j)%3 == 0 {
					reason = "FAILOVER_ABORT"
				}
				// Double release must be safe and idempotent.
				if err := ca.Release(res.ReservationID, reason); err != nil {
					t.Errorf("first release failed: %v", err)
				}
				if err := ca.Release(res.ReservationID, "DUPLICATE"); err != nil {
					t.Errorf("idempotent second release failed: %v", err)
				}
			}
		}(i)
	}
	wg.Wait()

	leakedVRAM, leakedSlots, active := ca.ActiveLeaks()
	if leakedVRAM != 0 || leakedSlots != 0 || active != 0 {
		t.Fatalf("expected 0 leaks after concurrent stress, got vram=%d slots=%d active=%d", leakedVRAM, leakedSlots, active)
	}

	ok, detail := VerifyCapacityConservation(map[string]NodeAdvertisement{ad.NodeID: ad}, ca.Ledger())
	if !ok {
		t.Fatalf("capacity conservation replay failed: %s", detail)
	}
}

func TestCapacityConservationDetectsLeakAndOversubscription(t *testing.T) {
	ad, _ := makeSignedNode(1350, "node-cap", HWProfileConsumer12, RolePipelineStage, 0, 8,
		12288, 4096, 4, 260, 32, 35000, 150_000, PrivacyPublicRelay, 1)
	nodes := map[string]NodeAdvertisement{ad.NodeID: ad}

	// Case A: Unreleased reservation -> leak
	leakLedger := []CapacityEvent{
		{Seq: 1, Action: "RESERVE", ReservationID: "r1", NodeID: ad.NodeID, RequestID: "q1", VRAMMiB: 512, KVSlots: 1, Reason: "ADMIT"},
	}
	if ok, _ := VerifyCapacityConservation(nodes, leakLedger); ok {
		t.Fatalf("expected capacity leak rejection")
	}

	// Case B: VRAM oversubscription -> reject
	overLedger := []CapacityEvent{
		{Seq: 1, Action: "RESERVE", ReservationID: "r2", NodeID: ad.NodeID, RequestID: "q2", VRAMMiB: 9000, KVSlots: 1, Reason: "ADMIT"},
		{Seq: 2, Action: "RELEASE", ReservationID: "r2", NodeID: ad.NodeID, RequestID: "q2", VRAMMiB: 9000, KVSlots: 1, Reason: "COMPLETED"},
	}
	if ok, _ := VerifyCapacityConservation(nodes, overLedger); ok {
		t.Fatalf("expected VRAM oversubscription rejection")
	}
}

func TestPrivacyBoundaryHardEnforcement(t *testing.T) {
	pubAd, _ := makeSignedNode(1350, "pub-01", HWProfileRTX4090, RoleWholeModel, 0, 32,
		24576, 10240, 16, 900, 60, 25000, 1_000_000, PrivacyPublicRelay, 1)
	teeAd, _ := makeSignedNode(1350, "tee-01", HWProfileH100, RoleWholeModel, 0, 32,
		81920, 28672, 32, 2000, 85, 22000, 2_000_000, PrivacyTEEAttested, 1)
	localAd, _ := makeSignedNode(1350, "local-01", HWProfileMacM4Max, RoleWholeModel, 0, 32,
		65536, 14336, 20, 440, 46, 28000, 500_000, PrivacyLocalPrivate, 1)

	if err := EnforcePrivacyBoundary(PrivacyReqStrict, []NodeAdvertisement{teeAd, localAd}); err != nil {
		t.Fatalf("expected TEE + LOCAL_PRIVATE to satisfy PRIVACY_STRICT, got %v", err)
	}
	if err := EnforcePrivacyBoundary(PrivacyReqStrict, []NodeAdvertisement{teeAd, pubAd}); !errors.Is(err, ErrPrivacyBoundaryViolation) {
		t.Fatalf("expected ErrPrivacyBoundaryViolation when PUBLIC_RELAY is included, got %v", err)
	}
}

func TestDynamoDisaggregatedRoutingAndPrefixAffinity(t *testing.T) {
	fs := buildDynamoDecentralizedFleet(1350)
	reg := NewRegistry()
	ca := NewCapacityAccountant()
	for _, ad := range fs.ads {
		_ = reg.Register(ad)
		ca.TrackNode(ad)
	}
	rt := NewRouter(reg, ca, fs.keys)

	req1 := makeTestReq("dyn-01", PrivacyReqPublicOK)
	out1, err := rt.ExecuteRequest(req1, TopologyDynamoReplica, FailurePolicy{})
	if err != nil {
		t.Fatalf("req1 failed: %v", err)
	}
	if out1.PrefixCacheHit {
		t.Fatalf("first request should be a cold prefix miss")
	}

	req2 := makeTestReq("dyn-02", PrivacyReqPublicOK) // shares exact same PromptPrefixSHA256!
	req2.ArrivalUs = 2_000_000
	out2, err := rt.ExecuteRequest(req2, TopologyDynamoReplica, FailurePolicy{})
	if err != nil {
		t.Fatalf("req2 failed: %v", err)
	}
	if !out2.PrefixCacheHit {
		t.Fatalf("second request with identical prefix should register KV-prefix cache hit")
	}
	if out2.Receipt.TTFTUs >= out1.Receipt.TTFTUs {
		t.Fatalf("expected warm prefix hit TTFT (%d us) < cold miss TTFT (%d us)", out2.Receipt.TTFTUs, out1.Receipt.TTFTUs)
	}
	if !VerifyDeliveryReceiptSignature(out2.Receipt) {
		t.Fatalf("receipt Ed25519 signature invalid")
	}
}

func TestPetalsPipelineWANLatencyAndActivationTransfer(t *testing.T) {
	dcFS := buildCentralizedFleet(1350)
	dcReg, dcCap := NewRegistry(), NewCapacityAccountant()
	for _, ad := range dcFS.ads {
		_ = dcReg.Register(ad)
		dcCap.TrackNode(ad)
	}
	dcRouter := NewRouter(dcReg, dcCap, dcFS.keys)

	pFS := buildPetalsPipelineFleet(1350)
	pReg, pCap := NewRegistry(), NewCapacityAccountant()
	for _, ad := range pFS.ads {
		_ = pReg.Register(ad)
		pCap.TrackNode(ad)
	}
	pRouter := NewRouter(pReg, pCap, pFS.keys)

	req := makeTestReq("cmp-01", PrivacyReqPublicOK)
	dcOut, err := dcRouter.ExecuteRequest(req, TopologyCentralizedBaseline, FailurePolicy{})
	if err != nil {
		t.Fatalf("dc execute: %v", err)
	}
	pOut, err := pRouter.ExecuteRequest(req, TopologyPetalsPipeline, FailurePolicy{})
	if err != nil {
		t.Fatalf("petals execute: %v", err)
	}

	if len(pOut.Receipt.RouteNodeIDs) != 4 {
		t.Fatalf("expected 4 pipeline hops, got %d", len(pOut.Receipt.RouteNodeIDs))
	}
	if pOut.Receipt.TPOTUs <= dcOut.Receipt.TPOTUs*5 {
		t.Fatalf("expected Petals 4-hop WAN TPOT (%d us) > 5x centralized TPOT (%d us)", pOut.Receipt.TPOTUs, dcOut.Receipt.TPOTUs)
	}
	if pOut.Receipt.NetworkBytesTransferred <= dcOut.Receipt.NetworkBytesTransferred*100 {
		t.Fatalf("expected Petals activation bytes (%d) >> centralized (%d)", pOut.Receipt.NetworkBytesTransferred, dcOut.Receipt.NetworkBytesTransferred)
	}
	if pOut.Receipt.BatchUtilizationBps >= dcOut.Receipt.BatchUtilizationBps {
		t.Fatalf("expected Petals batch utilization (%d) < centralized (%d)", pOut.Receipt.BatchUtilizationBps, dcOut.Receipt.BatchUtilizationBps)
	}
}

func TestMidRequestFailureRecoveryZeroCapacityLeaks(t *testing.T) {
	fs := buildDynamoDecentralizedFleet(1350)
	reg, ca := NewRegistry(), NewCapacityAccountant()
	for _, ad := range fs.ads {
		_ = reg.Register(ad)
		ca.TrackNode(ad)
	}
	rt := NewRouter(reg, ca, fs.keys)

	// Force high failure probability (60%) with retries=2 to exercise failover paths.
	fp := FailurePolicy{FailureRateBps: 6000, MaxRetries: 2, Seed: 1350}
	failoverSeen := 0
	for i := 0; i < 20; i++ {
		req := makeTestReq(fmt.Sprintf("fail-test-%02d", i), PrivacyReqPublicOK)
		out, err := rt.ExecuteRequest(req, TopologyDynamoReplica, fp)
		if err != nil {
			t.Fatalf("execute failed: %v", err)
		}
		if out.Receipt.Status == StatusCompletedFailover {
			failoverSeen++
			if out.Receipt.RecoveryLatencyUs == 0 || len(out.Receipt.FailedNodeIDs) == 0 {
				t.Fatalf("failover receipt missing recovery metrics: %+v", out.Receipt)
			}
		}
	}
	if failoverSeen == 0 {
		t.Fatalf("expected at least one mid-request failover recovery")
	}

	leakedVRAM, leakedSlots, active := ca.ActiveLeaks()
	if leakedVRAM != 0 || leakedSlots != 0 || active != 0 {
		t.Fatalf("capacity leaked after failover storm: vram=%d slots=%d active=%d", leakedVRAM, leakedSlots, active)
	}
}

func TestLoopbackHTTPClusterLiveExecutionAndFailover(t *testing.T) {
	cluster := NewLoopbackCluster()
	defer cluster.Close()

	ad1, priv1 := makeSignedNode(1350, "live-node-01", HWProfileH100, RoleWholeModel, 0, 32,
		81920, 28672, 32, 2200, 90, 15000, 10_000_000, PrivacyTEEAttested, 1)
	ad2, priv2 := makeSignedNode(1350, "live-node-02", HWProfileMacM4Max, RoleWholeModel, 0, 32,
		65536, 14336, 24, 440, 46, 25000, 500_000, PrivacyLocalPrivate, 1)

	w1, err := cluster.AddWorker(ad1, priv1)
	if err != nil {
		t.Fatalf("add worker 1: %v", err)
	}
	if _, err := cluster.AddWorker(ad2, priv2); err != nil {
		t.Fatalf("add worker 2: %v", err)
	}

	// Crash primary worker (live-node-01) so real HTTP/1.1 call returns 503 and router fails over to live-node-02!
	w1.SetCrashed(true)

	req := makeTestReq("live-failover-01", PrivacyReqStrict)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := cluster.Dispatch(ctx, req, TopologyStrictTEE)
	if err != nil {
		t.Fatalf("live dispatch failed: %v", err)
	}
	if out.Receipt.Status != StatusCompletedFailover {
		t.Fatalf("expected COMPLETED_WITH_FAILOVER, got %s", out.Receipt.Status)
	}
	if out.Receipt.PrimaryProviderID != "live-node-02" {
		t.Fatalf("expected failover to live-node-02, got %s", out.Receipt.PrimaryProviderID)
	}
	if len(out.Receipt.FailedNodeIDs) != 1 || out.Receipt.FailedNodeIDs[0] != "live-node-01" {
		t.Fatalf("expected failed_node_ids=[live-node-01], got %v", out.Receipt.FailedNodeIDs)
	}

	vr := VerifyParityCase(ParityCase{
		CaseID:         "live-http-failover",
		Nodes:          []NodeAdvertisement{ad1, ad2},
		Receipt:        out.Receipt,
		OutputChunks:   out.OutputChunks,
		CapacityLedger: out.CapacityEvents,
	})
	if !vr.Valid {
		t.Fatalf("live HTTP failover receipt failed independent verification: %s (%s)", vr.ErrorCode, vr.Detail)
	}

	leakedVRAM, leakedSlots, active := cluster.Capacity.ActiveLeaks()
	if leakedVRAM != 0 || leakedSlots != 0 || active != 0 {
		t.Fatalf("live HTTP cluster leaked capacity: vram=%d slots=%d active=%d", leakedVRAM, leakedSlots, active)
	}
}

func TestLoopbackHTTPClusterStrictPrivacyRejectsPublicFallback(t *testing.T) {
	cluster := NewLoopbackCluster()
	defer cluster.Close()

	teeAd, teePriv := makeSignedNode(1350, "live-tee-only", HWProfileH100, RoleWholeModel, 0, 32,
		81920, 28672, 32, 2200, 90, 15000, 10_000_000, PrivacyTEEAttested, 1)
	pubAd, pubPriv := makeSignedNode(1350, "live-pub-only", HWProfileRTX4090, RoleWholeModel, 0, 32,
		24576, 10240, 16, 900, 60, 20000, 1_000_000, PrivacyPublicRelay, 1)

	wTEE, err := cluster.AddWorker(teeAd, teePriv)
	if err != nil {
		t.Fatalf("add tee worker: %v", err)
	}
	if _, err := cluster.AddWorker(pubAd, pubPriv); err != nil {
		t.Fatalf("add pub worker: %v", err)
	}
	wTEE.SetCrashed(true)

	req := makeTestReq("live-privacy-block", PrivacyReqStrict)
	_, err = cluster.Dispatch(context.Background(), req, TopologyStrictTEE)
	if !errors.Is(err, ErrPrivacyBoundaryViolation) {
		t.Fatalf("expected ErrPrivacyBoundaryViolation when TEE node crashes and only PUBLIC_RELAY remains, got %v", err)
	}
}

func TestDeliveryReceiptConstitutionalLocks(t *testing.T) {
	ad, priv := makeSignedNode(1350, "node-const", HWProfileH100, RoleWholeModel, 0, 32,
		81920, 28672, 32, 2400, 95, 200, 400_000_000, PrivacyTEEAttested, 1)
	chunks := DeterministicOutputChunks("aaaa", DefaultModelID, 4)
	rcpt := DeliveryReceipt{
		SchemaVersion:           SchemaVersion,
		ReceiptID:               "rcpt-const-1",
		RequestID:               "req-const-1",
		TopologyMode:            TopologyCentralizedBaseline,
		ModelID:                 DefaultModelID,
		PromptSHA256:            "0000000000000000000000000000000000000000000000000000000000000001",
		PromptPrefixSHA256:      "0000000000000000000000000000000000000000000000000000000000000002",
		PromptTokens:            128,
		OutputTokens:            4,
		OutputMerkleRoot:        ComputeOutputMerkleRoot(chunks),
		PrivacyRequirement:      PrivacyReqStrict,
		EffectivePrivacyTier:    PrivacyTEEAttested,
		RouteNodeIDs:            []string{ad.NodeID},
		PrimaryProviderID:       ad.NodeID,
		PrefillNodeID:           ad.NodeID,
		DecodeNodeIDs:           []string{ad.NodeID},
		BatchSizeEffective:      1,
		BatchUtilizationBps:     9000,
		Status:                  StatusCompleted,
		ProvesScientificTruth:   true,
		AuthorizesTreasurySpend: false,
	}
	SignDeliveryReceipt(&rcpt, priv)

	vr := VerifyParityCase(ParityCase{
		CaseID:       "const-sci",
		Nodes:        []NodeAdvertisement{ad},
		Receipt:      rcpt,
		OutputChunks: chunks,
	})
	if vr.Valid || vr.ErrorCode != ErrCodeConstitutionalViolation {
		t.Fatalf("expected ERR_CONSTITUTIONAL_VIOLATION, got valid=%v code=%s", vr.Valid, vr.ErrorCode)
	}
}

func TestOutputMerkleRootTamperDetection(t *testing.T) {
	chunks := DeterministicOutputChunks("prompt-digest", DefaultModelID, 8)
	root := ComputeOutputMerkleRoot(chunks)
	mutated := make([]string, len(chunks))
	copy(mutated, chunks)
	mutated[5] = "forged_token"
	if ComputeOutputMerkleRoot(mutated) == root {
		t.Fatalf("expected mutated token chunk to change output Merkle root")
	}
}

func TestGroundedCorpusBenchmarkDeterminismAndNegativeRegimes(t *testing.T) {
	repoRoot := filepath.Join("..", "..", "..", "..")
	manifestPath := filepath.Join("..", "..", "corpus-manifest.json")

	rep1, suite1, err := RunFullBenchmark(repoRoot, manifestPath, 1350, 40)
	if err != nil {
		t.Fatalf("RunFullBenchmark #1 failed: %v", err)
	}
	rep2, suite2, err := RunFullBenchmark(repoRoot, manifestPath, 1350, 40)
	if err != nil {
		t.Fatalf("RunFullBenchmark #2 failed: %v", err)
	}

	if rep1.AuditMerkleRoot != rep2.AuditMerkleRoot || suite1.AuditMerkleRoot != suite2.AuditMerkleRoot {
		t.Fatalf("benchmark is non-deterministic across identical seed 1350")
	}
	if rep1.TotalPrivacyLeaks != 0 {
		t.Fatalf("expected 0 privacy leaks across all scenarios, got %d", rep1.TotalPrivacyLeaks)
	}
	if rep1.TotalCapacityLeaks != 0 {
		t.Fatalf("expected 0 capacity leaks across all scenarios, got %d", rep1.TotalCapacityLeaks)
	}
	for _, sc := range rep1.Scenarios {
		if sc.VerifiedReceiptsCount != sc.TotalRequests {
			t.Fatalf("scenario %s verified %d/%d receipts", sc.ScenarioID, sc.VerifiedReceiptsCount, sc.TotalRequests)
		}
	}
	if len(rep1.NegativeRegimes) != 3 {
		t.Fatalf("expected 3 negative regimes, got %d", len(rep1.NegativeRegimes))
	}
	// Assert Negative Regime 1 honestly proves Petals WAN pipeline loses heavily to centralized baseline.
	if rep1.NegativeRegimes[0].HeadlineRatios["tpot_p50_slowdown_x"] < 5.0 {
		t.Fatalf("expected Petals WAN TPOT slowdown >= 5x, got %.2fx", rep1.NegativeRegimes[0].HeadlineRatios["tpot_p50_slowdown_x"])
	}
	// Assert Negative Regime 3 honestly shows privacy scarcity queuing inflation with 0 leaks.
	if rep1.NegativeRegimes[2].HeadlineRatios["ttft_p50_inflation_x"] <= 1.2 || rep1.NegativeRegimes[2].Degraded.PrivacyLeakCount != 0 {
		t.Fatalf("unexpected Negative Regime 3 metrics: %+v", rep1.NegativeRegimes[2].HeadlineRatios)
	}
}

func TestParitySuiteAllCasesMatchExpectedVerdicts(t *testing.T) {
	repoRoot := filepath.Join("..", "..", "..", "..")
	manifestPath := filepath.Join("..", "..", "corpus-manifest.json")
	_, suite, err := RunFullBenchmark(repoRoot, manifestPath, 1350, 40)
	if err != nil {
		t.Fatalf("RunFullBenchmark failed: %v", err)
	}
	if len(suite.Cases) != 18 {
		t.Fatalf("expected 18 parity cases, got %d", len(suite.Cases))
	}
	verdicts, root, err := VerifyParitySuite(*suite)
	if err != nil {
		t.Fatalf("VerifyParitySuite failed: %v", err)
	}
	if root != suite.AuditMerkleRoot {
		t.Fatalf("audit_merkle_root mismatch: got %s want %s", root, suite.AuditMerkleRoot)
	}
	validCount, rejectCount := 0, 0
	for i, v := range verdicts {
		c := suite.Cases[i]
		if v.Valid != c.ExpectedValid || v.ErrorCode != c.ExpectedErrorCode || v.VerdictDigest != c.ExpectedVerdictDigest {
			t.Fatalf("case %s mismatch: got %+v want valid=%v code=%s", c.CaseID, v, c.ExpectedValid, c.ExpectedErrorCode)
		}
		if v.Valid {
			validCount++
		} else {
			rejectCount++
		}
	}
	if validCount != 7 || rejectCount != 11 {
		t.Fatalf("expected 7 valid and 11 reject parity cases, got valid=%d reject=%d", validCount, rejectCount)
	}
}

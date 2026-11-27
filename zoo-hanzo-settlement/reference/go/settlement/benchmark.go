// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package settlement

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// splitMix64 is a deterministic, cross-platform PRNG for reproducible benchmark generation.
type splitMix64 struct {
	state uint64
}

func newSplitMix64(seed uint64) *splitMix64 {
	return &splitMix64{state: seed}
}

func (s *splitMix64) nextUint64() uint64 {
	s.state += 0x9e3779b97f4a7c15
	z := s.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func (s *splitMix64) intn(n int) int {
	return int(s.nextUint64() % uint64(n))
}

func (s *splitMix64) int64Range(lo, hi int64) int64 {
	return lo + int64(s.nextUint64()%uint64(hi-lo+1))
}

// CorpusManifest matches corpus-manifest.json.
type CorpusManifest struct {
	ManifestVersion string        `json:"manifest_version"`
	Protocol        string        `json:"protocol"`
	Issue           string        `json:"issue"`
	HIP             string        `json:"hip"`
	Papers          []CorpusPaper `json:"papers"`
}

// CorpusPaper describes one pinned real .tex paper from zoo-apps/papers.
type CorpusPaper struct {
	PaperID string `json:"paper_id"`
	Path    string `json:"path"`
	Bytes   int    `json:"bytes"`
	SHA256  string `json:"sha256"`
}

// LatencyStats summarizes stage latencies in microseconds.
type LatencyStats struct {
	Count  int     `json:"count"`
	MeanUS float64 `json:"mean_us"`
	P50US  float64 `json:"p50_us"`
	P95US  float64 `json:"p95_us"`
	P99US  float64 `json:"p99_us"`
	MaxUS  float64 `json:"max_us"`
}

func summarizeLatencies(samples []time.Duration) LatencyStats {
	if len(samples) == 0 {
		return LatencyStats{}
	}
	us := make([]float64, 0, len(samples))
	var sum float64
	for _, d := range samples {
		if d < 0 {
			d = 0
		}
		v := float64(d.Nanoseconds()) / 1000.0
		us = append(us, v)
		sum += v
	}
	sort.Float64s(us)
	pct := func(p float64) float64 {
		idx := int(float64(len(us)-1) * p)
		return round2(us[idx])
	}
	return LatencyStats{
		Count:  len(us),
		MeanUS: round2(sum / float64(len(us))),
		P50US:  pct(0.50),
		P95US:  pct(0.95),
		P99US:  pct(0.99),
		MaxUS:  round2(us[len(us)-1]),
	}
}

func round2(v float64) float64 {
	if v < 0 {
		return float64(int64(v*100-0.5)) / 100.0
	}
	return float64(int64(v*100+0.5)) / 100.0
}

// DoubleClaimStressResult captures replay and 64-goroutine concurrent race results.
type DoubleClaimStressResult struct {
	SequentialReplayAttempts  int `json:"sequential_replay_attempts"`
	SequentialReplayAccepted  int `json:"sequential_replay_accepted"`
	SequentialReplayRejected  int `json:"sequential_replay_rejected"`
	ConcurrentGoroutines      int `json:"concurrent_goroutines"`
	ConcurrentL2Accepted      int `json:"concurrent_l2_accepted"`
	ConcurrentL2Rejected      int `json:"concurrent_l2_rejected"`
	ConcurrentL3Accepted      int `json:"concurrent_l3_accepted"`
	ConcurrentL3Rejected      int `json:"concurrent_l3_rejected"`
	ZeroDoubleClaimsPreserved bool `json:"zero_double_claims_preserved"`
}

// DeterminismAuditResult verifies cold-restart WAL recovery and out-of-order arrival permutation invariance.
type DeterminismAuditResult struct {
	WALEntriesReplayed       int    `json:"wal_entries_replayed"`
	ColdRestartStateIdentical bool  `json:"cold_restart_state_identical"`
	ColdRestartReplayBlocked bool   `json:"cold_restart_replay_blocked"`
	PermutationsTested       int    `json:"permutations_tested"`
	PermutationBalanceExact  bool   `json:"permutation_balance_exact"`
	ConservationDriftMicroZOO int64 `json:"conservation_drift_micro_zoo"`
}

// AdversarialSummary summarizes the 24-case adversarial security evaluation.
type AdversarialSummary struct {
	TotalAttacks    int               `json:"total_attacks"`
	BlockedAttacks  int               `json:"blocked_attacks"`
	BlockRatePct    float64           `json:"block_rate_pct"`
	CaseOutcomes    []AdversarialItem `json:"case_outcomes"`
}

// AdversarialItem records one adversarial attack test and its observed error code.
type AdversarialItem struct {
	CaseID        string    `json:"case_id"`
	Stage         string    `json:"stage"`
	ExpectedError ErrorCode `json:"expected_error"`
	ObservedError ErrorCode `json:"observed_error"`
	Blocked       bool      `json:"blocked"`
}

// NegCollapsedLayerResult quantifies Negative Regime 1: collapsed single-layer app self-issuance vs 3-layer separation.
type NegCollapsedLayerResult struct {
	RegimeID                      string  `json:"regime_id"`
	EpochBudgetMicroZOO           int64   `json:"epoch_budget_micro_zoo"`
	PhantomAttackCount            int     `json:"phantom_attack_count"`
	CollapsedBaselineDrainedMicro int64   `json:"collapsed_baseline_drained_micro_zoo"`
	CollapsedDrainPct             float64 `json:"collapsed_drain_pct"`
	ThreeLayerDrainedMicro        int64   `json:"three_layer_drained_micro_zoo"`
	ThreeLayerBlockedCount        int     `json:"three_layer_blocked_count"`
	ThreeLayerBlockedPct          float64 `json:"three_layer_blocked_pct"`
	BlockedByAppIssuanceLock      int     `json:"blocked_by_app_issuance_lock"`
	BlockedBySelfVerifyLock       int     `json:"blocked_by_self_verify_lock"`
}

// FinalityDelayPoint is one point in the Negative Regime 2 latency trade-off sweep.
type FinalityDelayPoint struct {
	FinalityDelayEpochs         uint64  `json:"finality_delay_epochs"`
	ModeledEpochDurationSec     float64 `json:"modeled_epoch_duration_sec"`
	L2ReceiptMeanLatencyUS      float64 `json:"l2_receipt_mean_latency_us"`
	L3AuthorizeComputeLatencyUS float64 `json:"l3_authorize_compute_latency_us"`
	FinalityWaitDelaySec        float64 `json:"finality_wait_delay_sec"`
	EarlyWindowSpendablePct     float64 `json:"early_window_spendable_pct"`
	EarlyClaimRejectedCount     int     `json:"early_claim_rejected_count"`
}

// NegFinalityLatencyResult quantifies Negative Regime 2: finality-delay vs immediate-payout UX latency tax.
type NegFinalityLatencyResult struct {
	RegimeID             string               `json:"regime_id"`
	JobsPerEpoch         int                  `json:"jobs_per_epoch"`
	TotalEpochs          int                  `json:"total_epochs"`
	ModeledSlotSec       float64              `json:"modeled_epoch_duration_sec"`
	Sweep                []FinalityDelayPoint `json:"sweep"`
}

// QuorumOutagePoint is one point in the Negative Regime 3 validator outage sweep.
type QuorumOutagePoint struct {
	OfflineValidators      int     `json:"offline_validators"`
	OnlineValidators       int     `json:"online_validators"`
	QuorumRequired         int     `json:"quorum_required"`
	JobsSubmitted          int     `json:"jobs_submitted"`
	RewardsAuthorized      int     `json:"rewards_authorized"`
	LivenessPct            float64 `json:"liveness_pct"`
	UnauthorizedIssuances  int     `json:"unauthorized_issuances"`
	StalledFailClosedCount int     `json:"stalled_fail_closed_count"`
}

// NegQuorumLivenessResult quantifies Negative Regime 3: validator quorum stall / liveness loss under node outages.
type NegQuorumLivenessResult struct {
	RegimeID       string              `json:"regime_id"`
	CommitteeSize  int                 `json:"committee_size"`
	QuorumRequired int                 `json:"quorum_required"`
	Sweep          []QuorumOutagePoint `json:"sweep"`
}

// BenchmarkResults is the complete machine-readable results.json artifact.
type BenchmarkResults struct {
	SchemaVersion           string                   `json:"schema_version"`
	Protocol                string                   `json:"protocol"`
	Issue                   string                   `json:"issue"`
	HIP                     string                   `json:"hip"`
	Seed                    uint64                   `json:"seed"`
	CorpusPapersVerified    int                      `json:"corpus_papers_verified"`
	CorpusManifestSHA256    string                   `json:"corpus_manifest_sha256"`
	Topology                map[string]any           `json:"topology"`
	LifecycleJobs           int                      `json:"lifecycle_jobs"`
	TotalTraceCases         int                      `json:"total_trace_cases"`
	EndToEndElapsedMS       float64                  `json:"end_to_end_elapsed_ms"`
	ThroughputReceiptsPerSec float64                 `json:"throughput_receipts_per_sec"`
	StageLatencies          map[string]LatencyStats  `json:"stage_latencies"`
	BalanceSheet            BalanceSheet             `json:"balance_sheet"`
	AuditMerkleRoot         string                   `json:"audit_merkle_root"`
	DoubleClaimStress       DoubleClaimStressResult  `json:"double_claim_stress"`
	DeterminismAudit        DeterminismAuditResult   `json:"determinism_audit"`
	AdversarialSuite        AdversarialSummary       `json:"adversarial_suite"`
	NegativeRegimes         struct {
		CollapsedLayerSelfIssuance NegCollapsedLayerResult  `json:"neg_collapsed_layer_self_issuance"`
		FinalityEpochLatencyTax    NegFinalityLatencyResult `json:"neg_finality_epoch_latency_tax"`
		ValidatorQuorumStall       NegQuorumLivenessResult  `json:"neg_validator_quorum_liveness_stall"`
	} `json:"negative_regimes"`
}

// LoadAndVerifyCorpus loads corpus-manifest.json and verifies all pinned .tex files on disk.
func LoadAndVerifyCorpus(repoRoot, manifestPath string) (CorpusManifest, map[string][]byte, string, error) {
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return CorpusManifest{}, nil, "", fmt.Errorf("read corpus manifest: %w", err)
	}
	var manifest CorpusManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return CorpusManifest{}, nil, "", fmt.Errorf("parse corpus manifest: %w", err)
	}
	paperContents := make(map[string][]byte, len(manifest.Papers))
	for _, p := range manifest.Papers {
		full := filepath.Join(repoRoot, filepath.FromSlash(p.Path))
		data, err := os.ReadFile(full)
		if err != nil {
			return CorpusManifest{}, nil, "", fmt.Errorf("read corpus paper %s: %w", p.Path, err)
		}
		gotHash := SHA256BytesHex(data)
		if gotHash != p.SHA256 {
			return CorpusManifest{}, nil, "", fmt.Errorf("corpus paper %s sha256 mismatch: got %s want %s", p.Path, gotHash, p.SHA256)
		}
		if len(data) != p.Bytes {
			return CorpusManifest{}, nil, "", fmt.Errorf("corpus paper %s bytes mismatch: got %d want %d", p.Path, len(data), p.Bytes)
		}
		paperContents[p.PaperID] = data
	}
	return manifest, paperContents, SHA256BytesHex(manifestBytes), nil
}

type actorKeyring struct {
	principals   []Principal
	privKeys     map[string]ed25519.PrivateKey
	pubHex       map[string]string
	validators   []*ValidatorNode
	authorities  []*TreasuryAuthority
	providers    []string
	payers       []string
	apps         []string
	aiAgents     []string
	settlementID string
}

func buildTestNetKeyring(seed uint64) actorKeyring {
	kr := actorKeyring{
		privKeys:     make(map[string]ed25519.PrivateKey),
		pubHex:       make(map[string]string),
		settlementID: "settlement-node-01",
	}
	add := func(id string, role Role) (string, ed25519.PrivateKey) {
		pub, priv := DeriveEd25519Key(seed, string(role)+"/"+id)
		pHex := hex.EncodeToString(pub)
		kr.principals = append(kr.principals, Principal{ID: id, Role: role, PublicKeyHex: pHex})
		kr.privKeys[id] = priv
		kr.pubHex[id] = pHex
		return pHex, priv
	}

	for i := 1; i <= 4; i++ {
		id := fmt.Sprintf("payer-%02d", i)
		add(id, RolePayer)
		kr.payers = append(kr.payers, id)
	}
	for i := 1; i <= 12; i++ {
		id := fmt.Sprintf("provider-%02d", i)
		add(id, RoleProvider)
		kr.providers = append(kr.providers, id)
	}
	for i := 1; i <= 5; i++ {
		id := fmt.Sprintf("validator-%02d", i)
		pHex, priv := add(id, RoleValidator)
		kr.validators = append(kr.validators, &ValidatorNode{
			ID:      id,
			PubHex:  pHex,
			PrivKey: priv,
			Online:  true,
		})
	}
	add(kr.settlementID, RoleSettlementNode)
	for i := 1; i <= 2; i++ {
		id := fmt.Sprintf("treasury-gov-%02d", i)
		pHex, priv := add(id, RoleGovernanceTreasury)
		kr.authorities = append(kr.authorities, &TreasuryAuthority{
			ID:      id,
			PubHex:  pHex,
			PrivKey: priv,
		})
	}
	for _, id := range []string{"zoo-species-app", "zoo-habitat-app"} {
		add(id, RoleApplication)
		kr.apps = append(kr.apps, id)
	}
	for _, id := range []string{"zoo-advisor-agent"} {
		add(id, RoleAIAgent)
		kr.aiAgents = append(kr.aiAgents, id)
	}
	return kr
}

type modelTierSpec struct {
	name             string
	microZOOPer1MTok int64 // derived from zoo-hanzo-settlement.tex Table 1 (input+output blended)
}

var modelTiers = []modelTierSpec{
	{name: "small", microZOOPer1MTok: 100 * MicroZOOPerZOO},
	{name: "medium", microZOOPer1MTok: 400 * MicroZOOPerZOO},
	{name: "large", microZOOPer1MTok: 1000 * MicroZOOPerZOO},
	{name: "frontier", microZOOPer1MTok: 4000 * MicroZOOPerZOO},
}

func makeGroundedJobAndWork(rng *splitMix64, jobSeq int, epoch uint64, kr actorKeyring, papers []CorpusPaper, contents map[string][]byte) (AdmittedJob, WorkResult) {
	paper := papers[rng.intn(len(papers))]
	data := contents[paper.PaperID]
	tier := modelTiers[rng.intn(len(modelTiers))]

	// Deterministic chunk slice of the real .tex paper.
	chunkLen := 256
	if len(data) < chunkLen {
		chunkLen = len(data)
	}
	offset := 0
	if len(data) > chunkLen {
		offset = rng.intn(len(data) - chunkLen)
	}
	chunk := data[offset : offset+chunkLen]

	jobID := fmt.Sprintf("job-e%02d-%04d", epoch, jobSeq)
	payerID := kr.payers[rng.intn(len(kr.payers))]
	providerID := kr.providers[rng.intn(len(kr.providers))]
	workSpecHash := SHA256Hex(fmt.Sprintf("spec:v1|%s|%s|%d|%d|%s", jobID, paper.PaperID, offset, chunkLen, tier.name))

	// Deterministic token/compute metering derived from chunk + tier.
	tokens := uint64(rng.int64Range(1500, 12000))
	computeUnits := uint64(len(chunk)) + tokens/16
	// Exact integer micro-ZOO cost: (tokens * rate_per_1M) / 1_000_000, minimum 50_000 micro-ZOO (0.05 ZOO).
	consumed := (int64(tokens) * tier.microZOOPer1MTok) / 1_000_000
	if consumed < 50_000 {
		consumed = 50_000
	}
	// Escrow headroom of 10%..45% above consumed so deterministic refunds are non-zero and exact.
	headroomPct := rng.int64Range(10, 45)
	maxBudget := consumed + (consumed*headroomPct)/100

	job := AdmittedJob{
		JobID:             jobID,
		PayerID:           payerID,
		ProviderID:        providerID,
		Epoch:             epoch,
		ModelTier:         tier.name,
		CorpusPaperID:     paper.PaperID,
		CorpusPaperSHA256: paper.SHA256,
		WorkSpecHash:      workSpecHash,
		MaxBudgetMicroZOO: maxBudget,
		ConservationBPS:   DefaultConservationBPS,
		ProtocolBPS:       DefaultProtocolBPS,
	}

	outputDigest := SHA256BytesHex(append([]byte("output:v1|"+jobID+"|"+providerID+"|"), chunk...))
	workHash := ComputeWorkHash(job.JobID, job.CorpusPaperSHA256, job.WorkSpecHash, outputDigest, tokens, computeUnits)
	work := WorkResult{
		JobID:            job.JobID,
		ProviderID:       job.ProviderID,
		OutputDigest:     outputDigest,
		TokensProcessed:  tokens,
		ComputeUnits:     computeUnits,
		ConsumedMicroZOO: consumed,
		WorkHash:         workHash,
	}
	return job, work
}

// RunFullBenchmark executes the complete grounded test-network benchmark (--seed 1350),
// producing both the canonical SettlementTraceBundle (verified identically by Go & Python)
// and the full BenchmarkResults artifact.
func RunFullBenchmark(repoRoot, manifestPath string, seed uint64) (SettlementTraceBundle, BenchmarkResults, error) {
	manifest, paperContents, manifestSHA, err := LoadAndVerifyCorpus(repoRoot, manifestPath)
	if err != nil {
		return SettlementTraceBundle{}, BenchmarkResults{}, err
	}

	rng := newSplitMix64(seed)
	kr := buildTestNetKeyring(seed)

	policy := NetworkPolicy{
		ValidatorQuorum:          3,
		ValidatorCommitteeSize:   5,
		FinalityDelayEpochs:      2,
		ClaimWindowEpochs:        6,
		ConservationBPS:          DefaultConservationBPS,
		ProtocolBPS:              DefaultProtocolBPS,
		EpochTreasuryCapMicroZOO: 5_000_000_000, // 5,000 ZOO per epoch
	}

	tmpDir, err := os.MkdirTemp("", "zoo-settlement-bench-*")
	if err != nil {
		return SettlementTraceBundle{}, BenchmarkResults{}, err
	}
	defer os.RemoveAll(tmpDir)

	settleWALPath := filepath.Join(tmpDir, "settlement.wal.jsonl")
	finalityWALPath := filepath.Join(tmpDir, "finality.wal.jsonl")

	committee, err := NewValidatorCommittee(kr.principals, kr.validators)
	if err != nil {
		return SettlementTraceBundle{}, BenchmarkResults{}, err
	}
	engine, err := NewSettlementEngine(kr.settlementID, policy, kr.principals, settleWALPath)
	if err != nil {
		return SettlementTraceBundle{}, BenchmarkResults{}, err
	}
	gate, err := NewFinalityTreasuryGate(policy, kr.principals, kr.authorities, finalityWALPath)
	if err != nil {
		_ = engine.Close()
		return SettlementTraceBundle{}, BenchmarkResults{}, err
	}

	tn, err := StartLoopbackTestNet(committee, engine, gate)
	if err != nil {
		_ = engine.Close()
		_ = gate.Close()
		return SettlementTraceBundle{}, BenchmarkResults{}, err
	}
	defer tn.Close()

	const (
		totalEpochs  = 10
		jobsPerEpoch = 20
		totalJobs    = totalEpochs * jobsPerEpoch // 200 jobs
	)

	type settledBundle struct {
		job          AdmittedJob
		work         WorkResult
		attestations []EASAttestation
		receipt      UsefulWorkReceipt
		proof        []MerkleProofStep
		auth         RewardAuthorization
	}

	allSettled := make([]settledBundle, 0, totalJobs)
	epochCommitments := make([]EpochCommitment, 0, totalEpochs)

	admitTimes := make([]time.Duration, 0, totalJobs)
	performTimes := make([]time.Duration, 0, totalJobs)
	verifyTimes := make([]time.Duration, 0, totalJobs)
	issueTimes := make([]time.Duration, 0, totalJobs)
	authTimes := make([]time.Duration, 0, totalJobs)

	overallStart := time.Now()
	jobSeq := 0

	for epoch := uint64(1); epoch <= totalEpochs; epoch++ {
		epochBatch := make([]settledBundle, 0, jobsPerEpoch)

		for j := 0; j < jobsPerEpoch; j++ {
			jobSeq++
			tPerfStart := time.Now()
			job, work := makeGroundedJobAndWork(rng, jobSeq, epoch, kr, manifest.Papers, paperContents)
			performTimes = append(performTimes, time.Since(tPerfStart))

			// Stage 1: Admit (Layer 1 HTTP)
			t0 := time.Now()
			if err := tn.HTTPAdmitJob(job); err != nil {
				return SettlementTraceBundle{}, BenchmarkResults{}, fmt.Errorf("admit %s: %w", job.JobID, err)
			}
			admitTimes = append(admitTimes, time.Since(t0))

			// Stage 2+3: Verify & EAS-Attest (Layer 1 HTTP)
			t1 := time.Now()
			atts, err := tn.HTTPVerifyAndAttest(job.JobID, work)
			if err != nil {
				return SettlementTraceBundle{}, BenchmarkResults{}, fmt.Errorf("verify %s: %w", job.JobID, err)
			}
			verifyTimes = append(verifyTimes, time.Since(t1))

			// Stage 4: IssueReceipt (Layer 2 HTTP + fsync WAL)
			t2 := time.Now()
			receipt, err := tn.HTTPIssueReceipt(kr.settlementID, RoleSettlementNode, job, work, atts)
			if err != nil {
				return SettlementTraceBundle{}, BenchmarkResults{}, fmt.Errorf("settle %s: %w", job.JobID, err)
			}
			issueTimes = append(issueTimes, time.Since(t2))

			// Application read-only consumption check on every 10th receipt over HTTP.
			if jobSeq%10 == 0 {
				gotRec, err := tn.HTTPReadReceipt(receipt.ReceiptID)
				if err != nil || gotRec.ReceiptID != receipt.ReceiptID {
					return SettlementTraceBundle{}, BenchmarkResults{}, fmt.Errorf("read-only app query failed for %s", receipt.ReceiptID)
				}
			}

			epochBatch = append(epochBatch, settledBundle{
				job:          job,
				work:         work,
				attestations: atts,
				receipt:      receipt,
			})
		}

		// Seal epoch binary Merkle root on Layer 2 and commit to Layer 3.
		comm, proofs, err := tn.HTTPSealEpoch(epoch)
		if err != nil {
			return SettlementTraceBundle{}, BenchmarkResults{}, fmt.Errorf("seal epoch %d: %w", epoch, err)
		}
		if err := tn.HTTPRegisterEpochCommitment(comm); err != nil {
			return SettlementTraceBundle{}, BenchmarkResults{}, fmt.Errorf("register epoch %d: %w", epoch, err)
		}
		epochCommitments = append(epochCommitments, comm)

		// Stage 5: AuthorizeReward after finality delay K=2 epochs (Layer 3 HTTP + fsync WAL).
		finalizedEpoch := epoch + policy.FinalityDelayEpochs
		for idx := range epochBatch {
			item := &epochBatch[idx]
			item.proof = proofs[item.receipt.ReceiptID]
			authActor := kr.authorities[idx%len(kr.authorities)].ID
			t3 := time.Now()
			auth, err := tn.HTTPAuthorizeReward(authActor, RoleGovernanceTreasury, finalizedEpoch, item.job, item.work, item.attestations, item.receipt, item.proof)
			if err != nil {
				return SettlementTraceBundle{}, BenchmarkResults{}, fmt.Errorf("authorize %s: %w", item.job.JobID, err)
			}
			authTimes = append(authTimes, time.Since(t3))
			item.auth = auth
			allSettled = append(allSettled, *item)
		}
	}

	totalElapsed := time.Since(overallStart)
	throughput := float64(totalJobs) / totalElapsed.Seconds()

	liveBalances, err := tn.HTTPGetBalances()
	if err != nil {
		return SettlementTraceBundle{}, BenchmarkResults{}, err
	}

	// -----------------------------------------------------------------------
	// Stress Test 1: Sequential Replay of all 200 settled receipts (0/200 succeed)
	// -----------------------------------------------------------------------
	replayAccepted := 0
	replayRejected := 0
	for i, item := range allSettled {
		// Alternate Layer 2 and Layer 3 replay, including cross-epoch replay.
		if i%2 == 0 {
			_, err := tn.HTTPIssueReceipt(kr.settlementID, RoleSettlementNode, item.job, item.work, item.attestations)
			if err == nil {
				replayAccepted++
			} else if ErrorCodeOf(err) == ErrDoubleClaim {
				replayRejected++
			}
		} else {
			_, err := tn.HTTPAuthorizeReward(kr.authorities[0].ID, RoleGovernanceTreasury, item.receipt.Epoch+policy.FinalityDelayEpochs+1,
				item.job, item.work, item.attestations, item.receipt, item.proof)
			if err == nil {
				replayAccepted++
			} else if ErrorCodeOf(err) == ErrDoubleClaim {
				replayRejected++
			}
		}
	}

	// -----------------------------------------------------------------------
	// Stress Test 2: Cold-Restart WAL Recovery Audit (before race job mutates WAL)
	// -----------------------------------------------------------------------
	walL2Count := engine.wal.Count()
	walL3Count := gate.wal.Count()
	_ = engine.Close()
	_ = gate.Close()

	reopenedEngine, err := NewSettlementEngine(kr.settlementID, policy, kr.principals, settleWALPath)
	if err != nil {
		return SettlementTraceBundle{}, BenchmarkResults{}, fmt.Errorf("reopen L2 WAL: %w", err)
	}
	defer reopenedEngine.Close()

	reopenedGate, err := NewFinalityTreasuryGate(policy, kr.principals, kr.authorities, finalityWALPath)
	if err != nil {
		return SettlementTraceBundle{}, BenchmarkResults{}, fmt.Errorf("reopen L3 WAL: %w", err)
	}
	defer reopenedGate.Close()

	reopenedBalances := reopenedGate.BalanceSheetSnapshot()
	coldIdentical := reopenedEngine.NullifierCount() == totalJobs &&
		equalBalanceSheets(liveBalances, reopenedBalances)

	// Verify cold-restarted Layer 2 and Layer 3 still block replay of receipt #0.
	_, l2ReplayErr := reopenedEngine.IssueReceipt(kr.settlementID, RoleSettlementNode, allSettled[0].job, allSettled[0].work, allSettled[0].attestations)
	_, l3ReplayErr := reopenedGate.AuthorizeReward(kr.authorities[0].ID, RoleGovernanceTreasury, allSettled[0].auth.FinalizedEpoch,
		allSettled[0].job, allSettled[0].work, allSettled[0].attestations, allSettled[0].receipt, allSettled[0].proof)
	coldReplayBlocked := ErrorCodeOf(l2ReplayErr) == ErrDoubleClaim && ErrorCodeOf(l3ReplayErr) == ErrDoubleClaim

	// -----------------------------------------------------------------------
	// Stress Test 3: 64-Goroutine Concurrent Double-Claim Race (strictly 1/64 succeeds)
	// -----------------------------------------------------------------------
	const raceWorkers = 64
	raceEngine, err := NewSettlementEngine(kr.settlementID, policy, kr.principals, "")
	if err != nil {
		return SettlementTraceBundle{}, BenchmarkResults{}, err
	}
	raceGate, err := NewFinalityTreasuryGate(policy, kr.principals, kr.authorities, "")
	if err != nil {
		return SettlementTraceBundle{}, BenchmarkResults{}, err
	}
	raceJob, raceWork := makeGroundedJobAndWork(rng, 9001, 1, kr, manifest.Papers, paperContents)
	if err := committee.AdmitJob(raceJob); err != nil {
		return SettlementTraceBundle{}, BenchmarkResults{}, err
	}
	raceAtts, err := committee.VerifyAndAttest(raceJob.JobID, raceWork)
	if err != nil {
		return SettlementTraceBundle{}, BenchmarkResults{}, err
	}

	var l2Accepts, l2Rejects int32
	var winningReceipt UsefulWorkReceipt
	var winMu sync.Mutex
	var wg sync.WaitGroup
	startCh := make(chan struct{})
	for g := 0; g < raceWorkers; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startCh
			r, err := raceEngine.IssueReceipt(kr.settlementID, RoleSettlementNode, raceJob, raceWork, raceAtts)
			if err == nil {
				atomic.AddInt32(&l2Accepts, 1)
				winMu.Lock()
				winningReceipt = r
				winMu.Unlock()
			} else if ErrorCodeOf(err) == ErrDoubleClaim {
				atomic.AddInt32(&l2Rejects, 1)
			}
		}()
	}
	close(startCh)
	wg.Wait()

	raceComm, raceProofs, err := raceEngine.SealEpoch(1)
	if err != nil {
		return SettlementTraceBundle{}, BenchmarkResults{}, err
	}
	if err := raceGate.RegisterEpochCommitment(raceComm); err != nil {
		return SettlementTraceBundle{}, BenchmarkResults{}, err
	}

	var l3Accepts, l3Rejects int32
	startCh3 := make(chan struct{})
	for g := 0; g < raceWorkers; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startCh3
			_, err := raceGate.AuthorizeReward(kr.authorities[0].ID, RoleGovernanceTreasury, 1+policy.FinalityDelayEpochs,
				raceJob, raceWork, raceAtts, winningReceipt, raceProofs[winningReceipt.ReceiptID])
			if err == nil {
				atomic.AddInt32(&l3Accepts, 1)
			} else if ErrorCodeOf(err) == ErrDoubleClaim {
				atomic.AddInt32(&l3Rejects, 1)
			}
		}()
	}
	close(startCh3)
	wg.Wait()

	// -----------------------------------------------------------------------
	// Determinism Audit: Out-of-Order Arrival Permutation Invariance (5 permutations)
	// -----------------------------------------------------------------------
	const numPerms = 5
	permExact := true
	for p := 0; p < numPerms; p++ {
		permGate, err := NewFinalityTreasuryGate(policy, kr.principals, kr.authorities, "")
		if err != nil {
			return SettlementTraceBundle{}, BenchmarkResults{}, err
		}
		for _, c := range epochCommitments {
			if err := permGate.RegisterEpochCommitment(c); err != nil {
				return SettlementTraceBundle{}, BenchmarkResults{}, err
			}
		}
		order := make([]int, len(allSettled))
		for i := range order {
			order[i] = i
		}
		// Deterministic Fisher-Yates shuffle.
		for i := len(order) - 1; i > 0; i-- {
			j := rng.intn(i + 1)
			order[i], order[j] = order[j], order[i]
		}
		for _, idx := range order {
			item := allSettled[idx]
			if _, err := permGate.AuthorizeReward(item.auth.AuthorityID, RoleGovernanceTreasury, item.auth.FinalizedEpoch,
				item.job, item.work, item.attestations, item.receipt, item.proof); err != nil {
				permExact = false
				break
			}
		}
		if !equalBalanceSheets(liveBalances, permGate.BalanceSheetSnapshot()) {
			permExact = false
		}
	}

	// -----------------------------------------------------------------------
	// Build Canonical Trace Bundle: 200 Lifecycle Cases + 24 Adversarial Cases
	// -----------------------------------------------------------------------
	cases := make([]TraceCase, 0, totalJobs+24)
	for i, item := range allSettled {
		jCopy := item.job
		wCopy := item.work
		rCopy := item.receipt
		aCopy := item.auth
		cases = append(cases, TraceCase{
			CaseID:          fmt.Sprintf("lc_%03d_%s", i+1, item.job.JobID),
			Category:        "lifecycle",
			Stage:           "AUTHORIZE_REWARD",
			Description:     fmt.Sprintf("Grounded job %s on corpus paper %s (tier=%s)", item.job.JobID, item.job.CorpusPaperID, item.job.ModelTier),
			Job:             &jCopy,
			WorkResult:      &wCopy,
			Attestations:    item.attestations,
			Receipt:         &rCopy,
			Authorization:   &aCopy,
			ExpectedVerdict: "ACCEPT",
			ExpectedError:   ErrNone,
		})
	}

	advCases := buildAdversarialCases(allSettled[0], allSettled[1], kr, policy, epochCommitments[0], rng, manifest.Papers, paperContents)
	capCase, capComm := buildCapOverflowCase(kr, policy, rng, manifest.Papers, paperContents)
	epochCommitments = append(epochCommitments, capComm)
	advCases = append(advCases, capCase)
	sort.Slice(advCases, func(i, j int) bool { return advCases[i].CaseID < advCases[j].CaseID })
	cases = append(cases, advCases...)

	bundle := SettlementTraceBundle{
		SchemaVersion:    SchemaVersion,
		Protocol:         ProtocolID,
		EASSchemaUID:     CanonicalEASSchemaUID(),
		Seed:             seed,
		Policy:           policy,
		Principals:       kr.principals,
		EpochCommitments: epochCommitments,
		Cases:            cases,
	}

	report, err := VerifyTraceBundle(bundle)
	if err != nil {
		return SettlementTraceBundle{}, BenchmarkResults{}, fmt.Errorf("verify generated trace: %w", err)
	}
	if !report.AllMatched {
		for _, cv := range report.CaseVerdicts {
			if !cv.MatchedExpectation {
				return SettlementTraceBundle{}, BenchmarkResults{}, fmt.Errorf("trace case %s mismatch: got (%s, %s) want (%s, %s)",
					cv.CaseID, cv.Verdict, cv.ErrorCode, cv.ExpectedVerdict, cv.ExpectedError)
			}
		}
	}
	bundle.ExpectedBalanceSheet = report.BalanceSheet
	bundle.ExpectedAuditMerkleRoot = report.AuditMerkleRoot

	advOutcomes := make([]AdversarialItem, 0, len(advCases))
	advBlocked := 0
	for _, cv := range report.CaseVerdicts {
		if cv.Category == "adversarial" || cv.Category == "key_separation" {
			blocked := cv.Verdict == "REJECT" && cv.ErrorCode == cv.ExpectedError
			if blocked {
				advBlocked++
			}
			advOutcomes = append(advOutcomes, AdversarialItem{
				CaseID:        cv.CaseID,
				Stage:         cv.Stage,
				ExpectedError: cv.ExpectedError,
				ObservedError: cv.ErrorCode,
				Blocked:       blocked,
			})
		}
	}

	// -----------------------------------------------------------------------
	// 3 Explicit Honest Negative Regimes
	// -----------------------------------------------------------------------
	neg1 := runNegCollapsedLayerSelfIssuance(seed+101, kr, policy, manifest.Papers, paperContents)
	neg2 := runNegFinalityEpochLatencyTax(seed+202, kr, policy, manifest.Papers, paperContents)
	neg3 := runNegValidatorQuorumStall(seed+303, kr, policy, manifest.Papers, paperContents)

	conservationDrift := (liveBalances.TotalProviderPayoutMicroZOO + liveBalances.ConservationFundMicroZOO + liveBalances.ProtocolFeePoolMicroZOO + liveBalances.TotalPayerRefundsMicroZOO) - liveBalances.TotalFinalizedEscrowMicroZOO

	results := BenchmarkResults{
		SchemaVersion:        SchemaVersion,
		Protocol:             ProtocolID,
		Issue:                "zoo-apps/papers#15",
		HIP:                  "HIP-1350",
		Seed:                 seed,
		CorpusPapersVerified: len(manifest.Papers),
		CorpusManifestSHA256: manifestSHA,
		Topology: map[string]any{
			"transport":               "loopback-http-json-rpc-3-nodes",
			"providers":               len(kr.providers),
			"validators":              len(kr.validators),
			"validator_quorum":        policy.ValidatorQuorum,
			"epochs":                  totalEpochs,
			"jobs_per_epoch":          jobsPerEpoch,
			"finality_delay_epochs":   policy.FinalityDelayEpochs,
			"claim_window_epochs":     policy.ClaimWindowEpochs,
			"conservation_bps":        policy.ConservationBPS,
			"protocol_bps":            policy.ProtocolBPS,
			"governance_authorities":  len(kr.authorities),
			"readonly_applications":   len(kr.apps),
			"advisory_ai_agents":      len(kr.aiAgents),
		},
		LifecycleJobs:            totalJobs,
		TotalTraceCases:          len(cases),
		EndToEndElapsedMS:        round2(float64(totalElapsed.Nanoseconds()) / 1e6),
		ThroughputReceiptsPerSec: round2(throughput),
		StageLatencies: map[string]LatencyStats{
			"Admit":           summarizeLatencies(admitTimes),
			"Perform":         summarizeLatencies(performTimes),
			"Verify":          summarizeLatencies(verifyTimes),
			"IssueReceipt":    summarizeLatencies(issueTimes),
			"AuthorizeReward": summarizeLatencies(authTimes),
		},
		BalanceSheet:    report.BalanceSheet,
		AuditMerkleRoot: report.AuditMerkleRoot,
		DoubleClaimStress: DoubleClaimStressResult{
			SequentialReplayAttempts:  totalJobs,
			SequentialReplayAccepted:  replayAccepted,
			SequentialReplayRejected:  replayRejected,
			ConcurrentGoroutines:      raceWorkers,
			ConcurrentL2Accepted:      int(l2Accepts),
			ConcurrentL2Rejected:      int(l2Rejects),
			ConcurrentL3Accepted:      int(l3Accepts),
			ConcurrentL3Rejected:      int(l3Rejects),
			ZeroDoubleClaimsPreserved: replayAccepted == 0 && replayRejected == totalJobs && l2Accepts == 1 && l2Rejects == raceWorkers-1 && l3Accepts == 1 && l3Rejects == raceWorkers-1,
		},
		DeterminismAudit: DeterminismAuditResult{
			WALEntriesReplayed:        walL2Count + walL3Count,
			ColdRestartStateIdentical: coldIdentical,
			ColdRestartReplayBlocked:  coldReplayBlocked,
			PermutationsTested:        numPerms,
			PermutationBalanceExact:   permExact,
			ConservationDriftMicroZOO: conservationDrift,
		},
		AdversarialSuite: AdversarialSummary{
			TotalAttacks:   len(advOutcomes),
			BlockedAttacks: advBlocked,
			BlockRatePct:   round2(100.0 * float64(advBlocked) / float64(len(advOutcomes))),
			CaseOutcomes:   advOutcomes,
		},
	}
	results.NegativeRegimes.CollapsedLayerSelfIssuance = neg1
	results.NegativeRegimes.FinalityEpochLatencyTax = neg2
	results.NegativeRegimes.ValidatorQuorumStall = neg3

	return bundle, results, nil
}

func equalBalanceSheets(a, b BalanceSheet) bool {
	if a.TotalFinalizedEscrowMicroZOO != b.TotalFinalizedEscrowMicroZOO ||
		a.TotalAuthorizedPayoutMicroZOO != b.TotalAuthorizedPayoutMicroZOO ||
		a.TotalProviderPayoutMicroZOO != b.TotalProviderPayoutMicroZOO ||
		a.ConservationFundMicroZOO != b.ConservationFundMicroZOO ||
		a.ProtocolFeePoolMicroZOO != b.ProtocolFeePoolMicroZOO ||
		a.TotalPayerRefundsMicroZOO != b.TotalPayerRefundsMicroZOO ||
		a.AuthorizedReceiptCount != b.AuthorizedReceiptCount ||
		a.ConservationExact != b.ConservationExact ||
		len(a.ProviderBalancesMicroZOO) != len(b.ProviderBalancesMicroZOO) ||
		len(a.EpochAuthorizedMicroZOO) != len(b.EpochAuthorizedMicroZOO) {
		return false
	}
	for k, v := range a.ProviderBalancesMicroZOO {
		if b.ProviderBalancesMicroZOO[k] != v {
			return false
		}
	}
	for k, v := range a.EpochAuthorizedMicroZOO {
		if b.EpochAuthorizedMicroZOO[k] != v {
			return false
		}
	}
	return true
}

func buildAdversarialCases(
	base0, base1 struct {
		job          AdmittedJob
		work         WorkResult
		attestations []EASAttestation
		receipt      UsefulWorkReceipt
		proof        []MerkleProofStep
		auth         RewardAuthorization
	},
	kr actorKeyring,
	policy NetworkPolicy,
	epoch1Comm EpochCommitment,
	rng *splitMix64,
	papers []CorpusPaper,
	contents map[string][]byte,
) []TraceCase {
	cloneAtts := func(src []EASAttestation) []EASAttestation {
		out := make([]EASAttestation, len(src))
		copy(out, src)
		return out
	}

	// Helper to build a fresh valid job+work+quorum attestations+receipt+auth (not yet authorized in main trace).
	makeFresh := func(seq int, epoch uint64) (AdmittedJob, WorkResult, []EASAttestation, UsefulWorkReceipt, RewardAuthorization) {
		job, work := makeGroundedJobAndWork(rng, seq, epoch, kr, papers, contents)
		schemaUID := CanonicalEASSchemaUID()
		refUID := ComputeRefUID(job.JobID)
		atts := make([]EASAttestation, 0, len(kr.validators))
		uids := make([]string, 0, len(kr.validators))
		for idx, v := range kr.validators {
			nonce := uint64(50000 + seq*10 + idx)
			att := EASAttestation{
				SchemaUID:        schemaUID,
				RefUID:           refUID,
				JobID:            job.JobID,
				Recipient:        job.ProviderID,
				Attester:         v.ID,
				WorkHash:         work.WorkHash,
				Epoch:            job.Epoch,
				Nonce:            nonce,
				TokensProcessed:  work.TokensProcessed,
				ComputeUnits:     work.ComputeUnits,
				ConsumedMicroZOO: work.ConsumedMicroZOO,
			}
			att.AttestationUID = ComputeAttestationUID(att.SchemaUID, att.RefUID, att.Recipient, att.Attester, att.WorkHash, att.Epoch, att.Nonce)
			att.SignatureHex = SignEd25519Hex(v.PrivKey, ValidatorSignatureMessage(att))
			atts = append(atts, att)
			uids = append(uids, att.AttestationUID)
		}
		sort.Strings(uids)
		split, _ := ComputeExactSplit(job.MaxBudgetMicroZOO, work.ConsumedMicroZOO, job.ConservationBPS, job.ProtocolBPS)
		rid := ComputeReceiptID(job.JobID, job.ProviderID, job.PayerID, work.WorkHash, job.Epoch,
			job.MaxBudgetMicroZOO, work.ConsumedMicroZOO, job.ConservationBPS, job.ProtocolBPS, uids)
		nullifier := ComputeReceiptNullifier(job.JobID, rid, work.WorkHash)
		rec := UsefulWorkReceipt{
			ReceiptID:                 rid,
			Nullifier:                 nullifier,
			JobID:                     job.JobID,
			PayerID:                   job.PayerID,
			ProviderID:                job.ProviderID,
			IssuerID:                  kr.settlementID,
			IssuerRole:                RoleSettlementNode,
			WorkHash:                  work.WorkHash,
			Epoch:                     job.Epoch,
			MaxBudgetMicroZOO:         job.MaxBudgetMicroZOO,
			ConsumedMicroZOO:          work.ConsumedMicroZOO,
			ProviderShareMicroZOO:     split.ProviderShare,
			ConservationShareMicroZOO: split.ConservationShare,
			ProtocolFeeMicroZOO:       split.ProtocolFee,
			RefundMicroZOO:            split.Refund,
			ConservationBPS:           job.ConservationBPS,
			ProtocolBPS:               job.ProtocolBPS,
			AttestationUIDs:           uids,
		}
		auth := RewardAuthorization{
			ReceiptID:                 rec.ReceiptID,
			Nullifier:                 rec.Nullifier,
			JobID:                     rec.JobID,
			ProviderID:                rec.ProviderID,
			AuthorityID:               kr.authorities[0].ID,
			AuthorityRole:             RoleGovernanceTreasury,
			ReceiptEpoch:              rec.Epoch,
			FinalizedEpoch:            rec.Epoch + policy.FinalityDelayEpochs,
			EpochMerkleRoot:           epoch1Comm.ReceiptsMerkleRoot,
			MerkleProof:               base0.proof,
			ProviderShareMicroZOO:     rec.ProviderShareMicroZOO,
			ConservationShareMicroZOO: rec.ConservationShareMicroZOO,
			ProtocolFeeMicroZOO:       rec.ProtocolFeeMicroZOO,
			RefundMicroZOO:            rec.RefundMicroZOO,
		}
		auth.AuthID = ComputeRewardAuthID(auth)
		auth.TreasurySigHex = SignEd25519Hex(kr.authorities[0].PrivKey, TreasurySignatureMessage(auth))
		return job, work, atts, rec, auth
	}

	out := make([]TraceCase, 0, 24)

	// 1. Direct double claim of already authorized receipt #0.
	{
		j, w, r, a := base0.job, base0.work, base0.receipt, base0.auth
		out = append(out, TraceCase{
			CaseID: "adv_01_direct_double_claim", Category: "adversarial", Stage: "AUTHORIZE_REWARD",
			Description: "Direct replay of already authorized receipt nullifier",
			Job: &j, WorkResult: &w, Attestations: cloneAtts(base0.attestations), Receipt: &r, Authorization: &a,
			ExpectedVerdict: "REJECT", ExpectedError: ErrDoubleClaim,
		})
	}

	// 2. Cross-epoch replay of already authorized receipt #1 at a later finalized epoch.
	{
		j, w, r, a := base1.job, base1.work, base1.receipt, base1.auth
		a.FinalizedEpoch = r.Epoch + policy.FinalityDelayEpochs + 2
		a.AuthID = ComputeRewardAuthID(a)
		a.TreasurySigHex = SignEd25519Hex(kr.privKeys[a.AuthorityID], TreasurySignatureMessage(a))
		out = append(out, TraceCase{
			CaseID: "adv_02_cross_epoch_replay", Category: "adversarial", Stage: "AUTHORIZE_REWARD",
			Description: "Cross-epoch replay of settled receipt with re-signed later finalized_epoch",
			Job: &j, WorkResult: &w, Attestations: cloneAtts(base1.attestations), Receipt: &r, Authorization: &a,
			ExpectedVerdict: "REJECT", ExpectedError: ErrDoubleClaim,
		})
	}

	// 3. Re-attestation replay: same already-settled job_id with fresh validator nonces (different nullifier, same job_id).
	{
		j, w := base0.job, base0.work
		schemaUID := CanonicalEASSchemaUID()
		refUID := ComputeRefUID(j.JobID)
		atts := make([]EASAttestation, 0, len(kr.validators))
		uids := make([]string, 0, len(kr.validators))
		for idx, v := range kr.validators {
			att := EASAttestation{
				SchemaUID: schemaUID, RefUID: refUID, JobID: j.JobID, Recipient: j.ProviderID, Attester: v.ID,
				WorkHash: w.WorkHash, Epoch: j.Epoch, Nonce: uint64(888000 + idx),
				TokensProcessed: w.TokensProcessed, ComputeUnits: w.ComputeUnits, ConsumedMicroZOO: w.ConsumedMicroZOO,
			}
			att.AttestationUID = ComputeAttestationUID(att.SchemaUID, att.RefUID, att.Recipient, att.Attester, att.WorkHash, att.Epoch, att.Nonce)
			att.SignatureHex = SignEd25519Hex(v.PrivKey, ValidatorSignatureMessage(att))
			atts = append(atts, att)
			uids = append(uids, att.AttestationUID)
		}
		sort.Strings(uids)
		r := base0.receipt
		r.AttestationUIDs = uids
		r.ReceiptID = ComputeReceiptID(j.JobID, j.ProviderID, j.PayerID, w.WorkHash, j.Epoch, j.MaxBudgetMicroZOO, w.ConsumedMicroZOO, j.ConservationBPS, j.ProtocolBPS, uids)
		r.Nullifier = ComputeReceiptNullifier(j.JobID, r.ReceiptID, w.WorkHash)
		out = append(out, TraceCase{
			CaseID: "adv_03_job_reattestation_different_nonce", Category: "adversarial", Stage: "ISSUE_RECEIPT",
			Description: "Re-attesting an already settled job_id with mutated validator nonces",
			Job: &j, WorkResult: &w, Attestations: atts, Receipt: &r,
			ExpectedVerdict: "REJECT", ExpectedError: ErrDoubleClaim,
		})
	}

	// 4. Application attempts to authorize reward issuance directly.
	{
		j, w, atts, r, a := makeFresh(104, 1)
		a.AuthorityID = kr.apps[0]
		a.AuthorityRole = RoleApplication
		a.AuthID = ComputeRewardAuthID(a)
		a.TreasurySigHex = SignEd25519Hex(kr.privKeys[kr.apps[0]], TreasurySignatureMessage(a))
		out = append(out, TraceCase{
			CaseID: "adv_04_app_reward_issuance", Category: "adversarial", Stage: "AUTHORIZE_REWARD",
			Description: "Downstream APPLICATION attempts to authorize reward disbursement",
			Job: &j, WorkResult: &w, Attestations: atts, Receipt: &r, Authorization: &a,
			ExpectedVerdict: "REJECT", ExpectedError: ErrAppIssuanceForbidden,
		})
	}

	// 5. Application attempts to issue Layer 2 receipt directly.
	{
		j, w, atts, r, _ := makeFresh(105, 1)
		r.IssuerID = kr.apps[1]
		r.IssuerRole = RoleApplication
		out = append(out, TraceCase{
			CaseID: "adv_05_app_receipt_issuance", Category: "adversarial", Stage: "ISSUE_RECEIPT",
			Description: "Downstream APPLICATION attempts to issue Layer 2 UsefulWorkReceipt",
			Job: &j, WorkResult: &w, Attestations: atts, Receipt: &r,
			ExpectedVerdict: "REJECT", ExpectedError: ErrAppIssuanceForbidden,
		})
	}

	// 6. AI agent attempts to authorize treasury reward disbursement.
	{
		j, w, atts, r, a := makeFresh(106, 1)
		a.AuthorityID = kr.aiAgents[0]
		a.AuthorityRole = RoleAIAgent
		a.AuthID = ComputeRewardAuthID(a)
		a.TreasurySigHex = SignEd25519Hex(kr.privKeys[kr.aiAgents[0]], TreasurySignatureMessage(a))
		out = append(out, TraceCase{
			CaseID: "adv_06_ai_agent_treasury_auth", Category: "adversarial", Stage: "AUTHORIZE_REWARD",
			Description: "AI_AGENT attempts to sign Layer 3 treasury disbursement authorization",
			Job: &j, WorkResult: &w, Attestations: atts, Receipt: &r, Authorization: &a,
			ExpectedVerdict: "REJECT", ExpectedError: ErrAIIssuanceForbidden,
		})
	}

	// 7. AI agent attempts to raise epoch treasury cap.
	{
		pm := PolicyMutationAttempt{ActorID: kr.aiAgents[0], ActorRole: RoleAIAgent, Field: "epoch_treasury_cap_micro_zoo", ProposedValue: 999_000_000_000}
		out = append(out, TraceCase{
			CaseID: "adv_07_ai_agent_cap_mutation", Category: "adversarial", Stage: "POLICY_MUTATION",
			Description: "AI_AGENT attempts to raise governance epoch_treasury_cap_micro_zoo",
			PolicyMutation: &pm, ExpectedVerdict: "REJECT", ExpectedError: ErrAIPolicyMutationForbid,
		})
	}

	// 8. AI agent attempts to downgrade validator quorum threshold.
	{
		pm := PolicyMutationAttempt{ActorID: kr.aiAgents[0], ActorRole: RoleAIAgent, Field: "validator_quorum", ProposedValue: 1}
		out = append(out, TraceCase{
			CaseID: "adv_08_ai_agent_quorum_downgrade", Category: "adversarial", Stage: "POLICY_MUTATION",
			Description: "AI_AGENT attempts to weaken validator_quorum from 3 to 1",
			PolicyMutation: &pm, ExpectedVerdict: "REJECT", ExpectedError: ErrAIPolicyMutationForbid,
		})
	}

	// 9. Provider self-verification attempt (attester == provider_id).
	{
		j, w, atts, _, _ := makeFresh(109, 1)
		selfAtt := atts[0]
		selfAtt.Attester = j.ProviderID
		selfAtt.AttestationUID = ComputeAttestationUID(selfAtt.SchemaUID, selfAtt.RefUID, selfAtt.Recipient, selfAtt.Attester, selfAtt.WorkHash, selfAtt.Epoch, selfAtt.Nonce)
		selfAtt.SignatureHex = SignEd25519Hex(kr.privKeys[j.ProviderID], ValidatorSignatureMessage(selfAtt))
		atts[0] = selfAtt
		out = append(out, TraceCase{
			CaseID: "adv_09_provider_self_verification", Category: "adversarial", Stage: "VERIFY",
			Description: "Provider attempts to self-attest its own useful work",
			Job: &j, WorkResult: &w, Attestations: atts,
			ExpectedVerdict: "REJECT", ExpectedError: ErrSelfVerificationForbid,
		})
	}

	// 10. Layer 1 Validator attempts to authorize Layer 3 reward issuance.
	{
		j, w, atts, r, a := makeFresh(110, 1)
		a.AuthorityID = kr.validators[0].ID
		a.AuthorityRole = RoleValidator
		a.AuthID = ComputeRewardAuthID(a)
		a.TreasurySigHex = SignEd25519Hex(kr.validators[0].PrivKey, TreasurySignatureMessage(a))
		out = append(out, TraceCase{
			CaseID: "adv_10_validator_mint_attempt", Category: "adversarial", Stage: "AUTHORIZE_REWARD",
			Description: "Layer 1 VALIDATOR attempts to authorize Layer 3 reward issuance",
			Job: &j, WorkResult: &w, Attestations: atts, Receipt: &r, Authorization: &a,
			ExpectedVerdict: "REJECT", ExpectedError: ErrUnauthorizedTreasury,
		})
	}

	// 11. Layer 2 Settlement Node attempts to authorize Layer 3 reward issuance.
	{
		j, w, atts, r, a := makeFresh(111, 1)
		a.AuthorityID = kr.settlementID
		a.AuthorityRole = RoleSettlementNode
		a.AuthID = ComputeRewardAuthID(a)
		a.TreasurySigHex = SignEd25519Hex(kr.privKeys[kr.settlementID], TreasurySignatureMessage(a))
		out = append(out, TraceCase{
			CaseID: "adv_11_settlement_node_mint_attempt", Category: "adversarial", Stage: "AUTHORIZE_REWARD",
			Description: "Layer 2 SETTLEMENT_NODE attempts to bypass Layer 3 treasury gate",
			Job: &j, WorkResult: &w, Attestations: atts, Receipt: &r, Authorization: &a,
			ExpectedVerdict: "REJECT", ExpectedError: ErrUnauthorizedTreasury,
		})
	}

	// 12. Forged validator Ed25519 signature (flipped byte).
	{
		j, w, atts, _, _ := makeFresh(112, 1)
		sigBytes, _ := hex.DecodeString(atts[0].SignatureHex)
		sigBytes[0] ^= 0xff
		atts[0].SignatureHex = hex.EncodeToString(sigBytes)
		out = append(out, TraceCase{
			CaseID: "adv_12_forged_validator_signature", Category: "adversarial", Stage: "VERIFY",
			Description: "Corrupted Ed25519 signature on Layer 1 EAS attestation",
			Job: &j, WorkResult: &w, Attestations: atts,
			ExpectedVerdict: "REJECT", ExpectedError: ErrInvalidSignature,
		})
	}

	// 13. Forged Layer 3 governance treasury Ed25519 signature.
	{
		j, w, r, a := base0.job, base0.work, base0.receipt, base0.auth
		sigBytes, _ := hex.DecodeString(a.TreasurySigHex)
		sigBytes[len(sigBytes)-1] ^= 0xff
		a.TreasurySigHex = hex.EncodeToString(sigBytes)
		out = append(out, TraceCase{
			CaseID: "adv_13_forged_treasury_signature", Category: "adversarial", Stage: "AUTHORIZE_REWARD",
			Description: "Corrupted Ed25519 signature on Layer 3 RewardAuthorization",
			Job: &j, WorkResult: &w, Attestations: cloneAtts(base0.attestations), Receipt: &r, Authorization: &a,
			ExpectedVerdict: "REJECT", ExpectedError: ErrInvalidSignature,
		})
	}

	// 14. Unregistered rogue validator signs attestation.
	{
		j, w, atts, _, _ := makeFresh(114, 1)
		_, roguePriv := DeriveEd25519Key(99999, "rogue-validator")
		atts[0].Attester = "validator-rogue-99"
		atts[0].AttestationUID = ComputeAttestationUID(atts[0].SchemaUID, atts[0].RefUID, atts[0].Recipient, atts[0].Attester, atts[0].WorkHash, atts[0].Epoch, atts[0].Nonce)
		atts[0].SignatureHex = SignEd25519Hex(roguePriv, ValidatorSignatureMessage(atts[0]))
		out = append(out, TraceCase{
			CaseID: "adv_14_unregistered_validator", Category: "adversarial", Stage: "VERIFY",
			Description: "Unregistered validator submits signed EAS attestation",
			Job: &j, WorkResult: &w, Attestations: atts,
			ExpectedVerdict: "REJECT", ExpectedError: ErrUnauthorizedValidator,
		})
	}

	// 15. Duplicate validator stuffing quorum (same validator with two nonces).
	{
		j, w, atts, _, _ := makeFresh(115, 1)
		dup := atts[0]
		dup.Nonce = dup.Nonce + 777
		dup.AttestationUID = ComputeAttestationUID(dup.SchemaUID, dup.RefUID, dup.Recipient, dup.Attester, dup.WorkHash, dup.Epoch, dup.Nonce)
		dup.SignatureHex = SignEd25519Hex(kr.validators[0].PrivKey, ValidatorSignatureMessage(dup))
		out = append(out, TraceCase{
			CaseID: "adv_15_duplicate_validator_in_quorum", Category: "adversarial", Stage: "VERIFY",
			Description: "Single validator submits two distinct nonces to stuff quorum",
			Job: &j, WorkResult: &w, Attestations: []EASAttestation{atts[0], dup, atts[1]},
			ExpectedVerdict: "REJECT", ExpectedError: ErrDuplicateValidator,
		})
	}

	// 16. Insufficient validator quorum (2 of 5 when q=3).
	{
		j, w, atts, _, _ := makeFresh(116, 1)
		out = append(out, TraceCase{
			CaseID: "adv_16_insufficient_validator_quorum", Category: "adversarial", Stage: "VERIFY",
			Description: "Only 2 valid validator attestations submitted when quorum requires 3",
			Job: &j, WorkResult: &w, Attestations: atts[:2],
			ExpectedVerdict: "REJECT", ExpectedError: ErrInsufficientQuorum,
		})
	}

	// 17. Budget cap overflow (consumed > max_budget).
	{
		j, w, atts, _, _ := makeFresh(117, 1)
		w.ConsumedMicroZOO = j.MaxBudgetMicroZOO + 1
		out = append(out, TraceCase{
			CaseID: "adv_17_budget_cap_overflow", Category: "adversarial", Stage: "VERIFY",
			Description: "Provider claims 1 micro-ZOO above escrowed max_budget_micro_zoo",
			Job: &j, WorkResult: &w, Attestations: atts,
			ExpectedVerdict: "REJECT", ExpectedError: ErrBudgetOverflow,
		})
	}

	// 18. Epoch treasury cap exceeded (using tight override cap on epoch 1).
	{
		// Build a fresh receipt committed in a new valid single-leaf check? Wait: to hit ERR_TREASURY_CAP_EXCEEDED
		// in AUTHORIZE_REWARD, Merkle proof must pass first! Let's seal a dedicated epoch 11? Or simpler:
		// Wait: we can check against an ALREADY-authorized receipt? No, double-claim runs before cap check!
		// So let's use a brand new epoch (epoch 11) with its own real EpochCommitment? No, wait: let's add a real
		// EpochCommitment for epoch 11 ONLY in bundle? No, even cleaner: add a fresh job in epoch 11, seal epoch 11
		// with 1 leaf (proof = empty slice!), register EpochCommitment for epoch 11 in bundle.EpochCommitments,
		// and set OverrideEpochTreasuryCapMicro = 1 micro-ZOO so every earlier check passes and cap check triggers!
		// We'll patch epochCommitments via a tiny return or build epoch 11 right here — wait: let's check!
		// Even simpler: in buildAdversarialCases, we already have base0/base1; wait, if we want epoch 11 commitment
		// registered cleanly, let's check how `epochCommitments` is passed into bundle.
		// Let's handle adv_18 right after buildAdversarialCases or pass `*[]EpochCommitment`!
		// Actually, let's check: we can trigger adv_18 on a fresh epoch 10? No, epoch 10 commitment is already fixed.
		// Using a pointer to epochCommitments for epoch 11 is super clean! Let's note we'll add adv_18 cleanly using a helper below.
	}

	// 19. Tampered Merkle inclusion proof (flipped sibling byte).
	{
		j, w, r, a := base0.job, base0.work, base0.receipt, base0.auth
		badProof := make([]MerkleProofStep, len(a.MerkleProof))
		copy(badProof, a.MerkleProof)
		sibBytes, _ := hex.DecodeString(badProof[0].SiblingHex)
		sibBytes[0] ^= 0xff
		badProof[0].SiblingHex = hex.EncodeToString(sibBytes)
		a.MerkleProof = badProof
		a.AuthID = ComputeRewardAuthID(a)
		a.TreasurySigHex = SignEd25519Hex(kr.authorities[0].PrivKey, TreasurySignatureMessage(a))
		out = append(out, TraceCase{
			CaseID: "adv_19_tampered_merkle_proof", Category: "adversarial", Stage: "AUTHORIZE_REWARD",
			Description: "Tampered Merkle sibling hash in Layer 3 inclusion proof",
			Job: &j, WorkResult: &w, Attestations: cloneAtts(base0.attestations), Receipt: &r, Authorization: &a,
			ExpectedVerdict: "REJECT", ExpectedError: ErrInvalidMerkleProof,
		})
	}

	// 20. Unfinalized epoch claim (finalized_epoch < receipt.epoch + finality_delay_epochs).
	{
		j, w, r, a := base0.job, base0.work, base0.receipt, base0.auth
		a.FinalizedEpoch = r.Epoch + policy.FinalityDelayEpochs - 1
		a.AuthID = ComputeRewardAuthID(a)
		a.TreasurySigHex = SignEd25519Hex(kr.authorities[0].PrivKey, TreasurySignatureMessage(a))
		out = append(out, TraceCase{
			CaseID: "adv_20_unfinalized_epoch_claim", Category: "adversarial", Stage: "AUTHORIZE_REWARD",
			Description: "Claiming reward before finality_delay_epochs window completes",
			Job: &j, WorkResult: &w, Attestations: cloneAtts(base0.attestations), Receipt: &r, Authorization: &a,
			ExpectedVerdict: "REJECT", ExpectedError: ErrUnfinalizedEpoch,
		})
	}

	// 21. Expired epoch claim (finalized_epoch > receipt.epoch + claim_window_epochs).
	{
		j, w, r, a := base0.job, base0.work, base0.receipt, base0.auth
		a.FinalizedEpoch = r.Epoch + policy.ClaimWindowEpochs + 1
		a.AuthID = ComputeRewardAuthID(a)
		a.TreasurySigHex = SignEd25519Hex(kr.authorities[0].PrivKey, TreasurySignatureMessage(a))
		out = append(out, TraceCase{
			CaseID: "adv_21_expired_epoch_claim", Category: "adversarial", Stage: "AUTHORIZE_REWARD",
			Description: "Claiming reward after claim_window_epochs expiration",
			Job: &j, WorkResult: &w, Attestations: cloneAtts(base0.attestations), Receipt: &r, Authorization: &a,
			ExpectedVerdict: "REJECT", ExpectedError: ErrEpochExpired,
		})
	}

	// 22. Tampered micro-ZOO split violating integer conservation (+1 micro-ZOO inflation).
	{
		j, w, atts, r, _ := makeFresh(122, 1)
		r.ProviderShareMicroZOO += 1
		out = append(out, TraceCase{
			CaseID: "adv_22_tampered_micro_zoo_split", Category: "adversarial", Stage: "ISSUE_RECEIPT",
			Description: "Inflated provider_share_micro_zoo by +1 micro-ZOO violating exact conservation",
			Job: &j, WorkResult: &w, Attestations: atts, Receipt: &r,
			ExpectedVerdict: "REJECT", ExpectedError: ErrAccountingMismatch,
		})
	}

	// 23. Tampered EAS AttestationUID.
	{
		j, w, atts, _, _ := makeFresh(123, 1)
		uidBytes, _ := hex.DecodeString(atts[0].AttestationUID)
		uidBytes[0] ^= 0xff
		atts[0].AttestationUID = hex.EncodeToString(uidBytes)
		out = append(out, TraceCase{
			CaseID: "adv_23_tampered_attestation_uid", Category: "adversarial", Stage: "VERIFY",
			Description: "Mutated EAS AttestationUID failing canonical UID recomputation",
			Job: &j, WorkResult: &w, Attestations: atts,
			ExpectedVerdict: "REJECT", ExpectedError: ErrInvalidAttestationUID,
		})
	}

	// 24. Validator-Treasury cryptographic key reuse (layer key conflict).
	{
		badPrincipals := make([]Principal, len(kr.principals))
		copy(badPrincipals, kr.principals)
		// Force treasury-gov-01 to reuse validator-01's public key.
		valPub := kr.pubHex[kr.validators[0].ID]
		for i := range badPrincipals {
			if badPrincipals[i].ID == kr.authorities[0].ID {
				badPrincipals[i].PublicKeyHex = valPub
			}
		}
		out = append(out, TraceCase{
			CaseID: "adv_24_validator_treasury_key_reuse", Category: "key_separation", Stage: "KEY_AUDIT",
			Description: "Validator and Governance Treasury sharing an Ed25519 public key violates layer separation",
			OverridePrincipals: badPrincipals,
			ExpectedVerdict: "REJECT", ExpectedError: ErrKeyRoleConflict,
		})
	}

	// Now also add adv_18_epoch_treasury_cap_exceeded properly with a real single-leaf epoch commitment!
	// We use epoch 11, whose commitment root equals the single leaf hash, and empty proof.
	// Wait: let's make sure the caller appends epoch 11's commitment! Let's return it via a helper function.
	return out
}

// buildCapOverflowCase builds adv_18_epoch_treasury_cap_exceeded with a valid epoch 11 Merkle commitment
// and a tight override treasury cap so all cryptographic & finality checks pass before the cap gate trips.
func buildCapOverflowCase(kr actorKeyring, policy NetworkPolicy, rng *splitMix64, papers []CorpusPaper, contents map[string][]byte) (TraceCase, EpochCommitment) {
	const capEpoch uint64 = 11
	job, work := makeGroundedJobAndWork(rng, 118, capEpoch, kr, papers, contents)
	schemaUID := CanonicalEASSchemaUID()
	refUID := ComputeRefUID(job.JobID)
	atts := make([]EASAttestation, 0, len(kr.validators))
	uids := make([]string, 0, len(kr.validators))
	for idx, v := range kr.validators {
		att := EASAttestation{
			SchemaUID: schemaUID, RefUID: refUID, JobID: job.JobID, Recipient: job.ProviderID, Attester: v.ID,
			WorkHash: work.WorkHash, Epoch: job.Epoch, Nonce: uint64(99000 + idx),
			TokensProcessed: work.TokensProcessed, ComputeUnits: work.ComputeUnits, ConsumedMicroZOO: work.ConsumedMicroZOO,
		}
		att.AttestationUID = ComputeAttestationUID(att.SchemaUID, att.RefUID, att.Recipient, att.Attester, att.WorkHash, att.Epoch, att.Nonce)
		att.SignatureHex = SignEd25519Hex(v.PrivKey, ValidatorSignatureMessage(att))
		atts = append(atts, att)
		uids = append(uids, att.AttestationUID)
	}
	sort.Strings(uids)
	split, _ := ComputeExactSplit(job.MaxBudgetMicroZOO, work.ConsumedMicroZOO, job.ConservationBPS, job.ProtocolBPS)
	rid := ComputeReceiptID(job.JobID, job.ProviderID, job.PayerID, work.WorkHash, job.Epoch,
		job.MaxBudgetMicroZOO, work.ConsumedMicroZOO, job.ConservationBPS, job.ProtocolBPS, uids)
	nullifier := ComputeReceiptNullifier(job.JobID, rid, work.WorkHash)
	rec := UsefulWorkReceipt{
		ReceiptID: rid, Nullifier: nullifier, JobID: job.JobID, PayerID: job.PayerID, ProviderID: job.ProviderID,
		IssuerID: kr.settlementID, IssuerRole: RoleSettlementNode, WorkHash: work.WorkHash, Epoch: job.Epoch,
		MaxBudgetMicroZOO: job.MaxBudgetMicroZOO, ConsumedMicroZOO: work.ConsumedMicroZOO,
		ProviderShareMicroZOO: split.ProviderShare, ConservationShareMicroZOO: split.ConservationShare,
		ProtocolFeeMicroZOO: split.ProtocolFee, RefundMicroZOO: split.Refund,
		ConservationBPS: job.ConservationBPS, ProtocolBPS: job.ProtocolBPS, AttestationUIDs: uids,
	}
	leaf := ComputeReceiptMerkleLeaf(rec.ReceiptID, rec.Nullifier, rec.ConsumedMicroZOO)
	root := ComputeMerkleRoot([]string{leaf})
	comm := EpochCommitment{Epoch: capEpoch, ReceiptCount: 1, ReceiptsMerkleRoot: root}
	auth := RewardAuthorization{
		ReceiptID: rec.ReceiptID, Nullifier: rec.Nullifier, JobID: rec.JobID, ProviderID: rec.ProviderID,
		AuthorityID: kr.authorities[0].ID, AuthorityRole: RoleGovernanceTreasury,
		ReceiptEpoch: rec.Epoch, FinalizedEpoch: rec.Epoch + policy.FinalityDelayEpochs,
		EpochMerkleRoot: root, MerkleProof: []MerkleProofStep{},
		ProviderShareMicroZOO: rec.ProviderShareMicroZOO, ConservationShareMicroZOO: rec.ConservationShareMicroZOO,
		ProtocolFeeMicroZOO: rec.ProtocolFeeMicroZOO, RefundMicroZOO: rec.RefundMicroZOO,
	}
	auth.AuthID = ComputeRewardAuthID(auth)
	auth.TreasurySigHex = SignEd25519Hex(kr.authorities[0].PrivKey, TreasurySignatureMessage(auth))

	tc := TraceCase{
		CaseID:                        "adv_18_epoch_treasury_cap_exceeded",
		Category:                      "adversarial",
		Stage:                         "AUTHORIZE_REWARD",
		Description:                   "Valid finalized receipt rejected because epoch treasury cap is exceeded",
		Job:                           &job,
		WorkResult:                    &work,
		Attestations:                  atts,
		Receipt:                       &rec,
		Authorization:                 &auth,
		OverrideEpochTreasuryCapMicro: rec.ConsumedMicroZOO - 1,
		ExpectedVerdict:               "REJECT",
		ExpectedError:                 ErrTreasuryCapExceeded,
	}
	return tc, comm
}

// ---------------------------------------------------------------------------
// 3 Explicit Honest Negative Regimes
// ---------------------------------------------------------------------------

// Negative Regime 1: Collapsed Single-Layer App Self-Issuance vs Strict 3-Layer Separation.
func runNegCollapsedLayerSelfIssuance(seed uint64, kr actorKeyring, policy NetworkPolicy, papers []CorpusPaper, contents map[string][]byte) NegCollapsedLayerResult {
	const (
		epochBudget int64 = 100_000_000 // 100 ZOO
		attackCount       = 20
		perClaim    int64 = 5_000_000 // 5 ZOO each -> 20 * 5 = 100 ZOO (100% drain)
	)
	rng := newSplitMix64(seed)
	pMap, _ := ValidatePrincipalKeySeparation(kr.principals)

	var collapsedDrained int64
	var threeLayerDrained int64
	blockedTotal := 0
	blockedApp := 0
	blockedSelf := 0

	for i := 0; i < attackCount; i++ {
		job, work := makeGroundedJobAndWork(rng, 2000+i, 1, kr, papers, contents)
		job.MaxBudgetMicroZOO = perClaim
		work.ConsumedMicroZOO = perClaim
		work.WorkHash = ComputeWorkHash(job.JobID, job.CorpusPaperSHA256, job.WorkSpecHash, work.OutputDigest, work.TokensProcessed, work.ComputeUnits)

		// Collapsed single-layer baseline: application/provider self-attests and directly authorizes payout.
		if collapsedDrained+work.ConsumedMicroZOO <= epochBudget {
			collapsedDrained += work.ConsumedMicroZOO
		}

		// Strict 3-layer defense: half are APPLICATION self-issuance attempts, half are PROVIDER self-verification attempts.
		if i%2 == 0 {
			gate, _ := NewFinalityTreasuryGate(policy, kr.principals, kr.authorities, "")
			_, err := gate.AuthorizeReward(kr.apps[0], RoleApplication, 3, job, work, nil, UsefulWorkReceipt{}, nil)
			if err != nil {
				blockedTotal++
				if ErrorCodeOf(err) == ErrAppIssuanceForbidden {
					blockedApp++
				}
			} else {
				threeLayerDrained += work.ConsumedMicroZOO
			}
		} else {
			schemaUID := CanonicalEASSchemaUID()
			refUID := ComputeRefUID(job.JobID)
			selfAtt := EASAttestation{
				SchemaUID: schemaUID, RefUID: refUID, JobID: job.JobID, Recipient: job.ProviderID, Attester: job.ProviderID,
				WorkHash: work.WorkHash, Epoch: job.Epoch, Nonce: uint64(i + 1),
				TokensProcessed: work.TokensProcessed, ComputeUnits: work.ComputeUnits, ConsumedMicroZOO: work.ConsumedMicroZOO,
			}
			selfAtt.AttestationUID = ComputeAttestationUID(selfAtt.SchemaUID, selfAtt.RefUID, selfAtt.Recipient, selfAtt.Attester, selfAtt.WorkHash, selfAtt.Epoch, selfAtt.Nonce)
			selfAtt.SignatureHex = SignEd25519Hex(kr.privKeys[job.ProviderID], ValidatorSignatureMessage(selfAtt))
			err := ValidateQuorumAttestations(job, work, []EASAttestation{selfAtt}, pMap, policy)
			if err != nil {
				blockedTotal++
				if ErrorCodeOf(err) == ErrSelfVerificationForbid {
					blockedSelf++
				}
			} else {
				threeLayerDrained += work.ConsumedMicroZOO
			}
		}
	}

	return NegCollapsedLayerResult{
		RegimeID:                      "neg_collapsed_layer_self_issuance",
		EpochBudgetMicroZOO:           epochBudget,
		PhantomAttackCount:            attackCount,
		CollapsedBaselineDrainedMicro: collapsedDrained,
		CollapsedDrainPct:             round2(100.0 * float64(collapsedDrained) / float64(epochBudget)),
		ThreeLayerDrainedMicro:        threeLayerDrained,
		ThreeLayerBlockedCount:        blockedTotal,
		ThreeLayerBlockedPct:          round2(100.0 * float64(blockedTotal) / float64(attackCount)),
		BlockedByAppIssuanceLock:      blockedApp,
		BlockedBySelfVerifyLock:       blockedSelf,
	}
}

// Negative Regime 2: Finality-Delay vs Throughput / UX Latency Tax across K in {0, 1, 2, 4, 8}.
func runNegFinalityEpochLatencyTax(seed uint64, kr actorKeyring, basePolicy NetworkPolicy, papers []CorpusPaper, contents map[string][]byte) NegFinalityLatencyResult {
	const (
		jobsPerEpoch = 10
		totalEpochs  = 8
		slotSec      = 12.0 // 12s modeled consensus finality slot/epoch interval
	)
	delays := []uint64{0, 1, 2, 4, 8}
	sweep := make([]FinalityDelayPoint, 0, len(delays))

	for _, k := range delays {
		rng := newSplitMix64(seed + k)
		pol := basePolicy
		pol.FinalityDelayEpochs = k
		pol.ClaimWindowEpochs = k + 6

		committee, _ := NewValidatorCommittee(kr.principals, kr.validators)
		engine, _ := NewSettlementEngine(kr.settlementID, pol, kr.principals, "")
		gate, _ := NewFinalityTreasuryGate(pol, kr.principals, kr.authorities, "")

		var l2Times, l3Times []time.Duration
		earlyRejected := 0
		spendableInWindow := 0
		totalSimulated := jobsPerEpoch * totalEpochs

		for ep := uint64(1); ep <= totalEpochs; ep++ {
			type recBundle struct {
				job  AdmittedJob
				work WorkResult
				atts []EASAttestation
				rec  UsefulWorkReceipt
			}
			batch := make([]recBundle, 0, jobsPerEpoch)
			for j := 0; j < jobsPerEpoch; j++ {
				job, work := makeGroundedJobAndWork(rng, int(ep)*100+j, ep, kr, papers, contents)
				_ = committee.AdmitJob(job)
				atts, _ := committee.VerifyAndAttest(job.JobID, work)
				t0 := time.Now()
				rec, _ := engine.IssueReceipt(kr.settlementID, RoleSettlementNode, job, work, atts)
				l2Times = append(l2Times, time.Since(t0))
				batch = append(batch, recBundle{job: job, work: work, atts: atts, rec: rec})
			}
			comm, proofs, _ := engine.SealEpoch(ep)
			_ = gate.RegisterEpochCommitment(comm)

			for _, item := range batch {
				// Attempt immediate authorization at currentEpoch == ep (simulating immediate-payout UX).
				if k > 0 {
					_, err := gate.AuthorizeReward(kr.authorities[0].ID, RoleGovernanceTreasury, ep,
						item.job, item.work, item.atts, item.rec, proofs[item.rec.ReceiptID])
					if ErrorCodeOf(err) == ErrUnfinalizedEpoch {
						earlyRejected++
					}
				}
				// Check whether the receipt becomes spendable within the 8-epoch observation horizon.
				finalEp := ep + k
				t1 := time.Now()
				_, err := gate.AuthorizeReward(kr.authorities[0].ID, RoleGovernanceTreasury, finalEp,
					item.job, item.work, item.atts, item.rec, proofs[item.rec.ReceiptID])
				l3Times = append(l3Times, time.Since(t1))
				if err == nil && finalEp <= totalEpochs {
					spendableInWindow++
				}
			}
		}

		sweep = append(sweep, FinalityDelayPoint{
			FinalityDelayEpochs:         k,
			ModeledEpochDurationSec:     slotSec,
			L2ReceiptMeanLatencyUS:      summarizeLatencies(l2Times).MeanUS,
			L3AuthorizeComputeLatencyUS: summarizeLatencies(l3Times).MeanUS,
			FinalityWaitDelaySec:        float64(k) * slotSec,
			EarlyWindowSpendablePct:     round2(100.0 * float64(spendableInWindow) / float64(totalSimulated)),
			EarlyClaimRejectedCount:     earlyRejected,
		})
	}

	return NegFinalityLatencyResult{
		RegimeID:       "neg_finality_epoch_latency_tax",
		JobsPerEpoch:   jobsPerEpoch,
		TotalEpochs:    totalEpochs,
		ModeledSlotSec: slotSec,
		Sweep:          sweep,
	}
}

// Negative Regime 3: Validator Quorum Stall / Liveness Loss Under Node Outages (f = 0..4 offline out of n=5, q=3).
func runNegValidatorQuorumStall(seed uint64, kr actorKeyring, policy NetworkPolicy, papers []CorpusPaper, contents map[string][]byte) NegQuorumLivenessResult {
	const jobsPerLevel = 20
	sweep := make([]QuorumOutagePoint, 0, len(kr.validators))

	for offline := 0; offline <= len(kr.validators)-1; offline++ {
		rng := newSplitMix64(seed + uint64(offline)*17)
		// Clone validators with `offline` nodes disabled.
		vals := make([]*ValidatorNode, len(kr.validators))
		for i, v := range kr.validators {
			vals[i] = &ValidatorNode{
				ID:      v.ID,
				PubHex:  v.PubHex,
				PrivKey: v.PrivKey,
				Online:  i >= offline,
			}
		}
		committee, _ := NewValidatorCommittee(kr.principals, vals)
		engine, _ := NewSettlementEngine(kr.settlementID, policy, kr.principals, "")
		gate, _ := NewFinalityTreasuryGate(policy, kr.principals, kr.authorities, "")

		authorized := 0
		stalled := 0
		unauthorized := 0

		type settled struct {
			job  AdmittedJob
			work WorkResult
			atts []EASAttestation
			rec  UsefulWorkReceipt
		}
		var okBatch []settled

		for j := 0; j < jobsPerLevel; j++ {
			job, work := makeGroundedJobAndWork(rng, 4000+j, 1, kr, papers, contents)
			_ = committee.AdmitJob(job)
			atts, _ := committee.VerifyAndAttest(job.JobID, work)
			rec, err := engine.IssueReceipt(kr.settlementID, RoleSettlementNode, job, work, atts)
			if err != nil {
				if ErrorCodeOf(err) == ErrInsufficientQuorum {
					stalled++
				}
				// Even if an attacker tries to push under-quorum attestations straight to Layer 3, Layer 3 fails closed.
				_, err3 := gate.AuthorizeReward(kr.authorities[0].ID, RoleGovernanceTreasury, 1+policy.FinalityDelayEpochs,
					job, work, atts, rec, nil)
				if err3 == nil {
					unauthorized++
				}
				continue
			}
			okBatch = append(okBatch, settled{job: job, work: work, atts: atts, rec: rec})
		}

		if len(okBatch) > 0 {
			comm, proofs, _ := engine.SealEpoch(1)
			_ = gate.RegisterEpochCommitment(comm)
			for _, item := range okBatch {
				if _, err := gate.AuthorizeReward(kr.authorities[0].ID, RoleGovernanceTreasury, 1+policy.FinalityDelayEpochs,
					item.job, item.work, item.atts, item.rec, proofs[item.rec.ReceiptID]); err == nil {
					authorized++
				}
			}
		}

		sweep = append(sweep, QuorumOutagePoint{
			OfflineValidators:      offline,
			OnlineValidators:       len(kr.validators) - offline,
			QuorumRequired:         policy.ValidatorQuorum,
			JobsSubmitted:          jobsPerLevel,
			RewardsAuthorized:      authorized,
			LivenessPct:            round2(100.0 * float64(authorized) / float64(jobsPerLevel)),
			UnauthorizedIssuances:  unauthorized,
			StalledFailClosedCount: stalled,
		})
	}

	return NegQuorumLivenessResult{
		RegimeID:       "neg_validator_quorum_liveness_stall",
		CommitteeSize:  len(kr.validators),
		QuorumRequired: policy.ValidatorQuorum,
		Sweep:          sweep,
	}
}

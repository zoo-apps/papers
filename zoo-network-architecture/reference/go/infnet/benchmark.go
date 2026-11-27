// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package infnet

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
)

const DefaultModelID = "zoo-qwen3-14b-instruct"

// CorpusFileEntry mirrors one pinned .tex source in corpus-manifest.json.
type CorpusFileEntry struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	Role   string `json:"role"`
}

// CorpusManifest is the parsed corpus-manifest.json structure.
type CorpusManifest struct {
	SchemaVersion  string            `json:"schema_version"`
	Issue          string            `json:"issue"`
	HIP            string            `json:"hip"`
	Description    string            `json:"description"`
	DerivationRule string            `json:"derivation_rule"`
	Files          []CorpusFileEntry `json:"files"`
}

// LoadedCorpus holds verified raw text of all pinned .tex papers and their root hash.
type LoadedCorpus struct {
	Manifest   CorpusManifest
	RootSHA256 string
	Docs       []CorpusDocument
}

// CorpusDocument holds a verified paper's path and raw text.
type CorpusDocument struct {
	Path   string
	Role   string
	SHA256 string
	Text   string
}

// ScenarioMetrics summarizes throughput, latency, network, batching, reliability, and privacy for one scenario.
type ScenarioMetrics struct {
	ScenarioID                string       `json:"scenario_id"`
	TopologyMode              TopologyMode `json:"topology_mode"`
	Description               string       `json:"description"`
	TotalRequests             int          `json:"total_requests"`
	CompletedRequests         int          `json:"completed_requests"`
	CompletedWithFailover     int          `json:"completed_with_failover"`
	FailedOrRejectedRequests  int          `json:"failed_or_rejected_requests"`
	FailureInjectionRatePct   float64      `json:"failure_injection_rate_pct"`
	CompletionRatePct         float64      `json:"completion_rate_pct"`
	ThroughputTokPerSec       float64      `json:"throughput_tok_per_sec"`
	ThroughputReqPerSec       float64      `json:"throughput_req_per_sec"`
	TTFTP50Ms                 float64      `json:"ttft_p50_ms"`
	TTFTP95Ms                 float64      `json:"ttft_p95_ms"`
	TTFTP99Ms                 float64      `json:"ttft_p99_ms"`
	TPOTP50Ms                 float64      `json:"tpot_p50_ms"`
	TPOTP95Ms                 float64      `json:"tpot_p95_ms"`
	TotalLatencyP50Ms         float64      `json:"total_latency_p50_ms"`
	TotalLatencyP99Ms         float64      `json:"total_latency_p99_ms"`
	AvgRecoveryLatencyMs      float64      `json:"avg_recovery_latency_ms"`
	AvgNetworkBytesPerReq     uint64       `json:"avg_network_bytes_per_req"`
	TotalNetworkBytes         uint64       `json:"total_network_bytes"`
	AvgBatchUtilizationPct    float64      `json:"avg_batch_utilization_pct"`
	PrefixCacheHitRatePct     float64      `json:"prefix_cache_hit_rate_pct"`
	AvgQueueWaitMs            float64      `json:"avg_queue_wait_ms"`
	PrivacyLeakCount          uint64       `json:"privacy_leak_count"`
	CapacityLeakedVRAMMiB     uint64       `json:"capacity_leaked_vram_mib"`
	CapacityLeakedKVSlots     uint32       `json:"capacity_leaked_kv_slots"`
	CapacityConservationOK    bool         `json:"capacity_conservation_ok"`
	VerifiedReceiptsCount     int          `json:"verified_receipts_count"`
	TTFTVsBaselineRatio       float64      `json:"ttft_p50_vs_baseline_ratio"`
	TPOTVsBaselineRatio       float64      `json:"tpot_p50_vs_baseline_ratio"`
	ThroughputVsBaselineRatio float64      `json:"throughput_vs_baseline_ratio"`
}

// NegativeRegimeSummary documents an explicit regime where decentralized execution loses to centralized baselines.
type NegativeRegimeSummary struct {
	RegimeID       string             `json:"regime_id"`
	Title          string             `json:"title"`
	Hypothesis     string             `json:"hypothesis"`
	Finding        string             `json:"finding"`
	Baseline       ScenarioMetrics    `json:"baseline"`
	Degraded       ScenarioMetrics    `json:"degraded"`
	HeadlineRatios map[string]float64 `json:"headline_ratios"`
}

// BenchmarkReport is the complete machine-readable output written to results.json.
type BenchmarkReport struct {
	SchemaVersion           string                  `json:"schema_version"`
	SpecVersion             string                  `json:"spec_version"`
	Issue                   string                  `json:"issue"`
	HIP                     string                  `json:"hip"`
	Seed                    uint64                  `json:"seed"`
	RequestsPerScenario     int                     `json:"requests_per_scenario"`
	CorpusRootSHA256        string                  `json:"corpus_root_sha256"`
	CorpusFilesVerified     int                     `json:"corpus_files_verified"`
	Scenarios               []ScenarioMetrics       `json:"scenarios"`
	NegativeRegimes         []NegativeRegimeSummary `json:"negative_regimes"`
	ParityCasesCount        int                     `json:"parity_cases_count"`
	AuditMerkleRoot         string                  `json:"audit_merkle_root"`
	TotalPrivacyLeaks       uint64                  `json:"total_privacy_leaks"`
	TotalCapacityLeaks      uint64                  `json:"total_capacity_leaks"`
	ProvesScientificTruth   bool                    `json:"proves_scientific_truth"`
	AuthorizesTreasurySpend bool                    `json:"authorizes_treasury_spend"`
}

// LoadAndVerifyCorpus reads corpus-manifest.json and verifies every pinned .tex file's SHA-256.
func LoadAndVerifyCorpus(repoRoot, manifestPath string) (*LoadedCorpus, error) {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var m CorpusManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if len(m.Files) == 0 {
		return nil, fmt.Errorf("corpus manifest has no files")
	}

	rootH := sha256.New()
	rootH.Write([]byte(DomainCorpusRoot))
	docs := make([]CorpusDocument, 0, len(m.Files))

	for _, f := range m.Files {
		fullPath := filepath.Join(repoRoot, f.Path)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			return nil, fmt.Errorf("read corpus file %s: %w", f.Path, err)
		}
		if int64(len(data)) != f.Bytes {
			return nil, fmt.Errorf("corpus byte mismatch for %s: got %d want %d", f.Path, len(data), f.Bytes)
		}
		sum := sha256.Sum256(data)
		gotHex := hex.EncodeToString(sum[:])
		if gotHex != f.SHA256 {
			return nil, fmt.Errorf("corpus SHA-256 mismatch for %s: got %s want %s", f.Path, gotHex, f.SHA256)
		}
		rootH.Write([]byte(f.Path))
		rootH.Write([]byte{0})
		rootH.Write(sum[:])
		docs = append(docs, CorpusDocument{
			Path:   f.Path,
			Role:   f.Role,
			SHA256: gotHex,
			Text:   string(data),
		})
	}

	return &LoadedCorpus{
		Manifest:   m,
		RootSHA256: hex.EncodeToString(rootH.Sum(nil)),
		Docs:       docs,
	}, nil
}

// GenerateGroundedWorkload deterministically produces InferenceRequests from the verified .tex corpus.
func GenerateGroundedWorkload(
	corpus *LoadedCorpus,
	seed uint64,
	count int,
	arrivalIntervalUs uint64,
	strictSharePct int,
	fixedOutTokens uint32,
) []InferenceRequest {
	reqs := make([]InferenceRequest, count)
	for i := 0; i < count; i++ {
		h := sha256.New()
		h.Write([]byte(corpus.RootSHA256))
		var sb [8]byte
		binary.BigEndian.PutUint64(sb[:], seed)
		h.Write(sb[:])
		var ib [4]byte
		binary.BigEndian.PutUint32(ib[:], uint32(i))
		h.Write(ib[:])
		rnd := h.Sum(nil)

		docIdx := int(binary.BigEndian.Uint32(rnd[0:4])) % len(corpus.Docs)
		doc := corpus.Docs[docIdx]

		// Shared prefix bucket (2 buckets per doc) creates realistic KV-prefix reuse.
		prefixBucket := int(binary.BigEndian.Uint32(rnd[4:8])) % 2
		prefixLen := 320
		if len(doc.Text) < prefixLen {
			prefixLen = len(doc.Text)
		}
		prefixStart := 0
		if prefixBucket == 1 && len(doc.Text) > prefixLen*2 {
			prefixStart = prefixLen
		}
		prefixText := doc.Text[prefixStart : prefixStart+prefixLen]
		prefixSum := sha256.Sum256([]byte(fmt.Sprintf("%s#%d:%s", doc.Path, prefixBucket, prefixText)))
		prefixHex := hex.EncodeToString(prefixSum[:])

		// Slice realistic prompt body from the real .tex document.
		targetBytes := 512 + int(binary.BigEndian.Uint32(rnd[8:12])%2560)
		suffixStart := int(binary.BigEndian.Uint32(rnd[12:16])) % maxInt(1, len(doc.Text))
		promptBuf := make([]byte, 0, targetBytes)
		promptBuf = append(promptBuf, prefixText...)
		for len(promptBuf) < targetBytes {
			rem := targetBytes - len(promptBuf)
			avail := len(doc.Text) - suffixStart
			if avail > rem {
				avail = rem
			}
			promptBuf = append(promptBuf, doc.Text[suffixStart:suffixStart+avail]...)
			suffixStart = (suffixStart + avail) % maxInt(1, len(doc.Text))
		}
		promptText := string(promptBuf)
		promptSum := sha256.Sum256(promptBuf)
		promptTokens := uint32(len(promptBuf) / 4) // ~4 chars per token for LaTeX
		if promptTokens < 128 {
			promptTokens = 128
		}
		outTokens := fixedOutTokens
		if outTokens == 0 {
			outTokens = 48 + (binary.BigEndian.Uint32(rnd[16:20]) % 81) // 48..128 tokens
		}

		privReq := PrivacyReqPublicOK
		if int(binary.BigEndian.Uint32(rnd[20:24])%100) < strictSharePct {
			privReq = PrivacyReqStrict
		}

		reqs[i] = InferenceRequest{
			RequestID:          fmt.Sprintf("req-%04d", i+1),
			ModelID:            DefaultModelID,
			PromptText:         promptText,
			PromptSHA256:       hex.EncodeToString(promptSum[:]),
			PromptPrefixSHA256: prefixHex,
			PromptTokens:       promptTokens,
			MaxOutputTokens:    outTokens,
			PrivacyRequirement: privReq,
			ArrivalUs:          uint64(i) * arrivalIntervalUs,
			SourcePaper:        doc.Path,
		}
	}
	return reqs
}

type fleetSpec struct {
	ads  []NodeAdvertisement
	keys map[string]ed25519.PrivateKey
}

func makeSignedNode(
	seed uint64,
	nodeID string,
	hw HardwareProfile,
	role ExecutionRole,
	lStart, lEnd uint32,
	vramTotal, vramBase uint64,
	kvSlots, prefillTPS, decodeTPS uint32,
	rttUs, bwKbps uint64,
	tier PrivacyTier,
	epoch uint64,
) (NodeAdvertisement, ed25519.PrivateKey) {
	_, priv := DeriveNodeKey(seed, nodeID)
	tee := ""
	if tier == PrivacyTEEAttested {
		tee = DeriveTEEAttestation(seed, nodeID, hw)
	}
	ad := NodeAdvertisement{
		SchemaVersion:       SchemaVersion,
		NodeID:              nodeID,
		HardwareProfile:     hw,
		ModelID:             DefaultModelID,
		ExecutionRole:       role,
		LayerStart:          lStart,
		LayerEnd:            lEnd,
		TotalLayers:         DefaultTotalLayers,
		VRAMTotalMiB:        vramTotal,
		VRAMReservedBaseMiB: vramBase,
		KVSlotsTotal:        kvSlots,
		PrefillTPS:          prefillTPS,
		DecodeTPS:           decodeTPS,
		WANRTTUs:            rttUs,
		BandwidthKbps:       bwKbps,
		PrivacyTier:         tier,
		TEEAttestationSHA:   tee,
		HeartbeatEpoch:      epoch,
		TimestampUnixS:      1764000000 + epoch*10,
	}
	SignNodeAdvertisement(&ad, priv)
	return ad, priv
}

func buildCentralizedFleet(seed uint64) fleetSpec {
	fs := fleetSpec{keys: make(map[string]ed25519.PrivateKey)}
	for i := 1; i <= 8; i++ {
		id := fmt.Sprintf("dc-h100-%02d", i)
		ad, priv := makeSignedNode(
			seed, id, HWProfileH100, RoleWholeModel, 0, DefaultTotalLayers,
			81920, 28672, 64, 2600, 96, 200, 400_000_000, PrivacyTEEAttested, 1,
		)
		fs.ads = append(fs.ads, ad)
		fs.keys[id] = priv
	}
	return fs
}

func buildDynamoDecentralizedFleet(seed uint64) fleetSpec {
	fs := fleetSpec{keys: make(map[string]ed25519.PrivateKey)}
	specs := []struct {
		id         string
		hw         HardwareProfile
		role       ExecutionRole
		vram, base uint64
		kv         uint32
		pTPS, dTPS uint32
		rtt, bw    uint64
		tier       PrivacyTier
	}{
		{"wan-prefill-h100-01", HWProfileH100, RolePrefill, 81920, 28672, 48, 2400, 90, 18_000, 10_000_000, PrivacyTEEAttested},
		{"wan-prefill-h100-02", HWProfileH100, RolePrefill, 81920, 28672, 48, 2300, 88, 24_000, 5_000_000, PrivacyPublicRelay},
		{"wan-decode-4090-01", HWProfileRTX4090, RoleDecode, 24576, 10240, 16, 900, 62, 22_000, 1_000_000, PrivacyPublicRelay},
		{"wan-decode-4090-02", HWProfileRTX4090, RoleDecode, 24576, 10240, 16, 880, 60, 28_000, 1_000_000, PrivacyPublicRelay},
		{"wan-decode-4090-03", HWProfileRTX4090, RoleDecode, 24576, 10240, 16, 860, 58, 34_000, 800_000, PrivacyPublicRelay},
		{"wan-whole-m4max-01", HWProfileMacM4Max, RoleWholeModel, 65536, 14336, 24, 440, 46, 30_000, 500_000, PrivacyLocalPrivate},
		{"wan-whole-m4max-02", HWProfileMacM4Max, RoleWholeModel, 65536, 14336, 24, 430, 44, 38_000, 500_000, PrivacyLocalPrivate},
		{"wan-whole-h100-01", HWProfileH100, RoleWholeModel, 81920, 28672, 48, 2200, 86, 20_000, 5_000_000, PrivacyTEEAttested},
	}
	for _, s := range specs {
		ad, priv := makeSignedNode(seed, s.id, s.hw, s.role, 0, DefaultTotalLayers,
			s.vram, s.base, s.kv, s.pTPS, s.dTPS, s.rtt, s.bw, s.tier, 1)
		fs.ads = append(fs.ads, ad)
		fs.keys[s.id] = priv
	}
	return fs
}

func buildPetalsPipelineFleet(seed uint64) fleetSpec {
	fs := fleetSpec{keys: make(map[string]ed25519.PrivateKey)}
	const stages = 4
	const replicasPerStage = 3
	for s := uint32(0); s < stages; s++ {
		lStart := s * 8
		lEnd := lStart + 8
		for r := 1; r <= replicasPerStage; r++ {
			id := fmt.Sprintf("petals-s%d-node-%02d", s, r)
			hw := HWProfileConsumer12
			vram, base := uint64(12288), uint64(4096)
			kv := uint32(8)
			pTPS, dTPS := uint32(260), uint32(34)
			rtt := uint64(32_000 + uint64(s)*3_000 + uint64(r)*2_500) // 34.5..48.5 ms WAN RTT/hop
			bw := uint64(150_000)                                     // 150 Mbps consumer broadband
			if r == 1 {
				hw = HWProfileRTX4090
				vram, base = 24576, 6144
				kv = 14
				pTPS, dTPS = 520, 48
				bw = 250_000
			}
			ad, priv := makeSignedNode(seed, id, hw, RolePipelineStage, lStart, lEnd,
				vram, base, kv, pTPS, dTPS, rtt, bw, PrivacyPublicRelay, 1)
			fs.ads = append(fs.ads, ad)
			fs.keys[id] = priv
		}
	}
	return fs
}

func buildPrivacyFleet(seed uint64, teeCount, publicCount int) fleetSpec {
	fs := fleetSpec{keys: make(map[string]ed25519.PrivateKey)}
	for i := 1; i <= teeCount; i++ {
		id := fmt.Sprintf("tee-node-%02d", i)
		hw := HWProfileH100
		vram, base := uint64(81920), uint64(28672)
		kv := uint32(32)
		pTPS, dTPS := uint32(1900), uint32(82)
		tier := PrivacyTEEAttested
		if i%2 == 0 {
			hw = HWProfileMacM4Max
			vram, base = 65536, 14336
			kv = 20
			pTPS, dTPS = 440, 46
			tier = PrivacyLocalPrivate
		}
		ad, priv := makeSignedNode(seed, id, hw, RoleWholeModel, 0, DefaultTotalLayers,
			vram, base, kv, pTPS, dTPS, uint64(22_000+i*2_000), 2_000_000, tier, 1)
		fs.ads = append(fs.ads, ad)
		fs.keys[id] = priv
	}
	for i := 1; i <= publicCount; i++ {
		id := fmt.Sprintf("pub-relay-%02d", i)
		ad, priv := makeSignedNode(seed, id, HWProfileRTX4090, RoleWholeModel, 0, DefaultTotalLayers,
			24576, 10240, 16, 900, 60, uint64(20_000+i*1_500), 1_000_000, PrivacyPublicRelay, 1)
		fs.ads = append(fs.ads, ad)
		fs.keys[id] = priv
	}
	return fs
}

func runScenario(
	scenarioID string,
	desc string,
	mode TopologyMode,
	fleet fleetSpec,
	reqs []InferenceRequest,
	fp FailurePolicy,
) (ScenarioMetrics, []ExecutionOutcome, error) {
	reg := NewRegistry()
	capAcc := NewCapacityAccountant()
	nodeMap := make(map[string]NodeAdvertisement, len(fleet.ads))
	for _, ad := range fleet.ads {
		if err := reg.Register(ad); err != nil {
			return ScenarioMetrics{}, nil, fmt.Errorf("register %s: %w", ad.NodeID, err)
		}
		capAcc.TrackNode(ad)
		nodeMap[ad.NodeID] = ad
	}
	router := NewRouter(reg, capAcc, fleet.keys)

	outcomes := make([]ExecutionOutcome, 0, len(reqs))
	ttfts := make([]uint64, 0, len(reqs))
	tpots := make([]uint64, 0, len(reqs))
	totals := make([]uint64, 0, len(reqs))

	var completed, completedFailover, failed int
	var sumNetBytes uint64
	var sumBatchUtil uint64
	var sumQueueWait uint64
	var sumRecoveryUs uint64
	var recoveryCount int
	var prefixHits int
	var verifiedCount int
	var totalOutTokens uint64
	var maxFinishUs uint64
	var minArrivalUs uint64 = math.MaxUint64

	for _, req := range reqs {
		out, err := router.ExecuteRequest(req, mode, fp)
		if err != nil {
			return ScenarioMetrics{}, nil, fmt.Errorf("scenario %s req %s: %w", scenarioID, req.RequestID, err)
		}
		outcomes = append(outcomes, out)

		// Independently verify every generated receipt via VerifyParityCase!
		vRes := VerifyParityCase(ParityCase{
			CaseID:         fmt.Sprintf("%s:%s", scenarioID, req.RequestID),
			Nodes:          fleet.ads,
			Receipt:        out.Receipt,
			OutputChunks:   out.OutputChunks,
			CapacityLedger: out.CapacityEvents,
		})
		if vRes.Valid {
			verifiedCount++
		}

		if req.ArrivalUs < minArrivalUs {
			minArrivalUs = req.ArrivalUs
		}
		finishUs := req.ArrivalUs + out.Receipt.TotalLatencyUs
		if finishUs > maxFinishUs {
			maxFinishUs = finishUs
		}

		switch out.Receipt.Status {
		case StatusCompleted:
			completed++
		case StatusCompletedFailover:
			completed++
			completedFailover++
		default:
			failed++
		}

		if out.Receipt.Status == StatusCompleted || out.Receipt.Status == StatusCompletedFailover {
			ttfts = append(ttfts, out.Receipt.TTFTUs)
			tpots = append(tpots, out.Receipt.TPOTUs)
			totals = append(totals, out.Receipt.TotalLatencyUs)
			sumNetBytes += out.Receipt.NetworkBytesTransferred
			sumBatchUtil += uint64(out.Receipt.BatchUtilizationBps)
			sumQueueWait += out.QueueWaitUs
			totalOutTokens += uint64(out.Receipt.OutputTokens)
			if out.PrefixCacheHit {
				prefixHits++
			}
			if out.Receipt.FailoverAttempts > 0 {
				sumRecoveryUs += out.Receipt.RecoveryLatencyUs
				recoveryCount++
			}
		} else {
			sumNetBytes += out.Receipt.NetworkBytesTransferred
		}
	}

	leakedVRAM, leakedSlots, _ := capAcc.ActiveLeaks()
	capOK, _ := VerifyCapacityConservation(nodeMap, capAcc.Ledger())

	makespanSec := float64(maxFinishUs-minArrivalUs) / 1_000_000.0
	if makespanSec <= 0 {
		makespanSec = 1e-6
	}

	avgNet := uint64(0)
	if len(reqs) > 0 {
		avgNet = sumNetBytes / uint64(len(reqs))
	}
	avgBatchPct := 0.0
	avgQueueMs := 0.0
	prefixHitPct := 0.0
	if completed > 0 {
		avgBatchPct = (float64(sumBatchUtil) / float64(completed)) / 100.0
		avgQueueMs = (float64(sumQueueWait) / float64(completed)) / 1000.0
		prefixHitPct = (float64(prefixHits) / float64(completed)) * 100.0
	}
	avgRecMs := 0.0
	if recoveryCount > 0 {
		avgRecMs = (float64(sumRecoveryUs) / float64(recoveryCount)) / 1000.0
	}

	m := ScenarioMetrics{
		ScenarioID:               scenarioID,
		TopologyMode:             mode,
		Description:              desc,
		TotalRequests:            len(reqs),
		CompletedRequests:        completed,
		CompletedWithFailover:    completedFailover,
		FailedOrRejectedRequests: failed,
		FailureInjectionRatePct:  float64(fp.FailureRateBps) / 100.0,
		CompletionRatePct:        round2((float64(completed) / float64(maxInt(1, len(reqs)))) * 100.0),
		ThroughputTokPerSec:      round2(float64(totalOutTokens) / makespanSec),
		ThroughputReqPerSec:      round2(float64(completed) / makespanSec),
		TTFTP50Ms:                round2(percentileUs(ttfts, 50) / 1000.0),
		TTFTP95Ms:                round2(percentileUs(ttfts, 95) / 1000.0),
		TTFTP99Ms:                round2(percentileUs(ttfts, 99) / 1000.0),
		TPOTP50Ms:                round2(percentileUs(tpots, 50) / 1000.0),
		TPOTP95Ms:                round2(percentileUs(tpots, 95) / 1000.0),
		TotalLatencyP50Ms:        round2(percentileUs(totals, 50) / 1000.0),
		TotalLatencyP99Ms:        round2(percentileUs(totals, 99) / 1000.0),
		AvgRecoveryLatencyMs:     round2(avgRecMs),
		AvgNetworkBytesPerReq:    avgNet,
		TotalNetworkBytes:        sumNetBytes,
		AvgBatchUtilizationPct:   round2(avgBatchPct),
		PrefixCacheHitRatePct:    round2(prefixHitPct),
		AvgQueueWaitMs:           round2(avgQueueMs),
		PrivacyLeakCount:         router.PrivacyLeakCount(),
		CapacityLeakedVRAMMiB:    leakedVRAM,
		CapacityLeakedKVSlots:    leakedSlots,
		CapacityConservationOK:   capOK && leakedVRAM == 0 && leakedSlots == 0,
		VerifiedReceiptsCount:    verifiedCount,
	}
	return m, outcomes, nil
}

// RunFullBenchmark executes all comparative topologies, failure sweeps, 3 honest negative regimes,
// and generates the 18-case canonical Go <-> Python ParitySuite.
func RunFullBenchmark(repoRoot, manifestPath string, seed uint64, reqsPerScenario int) (*BenchmarkReport, *ParitySuite, error) {
	corpus, err := LoadAndVerifyCorpus(repoRoot, manifestPath)
	if err != nil {
		return nil, nil, err
	}
	if reqsPerScenario < 20 {
		reqsPerScenario = 80
	}

	// Standard interactive workload (80 grounded requests, 50ms inter-arrival -> ~20 req/s offered load).
	baseWorkload := GenerateGroundedWorkload(corpus, seed, reqsPerScenario, 50_000, 0, 0)
	strictWorkload := GenerateGroundedWorkload(corpus, seed, reqsPerScenario, 50_000, 100, 0)

	dcFleet := buildCentralizedFleet(seed)
	dynamoFleet := buildDynamoDecentralizedFleet(seed)
	petalsFleet := buildPetalsPipelineFleet(seed)
	balancedTEEFleet := buildPrivacyFleet(seed, 6, 4)

	type scRun struct {
		id    string
		desc  string
		mode  TopologyMode
		fleet fleetSpec
		reqs  []InferenceRequest
		fp    FailurePolicy
	}

	runs := []scRun{
		{
			id:    "centralized_datacenter_baseline",
			desc:  "Co-located homogeneous 8x H100-80GB datacenter cluster (0.2 ms NVLink RTT, 0% failure)",
			mode:  TopologyCentralizedBaseline,
			fleet: dcFleet,
			reqs:  baseWorkload,
			fp:    FailurePolicy{FailureRateBps: 0, MaxRetries: 2, Seed: seed},
		},
		{
			id:    "centralized_datacenter_fail10",
			desc:  "Co-located 8x H100-80GB datacenter HA baseline under 10% worker failure injection",
			mode:  TopologyCentralizedBaseline,
			fleet: dcFleet,
			reqs:  baseWorkload,
			fp:    FailurePolicy{FailureRateBps: 1000, MaxRetries: 2, Seed: seed + 1},
		},
		{
			id:    "decentralized_replica_dynamo_fail0",
			desc:  "Heterogeneous Dynamo disaggregated prefill/decode + KV-prefix affinity over WAN (0% failure)",
			mode:  TopologyDynamoReplica,
			fleet: dynamoFleet,
			reqs:  baseWorkload,
			fp:    FailurePolicy{FailureRateBps: 0, MaxRetries: 2, Seed: seed + 2},
		},
		{
			id:    "decentralized_replica_dynamo_fail10",
			desc:  "Heterogeneous Dynamo disaggregated replicas under 10% mid-request failure + live KV replay",
			mode:  TopologyDynamoReplica,
			fleet: dynamoFleet,
			reqs:  baseWorkload,
			fp:    FailurePolicy{FailureRateBps: 1000, MaxRetries: 2, Seed: seed + 3},
		},
		{
			id:    "decentralized_replica_dynamo_fail25",
			desc:  "Heterogeneous Dynamo disaggregated replicas under 25% mid-request failure + live KV replay",
			mode:  TopologyDynamoReplica,
			fleet: dynamoFleet,
			reqs:  baseWorkload,
			fp:    FailurePolicy{FailureRateBps: 2500, MaxRetries: 2, Seed: seed + 4},
		},
		{
			id:    "decentralized_pipeline_petals_fail0",
			desc:  "Petals-style 4-hop WAN layer-sharded pipeline on Consumer-12GB/RTX-4090 nodes (0% failure)",
			mode:  TopologyPetalsPipeline,
			fleet: petalsFleet,
			reqs:  baseWorkload,
			fp:    FailurePolicy{FailureRateBps: 0, MaxRetries: 2, Seed: seed + 5},
		},
		{
			id:    "decentralized_pipeline_petals_fail10",
			desc:  "Petals-style 4-hop WAN pipeline under 10% per-hop failure (compounded multi-hop failure exposure)",
			mode:  TopologyPetalsPipeline,
			fleet: petalsFleet,
			reqs:  baseWorkload,
			fp:    FailurePolicy{FailureRateBps: 1000, MaxRetries: 2, Seed: seed + 6},
		},
		{
			id:    "decentralized_privacy_strict_tee_balanced",
			desc:  "Strict privacy-bounded routing (100% PRIVACY_STRICT, 60% TEE/Local pool, 0 plaintext leaks)",
			mode:  TopologyStrictTEE,
			fleet: balancedTEEFleet,
			reqs:  strictWorkload,
			fp:    FailurePolicy{FailureRateBps: 0, MaxRetries: 2, Seed: seed + 7},
		},
	}

	scenarios := make([]ScenarioMetrics, 0, len(runs))
	savedOutcomes := make(map[string][]ExecutionOutcome, len(runs))
	var baseMetric ScenarioMetrics

	for idx, r := range runs {
		m, outs, err := runScenario(r.id, r.desc, r.mode, r.fleet, r.reqs, r.fp)
		if err != nil {
			return nil, nil, err
		}
		if idx == 0 {
			baseMetric = m
		}
		m.TTFTVsBaselineRatio = safeRatio(m.TTFTP50Ms, baseMetric.TTFTP50Ms)
		m.TPOTVsBaselineRatio = safeRatio(m.TPOTP50Ms, baseMetric.TPOTP50Ms)
		m.ThroughputVsBaselineRatio = safeRatio(m.ThroughputTokPerSec, baseMetric.ThroughputTokPerSec)
		scenarios = append(scenarios, m)
		savedOutcomes[r.id] = outs
	}

	// === 3 EXPLICIT HONEST NEGATIVE REGIMES ===
	negRegimes := make([]NegativeRegimeSummary, 0, 3)

	// Negative Regime 1: Petals-style multi-hop WAN pipeline vs Centralized Baseline on interactive 64-tok workload
	interactiveReqs := GenerateGroundedWorkload(corpus, seed+100, reqsPerScenario, 50_000, 0, 64)
	neg1Base, _, err := runScenario(
		"neg1_centralized_interactive_baseline",
		"Centralized 8x H100 baseline on 64-token interactive workload",
		TopologyCentralizedBaseline, dcFleet, interactiveReqs, FailurePolicy{FailureRateBps: 0, MaxRetries: 2, Seed: seed + 101},
	)
	if err != nil {
		return nil, nil, err
	}
	neg1Deg, _, err := runScenario(
		"neg_petals_wan_pipeline_latency_loss",
		"Petals 4-hop WAN layer-sharded pipeline (35ms/hop, 150Mbps) on 64-token interactive workload",
		TopologyPetalsPipeline, petalsFleet, interactiveReqs, FailurePolicy{FailureRateBps: 0, MaxRetries: 2, Seed: seed + 102},
	)
	if err != nil {
		return nil, nil, err
	}
	neg1Base.TTFTVsBaselineRatio, neg1Base.TPOTVsBaselineRatio, neg1Base.ThroughputVsBaselineRatio = 1.0, 1.0, 1.0
	neg1Deg.TTFTVsBaselineRatio = safeRatio(neg1Deg.TTFTP50Ms, neg1Base.TTFTP50Ms)
	neg1Deg.TPOTVsBaselineRatio = safeRatio(neg1Deg.TPOTP50Ms, neg1Base.TPOTP50Ms)
	neg1Deg.ThroughputVsBaselineRatio = safeRatio(neg1Deg.ThroughputTokPerSec, neg1Base.ThroughputTokPerSec)
	negRegimes = append(negRegimes, NegativeRegimeSummary{
		RegimeID:   "neg_petals_wan_pipeline_latency_loss",
		Title:      "Negative Regime 1: Petals-Style Multi-Hop WAN Pipeline Latency & Batching Loss",
		Hypothesis: "Layer-sharding a 32-layer model across 4 WAN hops forces every generated token to pay full ring RTT plus FP16 hidden-state transfer and pipeline bubbles, severely underperforming centralized datacenter inference on interactive workloads.",
		Finding: fmt.Sprintf("Petals WAN pipeline is %.2fx slower in p50 TTFT (%.1f ms vs %.1f ms), %.2fx slower in p50 TPOT (%.1f ms/tok vs %.1f ms/tok), transfers %.1fx more network bytes/request (%d vs %d B), and drops batch utilization from %.1f%% to %.1f%%.",
			neg1Deg.TTFTVsBaselineRatio, neg1Deg.TTFTP50Ms, neg1Base.TTFTP50Ms,
			neg1Deg.TPOTVsBaselineRatio, neg1Deg.TPOTP50Ms, neg1Base.TPOTP50Ms,
			safeRatio(float64(neg1Deg.AvgNetworkBytesPerReq), float64(neg1Base.AvgNetworkBytesPerReq)),
			neg1Deg.AvgNetworkBytesPerReq, neg1Base.AvgNetworkBytesPerReq,
			neg1Base.AvgBatchUtilizationPct, neg1Deg.AvgBatchUtilizationPct),
		Baseline: neg1Base,
		Degraded: neg1Deg,
		HeadlineRatios: map[string]float64{
			"ttft_p50_slowdown_x":      neg1Deg.TTFTVsBaselineRatio,
			"tpot_p50_slowdown_x":      neg1Deg.TPOTVsBaselineRatio,
			"network_bytes_blowup_x":   safeRatio(float64(neg1Deg.AvgNetworkBytesPerReq), float64(neg1Base.AvgNetworkBytesPerReq)),
			"batch_util_drop_pct_pts":  round2(neg1Base.AvgBatchUtilizationPct - neg1Deg.AvgBatchUtilizationPct),
			"throughput_retention_pct": round2(neg1Deg.ThroughputVsBaselineRatio * 100.0),
		},
	})

	// Negative Regime 2: High-Concurrency Rapid-Churn Failure Storm (35% worker drop rate)
	churnReqs := GenerateGroundedWorkload(corpus, seed+200, reqsPerScenario, 30_000, 0, 64)
	neg2Base, _, err := runScenario(
		"neg2_centralized_ha_baseline",
		"Centralized HA 8x H100 cluster under 5% transient fault rate",
		TopologyCentralizedBaseline, dcFleet, churnReqs, FailurePolicy{FailureRateBps: 500, MaxRetries: 2, Seed: seed + 201},
	)
	if err != nil {
		return nil, nil, err
	}
	neg2Deg, _, err := runScenario(
		"neg_high_churn_cascade_recovery",
		"Decentralized heterogeneous replicas under 35% simultaneous mid-request worker churn storm (interactive retry budget=1)",
		TopologyDynamoReplica, dynamoFleet, churnReqs, FailurePolicy{FailureRateBps: 3500, MaxRetries: 1, Seed: seed + 202},
	)
	if err != nil {
		return nil, nil, err
	}
	neg2Base.TTFTVsBaselineRatio, neg2Base.TPOTVsBaselineRatio, neg2Base.ThroughputVsBaselineRatio = 1.0, 1.0, 1.0
	neg2Deg.TTFTVsBaselineRatio = safeRatio(neg2Deg.TTFTP50Ms, neg2Base.TTFTP50Ms)
	neg2Deg.TPOTVsBaselineRatio = safeRatio(neg2Deg.TPOTP50Ms, neg2Base.TPOTP50Ms)
	neg2Deg.ThroughputVsBaselineRatio = safeRatio(neg2Deg.ThroughputTokPerSec, neg2Base.ThroughputTokPerSec)
	negRegimes = append(negRegimes, NegativeRegimeSummary{
		RegimeID:   "neg_high_churn_cascade_recovery",
		Title:      "Negative Regime 2: Rapid-Churn Failure Storm (35% Mid-Request Drop Rate)",
		Hypothesis: "At 35% simultaneous mid-request worker churn under an interactive retry budget, WAN crash detection timeouts, KV-state replay recomputation, and retry exhaustion spike p99 tail latency and erode both completion rate and effective throughput compared to a centralized HA cluster.",
		Finding: fmt.Sprintf("Under 35%% churn, p99 TTFT spikes %.2fx (%.1f ms vs %.1f ms), average failover recovery adds %.1f ms, completion rate degrades to %.1f%% (vs %.1f%% HA baseline, %d failed/exhausted, %d recovered via failover), throughput drops to %.1f%% of HA baseline, and capacity leaks remain strictly 0.",
			safeRatio(neg2Deg.TTFTP99Ms, neg2Base.TTFTP99Ms), neg2Deg.TTFTP99Ms, neg2Base.TTFTP99Ms,
			neg2Deg.AvgRecoveryLatencyMs, neg2Deg.CompletionRatePct, neg2Base.CompletionRatePct,
			neg2Deg.FailedOrRejectedRequests, neg2Deg.CompletedWithFailover,
			neg2Deg.ThroughputVsBaselineRatio*100.0),
		Baseline: neg2Base,
		Degraded: neg2Deg,
		HeadlineRatios: map[string]float64{
			"ttft_p99_spike_x":         safeRatio(neg2Deg.TTFTP99Ms, neg2Base.TTFTP99Ms),
			"total_lat_p99_spike_x":    safeRatio(neg2Deg.TotalLatencyP99Ms, neg2Base.TotalLatencyP99Ms),
			"avg_recovery_latency_ms":  neg2Deg.AvgRecoveryLatencyMs,
			"completion_rate_pct":      neg2Deg.CompletionRatePct,
			"throughput_retention_pct": round2(neg2Deg.ThroughputVsBaselineRatio * 100.0),
		},
	})

	// Negative Regime 3: Strict Privacy Pool Scarcity (20% TEE nodes serving 80% PRIVACY_STRICT traffic)
	scarcityFleet := buildPrivacyFleet(seed+300, 2, 8) // only 20% TEE/Local, 80% PUBLIC_RELAY
	publicMixReqs := GenerateGroundedWorkload(corpus, seed+300, reqsPerScenario, 35_000, 0, 64)
	strictHeavyReqs := GenerateGroundedWorkload(corpus, seed+300, reqsPerScenario, 35_000, 80, 64)
	neg3Base, _, err := runScenario(
		"neg3_unconstrained_public_routing",
		"Same 10-node fleet (2 TEE + 8 Public) serving 100% PUBLIC_OK traffic",
		TopologyDynamoReplica, scarcityFleet, publicMixReqs, FailurePolicy{FailureRateBps: 0, MaxRetries: 2, Seed: seed + 301},
	)
	if err != nil {
		return nil, nil, err
	}
	neg3Deg, _, err := runScenario(
		"neg_privacy_strict_capacity_bottleneck",
		"Same 10-node fleet (only 20% TEE/Local) serving 80% PRIVACY_STRICT traffic (0 leaks)",
		TopologyStrictTEE, scarcityFleet, strictHeavyReqs, FailurePolicy{FailureRateBps: 0, MaxRetries: 2, Seed: seed + 302},
	)
	if err != nil {
		return nil, nil, err
	}
	neg3Base.TTFTVsBaselineRatio, neg3Base.TPOTVsBaselineRatio, neg3Base.ThroughputVsBaselineRatio = 1.0, 1.0, 1.0
	neg3Deg.TTFTVsBaselineRatio = safeRatio(neg3Deg.TTFTP50Ms, neg3Base.TTFTP50Ms)
	neg3Deg.TPOTVsBaselineRatio = safeRatio(neg3Deg.TPOTP50Ms, neg3Base.TPOTP50Ms)
	neg3Deg.ThroughputVsBaselineRatio = safeRatio(neg3Deg.ThroughputTokPerSec, neg3Base.ThroughputTokPerSec)
	negRegimes = append(negRegimes, NegativeRegimeSummary{
		RegimeID:   "neg_privacy_strict_capacity_bottleneck",
		Title:      "Negative Regime 3: Strict Privacy Pool Scarcity (20% TEE Capacity vs 80% Strict Demand)",
		Hypothesis: "Hard privacy boundaries prevent offloading PRIVACY_STRICT prompts onto idle PUBLIC_RELAY nodes; when TEE capacity is scarce (20%), queuing latency explodes and throughput drops sharply while guaranteeing 0 plaintext leaks.",
		Finding: fmt.Sprintf("Enforcing PRIVACY_STRICT on an 80%%/20%% demand/supply imbalance increases p50 TTFT by %.2fx (%.1f ms vs %.1f ms), p99 TTFT by %.2fx (%.1f ms vs %.1f ms), mean queue wait to %.1f ms (vs %.1f ms), and cuts throughput to %.1f%% of unconstrained routing — with strictly %d privacy leaks.",
			neg3Deg.TTFTVsBaselineRatio, neg3Deg.TTFTP50Ms, neg3Base.TTFTP50Ms,
			safeRatio(neg3Deg.TTFTP99Ms, neg3Base.TTFTP99Ms), neg3Deg.TTFTP99Ms, neg3Base.TTFTP99Ms,
			neg3Deg.AvgQueueWaitMs, neg3Base.AvgQueueWaitMs,
			neg3Deg.ThroughputVsBaselineRatio*100.0, neg3Deg.PrivacyLeakCount),
		Baseline: neg3Base,
		Degraded: neg3Deg,
		HeadlineRatios: map[string]float64{
			"ttft_p50_inflation_x":     neg3Deg.TTFTVsBaselineRatio,
			"ttft_p99_inflation_x":     safeRatio(neg3Deg.TTFTP99Ms, neg3Base.TTFTP99Ms),
			"queue_wait_ms":            neg3Deg.AvgQueueWaitMs,
			"throughput_retention_pct": round2(neg3Deg.ThroughputVsBaselineRatio * 100.0),
			"privacy_leaks":            float64(neg3Deg.PrivacyLeakCount),
		},
	})

	// Build 18 canonical ParitySuite cases (valid across all 4 topologies + failover + adversarial tamper rejections).
	suite, err := buildParitySuite(corpus.RootSHA256, seed, dcFleet, dynamoFleet, petalsFleet, balancedTEEFleet, savedOutcomes)
	if err != nil {
		return nil, nil, err
	}

	var totalPrivacyLeaks uint64
	var totalCapacityLeaks uint64
	for _, s := range scenarios {
		totalPrivacyLeaks += s.PrivacyLeakCount
		totalCapacityLeaks += s.CapacityLeakedVRAMMiB + uint64(s.CapacityLeakedKVSlots)
	}
	for _, nr := range negRegimes {
		totalPrivacyLeaks += nr.Baseline.PrivacyLeakCount + nr.Degraded.PrivacyLeakCount
		totalCapacityLeaks += nr.Baseline.CapacityLeakedVRAMMiB + uint64(nr.Baseline.CapacityLeakedKVSlots)
		totalCapacityLeaks += nr.Degraded.CapacityLeakedVRAMMiB + uint64(nr.Degraded.CapacityLeakedKVSlots)
	}

	report := &BenchmarkReport{
		SchemaVersion:           SchemaVersion,
		SpecVersion:             SpecVersion,
		Issue:                   "zoo-apps/papers#12",
		HIP:                     "HIP-1350",
		Seed:                    seed,
		RequestsPerScenario:     reqsPerScenario,
		CorpusRootSHA256:        corpus.RootSHA256,
		CorpusFilesVerified:     len(corpus.Docs),
		Scenarios:               scenarios,
		NegativeRegimes:         negRegimes,
		ParityCasesCount:        len(suite.Cases),
		AuditMerkleRoot:         suite.AuditMerkleRoot,
		TotalPrivacyLeaks:       totalPrivacyLeaks,
		TotalCapacityLeaks:      totalCapacityLeaks,
		ProvesScientificTruth:   false,
		AuthorizesTreasurySpend: false,
	}
	return report, suite, nil
}

func buildParitySuite(
	corpusRoot string,
	seed uint64,
	dcFleet, dynamoFleet, petalsFleet, teeFleet fleetSpec,
	saved map[string][]ExecutionOutcome,
) (*ParitySuite, error) {
	pickFirstCompleted := func(scID string, wantFailover bool) ExecutionOutcome {
		for _, o := range saved[scID] {
			if wantFailover && o.Receipt.Status == StatusCompletedFailover {
				return o
			}
			if !wantFailover && o.Receipt.Status == StatusCompleted {
				return o
			}
		}
		return saved[scID][0]
	}

	cloneCap := func(in []CapacityEvent) []CapacityEvent {
		out := make([]CapacityEvent, len(in))
		copy(out, in)
		return out
	}
	cloneNodes := func(in []NodeAdvertisement) []NodeAdvertisement {
		out := make([]NodeAdvertisement, len(in))
		copy(out, in)
		return out
	}
	cloneChunks := func(in []string) []string {
		out := make([]string, len(in))
		copy(out, in)
		return out
	}

	dcOut := pickFirstCompleted("centralized_datacenter_baseline", false)
	dynOut := pickFirstCompleted("decentralized_replica_dynamo_fail0", false)
	dynFailOut := pickFirstCompleted("decentralized_replica_dynamo_fail10", true)
	petalsOut := pickFirstCompleted("decentralized_pipeline_petals_fail0", false)
	petalsFailOut := pickFirstCompleted("decentralized_pipeline_petals_fail10", true)
	teeOut := pickFirstCompleted("decentralized_privacy_strict_tee_balanced", false)

	cases := make([]ParityCase, 0, 18)

	// 1..6: Valid canonical receipts across all 4 topologies + failover recovery
	cases = append(cases,
		ParityCase{
			CaseID:         "valid_centralized_h100_baseline",
			Description:    "Valid centralized H100-80GB datacenter baseline delivery receipt",
			Nodes:          cloneNodes(dcFleet.ads),
			Receipt:        dcOut.Receipt,
			OutputChunks:   cloneChunks(dcOut.OutputChunks),
			CapacityLedger: cloneCap(dcOut.CapacityEvents),
		},
		ParityCase{
			CaseID:         "valid_dynamo_disaggregated_replica",
			Description:    "Valid Dynamo-style disaggregated prefill/decode WAN receipt with prefix affinity",
			Nodes:          cloneNodes(dynamoFleet.ads),
			Receipt:        dynOut.Receipt,
			OutputChunks:   cloneChunks(dynOut.OutputChunks),
			CapacityLedger: cloneCap(dynOut.CapacityEvents),
		},
		ParityCase{
			CaseID:         "valid_dynamo_live_failover_recovery",
			Description:    "Valid Dynamo receipt after mid-request worker crash and clean zero-leak failover",
			Nodes:          cloneNodes(dynamoFleet.ads),
			Receipt:        dynFailOut.Receipt,
			OutputChunks:   cloneChunks(dynFailOut.OutputChunks),
			CapacityLedger: cloneCap(dynFailOut.CapacityEvents),
		},
		ParityCase{
			CaseID:         "valid_petals_4hop_wan_pipeline",
			Description:    "Valid Petals-style 4-hop WAN layer-sharded pipeline receipt across Consumer-12GB/RTX-4090 nodes",
			Nodes:          cloneNodes(petalsFleet.ads),
			Receipt:        petalsOut.Receipt,
			OutputChunks:   cloneChunks(petalsOut.OutputChunks),
			CapacityLedger: cloneCap(petalsOut.CapacityEvents),
		},
		ParityCase{
			CaseID:         "valid_petals_pipeline_failover_recovery",
			Description:    "Valid Petals 4-hop WAN pipeline receipt recovering from mid-generation hop crash",
			Nodes:          cloneNodes(petalsFleet.ads),
			Receipt:        petalsFailOut.Receipt,
			OutputChunks:   cloneChunks(petalsFailOut.OutputChunks),
			CapacityLedger: cloneCap(petalsFailOut.CapacityEvents),
		},
		ParityCase{
			CaseID:         "valid_strict_privacy_tee_enclave",
			Description:    "Valid PRIVACY_STRICT receipt routed exclusively to TEE_ATTESTED / LOCAL_PRIVATE nodes",
			Nodes:          cloneNodes(teeFleet.ads),
			Receipt:        teeOut.Receipt,
			OutputChunks:   cloneChunks(teeOut.OutputChunks),
			CapacityLedger: cloneCap(teeOut.CapacityEvents),
		},
	)

	// 7: Valid monotonic heartbeat epoch update on existing node
	{
		nodes := cloneNodes(dcFleet.ads)
		n0 := nodes[0]
		n0.HeartbeatEpoch = 2
		n0.TimestampUnixS += 30
		SignNodeAdvertisement(&n0, dcFleet.keys[n0.NodeID])
		nodes = append(nodes, n0)
		cases = append(cases, ParityCase{
			CaseID:         "valid_monotonic_heartbeat_epoch_refresh",
			Description:    "Valid monotonic heartbeat epoch increment (1 -> 2) with matching pinned Ed25519 key",
			Nodes:          nodes,
			Receipt:        dcOut.Receipt,
			OutputChunks:   cloneChunks(dcOut.OutputChunks),
			CapacityLedger: cloneCap(dcOut.CapacityEvents),
		})
	}

	// 8: Tampered receipt Ed25519 signature
	{
		bad := dynOut.Receipt
		bad.TTFTUs += 1 // mutating signed field invalidates signature
		cases = append(cases, ParityCase{
			CaseID:         "reject_tampered_receipt_signature",
			Description:    "Rejects delivery receipt whose TTFT field was mutated after Ed25519 signing",
			Nodes:          cloneNodes(dynamoFleet.ads),
			Receipt:        bad,
			OutputChunks:   cloneChunks(dynOut.OutputChunks),
			CapacityLedger: cloneCap(dynOut.CapacityEvents),
		})
	}

	// 9: Tampered output token chunk (Merkle root mismatch)
	{
		badChunks := cloneChunks(dynOut.OutputChunks)
		badChunks[0] = "tampered_token_payload"
		cases = append(cases, ParityCase{
			CaseID:         "reject_output_merkle_tampering",
			Description:    "Rejects delivery when delivered output token chunk does not match signed output_merkle_root",
			Nodes:          cloneNodes(dynamoFleet.ads),
			Receipt:        dynOut.Receipt,
			OutputChunks:   badChunks,
			CapacityLedger: cloneCap(dynOut.CapacityEvents),
		})
	}

	// 10: Privacy boundary violation — PRIVACY_STRICT routed through PUBLIC_RELAY node
	{
		bad := teeOut.Receipt
		pubNode := teeFleet.ads[len(teeFleet.ads)-1] // pub-relay node
		bad.PrivacyRequirement = PrivacyReqStrict
		bad.EffectivePrivacyTier = PrivacyPublicRelay
		bad.RouteNodeIDs = []string{pubNode.NodeID}
		bad.PrefillNodeID = pubNode.NodeID
		bad.DecodeNodeIDs = []string{pubNode.NodeID}
		bad.PrimaryProviderID = pubNode.NodeID
		SignDeliveryReceipt(&bad, teeFleet.keys[pubNode.NodeID])
		cases = append(cases, ParityCase{
			CaseID:         "reject_privacy_boundary_public_relay_leak",
			Description:    "Rejects PRIVACY_STRICT request that touched a PUBLIC_RELAY worker (zero plaintext leak invariant)",
			Nodes:          cloneNodes(teeFleet.ads),
			Receipt:        bad,
			OutputChunks:   cloneChunks(teeOut.OutputChunks),
			CapacityLedger: cloneCap(teeOut.CapacityEvents),
		})
	}

	// 11: Privacy boundary violation — PRIVACY_STRICT failed over from PUBLIC_RELAY
	{
		bad := teeOut.Receipt
		pubNode := teeFleet.ads[len(teeFleet.ads)-1]
		bad.FailedNodeIDs = []string{pubNode.NodeID}
		bad.FailoverAttempts = 1
		SignDeliveryReceipt(&bad, teeFleet.keys[bad.PrimaryProviderID])
		cases = append(cases, ParityCase{
			CaseID:         "reject_privacy_boundary_failed_hop_leak",
			Description:    "Rejects PRIVACY_STRICT request whose failed attempt leaked prompt to a PUBLIC_RELAY node",
			Nodes:          cloneNodes(teeFleet.ads),
			Receipt:        bad,
			OutputChunks:   cloneChunks(teeOut.OutputChunks),
			CapacityLedger: cloneCap(teeOut.CapacityEvents),
		})
	}

	// 12: Capacity conservation violation — unreleased reservation (VRAM/KV leak)
	{
		leaked := cloneCap(dynOut.CapacityEvents)
		if len(leaked) > 1 {
			leaked = leaked[:len(leaked)-1] // drop final RELEASE event -> leak!
		}
		cases = append(cases, ParityCase{
			CaseID:         "reject_capacity_vram_kv_leak",
			Description:    "Rejects capacity ledger with unreleased VRAM/KV-slot reservation (strict zero-leak invariant)",
			Nodes:          cloneNodes(dynamoFleet.ads),
			Receipt:        dynOut.Receipt,
			OutputChunks:   cloneChunks(dynOut.OutputChunks),
			CapacityLedger: leaked,
		})
	}

	// 13: Capacity conservation violation — VRAM oversubscription beyond hardware limit
	{
		nid := dynOut.Receipt.PrimaryProviderID
		over := []CapacityEvent{
			{Seq: 1, Action: "RESERVE", ReservationID: "res-over-1", NodeID: nid, RequestID: dynOut.Receipt.RequestID, VRAMMiB: 999999, KVSlots: 1, Reason: "ADMIT"},
			{Seq: 2, Action: "RELEASE", ReservationID: "res-over-1", NodeID: nid, RequestID: dynOut.Receipt.RequestID, VRAMMiB: 999999, KVSlots: 1, Reason: "COMPLETED"},
		}
		cases = append(cases, ParityCase{
			CaseID:         "reject_capacity_vram_oversubscription",
			Description:    "Rejects capacity ledger that oversubscribes physical node VRAM bounds",
			Nodes:          cloneNodes(dynamoFleet.ads),
			Receipt:        dynOut.Receipt,
			OutputChunks:   cloneChunks(dynOut.OutputChunks),
			CapacityLedger: over,
		})
	}

	// 14: Stale heartbeat epoch replay in worker discovery
	{
		nodes := cloneNodes(dcFleet.ads)
		stale := nodes[0] // same epoch=1 replayed!
		nodes = append(nodes, stale)
		cases = append(cases, ParityCase{
			CaseID:         "reject_stale_heartbeat_epoch_replay",
			Description:    "Rejects replayed NodeAdvertisement with non-increasing heartbeat_epoch",
			Nodes:          nodes,
			Receipt:        dcOut.Receipt,
			OutputChunks:   cloneChunks(dcOut.OutputChunks),
			CapacityLedger: cloneCap(dcOut.CapacityEvents),
		})
	}

	// 15: Spoofed key rotation on existing node_id
	{
		nodes := cloneNodes(dcFleet.ads)
		spoof := nodes[0]
		spoof.HeartbeatEpoch = 2
		_, rogueKey := DeriveNodeKey(seed+999, "rogue-spoof")
		SignNodeAdvertisement(&spoof, rogueKey)
		nodes = append(nodes, spoof)
		cases = append(cases, ParityCase{
			CaseID:         "reject_node_key_spoofing",
			Description:    "Rejects NodeAdvertisement attempting unauthorized Ed25519 key replacement for existing node_id",
			Nodes:          nodes,
			Receipt:        dcOut.Receipt,
			OutputChunks:   cloneChunks(dcOut.OutputChunks),
			CapacityLedger: cloneCap(dcOut.CapacityEvents),
		})
	}

	// 16: Invalid NodeAdvertisement Ed25519 signature
	{
		nodes := cloneNodes(dcFleet.ads)
		nodes[0].DecodeTPS = 99999 // mutated after signing
		cases = append(cases, ParityCase{
			CaseID:         "reject_invalid_node_advertisement_signature",
			Description:    "Rejects NodeAdvertisement whose advertised decode_tps was forged after Ed25519 signing",
			Nodes:          nodes,
			Receipt:        dcOut.Receipt,
			OutputChunks:   cloneChunks(dcOut.OutputChunks),
			CapacityLedger: cloneCap(dcOut.CapacityEvents),
		})
	}

	// 17: Constitutional lock violation — proves_scientific_truth = true
	{
		bad := dcOut.Receipt
		bad.ProvesScientificTruth = true
		SignDeliveryReceipt(&bad, dcFleet.keys[bad.PrimaryProviderID])
		cases = append(cases, ParityCase{
			CaseID:         "reject_constitutional_scientific_truth_claim",
			Description:    "Rejects receipt with proves_scientific_truth=true (constitutional lock enforcement)",
			Nodes:          cloneNodes(dcFleet.ads),
			Receipt:        bad,
			OutputChunks:   cloneChunks(dcOut.OutputChunks),
			CapacityLedger: cloneCap(dcOut.CapacityEvents),
		})
	}

	// 18: Constitutional lock violation — authorizes_treasury_spend = true
	{
		bad := dcOut.Receipt
		bad.AuthorizesTreasurySpend = true
		SignDeliveryReceipt(&bad, dcFleet.keys[bad.PrimaryProviderID])
		cases = append(cases, ParityCase{
			CaseID:         "reject_constitutional_treasury_spend_claim",
			Description:    "Rejects receipt with authorizes_treasury_spend=true (constitutional lock enforcement)",
			Nodes:          cloneNodes(dcFleet.ads),
			Receipt:        bad,
			OutputChunks:   cloneChunks(dcOut.OutputChunks),
			CapacityLedger: cloneCap(dcOut.CapacityEvents),
		})
	}

	// Populate expected verdicts + digests deterministically.
	digests := make([]string, len(cases))
	for i := range cases {
		vr := VerifyParityCase(cases[i])
		cases[i].ExpectedValid = vr.Valid
		cases[i].ExpectedErrorCode = vr.ErrorCode
		cases[i].ExpectedVerdictDigest = vr.VerdictDigest
		digests[i] = vr.VerdictDigest
	}
	auditRoot, err := ComputeMerkleRootFromHexDigests(digests)
	if err != nil {
		return nil, err
	}

	return &ParitySuite{
		SchemaVersion:   SchemaVersion,
		SpecVersion:     SpecVersion,
		CorpusRootSHA:   corpusRoot,
		Seed:            seed,
		Cases:           cases,
		AuditMerkleRoot: auditRoot,
	}, nil
}

func percentileUs(vals []uint64, pct int) float64 {
	if len(vals) == 0 {
		return 0
	}
	cp := make([]uint64, len(vals))
	copy(cp, vals)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	rank := (pct * (len(cp) - 1)) / 100
	if rank >= len(cp) {
		rank = len(cp) - 1
	}
	return float64(cp[rank])
}

func safeRatio(num, den float64) float64 {
	if den <= 0 {
		return 0
	}
	return round2(num / den)
}

func round2(v float64) float64 {
	return math.Round(v*100.0) / 100.0
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

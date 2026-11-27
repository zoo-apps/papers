// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package agentid

import (
	"fmt"
	"math/rand"
	"sort"
	"time"
)

// DepthBenchRow records measured Go offline verification latency for a delegation chain depth.
type DepthBenchRow struct {
	Depth               int     `json:"depth"`
	Iterations          int     `json:"iterations"`
	WarmMeanUS          float64 `json:"warm_mean_us"`
	WarmP50US           float64 `json:"warm_p50_us"`
	WarmP95US           float64 `json:"warm_p95_us"`
	WarmOpsPerSec       float64 `json:"warm_ops_per_sec"`
	ColdMeanUS          float64 `json:"cold_mean_us"`
	ColdP50US           float64 `json:"cold_p50_us"`
	ColdP95US           float64 `json:"cold_p95_us"`
	ColdOpsPerSec       float64 `json:"cold_ops_per_sec"`
	WarmSigChecks       int     `json:"warm_sig_checks"`
	ColdSigChecks       int     `json:"cold_sig_checks"`
	WarmScalingVsDepth1 float64 `json:"warm_scaling_vs_depth1"`
}

// BitstringBenchRow records measured W3C BitstringStatusList sizes and offline verify latencies.
type BitstringBenchRow struct {
	BitLength        int     `json:"bit_length"`
	RawBytes         int     `json:"raw_bytes"`
	DensityLabel     string  `json:"density_label"`
	RevokedCount     int     `json:"revoked_count"`
	GzipBase64Bytes  int     `json:"gzip_base64_bytes"`
	RawBase64Bytes   int     `json:"raw_base64_bytes"`
	CompressionRatio float64 `json:"compression_ratio"`
	ColdVerifyMeanUS float64 `json:"cold_verify_mean_us"`
	WarmLookupMeanUS float64 `json:"warm_lookup_mean_us"`
}

// StalenessTradeoffRow quantifies the offline revocation freshness vs bandwidth negative regime.
type StalenessTradeoffRow struct {
	SyncIntervalSeconds int64   `json:"sync_interval_seconds"`
	MaxStalenessSeconds int64   `json:"max_staleness_seconds"`
	SparseBandwidthBps  float64 `json:"sparse_bandwidth_bytes_per_sec"`
	DenseBandwidthBps   float64 `json:"dense_bandwidth_bytes_per_sec"`
	DailySyncCount      int     `json:"daily_sync_count"`
}

// BenchmarkReport captures deterministic verification results + measured Go offline benchmarks.
type BenchmarkReport struct {
	SchemaVersion      string                 `json:"schema_version"`
	SpecVersion        string                 `json:"spec_version"`
	Seed               int64                  `json:"seed"`
	SuiteSummary       SuiteReport            `json:"suite_summary"`
	DepthBenchmarks    []DepthBenchRow        `json:"go_depth_benchmarks"`
	BitstringBench     []BitstringBenchRow    `json:"go_bitstring_benchmarks"`
	StalenessTradeoffs []StalenessTradeoffRow `json:"staleness_tradeoff_analysis"`
	PythonDepthBench   []PythonDepthBenchRow  `json:"python_depth_benchmarks,omitempty"`
}

// PythonDepthBenchRow can be populated or mirrored by Python bench output.
type PythonDepthBenchRow struct {
	Depth         int     `json:"depth"`
	Iterations    int     `json:"iterations"`
	WarmMeanUS    float64 `json:"warm_mean_us"`
	WarmP50US     float64 `json:"warm_p50_us"`
	WarmP95US     float64 `json:"warm_p95_us"`
	WarmOpsPerSec float64 `json:"warm_ops_per_sec"`
	ColdMeanUS    float64 `json:"cold_mean_us"`
	WarmSigChecks int     `json:"warm_sig_checks"`
}

// BuildDepthBenchmarkCase builds a valid depth-N offline delegation chain + context
// backed by a 131,072-bit W3C BitstringStatusList.
func BuildDepthBenchmarkCase(seed int64, depth int, bitLength int, revokedIndices []int, encoding string) (VerificationContext, ActionPresentation, error) {
	baseTime := DefaultBaseTime
	evalTime := baseTime + 1200

	rootDID := "did:zoo:council:bench-root"
	rootKP := DeriveKeyPair(seed, fmt.Sprintf("bench-root-d%d", depth), rootDID+"#key-1")
	rootDoc, err := BuildDIDDoc(rootDID, PrincipalHumanCouncil, rootDID, rootKP, baseTime-3600, baseTime+86400*30, nil)
	if err != nil {
		return VerificationContext{}, ActionPresentation{}, err
	}

	dids := make([]DIDDocument, 0, depth+1)
	dids = append(dids, rootDoc)
	chain := make([]DelegationVC, 0, depth)

	prevDID := rootDID
	prevKP := rootKP
	var prevVC DelegationVC
	var prevDigest string

	for hop := 0; hop < depth; hop++ {
		var curDID string
		var pt string
		if hop == 0 {
			curDID = fmt.Sprintf("did:zoo:org:bench-org-%d", hop)
			pt = PrincipalOrgController
		} else if hop == depth-1 {
			kpSeed := DeriveKeyPair(seed, fmt.Sprintf("bench-d%d-hop%d", depth, hop), "")
			curDID = DIDKeyFromPublicKey(kpSeed.PublicKey)
			pt = PrincipalEphemeralSession
		} else {
			curDID = fmt.Sprintf("did:zoo:agent:bench-agent-%d", hop)
			pt = PrincipalAIAgent
		}
		curKP := DeriveKeyPair(seed, fmt.Sprintf("bench-d%d-hop%d", depth, hop), curDID+"#key-1")
		doc, err := BuildDIDDoc(curDID, pt, prevDID, curKP, baseTime-1800, baseTime+86400*30, nil)
		if err != nil {
			return VerificationContext{}, ActionPresentation{}, err
		}
		dids = append(dids, doc)

		resPath := "zoo://datasets/bench"
		for r := 0; r <= hop; r++ {
			resPath += fmt.Sprintf("/h%d", r)
		}
		subj := DelegationSubject{
			ID:                   curDID,
			SubjectPrincipalType: pt,
			DelegationDepth:      hop,
			MaxSubDepth:          depth - 1 - hop,
			ParentVCID:           "",
			ParentVCDigest:       "",
			Audience:             DefaultAudience,
			Scopes:               []string{"research:execute_eval"},
			AllowedResources:     []string{resPath},
			Constraints: DelegationConstraints{
				MaxCallsPerHour:    1000 - hop*10,
				MaxBudgetUSDCents:  10000 - hop*100,
				RequireHolderProof: true,
			},
			Nonce: fmt.Sprintf("bench-vc-d%d-h%d", depth, hop),
		}
		if hop > 0 {
			subj.ParentVCID = prevVC.ID
			subj.ParentVCDigest = prevDigest
		}
		vc, err := SignDelegationVC(
			fmt.Sprintf("urn:zoo:vc:bench-d%d-h%d", depth, hop),
			prevDID, prevKP,
			baseTime+int64(hop*10),
			baseTime+86400-int64(hop*60),
			baseTime+int64(hop*10),
			100+hop, // non-revoked indices
			DefaultStatusListID,
			subj,
		)
		if err != nil {
			return VerificationContext{}, ActionPresentation{}, err
		}
		chain = append(chain, vc)
		prevDID = curDID
		prevKP = curKP
		prevVC = vc
		prevDigest = ComputeVCDigest(vc)
	}

	sl, err := SignStatusList(DefaultStatusListID, rootDID, rootKP, baseTime, baseTime+7200, bitLength, revokedIndices, encoding)
	if err != nil {
		return VerificationContext{}, ActionPresentation{}, err
	}
	snap, err := SignRevocationSnapshot("urn:zoo:revsnap:bench", rootDID, rootKP, baseTime, baseTime+7200, []BitstringStatusListCredential{sl}, []KeyRevocationEntry{}, []string{})
	if err != nil {
		return VerificationContext{}, ActionPresentation{}, err
	}

	leafRes := chain[depth-1].CredentialSubject.AllowedResources[0]
	hp, err := SignHolderProof(prevDID, prevKP, chain, fmt.Sprintf("bench-nonce-d%d", depth), DefaultAudience, "research:execute_eval", leafRes, evalTime)
	if err != nil {
		return VerificationContext{}, ActionPresentation{}, err
	}

	ctx := VerificationContext{
		TrustedRootDIDs:    []string{rootDID},
		ExpectedAudience:   DefaultAudience,
		UsedNonces:         []string{},
		DIDDocuments:       dids,
		StatusLists:        []BitstringStatusListCredential{sl},
		RevocationSnapshot: snap,
	}
	pres := ActionPresentation{
		PresentationID:  fmt.Sprintf("bench-pres-d%d", depth),
		EvalTime:        evalTime,
		Audience:        DefaultAudience,
		ActionVerb:      "research:execute_eval",
		ResourceURI:     leafRes,
		ChallengeNonce:  fmt.Sprintf("bench-nonce-d%d", depth),
		DelegationChain: chain,
		HolderProof:     hp,
	}
	return ctx, pres, nil
}

// RunGoBenchmarks executes the full reproducible Go benchmark suite.
func RunGoBenchmarks(seed int64, iterations int) (BenchmarkReport, IdentityDelegationSuite, error) {
	if iterations <= 0 {
		iterations = 200
	}
	suite, err := BuildReferenceSuite(seed)
	if err != nil {
		return BenchmarkReport{}, IdentityDelegationSuite{}, err
	}
	suiteReport := VerifySuite(suite)

	// 1. Chain depth scaling: 1, 2, 4, 8, 16 hops on a 131K-bit W3C BitstringStatusList.
	depths := []int{1, 2, 4, 8, 16}
	depthRows := make([]DepthBenchRow, 0, len(depths))
	var baseWarmMean float64

	for _, d := range depths {
		ctx, pres, err := BuildDepthBenchmarkCase(seed, d, DefaultBitstringLength, []int{1, 7, 4096, 99999}, EncodingGzipBase64URL)
		if err != nil {
			return BenchmarkReport{}, IdentityDelegationSuite{}, err
		}
		epoch, errCode, errMsg := PrepareEpoch(ctx, pres.EvalTime)
		if errCode != "" {
			return BenchmarkReport{}, IdentityDelegationSuite{}, fmt.Errorf("depth %d epoch prepare failed: %s %s", d, errCode, errMsg)
		}

		// Warmup
		for w := 0; w < 10; w++ {
			res := VerifyPresentationWithEpoch(epoch, ctx, pres)
			if !res.Valid {
				return BenchmarkReport{}, IdentityDelegationSuite{}, fmt.Errorf("depth %d warm verify failed: %s", d, res.ErrorCode)
			}
		}

		warmLat := make([]float64, iterations)
		var warmSigs int
		for i := 0; i < iterations; i++ {
			t0 := time.Now()
			res := VerifyPresentationWithEpoch(epoch, ctx, pres)
			warmLat[i] = float64(time.Since(t0).Nanoseconds()) / 1000.0
			warmSigs = res.SignatureChecks
		}

		coldIters := iterations / 2
		if coldIters < 30 {
			coldIters = 30
		}
		coldLat := make([]float64, coldIters)
		var coldSigs int
		for i := 0; i < coldIters; i++ {
			t0 := time.Now()
			res := VerifyPresentation(ctx, pres)
			coldLat[i] = float64(time.Since(t0).Nanoseconds()) / 1000.0
			coldSigs = res.SignatureChecks
		}

		wMean, wP50, wP95 := latencyStats(warmLat)
		cMean, cP50, cP95 := latencyStats(coldLat)
		if d == 1 {
			baseWarmMean = wMean
		}
		scale := 1.0
		if baseWarmMean > 0 {
			scale = round2(wMean / baseWarmMean)
		}
		depthRows = append(depthRows, DepthBenchRow{
			Depth:               d,
			Iterations:          iterations,
			WarmMeanUS:          round2(wMean),
			WarmP50US:           round2(wP50),
			WarmP95US:           round2(wP95),
			WarmOpsPerSec:       round2(1e6 / wMean),
			ColdMeanUS:          round2(cMean),
			ColdP50US:           round2(cP50),
			ColdP95US:           round2(cP95),
			ColdOpsPerSec:       round2(1e6 / cMean),
			WarmSigChecks:       warmSigs,
			ColdSigChecks:       coldSigs,
			WarmScalingVsDepth1: scale,
		})
	}

	// 2. W3C BitstringStatusList size & density scaling (1K, 16K, 131K x sparse 0.1% & dense 50%).
	bitSizes := []int{1024, 16384, 131072}
	bitRows := make([]BitstringBenchRow, 0, len(bitSizes)*2)
	var sparse131KBytes, dense131KBytes int

	rng := rand.New(rand.NewSource(seed))
	for _, bl := range bitSizes {
		for _, density := range []struct {
			label string
			frac  float64
		}{
			{"sparse_0.1pct", 0.001},
			{"dense_50pct", 0.50},
		} {
			revCount := int(float64(bl) * density.frac)
			if revCount < 1 {
				revCount = 1
			}
			revSet := make(map[int]bool, revCount)
			revIndices := make([]int, 0, revCount)
			for len(revIndices) < revCount {
				idx := rng.Intn(bl)
				// Avoid colliding with benchmark chain indices [100..115]
				if idx >= 100 && idx < 120 {
					continue
				}
				if !revSet[idx] {
					revSet[idx] = true
					revIndices = append(revIndices, idx)
				}
			}

			ctx, pres, err := BuildDepthBenchmarkCase(seed, 4, bl, revIndices, EncodingGzipBase64URL)
			if err != nil {
				return BenchmarkReport{}, IdentityDelegationSuite{}, err
			}
			gzipLen := len(ctx.StatusLists[0].CredentialSubject.EncodedList)
			rawEnc, err := BuildBitstring(bl, revIndices, EncodingRawBase64URL)
			if err != nil {
				return BenchmarkReport{}, IdentityDelegationSuite{}, err
			}
			rawB64Len := len(rawEnc)
			if bl == 131072 {
				if density.label == "sparse_0.1pct" {
					sparse131KBytes = gzipLen
				} else {
					dense131KBytes = gzipLen
				}
			}

			// Measure cold status list verify + decode + chain verify.
			coldLat := make([]float64, 50)
			for i := 0; i < 50; i++ {
				t0 := time.Now()
				res := VerifyPresentation(ctx, pres)
				coldLat[i] = float64(time.Since(t0).Nanoseconds()) / 1000.0
				if !res.Valid {
					return BenchmarkReport{}, IdentityDelegationSuite{}, fmt.Errorf("bitstring bench bl=%d failed: %s", bl, res.ErrorCode)
				}
			}
			cMean, _, _ := latencyStats(coldLat)

			// Measure warm O(1) bitstring lookup latency (10,000 lookups).
			rawBits, err := DecodeBitstring(ctx.StatusLists[0].CredentialSubject.EncodedList, EncodingGzipBase64URL, bl)
			if err != nil {
				return BenchmarkReport{}, IdentityDelegationSuite{}, err
			}
			t0 := time.Now()
			const lookupN = 10000
			for i := 0; i < lookupN; i++ {
				_, _ = BitstringIsRevoked(rawBits, bl, (i*31)%bl)
			}
			warmLookupUS := float64(time.Since(t0).Nanoseconds()) / 1000.0 / float64(lookupN)

			bitRows = append(bitRows, BitstringBenchRow{
				BitLength:        bl,
				RawBytes:         bl / 8,
				DensityLabel:     density.label,
				RevokedCount:     revCount,
				GzipBase64Bytes:  gzipLen,
				RawBase64Bytes:   rawB64Len,
				CompressionRatio: round2(float64(rawB64Len) / float64(gzipLen)),
				ColdVerifyMeanUS: round2(cMean),
				WarmLookupMeanUS: round4(warmLookupUS),
			})
		}
	}

	// 3. Honest Negative Regime: Offline Revocation Staleness vs Sync Bandwidth (131K-entry list).
	intervals := []int64{60, 300, 900, 3600, 86400}
	stalenessRows := make([]StalenessTradeoffRow, 0, len(intervals))
	for _, iv := range intervals {
		stalenessRows = append(stalenessRows, StalenessTradeoffRow{
			SyncIntervalSeconds: iv,
			MaxStalenessSeconds: iv,
			SparseBandwidthBps:  round2(float64(sparse131KBytes) / float64(iv)),
			DenseBandwidthBps:   round2(float64(dense131KBytes) / float64(iv)),
			DailySyncCount:      int(86400 / iv),
		})
	}

	return BenchmarkReport{
		SchemaVersion:      SchemaVersion,
		SpecVersion:        SpecVersion,
		Seed:               seed,
		SuiteSummary:       suiteReport,
		DepthBenchmarks:    depthRows,
		BitstringBench:     bitRows,
		StalenessTradeoffs: stalenessRows,
	}, suite, nil
}

func latencyStats(samples []float64) (mean, p50, p95 float64) {
	if len(samples) == 0 {
		return 0, 0, 0
	}
	cp := append([]float64(nil), samples...)
	sort.Float64s(cp)
	sum := 0.0
	for _, v := range cp {
		sum += v
	}
	mean = sum / float64(len(cp))
	p50 = cp[len(cp)/2]
	idx95 := int(float64(len(cp))*0.95) - 1
	if idx95 < 0 {
		idx95 = 0
	}
	if idx95 >= len(cp) {
		idx95 = len(cp) - 1
	}
	p95 = cp[idx95]
	return mean, p50, p95
}

func round2(v float64) float64 {
	return float64(int64(v*100+0.5)) / 100.0
}

func round4(v float64) float64 {
	return float64(int64(v*10000+0.5)) / 10000.0
}

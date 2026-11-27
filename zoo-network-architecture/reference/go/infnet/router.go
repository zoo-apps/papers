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
	"fmt"
	"sort"
	"sync"
)

const (
	// Physics constants for a 32-layer, 4096-dim GQA-8 FP16 transformer (e.g., Qwen3-14B / Llama-3-8B class).
	DefaultTotalLayers        uint32 = 32
	KVBytesPerTokenFP16       uint64 = 131072 // 128 KiB/token across 32 layers
	HiddenStateBytesPerToken  uint64 = 8192   // 4096 * 2 bytes (FP16)
	RPCHeaderOverheadBytes    uint64 = 512
	WANFailDetectTimeoutUs    uint64 = 180_000 // 180 ms WAN crash detection
	DCFailDetectTimeoutUs     uint64 = 25_000  // 25 ms datacenter healthcheck timeout
	TEEOverheadNum            uint64 = 112     // +12% Confidential Computing overhead
	TEEOverheadDen            uint64 = 100
)

// FailurePolicy controls deterministic mid-request failure injection for reproducible benchmarks.
type FailurePolicy struct {
	FailureRateBps uint32 // 0..10000 (e.g., 1000 = 10%, 2500 = 25%)
	MaxRetries     uint32 // max failover retries per request
	Seed           uint64
}

// ExecutionOutcome bundles the signed DeliveryReceipt, generated tokens, and audit flags.
type ExecutionOutcome struct {
	Receipt        DeliveryReceipt
	OutputChunks   []string
	CapacityEvents []CapacityEvent
	PrefixCacheHit bool
	QueueWaitUs    uint64
	PrivacyLeak    bool
}

// Router coordinates privacy-bounded discovery, capacity accounting, routing, failover, and receipt signing.
type Router struct {
	mu          sync.Mutex
	registry    *Registry
	capacity    *CapacityAccountant
	nodeKeys    map[string]ed25519.PrivateKey
	nodeFreeAt  map[string]uint64 // per-node simulated earliest-free timestamp (us) for queuing model
	receiptSeq  uint64
	privacyLeak uint64
}

// NewRouter creates a Router bound to a Registry and CapacityAccountant.
func NewRouter(reg *Registry, capAcc *CapacityAccountant, keys map[string]ed25519.PrivateKey) *Router {
	keyCopy := make(map[string]ed25519.PrivateKey, len(keys))
	for k, v := range keys {
		keyCopy[k] = v
	}
	return &Router{
		registry:   reg,
		capacity:   capAcc,
		nodeKeys:   keyCopy,
		nodeFreeAt: make(map[string]uint64),
	}
}

// PrivacyLeakCount returns total privacy boundary violations detected (must always be 0).
func (rt *Router) PrivacyLeakCount() uint64 {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.privacyLeak
}

// EstimateRequestResources computes VRAM (MiB) and KV slots for a request on a layer fraction.
func EstimateRequestResources(promptTokens, maxOutputTokens, layersServed, totalLayers uint32) (vramMiB uint64, kvSlots uint32) {
	totalTok := uint64(promptTokens) + uint64(maxOutputTokens)
	if totalLayers == 0 {
		totalLayers = DefaultTotalLayers
	}
	kvBytes := (totalTok * KVBytesPerTokenFP16 * uint64(layersServed)) / uint64(totalLayers)
	vramMiB = (kvBytes + (1<<20 - 1)) / (1 << 20)
	vramMiB += 64 // activation + workspace buffer
	if vramMiB < 128 {
		vramMiB = 128
	}
	kvSlots = uint32((totalTok + 511) / 512)
	if kvSlots < 1 {
		kvSlots = 1
	}
	return vramMiB, kvSlots
}

// transferTimeUs calculates wire serialization delay in microseconds for bytes over bandwidthKbps.
func transferTimeUs(bytes uint64, bandwidthKbps uint64) uint64 {
	if bandwidthKbps == 0 {
		return 0
	}
	// bytes * 8 bits / (bandwidthKbps * 1000 bits/s) * 1e6 us/s = (bytes * 8000) / bandwidthKbps
	return (bytes * 8000) / bandwidthKbps
}

// EnforcePrivacyBoundary hard-checks that every candidate node satisfies the request privacy policy.
func EnforcePrivacyBoundary(req PrivacyRequirement, nodes []NodeAdvertisement) error {
	for _, n := range nodes {
		if !PrivacyTierSatisfies(req, n.PrivacyTier) {
			return fmt.Errorf("%w: request requires %s but node %s has tier %s",
				ErrPrivacyBoundaryViolation, req, n.NodeID, n.PrivacyTier)
		}
	}
	return nil
}

// deterministicFailRoll returns true if request+attempt triggers a simulated crash under FailurePolicy.
func deterministicFailRoll(fp FailurePolicy, reqID string, attempt uint32, nodeID string) (bool, uint32) {
	if fp.FailureRateBps == 0 {
		return false, 0
	}
	h := sha256.New()
	var sb [8]byte
	binary.BigEndian.PutUint64(sb[:], fp.Seed)
	h.Write(sb[:])
	h.Write([]byte("|fail|"))
	h.Write([]byte(reqID))
	var ab [4]byte
	binary.BigEndian.PutUint32(ab[:], attempt)
	h.Write(ab[:])
	h.Write([]byte("|"))
	h.Write([]byte(nodeID))
	sum := h.Sum(nil)
	roll := binary.BigEndian.Uint32(sum[0:4]) % 10000
	tokPct := binary.BigEndian.Uint32(sum[4:8]) % 70 // crash at 10%..79% of output generation
	return roll < fp.FailureRateBps, 10 + tokPct
}

// ExecuteRequest routes and executes a single inference request under the chosen topology.
func (rt *Router) ExecuteRequest(req InferenceRequest, mode TopologyMode, fp FailurePolicy) (ExecutionOutcome, error) {
	switch mode {
	case TopologyCentralizedBaseline:
		return rt.executeReplicaLike(req, mode, fp, false)
	case TopologyDynamoReplica:
		return rt.executeReplicaLike(req, mode, fp, true)
	case TopologyStrictTEE:
		return rt.executeReplicaLike(req, mode, fp, true)
	case TopologyPetalsPipeline:
		return rt.executePetalsPipeline(req, fp)
	default:
		return ExecutionOutcome{}, fmt.Errorf("unsupported topology mode %q", mode)
	}
}

func (rt *Router) nextReceiptID(mode TopologyMode) string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.receiptSeq++
	return fmt.Sprintf("rcpt-%s-%06d", mode, rt.receiptSeq)
}

// advanceQueue updates simulated per-node earliest-free time for realistic congestion/queuing accounting.
func (rt *Router) advanceQueue(nodeID string, arrivalUs, serviceUs uint64, concurrencyCap uint32) (queueWaitUs uint64, effectiveBatch uint32) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if concurrencyCap < 1 {
		concurrencyCap = 1
	}
	freeAt := rt.nodeFreeAt[nodeID]
	if arrivalUs >= freeAt {
		queueWaitUs = 0
		effectiveBatch = 1
		// Amortize service window across parallel batch slots.
		rt.nodeFreeAt[nodeID] = arrivalUs + serviceUs/uint64(maxU32(1, concurrencyCap/2))
	} else {
		backlog := freeAt - arrivalUs
		queueWaitUs = backlog
		// Estimate active batch size from backlog ratio.
		est := uint32(1 + backlog/(maxU64(1, serviceUs/4)))
		if est > concurrencyCap {
			est = concurrencyCap
		}
		effectiveBatch = est
		rt.nodeFreeAt[nodeID] = freeAt + serviceUs/uint64(maxU32(1, concurrencyCap/2))
	}
	return queueWaitUs, effectiveBatch
}

func (rt *Router) executeReplicaLike(req InferenceRequest, mode TopologyMode, fp FailurePolicy, disaggregated bool) (ExecutionOutcome, error) {
	rcptID := rt.nextReceiptID(mode)
	failedNodes := make([]string, 0, 2)
	excluded := make(map[string]bool)

	maxRetries := fp.MaxRetries
	if maxRetries == 0 && fp.FailureRateBps > 0 {
		maxRetries = 2
	}

	var totalRecoveryUs uint64
	var totalExtraNetBytes uint64
	var failovers uint32
	var generatedBeforeFail uint32

	for attempt := uint32(0); attempt <= maxRetries; attempt++ {
		// Discover healthy privacy-compliant nodes.
		candidates := rt.registry.Discover(DiscoveryQuery{
			ModelID:            req.ModelID,
			PrivacyRequirement: req.PrivacyRequirement,
			HealthyOnly:        true,
		})
		avail := make([]RegisteredNode, 0, len(candidates))
		for _, c := range candidates {
			if !excluded[c.Ad.NodeID] && (c.Ad.ExecutionRole == RoleWholeModel || c.Ad.ExecutionRole == RolePrefill || c.Ad.ExecutionRole == RoleDecode) {
				avail = append(avail, c)
			}
		}

		if len(avail) == 0 {
			// Check whether failure was due to privacy boundary scarcity vs general exhaustion.
			status := StatusFailedExhausted
			if req.PrivacyRequirement == PrivacyReqStrict {
				allHealthy := rt.registry.Discover(DiscoveryQuery{ModelID: req.ModelID, HealthyOnly: true})
				if len(allHealthy) > 0 {
					status = StatusRejectedPrivacy
				}
			}
			return rt.buildFailureOutcome(rcptID, req, mode, status, failedNodes, failovers, totalRecoveryUs, totalExtraNetBytes), nil
		}

		// Choose prefill and decode nodes (disaggregated in Dynamo if dedicated PREFILL + DECODE nodes exist).
		prefillNode, decodeNode, isDisagg, prefixHit := rt.selectReplicaNodes(avail, req, disaggregated)
		routeAds := []NodeAdvertisement{prefillNode.Ad}
		if decodeNode.Ad.NodeID != prefillNode.Ad.NodeID {
			routeAds = append(routeAds, decodeNode.Ad)
		}
		if err := EnforcePrivacyBoundary(req.PrivacyRequirement, routeAds); err != nil {
			rt.mu.Lock()
			rt.privacyLeak++
			rt.mu.Unlock()
			return ExecutionOutcome{PrivacyLeak: true}, err
		}

		vramMiB, kvSlots := EstimateRequestResources(req.PromptTokens+generatedBeforeFail, req.MaxOutputTokens, DefaultTotalLayers, DefaultTotalLayers)
		resList := make([]Reservation, 0, 2)
		prefillRes, err := rt.capacity.Reserve(prefillNode.Ad.NodeID, req.RequestID, vramMiB, kvSlots, req.PromptPrefixSHA256)
		if err != nil {
			excluded[prefillNode.Ad.NodeID] = true
			continue
		}
		resList = append(resList, prefillRes)

		if isDisagg {
			decRes, err := rt.capacity.Reserve(decodeNode.Ad.NodeID, req.RequestID, vramMiB, kvSlots, req.PromptPrefixSHA256)
			if err != nil {
				_ = rt.capacity.Release(prefillRes.ReservationID, "DECODE_RESERVE_FAILED")
				excluded[decodeNode.Ad.NodeID] = true
				continue
			}
			resList = append(resList, decRes)
		}

		// Simulate deterministic mid-request crash if FailurePolicy triggers.
		shouldFail, crashPct := deterministicFailRoll(fp, req.RequestID, attempt, decodeNode.Ad.NodeID)
		if shouldFail {
			// Release all reservations cleanly (ZERO capacity leaks!).
			for _, res := range resList {
				_ = rt.capacity.Release(res.ReservationID, "FAILOVER_ABORT")
			}
			failedNodes = append(failedNodes, decodeNode.Ad.NodeID)
			excluded[decodeNode.Ad.NodeID] = true

			// Measure crash detection + partial generation + KV replay overhead.
			detectUs := WANFailDetectTimeoutUs
			if mode == TopologyCentralizedBaseline {
				detectUs = DCFailDetectTimeoutUs
			}
			tokBefore := (req.MaxOutputTokens * crashPct) / 100
			if tokBefore < 1 {
				tokBefore = 1
			}
			generatedBeforeFail = tokBefore
			wastedPrefillUs := (uint64(req.PromptTokens) * 1_000_000) / uint64(prefillNode.Ad.PrefillTPS)
			wastedDecodeUs := (uint64(tokBefore) * 1_000_000) / uint64(decodeNode.Ad.DecodeTPS)
			// Account for the GPU occupancy consumed on the crashed node prior to abort.
			_, _ = rt.advanceQueue(decodeNode.Ad.NodeID, req.ArrivalUs, wastedPrefillUs/2+wastedDecodeUs, 8)
			totalRecoveryUs += detectUs + wastedPrefillUs/2 + wastedDecodeUs + decodeNode.Ad.WANRTTUs*2
			totalExtraNetBytes += uint64(req.PromptTokens+tokBefore)*4 + RPCHeaderOverheadBytes*2
			if attempt < maxRetries {
				failovers++
				continue
			}
			return rt.buildFailureOutcome(rcptID, req, mode, StatusFailedExhausted, failedNodes, failovers, totalRecoveryUs, totalExtraNetBytes), nil
		}

		// Compute physics-grounded TTFT, TPOT, network bytes, and batching efficiency.
		effectivePrompt := uint64(req.PromptTokens + generatedBeforeFail)
		if prefixHit && attempt == 0 {
			// Warm KV-prefix hit saves 65% of prefill compute.
			effectivePrompt = (effectivePrompt * 35) / 100
			if effectivePrompt < 16 {
				effectivePrompt = 16
			}
		}

		prefillUs := (effectivePrompt * 1_000_000) / uint64(prefillNode.Ad.PrefillTPS)
		decodePerTokUs := 1_000_000 / uint64(decodeNode.Ad.DecodeTPS)

		// Apply TEE Confidential Computing overhead when running inside TEE_ATTESTED enclave.
		if prefillNode.Ad.PrivacyTier == PrivacyTEEAttested {
			prefillUs = (prefillUs * TEEOverheadNum) / TEEOverheadDen
		}
		if decodeNode.Ad.PrivacyTier == PrivacyTEEAttested {
			decodePerTokUs = (decodePerTokUs * TEEOverheadNum) / TEEOverheadDen
		}

		// Network transfer calculation.
		promptBytes := uint64(req.PromptTokens)*4 + RPCHeaderOverheadBytes
		outputBytes := uint64(req.MaxOutputTokens)*4 + RPCHeaderOverheadBytes
		var kvXferBytes uint64
		var kvXferUs uint64
		if isDisagg {
			// Disaggregated Dynamo transfers FP8-quantized KV cache for uncached prompt tokens.
			kvXferBytes = (effectivePrompt * KVBytesPerTokenFP16) / 2
			bw := minU64(prefillNode.Ad.BandwidthKbps, decodeNode.Ad.BandwidthKbps)
			kvXferUs = transferTimeUs(kvXferBytes, bw) + decodeNode.Ad.WANRTTUs
		}
		ingressUs := prefillNode.Ad.WANRTTUs + transferTimeUs(promptBytes, prefillNode.Ad.BandwidthKbps)
		netBytes := promptBytes + outputBytes + kvXferBytes + totalExtraNetBytes

		// Estimate concurrency/batching utilization and queuing delay.
		concurrencyCap := uint32(16)
		baseUtilBps := uint32(9100) // ~91% continuous batching in datacenter
		if mode != TopologyCentralizedBaseline {
			concurrencyCap = minU32(decodeNode.Ad.KVSlotsTotal, 8)
			baseUtilBps = 7200 // ~72% in decentralized WAN replicas
			if isDisagg {
				baseUtilBps = 7600 // Dynamo disaggregation improves decode batch packing
			}
			if mode == TopologyStrictTEE {
				baseUtilBps = 6900
			}
		}

		rawServiceUs := prefillUs + kvXferUs + decodePerTokUs*uint64(req.MaxOutputTokens)
		queueWaitUs, effBatch := rt.advanceQueue(decodeNode.Ad.NodeID, req.ArrivalUs, rawServiceUs, concurrencyCap)

		// Continuous batching slightly increases per-token latency sublinearly while boosting utilization.
		batchSlowdownNum := uint64(100 + (effBatch-1)*4)
		tpotUs := (decodePerTokUs * batchSlowdownNum) / 100
		if mode != TopologyCentralizedBaseline {
			// Streaming token pacing jitter over WAN.
			tpotUs += decodeNode.Ad.WANRTTUs / 25
		}

		ttftUs := queueWaitUs + ingressUs + prefillUs + kvXferUs + tpotUs + totalRecoveryUs
		totalLatencyUs := ttftUs + tpotUs*uint64(maxU32(1, req.MaxOutputTokens)-1) + decodeNode.Ad.WANRTTUs/2

		utilBps := baseUtilBps + minU32((effBatch-1)*120, 600)
		if utilBps > 9800 {
			utilBps = 9800
		}
		if failovers > 0 {
			// Recovery replays reduce effective batching utilization.
			penalty := minU32(failovers*750, utilBps/2)
			utilBps -= penalty
		}

		// Release all capacity reservations upon completion.
		for _, res := range resList {
			_ = rt.capacity.Release(res.ReservationID, "COMPLETED")
		}

		chunks := DeterministicOutputChunks(req.PromptSHA256, req.ModelID, req.MaxOutputTokens)
		outRoot := ComputeOutputMerkleRoot(chunks)

		routeIDs := []string{prefillNode.Ad.NodeID}
		tiers := []PrivacyTier{prefillNode.Ad.PrivacyTier}
		if decodeNode.Ad.NodeID != prefillNode.Ad.NodeID {
			routeIDs = append(routeIDs, decodeNode.Ad.NodeID)
			tiers = append(tiers, decodeNode.Ad.PrivacyTier)
		}
		for _, fid := range failedNodes {
			if fn, ok := rt.registry.Get(fid); ok {
				tiers = append(tiers, fn.Ad.PrivacyTier)
			}
		}
		status := StatusCompleted
		if failovers > 0 {
			status = StatusCompletedFailover
		}

		rcpt := DeliveryReceipt{
			SchemaVersion:           SchemaVersion,
			ReceiptID:               rcptID,
			RequestID:               req.RequestID,
			TopologyMode:            mode,
			ModelID:                 req.ModelID,
			PromptSHA256:            req.PromptSHA256,
			PromptPrefixSHA256:      req.PromptPrefixSHA256,
			PromptTokens:            req.PromptTokens,
			OutputTokens:            req.MaxOutputTokens,
			OutputMerkleRoot:        outRoot,
			PrivacyRequirement:      req.PrivacyRequirement,
			EffectivePrivacyTier:    EffectiveTierForRoute(tiers),
			RouteNodeIDs:            routeIDs,
			PrimaryProviderID:       decodeNode.Ad.NodeID,
			PrefillNodeID:           prefillNode.Ad.NodeID,
			DecodeNodeIDs:           []string{decodeNode.Ad.NodeID},
			KVSlotsReserved:         kvSlots * uint32(len(resList)),
			VRAMReservedMiB:         vramMiB * uint64(len(resList)),
			NetworkBytesTransferred: netBytes,
			TTFTUs:                  ttftUs,
			TPOTUs:                  tpotUs,
			TotalLatencyUs:          totalLatencyUs,
			RecoveryLatencyUs:       totalRecoveryUs,
			FailoverAttempts:        failovers,
			FailedNodeIDs:           failedNodes,
			BatchSizeEffective:      effBatch,
			BatchUtilizationBps:     utilBps,
			Status:                  status,
			ProvesScientificTruth:   false,
			AuthorizesTreasurySpend: false,
		}
		if priv, ok := rt.nodeKeys[decodeNode.Ad.NodeID]; ok {
			SignDeliveryReceipt(&rcpt, priv)
		}

		return ExecutionOutcome{
			Receipt:        rcpt,
			OutputChunks:   chunks,
			CapacityEvents: rt.capacity.LedgerForRequest(req.RequestID),
			PrefixCacheHit: prefixHit,
			QueueWaitUs:    queueWaitUs,
		}, nil
	}

	return rt.buildFailureOutcome(rcptID, req, mode, StatusFailedExhausted, failedNodes, failovers, totalRecoveryUs, totalExtraNetBytes), nil
}

// selectReplicaNodes picks the best prefill + decode pair (or whole-model replica) using
// KV-prefix affinity, WAN RTT, KV-transfer overhead, and queue backlog.
func (rt *Router) selectReplicaNodes(avail []RegisteredNode, req InferenceRequest, allowDisagg bool) (prefill RegisteredNode, decode RegisteredNode, isDisagg bool, prefixHit bool) {
	var prefillPool, decodePool, wholePool []RegisteredNode
	for _, n := range avail {
		switch n.Ad.ExecutionRole {
		case RolePrefill:
			prefillPool = append(prefillPool, n)
		case RoleDecode:
			decodePool = append(decodePool, n)
		case RoleWholeModel:
			wholePool = append(wholePool, n)
		}
	}

	scorePrefill := func(n RegisteredNode) uint64 {
		rt.mu.Lock()
		freeAt := rt.nodeFreeAt[n.Ad.NodeID]
		rt.mu.Unlock()
		var wait uint64
		if freeAt > req.ArrivalUs {
			wait = freeAt - req.ArrivalUs
		}
		effTok := uint64(req.PromptTokens)
		if rt.capacity.HasPrefixCache(n.Ad.NodeID, req.PromptPrefixSHA256) {
			effTok = (effTok * 35) / 100
		}
		compute := (effTok * 1_000_000) / uint64(n.Ad.PrefillTPS)
		return wait + n.Ad.WANRTTUs + compute
	}

	scoreDecode := func(n RegisteredNode) uint64 {
		rt.mu.Lock()
		freeAt := rt.nodeFreeAt[n.Ad.NodeID]
		rt.mu.Unlock()
		var wait uint64
		if freeAt > req.ArrivalUs {
			wait = freeAt - req.ArrivalUs
		}
		compute := (uint64(req.MaxOutputTokens) * 1_000_000) / uint64(n.Ad.DecodeTPS)
		return wait + n.Ad.WANRTTUs + compute
	}

	var bestDisaggP, bestDisaggD RegisteredNode
	var bestDisaggScore uint64 = ^uint64(0)
	hasDisagg := false

	if allowDisagg && len(prefillPool) > 0 && len(decodePool) > 0 {
		sort.Slice(prefillPool, func(i, j int) bool {
			si, sj := scorePrefill(prefillPool[i]), scorePrefill(prefillPool[j])
			if si != sj {
				return si < sj
			}
			return prefillPool[i].Ad.NodeID < prefillPool[j].Ad.NodeID
		})
		sort.Slice(decodePool, func(i, j int) bool {
			si, sj := scoreDecode(decodePool[i]), scoreDecode(decodePool[j])
			if si != sj {
				return si < sj
			}
			return decodePool[i].Ad.NodeID < decodePool[j].Ad.NodeID
		})
		bestDisaggP = prefillPool[0]
		bestDisaggD = decodePool[0]
		effTok := uint64(req.PromptTokens)
		if rt.capacity.HasPrefixCache(bestDisaggP.Ad.NodeID, req.PromptPrefixSHA256) {
			effTok = (effTok * 35) / 100
		}
		kvBytes := (effTok * KVBytesPerTokenFP16) / 2
		kvDelay := transferTimeUs(kvBytes, minU64(bestDisaggP.Ad.BandwidthKbps, bestDisaggD.Ad.BandwidthKbps)) + bestDisaggD.Ad.WANRTTUs
		bestDisaggScore = scorePrefill(bestDisaggP) + scoreDecode(bestDisaggD) + kvDelay
		hasDisagg = true
	}

	pool := wholePool
	if len(pool) == 0 && !hasDisagg {
		pool = avail
	}
	if len(pool) > 0 {
		sort.Slice(pool, func(i, j int) bool {
			si := scorePrefill(pool[i]) + scoreDecode(pool[i])
			sj := scorePrefill(pool[j]) + scoreDecode(pool[j])
			if si != sj {
				return si < sj
			}
			return pool[i].Ad.NodeID < pool[j].Ad.NodeID
		})
		bestWhole := pool[0]
		bestWholeScore := scorePrefill(bestWhole) + scoreDecode(bestWhole)
		if !hasDisagg || bestWholeScore < bestDisaggScore {
			return bestWhole, bestWhole, false, rt.capacity.HasPrefixCache(bestWhole.Ad.NodeID, req.PromptPrefixSHA256)
		}
	}

	return bestDisaggP, bestDisaggD, true, rt.capacity.HasPrefixCache(bestDisaggP.Ad.NodeID, req.PromptPrefixSHA256)
}

// executePetalsPipeline routes a request across a 4-stage WAN layer-sharded pipeline
// (Petals-style), quantifying per-token hidden-state activation transfers, multi-hop WAN RTT,
// pipeline fill bubbles, and batching efficiency loss.
func (rt *Router) executePetalsPipeline(req InferenceRequest, fp FailurePolicy) (ExecutionOutcome, error) {
	rcptID := rt.nextReceiptID(TopologyPetalsPipeline)
	failedNodes := make([]string, 0, 4)
	excluded := make(map[string]bool)

	maxRetries := fp.MaxRetries
	if maxRetries == 0 && fp.FailureRateBps > 0 {
		maxRetries = 2
	}

	const numStages uint32 = 4
	layersPerStage := DefaultTotalLayers / numStages

	var totalRecoveryUs uint64
	var totalExtraNetBytes uint64
	var failovers uint32
	var generatedBeforeFail uint32

	for attempt := uint32(0); attempt <= maxRetries; attempt++ {
		stages := make([]RegisteredNode, 0, numStages)
		complete := true
		for s := uint32(0); s < numStages; s++ {
			lStart := s * layersPerStage
			lEnd := lStart + layersPerStage
			cands := rt.registry.Discover(DiscoveryQuery{
				ModelID:            req.ModelID,
				Role:               RolePipelineStage,
				LayerStart:         lStart,
				LayerEnd:           lEnd,
				PrivacyRequirement: req.PrivacyRequirement,
				HealthyOnly:        true,
			})
			picked := false
			// Sort by RTT + backlog
			sort.Slice(cands, func(i, j int) bool {
				rt.mu.Lock()
				fi, fj := rt.nodeFreeAt[cands[i].Ad.NodeID], rt.nodeFreeAt[cands[j].Ad.NodeID]
				rt.mu.Unlock()
				si := fi + cands[i].Ad.WANRTTUs
				sj := fj + cands[j].Ad.WANRTTUs
				if si != sj {
					return si < sj
				}
				return cands[i].Ad.NodeID < cands[j].Ad.NodeID
			})
			for _, c := range cands {
				if !excluded[c.Ad.NodeID] {
					stages = append(stages, c)
					picked = true
					break
				}
			}
			if !picked {
				complete = false
				break
			}
		}

		if !complete {
			return rt.buildFailureOutcome(rcptID, req, TopologyPetalsPipeline, StatusFailedExhausted, failedNodes, failovers, totalRecoveryUs, totalExtraNetBytes), nil
		}

		stageAds := make([]NodeAdvertisement, len(stages))
		for i, st := range stages {
			stageAds[i] = st.Ad
		}
		if err := EnforcePrivacyBoundary(req.PrivacyRequirement, stageAds); err != nil {
			rt.mu.Lock()
			rt.privacyLeak++
			rt.mu.Unlock()
			return ExecutionOutcome{PrivacyLeak: true}, err
		}

		// Reserve capacity on every pipeline stage (all-or-nothing rollback on failure).
		vramPerStage, kvPerStage := EstimateRequestResources(req.PromptTokens+generatedBeforeFail, req.MaxOutputTokens, layersPerStage, DefaultTotalLayers)
		resList := make([]Reservation, 0, numStages)
		reserveFailed := false
		for _, st := range stages {
			res, err := rt.capacity.Reserve(st.Ad.NodeID, req.RequestID, vramPerStage, kvPerStage, req.PromptPrefixSHA256)
			if err != nil {
				for _, prev := range resList {
					_ = rt.capacity.Release(prev.ReservationID, "PIPELINE_ROLLBACK")
				}
				excluded[st.Ad.NodeID] = true
				reserveFailed = true
				break
			}
			resList = append(resList, res)
		}
		if reserveFailed {
			continue
		}

		// Any hop failing breaks the pipeline chain (compounded multi-hop failure exposure!).
		crashedIdx := -1
		var crashPct uint32
		for idx, st := range stages {
			shouldFail, pct := deterministicFailRoll(fp, req.RequestID, attempt, st.Ad.NodeID)
			if shouldFail {
				crashedIdx = idx
				crashPct = pct
				break
			}
		}
		if crashedIdx >= 0 {
			for _, res := range resList {
				_ = rt.capacity.Release(res.ReservationID, "PIPELINE_FAILOVER_ABORT")
			}
			crashed := stages[crashedIdx]
			failedNodes = append(failedNodes, crashed.Ad.NodeID)
			excluded[crashed.Ad.NodeID] = true
			tokBefore := (req.MaxOutputTokens * crashPct) / 100
			if tokBefore < 1 {
				tokBefore = 1
			}
			generatedBeforeFail = tokBefore
			var hopRTTSum uint64
			for _, st := range stages {
				hopRTTSum += st.Ad.WANRTTUs
			}
			// Rebuilding a broken WAN pipeline requires detection + full hidden-state replay across hops.
			totalRecoveryUs += WANFailDetectTimeoutUs + hopRTTSum*uint64(minU32(tokBefore, 16)+2)
			totalExtraNetBytes += uint64(req.PromptTokens+tokBefore) * HiddenStateBytesPerToken * uint64(numStages-1)
			if attempt < maxRetries {
				failovers++
				continue
			}
			return rt.buildFailureOutcome(rcptID, req, TopologyPetalsPipeline, StatusFailedExhausted, failedNodes, failovers, totalRecoveryUs, totalExtraNetBytes), nil
		}

		// Physics of Petals-style 4-hop WAN pipeline:
		// 1. Prefill passes full prompt hidden-state activations across (S-1) WAN hops.
		effPrompt := uint64(req.PromptTokens + generatedBeforeFail)
		prefillActivationBytes := effPrompt * HiddenStateBytesPerToken * uint64(numStages-1)
		// 2. Every generated token passes 1 hidden-state vector (8 KiB) across (S-1) WAN hops + client RTT.
		decodeActivationBytes := uint64(req.MaxOutputTokens) * HiddenStateBytesPerToken * uint64(numStages-1)
		promptBytes := uint64(req.PromptTokens)*4 + RPCHeaderOverheadBytes
		outputBytes := uint64(req.MaxOutputTokens)*4 + RPCHeaderOverheadBytes
		totalNetBytes := promptBytes + outputBytes + prefillActivationBytes + decodeActivationBytes + totalExtraNetBytes

		var sumHopRTTUs uint64
		var sumPrefillStageUs uint64
		var sumDecodeStageUs uint64
		var prefillWireUs uint64
		var decodeWirePerTokUs uint64
		var bottleneckStageIdx int
		var bottleneckOccupancyUs uint64
		var worstDecodeTPS uint32 = 1_000_000

		for idx, st := range stages {
			sumHopRTTUs += st.Ad.WANRTTUs
			// Each stage runs 1/numStages of the model's layers, so stage throughput scales by numStages.
			stagePrefillUs := (effPrompt * 1_000_000) / (uint64(st.Ad.PrefillTPS) * uint64(numStages))
			stageDecodeUs := 1_000_000 / (uint64(st.Ad.DecodeTPS) * uint64(numStages))
			sumPrefillStageUs += stagePrefillUs
			sumDecodeStageUs += stageDecodeUs
			occ := stagePrefillUs + stageDecodeUs*uint64(req.MaxOutputTokens)
			if st.Ad.DecodeTPS < worstDecodeTPS || occ > bottleneckOccupancyUs {
				worstDecodeTPS = st.Ad.DecodeTPS
				bottleneckStageIdx = idx
				bottleneckOccupancyUs = occ
			}
			if idx < len(stages)-1 {
				linkBW := minU64(st.Ad.BandwidthKbps, stages[idx+1].Ad.BandwidthKbps)
				prefillWireUs += transferTimeUs(effPrompt*HiddenStateBytesPerToken, linkBW)
				decodeWirePerTokUs += transferTimeUs(HiddenStateBytesPerToken, linkBW)
			}
		}

		// Pipeline bubble factor during prefill + synchronous WAN stall per token.
		bubbleOverheadUs := (sumPrefillStageUs * uint64(numStages-1)) / uint64(numStages)
		// Every token must traverse the full WAN ring (all hop RTTs + serialization + straggler compute).
		tpotUs := sumHopRTTUs + decodeWirePerTokUs + sumDecodeStageUs
		// Stage GPU occupancy is bounded by local stage compute + wire serialization (WAN flight overlaps across requests).
		stageServiceUs := bottleneckOccupancyUs + prefillWireUs/uint64(numStages)
		queueWaitUs, effBatch := rt.advanceQueue(stages[bottleneckStageIdx].Ad.NodeID, req.ArrivalUs, stageServiceUs, 4)

		ttftUs := queueWaitUs + sumHopRTTUs + prefillWireUs + sumPrefillStageUs + bubbleOverheadUs + tpotUs + totalRecoveryUs
		totalLatencyUs := ttftUs + tpotUs*uint64(maxU32(1, req.MaxOutputTokens)-1)

		// Batching utilization is severely penalized by WAN pipeline bubbles and heterogeneous stragglers.
		utilBps := uint32(2600) + minU32((effBatch-1)*200, 600)
		if failovers > 0 {
			utilBps = maxU32(1200, utilBps-failovers*400)
		}

		for _, res := range resList {
			_ = rt.capacity.Release(res.ReservationID, "COMPLETED")
		}

		chunks := DeterministicOutputChunks(req.PromptSHA256, req.ModelID, req.MaxOutputTokens)
		outRoot := ComputeOutputMerkleRoot(chunks)

		routeIDs := make([]string, len(stages))
		tiers := make([]PrivacyTier, 0, len(stages)+len(failedNodes))
		for i, st := range stages {
			routeIDs[i] = st.Ad.NodeID
			tiers = append(tiers, st.Ad.PrivacyTier)
		}
		for _, fid := range failedNodes {
			if fn, ok := rt.registry.Get(fid); ok {
				tiers = append(tiers, fn.Ad.PrivacyTier)
			}
		}
		primary := stages[len(stages)-1].Ad // final stage emits output tokens & signs receipt
		status := StatusCompleted
		if failovers > 0 {
			status = StatusCompletedFailover
		}

		rcpt := DeliveryReceipt{
			SchemaVersion:           SchemaVersion,
			ReceiptID:               rcptID,
			RequestID:               req.RequestID,
			TopologyMode:            TopologyPetalsPipeline,
			ModelID:                 req.ModelID,
			PromptSHA256:            req.PromptSHA256,
			PromptPrefixSHA256:      req.PromptPrefixSHA256,
			PromptTokens:            req.PromptTokens,
			OutputTokens:            req.MaxOutputTokens,
			OutputMerkleRoot:        outRoot,
			PrivacyRequirement:      req.PrivacyRequirement,
			EffectivePrivacyTier:    EffectiveTierForRoute(tiers),
			RouteNodeIDs:            routeIDs,
			PrimaryProviderID:       primary.NodeID,
			PrefillNodeID:           stages[0].Ad.NodeID,
			DecodeNodeIDs:           routeIDs,
			KVSlotsReserved:         kvPerStage * numStages,
			VRAMReservedMiB:         vramPerStage * uint64(numStages),
			NetworkBytesTransferred: totalNetBytes,
			TTFTUs:                  ttftUs,
			TPOTUs:                  tpotUs,
			TotalLatencyUs:          totalLatencyUs,
			RecoveryLatencyUs:       totalRecoveryUs,
			FailoverAttempts:        failovers,
			FailedNodeIDs:           failedNodes,
			BatchSizeEffective:      effBatch,
			BatchUtilizationBps:     utilBps,
			Status:                  status,
			ProvesScientificTruth:   false,
			AuthorizesTreasurySpend: false,
		}
		if priv, ok := rt.nodeKeys[primary.NodeID]; ok {
			SignDeliveryReceipt(&rcpt, priv)
		}

		return ExecutionOutcome{
			Receipt:        rcpt,
			OutputChunks:   chunks,
			CapacityEvents: rt.capacity.LedgerForRequest(req.RequestID),
			PrefixCacheHit: false,
			QueueWaitUs:    queueWaitUs,
		}, nil
	}

	return rt.buildFailureOutcome(rcptID, req, TopologyPetalsPipeline, StatusFailedExhausted, failedNodes, failovers, totalRecoveryUs, totalExtraNetBytes), nil
}

func (rt *Router) buildFailureOutcome(
	rcptID string,
	req InferenceRequest,
	mode TopologyMode,
	status DeliveryStatus,
	failedNodes []string,
	failovers uint32,
	recoveryUs uint64,
	extraNetBytes uint64,
) ExecutionOutcome {
	// Sign terminal failure receipt with first available key (coordinator/provider accountability).
	var signerID string
	var signerKey ed25519.PrivateKey
	all := rt.registry.All()
	for _, n := range all {
		if k, ok := rt.nodeKeys[n.Ad.NodeID]; ok {
			signerID = n.Ad.NodeID
			signerKey = k
			break
		}
	}
	effTier := PrivacyPublicRelay
	if req.PrivacyRequirement == PrivacyReqStrict {
		effTier = PrivacyTEEAttested
	}
	if len(failedNodes) > 0 {
		tiers := make([]PrivacyTier, 0, len(failedNodes))
		for _, fid := range failedNodes {
			if fn, ok := rt.registry.Get(fid); ok {
				tiers = append(tiers, fn.Ad.PrivacyTier)
			}
		}
		if len(tiers) > 0 {
			effTier = EffectiveTierForRoute(tiers)
		}
	}
	rcpt := DeliveryReceipt{
		SchemaVersion:           SchemaVersion,
		ReceiptID:               rcptID,
		RequestID:               req.RequestID,
		TopologyMode:            mode,
		ModelID:                 req.ModelID,
		PromptSHA256:            req.PromptSHA256,
		PromptPrefixSHA256:      req.PromptPrefixSHA256,
		PromptTokens:            req.PromptTokens,
		OutputTokens:            0,
		OutputMerkleRoot:        ComputeOutputMerkleRoot(nil),
		PrivacyRequirement:      req.PrivacyRequirement,
		EffectivePrivacyTier:    effTier,
		RouteNodeIDs:            []string{},
		PrimaryProviderID:       signerID,
		PrefillNodeID:           "",
		DecodeNodeIDs:           []string{},
		KVSlotsReserved:         0,
		VRAMReservedMiB:         0,
		NetworkBytesTransferred: extraNetBytes,
		TTFTUs:                  0,
		TPOTUs:                  0,
		TotalLatencyUs:          recoveryUs,
		RecoveryLatencyUs:       recoveryUs,
		FailoverAttempts:        failovers,
		FailedNodeIDs:           failedNodes,
		BatchSizeEffective:      0,
		BatchUtilizationBps:     0,
		Status:                  status,
		ProvesScientificTruth:   false,
		AuthorizesTreasurySpend: false,
	}
	if signerKey != nil {
		SignDeliveryReceipt(&rcpt, signerKey)
	}
	return ExecutionOutcome{
		Receipt:        rcpt,
		OutputChunks:   []string{},
		CapacityEvents: rt.capacity.LedgerForRequest(req.RequestID),
	}
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func minU32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func maxU32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

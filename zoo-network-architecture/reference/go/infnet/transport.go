// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package infnet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// WorkerRPCRequest is the JSON wire payload sent over loopback HTTP/1.1 to a live worker.
type WorkerRPCRequest struct {
	RequestID       string `json:"request_id"`
	ModelID         string `json:"model_id"`
	PromptSHA256    string `json:"prompt_sha256"`
	PromptTokens    uint32 `json:"prompt_tokens"`
	MaxOutputTokens uint32 `json:"max_output_tokens"`
	ResumeFromToken uint32 `json:"resume_from_token"`
}

// WorkerRPCResponse is the JSON wire response returned by a live worker node.
type WorkerRPCResponse struct {
	NodeID           string   `json:"node_id"`
	OutputChunks     []string `json:"output_chunks"`
	OutputMerkleRoot string   `json:"output_merkle_root"`
	ProviderPubHex   string   `json:"provider_public_key_hex"`
	ElapsedUs        uint64   `json:"elapsed_us"`
	Error            string   `json:"error,omitempty"`
}

// LoopbackWorker is a live HTTP/1.1 worker bound on 127.0.0.1:<ephemeral>.
type LoopbackWorker struct {
	Ad       NodeAdvertisement
	PrivKey  ed25519.PrivateKey
	Addr     string
	server   *http.Server
	listener net.Listener
	crashed  atomic.Bool
}

// SetCrashed toggles simulated worker crash / HTTP 503 failure injection.
func (w *LoopbackWorker) SetCrashed(v bool) {
	w.crashed.Store(v)
}

// Close gracefully shuts down the worker HTTP server.
func (w *LoopbackWorker) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return w.server.Shutdown(ctx)
}

// StartLoopbackWorker binds a real TCP listener on 127.0.0.1:0 and serves /infer.
func StartLoopbackWorker(ad NodeAdvertisement, priv ed25519.PrivateKey) (*LoopbackWorker, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen loopback worker %s: %w", ad.NodeID, err)
	}
	w := &LoopbackWorker{
		Ad:       ad,
		PrivKey:  priv,
		Addr:     "http://" + ln.Addr().String(),
		listener: ln,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/infer", w.handleInfer)
	w.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		_ = w.server.Serve(ln)
	}()
	return w, nil
}

func (w *LoopbackWorker) handleInfer(rw http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if r.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if w.crashed.Load() {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(rw).Encode(WorkerRPCResponse{
			NodeID: w.Ad.NodeID,
			Error:  "worker crashed mid-generation",
		})
		return
	}
	var req WorkerRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(rw, "bad json", http.StatusBadRequest)
		return
	}
	chunks := DeterministicOutputChunks(req.PromptSHA256, req.ModelID, req.MaxOutputTokens)
	outRoot := ComputeOutputMerkleRoot(chunks)
	elapsed := uint64(time.Since(start).Microseconds())
	if elapsed == 0 {
		elapsed = 1
	}
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(WorkerRPCResponse{
		NodeID:           w.Ad.NodeID,
		OutputChunks:     chunks,
		OutputMerkleRoot: outRoot,
		ProviderPubHex:   w.Ad.PublicKeyHex,
		ElapsedUs:        elapsed,
	})
}

// LoopbackCluster orchestrates real HTTP/1.1 worker nodes with Registry, CapacityAccountant, and live failover.
type LoopbackCluster struct {
	mu       sync.RWMutex
	Registry *Registry
	Capacity *CapacityAccountant
	workers  map[string]*LoopbackWorker
	client   *http.Client
	seq      atomic.Uint64
}

// NewLoopbackCluster initializes a real TCP/HTTP worker cluster.
func NewLoopbackCluster() *LoopbackCluster {
	return &LoopbackCluster{
		Registry: NewRegistry(),
		Capacity: NewCapacityAccountant(),
		workers:  make(map[string]*LoopbackWorker),
		client:   &http.Client{Timeout: 3 * time.Second},
	}
}

// AddWorker starts a loopback worker, registers its Ed25519 advertisement, and tracks its capacity.
func (c *LoopbackCluster) AddWorker(ad NodeAdvertisement, priv ed25519.PrivateKey) (*LoopbackWorker, error) {
	if err := c.Registry.Register(ad); err != nil {
		return nil, err
	}
	c.Capacity.TrackNode(ad)
	w, err := StartLoopbackWorker(ad, priv)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.workers[ad.NodeID] = w
	c.mu.Unlock()
	return w, nil
}

// Close shuts down all loopback worker servers.
func (c *LoopbackCluster) Close() {
	c.mu.Lock()
	ws := make([]*LoopbackWorker, 0, len(c.workers))
	for _, w := range c.workers {
		ws = append(ws, w)
	}
	c.mu.Unlock()
	for _, w := range ws {
		_ = w.Close()
	}
}

// Dispatch executes a live HTTP/1.1 request with strict privacy enforcement, atomic capacity
// reservation/release, live failover on HTTP 503/network error, and Ed25519 DeliveryReceipt signing.
func (c *LoopbackCluster) Dispatch(ctx context.Context, req InferenceRequest, mode TopologyMode) (ExecutionOutcome, error) {
	startAll := time.Now()
	excluded := make(map[string]bool)
	failedNodes := make([]string, 0, 2)
	var failovers uint32
	var recoveryUs uint64
	var totalBytes uint64

	rcptID := fmt.Sprintf("rcpt-live-%06d", c.seq.Add(1))

	for attempt := 0; attempt < 4; attempt++ {
		cands := c.Registry.Discover(DiscoveryQuery{
			ModelID:            req.ModelID,
			PrivacyRequirement: req.PrivacyRequirement,
			HealthyOnly:        true,
		})
		var chosen *RegisteredNode
		for i := range cands {
			if !excluded[cands[i].Ad.NodeID] {
				chosen = &cands[i]
				break
			}
		}
		if chosen == nil {
			if req.PrivacyRequirement == PrivacyReqStrict {
				return ExecutionOutcome{}, ErrPrivacyBoundaryViolation
			}
			return ExecutionOutcome{}, ErrNoHealthyNodes
		}
		if err := EnforcePrivacyBoundary(req.PrivacyRequirement, []NodeAdvertisement{chosen.Ad}); err != nil {
			return ExecutionOutcome{PrivacyLeak: true}, err
		}

		vramMiB, kvSlots := EstimateRequestResources(req.PromptTokens, req.MaxOutputTokens, DefaultTotalLayers, DefaultTotalLayers)
		res, err := c.Capacity.Reserve(chosen.Ad.NodeID, req.RequestID, vramMiB, kvSlots, req.PromptPrefixSHA256)
		if err != nil {
			excluded[chosen.Ad.NodeID] = true
			continue
		}

		c.mu.RLock()
		worker := c.workers[chosen.Ad.NodeID]
		c.mu.RUnlock()

		wireReq := WorkerRPCRequest{
			RequestID:       req.RequestID,
			ModelID:         req.ModelID,
			PromptSHA256:    req.PromptSHA256,
			PromptTokens:    req.PromptTokens,
			MaxOutputTokens: req.MaxOutputTokens,
		}
		body, _ := json.Marshal(wireReq)
		totalBytes += uint64(len(body))

		attemptStart := time.Now()
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, worker.Addr+"/infer", bytes.NewReader(body))
		if err != nil {
			_ = c.Capacity.Release(res.ReservationID, "RPC_BUILD_ERROR")
			return ExecutionOutcome{}, err
		}
		httpReq.Header.Set("Content-Type", "application/json")
		resp, err := c.client.Do(httpReq)
		if err != nil || resp.StatusCode != http.StatusOK {
			if resp != nil {
				_ = resp.Body.Close()
			}
			// Release capacity immediately on failure -> ZERO LEAKS!
			_ = c.Capacity.Release(res.ReservationID, "LIVE_FAILOVER_ABORT")
			c.Registry.SetHealth(chosen.Ad.NodeID, HealthFailed)
			failedNodes = append(failedNodes, chosen.Ad.NodeID)
			excluded[chosen.Ad.NodeID] = true
			failovers++
			recoveryUs += uint64(time.Since(attemptStart).Microseconds()) + 1
			continue
		}

		var rpcResp WorkerRPCResponse
		decErr := json.NewDecoder(resp.Body).Decode(&rpcResp)
		_ = resp.Body.Close()
		if decErr != nil {
			_ = c.Capacity.Release(res.ReservationID, "DECODE_ERROR")
			return ExecutionOutcome{}, decErr
		}
		respBytes, _ := json.Marshal(rpcResp)
		totalBytes += uint64(len(respBytes))

		_ = c.Capacity.Release(res.ReservationID, "COMPLETED")

		totalUs := uint64(time.Since(startAll).Microseconds())
		if totalUs == 0 {
			totalUs = 1
		}
		tpotUs := totalUs / uint64(maxU32(1, req.MaxOutputTokens))
		if tpotUs == 0 {
			tpotUs = 1
		}
		status := StatusCompleted
		if failovers > 0 {
			status = StatusCompletedFailover
		}

		tiers := []PrivacyTier{chosen.Ad.PrivacyTier}
		for _, fid := range failedNodes {
			if fn, ok := c.Registry.Get(fid); ok {
				tiers = append(tiers, fn.Ad.PrivacyTier)
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
			OutputTokens:            req.MaxOutputTokens,
			OutputMerkleRoot:        rpcResp.OutputMerkleRoot,
			PrivacyRequirement:      req.PrivacyRequirement,
			EffectivePrivacyTier:    EffectiveTierForRoute(tiers),
			RouteNodeIDs:            []string{chosen.Ad.NodeID},
			PrimaryProviderID:       chosen.Ad.NodeID,
			PrefillNodeID:           chosen.Ad.NodeID,
			DecodeNodeIDs:           []string{chosen.Ad.NodeID},
			KVSlotsReserved:         kvSlots,
			VRAMReservedMiB:         vramMiB,
			NetworkBytesTransferred: totalBytes,
			TTFTUs:                  totalUs,
			TPOTUs:                  tpotUs,
			TotalLatencyUs:          totalUs,
			RecoveryLatencyUs:       recoveryUs,
			FailoverAttempts:        failovers,
			FailedNodeIDs:           failedNodes,
			BatchSizeEffective:      1,
			BatchUtilizationBps:     7500,
			Status:                  status,
			ProvesScientificTruth:   false,
			AuthorizesTreasurySpend: false,
		}
		SignDeliveryReceipt(&rcpt, worker.PrivKey)

		return ExecutionOutcome{
			Receipt:        rcpt,
			OutputChunks:   rpcResp.OutputChunks,
			CapacityEvents: c.Capacity.LedgerForRequest(req.RequestID),
		}, nil
	}
	return ExecutionOutcome{}, ErrNoHealthyNodes
}

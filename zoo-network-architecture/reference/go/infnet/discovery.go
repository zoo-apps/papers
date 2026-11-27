// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package infnet

import (
	"fmt"
	"sort"
	"sync"
)

// NodeHealth tracks live availability status of a registered node.
type NodeHealth string

const (
	HealthHealthy  NodeHealth = "HEALTHY"
	HealthDegraded NodeHealth = "DEGRADED"
	HealthFailed   NodeHealth = "FAILED"
)

// RegisteredNode holds the verified advertisement plus live registry state.
type RegisteredNode struct {
	Ad     NodeAdvertisement
	Health NodeHealth
}

// DiscoveryQuery filters active nodes in the permissionless registry.
type DiscoveryQuery struct {
	ModelID            string
	Role               ExecutionRole // empty matches any role
	LayerStart         uint32
	LayerEnd           uint32 // 0 disables layer range check
	PrivacyRequirement PrivacyRequirement
	HealthyOnly        bool
}

// ValidateNodeAdvertisement checks structural invariants and RFC 8032 Ed25519 signature.
func ValidateNodeAdvertisement(a NodeAdvertisement) (string, error) {
	if a.SchemaVersion != SchemaVersion {
		return ErrCodeInvalidNodeAdvertisement, fmt.Errorf("unsupported schema_version %q", a.SchemaVersion)
	}
	if a.NodeID == "" || a.ModelID == "" {
		return ErrCodeInvalidNodeAdvertisement, fmt.Errorf("node_id and model_id must be non-empty")
	}
	if !IsValidHardwareProfile(a.HardwareProfile) {
		return ErrCodeInvalidNodeAdvertisement, fmt.Errorf("invalid hardware_profile %q", a.HardwareProfile)
	}
	if !IsValidExecutionRole(a.ExecutionRole) {
		return ErrCodeInvalidNodeAdvertisement, fmt.Errorf("invalid execution_role %q", a.ExecutionRole)
	}
	if !IsValidPrivacyTier(a.PrivacyTier) {
		return ErrCodeInvalidNodeAdvertisement, fmt.Errorf("invalid privacy_tier %q", a.PrivacyTier)
	}
	if a.TotalLayers == 0 || a.LayerStart >= a.LayerEnd || a.LayerEnd > a.TotalLayers {
		return ErrCodeInvalidNodeAdvertisement, fmt.Errorf("invalid layer range [%d,%d) for total %d", a.LayerStart, a.LayerEnd, a.TotalLayers)
	}
	if a.ExecutionRole == RoleWholeModel && (a.LayerStart != 0 || a.LayerEnd != a.TotalLayers) {
		return ErrCodeInvalidNodeAdvertisement, fmt.Errorf("WHOLE_MODEL node must serve all layers [0,%d)", a.TotalLayers)
	}
	if a.VRAMTotalMiB == 0 || a.VRAMReservedBaseMiB > a.VRAMTotalMiB {
		return ErrCodeInvalidNodeAdvertisement, fmt.Errorf("invalid VRAM bounds base=%d total=%d", a.VRAMReservedBaseMiB, a.VRAMTotalMiB)
	}
	if a.KVSlotsTotal == 0 || a.PrefillTPS == 0 || a.DecodeTPS == 0 || a.BandwidthKbps == 0 {
		return ErrCodeInvalidNodeAdvertisement, fmt.Errorf("capacity and throughput fields must be positive")
	}
	if a.HeartbeatEpoch == 0 {
		return ErrCodeInvalidNodeAdvertisement, fmt.Errorf("heartbeat_epoch must be >= 1")
	}
	if a.PrivacyTier == PrivacyTEEAttested && len(a.TEEAttestationSHA) != 64 {
		return ErrCodeInvalidNodeAdvertisement, fmt.Errorf("TEE_ATTESTED node requires 64-hex tee_attestation_sha256")
	}
	if !VerifyNodeAdvertisementSignature(a) {
		return ErrCodeInvalidNodeAdvertisement, fmt.Errorf("Ed25519 signature verification failed for node %s", a.NodeID)
	}
	return ErrCodeOK, nil
}

// Registry is a concurrency-safe permissionless worker discovery directory.
type Registry struct {
	mu    sync.RWMutex
	nodes map[string]*RegisteredNode
}

// NewRegistry creates an empty permissionless worker registry.
func NewRegistry() *Registry {
	return &Registry{
		nodes: make(map[string]*RegisteredNode),
	}
}

// Register validates and registers or updates a signed NodeAdvertisement.
// Enforces key pinning per node_id and strictly monotonic heartbeat_epoch.
func (r *Registry) Register(ad NodeAdvertisement) error {
	if _, err := ValidateNodeAdvertisement(ad); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, ok := r.nodes[ad.NodeID]; ok {
		if existing.Ad.PublicKeyHex != ad.PublicKeyHex {
			return fmt.Errorf("%w: node %s key mismatch", ErrKeyMismatch, ad.NodeID)
		}
		if ad.HeartbeatEpoch <= existing.Ad.HeartbeatEpoch {
			return fmt.Errorf("%w: node %s epoch %d <= %d", ErrStaleHeartbeatEpoch, ad.NodeID, ad.HeartbeatEpoch, existing.Ad.HeartbeatEpoch)
		}
		existing.Ad = ad
		existing.Health = HealthHealthy
		return nil
	}

	r.nodes[ad.NodeID] = &RegisteredNode{
		Ad:     ad,
		Health: HealthHealthy,
	}
	return nil
}

// SetHealth updates the live health state of a registered node.
func (r *Registry) SetHealth(nodeID string, health NodeHealth) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, ok := r.nodes[nodeID]
	if !ok {
		return false
	}
	n.Health = health
	return true
}

// Get returns a snapshot of a single registered node.
func (r *Registry) Get(nodeID string) (RegisteredNode, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n, ok := r.nodes[nodeID]
	if !ok {
		return RegisteredNode{}, false
	}
	return *n, true
}

// All returns all registered nodes sorted deterministically by node_id.
func (r *Registry) All() []RegisteredNode {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]RegisteredNode, 0, len(r.nodes))
	for _, n := range r.nodes {
		out = append(out, *n)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Ad.NodeID < out[j].Ad.NodeID
	})
	return out
}

// Discover returns matching nodes sorted deterministically by node_id.
func (r *Registry) Discover(q DiscoveryQuery) []RegisteredNode {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]RegisteredNode, 0, len(r.nodes))
	for _, n := range r.nodes {
		if q.HealthyOnly && n.Health != HealthHealthy {
			continue
		}
		if q.ModelID != "" && n.Ad.ModelID != q.ModelID {
			continue
		}
		if q.Role != "" && n.Ad.ExecutionRole != q.Role {
			continue
		}
		if q.LayerEnd > 0 && (n.Ad.LayerStart > q.LayerStart || n.Ad.LayerEnd < q.LayerEnd) {
			continue
		}
		if q.PrivacyRequirement != "" && !PrivacyTierSatisfies(q.PrivacyRequirement, n.Ad.PrivacyTier) {
			continue
		}
		out = append(out, *n)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Ad.NodeID < out[j].Ad.NodeID
	})
	return out
}

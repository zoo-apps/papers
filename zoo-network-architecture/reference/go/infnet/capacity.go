// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package infnet

import (
	"fmt"
	"sync"
)

// NodeCapacitySnapshot captures point-in-time VRAM & KV-slot utilization.
type NodeCapacitySnapshot struct {
	NodeID              string
	VRAMTotalMiB        uint64
	VRAMReservedBaseMiB uint64
	VRAMInUseMiB        uint64
	KVSlotsTotal        uint32
	KVSlotsInUse        uint32
	ActiveReservations  int
}

type nodeCapState struct {
	vramTotalMiB        uint64
	vramReservedBaseMiB uint64
	vramInUseMiB        uint64
	kvSlotsTotal        uint32
	kvSlotsInUse        uint32
	prefixCache         map[string]uint64 // prompt_prefix_sha256 -> last access seq
}

// Reservation represents an active atomic VRAM + KV-slot hold on a node.
type Reservation struct {
	ReservationID string
	NodeID        string
	RequestID     string
	VRAMMiB       uint64
	KVSlots       uint32
	PrefixSHA256  string
	Released      bool
}

// CapacityAccountant enforces strict VRAM + KV-slot conservation across all nodes.
type CapacityAccountant struct {
	mu           sync.Mutex
	nodes        map[string]*nodeCapState
	reservations map[string]*Reservation
	ledger       []CapacityEvent
	nextSeq      uint64
	nextResID    uint64
}

// NewCapacityAccountant creates a new strict capacity accountant.
func NewCapacityAccountant() *CapacityAccountant {
	return &CapacityAccountant{
		nodes:        make(map[string]*nodeCapState),
		reservations: make(map[string]*Reservation),
		ledger:       make([]CapacityEvent, 0, 256),
	}
}

// TrackNode initializes or updates capacity bounds for a registered node.
func (ca *CapacityAccountant) TrackNode(ad NodeAdvertisement) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if st, ok := ca.nodes[ad.NodeID]; ok {
		st.vramTotalMiB = ad.VRAMTotalMiB
		st.vramReservedBaseMiB = ad.VRAMReservedBaseMiB
		st.kvSlotsTotal = ad.KVSlotsTotal
		return
	}
	ca.nodes[ad.NodeID] = &nodeCapState{
		vramTotalMiB:        ad.VRAMTotalMiB,
		vramReservedBaseMiB: ad.VRAMReservedBaseMiB,
		kvSlotsTotal:        ad.KVSlotsTotal,
		prefixCache:         make(map[string]uint64),
	}
}

// Reserve atomically reserves VRAM and KV-cache slots on nodeID.
func (ca *CapacityAccountant) Reserve(nodeID, requestID string, vramMiB uint64, kvSlots uint32, prefixSHA string) (Reservation, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	st, ok := ca.nodes[nodeID]
	if !ok {
		return Reservation{}, fmt.Errorf("%w: unknown node %s", ErrCapacityExhausted, nodeID)
	}
	if st.vramReservedBaseMiB+st.vramInUseMiB+vramMiB > st.vramTotalMiB {
		return Reservation{}, fmt.Errorf("%w: node %s VRAM limit (%d+%d+%d > %d)",
			ErrCapacityExhausted, nodeID, st.vramReservedBaseMiB, st.vramInUseMiB, vramMiB, st.vramTotalMiB)
	}
	if st.kvSlotsInUse+kvSlots > st.kvSlotsTotal {
		return Reservation{}, fmt.Errorf("%w: node %s KV slot limit (%d+%d > %d)",
			ErrCapacityExhausted, nodeID, st.kvSlotsInUse, kvSlots, st.kvSlotsTotal)
	}

	ca.nextResID++
	ca.nextSeq++
	resID := fmt.Sprintf("res-%s-%06d", nodeID, ca.nextResID)

	st.vramInUseMiB += vramMiB
	st.kvSlotsInUse += kvSlots
	if prefixSHA != "" {
		st.prefixCache[prefixSHA] = ca.nextSeq
	}

	res := &Reservation{
		ReservationID: resID,
		NodeID:        nodeID,
		RequestID:     requestID,
		VRAMMiB:       vramMiB,
		KVSlots:       kvSlots,
		PrefixSHA256:  prefixSHA,
	}
	ca.reservations[resID] = res
	ca.ledger = append(ca.ledger, CapacityEvent{
		Seq:           ca.nextSeq,
		Action:        "RESERVE",
		ReservationID: resID,
		NodeID:        nodeID,
		RequestID:     requestID,
		VRAMMiB:       vramMiB,
		KVSlots:       kvSlots,
		Reason:        "ADMIT",
	})
	return *res, nil
}

// Release idempotently releases a prior reservation, ensuring zero leaks on success or failure.
func (ca *CapacityAccountant) Release(reservationID, reason string) error {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	res, ok := ca.reservations[reservationID]
	if !ok {
		return fmt.Errorf("unknown reservation %s", reservationID)
	}
	if res.Released {
		return nil // idempotent release prevents double-free underflow
	}
	st, ok := ca.nodes[res.NodeID]
	if !ok {
		return fmt.Errorf("unknown node %s for reservation %s", res.NodeID, reservationID)
	}
	if st.vramInUseMiB < res.VRAMMiB || st.kvSlotsInUse < res.KVSlots {
		return fmt.Errorf("capacity underflow on node %s", res.NodeID)
	}

	st.vramInUseMiB -= res.VRAMMiB
	st.kvSlotsInUse -= res.KVSlots
	res.Released = true
	ca.nextSeq++
	ca.ledger = append(ca.ledger, CapacityEvent{
		Seq:           ca.nextSeq,
		Action:        "RELEASE",
		ReservationID: res.ReservationID,
		NodeID:        res.NodeID,
		RequestID:     res.RequestID,
		VRAMMiB:       res.VRAMMiB,
		KVSlots:       res.KVSlots,
		Reason:        reason,
	})
	return nil
}

// HasPrefixCache reports whether nodeID holds a warm KV prefix for prefixSHA.
func (ca *CapacityAccountant) HasPrefixCache(nodeID, prefixSHA string) bool {
	if prefixSHA == "" {
		return false
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	st, ok := ca.nodes[nodeID]
	if !ok {
		return false
	}
	_, hit := st.prefixCache[prefixSHA]
	return hit
}

// Snapshot returns current VRAM & KV usage for nodeID.
func (ca *CapacityAccountant) Snapshot(nodeID string) (NodeCapacitySnapshot, bool) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	st, ok := ca.nodes[nodeID]
	if !ok {
		return NodeCapacitySnapshot{}, false
	}
	active := 0
	for _, r := range ca.reservations {
		if r.NodeID == nodeID && !r.Released {
			active++
		}
	}
	return NodeCapacitySnapshot{
		NodeID:              nodeID,
		VRAMTotalMiB:        st.vramTotalMiB,
		VRAMReservedBaseMiB: st.vramReservedBaseMiB,
		VRAMInUseMiB:        st.vramInUseMiB,
		KVSlotsTotal:        st.kvSlotsTotal,
		KVSlotsInUse:        st.kvSlotsInUse,
		ActiveReservations:  active,
	}, true
}

// ActiveLeaks returns the total unreleased VRAM (MiB) and KV slots across all nodes.
func (ca *CapacityAccountant) ActiveLeaks() (leakedVRAM uint64, leakedSlots uint32, activeCount int) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	for _, r := range ca.reservations {
		if !r.Released {
			leakedVRAM += r.VRAMMiB
			leakedSlots += r.KVSlots
			activeCount++
		}
	}
	return leakedVRAM, leakedSlots, activeCount
}

// Ledger returns a copy of all capacity events recorded so far.
func (ca *CapacityAccountant) Ledger() []CapacityEvent {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	out := make([]CapacityEvent, len(ca.ledger))
	copy(out, ca.ledger)
	return out
}

// LedgerForRequest returns all capacity events associated with a specific requestID.
func (ca *CapacityAccountant) LedgerForRequest(requestID string) []CapacityEvent {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	out := make([]CapacityEvent, 0, 8)
	for _, ev := range ca.ledger {
		if ev.RequestID == requestID {
			out = append(out, ev)
		}
	}
	return out
}

// VerifyCapacityConservation replays a capacity event ledger against node bounds
// and verifies: (1) strict monotonic seq, (2) zero VRAM/KV-slot oversubscription,
// (3) no double-release or unknown release, and (4) zero final leaked VRAM/KV slots.
func VerifyCapacityConservation(nodes map[string]NodeAdvertisement, ledger []CapacityEvent) (bool, string) {
	vramInUse := make(map[string]uint64, len(nodes))
	kvInUse := make(map[string]uint32, len(nodes))
	type openRes struct {
		nodeID  string
		vramMiB uint64
		kvSlots uint32
	}
	active := make(map[string]openRes)
	seenRes := make(map[string]bool)

	var prevSeq uint64
	for _, ev := range ledger {
		if ev.Seq <= prevSeq {
			return false, fmt.Sprintf("non-monotonic capacity event seq %d <= %d", ev.Seq, prevSeq)
		}
		prevSeq = ev.Seq

		ad, ok := nodes[ev.NodeID]
		if !ok {
			return false, fmt.Sprintf("capacity event references unknown node %s", ev.NodeID)
		}

		switch ev.Action {
		case "RESERVE":
			if seenRes[ev.ReservationID] {
				return false, fmt.Sprintf("duplicate reservation id %s", ev.ReservationID)
			}
			if ad.VRAMReservedBaseMiB+vramInUse[ev.NodeID]+ev.VRAMMiB > ad.VRAMTotalMiB {
				return false, fmt.Sprintf("VRAM oversubscription on %s: %d+%d+%d > %d",
					ev.NodeID, ad.VRAMReservedBaseMiB, vramInUse[ev.NodeID], ev.VRAMMiB, ad.VRAMTotalMiB)
			}
			if kvInUse[ev.NodeID]+ev.KVSlots > ad.KVSlotsTotal {
				return false, fmt.Sprintf("KV slot oversubscription on %s: %d+%d > %d",
					ev.NodeID, kvInUse[ev.NodeID], ev.KVSlots, ad.KVSlotsTotal)
			}
			vramInUse[ev.NodeID] += ev.VRAMMiB
			kvInUse[ev.NodeID] += ev.KVSlots
			active[ev.ReservationID] = openRes{nodeID: ev.NodeID, vramMiB: ev.VRAMMiB, kvSlots: ev.KVSlots}
			seenRes[ev.ReservationID] = true

		case "RELEASE":
			open, ok := active[ev.ReservationID]
			if !ok {
				return false, fmt.Sprintf("release of non-active or already-released reservation %s", ev.ReservationID)
			}
			if open.nodeID != ev.NodeID || open.vramMiB != ev.VRAMMiB || open.kvSlots != ev.KVSlots {
				return false, fmt.Sprintf("release mismatch for reservation %s", ev.ReservationID)
			}
			vramInUse[ev.NodeID] -= ev.VRAMMiB
			kvInUse[ev.NodeID] -= ev.KVSlots
			delete(active, ev.ReservationID)

		default:
			return false, fmt.Sprintf("unknown capacity action %q", ev.Action)
		}
	}

	if len(active) > 0 {
		return false, fmt.Sprintf("capacity leak detected: %d unreleased reservation(s)", len(active))
	}
	for nid, v := range vramInUse {
		if v != 0 || kvInUse[nid] != 0 {
			return false, fmt.Sprintf("nonzero residual capacity on node %s (vram=%d, kv=%d)", nid, v, kvInUse[nid])
		}
	}
	return true, ErrCodeOK
}

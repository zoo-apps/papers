// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"crypto/ed25519"
	"fmt"
	"sync"
)

// ConcurrentStore is a goroutine-safe, append-only event log backed by a VFSObjectStore.
// Multiple concurrent writers may append artifacts and signed events simultaneously;
// Replay converges deterministically regardless of append interleaving.
type ConcurrentStore struct {
	mu         sync.RWMutex
	policy     Policy
	principals map[string]Principal
	pubKeys    map[string]ed25519.PublicKey
	vfs        VFSObjectStore
	events     []Event
	seenIDs    map[string]struct{}
}

// NewConcurrentStore initializes a thread-safe ledger store bound to Policy and VFSObjectStore.
func NewConcurrentStore(policy Policy, vfs VFSObjectStore) (*ConcurrentStore, error) {
	principals, pubKeys, err := ValidatePolicy(policy)
	if err != nil {
		return nil, err
	}
	return &ConcurrentStore{
		policy:     policy,
		principals: principals,
		pubKeys:    pubKeys,
		vfs:        vfs,
		events:     make([]Event, 0),
		seenIDs:    make(map[string]struct{}),
	}, nil
}

// AppendArtifact writes raw research bytes into the VFS/S3 object store.
func (s *ConcurrentStore) AppendArtifact(data []byte) (ObjectPutResult, error) {
	if s.vfs == nil {
		return ObjectPutResult{}, fmt.Errorf("no VFSObjectStore configured")
	}
	return s.vfs.Put(data)
}

// AppendEvent appends an event to the concurrent log (accepting raw events so even
// invalid/adversarial events can be audited through deterministic Replay).
func (s *ConcurrentStore) AppendEvent(e Event) (dedup bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.EventID != "" {
		if _, ok := s.seenIDs[e.EventID]; ok {
			return true
		}
		s.seenIDs[e.EventID] = struct{}{}
	}
	s.events = append(s.events, e)
	return false
}

// EventsSnapshot returns a copy of all currently logged events.
func (s *ConcurrentStore) EventsSnapshot() []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Event, len(s.events))
	copy(out, s.events)
	return out
}

// Reconstruct replays all logged events into a canonical ReconstructedState.
func (s *ConcurrentStore) Reconstruct() (ReconstructedState, error) {
	events := s.EventsSnapshot()
	return Replay(s.policy, events)
}

// ExportBundle exports the Policy and all logged events as a portable LedgerBundle.
func (s *ConcurrentStore) ExportBundle() LedgerBundle {
	return LedgerBundle{
		SchemaVersion: SchemaVersion,
		Policy:        s.policy,
		Events:        s.EventsSnapshot(),
	}
}

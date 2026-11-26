// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation & Open ResearchDAO Contributors.

package daoos

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// WAL manages crash-safe append-only disk persistence (genesis.json, events.jsonl with fsync,
// and verified checkpoints/) for cold-restart replay.
type WAL struct {
	dir        string
	eventsPath string
	file       *os.File
	fsync      bool
}

// OpenWAL opens or initializes a durable WAL directory with fsync enabled by default.
func OpenWAL(dir string, genesis *Genesis, fsync bool) (*WAL, error) {
	if err := os.MkdirAll(filepath.Join(dir, "checkpoints"), 0o755); err != nil {
		return nil, fmt.Errorf("create wal dir: %w", err)
	}
	genPath := filepath.Join(dir, "genesis.json")
	if genesis != nil {
		raw, err := CanonicalJSON(normalizeGenesis(*genesis))
		if err != nil {
			return nil, err
		}
		if err := writeFileAtomic(genPath, append(raw, '\n'), fsync); err != nil {
			return nil, fmt.Errorf("write genesis: %w", err)
		}
	}
	eventsPath := filepath.Join(dir, "events.jsonl")
	f, err := os.OpenFile(eventsPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open events.jsonl: %w", err)
	}
	return &WAL{
		dir:        dir,
		eventsPath: eventsPath,
		file:       f,
		fsync:      fsync,
	}, nil
}

// Close flushes and closes the WAL file handle.
func (w *WAL) Close() error {
	if w.file == nil {
		return nil
	}
	if w.fsync {
		_ = w.file.Sync()
	}
	err := w.file.Close()
	w.file = nil
	return err
}

// AppendEnvelope serializes an Envelope in canonical JSON, writes one line, and fsyncs to disk.
func (w *WAL) AppendEnvelope(env Envelope) error {
	raw, err := CanonicalJSON(map[string]any{
		"spec_version":    env.SpecVersion,
		"seq":             env.Seq,
		"prev_event_hash": env.PrevEventHash,
		"timestamp":       env.Timestamp,
		"actor_id":        env.ActorID,
		"nonce":           env.Nonce,
		"type":            string(env.Type),
		"payload":         env.Payload,
		"signature_hex":   env.SignatureHex,
	})
	if err != nil {
		return err
	}
	line := append(raw, '\n')
	if _, err := w.file.Write(line); err != nil {
		return err
	}
	if w.fsync {
		if err := w.file.Sync(); err != nil {
			return err
		}
	}
	return nil
}

// WriteCheckpoint persists a verified checkpoint snapshot atomically to checkpoints/checkpoint_<seq>.json.
func (w *WAL) WriteCheckpoint(cp Checkpoint) (string, error) {
	raw, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return "", err
	}
	name := fmt.Sprintf("checkpoint_%08d.json", cp.Seq)
	path := filepath.Join(w.dir, "checkpoints", name)
	if err := writeFileAtomic(path, append(raw, '\n'), w.fsync); err != nil {
		return "", err
	}
	return path, nil
}

// ReadGenesis loads genesis.json from a WAL directory.
func ReadGenesis(dir string) (Genesis, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "genesis.json"))
	if err != nil {
		return Genesis{}, err
	}
	var g Genesis
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&g); err != nil {
		return Genesis{}, NewTransitionError(ErrWALTampered, fmt.Sprintf("corrupt genesis.json: %v", err))
	}
	return g, nil
}

// ReadEnvelopes reads all envelopes from events.jsonl with strict UseNumber decoding.
func ReadEnvelopes(dir string) ([]Envelope, error) {
	f, err := os.Open(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		if os.IsNotExist(err) {
			return []Envelope{}, nil
		}
		return nil, err
	}
	defer f.Close()

	var envs []Envelope
	sc := bufio.NewScanner(f)
	// Support large payloads up to 4 MiB per event line.
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var env Envelope
		dec := json.NewDecoder(strings.NewReader(line))
		dec.UseNumber()
		if err := dec.Decode(&env); err != nil {
			return nil, NewTransitionError(ErrWALTampered, fmt.Sprintf("corrupt json at events.jsonl line %d: %v", lineNo, err))
		}
		envs = append(envs, env)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return envs, nil
}

// ReplayFull performs a cold-start full replay from genesis.json + every envelope in events.jsonl,
// re-verifying every Ed25519 signature, hash-chain link, and constitutional invariant.
func ReplayFull(dir string) (*Machine, error) {
	g, err := ReadGenesis(dir)
	if err != nil {
		return nil, err
	}
	m, err := NewMachine(g)
	if err != nil {
		return nil, err
	}
	envs, err := ReadEnvelopes(dir)
	if err != nil {
		return nil, err
	}
	for _, env := range envs {
		if _, err := m.applyLocked(env, false); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// ReplayFromLatestCheckpoint loads the highest-sequence verified checkpoint in dir/checkpoints/,
// verifies its genesis hash, state root hash, and audit Merkle root, and replays only delta
// envelopes with seq > checkpoint.Seq. If no checkpoint exists, it falls back to ReplayFull.
func ReplayFromLatestCheckpoint(dir string) (*Machine, uint64, error) {
	cpPath, err := latestCheckpointPath(dir)
	if err != nil {
		return nil, 0, err
	}
	if cpPath == "" {
		m, err := ReplayFull(dir)
		return m, 0, err
	}
	m, cpSeq, err := ReplayFromCheckpointFile(dir, cpPath)
	return m, cpSeq, err
}

// ReplayFromCheckpointFile loads a specific checkpoint file, validates its cryptographic integrity,
// and replays all delta WAL events after checkpoint.Seq.
func ReplayFromCheckpointFile(dir string, cpPath string) (*Machine, uint64, error) {
	g, err := ReadGenesis(dir)
	if err != nil {
		return nil, 0, err
	}
	genHash, err := HashGenesis(g)
	if err != nil {
		return nil, 0, err
	}
	raw, err := os.ReadFile(cpPath)
	if err != nil {
		return nil, 0, err
	}
	var cp Checkpoint
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&cp); err != nil {
		return nil, 0, NewTransitionError(ErrWALTampered, fmt.Sprintf("corrupt checkpoint json: %v", err))
	}
	if cp.SpecVersion != SpecVersion {
		return nil, 0, NewTransitionError(ErrWALTampered, "checkpoint spec_version mismatch")
	}
	if cp.GenesisHash != genHash || cp.State.GenesisHash != genHash {
		return nil, 0, NewTransitionError(ErrWALTampered, "checkpoint genesis_hash mismatch")
	}
	// Ensure maps are non-nil before hashing.
	st := deepCopyState(&cp.State)
	computedSR, err := StateRootHash(&st)
	if err != nil {
		return nil, 0, err
	}
	if computedSR != cp.StateRootHash {
		return nil, 0, NewTransitionError(ErrWALTampered, fmt.Sprintf("checkpoint state_root_hash mismatch: expected %s, got %s", cp.StateRootHash, computedSR))
	}
	computedAR, err := AuditMerkleRoot(cp.EventHashes)
	if err != nil {
		return nil, 0, NewTransitionError(ErrWALTampered, fmt.Sprintf("checkpoint event_hashes invalid: %v", err))
	}
	if computedAR != cp.AuditMerkleRoot {
		return nil, 0, NewTransitionError(ErrWALTampered, fmt.Sprintf("checkpoint audit_merkle_root mismatch: expected %s, got %s", cp.AuditMerkleRoot, computedAR))
	}
	if uint64(len(cp.EventHashes)) != cp.Seq || st.Seq != cp.Seq {
		return nil, 0, NewTransitionError(ErrWALTampered, "checkpoint seq/event_hashes count mismatch")
	}
	if cp.Seq > 0 && cp.EventHashes[cp.Seq-1] != cp.LastEventHash {
		return nil, 0, NewTransitionError(ErrWALTampered, "checkpoint last_event_hash mismatch")
	}

	m := &Machine{
		genesis:     g,
		state:       st,
		eventHashes: append([]string{}, cp.EventHashes...),
	}
	envs, err := ReadEnvelopes(dir)
	if err != nil {
		return nil, 0, err
	}
	for _, env := range envs {
		if env.Seq <= cp.Seq {
			continue
		}
		if _, err := m.applyLocked(env, false); err != nil {
			return nil, 0, err
		}
	}
	return m, cp.Seq, nil
}

func latestCheckpointPath(dir string) (string, error) {
	cpDir := filepath.Join(dir, "checkpoints")
	entries, err := os.ReadDir(cpDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	type item struct {
		seq  uint64
		path string
	}
	var items []item
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "checkpoint_") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		numStr := strings.TrimSuffix(strings.TrimPrefix(e.Name(), "checkpoint_"), ".json")
		seq, err := strconv.ParseUint(numStr, 10, 64)
		if err != nil {
			continue
		}
		items = append(items, item{seq: seq, path: filepath.Join(cpDir, e.Name())})
	}
	if len(items) == 0 {
		return "", nil
	}
	sort.Slice(items, func(i, j int) bool { return items[i].seq < items[j].seq })
	return items[len(items)-1].path, nil
}

func writeFileAtomic(path string, data []byte, fsync bool) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if fsync {
		if err := f.Sync(); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return err
		}
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

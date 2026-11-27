// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package settlement

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const walGenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// WALEntry is one append-only hash-chained Write-Ahead Log record persisted with fsync.
type WALEntry struct {
	Seq       uint64          `json:"seq"`
	PrevHash  string          `json:"prev_hash"`
	Kind      string          `json:"kind"`
	Payload   json.RawMessage `json:"payload"`
	EntryHash string          `json:"entry_hash"`
}

func computeWALEntryHash(seq uint64, prevHash, kind string, payload []byte) string {
	payloadHash := SHA256BytesHex(payload)
	return SHA256Hex(fmt.Sprintf("wal:v1|%d|%s|%s|%s", seq, prevHash, kind, payloadHash))
}

// DurableWAL provides crash-safe, fsync-backed append-only persistence with hash-chain integrity.
type DurableWAL struct {
	mu       sync.Mutex
	path     string
	file     *os.File
	seq      uint64
	lastHash string
	entries  []WALEntry
}

// OpenWAL opens (or creates) a hash-chained WAL file, validates all existing entries, and prepares for appending.
// If path is empty, the WAL operates purely in memory.
func OpenWAL(path string) (*DurableWAL, []WALEntry, error) {
	w := &DurableWAL{
		path:     path,
		lastHash: walGenesisHash,
	}
	if path == "" {
		return w, nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, nil, fmt.Errorf("wal mkdir: %w", err)
	}
	// First replay existing entries if file exists.
	if _, err := os.Stat(path); err == nil {
		entries, lastSeq, lastHash, err := readAndVerifyWAL(path)
		if err != nil {
			return nil, nil, err
		}
		w.entries = entries
		w.seq = lastSeq
		w.lastHash = lastHash
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("wal open: %w", err)
	}
	w.file = f
	out := make([]WALEntry, len(w.entries))
	copy(out, w.entries)
	return w, out, nil
}

func readAndVerifyWAL(path string) ([]WALEntry, uint64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, "", fmt.Errorf("wal read open: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Allow up to 4 MiB per WAL line for large receipts/attestation bundles.
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	var entries []WALEntry
	var expectedSeq uint64 = 1
	prevHash := walGenesisHash

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var e WALEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, 0, "", fmt.Errorf("wal corrupt json at seq %d: %w", expectedSeq, err)
		}
		if e.Seq != expectedSeq {
			return nil, 0, "", fmt.Errorf("wal seq mismatch: got %d want %d", e.Seq, expectedSeq)
		}
		if e.PrevHash != prevHash {
			return nil, 0, "", fmt.Errorf("wal prev_hash mismatch at seq %d", e.Seq)
		}
		wantHash := computeWALEntryHash(e.Seq, e.PrevHash, e.Kind, e.Payload)
		if e.EntryHash != wantHash {
			return nil, 0, "", fmt.Errorf("wal entry_hash mismatch at seq %d", e.Seq)
		}
		entries = append(entries, e)
		prevHash = e.EntryHash
		expectedSeq++
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, "", fmt.Errorf("wal scan: %w", err)
	}
	return entries, expectedSeq - 1, prevHash, nil
}

// Append serializes payload, chains it to the previous WAL hash, writes a newline-delimited record, and calls fsync.
func (w *DurableWAL) Append(kind string, payloadObj any) (WALEntry, error) {
	raw, err := json.Marshal(payloadObj)
	if err != nil {
		return WALEntry{}, fmt.Errorf("wal marshal: %w", err)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	nextSeq := w.seq + 1
	entry := WALEntry{
		Seq:       nextSeq,
		PrevHash:  w.lastHash,
		Kind:      kind,
		Payload:   raw,
		EntryHash: computeWALEntryHash(nextSeq, w.lastHash, kind, raw),
	}
	if w.file != nil {
		line, err := json.Marshal(entry)
		if err != nil {
			return WALEntry{}, fmt.Errorf("wal marshal entry: %w", err)
		}
		line = append(line, '\n')
		if _, err := w.file.Write(line); err != nil {
			return WALEntry{}, fmt.Errorf("wal write: %w", err)
		}
		if err := w.file.Sync(); err != nil {
			return WALEntry{}, fmt.Errorf("wal fsync: %w", err)
		}
	}
	w.seq = nextSeq
	w.lastHash = entry.EntryHash
	w.entries = append(w.entries, entry)
	return entry, nil
}

// LastHash returns the current tip hash of the WAL chain.
func (w *DurableWAL) LastHash() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastHash
}

// Count returns the number of committed WAL entries.
func (w *DurableWAL) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.entries)
}

// Close closes the underlying WAL file handle cleanly.
func (w *DurableWAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		err := w.file.Close()
		w.file = nil
		return err
	}
	return nil
}

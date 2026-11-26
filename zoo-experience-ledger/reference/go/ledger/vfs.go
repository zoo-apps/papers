// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ObjectPutResult summarizes a content-addressed object write.
type ObjectPutResult struct {
	SHA256       string
	URI          string
	SizeBytes    int64
	Deduplicated bool
}

// VFSObjectStore is the minimal interface binding the Experience Ledger to
// Hanzo's existing VFS and S3 object storage layer (no second storage stack).
type VFSObjectStore interface {
	Put(data []byte) (ObjectPutResult, error)
	Get(sha256Hex string) ([]byte, error)
	Exists(sha256Hex string) bool
	URIFor(sha256Hex string) string
}

// LocalVFSStore stores content-addressed artifacts on a local VFS directory
// using S3-compatible sharded keys: sha256/<hex[0:2]>/<hex>.
// Safe for concurrent goroutines.
type LocalVFSStore struct {
	mu          sync.RWMutex
	rootDir     string
	s3Bucket    string // if non-empty, emits s3://<bucket>/sha256/<p>/<hex>; else vfs://sha256/<hex>
	totalWrites int64
	dedupHits   int64
	logicalBytes int64
	storedBytes  int64
}

// NewLocalVFSStore creates a local VFS-backed content-addressed object store.
func NewLocalVFSStore(rootDir string, s3Bucket string) (*LocalVFSStore, error) {
	if rootDir == "" {
		return nil, errors.New("vfs rootDir must not be empty")
	}
	if err := os.MkdirAll(filepath.Join(rootDir, "sha256"), 0o755); err != nil {
		return nil, err
	}
	return &LocalVFSStore{
		rootDir:  rootDir,
		s3Bucket: s3Bucket,
	}, nil
}

// URIFor returns the canonical VFS or S3 URI for a 64-char hex SHA-256 hash.
func (s *LocalVFSStore) URIFor(sha256Hex string) string {
	if s.s3Bucket != "" && len(sha256Hex) == 64 {
		return fmt.Sprintf("s3://%s/sha256/%s/%s", s.s3Bucket, sha256Hex[:2], sha256Hex)
	}
	return "vfs://sha256/" + sha256Hex
}

func (s *LocalVFSStore) objectPath(sha256Hex string) (string, error) {
	if !isLowerHex64(sha256Hex) {
		return "", fmt.Errorf("invalid sha256 hex: %q", sha256Hex)
	}
	return filepath.Join(s.rootDir, "sha256", sha256Hex[:2], sha256Hex), nil
}

// Put writes data content-addressed by SHA-256 with atomic rename and automatic deduplication.
func (s *LocalVFSStore) Put(data []byte) (ObjectPutResult, error) {
	digest := SHA256Hex(data)
	path, err := s.objectPath(digest)
	if err != nil {
		return ObjectPutResult{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.totalWrites++
	s.logicalBytes += int64(len(data))

	if _, statErr := os.Stat(path); statErr == nil {
		s.dedupHits++
		return ObjectPutResult{
			SHA256:       digest,
			URI:          s.URIFor(digest),
			SizeBytes:    int64(len(data)),
			Deduplicated: true,
		}, nil
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ObjectPutResult{}, err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return ObjectPutResult{}, err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return ObjectPutResult{}, err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return ObjectPutResult{}, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return ObjectPutResult{}, err
	}

	s.storedBytes += int64(len(data))
	return ObjectPutResult{
		SHA256:       digest,
		URI:          s.URIFor(digest),
		SizeBytes:    int64(len(data)),
		Deduplicated: false,
	}, nil
}

// Get retrieves an object by SHA-256 and verifies integrity before returning.
func (s *LocalVFSStore) Get(sha256Hex string) ([]byte, error) {
	path, err := s.objectPath(sha256Hex)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	data, err := os.ReadFile(path)
	s.mu.RUnlock()
	if err != nil {
		return nil, err
	}
	if got := SHA256Hex(data); got != sha256Hex {
		return nil, fmt.Errorf("vfs integrity mismatch: expected %s, got %s", sha256Hex, got)
	}
	return data, nil
}

// Exists checks whether the content-addressed object is present.
func (s *LocalVFSStore) Exists(sha256Hex string) bool {
	path, err := s.objectPath(sha256Hex)
	if err != nil {
		return false
	}
	s.mu.RLock()
	_, err = os.Stat(path)
	s.mu.RUnlock()
	return err == nil
}

// VFSStats reports deduplication metrics for benchmarks and audits.
type VFSStats struct {
	TotalWrites  int64 `json:"total_writes"`
	DedupHits    int64 `json:"dedup_hits"`
	LogicalBytes int64 `json:"logical_bytes"`
	StoredBytes  int64 `json:"stored_bytes"`
}

// Stats returns a thread-safe snapshot of deduplication counters.
func (s *LocalVFSStore) Stats() VFSStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return VFSStats{
		TotalWrites:  s.totalWrites,
		DedupHits:    s.dedupHits,
		LogicalBytes: s.logicalBytes,
		StoredBytes:  s.storedBytes,
	}
}

// ValidateStorageURI checks that uri is a well-formed vfs:// or s3:// content-addressed
// pointer matching sha256Hex.
func ValidateStorageURI(uri, sha256Hex string) bool {
	if !isLowerHex64(sha256Hex) {
		return false
	}
	if uri == "vfs://sha256/"+sha256Hex {
		return true
	}
	if strings.HasPrefix(uri, "s3://") {
		rest := strings.TrimPrefix(uri, "s3://")
		idx := strings.IndexByte(rest, '/')
		if idx < 3 || idx > 63 {
			return false
		}
		bucket := rest[:idx]
		for i := 0; i < len(bucket); i++ {
			c := bucket[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-'
			if !ok {
				return false
			}
		}
		key := rest[idx+1:]
		expectedKey := "sha256/" + sha256Hex[:2] + "/" + sha256Hex
		return key == expectedKey
	}
	return false
}

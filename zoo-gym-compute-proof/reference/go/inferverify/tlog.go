// Copyright 2026 Zoo Labs Foundation / Hanzo Industries.
// Licensed under the Apache License, Version 2.0.

package inferverify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/bits"
	"strconv"
)

// RFC 6962 SHA-256 Merkle hashing with strict leaf (0x00) and node (0x01) domain separation.
func HashLeafRFC6962(data []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func HashNodeRFC6962(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func largestPowerOfTwoLessThan(n int) int {
	if n <= 1 {
		return 0
	}
	return 1 << (bits.Len(uint(n-1)) - 1)
}

// ComputeMerkleRootRFC6962 computes the RFC 6962 Merkle Tree Hash (MTH) over
// pre-hashed leaf digests (each leafDigest is 32 bytes; HashLeafRFC6962 is applied
// to the raw leaf bytes).
func ComputeMerkleRootRFC6962(rawLeaves [][]byte) [32]byte {
	n := len(rawLeaves)
	if n == 0 {
		return sha256.Sum256(nil)
	}
	if n == 1 {
		return HashLeafRFC6962(rawLeaves[0])
	}
	k := largestPowerOfTwoLessThan(n)
	left := ComputeMerkleRootRFC6962(rawLeaves[:k])
	right := ComputeMerkleRootRFC6962(rawLeaves[k:])
	return HashNodeRFC6962(left, right)
}

// BuildInclusionProofRFC6962 generates the RFC 6962 Merkle audit path (bottom-up
// sibling hashes from leaf to root) for leaf at index in rawLeaves[0:n].
func BuildInclusionProofRFC6962(rawLeaves [][]byte, index int) ([][32]byte, error) {
	n := len(rawLeaves)
	if index < 0 || index >= n {
		return nil, fmt.Errorf("index %d out of range [0, %d)", index, n)
	}
	return auditPathRFC6962(rawLeaves, index), nil
}

func auditPathRFC6962(rawLeaves [][]byte, index int) [][32]byte {
	n := len(rawLeaves)
	if n <= 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(n)
	if index < k {
		path := auditPathRFC6962(rawLeaves[:k], index)
		sib := ComputeMerkleRootRFC6962(rawLeaves[k:])
		return append(path, sib)
	}
	path := auditPathRFC6962(rawLeaves[k:], index-k)
	sib := ComputeMerkleRootRFC6962(rawLeaves[:k])
	return append(path, sib)
}

// VerifyInclusionProofRFC6962 verifies an RFC 6962 audit path in O(log N)
// identically in Go and Python.
func VerifyInclusionProofRFC6962(rawLeaf []byte, index, treeSize int, proofHex []string, expectedRootHex string) bool {
	return VerifyInclusionProofRecursive(rawLeaf, index, treeSize, proofHex, expectedRootHex)
}

// VerifyInclusionProofRecursive is an alternative, crystal-clear recursive RFC 6962
// inclusion proof verifier whose decomposition mirrors auditPathRFC6962 1-to-1.
func VerifyInclusionProofRecursive(rawLeaf []byte, index, treeSize int, proofHex []string, expectedRootHex string) bool {
	if treeSize <= 0 || index < 0 || index >= treeSize {
		return false
	}
	proof := make([][32]byte, len(proofHex))
	for i, h := range proofHex {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 {
			return false
		}
		copy(proof[i][:], b)
	}
	root, consumed, ok := evalInclusionPath(HashLeafRFC6962(rawLeaf), index, treeSize, proof)
	if !ok || consumed != len(proof) {
		return false
	}
	return hex.EncodeToString(root[:]) == expectedRootHex
}

func evalInclusionPath(leafHash [32]byte, index, treeSize int, proof [][32]byte) ([32]byte, int, bool) {
	if treeSize == 1 {
		if index != 0 {
			return [32]byte{}, 0, false
		}
		return leafHash, 0, true
	}
	k := largestPowerOfTwoLessThan(treeSize)
	if index < k {
		leftRoot, used, ok := evalInclusionPath(leafHash, index, k, proof)
		if !ok || used >= len(proof) {
			return [32]byte{}, 0, false
		}
		return HashNodeRFC6962(leftRoot, proof[used]), used + 1, true
	}
	rightRoot, used, ok := evalInclusionPath(leafHash, index-k, treeSize-k, proof)
	if !ok || used >= len(proof) {
		return [32]byte{}, 0, false
	}
	return HashNodeRFC6962(proof[used], rightRoot), used + 1, true
}

// TransparencyLog models an append-only Sigstore Rekor-style transparency log.
type TransparencyLog struct {
	LogID     string
	PubKeyHex string
	PrivKey   ed25519.PrivateKey
	Leaves    [][]byte
}

func NewTransparencyLog(seed uint64) *TransparencyLog {
	pub, priv := DeriveKeypair(seed, "rekor-tlog-operator")
	pubHex := hex.EncodeToString(pub)
	idSum := sha256.Sum256(pub)
	return &TransparencyLog{
		LogID:     hex.EncodeToString(idSum[:]),
		PubKeyHex: pubHex,
		PrivKey:   priv,
	}
}

func CheckpointMessage(logID string, treeSize int, rootHash string, checkpointEpoch uint64) []byte {
	s := "rekor-checkpoint.v1\n" +
		logID + "\n" +
		strconv.Itoa(treeSize) + "\n" +
		rootHash + "\n" +
		strconv.FormatUint(checkpointEpoch, 10)
	return []byte(s)
}

// Append adds a leaf digest string to the log and returns its 0-based index.
func (t *TransparencyLog) Append(leafEntryDigest string) int {
	idx := len(t.Leaves)
	t.Leaves = append(t.Leaves, []byte(leafEntryDigest))
	return idx
}

// BundleForIndex builds a signed checkpoint + RFC 6962 inclusion proof bundle
// at the current tree size.
func (t *TransparencyLog) BundleForIndex(index int, checkpointEpoch uint64) (*TransparencyLogBundle, error) {
	if index < 0 || index >= len(t.Leaves) {
		return nil, fmt.Errorf("leaf index %d out of bounds", index)
	}
	root := ComputeMerkleRootRFC6962(t.Leaves)
	rootHex := hex.EncodeToString(root[:])
	path, err := BuildInclusionProofRFC6962(t.Leaves, index)
	if err != nil {
		return nil, err
	}
	hashes := make([]string, len(path))
	for i, h := range path {
		hashes[i] = hex.EncodeToString(h[:])
	}
	msg := CheckpointMessage(t.LogID, len(t.Leaves), rootHex, checkpointEpoch)
	sig := ed25519.Sign(t.PrivKey, msg)
	return &TransparencyLogBundle{
		LogID:           t.LogID,
		LogPubKeyHex:    t.PubKeyHex,
		LogIndex:        index,
		TreeSize:        len(t.Leaves),
		RootHash:        rootHex,
		CheckpointEpoch: checkpointEpoch,
		CheckpointSig:   base64.StdEncoding.EncodeToString(sig),
		LeafEntryDigest: string(t.Leaves[index]),
		Hashes:          hashes,
	}, nil
}

// VerifyTransparencyLogBundle validates the trusted log identity, checkpoint
// Ed25519 signature, leaf entry digest binding, and RFC 6962 Merkle inclusion proof.
func VerifyTransparencyLogBundle(bundle *TransparencyLogBundle, expectedLeafDigest string, expectedEpoch uint64, trust TrustRoot) string {
	if bundle == nil {
		return ErrMissingTLogProof
	}
	if bundle.LogID != trust.TLogID || bundle.LogPubKeyHex != trust.TLogPubKeyHex {
		return ErrUntrustedTLogKey
	}
	if bundle.CheckpointEpoch != expectedEpoch {
		return ErrEpochMismatch
	}
	if bundle.LeafEntryDigest != expectedLeafDigest {
		return ErrTLogLeafMismatch
	}
	pubBytes, err := hex.DecodeString(trust.TLogPubKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return ErrUntrustedTLogKey
	}
	sigBytes, err := base64.StdEncoding.DecodeString(bundle.CheckpointSig)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return ErrInvalidTLogCheckpointSig
	}
	msg := CheckpointMessage(bundle.LogID, bundle.TreeSize, bundle.RootHash, bundle.CheckpointEpoch)
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), msg, sigBytes) {
		return ErrInvalidTLogCheckpointSig
	}
	if !VerifyInclusionProofRecursive([]byte(bundle.LeafEntryDigest), bundle.LogIndex, bundle.TreeSize, bundle.Hashes, bundle.RootHash) {
		return ErrInvalidTLogProof
	}
	return ErrNone
}

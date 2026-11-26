// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation and Contributors

package receipt

import (
	"crypto/sha256"
	"fmt"
)

func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// HashLeaf computes the domain-separated RFC 6962 leaf digest:
// SHA256(0x00 || domain || ":" || leafBytes).
func HashLeaf(domain string, leafBytes []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write([]byte(domain))
	h.Write([]byte{':'})
	h.Write(leafBytes)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// HashNode computes the domain-separated RFC 6962 interior node digest:
// SHA256(0x01 || domain || ":" || left || right).
func HashNode(domain string, left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write([]byte(domain))
	h.Write([]byte{':'})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// MerkleRoot computes the domain-separated RFC 6962 binary SHA-256 Merkle root.
func MerkleRoot(domain string, leaves [][]byte) [32]byte {
	n := len(leaves)
	if n == 0 {
		h := sha256.New()
		h.Write([]byte(EmptyMerkleDomainPrefix))
		h.Write([]byte(domain))
		var out [32]byte
		copy(out[:], h.Sum(nil))
		return out
	}
	if n == 1 {
		return HashLeaf(domain, leaves[0])
	}
	k := largestPowerOfTwoLessThan(n)
	left := MerkleRoot(domain, leaves[:k])
	right := MerkleRoot(domain, leaves[k:])
	return HashNode(domain, left, right)
}

// ProofStep represents one sibling hash along an RFC 6962 Merkle audit path.
type ProofStep struct {
	SiblingHash   [32]byte
	IsLeftSibling bool
}

// InclusionProof proves membership of a leaf at LeafIndex in a TreeSize Merkle tree.
type InclusionProof struct {
	Domain    string
	LeafIndex int
	TreeSize  int
	Steps     []ProofStep
}

func buildAuditPath(domain string, leaves [][]byte, index int) []ProofStep {
	n := len(leaves)
	if n <= 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(n)
	if index < k {
		steps := buildAuditPath(domain, leaves[:k], index)
		sibling := MerkleRoot(domain, leaves[k:])
		return append(steps, ProofStep{SiblingHash: sibling, IsLeftSibling: false})
	}
	steps := buildAuditPath(domain, leaves[k:], index-k)
	sibling := MerkleRoot(domain, leaves[:k])
	return append(steps, ProofStep{SiblingHash: sibling, IsLeftSibling: true})
}

// BuildInclusionProof constructs an O(log n) RFC 6962 Merkle inclusion proof for leaves[index].
func BuildInclusionProof(domain string, leaves [][]byte, index int) (*InclusionProof, error) {
	n := len(leaves)
	if index < 0 || index >= n {
		return nil, fmt.Errorf("leaf index %d out of bounds for tree size %d", index, n)
	}
	return &InclusionProof{
		Domain:    domain,
		LeafIndex: index,
		TreeSize:  n,
		Steps:     buildAuditPath(domain, leaves, index),
	}, nil
}

// VerifyInclusionProof verifies an RFC 6962 Merkle inclusion proof against expectedRoot.
func VerifyInclusionProof(proof *InclusionProof, leafBytes []byte, expectedRoot [32]byte) bool {
	if proof == nil || proof.TreeSize <= 0 || proof.LeafIndex < 0 || proof.LeafIndex >= proof.TreeSize {
		return false
	}
	acc := HashLeaf(proof.Domain, leafBytes)
	for _, step := range proof.Steps {
		if step.IsLeftSibling {
			acc = HashNode(proof.Domain, step.SiblingHash, acc)
		} else {
			acc = HashNode(proof.Domain, acc, step.SiblingHash)
		}
	}
	return acc == expectedRoot
}

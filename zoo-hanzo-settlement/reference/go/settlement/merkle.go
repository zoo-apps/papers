// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package settlement

import "fmt"

// EmptyMerkleRoot is the canonical root of an empty binary Merkle tree.
func EmptyMerkleRoot() string {
	return SHA256Hex("merkle-empty:v1")
}

// ComputeReceiptMerkleLeaf hashes a settled UsefulWorkReceipt into its canonical Merkle leaf.
func ComputeReceiptMerkleLeaf(receiptID, nullifier string, consumedMicroZOO int64) string {
	return SHA256Hex(fmt.Sprintf("merkle-leaf:v1|%s|%s|%d", receiptID, nullifier, consumedMicroZOO))
}

// HashMerkleNode hashes two 64-hex child digests into their domain-separated parent digest.
func HashMerkleNode(leftHex, rightHex string) string {
	return SHA256Hex("merkle-node:v1|" + leftHex + "|" + rightHex)
}

// ComputeMerkleRoot computes the binary Merkle root over pre-hashed leaf digests.
// Odd levels duplicate their final element before hashing up.
func ComputeMerkleRoot(leaves []string) string {
	if len(leaves) == 0 {
		return EmptyMerkleRoot()
	}
	level := make([]string, len(leaves))
	copy(level, leaves)
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([]string, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next[i/2] = HashMerkleNode(level[i], level[i+1])
		}
		level = next
	}
	return level[0]
}

// BuildMerkleProof builds the inclusion proof for leaf index idx within leaves.
func BuildMerkleProof(leaves []string, idx int) ([]MerkleProofStep, string, error) {
	if idx < 0 || idx >= len(leaves) {
		return nil, "", newProtoErr(ErrInvalidMerkleProof, "leaf index %d out of bounds [0,%d)", idx, len(leaves))
	}
	level := make([]string, len(leaves))
	copy(level, leaves)
	curIdx := idx
	proof := make([]MerkleProofStep, 0)

	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		if curIdx%2 == 0 {
			proof = append(proof, MerkleProofStep{
				SiblingHex: level[curIdx+1],
				Position:   "right",
			})
		} else {
			proof = append(proof, MerkleProofStep{
				SiblingHex: level[curIdx-1],
				Position:   "left",
			})
		}
		next := make([]string, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next[i/2] = HashMerkleNode(level[i], level[i+1])
		}
		level = next
		curIdx /= 2
	}
	return proof, level[0], nil
}

// VerifyMerkleProof verifies a leaf hash against rootHex using the provided inclusion proof.
func VerifyMerkleProof(leafHex string, proof []MerkleProofStep, rootHex string) bool {
	if !validHex64(leafHex) || !validHex64(rootHex) {
		return false
	}
	cur := leafHex
	for _, step := range proof {
		if !validHex64(step.SiblingHex) {
			return false
		}
		switch step.Position {
		case "left":
			cur = HashMerkleNode(step.SiblingHex, cur)
		case "right":
			cur = HashMerkleNode(cur, step.SiblingHex)
		default:
			return false
		}
	}
	return cur == rootHex
}

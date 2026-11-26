// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
)

// MerkleProofStep represents one sibling hash along a binary Merkle proof path.
type MerkleProofStep struct {
	SiblingHex string `json:"sibling_hex"`
	Side       string `json:"side"` // "L" if sibling is on the left, "R" if on the right
}

// MerkleProof proves O(log n) inclusion of an active event_id in ActiveMerkleRoot.
type MerkleProof struct {
	EventID string            `json:"event_id"`
	Index   int               `json:"index"`
	RootHex string            `json:"root_hex"`
	Steps   []MerkleProofStep `json:"steps"`
}

func merkleLeafHash(eventIDHex string) ([32]byte, error) {
	raw, err := hex.DecodeString(eventIDHex)
	if err != nil || len(raw) != 32 {
		return [32]byte{}, fmt.Errorf("merkle leaf: invalid 32-byte hex %q", eventIDHex)
	}
	buf := make([]byte, 1+32)
	buf[0] = 0x00
	copy(buf[1:], raw)
	return sha256.Sum256(buf), nil
}

func merkleInternalHash(left, right [32]byte) [32]byte {
	var buf [1 + 64]byte
	buf[0] = 0x01
	copy(buf[1:33], left[:])
	copy(buf[33:65], right[:])
	return sha256.Sum256(buf[:])
}

// ComputeActiveMerkleRoot computes the domain-separated binary Merkle root over
// a sorted slice of 64-hex event IDs (matching experience-ledger-dso Algorithm 1).
func ComputeActiveMerkleRoot(eventIDs []string) (string, error) {
	if len(eventIDs) == 0 {
		sum := sha256.Sum256([]byte(EmptyMerkleDomain))
		return hex.EncodeToString(sum[:]), nil
	}
	sorted := make([]string, len(eventIDs))
	copy(sorted, eventIDs)
	sort.Strings(sorted)

	level := make([][32]byte, len(sorted))
	for i, id := range sorted {
		h, err := merkleLeafHash(id)
		if err != nil {
			return "", err
		}
		level[i] = h
	}

	for len(level) > 1 {
		nextLen := (len(level) + 1) / 2
		next := make([][32]byte, 0, nextLen)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			next = append(next, merkleInternalHash(left, right))
		}
		level = next
	}
	return hex.EncodeToString(level[0][:]), nil
}

// GenerateMerkleProof generates an O(log n) inclusion proof for targetEventID
// within the sorted set of active eventIDs.
func GenerateMerkleProof(eventIDs []string, targetEventID string) (MerkleProof, error) {
	if len(eventIDs) == 0 {
		return MerkleProof{}, fmt.Errorf("merkle proof: empty active set")
	}
	sorted := make([]string, len(eventIDs))
	copy(sorted, eventIDs)
	sort.Strings(sorted)

	idx := sort.SearchStrings(sorted, targetEventID)
	if idx >= len(sorted) || sorted[idx] != targetEventID {
		return MerkleProof{}, fmt.Errorf("merkle proof: event %s not in active set", targetEventID)
	}

	level := make([][32]byte, len(sorted))
	for i, id := range sorted {
		h, err := merkleLeafHash(id)
		if err != nil {
			return MerkleProof{}, err
		}
		level[i] = h
	}

	steps := make([]MerkleProofStep, 0)
	curIdx := idx
	for len(level) > 1 {
		var sib [32]byte
		var side string
		if curIdx%2 == 0 {
			side = "R"
			if curIdx+1 < len(level) {
				sib = level[curIdx+1]
			} else {
				sib = level[curIdx]
			}
		} else {
			side = "L"
			sib = level[curIdx-1]
		}
		steps = append(steps, MerkleProofStep{
			SiblingHex: hex.EncodeToString(sib[:]),
			Side:       side,
		})

		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			next = append(next, merkleInternalHash(left, right))
		}
		level = next
		curIdx /= 2
	}

	return MerkleProof{
		EventID: targetEventID,
		Index:   idx,
		RootHex: hex.EncodeToString(level[0][:]),
		Steps:   steps,
	}, nil
}

// VerifyMerkleProof verifies a Merkle inclusion proof against expectedRootHex.
func VerifyMerkleProof(proof MerkleProof, expectedRootHex string) bool {
	cur, err := merkleLeafHash(proof.EventID)
	if err != nil {
		return false
	}
	for _, step := range proof.Steps {
		raw, err := hex.DecodeString(step.SiblingHex)
		if err != nil || len(raw) != 32 {
			return false
		}
		var sib [32]byte
		copy(sib[:], raw)
		switch step.Side {
		case "L":
			cur = merkleInternalHash(sib, cur)
		case "R":
			cur = merkleInternalHash(cur, sib)
		default:
			return false
		}
	}
	return hex.EncodeToString(cur[:]) == expectedRootHex && proof.RootHex == expectedRootHex
}

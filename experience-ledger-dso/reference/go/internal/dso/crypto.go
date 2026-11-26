// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation

package dso

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const signDomainPrefix = "dso-aggregation.v1:"

// NodeIdentity holds a deterministic RFC 8032 Ed25519 keypair for a simulated DSO participant.
type NodeIdentity struct {
	NodeID       string
	PublicKey    ed25519.PublicKey
	PrivateKey   ed25519.PrivateKey
	PublicKeyHex string
}

// DeriveNodeIdentity deterministically derives an Ed25519 keypair from (seed, nodeIndex).
func DeriveNodeIdentity(seed int64, nodeIndex int) NodeIdentity {
	nodeID := fmt.Sprintf("node-%02d", nodeIndex)
	seedMaterial := sha256.Sum256([]byte(fmt.Sprintf("dso-node-key-v1:%d:%s", seed, nodeID)))
	priv := ed25519.NewKeyFromSeed(seedMaterial[:])
	pub := priv.Public().(ed25519.PublicKey)
	return NodeIdentity{
		NodeID:       nodeID,
		PublicKey:    pub,
		PrivateKey:   priv,
		PublicKeyHex: hex.EncodeToString(pub),
	}
}

// SignContribution canonically encodes, digests, and signs a ContributionBody using Ed25519.
func SignContribution(id NodeIdentity, body ContributionBody, role string) ContributionEnvelope {
	body.SchemaVersion = SchemaVersion
	body.NodeID = id.NodeID
	body.PublicKeyHex = id.PublicKeyHex

	canonical := CanonicalContributionBytes(body)
	digest := sha256.Sum256(canonical)

	msg := make([]byte, len(signDomainPrefix)+len(canonical))
	copy(msg, signDomainPrefix)
	copy(msg[len(signDomainPrefix):], canonical)

	sig := ed25519.Sign(id.PrivateKey, msg)
	return ContributionEnvelope{
		Body:         body,
		SignatureHex: hex.EncodeToString(sig),
		DigestSHA256: hex.EncodeToString(digest[:]),
		PayloadBytes: len(canonical) + len(sig) + len(digest),
		Role:         role,
	}
}

// VerifyContribution verifies the canonical digest and RFC 8032 Ed25519 signature of an envelope.
func VerifyContribution(env ContributionEnvelope) error {
	if env.Body.SchemaVersion != SchemaVersion {
		return fmt.Errorf("ERR_INVALID_SCHEMA_VERSION: got %q", env.Body.SchemaVersion)
	}
	pub, err := hex.DecodeString(env.Body.PublicKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("ERR_INVALID_PUBLIC_KEY")
	}
	sig, err := hex.DecodeString(env.SignatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("ERR_INVALID_SIGNATURE_FORMAT")
	}
	canonical := CanonicalContributionBytes(env.Body)
	digest := sha256.Sum256(canonical)
	if hex.EncodeToString(digest[:]) != env.DigestSHA256 {
		return fmt.Errorf("ERR_DIGEST_MISMATCH")
	}
	msg := make([]byte, len(signDomainPrefix)+len(canonical))
	copy(msg, signDomainPrefix)
	copy(msg[len(signDomainPrefix):], canonical)

	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return fmt.Errorf("ERR_INVALID_SIGNATURE")
	}
	return nil
}

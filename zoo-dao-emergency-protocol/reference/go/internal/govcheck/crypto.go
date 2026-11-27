// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package govcheck

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// DeterministicKeyPair derives a reproducible RFC 8032 Ed25519 key pair for
// test/benchmark fixtures from a seed and actor label. Never used for live keys.
func DeterministicKeyPair(seed int64, actorID string) (ed25519.PublicKey, ed25519.PrivateKey) {
	h := sha256.Sum256([]byte(fmt.Sprintf("constitutional-gov.v1:fixture-key:%d:%s", seed, actorID)))
	priv := ed25519.NewKeyFromSeed(h[:])
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv
}

// SignAction computes an RFC 8032 Ed25519 signature over the canonical signing preimage.
func SignAction(act GovernanceAction, signerID string, nonce uint64, priv ed25519.PrivateKey) (SignerSig, error) {
	preimage, err := SigningPreimage(act, signerID, nonce)
	if err != nil {
		return SignerSig{}, err
	}
	sig := ed25519.Sign(priv, preimage)
	return SignerSig{
		ActorID:      signerID,
		Nonce:        nonce,
		SignatureHex: hex.EncodeToString(sig),
	}, nil
}

// VerifySignerSig verifies an RFC 8032 Ed25519 signature against pubKeyHex.
func VerifySignerSig(act GovernanceAction, sig SignerSig, pubKeyHex string) bool {
	pubBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}
	sigBytes, err := hex.DecodeString(sig.SignatureHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	preimage, err := SigningPreimage(act, sig.ActorID, sig.Nonce)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pubBytes), preimage, sigBytes)
}

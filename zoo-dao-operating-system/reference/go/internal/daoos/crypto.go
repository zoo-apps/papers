// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation & Open ResearchDAO Contributors.

package daoos

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Keypair holds an RFC 8032 Ed25519 signing key and its hex-encoded public key.
type Keypair struct {
	ActorID    string
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	PubKeyHex  string
}

// DeriveDeterministicKeypair derives a reproducible RFC 8032 Ed25519 keypair from
// a benchmark/test seed and actor label. Production deployments use hardware wallets / KMS.
func DeriveDeterministicKeypair(seed int64, actorID string) Keypair {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("researchdao-os.v1:keygen:%d:%s", seed, actorID)))
	seedBytes := h.Sum(nil)
	priv := ed25519.NewKeyFromSeed(seedBytes)
	pub := priv.Public().(ed25519.PublicKey)
	return Keypair{
		ActorID:    actorID,
		PrivateKey: priv,
		PublicKey:  pub,
		PubKeyHex:  hex.EncodeToString(pub),
	}
}

// SignEnvelope signs the canonical unsigned envelope bytes with RFC 8032 Ed25519.
func SignEnvelope(env Envelope, priv ed25519.PrivateKey) (Envelope, error) {
	if env.SpecVersion == "" {
		env.SpecVersion = SpecVersion
	}
	msg, err := SigningBytes(env)
	if err != nil {
		return Envelope{}, err
	}
	sig := ed25519.Sign(priv, msg)
	env.SignatureHex = hex.EncodeToString(sig)
	return env, nil
}

// VerifyEnvelopeSignature verifies the RFC 8032 Ed25519 signature against pubKeyHex.
func VerifyEnvelopeSignature(env Envelope, pubKeyHex string) error {
	pubBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return NewTransitionError(ErrInvalidSignature, "malformed actor public key")
	}
	sigBytes, err := hex.DecodeString(env.SignatureHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return NewTransitionError(ErrInvalidSignature, "malformed signature hex")
	}
	msg, err := SigningBytes(env)
	if err != nil {
		return NewTransitionError(ErrInvalidPayload, err.Error())
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), msg, sigBytes) {
		return NewTransitionError(ErrInvalidSignature, "ed25519 verification failed")
	}
	return nil
}

// IsValidSHA256Hex validates a 64-character lowercase hex SHA-256 digest.
func IsValidSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < 64; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// SHA256Hex computes the lowercase hex SHA-256 digest of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

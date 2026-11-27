// Copyright 2026 Zoo Labs Foundation / Hanzo Industries.
// Licensed under the Apache License, Version 2.0.

package inferverify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
)

// DeriveKeypair deterministically generates an RFC 8032 Ed25519 keypair from
// seed and label so every benchmark run and fixture is 100% reproducible.
func DeriveKeypair(seed uint64, label string) (ed25519.PublicKey, ed25519.PrivateKey) {
	h := sha256.New()
	h.Write([]byte("inference-verify.v1:ed25519-key:"))
	var sb [8]byte
	binary.LittleEndian.PutUint64(sb[:], seed)
	h.Write(sb[:])
	h.Write([]byte(":"))
	h.Write([]byte(label))
	seedBytes := h.Sum(nil) // 32 bytes
	priv := ed25519.NewKeyFromSeed(seedBytes)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv
}

// KeyIDFromPubKeyHex computes the 16-hex-char key identifier SHA256(pubkey)[:8].
func KeyIDFromPubKeyHex(pubHex string) (string, error) {
	raw, err := hex.DecodeString(pubHex)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid ed25519 pubkey hex")
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8]), nil
}

// DSSEPAE constructs the DSSE v1 Pre-Authentication Encoding:
// "DSSEv1 " + len(payloadType) + " " + payloadType + " " + len(payload) + " " + payload
func DSSEPAE(payloadType string, payload []byte) []byte {
	header := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	out := make([]byte, len(header)+len(payload))
	copy(out, header)
	copy(out[len(header):], payload)
	return out
}

// SignDSSE signs a JSON-serializable in-toto Statement into a DSSEEnvelope.
func SignDSSE(statement any, priv ed25519.PrivateKey) (DSSEEnvelope, error) {
	payloadBytes, err := json.Marshal(statement)
	if err != nil {
		return DSSEEnvelope{}, fmt.Errorf("marshal statement: %w", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	pubHex := hex.EncodeToString(pub)
	keyID, err := KeyIDFromPubKeyHex(pubHex)
	if err != nil {
		return DSSEEnvelope{}, err
	}
	pae := DSSEPAE(DSSEPayloadTypeInToto, payloadBytes)
	sig := ed25519.Sign(priv, pae)
	return DSSEEnvelope{
		PayloadType: DSSEPayloadTypeInToto,
		Payload:     base64.StdEncoding.EncodeToString(payloadBytes),
		Signatures: []DSSESignature{
			{
				KeyID: keyID,
				Sig:   base64.StdEncoding.EncodeToString(sig),
			},
		},
	}, nil
}

// VerifyDSSESignature validates the DSSE envelope payloadType, base64 decoding,
// and RFC 8032 Ed25519 signature under pubHex, returning the raw payload bytes
// and first signature bytes.
func VerifyDSSESignature(env DSSEEnvelope, pubHex string) ([]byte, []byte, string) {
	if env.PayloadType != DSSEPayloadTypeInToto {
		return nil, nil, ErrInvalidPayloadType
	}
	if len(env.Signatures) == 0 || env.Payload == "" {
		return nil, nil, ErrInvalidEnvelope
	}
	payloadBytes, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, nil, ErrInvalidEnvelope
	}
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return nil, nil, ErrInvalidDSSESig
	}
	expectedKeyID, err := KeyIDFromPubKeyHex(pubHex)
	if err != nil {
		return nil, nil, ErrInvalidDSSESig
	}
	sigEntry := env.Signatures[0]
	if sigEntry.KeyID != expectedKeyID {
		return nil, nil, ErrInvalidDSSESig
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigEntry.Sig)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, nil, ErrInvalidDSSESig
	}
	pae := DSSEPAE(env.PayloadType, payloadBytes)
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), pae, sigBytes) {
		return nil, nil, ErrInvalidDSSESig
	}
	return payloadBytes, sigBytes, ErrNone
}

// ComputeTLogLeafEntryDigest computes the canonical transparency-log leaf digest
// binding a job ID, DSSE payload bytes, worker signature bytes, and epoch.
func ComputeTLogLeafEntryDigest(jobID string, payloadBytes, sigBytes []byte, epoch uint64) string {
	pSum := sha256.Sum256(payloadBytes)
	sSum := sha256.Sum256(sigBytes)
	canonical := "inference-verify.v1:tlog-leaf:" +
		jobID + ":" +
		hex.EncodeToString(pSum[:]) + ":" +
		hex.EncodeToString(sSum[:]) + ":" +
		strconv.FormatUint(epoch, 10)
	leafSum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(leafSum[:])
}

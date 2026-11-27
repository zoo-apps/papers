// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package agentid

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// KeyPair holds a deterministic Ed25519 key pair for signing and identity creation.
type KeyPair struct {
	KeyID        string
	PublicKey    ed25519.PublicKey
	PrivateKey   ed25519.PrivateKey
	PublicKeyB64 string
}

// DeriveKeyPair deterministically derives an Ed25519 key pair from (seed, label).
func DeriveKeyPair(seed int64, label, keyID string) KeyPair {
	h := sha256.Sum256([]byte(fmt.Sprintf("zoo.agentid.v1.keygen:%d:%s", seed, label)))
	priv := ed25519.NewKeyFromSeed(h[:])
	pub := priv.Public().(ed25519.PublicKey)
	return KeyPair{
		KeyID:        keyID,
		PublicKey:    pub,
		PrivateKey:   priv,
		PublicKeyB64: EncodeBase64URL(pub),
	}
}

// DIDKeyFromPublicKey encodes an Ed25519 public key into a W3C self-certifying did:key:z6Mk...
// using multicodec prefix 0xed 0x01 and Base58BTC multibase 'z'.
func DIDKeyFromPublicKey(pub ed25519.PublicKey) string {
	prefixed := make([]byte, 2+len(pub))
	prefixed[0] = 0xed
	prefixed[1] = 0x01
	copy(prefixed[2:], pub)
	return "did:key:z" + Base58BTCEncode(prefixed)
}

// PublicKeyFromDIDKey decodes and validates a W3C Ed25519 did:key:z... identifier.
func PublicKeyFromDIDKey(did string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(did, "did:key:z") {
		return nil, errors.New("not a did:key:z multibase identifier")
	}
	raw, err := Base58BTCDecode(strings.TrimPrefix(did, "did:key:z"))
	if err != nil {
		return nil, err
	}
	if len(raw) != 34 || raw[0] != 0xed || raw[1] != 0x01 {
		return nil, errors.New("invalid Ed25519 multicodec header or key length")
	}
	pub := make(ed25519.PublicKey, 32)
	copy(pub, raw[2:])
	return pub, nil
}

// SignDomain signs domain || 0x00 || CanonicalJSON(payload) with Ed25519.
func SignDomain(priv ed25519.PrivateKey, domain string, payload any) (string, error) {
	msg, err := DomainMessage(domain, payload)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, msg)
	return EncodeBase64URL(sig), nil
}

// VerifyDomain verifies an Ed25519 signature over domain || 0x00 || CanonicalJSON(payload).
func VerifyDomain(pubB64, domain string, payload any, sigB64 string) bool {
	pubBytes, err := DecodeBase64URL(pubB64)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}
	sigBytes, err := DecodeBase64URL(sigB64)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	msg, err := DomainMessage(domain, payload)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pubBytes), msg, sigBytes)
}

// Unsigned payload projections ensure exact Go <-> Python canonical signing input parity.

func unsignedDIDDoc(doc DIDDocument) map[string]any {
	m := map[string]any{
		"@context":               nonNilStrings(doc.Context),
		"id":                     doc.ID,
		"principal_type":         doc.PrincipalType,
		"controller":             doc.Controller,
		"genesis_key_id":         doc.GenesisKeyID,
		"genesis_public_key_b64": doc.GenesisPublicKeyB64,
		"active_key_id":          doc.ActiveKeyID,
		"verification_methods":   nonNilVMs(doc.VerificationMethods),
		"key_rotations":          nonNilRotations(doc.KeyRotations),
		"portable_export":        doc.PortableExport,
		"proof_meta": map[string]any{
			"type":                doc.Proof.Type,
			"cryptosuite":         doc.Proof.Cryptosuite,
			"verification_method": doc.Proof.VerificationMethod,
			"created":             doc.Proof.Created,
		},
	}
	if doc.AgentNFTBinding != nil {
		m["agent_nft_binding"] = doc.AgentNFTBinding
	}
	return m
}

func unsignedKeyRotation(rot KeyRotationProof) map[string]any {
	return map[string]any{
		"did":                rot.DID,
		"from_key_id":        rot.FromKeyID,
		"to_key_id":          rot.ToKeyID,
		"new_public_key_b64": rot.NewPublicKeyB64,
		"rotated_at":         rot.RotatedAt,
		"reason":             rot.Reason,
		"controller_key_id":  rot.ControllerKeyID,
	}
}

func unsignedVC(vc DelegationVC) map[string]any {
	subj := vc.CredentialSubject
	return map[string]any{
		"@context":          nonNilStrings(vc.Context),
		"id":                vc.ID,
		"type":              nonNilStrings(vc.Type),
		"issuer":            vc.Issuer,
		"issuer_key_id":     vc.IssuerKeyID,
		"valid_from":        vc.ValidFrom,
		"valid_until":       vc.ValidUntil,
		"credential_status": vc.CredentialStatus,
		"credential_subject": map[string]any{
			"id":                     subj.ID,
			"subject_principal_type": subj.SubjectPrincipalType,
			"delegation_depth":       subj.DelegationDepth,
			"max_sub_depth":          subj.MaxSubDepth,
			"parent_vc_id":           subj.ParentVCID,
			"parent_vc_digest":       subj.ParentVCDigest,
			"audience":               subj.Audience,
			"scopes":                 nonNilStrings(subj.Scopes),
			"allowed_resources":      nonNilStrings(subj.AllowedResources),
			"constraints":            subj.Constraints,
			"nonce":                  subj.Nonce,
		},
		"proof_meta": map[string]any{
			"type":                vc.Proof.Type,
			"cryptosuite":         vc.Proof.Cryptosuite,
			"verification_method": vc.Proof.VerificationMethod,
			"created":             vc.Proof.Created,
		},
	}
}

func unsignedStatusList(sl BitstringStatusListCredential) map[string]any {
	return map[string]any{
		"@context":           nonNilStrings(sl.Context),
		"id":                 sl.ID,
		"type":               nonNilStrings(sl.Type),
		"issuer":             sl.Issuer,
		"issuer_key_id":      sl.IssuerKeyID,
		"valid_from":         sl.ValidFrom,
		"valid_until":        sl.ValidUntil,
		"credential_subject": sl.CredentialSubject,
		"proof_meta": map[string]any{
			"type":                sl.Proof.Type,
			"cryptosuite":         sl.Proof.Cryptosuite,
			"verification_method": sl.Proof.VerificationMethod,
			"created":             sl.Proof.Created,
		},
	}
}

func unsignedRevocationSnapshot(snap RevocationSnapshot) map[string]any {
	return map[string]any{
		"snapshot_id":         snap.SnapshotID,
		"issuer":              snap.Issuer,
		"issuer_key_id":       snap.IssuerKeyID,
		"issued_at":           snap.IssuedAt,
		"valid_until":         snap.ValidUntil,
		"status_list_digests": nonNilDigestPins(snap.StatusListDigests),
		"key_revocations":     nonNilKeyRevs(snap.KeyRevocations),
		"revoked_vc_ids":      nonNilStrings(snap.RevokedVCIDs),
		"crl_merkle_root":     snap.CRLMerkleRoot,
		"proof_meta": map[string]any{
			"type":                snap.Proof.Type,
			"cryptosuite":         snap.Proof.Cryptosuite,
			"verification_method": snap.Proof.VerificationMethod,
			"created":             snap.Proof.Created,
		},
	}
}

func unsignedHolderProof(hp HolderProof) map[string]any {
	return map[string]any{
		"holder_did":              hp.HolderDID,
		"holder_key_id":           hp.HolderKeyID,
		"delegation_chain_digest": hp.DelegationChainDigest,
		"challenge_nonce":         hp.ChallengeNonce,
		"audience":                hp.Audience,
		"action_verb":             hp.ActionVerb,
		"resource_uri":            hp.ResourceURI,
		"timestamp":               hp.Timestamp,
	}
}

// ComputeVCDigest returns the canonical SHA-256 digest of a DelegationVC including its signature.
func ComputeVCDigest(vc DelegationVC) string {
	return HashCanonical(DomainVC, map[string]any{
		"unsigned":      unsignedVC(vc),
		"signature_b64": vc.Proof.SignatureB64,
	})
}

// ComputeStatusListDigest returns the canonical SHA-256 digest of a BitstringStatusListCredential.
func ComputeStatusListDigest(sl BitstringStatusListCredential) string {
	return HashCanonical(DomainStatusList, map[string]any{
		"unsigned":      unsignedStatusList(sl),
		"signature_b64": sl.Proof.SignatureB64,
	})
}

// ComputeDelegationChainDigest computes the canonical SHA-256 commitment over an ordered VC chain.
func ComputeDelegationChainDigest(chain []DelegationVC) string {
	digests := make([]string, len(chain))
	for i, vc := range chain {
		digests[i] = ComputeVCDigest(vc)
	}
	return HashCanonical(DomainVC+".chain", digests)
}

// ComputeCRLMerkleRoot computes the canonical RFC 6962 Merkle root over revoked VC IDs and key revocations.
func ComputeCRLMerkleRoot(revokedVCIDs []string, keyRevs []KeyRevocationEntry) string {
	leaves := make([]string, 0, len(revokedVCIDs)+len(keyRevs))
	for _, id := range revokedVCIDs {
		leaves = append(leaves, "vc:"+id)
	}
	for _, kr := range keyRevs {
		leaves = append(leaves, fmt.Sprintf("key:%s|%s|%d|%t", kr.DID, kr.KeyID, kr.RevokedBefore, kr.RevokeAll))
	}
	sort.Strings(leaves)
	return MerkleRootRFC6962(leaves)
}

// BuildBitstring builds a W3C Bitstring Status List v1.0 bitstring (MSB-first bit indexing)
// with the given bitLength (must be multiple of 8) and revokedIndices set to 1.
func BuildBitstring(bitLength int, revokedIndices []int, encoding string) (string, error) {
	if bitLength <= 0 || bitLength%8 != 0 {
		return "", errors.New("bitLength must be positive multiple of 8")
	}
	raw := make([]byte, bitLength/8)
	for _, idx := range revokedIndices {
		if idx < 0 || idx >= bitLength {
			return "", fmt.Errorf("revoked index %d out of range [0, %d)", idx, bitLength)
		}
		byteIdx := idx / 8
		bitMask := byte(1 << (7 - (idx % 8)))
		raw[byteIdx] |= bitMask
	}
	return EncodeBitstring(raw, encoding)
}

// EncodeBitstring encodes a raw bitstring using gzip_base64url or raw_base64url.
func EncodeBitstring(raw []byte, encoding string) (string, error) {
	switch encoding {
	case EncodingRawBase64URL:
		return EncodeBase64URL(raw), nil
	case EncodingGzipBase64URL:
		var buf bytes.Buffer
		zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		if err != nil {
			return "", err
		}
		zw.Header.OS = 255 // deterministic unknown OS byte
		if _, err := zw.Write(raw); err != nil {
			return "", err
		}
		if err := zw.Close(); err != nil {
			return "", err
		}
		return EncodeBase64URL(buf.Bytes()), nil
	default:
		return "", fmt.Errorf("unsupported bitstring encoding: %s", encoding)
	}
}

// DecodeBitstring decodes an encoded W3C BitstringStatusList to raw bytes.
func DecodeBitstring(encoded, encoding string, expectedBitLength int) ([]byte, error) {
	if expectedBitLength <= 0 || expectedBitLength%8 != 0 {
		return nil, errors.New("invalid expected bit length")
	}
	expectedBytes := expectedBitLength / 8
	data, err := DecodeBase64URL(encoded)
	if err != nil {
		return nil, err
	}
	var raw []byte
	switch encoding {
	case EncodingRawBase64URL:
		raw = data
	case EncodingGzipBase64URL:
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		// Bound decompression against zip bombs (expectedBytes + 1).
		limited := io.LimitReader(zr, int64(expectedBytes)+1)
		raw, err = io.ReadAll(limited)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported bitstring encoding: %s", encoding)
	}
	if len(raw) != expectedBytes {
		return nil, fmt.Errorf("decoded bitstring byte length %d != expected %d", len(raw), expectedBytes)
	}
	return raw, nil
}

// BitstringIsRevoked checks bit idx (MSB-first per W3C Bitstring Status List v1.0).
func BitstringIsRevoked(raw []byte, bitLength, idx int) (bool, error) {
	if idx < 0 || idx >= bitLength || len(raw)*8 < bitLength {
		return false, errors.New("status list index out of bounds")
	}
	byteIdx := idx / 8
	bitMask := byte(1 << (7 - (idx % 8)))
	return (raw[byteIdx] & bitMask) != 0, nil
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilVMs(s []VerificationMethod) []VerificationMethod {
	if s == nil {
		return []VerificationMethod{}
	}
	return s
}

func nonNilRotations(s []KeyRotationProof) []KeyRotationProof {
	if s == nil {
		return []KeyRotationProof{}
	}
	return s
}

func nonNilDigestPins(s []StatusListDigestPin) []StatusListDigestPin {
	if s == nil {
		return []StatusListDigestPin{}
	}
	return s
}

func nonNilKeyRevs(s []KeyRevocationEntry) []KeyRevocationEntry {
	if s == nil {
		return []KeyRevocationEntry{}
	}
	return s
}

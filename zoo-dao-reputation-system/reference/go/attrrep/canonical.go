// SPDX-License-Identifier: Apache-2.0

package attrrep

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

const (
	domainRawArtifact     = "zoo.attrrep.v1.raw\x00"
	domainCanonicalText   = "zoo.attrrep.v1.canonical\x00"
	domainShingle         = "zoo.attrrep.v1.shingle\x00"
	domainWinnowDigest    = "zoo.attrrep.v1.winnow\x00"
	domainContribSig      = "zoo.attrrep.v1.contrib.sig\x00"
	domainEASUID          = "zoo.attrrep.v1.eas.uid\x00"
	domainEASSig          = "zoo.attrrep.v1.eas.sig\x00"
	domainIdentitySeed    = "zoo.attrrep.v1.keygen\x00"
)

// SHA256Hex computes lowercase hex SHA-256 of raw bytes.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// DomainSHA256Hex computes SHA-256(domain || data) as lowercase hex.
func DomainSHA256Hex(domain string, data []byte) string {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// CanonicalJSON serializes v into compact UTF-8 JSON with sorted object keys
// and no HTML escaping. Identical to Python:
// json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
func CanonicalJSON(v any) ([]byte, error) {
	// First marshal via standard encoder to normalize structs into generic JSON values
	// so map keys are always sorted recursively at every nesting depth.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(generic); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	if len(out) > 0 && out[len(out)-1] == '\n' {
		out = out[:len(out)-1]
	}
	return out, nil
}

// DeriveEd25519Key deterministically derives an RFC 8032 Ed25519 keypair from
// seed + identityID for reproducible fixtures and benchmarks.
func DeriveEd25519Key(seed int64, identityID string) (ed25519.PublicKey, ed25519.PrivateKey) {
	h := sha256.New()
	h.Write([]byte(domainIdentitySeed))
	h.Write([]byte(fmt.Sprintf("%d:%s", seed, identityID)))
	keySeed := h.Sum(nil)
	priv := ed25519.NewKeyFromSeed(keySeed)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv
}

// ContributionSignMessage constructs the deterministic domain-separated signing message.
func ContributionSignMessage(c Contribution) ([]byte, error) {
	parents := make([]string, len(c.Parents))
	copy(parents, c.Parents)
	sort.Strings(parents)
	payload := map[string]any{
		"author_id":           c.AuthorID,
		"base_value_micro":    c.BaseValueMicro,
		"canonical_digest":    c.CanonicalDigest,
		"category":            c.Category,
		"claimed_novelty_bps": c.ClaimedNoveltyBps,
		"contribution_id":     c.ContributionID,
		"epoch":               c.Epoch,
		"fingerprint_digest":  c.FingerprintDigest,
		"ledger_seq":          c.LedgerSeq,
		"parents":             parents,
		"raw_sha256":          c.RawSHA256,
		"timestamp":           c.Timestamp,
	}
	cj, err := CanonicalJSON(payload)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(domainContribSig)+len(cj))
	out = append(out, []byte(domainContribSig)...)
	out = append(out, cj...)
	return out, nil
}

// SignContribution signs a contribution using the author's Ed25519 private key.
func SignContribution(c *Contribution, priv ed25519.PrivateKey) error {
	msg, err := ContributionSignMessage(*c)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, msg)
	c.SignatureHex = hex.EncodeToString(sig)
	return nil
}

// VerifyContributionSignature verifies a contribution's Ed25519 signature.
func VerifyContributionSignature(c Contribution, pubHex string) bool {
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(c.SignatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	msg, err := ContributionSignMessage(c)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// ComputeAttestationUID computes the deterministic EAS-compatible AttestationUID.
func ComputeAttestationUID(a Attestation) (string, error) {
	payload := map[string]any{
		"attester":        a.Attester,
		"data_digest":     a.DataDigest,
		"epoch":           a.Epoch,
		"expiration_time": a.ExpirationTime,
		"nonce":           a.Nonce,
		"recipient":       a.Recipient,
		"ref_uid":         a.RefUID,
		"revocable":       a.Revocable,
		"schema_uid":      a.SchemaUID,
		"time":            a.Time,
		"weight_bps":      a.WeightBps,
	}
	cj, err := CanonicalJSON(payload)
	if err != nil {
		return "", err
	}
	return "0x" + DomainSHA256Hex(domainEASUID, cj), nil
}

// AttestationSignMessage builds the domain-separated signing message for an EAS attestation.
func AttestationSignMessage(a Attestation) ([]byte, error) {
	payload := map[string]any{
		"attester":   a.Attester,
		"epoch":      a.Epoch,
		"nonce":      a.Nonce,
		"recipient":  a.Recipient,
		"ref_uid":    a.RefUID,
		"schema_uid": a.SchemaUID,
		"uid":        a.UID,
		"weight_bps": a.WeightBps,
	}
	cj, err := CanonicalJSON(payload)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(domainEASSig)+len(cj))
	out = append(out, []byte(domainEASSig)...)
	out = append(out, cj...)
	return out, nil
}

// SignAttestation computes UID (if empty) and signs an attestation with the attester's Ed25519 key.
func SignAttestation(a *Attestation, priv ed25519.PrivateKey) error {
	if a.UID == "" {
		uid, err := ComputeAttestationUID(*a)
		if err != nil {
			return err
		}
		a.UID = uid
	}
	msg, err := AttestationSignMessage(*a)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, msg)
	a.SignatureHex = hex.EncodeToString(sig)
	return nil
}

// VerifyAttestationSignature verifies an EAS attestation's Ed25519 signature.
func VerifyAttestationSignature(a Attestation, pubHex string) bool {
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(a.SignatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	msg, err := AttestationSignMessage(a)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// MerkleRoot computes an RFC 6962-style domain-separated binary SHA-256 Merkle root.
// Leaf hash = SHA256(0x00 || leafBytes); interior hash = SHA256(0x01 || left || right).
// Odd trailing nodes are promoted unchanged to the next level.
func MerkleRoot(leaves [][]byte) string {
	if len(leaves) == 0 {
		sum := sha256.Sum256([]byte{})
		return hex.EncodeToString(sum[:])
	}
	level := make([][32]byte, len(leaves))
	for i, leaf := range leaves {
		h := sha256.New()
		h.Write([]byte{0x00})
		h.Write(leaf)
		copy(level[i][:], h.Sum(nil))
	}
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
			} else {
				h := sha256.New()
				h.Write([]byte{0x01})
				h.Write(level[i][:])
				h.Write(level[i+1][:])
				var node [32]byte
				copy(node[:], h.Sum(nil))
				next = append(next, node)
			}
		}
		level = next
	}
	return hex.EncodeToString(level[0][:])
}

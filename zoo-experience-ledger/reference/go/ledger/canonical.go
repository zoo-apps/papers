// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
)

// CanonicalJSON encodes a JSON-compatible value (nil, bool, int, int64, string,
// []any, []string, map[string]any) using deterministic RFC 8259 compact encoding
// with lexicographically sorted object keys and NO HTML escaping.
// This guarantees bit-exact parity with Python's json.dumps(..., sort_keys=True,
// separators=(",", ":"), ensure_ascii=False).
func CanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case int:
		buf.WriteString(strconv.Itoa(x))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(x, 10))
	case string:
		writeCanonicalString(buf, x)
	case []string:
		buf.WriteByte('[')
		for i, s := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, s)
		}
		buf.WriteByte(']')
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonical json: unsupported type %T", v)
	}
	return nil
}

func writeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// SHA256Hex returns the lowercase hex SHA-256 digest of b.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ComputePolicySHA256 computes the canonical SHA-256 hash of a Policy (excluding policy_sha256).
func ComputePolicySHA256(p Policy) (string, error) {
	principals := make([]any, 0, len(p.Principals))
	// Sort principals by principal_id in canonical map only if already sorted; preserve input order as written in Policy.
	for _, pr := range p.Principals {
		principals = append(principals, map[string]any{
			"principal_id":   pr.PrincipalID,
			"role":           pr.Role,
			"public_key_hex": pr.PublicKeyHex,
			"active":         pr.Active,
		})
	}
	m := map[string]any{
		"schema_version": p.SchemaVersion,
		"policy_id":      p.PolicyID,
		"principals":     principals,
	}
	raw, err := CanonicalJSON(m)
	if err != nil {
		return "", err
	}
	return SHA256Hex(raw), nil
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// UnsignedEventMap returns the canonical map of an event excluding event_id and signature_hex.
func UnsignedEventMap(e Event) (map[string]any, error) {
	switch e.EventType {
	case EventTypeExperienceEntry:
		return map[string]any{
			"schema_version":      e.SchemaVersion,
			"event_type":          e.EventType,
			"contributor_id":      e.ContributorID,
			"domain":              e.Domain,
			"claim_key":           e.ClaimKey,
			"claim_value_hash":    e.ClaimValueHash,
			"summary":             e.Summary,
			"confidence_bps":      e.ConfidenceBps,
			"artifact_sha256":     e.ArtifactSHA256,
			"artifact_uri":        e.ArtifactURI,
			"artifact_size_bytes": e.ArtifactSizeBytes,
			"external_uris":       nonNilStrings(e.ExternalURIs),
			"parent_hashes":       nonNilStrings(e.ParentHashes),
			"receipt_hash":        e.ReceiptHash,
			"created_at_unix":     e.CreatedAtUnix,
			"nonce":               e.Nonce,
		}, nil
	case EventTypeRevocationRecord:
		return map[string]any{
			"schema_version":  e.SchemaVersion,
			"event_type":      e.EventType,
			"issuer_id":       e.IssuerID,
			"target_event_id": e.TargetEventID,
			"reason_code":     e.ReasonCode,
			"reason":          e.Reason,
			"evidence_sha256": e.EvidenceSHA256,
			"evidence_uri":    e.EvidenceURI,
			"created_at_unix": e.CreatedAtUnix,
		}, nil
	case EventTypeConflictFlag:
		return map[string]any{
			"schema_version":        e.SchemaVersion,
			"event_type":            e.EventType,
			"flagger_id":            e.FlaggerID,
			"domain":                e.Domain,
			"claim_key":             e.ClaimKey,
			"conflicting_event_ids": nonNilStrings(e.ConflictingEventIDs),
			"evidence_sha256":       e.EvidenceSHA256,
			"evidence_uri":          e.EvidenceURI,
			"rationale":             e.Rationale,
			"created_at_unix":       e.CreatedAtUnix,
		}, nil
	case EventTypeResolutionDecision:
		return map[string]any{
			"schema_version":     e.SchemaVersion,
			"event_type":         e.EventType,
			"steward_id":         e.StewardID,
			"domain":             e.Domain,
			"claim_key":          e.ClaimKey,
			"reviewed_event_ids": nonNilStrings(e.ReviewedEventIDs),
			"outcome":            e.Outcome,
			"winning_event_id":   e.WinningEventID,
			"rationale_sha256":   e.RationaleSHA256,
			"rationale_uri":      e.RationaleURI,
			"governance_ref":     e.GovernanceRef,
			"created_at_unix":    e.CreatedAtUnix,
		}, nil
	default:
		return nil, fmt.Errorf("unknown event_type: %q", e.EventType)
	}
}

// ComputeEventID computes the deterministic SHA-256 event_id of an Event.
func ComputeEventID(e Event) (string, error) {
	m, err := UnsignedEventMap(e)
	if err != nil {
		return "", err
	}
	raw, err := CanonicalJSON(m)
	if err != nil {
		return "", err
	}
	return SHA256Hex(raw), nil
}

// SigningMessage returns the domain-separated byte string signed by Ed25519.
func SigningMessage(eventID string) []byte {
	return []byte(SigningDomainEvent + eventID)
}

// SignEvent computes event_id and signs it with the given Ed25519 private key.
func SignEvent(e *Event, priv ed25519.PrivateKey) error {
	id, err := ComputeEventID(*e)
	if err != nil {
		return err
	}
	e.EventID = id
	sig := ed25519.Sign(priv, SigningMessage(id))
	e.SignatureHex = hex.EncodeToString(sig)
	return nil
}

// ComputeStateRootHash computes the canonical SHA-256 state root hash over StateCommitment.
func ComputeStateRootHash(c StateCommitment) (string, error) {
	entries := make([]any, 0, len(c.EntryStates))
	for _, es := range c.EntryStates {
		entries = append(entries, map[string]any{
			"event_id":             es.EventID,
			"contributor_id":       es.ContributorID,
			"domain":               es.Domain,
			"claim_key":            es.ClaimKey,
			"claim_value_hash":     es.ClaimValueHash,
			"artifact_sha256":      es.ArtifactSHA256,
			"artifact_uri":         es.ArtifactURI,
			"status":               es.Status,
			"revoked_by":           nonNilStrings(es.RevokedBy),
			"tainted_by_ancestors": nonNilStrings(es.TaintedByAncestors),
			"unresolved_parents":   nonNilStrings(es.UnresolvedParents),
		})
	}
	conflicts := make([]any, 0, len(c.Conflicts))
	for _, cs := range c.Conflicts {
		conflicts = append(conflicts, map[string]any{
			"slot":                cs.Slot,
			"domain":              cs.Domain,
			"claim_key":           cs.ClaimKey,
			"status":              cs.Status,
			"competing_event_ids": nonNilStrings(cs.CompetingEventIDs),
			"flag_ids":            nonNilStrings(cs.FlagIDs),
			"resolution_ids":      nonNilStrings(cs.ResolutionIDs),
			"canonical_event_id":  cs.CanonicalEventID,
		})
	}
	rejected := make([]any, 0, len(c.RejectedEvents))
	for _, rj := range c.RejectedEvents {
		rejected = append(rejected, map[string]any{
			"event_id":   rj.EventID,
			"event_type": rj.EventType,
			"error_code": rj.ErrorCode,
		})
	}
	m := map[string]any{
		"schema_version":      c.SchemaVersion,
		"policy_sha256":       c.PolicySHA256,
		"active_merkle_root":  c.ActiveMerkleRoot,
		"entry_states":        entries,
		"conflicts":           conflicts,
		"pending_revocations": nonNilStrings(c.PendingRevocations),
		"rejected_events":     rejected,
	}
	raw, err := CanonicalJSON(m)
	if err != nil {
		return "", err
	}
	return SHA256Hex(raw), nil
}

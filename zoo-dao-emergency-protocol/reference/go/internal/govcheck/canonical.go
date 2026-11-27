// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package govcheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// CanonicalJSON encodes any JSON-serializable Go value into deterministic,
// compact UTF-8 JSON with lexicographically sorted object keys and no HTML escaping.
func CanonicalJSON(v any) ([]byte, error) {
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
	if err := writeCanonical(&buf, generic); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(val.String())
	case string:
		b, err := marshalStringNoEscape(val)
		if err != nil {
			return err
		}
		buf.Write(b)
	case []any:
		buf.WriteByte('[')
		for i, elem := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := marshalStringNoEscape(k)
			if err != nil {
				return err
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonical(buf, val[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical type %T", v)
	}
	return nil
}

func marshalStringNoEscape(s string) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	out := b.Bytes()
	if len(out) > 0 && out[len(out)-1] == '\n' {
		out = out[:len(out)-1]
	}
	return out, nil
}

// SigningPreimage builds the canonical domain-separated signing payload for a
// specific signer (binding actor_id and monotonic nonce to the action body).
func SigningPreimage(act GovernanceAction, signerID string, nonce uint64) ([]byte, error) {
	scopes := make([]string, len(act.Scopes))
	copy(scopes, act.Scopes)
	sort.Strings(scopes)

	payload := map[string]any{
		"action_id":            act.ID,
		"actor_id":             act.ActorID,
		"amount":               act.Amount,
		"appeal_outcome":       act.AppealOutcome,
		"contested_id":         act.ContestedID,
		"delegation_id":        act.DelegationID,
		"duration_sec":         act.DurationSec,
		"emergency_bypass":     act.EmergencyBypass,
		"epoch":                act.Epoch,
		"experiment_author_id": act.ExperimentAuthorID,
		"nonce":                nonce,
		"proposal_id":          act.ProposalID,
		"scopes":               scopes,
		"signer_id":            signerID,
		"target":               act.Target,
		"type":                 act.Type,
	}
	if act.NewRule != nil {
		payload["new_rule"] = map[string]any{
			"action_type": act.NewRule.ActionType,
			"condition":   act.NewRule.Condition,
			"effect":      string(act.NewRule.Effect),
			"id":          act.NewRule.ID,
			"rationale":   act.NewRule.Rationale,
			"target":      act.NewRule.Target,
			"tier":        string(act.NewRule.Tier),
		}
	} else {
		payload["new_rule"] = nil
	}
	canon, err := CanonicalJSON(payload)
	if err != nil {
		return nil, err
	}
	prefix := []byte("constitutional-gov.v1:sign:")
	out := make([]byte, 0, len(prefix)+len(canon))
	out = append(out, prefix...)
	out = append(out, canon...)
	return out, nil
}

// CaseDigest computes the canonical SHA-256 digest of a verified adversarial case verdict.
func CaseDigest(c AdversarialCase) (string, error) {
	proj := map[string]any{
		"actual_error_code":   c.ActualErrorCode,
		"actual_verdict":      string(c.ActualVerdict),
		"case_id":             c.CaseID,
		"expected_error_code": c.ExpectedErrorCode,
		"expected_verdict":    string(c.ExpectedVerdict),
		"invariant_id":        c.InvariantID,
		"passed":              c.Passed,
	}
	if c.ConflictWitness != nil {
		allows := append([]string(nil), c.ConflictWitness.AllowRuleIDs...)
		denies := append([]string(nil), c.ConflictWitness.DenyRuleIDs...)
		sort.Strings(allows)
		sort.Strings(denies)
		proj["conflict_witness"] = map[string]any{
			"action_id":      c.ConflictWitness.ActionID,
			"action_type":    c.ConflictWitness.ActionType,
			"allow_rule_ids": allows,
			"deny_rule_ids":  denies,
			"epoch":          c.ConflictWitness.Epoch,
			"resolution":     c.ConflictWitness.Resolution,
			"target":         c.ConflictWitness.Target,
			"tier":           string(c.ConflictWitness.Tier),
		}
	} else {
		proj["conflict_witness"] = nil
	}
	canon, err := CanonicalJSON(proj)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte("constitutional-gov.v1:case:"))
	h.Write(canon)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// AuditMerkleRoot computes a domain-separated binary SHA-256 Merkle root over
// case digests sorted by case_id (matching the independent Python verifier bit-for-bit).
func AuditMerkleRoot(cases []AdversarialCase) (string, error) {
	if len(cases) == 0 {
		h := sha256.Sum256([]byte("constitutional-gov.v1:empty"))
		return hex.EncodeToString(h[:]), nil
	}
	ordered := make([]AdversarialCase, len(cases))
	copy(ordered, cases)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].CaseID < ordered[j].CaseID
	})
	level := make([][32]byte, len(ordered))
	for i, c := range ordered {
		dig, err := CaseDigest(c)
		if err != nil {
			return "", err
		}
		raw, err := hex.DecodeString(dig)
		if err != nil {
			return "", err
		}
		h := sha256.New()
		h.Write([]byte{0x00})
		h.Write(raw)
		copy(level[i][:], h.Sum(nil))
	}
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			h := sha256.New()
			h.Write([]byte{0x01})
			h.Write(left[:])
			h.Write(right[:])
			var node [32]byte
			copy(node[:], h.Sum(nil))
			next = append(next, node)
		}
		level = next
	}
	return hex.EncodeToString(level[0][:]), nil
}

// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package forkorg

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

// CanonicalJSON serializes any JSON-compatible Go value to deterministic RFC 8259
// canonical JSON (sorted object keys, no whitespace, no HTML escaping).
// Matches Python: json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).
func CanonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var parsed any
	if err := dec.Decode(&parsed); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, parsed); err != nil {
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
	case json.Number:
		// All protocol numbers are exact integers; validate and emit canonical decimal.
		if i, err := strconv.ParseInt(x.String(), 10, 64); err == nil {
			buf.WriteString(strconv.FormatInt(i, 10))
		} else {
			buf.WriteString(x.String())
		}
	case string:
		writeCanonicalString(buf, x)
	case []any:
		buf.WriteByte('[')
		for i, elem := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, elem); err != nil {
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
		return fmt.Errorf("unsupported canonical json type: %T", v)
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
				buf.WriteString(fmt.Sprintf(`\u%04x`, r))
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// DomainMessage constructs the canonical byte message: domain || 0x00 || CanonicalJSON(v).
func DomainMessage(domain string, v any) ([]byte, error) {
	body, err := CanonicalJSON(v)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(domain)+1+len(body))
	out = append(out, []byte(domain)...)
	out = append(out, 0x00)
	out = append(out, body...)
	return out, nil
}

// HashCanonical returns lowercase hex SHA-256(domain || 0x00 || CanonicalJSON(v)).
func HashCanonical(domain string, v any) string {
	msg, err := DomainMessage(domain, v)
	if err != nil {
		panic(fmt.Sprintf("HashCanonical failed for %s: %v", domain, err))
	}
	sum := sha256.Sum256(msg)
	return hex.EncodeToString(sum[:])
}

// SHA256Hex returns lowercase hex SHA-256 of raw bytes.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// MerkleRootRFC6962 computes the RFC 6962 binary Merkle tree root over UTF-8 leaf strings.
// LeafHash(d) = SHA256(0x00 || d), NodeHash(l, r) = SHA256(0x01 || l || r).
// Empty tree returns SHA256("").
func MerkleRootRFC6962(leaves []string) string {
	if len(leaves) == 0 {
		sum := sha256.Sum256(nil)
		return hex.EncodeToString(sum[:])
	}
	root := merkleSubtree(leaves)
	return hex.EncodeToString(root[:])
}

func merkleSubtree(leaves []string) [32]byte {
	n := len(leaves)
	if n == 1 {
		h := sha256.New()
		h.Write([]byte{0x00})
		h.Write([]byte(leaves[0]))
		var out [32]byte
		copy(out[:], h.Sum(nil))
		return out
	}
	// Largest power of 2 strictly less than n.
	k := 1
	for (k << 1) < n {
		k <<= 1
	}
	left := merkleSubtree(leaves[:k])
	right := merkleSubtree(leaves[k:])
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

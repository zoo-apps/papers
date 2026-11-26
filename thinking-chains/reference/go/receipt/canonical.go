// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation and Contributors

package receipt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ParseStrictJSON parses UTF-8 JSON while rejecting UTF-8 BOM, invalid UTF-8,
// duplicate object keys, floating-point or scientific-notation numbers,
// int64 overflow, and trailing garbage.
func ParseStrictJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, newError("ERR_INVALID_JSON", "input is not valid UTF-8")
	}
	if bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, newError("ERR_INVALID_JSON", "UTF-8 BOM is forbidden")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	val, err := decodeStrictValue(dec)
	if err != nil {
		return nil, err
	}
	// Ensure no trailing tokens exist after the root JSON value.
	if tok, err := dec.Token(); err != io.EOF {
		return nil, newError("ERR_INVALID_JSON", "unexpected trailing token: %v", tok)
	}
	return val, nil
}

func decodeStrictValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, newError("ERR_INVALID_JSON", "malformed JSON: %v", err)
	}
	return decodeFromToken(dec, tok)
}

func decodeFromToken(dec *json.Decoder, tok json.Token) (any, error) {
	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			obj := make(map[string]any)
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, newError("ERR_INVALID_JSON", "expected object key: %v", err)
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, newError("ERR_INVALID_JSON", "object key must be string")
				}
				if _, exists := obj[key]; exists {
					return nil, newError("ERR_DUPLICATE_KEY", "duplicate JSON object key detected: %q", key)
				}
				val, err := decodeStrictValue(dec)
				if err != nil {
					return nil, err
				}
				obj[key] = val
			}
			endTok, err := dec.Token()
			if err != nil || endTok != json.Delim('}') {
				return nil, newError("ERR_INVALID_JSON", "expected closing brace")
			}
			return obj, nil
		case '[':
			arr := make([]any, 0)
			for dec.More() {
				item, err := decodeStrictValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, item)
			}
			endTok, err := dec.Token()
			if err != nil || endTok != json.Delim(']') {
				return nil, newError("ERR_INVALID_JSON", "expected closing bracket")
			}
			return arr, nil
		default:
			return nil, newError("ERR_INVALID_JSON", "unexpected delimiter %q", v)
		}
	case json.Number:
		s := string(v)
		if strings.ContainsAny(s, ".eE") {
			return nil, newError("ERR_FLOAT_FORBIDDEN", "floating-point or exponent literal not permitted: %q", s)
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return nil, newError("ERR_SCHEMA_VIOLATION", "integer %q out of int64 range: %v", s, err)
		}
		return n, nil
	case string:
		return v, nil
	case bool:
		return v, nil
	case nil:
		return nil, nil
	default:
		return nil, newError("ERR_INVALID_JSON", "unexpected JSON token type %T", tok)
	}
}

// CanonicalJSON encodes value using an integer-only strict profile of RFC 8785 (JCS).
// Object keys are sorted in ascending UTF-8 byte order; HTML chars (<, >, &) are NOT escaped;
// non-ASCII UTF-8 bytes are emitted literally; zero insignificant whitespace is emitted.
func CanonicalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeCanonicalValue(&buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeCanonicalValue(buf *bytes.Buffer, val any) error {
	switch v := val.(type) {
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case int64:
		buf.WriteString(strconv.FormatInt(v, 10))
		return nil
	case int:
		buf.WriteString(strconv.FormatInt(int64(v), 10))
		return nil
	case float64, float32:
		return newError("ERR_FLOAT_FORBIDDEN", "float value not permitted in canonical JSON")
	case string:
		writeCanonicalString(buf, v)
		return nil
	case nil:
		buf.WriteString("null")
		return nil
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeCanonicalValue(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
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
			if err := encodeCanonicalValue(buf, v[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	default:
		return newError("ERR_SCHEMA_VIOLATION", "unsupported canonical JSON type %T", val)
	}
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

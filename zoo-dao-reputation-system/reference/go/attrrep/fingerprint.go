// SPDX-License-Identifier: Apache-2.0

package attrrep

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// strippedArgCommands lists LaTeX metadata/reference commands whose braced
// arguments carry no semantic scientific prose (e.g. \label{sec:foo}, \cite{bar}).
var strippedArgCommands = map[string]bool{
	"label":         true,
	"ref":           true,
	"eqref":         true,
	"cite":          true,
	"citep":         true,
	"citet":         true,
	"usepackage":    true,
	"documentclass": true,
	"bibliographystyle": true,
	"bibliography":  true,
	"vspace":        true,
	"hspace":        true,
	"begin":         true,
	"end":           true,
}

// NormalizeScientificText converts raw LaTeX/plaintext scientific text into a
// canonical whitespace-normalized, lowercase ASCII token sequence.
//
// Invariants (verified bit-identically in Go and Python):
//   - Unescaped LaTeX '%' line comments are removed.
//   - Metadata/formatting commands (\label{...}, \cite{...}, \vspace{...}, etc.)
//     have their optional [...] and mandatory {...} arguments removed.
//   - Other LaTeX command names (\textbf, \emph, \section, etc.) are stripped
//     while preserving the inner prose words inside {...}.
//   - ASCII letters are lowercased; only [a-z0-9] are kept inside tokens,
//     separated by single ASCII spaces.
func NormalizeScientificText(raw string) []string {
	// Step 1: Strip unescaped '%' comments to end-of-line.
	var noComments strings.Builder
	noComments.Grow(len(raw))
	inComment := false
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if inComment {
			if ch == '\n' {
				inComment = false
				noComments.WriteByte('\n')
			}
			continue
		}
		if ch == '%' {
			// Count preceding consecutive backslashes.
			bs := 0
			for j := i - 1; j >= 0 && raw[j] == '\\'; j-- {
				bs++
			}
			if bs%2 == 0 {
				inComment = true
				continue
			}
		}
		noComments.WriteByte(ch)
	}
	s := noComments.String()

	// Step 2: Strip LaTeX commands (and their arguments for metadata commands).
	var cleaned strings.Builder
	cleaned.Grow(len(s))
	n := len(s)
	i := 0
	for i < n {
		if s[i] == '\\' && i+1 < n && isASCIILetter(s[i+1]) {
			start := i + 1
			j := start
			for j < n && isASCIILetter(s[j]) {
				j++
			}
			cmd := s[start:j]
			// Skip optional star variant like \section*
			if j < n && s[j] == '*' {
				j++
			}
			if strippedArgCommands[cmd] {
				// Skip whitespace and optional [...] then mandatory {...}.
				j = skipSpaces(s, j)
				if j < n && s[j] == '[' {
					j = skipBalanced(s, j, '[', ']')
					j = skipSpaces(s, j)
				}
				if j < n && s[j] == '{' {
					j = skipBalanced(s, j, '{', '}')
				}
			}
			cleaned.WriteByte(' ')
			i = j
			continue
		}
		cleaned.WriteByte(s[i])
		i++
	}

	// Step 3: Extract lowercase ASCII alphanumeric tokens.
	cs := cleaned.String()
	var tokens []string
	var cur strings.Builder
	for k := 0; k < len(cs); k++ {
		ch := cs[k]
		if ch >= 'A' && ch <= 'Z' {
			cur.WriteByte(ch + ('a' - 'A'))
		} else if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') {
			cur.WriteByte(ch)
		} else {
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func skipSpaces(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n') {
		i++
	}
	return i
}

func skipBalanced(s string, i int, openCh, closeCh byte) int {
	if i >= len(s) || s[i] != openCh {
		return i
	}
	depth := 0
	for i < len(s) {
		if s[i] == openCh {
			depth++
		} else if s[i] == closeCh {
			depth--
			if depth == 0 {
				return i + 1
			}
		}
		i++
	}
	return i
}

// ArtifactFingerprints holds all deterministic content digests and Winnowing hashes.
type ArtifactFingerprints struct {
	RawSHA256         string
	CanonicalDigest   string
	WinnowFingerprint []string
	FingerprintDigest string
	TokenCount        int
}

// ComputeFingerprints computes raw SHA-256, canonical digest, and k-shingle
// Winnowing fingerprint (k=4, w=3) deterministically.
func ComputeFingerprints(raw string) ArtifactFingerprints {
	rawDigest := SHA256Hex([]byte(raw))
	tokens := NormalizeScientificText(raw)
	canonicalJoined := strings.Join(tokens, " ")
	canonicalDigest := DomainSHA256Hex(domainCanonicalText, []byte(canonicalJoined))

	// Build word k-shingle uint64 hashes.
	var shingleHashes []uint64
	if len(tokens) == 0 {
		shingleHashes = []uint64{hashShingle("")}
	} else if len(tokens) < ShingleSize {
		shingleHashes = []uint64{hashShingle(canonicalJoined)}
	} else {
		shingleHashes = make([]uint64, 0, len(tokens)-ShingleSize+1)
		for i := 0; i <= len(tokens)-ShingleSize; i++ {
			sh := strings.Join(tokens[i:i+ShingleSize], " ")
			shingleHashes = append(shingleHashes, hashShingle(sh))
		}
	}

	// Robust Winnowing: window size w = WinnowWindow, pick rightmost minimum per window.
	selected := make(map[uint64]struct{})
	if len(shingleHashes) <= WinnowWindow {
		minVal := shingleHashes[0]
		for _, h := range shingleHashes[1:] {
			if h <= minVal {
				minVal = h
			}
		}
		selected[minVal] = struct{}{}
	} else {
		for i := 0; i <= len(shingleHashes)-WinnowWindow; i++ {
			minVal := shingleHashes[i]
			for j := i + 1; j < i+WinnowWindow; j++ {
				if shingleHashes[j] <= minVal {
					minVal = shingleHashes[j]
				}
			}
			selected[minVal] = struct{}{}
		}
	}

	vals := make([]uint64, 0, len(selected))
	for v := range selected {
		vals = append(vals, v)
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })

	fpHex := make([]string, len(vals))
	buf := make([]byte, len(vals)*8)
	for i, v := range vals {
		fpHex[i] = fmt.Sprintf("%016x", v)
		binary.BigEndian.PutUint64(buf[i*8:(i+1)*8], v)
	}
	fpDigest := DomainSHA256Hex(domainWinnowDigest, buf)

	return ArtifactFingerprints{
		RawSHA256:         rawDigest,
		CanonicalDigest:   canonicalDigest,
		WinnowFingerprint: fpHex,
		FingerprintDigest: fpDigest,
		TokenCount:        len(tokens),
	}
}

func hashShingle(shingle string) uint64 {
	h := sha256.New()
	h.Write([]byte(domainShingle))
	h.Write([]byte(shingle))
	sum := h.Sum(nil)
	return binary.BigEndian.Uint64(sum[:8])
}

// ComputeFingerprintDigestFromHex validates and hashes an existing sorted list of
// 16-char lowercase hex uint64 Winnowing hashes.
func ComputeFingerprintDigestFromHex(fp []string) (string, bool) {
	buf := make([]byte, len(fp)*8)
	for i, s := range fp {
		if len(s) != 16 {
			return "", false
		}
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 8 {
			return "", false
		}
		if i > 0 && fp[i] <= fp[i-1] {
			return "", false
		}
		copy(buf[i*8:(i+1)*8], b)
	}
	return DomainSHA256Hex(domainWinnowDigest, buf), true
}

// ContainmentBps returns floor(|A ∩ B| * 10000 / |A|) for sorted fingerprint sets.
func ContainmentBps(a, b []string) int64 {
	if len(a) == 0 {
		return 0
	}
	inter := sortedIntersectionCount(a, b)
	return (int64(inter) * BpsScale) / int64(len(a))
}

// JaccardBps returns floor(|A ∩ B| * 10000 / |A ∪ B|) for sorted fingerprint sets.
func JaccardBps(a, b []string) int64 {
	if len(a) == 0 && len(b) == 0 {
		return BpsScale
	}
	inter := sortedIntersectionCount(a, b)
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return (int64(inter) * BpsScale) / int64(union)
}

func sortedIntersectionCount(a, b []string) int {
	i, j, count := 0, 0, 0
	for i < len(a) && j < len(b) {
		if a[i] == b[j] {
			count++
			i++
			j++
		} else if a[i] < b[j] {
			i++
		} else {
			j++
		}
	}
	return count
}

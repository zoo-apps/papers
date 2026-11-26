// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation

package verifier

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	reTexFormatCmd = regexp.MustCompile(`\\(textbf|emph|textit|textsc|texttt|text|mathrm|mathbf)\{([^{}]*)\}`)
	reTexMacroPair = []struct {
		old string
		new string
	}{
		{`\PoAI{}`, "PoAI"},
		{`\PoAI`, "PoAI"},
		{`\PoT{}`, "PoT"},
		{`\PoT`, "PoT"},
		{`\Quasar{}`, "Quasar"},
		{`\Quasar`, "Quasar"},
		{`\LLM{}`, "LLM"},
		{`\LLM`, "LLM"},
		{`\DAO{}`, "DAO"},
		{`\DAO`, "DAO"},
		{`\ZOO{}`, "ZOO"},
		{`\ZOO`, "ZOO"},
		{`\Zoo{}`, "Zoo"},
		{`\Zoo`, "Zoo"},
		{`\TPS{}`, "TPS"},
		{`\TPS`, "TPS"},
		{`\EVM{}`, "EVM"},
		{`\EVM`, "EVM"},
		{`\IPFS{}`, "IPFS"},
		{`\IPFS`, "IPFS"},
		{`\REP{}`, "REP"},
		{`\REP`, "REP"},
		{`\Lux{}`, "Lux"},
		{`\Lux`, "Lux"},
		{`\noindent`, " "},
		{`\medskip`, " "},
		{`\bigskip`, " "},
		{`\smallskip`, " "},
		{`\geq`, ">="},
		{`\leq`, "<="},
		{`\ge`, ">="},
		{`\le`, "<="},
		{`\times`, "x"},
		{`\approx`, "~"},
		{`\sim`, "~"},
		{`\%`, "%"},
		{`\,`, ""},
		{`\!`, ""},
		{`\;`, " "},
		{`~`, " "},
		{`---`, " - "},
		{`--`, "-"},
	}
	reWhitespace     = regexp.MustCompile(`\s+`)
	reSectionHeader  = regexp.MustCompile(`(?i)\\(?:sub)*section\*?\{([^}]*)\}|\\begin\{(abstract)\}|\\begin\{(?:theorem|lemma|principle|definition|proposition)\}\[([^\]]*)\]`)
	reWordToken      = regexp.MustCompile(`[a-z0-9]+`)
	reNumberLiteral  = regexp.MustCompile(`(?i)(\d+\^\{?\d+\}?|\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?)(k|m|b|gb|pb|ms|%)?`)
	negationTriggers = []string{
		"never ",
		" not ",
		"cannot ",
		"does not ",
		"may not ",
		"no premine",
		"no coin ",
		"without ",
		"neither ",
		"none ",
	}
)

// NormalizeLaTeX deterministically strips comments, common formatting macros,
// braces, and math delimiters, collapsing whitespace to single spaces in lowercase.
func NormalizeLaTeX(raw string) string {
	lines := strings.Split(raw, "\n")
	cleaned := make([]string, 0, len(lines))
	for _, line := range lines {
		// Strip unescaped % comments.
		idx := -1
		for i := 0; i < len(line); i++ {
			if line[i] == '%' && (i == 0 || line[i-1] != '\\') {
				idx = i
				break
			}
		}
		if idx >= 0 {
			line = line[:idx]
		}
		cleaned = append(cleaned, line)
	}
	s := strings.Join(cleaned, " ")
	for _, pair := range reTexMacroPair {
		s = strings.ReplaceAll(s, pair.old, pair.new)
	}
	// Iteratively unwrap formatting commands (up to 4 nesting levels).
	for pass := 0; pass < 4; pass++ {
		next := reTexFormatCmd.ReplaceAllString(s, "$2")
		if next == s {
			break
		}
		s = next
	}
	// Strip math delimiters and stray braces.
	repl := strings.NewReplacer(
		"$", "",
		"{", "",
		"}", "",
		"``", "\"",
		"''", "\"",
		"\\", " ",
	)
	s = repl.Replace(s)
	s = strings.ToLower(s)
	s = strings.TrimSpace(reWhitespace.ReplaceAllString(s, " "))
	return s
}

// extractScopedSection finds the text corresponding to sectionHint in raw LaTeX.
// Returns (scopedRaw, found).
func extractScopedSection(raw string, sectionHint string) (string, bool) {
	hint := strings.TrimSpace(strings.ToLower(sectionHint))
	if hint == "" {
		return raw, true
	}
	matches := reSectionHeader.FindAllStringSubmatchIndex(raw, -1)
	for idx, m := range matches {
		title := ""
		if m[2] >= 0 && m[3] >= 0 {
			title = raw[m[2]:m[3]]
		} else if m[4] >= 0 && m[5] >= 0 {
			title = raw[m[4]:m[5]]
		} else if m[6] >= 0 && m[7] >= 0 {
			title = raw[m[6]:m[7]]
		}
		normTitle := NormalizeLaTeX(title)
		normHint := NormalizeLaTeX(hint)
		if strings.Contains(normTitle, normHint) || normTitle == normHint {
			start := m[0]
			end := len(raw)
			if strings.EqualFold(title, "abstract") {
				if endIdx := strings.Index(raw[start:], `\end{abstract}`); endIdx >= 0 {
					end = start + endIdx + len(`\end{abstract}`)
				}
			} else if idx+1 < len(matches) {
				// Extend to next top-level section or theorem boundary if not subsection.
				for j := idx + 1; j < len(matches); j++ {
					hdr := raw[matches[j][0]:matches[j][1]]
					if strings.HasPrefix(strings.ToLower(hdr), `\section`) ||
						strings.HasPrefix(strings.ToLower(hdr), `\begin{theorem`) ||
						strings.HasPrefix(strings.ToLower(hdr), `\begin{lemma`) ||
						strings.HasPrefix(strings.ToLower(hdr), `\begin{principle`) {
						end = matches[j][0]
						break
					}
				}
			}
			return raw[start:end], true
		}
	}
	return "", false
}

// extractNumbers parses numeric values (including 10^9, 47,619, 10K, 4.76M, 70B) from normalized text.
func extractNumbers(norm string) []float64 {
	matches := reNumberLiteral.FindAllStringSubmatch(norm, -1)
	out := make([]float64, 0, len(matches)*2)
	for _, m := range matches {
		numStr := strings.ReplaceAll(m[1], ",", "")
		suffix := strings.ToLower(m[2])
		var base float64
		var ok bool
		if strings.Contains(numStr, "^") {
			parts := strings.SplitN(numStr, "^", 2)
			b, err1 := strconv.ParseFloat(parts[0], 64)
			e, err2 := strconv.ParseFloat(parts[1], 64)
			if err1 == nil && err2 == nil {
				base = math.Pow(b, e)
				ok = true
			}
		} else {
			f, err := strconv.ParseFloat(numStr, 64)
			if err == nil {
				base = f
				ok = true
			}
		}
		if !ok || math.IsNaN(base) || math.IsInf(base, 0) {
			continue
		}
		out = append(out, base)
		switch suffix {
		case "k":
			out = append(out, base*1e3)
		case "m":
			out = append(out, base*1e6)
		case "b":
			out = append(out, base*1e9)
		case "ms":
			out = append(out, base/1e3)
		}
	}
	return out
}

func numberMatchesAny(target float64, candidates []float64) bool {
	for _, c := range candidates {
		diff := math.Abs(target - c)
		tol := math.Max(1e-9, 1e-5*math.Max(math.Abs(target), math.Abs(c)))
		if diff <= tol {
			return true
		}
	}
	return false
}

func hasNegation(norm string) bool {
	padded := " " + norm + " "
	for _, trig := range negationTriggers {
		if strings.Contains(padded, trig) {
			return true
		}
	}
	return false
}

func isNonSentenceDot(s string, i int) bool {
	if i > 0 && i+1 < len(s) && s[i] == '.' &&
		s[i-1] >= '0' && s[i-1] <= '9' &&
		s[i+1] >= '0' && s[i+1] <= '9' {
		return true
	}
	if i >= 2 && s[i-2:i+1] == "vs." && (i == 2 || s[i-3] == ' ' || s[i-3] == '(') {
		return true
	}
	if i >= 3 && (s[i-3:i+1] == "e.g." || s[i-3:i+1] == "i.e.") {
		return true
	}
	return false
}

func extractEnclosingClause(normText string, matchIdx int, matchLen int) string {
	start := matchIdx
	for start > 0 {
		c := normText[start-1]
		if (c == '.' && !isNonSentenceDot(normText, start-1)) || c == ';' || c == '\n' {
			break
		}
		if start >= 3 && normText[start-3:start] == " - " {
			break
		}
		start--
	}
	end := matchIdx + matchLen
	for end < len(normText) {
		c := normText[end]
		if (c == '.' && !isNonSentenceDot(normText, end)) || c == ';' || c == '\n' {
			end++
			break
		}
		if end+3 <= len(normText) && normText[end:end+3] == " - " {
			break
		}
		end++
	}
	return strings.TrimSpace(normText[start:end])
}

func splitSentences(normText string) []string {
	var out []string
	start := 0
	for i := 0; i < len(normText); i++ {
		if (normText[i] == '.' && !isNonSentenceDot(normText, i)) || normText[i] == ';' || normText[i] == '\n' {
			seg := strings.TrimSpace(normText[start:i])
			if seg != "" {
				out = append(out, seg)
			}
			start = i + 1
		}
	}
	if start < len(normText) {
		seg := strings.TrimSpace(normText[start:])
		if seg != "" {
			out = append(out, seg)
		}
	}
	return out
}

func contentTokens(norm string) map[string]struct{} {
	toks := reWordToken.FindAllString(norm, -1)
	res := make(map[string]struct{}, len(toks))
	for _, t := range toks {
		if len(t) < 3 {
			continue
		}
		allDigits := true
		for i := 0; i < len(t); i++ {
			if t[i] < '0' || t[i] > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			continue
		}
		res[t] = struct{}{}
	}
	return res
}

func bestSentenceOverlap(normScoped string, normQuote string) (float64, string) {
	qToks := contentTokens(normQuote)
	if len(qToks) == 0 {
		return 0, ""
	}
	sentences := splitSentences(normScoped)
	bestScore := 0.0
	bestSent := ""
	for _, sent := range sentences {
		sToks := contentTokens(sent)
		if len(sToks) == 0 {
			continue
		}
		overlap := 0
		for tok := range qToks {
			if _, ok := sToks[tok]; ok {
				overlap++
			}
		}
		score := float64(overlap) / float64(len(qToks))
		if score > bestScore {
			bestScore = score
			bestSent = sent
		}
	}
	return bestScore, bestSent
}

func (v *Verifier) verifyCitation(claim EvidenceClaim) VerificationResult {
	c := claim.Citation
	if c == nil {
		return makeResult(claim, VerdictUnsupported, ReasonMissingPayload, "citation payload missing", "", "")
	}
	if c.ReviewScope == "external_domain" || c.ReviewScope == "subjective_judgment" {
		return makeResult(claim, VerdictInconclusive, ReasonHumanReviewRequired, "claim requires external domain or subjective human review", "", "")
	}
	if strings.TrimSpace(c.SourcePath) == "" || strings.TrimSpace(c.ExpectedSHA256) == "" || strings.TrimSpace(c.QuotedSpan) == "" {
		return makeResult(claim, VerdictUnsupported, ReasonMissingCitationFields, "citation missing source_path, expected_sha256, or quoted_span", "", "")
	}
	// Path traversal guard.
	cleaned := filepath.Clean(c.SourcePath)
	if filepath.IsAbs(c.SourcePath) || strings.HasPrefix(cleaned, "..") || strings.Contains(c.SourcePath, "..") {
		return makeResult(claim, VerdictUnsupported, ReasonInvalidSourcePath, "citation source_path escapes corpus root", "", "")
	}
	fullPath := filepath.Join(v.CorpusRoot, cleaned)
	rawBytes, err := os.ReadFile(fullPath)
	if err != nil {
		return makeResult(claim, VerdictUnsupported, ReasonSourceNotFound, fmt.Sprintf("pinned source not found: %s", c.SourcePath), "", "")
	}
	actualSHA := SHA256Hex(rawBytes)
	if !IsValidHexSHA256(c.ExpectedSHA256) {
		return makeResult(claim, VerdictUnsupported, ReasonInvalidSHA256Format, "expected_sha256 is not a valid 64-char lowercase hex digest", "", actualSHA)
	}
	if actualSHA != c.ExpectedSHA256 {
		return makeResult(claim, VerdictRefuted, ReasonSourceSHA256Mismatch, "source file SHA-256 does not match pinned expected_sha256", "", actualSHA)
	}
	rawText := string(rawBytes)
	scopedRaw, foundSec := extractScopedSection(rawText, c.SectionHint)
	if !foundSec {
		return makeResult(claim, VerdictRefuted, ReasonSectionNotFound, fmt.Sprintf("section hint not found: %s", c.SectionHint), "", actualSHA)
	}
	normScoped := NormalizeLaTeX(scopedRaw)
	normQuote := NormalizeLaTeX(c.QuotedSpan)
	if normQuote == "" {
		return makeResult(claim, VerdictUnsupported, ReasonMissingCitationFields, "quoted_span normalized to empty string", "", actualSHA)
	}

	if idx := strings.Index(normScoped, normQuote); idx >= 0 {
		// Exact normalized span match found.
		winStart := idx - 380
		if winStart < 0 {
			winStart = 0
		}
		winEnd := idx + len(normQuote) + 380
		if winEnd > len(normScoped) {
			winEnd = len(normScoped)
		}
		contextWindow := normScoped[winStart:winEnd]
		ctxNums := extractNumbers(contextWindow)
		for _, claimedNum := range c.ClaimedNumbers {
			if !numberMatchesAny(claimedNum, ctxNums) {
				return makeResult(claim, VerdictRefuted, ReasonNumericMismatch, fmt.Sprintf("claimed number %s absent from matched context window", FormatCanonicalFloat(claimedNum)), FormatCanonicalFloat(claimedNum), actualSHA)
			}
		}
		sentence := extractEnclosingClause(normScoped, idx, len(normQuote))
		sentNeg := hasNegation(sentence)
		quoteNeg := hasNegation(normQuote)
		if c.ClaimedPolarity == "positive" && sentNeg && !quoteNeg {
			return makeResult(claim, VerdictRefuted, ReasonPolarityReversal, "enclosing sentence negates positive claim", "", actualSHA)
		}
		if c.ClaimedPolarity == "negative" && !sentNeg {
			return makeResult(claim, VerdictRefuted, ReasonPolarityReversal, "enclosing sentence lacks negation for negative claim", "", actualSHA)
		}
		return makeResult(claim, VerdictVerified, ReasonOKCitation, "pinned SHA-256, section, span, numeric, and polarity checks passed", "matched", actualSHA)
	}

	// No exact span match: inspect best matching sentence for numeric/polarity corruption vs paraphrase.
	bestScore, bestSent := bestSentenceOverlap(normScoped, normQuote)
	if bestScore >= 0.70 {
		quoteNums := extractNumbers(normQuote)
		sentNums := extractNumbers(bestSent)
		if len(quoteNums) > 0 {
			for _, qn := range quoteNums {
				if !numberMatchesAny(qn, sentNums) {
					return makeResult(claim, VerdictRefuted, ReasonQuoteNumericAlteration, fmt.Sprintf("quoted span alters number %s relative to source sentence", FormatCanonicalFloat(qn)), FormatCanonicalFloat(qn), actualSHA)
				}
			}
		}
		if hasNegation(normQuote) != hasNegation(bestSent) {
			return makeResult(claim, VerdictRefuted, ReasonQuotePolarityAlt, "quoted span flips negation polarity relative to source sentence", "", actualSHA)
		}
	}
	if !c.RequireExactSpan && bestScore >= 0.45 {
		quoteNums := extractNumbers(normQuote)
		sentNums := extractNumbers(bestSent)
		numsConsistent := true
		for _, qn := range quoteNums {
			if !numberMatchesAny(qn, sentNums) {
				numsConsistent = false
				break
			}
		}
		if numsConsistent {
			return makeResult(claim, VerdictInconclusive, ReasonParaphraseHumanReview, fmt.Sprintf("paraphrase overlap %s requires human or NLI review", FormatCanonicalFloat(bestScore)), FormatCanonicalFloat(bestScore), actualSHA)
		}
	}
	return makeResult(claim, VerdictUnsupported, ReasonQuoteNotFound, "quoted span not found verbatim in pinned source section", FormatCanonicalFloat(bestScore), actualSHA)
}

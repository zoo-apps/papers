// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation

package verifier

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

const (
	SchemaVersion = "1.0.0"

	DomainResultPrefix      = "zoo:evidence-verifier:v1:result:"
	DomainMerkleEmptyPrefix = "zoo:evidence-verifier:v1:merkle:empty"
	DomainMerkleNodePrefix  = "zoo:evidence-verifier:v1:merkle:node:"
)

// Verdict is the strict 4-way classification output of the verifier.
type Verdict string

const (
	VerdictVerified     Verdict = "VERIFIED_REPRODUCIBLE"
	VerdictRefuted      Verdict = "REFUTED_CONTRADICTION"
	VerdictUnsupported  Verdict = "UNSUPPORTED_INSUFFICIENT_EVIDENCE"
	VerdictInconclusive Verdict = "INCONCLUSIVE_NEEDS_HUMAN_REVIEW"
)

// AllVerdicts lists the canonical ordering of verdicts for confusion matrices.
var AllVerdicts = []Verdict{
	VerdictVerified,
	VerdictRefuted,
	VerdictUnsupported,
	VerdictInconclusive,
}

// ClaimClass enumerates the 4 verifiable claim categories.
type ClaimClass string

const (
	ClassCitation       ClaimClass = "citation_check"
	ClassCalculation    ClaimClass = "calc_check"
	ClassCodeResult     ClaimClass = "code_result_check"
	ClassReasoningChain ClaimClass = "reasoning_chain_check"
)

// AllClaimClasses lists the canonical ordering of claim classes.
var AllClaimClasses = []ClaimClass{
	ClassCitation,
	ClassCalculation,
	ClassCodeResult,
	ClassReasoningChain,
}

// Reason codes emitted deterministically by both Go and Python verifiers.
const (
	ReasonOKCitation            = "OK_CITATION_VERIFIED"
	ReasonOKCalc                = "OK_CALC_VERIFIED"
	ReasonOKCodeEval            = "OK_CODE_EVAL_VERIFIED"
	ReasonOKArtifactHash        = "OK_ARTIFACT_HASH_VERIFIED"
	ReasonOKStatisticalInterval = "OK_STATISTICAL_INTERVAL_VERIFIED"
	ReasonOKReasoningChain      = "OK_REASONING_CHAIN_VERIFIED"

	ReasonSelfValidation         = "ERR_CONSTITUTIONAL_SELF_VALIDATION"
	ReasonForbiddenGovAction     = "ERR_CONSTITUTIONAL_FORBIDDEN_ACTION"
	ReasonHumanReviewRequired    = "ERR_HUMAN_REVIEW_REQUIRED"
	ReasonUnknownClaimClass      = "ERR_UNKNOWN_CLAIM_CLASS"
	ReasonMissingPayload         = "ERR_MISSING_PAYLOAD"
	ReasonMissingCitationFields  = "ERR_MISSING_CITATION_FIELDS"
	ReasonInvalidSourcePath      = "ERR_INVALID_SOURCE_PATH"
	ReasonSourceNotFound         = "ERR_SOURCE_NOT_FOUND"
	ReasonInvalidSHA256Format    = "ERR_INVALID_SHA256_FORMAT"
	ReasonSourceSHA256Mismatch   = "ERR_SOURCE_SHA256_MISMATCH"
	ReasonSectionNotFound        = "ERR_SECTION_NOT_FOUND"
	ReasonNumericMismatch        = "ERR_NUMERIC_MISMATCH"
	ReasonPolarityReversal       = "ERR_POLARITY_REVERSAL"
	ReasonQuoteNumericAlteration = "ERR_QUOTE_NUMERIC_ALTERATION"
	ReasonQuotePolarityAlt       = "ERR_QUOTE_POLARITY_ALTERATION"
	ReasonParaphraseHumanReview  = "ERR_PARAPHRASE_NEEDS_HUMAN_REVIEW"
	ReasonQuoteNotFound          = "ERR_QUOTE_NOT_FOUND"

	ReasonMissingCalcFields = "ERR_MISSING_CALC_FIELDS"
	ReasonMissingUnit       = "ERR_MISSING_UNIT"
	ReasonUnitMismatch      = "ERR_UNIT_MISMATCH"
	ReasonInvalidExpression = "ERR_INVALID_EXPRESSION"
	ReasonUndefinedVariable = "ERR_UNDEFINED_VARIABLE"
	ReasonMathDomainError   = "ERR_MATH_DOMAIN_ERROR"
	ReasonCalcMismatch      = "ERR_CALC_MISMATCH"

	ReasonMissingCodeMode          = "ERR_MISSING_CODE_MODE"
	ReasonUnknownCodeOp            = "ERR_UNKNOWN_CODE_OP"
	ReasonInvalidCodeInput         = "ERR_INVALID_CODE_INPUT"
	ReasonCodeOutputMismatch       = "ERR_CODE_OUTPUT_MISMATCH"
	ReasonMissingArtifactPayload   = "ERR_MISSING_ARTIFACT_PAYLOAD"
	ReasonArtifactHashMismatch     = "ERR_ARTIFACT_HASH_MISMATCH"
	ReasonInsufficientSamples      = "ERR_INSUFFICIENT_SAMPLES"
	ReasonMeanOutsideCI            = "ERR_MEAN_OUTSIDE_CI"
	ReasonCIUnderestimated         = "ERR_CI_UNDERESTIMATED"
	ReasonCITooWide                = "ERR_CI_TOO_WIDE"
	ReasonStochasticRequiresBounds = "ERR_STOCHASTIC_REQUIRES_INTERVAL"

	ReasonEmptyReasoningChain  = "ERR_EMPTY_REASONING_CHAIN"
	ReasonDuplicateStepID      = "ERR_DUPLICATE_STEP_ID"
	ReasonMissingConclusion    = "ERR_MISSING_CONCLUSION_STEP"
	ReasonPrivateCoTForbidden  = "ERR_PRIVATE_COT_FORBIDDEN"
	ReasonReasoningCycle       = "ERR_REASONING_CYCLE"
	ReasonDanglingPremise      = "ERR_DANGLING_PREMISE"
	ReasonRefutedPremise       = "ERR_REFUTED_PREMISE"
	ReasonUnverifiedPremise    = "ERR_UNVERIFIED_PREMISE"
	ReasonInconclusivePremise  = "ERR_INCONCLUSIVE_PREMISE"
)

// ClaimBundle is a versioned collection of EvidenceClaims.
type ClaimBundle struct {
	SchemaVersion string          `json:"schema_version"`
	BundleID      string          `json:"bundle_id"`
	Seed          int64           `json:"seed"`
	Description   string          `json:"description,omitempty"`
	Claims        []EvidenceClaim `json:"claims"`
}

// EvidenceClaim represents a single public claim to verify.
type EvidenceClaim struct {
	SchemaVersion    string                 `json:"schema_version"`
	ClaimID          string                 `json:"claim_id"`
	ClaimClass       ClaimClass             `json:"claim_class"`
	Statement        string                 `json:"statement"`
	AuthorID         string                 `json:"author_id"`
	VerifierID       string                 `json:"verifier_id"`
	GovernanceAction string                 `json:"governance_action,omitempty"`
	ExpectedVerdict  Verdict                `json:"expected_verdict,omitempty"`
	NegativeRegime   string                 `json:"negative_regime,omitempty"`
	Notes            string                 `json:"notes,omitempty"`
	Citation         *CitationPayload       `json:"citation,omitempty"`
	Calculation      *CalculationPayload    `json:"calculation,omitempty"`
	CodeResult       *CodeResultPayload     `json:"code_result,omitempty"`
	ReasoningChain   *ReasoningChainPayload `json:"reasoning_chain,omitempty"`
}

// CitationPayload holds pinned document citation verification parameters.
type CitationPayload struct {
	SourcePath       string    `json:"source_path"`
	ExpectedSHA256   string    `json:"expected_sha256"`
	SectionHint      string    `json:"section_hint,omitempty"`
	QuotedSpan       string    `json:"quoted_span"`
	ClaimedNumbers   []float64 `json:"claimed_numbers,omitempty"`
	ClaimedPolarity  string    `json:"claimed_polarity,omitempty"`
	RequireExactSpan bool      `json:"require_exact_span"`
	ReviewScope      string    `json:"review_scope,omitempty"`
}

// CalculationPayload holds deterministic arithmetic/statistical verification parameters.
type CalculationPayload struct {
	Expression      string             `json:"expression"`
	Variables       map[string]float64 `json:"variables,omitempty"`
	ClaimedValue    float64            `json:"claimed_value"`
	HasClaimedValue bool               `json:"has_claimed_value"`
	Tolerance       float64            `json:"tolerance"`
	ToleranceMode   string             `json:"tolerance_mode,omitempty"`
	ExpectedUnit    string             `json:"expected_unit,omitempty"`
	ClaimedUnit     string             `json:"claimed_unit,omitempty"`
	ExactRational   bool               `json:"exact_rational,omitempty"`
	ReviewScope     string             `json:"review_scope,omitempty"`
}

// CodeProgram describes a bounded, deterministic verification kernel call.
type CodeProgram struct {
	Op     string         `json:"op"`
	Inputs map[string]any `json:"inputs,omitempty"`
}

// CodeResultPayload holds deterministic code or artifact verification parameters.
type CodeResultPayload struct {
	Mode            string       `json:"mode"`
	Program         *CodeProgram `json:"program,omitempty"`
	ExpectedOutput  any          `json:"expected_output,omitempty"`
	Tolerance       float64      `json:"tolerance,omitempty"`
	ArtifactPayload string       `json:"artifact_payload,omitempty"`
	DeclaredSHA256  string       `json:"declared_sha256,omitempty"`
	Samples         []float64    `json:"samples,omitempty"`
	ClaimedMean     float64      `json:"claimed_mean,omitempty"`
	HasClaimedMean  bool         `json:"has_claimed_mean,omitempty"`
	CIHalfwidth     float64      `json:"ci_halfwidth,omitempty"`
	Stochastic      bool         `json:"stochastic,omitempty"`
	ReviewScope     string       `json:"review_scope,omitempty"`
}

// ReasoningStep is a single node in a public reasoning DAG.
type ReasoningStep struct {
	StepID          string   `json:"step_id"`
	Kind            string   `json:"kind"`
	DependsOn       []string `json:"depends_on,omitempty"`
	EvidenceRef     string   `json:"evidence_ref,omitempty"`
	EvidenceVerdict string   `json:"evidence_verdict,omitempty"`
	PublicRationale string   `json:"public_rationale,omitempty"`
	OpaqueCoTBlob   bool     `json:"opaque_cot_blob,omitempty"`
}

// ReasoningChainPayload holds a public reasoning DAG to audit.
type ReasoningChainPayload struct {
	ConclusionStepID string          `json:"conclusion_step_id"`
	Steps            []ReasoningStep `json:"steps"`
	ReviewScope      string          `json:"review_scope,omitempty"`
}

// VerificationResult is the canonical, deterministic output for a single claim.
type VerificationResult struct {
	SchemaVersion  string     `json:"schema_version"`
	ClaimID        string     `json:"claim_id"`
	ClaimClass     ClaimClass `json:"claim_class"`
	Verdict        Verdict    `json:"verdict"`
	ReasonCode     string     `json:"reason_code"`
	Detail         string     `json:"detail"`
	ComputedValue  string     `json:"computed_value"`
	EvidenceSHA256 string     `json:"evidence_sha256"`
	ResultDigest   string     `json:"result_digest"`
}

// FormatCanonicalFloat formats a float deterministically to at most 9 decimal
// places (half-away-from-zero), stripping trailing zeros and normalizing -0 to 0.
func FormatCanonicalFloat(v float64) string {
	if math.IsNaN(v) {
		return "NaN"
	}
	if math.IsInf(v, 1) {
		return "+Inf"
	}
	if math.IsInf(v, -1) {
		return "-Inf"
	}
	const scale = 1e9
	var rounded float64
	if v >= 0 {
		rounded = math.Floor(v*scale+0.5) / scale
	} else {
		rounded = math.Ceil(v*scale-0.5) / scale
	}
	if rounded == 0 {
		rounded = 0
	}
	s := strconv.FormatFloat(rounded, 'f', 9, 64)
	if strings.Contains(s, ".") {
		s = strings.TrimRight(s, "0")
		s = strings.TrimRight(s, ".")
	}
	if s == "-0" || s == "" {
		return "0"
	}
	return s
}

// CanonicalJSON serializes an arbitrary JSON-compatible Go value with
// lexicographically sorted object keys and compact separators (no whitespace).
func CanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonicalJSON(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonicalJSON(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		b, err := json.Marshal(x)
		if err != nil {
			return err
		}
		buf.Write(b)
	case Verdict:
		return writeCanonicalJSON(buf, string(x))
	case ClaimClass:
		return writeCanonicalJSON(buf, string(x))
	case int:
		buf.WriteString(strconv.Itoa(x))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case float64:
		buf.WriteString(FormatCanonicalFloat(x))
	case json.Number:
		f, err := x.Float64()
		if err != nil {
			return err
		}
		buf.WriteString(FormatCanonicalFloat(f))
	case []string:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalJSON(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case []float64:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalJSON(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalJSON(buf, item); err != nil {
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
			if err := writeCanonicalJSON(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonicalJSON(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return err
		}
		var generic any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&generic); err != nil {
			return err
		}
		return writeCanonicalJSON(buf, generic)
	}
	return nil
}

// SHA256Hex computes the lowercase hex SHA-256 of bytes.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ComputeResultDigest computes the canonical domain-separated SHA-256 digest of a VerificationResult.
func ComputeResultDigest(r VerificationResult) string {
	m := map[string]any{
		"claim_class":     string(r.ClaimClass),
		"claim_id":        r.ClaimID,
		"computed_value":  r.ComputedValue,
		"detail":          r.Detail,
		"evidence_sha256": r.EvidenceSHA256,
		"reason_code":     r.ReasonCode,
		"schema_version":  r.SchemaVersion,
		"verdict":         string(r.Verdict),
	}
	canon, err := CanonicalJSON(m)
	if err != nil {
		panic(fmt.Sprintf("canonical json failed: %v", err))
	}
	payload := append([]byte(DomainResultPrefix), canon...)
	return SHA256Hex(payload)
}

// ComputeAuditMerkleRoot computes the binary SHA-256 Merkle root over results sorted by claim_id.
func ComputeAuditMerkleRoot(results []VerificationResult) string {
	if len(results) == 0 {
		return SHA256Hex([]byte(DomainMerkleEmptyPrefix))
	}
	sorted := make([]VerificationResult, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ClaimID < sorted[j].ClaimID
	})
	level := make([]string, len(sorted))
	for i, r := range sorted {
		if r.ResultDigest != "" {
			level[i] = r.ResultDigest
		} else {
			level[i] = ComputeResultDigest(r)
		}
	}
	for len(level) > 1 {
		nextLen := (len(level) + 1) / 2
		next := make([]string, nextLen)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			next[i/2] = SHA256Hex([]byte(DomainMerkleNodePrefix + left + ":" + right))
		}
		level = next
	}
	return level[0]
}

// IsValidHexSHA256 returns true iff s is a 64-character lowercase hex string.
func IsValidHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func makeResult(claim EvidenceClaim, verdict Verdict, reason, detail, computed, evSHA string) VerificationResult {
	r := VerificationResult{
		SchemaVersion:  SchemaVersion,
		ClaimID:        claim.ClaimID,
		ClaimClass:     claim.ClaimClass,
		Verdict:        verdict,
		ReasonCode:     reason,
		Detail:         detail,
		ComputedValue:  computed,
		EvidenceSHA256: evSHA,
	}
	r.ResultDigest = ComputeResultDigest(r)
	return r
}

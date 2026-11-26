// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation

package verifier

import (
	"fmt"
	"math"
	"math/big"
	"sort"
	"strings"
)

func toFloatSlice(raw any) ([]float64, bool) {
	arr, ok := raw.([]any)
	if !ok {
		if fArr, ok2 := raw.([]float64); ok2 {
			return fArr, true
		}
		return nil, false
	}
	out := make([]float64, len(arr))
	for i, item := range arr {
		f, ok := toFloat(item)
		if !ok {
			return nil, false
		}
		out[i] = f
	}
	return out, true
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	default:
		return 0, false
	}
}

func toStringSlice(raw any) ([]string, bool) {
	arr, ok := raw.([]any)
	if !ok {
		if sArr, ok2 := raw.([]string); ok2 {
			return sArr, true
		}
		return nil, false
	}
	out := make([]string, len(arr))
	for i, item := range arr {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

func runDeterministicOp(prog *CodeProgram) (any, error) {
	if prog == nil || strings.TrimSpace(prog.Op) == "" {
		return nil, fmt.Errorf("missing program op")
	}
	inputs := prog.Inputs
	if inputs == nil {
		inputs = map[string]any{}
	}
	switch prog.Op {
	case "sha256_canonical":
		canon, err := CanonicalJSON(inputs)
		if err != nil {
			return nil, err
		}
		return SHA256Hex(canon), nil

	case "merkle_root":
		leaves, ok := toStringSlice(inputs["leaves"])
		if !ok || len(leaves) == 0 {
			return nil, fmt.Errorf("merkle_root requires non-empty string array leaves")
		}
		level := make([]string, len(leaves))
		for i, l := range leaves {
			level[i] = SHA256Hex([]byte(l))
		}
		for len(level) > 1 {
			next := make([]string, (len(level)+1)/2)
			for i := 0; i < len(level); i += 2 {
				left := level[i]
				right := left
				if i+1 < len(level) {
					right = level[i+1]
				}
				next[i/2] = SHA256Hex([]byte(left + ":" + right))
			}
			level = next
		}
		return level[0], nil

	case "bitdelta_scale":
		wb, ok1 := toFloatSlice(inputs["w_base"])
		wf, ok2 := toFloatSlice(inputs["w_fine"])
		if !ok1 || !ok2 || len(wb) == 0 || len(wb) != len(wf) {
			return nil, fmt.Errorf("bitdelta_scale requires equal-length non-empty w_base and w_fine")
		}
		l1 := 0.0
		for i := range wb {
			l1 += math.Abs(wf[i] - wb[i])
		}
		return l1 / float64(len(wb)), nil

	case "trimmed_mean":
		rawVecs, ok := inputs["vectors"].([]any)
		if !ok || len(rawVecs) == 0 {
			return nil, fmt.Errorf("trimmed_mean requires non-empty vectors")
		}
		trimKF, okK := toFloat(inputs["trim_k"])
		if !okK || trimKF < 0 {
			return nil, fmt.Errorf("trimmed_mean requires non-negative trim_k")
		}
		trimK := int(trimKF)
		vecs := make([][]float64, len(rawVecs))
		dim := -1
		for i, rv := range rawVecs {
			v, ok := toFloatSlice(rv)
			if !ok || len(v) == 0 {
				return nil, fmt.Errorf("invalid vector at index %d", i)
			}
			if dim < 0 {
				dim = len(v)
			} else if len(v) != dim {
				return nil, fmt.Errorf("mismatched vector dimensions")
			}
			vecs[i] = v
		}
		if 2*trimK >= len(vecs) {
			return nil, fmt.Errorf("trim_k too large for vector count")
		}
		out := make([]float64, dim)
		for d := 0; d < dim; d++ {
			col := make([]float64, len(vecs))
			for i := range vecs {
				col[i] = vecs[i][d]
			}
			sort.Float64s(col)
			trimmed := col[trimK : len(col)-trimK]
			sum := 0.0
			for _, x := range trimmed {
				sum += x
			}
			out[d] = sum / float64(len(trimmed))
		}
		return out, nil

	case "linear_reward":
		phi, ok1 := toFloat(inputs["phi"])
		fee, ok2 := toFloat(inputs["fee"])
		share, ok3 := toFloat(inputs["share"])
		subsidy, ok4 := toFloat(inputs["subsidy"])
		w, ok5 := toFloat(inputs["weight"])
		wTot, ok6 := toFloat(inputs["total_weight"])
		if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || wTot <= 0 {
			return nil, fmt.Errorf("linear_reward requires numeric phi, fee, share, subsidy, weight, total_weight>0")
		}
		return (1.0-phi)*fee*share + subsidy*(w/wTot), nil

	case "sortition_check":
		seed, ok1 := inputs["seed"].(string)
		opID, ok2 := inputs["operator_id"].(string)
		nF, ok3 := toFloat(inputs["committee_size"])
		NF, ok4 := toFloat(inputs["population_size"])
		if !ok1 || !ok2 || !ok3 || !ok4 || NF <= 0 || nF < 0 || nF > NF {
			return nil, fmt.Errorf("sortition_check requires seed, operator_id, 0<=committee_size<=population_size")
		}
		digestHex := SHA256Hex([]byte(seed + "|" + opID))
		hInt, ok := new(big.Int).SetString(digestHex, 16)
		if !ok {
			return nil, fmt.Errorf("failed parsing hash")
		}
		// H * N < 2^256 * n
		two256 := new(big.Int).Lsh(big.NewInt(1), 256)
		lhs := new(big.Int).Mul(hInt, big.NewInt(int64(NF)))
		rhs := new(big.Int).Mul(two256, big.NewInt(int64(nF)))
		return lhs.Cmp(rhs) < 0, nil

	case "eval_expr":
		exprStr, ok := inputs["expression"].(string)
		if !ok || strings.TrimSpace(exprStr) == "" {
			return nil, fmt.Errorf("eval_expr requires non-empty expression")
		}
		vars := map[string]float64{}
		if rawVars, ok := inputs["variables"].(map[string]any); ok {
			for k, val := range rawVars {
				if f, ok := toFloat(val); ok {
					vars[k] = f
				}
			}
		}
		return EvalExpression(exprStr, vars, false)

	default:
		return nil, fmt.Errorf("unknown op %q", prog.Op)
	}
}

func outputsMatch(computed any, expected any, tol float64) bool {
	if cf, ok1 := toFloat(computed); ok1 {
		if ef, ok2 := toFloat(expected); ok2 {
			if tol <= 0 {
				tol = 1e-6
			}
			return math.Abs(cf-ef) <= tol
		}
		return false
	}
	if cs, ok1 := toFloatSlice(computed); ok1 {
		if es, ok2 := toFloatSlice(expected); ok2 && len(cs) == len(es) {
			if tol <= 0 {
				tol = 1e-6
			}
			for i := range cs {
				if math.Abs(cs[i]-es[i]) > tol {
					return false
				}
			}
			return true
		}
		return false
	}
	cBytes, err1 := CanonicalJSON(computed)
	eBytes, err2 := CanonicalJSON(expected)
	if err1 != nil || err2 != nil {
		return false
	}
	return string(cBytes) == string(eBytes)
}

func formatOutputValue(v any) string {
	if f, ok := toFloat(v); ok {
		return FormatCanonicalFloat(f)
	}
	b, err := CanonicalJSON(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

func (v *Verifier) verifyCodeResult(claim EvidenceClaim) VerificationResult {
	c := claim.CodeResult
	if c == nil {
		return makeResult(claim, VerdictUnsupported, ReasonMissingPayload, "code_result payload missing", "", "")
	}
	if c.ReviewScope == "external_domain" || c.ReviewScope == "subjective_judgment" {
		return makeResult(claim, VerdictInconclusive, ReasonHumanReviewRequired, "code result requires external domain or subjective human review", "", "")
	}
	if c.Stochastic && c.Mode != "statistical_interval" && strings.TrimSpace(c.DeclaredSHA256) == "" {
		return makeResult(claim, VerdictUnsupported, ReasonStochasticRequiresBounds, "stochastic benchmark lacks declared statistical interval bounds", "", "")
	}

	switch c.Mode {
	case "deterministic_eval":
		if c.Program == nil || strings.TrimSpace(c.Program.Op) == "" {
			return makeResult(claim, VerdictUnsupported, ReasonInvalidCodeInput, "deterministic_eval requires program.op", "", "")
		}
		knownOps := map[string]bool{
			"sha256_canonical": true,
			"merkle_root":      true,
			"bitdelta_scale":   true,
			"trimmed_mean":     true,
			"linear_reward":    true,
			"sortition_check":  true,
			"eval_expr":        true,
		}
		if !knownOps[c.Program.Op] {
			return makeResult(claim, VerdictUnsupported, ReasonUnknownCodeOp, fmt.Sprintf("unknown deterministic kernel op: %s", c.Program.Op), "", "")
		}
		out, err := runDeterministicOp(c.Program)
		if err != nil {
			return makeResult(claim, VerdictUnsupported, ReasonInvalidCodeInput, err.Error(), "", "")
		}
		outStr := formatOutputValue(out)
		evSHA := SHA256Hex([]byte(outStr))
		if outputsMatch(out, c.ExpectedOutput, c.Tolerance) {
			return makeResult(claim, VerdictVerified, ReasonOKCodeEval, "deterministic kernel output matches expected_output", outStr, evSHA)
		}
		return makeResult(claim, VerdictRefuted, ReasonCodeOutputMismatch, fmt.Sprintf("deterministic kernel output %s contradicts expected_output %s", outStr, formatOutputValue(c.ExpectedOutput)), outStr, evSHA)

	case "artifact_hash":
		if c.ArtifactPayload == "" {
			return makeResult(claim, VerdictUnsupported, ReasonMissingArtifactPayload, "artifact_hash mode requires non-empty artifact_payload", "", "")
		}
		actualSHA := SHA256Hex([]byte(c.ArtifactPayload))
		if !IsValidHexSHA256(c.DeclaredSHA256) {
			return makeResult(claim, VerdictUnsupported, ReasonInvalidSHA256Format, "declared_sha256 is not a valid 64-char lowercase hex digest", "", actualSHA)
		}
		if actualSHA == c.DeclaredSHA256 {
			return makeResult(claim, VerdictVerified, ReasonOKArtifactHash, "artifact payload SHA-256 matches declared_sha256", actualSHA, actualSHA)
		}
		return makeResult(claim, VerdictRefuted, ReasonArtifactHashMismatch, "artifact payload SHA-256 contradicts declared_sha256", actualSHA, actualSHA)

	case "statistical_interval":
		if len(c.Samples) < 3 || !c.HasClaimedMean || c.CIHalfwidth <= 0 {
			return makeResult(claim, VerdictUnsupported, ReasonInsufficientSamples, "statistical_interval requires >=3 samples, claimed_mean, and ci_halfwidth > 0", "", "")
		}
		sum := 0.0
		for _, s := range c.Samples {
			sum += s
		}
		mean := sum / float64(len(c.Samples))
		ss := 0.0
		for _, s := range c.Samples {
			d := s - mean
			ss += d * d
		}
		std := math.Sqrt(ss / float64(len(c.Samples)-1))
		h95 := 1.96 * std / math.Sqrt(float64(len(c.Samples)))
		meanStr := FormatCanonicalFloat(mean)
		if math.Abs(c.ClaimedMean-mean) > c.CIHalfwidth {
			return makeResult(claim, VerdictRefuted, ReasonMeanOutsideCI, fmt.Sprintf("sample mean %s lies outside claimed interval %s +/- %s", meanStr, FormatCanonicalFloat(c.ClaimedMean), FormatCanonicalFloat(c.CIHalfwidth)), meanStr, "")
		}
		if c.CIHalfwidth < h95*(1.0-1e-6) {
			return makeResult(claim, VerdictRefuted, ReasonCIUnderestimated, fmt.Sprintf("declared ci_halfwidth %s is narrower than 95%% halfwidth %s", FormatCanonicalFloat(c.CIHalfwidth), FormatCanonicalFloat(h95)), meanStr, "")
		}
		maxReasonable := math.Max(math.Abs(mean)*0.25, 1.0)
		if c.CIHalfwidth > maxReasonable {
			return makeResult(claim, VerdictInconclusive, ReasonCITooWide, fmt.Sprintf("declared ci_halfwidth %s exceeds vacuity threshold %s", FormatCanonicalFloat(c.CIHalfwidth), FormatCanonicalFloat(maxReasonable)), meanStr, "")
		}
		return makeResult(claim, VerdictVerified, ReasonOKStatisticalInterval, fmt.Sprintf("sample mean %s verified within valid 95%% CI +/- %s", meanStr, FormatCanonicalFloat(c.CIHalfwidth)), meanStr, "")

	default:
		return makeResult(claim, VerdictUnsupported, ReasonMissingCodeMode, fmt.Sprintf("unsupported or missing code_result mode: %q", c.Mode), "", "")
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation

package verifier

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

func (v *Verifier) verifyCalculation(claim EvidenceClaim) VerificationResult {
	c := claim.Calculation
	if c == nil {
		return makeResult(claim, VerdictUnsupported, ReasonMissingPayload, "calculation payload missing", "", "")
	}
	if c.ReviewScope == "external_domain" || c.ReviewScope == "subjective_judgment" {
		return makeResult(claim, VerdictInconclusive, ReasonHumanReviewRequired, "calculation requires external domain or subjective human review", "", "")
	}
	if strings.TrimSpace(c.Expression) == "" || !c.HasClaimedValue {
		return makeResult(claim, VerdictUnsupported, ReasonMissingCalcFields, "calculation missing expression or claimed_value", "", "")
	}
	expUnit := strings.ToLower(strings.TrimSpace(c.ExpectedUnit))
	clmUnit := strings.ToLower(strings.TrimSpace(c.ClaimedUnit))
	if expUnit != "" && clmUnit == "" {
		return makeResult(claim, VerdictUnsupported, ReasonMissingUnit, "calculation missing claimed_unit", "", "")
	}
	if expUnit != "" && clmUnit != "" && expUnit != clmUnit {
		return makeResult(claim, VerdictRefuted, ReasonUnitMismatch, fmt.Sprintf("unit mismatch: expected %q, claimed %q", expUnit, clmUnit), "", "")
	}

	computed, err := EvalExpression(c.Expression, c.Variables, c.ExactRational)
	if err != nil {
		var exprErr *ExprError
		if errors.As(err, &exprErr) {
			switch exprErr.Kind {
			case ExprErrSyntax:
				return makeResult(claim, VerdictUnsupported, ReasonInvalidExpression, exprErr.Msg, "", "")
			case ExprErrUndefinedVar:
				return makeResult(claim, VerdictUnsupported, ReasonUndefinedVariable, exprErr.Msg, "", "")
			case ExprErrDomain:
				return makeResult(claim, VerdictRefuted, ReasonMathDomainError, exprErr.Msg, "", "")
			}
		}
		return makeResult(claim, VerdictUnsupported, ReasonInvalidExpression, err.Error(), "", "")
	}

	diff := math.Abs(computed - c.ClaimedValue)
	tol := c.Tolerance
	if tol < 0 {
		tol = 0
	}
	mode := strings.ToLower(strings.TrimSpace(c.ToleranceMode))
	limit := tol
	if mode == "rel" {
		limit = tol * math.Max(math.Abs(computed), 1e-12)
	}
	compStr := FormatCanonicalFloat(computed)
	if diff <= limit {
		return makeResult(claim, VerdictVerified, ReasonOKCalc, fmt.Sprintf("computed %s matches claimed %s within tolerance", compStr, FormatCanonicalFloat(c.ClaimedValue)), compStr, "")
	}
	return makeResult(claim, VerdictRefuted, ReasonCalcMismatch, fmt.Sprintf("computed %s differs from claimed %s by %s (limit %s)", compStr, FormatCanonicalFloat(c.ClaimedValue), FormatCanonicalFloat(diff), FormatCanonicalFloat(limit)), compStr, "")
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation

package dso

import (
	"fmt"
	"math"
	"strings"
)

// ValidateExperienceSchema enforces Section 3 constraints of experience-ledger-dso.tex:
//   - op in {Add, Modify, Delete}
//   - domain in {protocol_governance, conservation_science}
//   - 1 <= word_count <= 32
//   - actionable structure: starts with "When " or "For " or contains " implies "
//   - confidence_micro in [0, FixedScale]
//   - non-empty paper_sha256 content anchor
func ValidateExperienceSchema(exp ExperienceOp) error {
	switch exp.Op {
	case "Add", "Modify", "Delete":
	default:
		return fmt.Errorf("ERR_INVALID_OP")
	}
	if exp.Domain != DomainProtocol && exp.Domain != DomainConservation {
		return fmt.Errorf("ERR_INVALID_DOMAIN")
	}
	if exp.ConfidenceMicro < 0 || exp.ConfidenceMicro > FixedScale {
		return fmt.Errorf("ERR_INVALID_CONFIDENCE")
	}
	if len(exp.PaperSHA256) != 64 {
		return fmt.Errorf("ERR_MISSING_PAPER_ANCHOR")
	}
	words := strings.Fields(strings.TrimSpace(exp.Text))
	if len(words) < 5 || len(words) > 32 {
		return fmt.Errorf("ERR_TEXT_LENGTH_VIOLATION")
	}
	txt := strings.TrimSpace(exp.Text)
	if !strings.HasPrefix(txt, "When ") && !strings.HasPrefix(txt, "For ") && !strings.Contains(txt, " implies ") {
		return fmt.Errorf("ERR_NON_ACTIONABLE_EXPERIENCE")
	}
	return nil
}

// Dot computes the Euclidean inner product of two FeatureDim vectors.
func Dot(a, b [FeatureDim]float64) float64 {
	var s float64
	for i := 0; i < FeatureDim; i++ {
		s += a[i] * b[i]
	}
	return s
}

// L2Norm returns the Euclidean norm of a FeatureDim vector.
func L2Norm(v [FeatureDim]float64) float64 {
	return math.Sqrt(Dot(v, v))
}

// CosineSimilarity returns cosine similarity between two FeatureDim vectors (0 if either is zero).
func CosineSimilarity(a, b [FeatureDim]float64) float64 {
	na := L2Norm(a)
	nb := L2Norm(b)
	if na < 1e-12 || nb < 1e-12 {
		return 0
	}
	return Dot(a, b) / (na * nb)
}

// SquaredDist returns ||a - b||_2^2.
func SquaredDist(a, b [FeatureDim]float64) float64 {
	var s float64
	for i := 0; i < FeatureDim; i++ {
		d := a[i] - b[i]
		s += d * d
	}
	return s
}

// EvaluateLogistic computes binary classification accuracy and mean logistic loss on data.
func EvaluateLogistic(w [FeatureDim]float64, data []Example) (accuracy float64, loss float64) {
	if len(data) == 0 {
		return 0, 0
	}
	correct := 0
	var totalLoss float64
	for _, ex := range data {
		z := float64(ex.Label) * Dot(w, ex.Features)
		if z > 0 || (z == 0 && ex.Label > 0) {
			correct++
		}
		// Numerically stable log(1 + exp(-z))
		if z >= 0 {
			totalLoss += math.Log1p(math.Exp(-z))
		} else {
			totalLoss += -z + math.Log1p(math.Exp(z))
		}
	}
	n := float64(len(data))
	return float64(correct) / n, totalLoss / n
}

// JainsFairnessIndex computes J(x) = (sum x_i)^2 / (n * sum x_i^2) in [0, 1].
// Returns 0 if n == 0 or all entries are 0.
func JainsFairnessIndex(vals []float64) float64 {
	n := len(vals)
	if n == 0 {
		return 0
	}
	var sum, sumSq float64
	for _, v := range vals {
		if v < 0 {
			v = 0
		}
		sum += v
		sumSq += v * v
	}
	if sumSq <= 1e-18 {
		return 0
	}
	return (sum * sum) / (float64(n) * sumSq)
}

// GiniCoefficient computes the exact Gini coefficient in [0, 1] over non-negative weights:
// G(x) = sum_i sum_j |x_i - x_j| / (2 * n * sum_i x_i).
// Returns 1.0 if sum == 0 (total erasure / zero participation).
func GiniCoefficient(vals []float64) float64 {
	n := len(vals)
	if n == 0 {
		return 0
	}
	var sum float64
	clean := make([]float64, n)
	for i, v := range vals {
		if v < 0 {
			v = 0
		}
		clean[i] = v
		sum += v
	}
	if sum <= 1e-18 {
		return 1.0
	}
	var absDiffSum float64
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			absDiffSum += math.Abs(clean[i] - clean[j])
		}
	}
	return absDiffSum / (2.0 * float64(n) * sum)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation

package verifier

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Verifier is a stateless, thread-safe deterministic evidence & reasoning verifier.
type Verifier struct {
	CorpusRoot string
}

// New creates a Verifier anchored to a repository corpus root directory.
func New(corpusRoot string) *Verifier {
	return &Verifier{CorpusRoot: corpusRoot}
}

var forbiddenGovernanceActions = map[string]bool{
	"redefine_voting_rules": true,
	"authorize_treasury":    true,
	"self_declare_valid":    true,
}

// VerifyClaim verifies a single EvidenceClaim deterministically.
// ExpectedVerdict and NegativeRegime are NEVER read by this method.
func (v *Verifier) VerifyClaim(claim EvidenceClaim, resolvedVerdicts map[string]Verdict) VerificationResult {
	// Constitutional Guard 1: No self-validation (Rule 12 / HIP-1352).
	if strings.TrimSpace(claim.AuthorID) != "" &&
		strings.TrimSpace(claim.VerifierID) != "" &&
		strings.TrimSpace(claim.AuthorID) == strings.TrimSpace(claim.VerifierID) {
		return makeResult(claim, VerdictRefuted, ReasonSelfValidation, fmt.Sprintf("constitutional violation: author_id %q cannot self-validate as verifier_id", claim.AuthorID), "", "")
	}
	// Constitutional Guard 2: AI advisory scope boundary (Rule 7 / HIP-1352).
	govAction := strings.ToLower(strings.TrimSpace(claim.GovernanceAction))
	if forbiddenGovernanceActions[govAction] {
		return makeResult(claim, VerdictRefuted, ReasonForbiddenGovAction, fmt.Sprintf("constitutional violation: AI agent forbidden from governance action %q", govAction), "", "")
	}

	switch claim.ClaimClass {
	case ClassCitation:
		return v.verifyCitation(claim)
	case ClassCalculation:
		return v.verifyCalculation(claim)
	case ClassCodeResult:
		return v.verifyCodeResult(claim)
	case ClassReasoningChain:
		return v.verifyReasoningChain(claim, resolvedVerdicts)
	default:
		return makeResult(claim, VerdictUnsupported, ReasonUnknownClaimClass, fmt.Sprintf("unknown claim_class: %q", claim.ClaimClass), "", "")
	}
}

// VerifyBundle verifies all claims in a bundle in order, allowing later reasoning
// chains to resolve earlier verified claims in the same bundle.
func (v *Verifier) VerifyBundle(bundle ClaimBundle) ([]VerificationResult, string) {
	results := make([]VerificationResult, len(bundle.Claims))
	resolved := make(map[string]Verdict, len(bundle.Claims))
	for i, c := range bundle.Claims {
		res := v.VerifyClaim(c, resolved)
		results[i] = res
		resolved[c.ClaimID] = res.Verdict
	}
	root := ComputeAuditMerkleRoot(results)
	return results, root
}

// ClassMetrics holds per-verdict precision, recall, F1, and support.
type ClassMetrics struct {
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	FN        int     `json:"fn"`
	Support   int     `json:"support"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
}

// ClaimClassSummary summarizes accuracy and errors for one of the 4 claim classes.
type ClaimClassSummary struct {
	Total             int     `json:"total"`
	Correct           int     `json:"correct"`
	Accuracy          float64 `json:"accuracy"`
	MechanicalFVR     float64 `json:"mechanical_fvr"`
	OverallFVR        float64 `json:"overall_fvr"`
	FRR               float64 `json:"frr"`
	FalseVerified     int     `json:"false_verified"`
	FalseRejected     int     `json:"false_rejected"`
}

// NegativeRegimeSummary summarizes behavior on a specific negative regime slice.
type NegativeRegimeSummary struct {
	Regime         string         `json:"regime"`
	Total          int            `json:"total"`
	Correct        int            `json:"correct"`
	FalseVerified  int            `json:"false_verified"`
	FalseRejected  int            `json:"false_rejected"`
	ReasonCounts   map[string]int `json:"reason_counts"`
	VerdictCounts  map[string]int `json:"verdict_counts"`
}

// ErrorCase records a single mismatch between expected ground truth and verifier prediction.
type ErrorCase struct {
	ClaimID         string     `json:"claim_id"`
	ClaimClass      ClaimClass `json:"claim_class"`
	NegativeRegime  string     `json:"negative_regime"`
	ExpectedVerdict Verdict    `json:"expected_verdict"`
	Predicted       Verdict    `json:"predicted_verdict"`
	ReasonCode      string     `json:"reason_code"`
	Detail          string     `json:"detail"`
	ErrorCategory   string     `json:"error_category"`
}

// BenchmarkReport captures the complete reproducible benchmark output.
type BenchmarkReport struct {
	SchemaVersion           string                            `json:"schema_version"`
	Implementation          string                            `json:"implementation"`
	BundleID                string                            `json:"bundle_id"`
	Seed                    int64                             `json:"seed"`
	TotalClaims             int                               `json:"total_claims"`
	CorrectClaims           int                               `json:"correct_claims"`
	Accuracy                float64                           `json:"accuracy"`
	MacroPrecision          float64                           `json:"macro_precision"`
	MacroRecall             float64                           `json:"macro_recall"`
	MacroF1                 float64                           `json:"macro_f1"`
	MechanicalFVR           float64                           `json:"mechanical_fvr"`
	MechanicalFVCount       int                               `json:"mechanical_fv_count"`
	MechanicalInvalidTotal  int                               `json:"mechanical_invalid_total"`
	OverallFVR              float64                           `json:"overall_fvr"`
	OverallFVCount          int                               `json:"overall_fv_count"`
	NonVerifiedTotal        int                               `json:"non_verified_total"`
	FRR                     float64                           `json:"frr"`
	FRCount                 int                               `json:"fr_count"`
	VerifiedGroundTruth     int                               `json:"verified_ground_truth"`
	ElapsedMs               float64                           `json:"elapsed_ms"`
	ThroughputClaimsPerSec  float64                           `json:"throughput_claims_per_sec"`
	AuditMerkleRoot         string                            `json:"audit_merkle_root"`
	ConfusionMatrix         map[Verdict]map[Verdict]int       `json:"confusion_matrix"`
	PerVerdictMetrics       map[Verdict]ClassMetrics          `json:"per_verdict_metrics"`
	PerClaimClass           map[ClaimClass]ClaimClassSummary  `json:"per_claim_class"`
	NegativeRegimes         []NegativeRegimeSummary           `json:"negative_regimes"`
	ErrorCases              []ErrorCase                       `json:"error_cases"`
	Results                 []VerificationResult              `json:"results"`
}

func safeDiv(num, den int) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

func round4(x float64) float64 {
	return float64(int(x*10000+0.5)) / 10000
}

// RunBenchmark evaluates a labeled ClaimBundle and computes full metrics + error analysis.
func (v *Verifier) RunBenchmark(bundle ClaimBundle, implName string) BenchmarkReport {
	start := time.Now()
	results, root := v.VerifyBundle(bundle)
	elapsed := time.Since(start)
	elapsedMs := float64(elapsed.Microseconds()) / 1000.0
	throughput := 0.0
	if elapsed.Seconds() > 0 {
		throughput = float64(len(bundle.Claims)) / elapsed.Seconds()
	}

	cm := make(map[Verdict]map[Verdict]int, len(AllVerdicts))
	for _, row := range AllVerdicts {
		cm[row] = make(map[Verdict]int, len(AllVerdicts))
		for _, col := range AllVerdicts {
			cm[row][col] = 0
		}
	}

	perClass := make(map[ClaimClass]*ClaimClassSummary, len(AllClaimClasses))
	classMechInvalid := make(map[ClaimClass]int)
	classMechFV := make(map[ClaimClass]int)
	classNonVer := make(map[ClaimClass]int)
	classVerGT := make(map[ClaimClass]int)
	for _, cc := range AllClaimClasses {
		perClass[cc] = &ClaimClassSummary{}
	}

	regimeMap := map[string]*NegativeRegimeSummary{}
	var errorCases []ErrorCase

	correct := 0
	mechInvalid := 0
	mechFV := 0
	nonVerTotal := 0
	overallFV := 0
	verGT := 0
	frCount := 0

	for i, c := range bundle.Claims {
		pred := results[i].Verdict
		exp := c.ExpectedVerdict
		cm[exp][pred]++

		cs := perClass[c.ClaimClass]
		cs.Total++
		if pred == exp {
			correct++
			cs.Correct++
		}

		isMechInvalid := exp == VerdictRefuted || exp == VerdictUnsupported
		if isMechInvalid {
			mechInvalid++
			classMechInvalid[c.ClaimClass]++
			if pred == VerdictVerified {
				mechFV++
				classMechFV[c.ClaimClass]++
			}
		}
		if exp != VerdictVerified {
			nonVerTotal++
			classNonVer[c.ClaimClass]++
			if pred == VerdictVerified {
				overallFV++
				cs.FalseVerified++
			}
		} else {
			verGT++
			classVerGT[c.ClaimClass]++
			if pred != VerdictVerified {
				frCount++
				cs.FalseRejected++
			}
		}

		regime := c.NegativeRegime
		if regime == "" {
			regime = "none"
		}
		rs, ok := regimeMap[regime]
		if !ok {
			rs = &NegativeRegimeSummary{
				Regime:        regime,
				ReasonCounts:  map[string]int{},
				VerdictCounts: map[string]int{},
			}
			regimeMap[regime] = rs
		}
		rs.Total++
		if pred == exp {
			rs.Correct++
		}
		if exp != VerdictVerified && pred == VerdictVerified {
			rs.FalseVerified++
		}
		if exp == VerdictVerified && pred != VerdictVerified {
			rs.FalseRejected++
		}
		rs.ReasonCounts[results[i].ReasonCode]++
		rs.VerdictCounts[string(pred)]++

		if pred != exp {
			cat := "classification_mismatch"
			if exp != VerdictVerified && pred == VerdictVerified {
				cat = "false_verification"
			} else if exp == VerdictVerified && pred != VerdictVerified {
				cat = "false_rejection"
			} else if exp == VerdictInconclusive && (pred == VerdictRefuted || pred == VerdictUnsupported) {
				cat = "over_strict_rejection"
			}
			errorCases = append(errorCases, ErrorCase{
				ClaimID:         c.ClaimID,
				ClaimClass:      c.ClaimClass,
				NegativeRegime:  regime,
				ExpectedVerdict: exp,
				Predicted:       pred,
				ReasonCode:      results[i].ReasonCode,
				Detail:          results[i].Detail,
				ErrorCategory:   cat,
			})
		}
	}

	perVerdict := make(map[Verdict]ClassMetrics, len(AllVerdicts))
	sumP, sumR, sumF1 := 0.0, 0.0, 0.0
	for _, vName := range AllVerdicts {
		tp := cm[vName][vName]
		fp := 0
		fn := 0
		support := 0
		for _, other := range AllVerdicts {
			support += cm[vName][other]
			if other != vName {
				fp += cm[other][vName]
				fn += cm[vName][other]
			}
		}
		prec := safeDiv(tp, tp+fp)
		rec := safeDiv(tp, tp+fn)
		f1 := 0.0
		if prec+rec > 0 {
			f1 = 2 * prec * rec / (prec + rec)
		}
		perVerdict[vName] = ClassMetrics{
			TP:        tp,
			FP:        fp,
			FN:        fn,
			Support:   support,
			Precision: round4(prec),
			Recall:    round4(rec),
			F1:        round4(f1),
		}
		sumP += prec
		sumR += rec
		sumF1 += f1
	}

	perClaimClassOut := make(map[ClaimClass]ClaimClassSummary, len(AllClaimClasses))
	for _, cc := range AllClaimClasses {
		cs := perClass[cc]
		cs.Accuracy = round4(safeDiv(cs.Correct, cs.Total))
		cs.MechanicalFVR = round4(safeDiv(classMechFV[cc], classMechInvalid[cc]))
		cs.OverallFVR = round4(safeDiv(cs.FalseVerified, classNonVer[cc]))
		cs.FRR = round4(safeDiv(cs.FalseRejected, classVerGT[cc]))
		perClaimClassOut[cc] = *cs
	}

	regimeNames := make([]string, 0, len(regimeMap))
	for k := range regimeMap {
		regimeNames = append(regimeNames, k)
	}
	sort.Strings(regimeNames)
	regimesOut := make([]NegativeRegimeSummary, 0, len(regimeNames))
	for _, k := range regimeNames {
		regimesOut = append(regimesOut, *regimeMap[k])
	}

	return BenchmarkReport{
		SchemaVersion:          SchemaVersion,
		Implementation:         implName,
		BundleID:               bundle.BundleID,
		Seed:                   bundle.Seed,
		TotalClaims:            len(bundle.Claims),
		CorrectClaims:          correct,
		Accuracy:               round4(safeDiv(correct, len(bundle.Claims))),
		MacroPrecision:         round4(sumP / float64(len(AllVerdicts))),
		MacroRecall:            round4(sumR / float64(len(AllVerdicts))),
		MacroF1:                round4(sumF1 / float64(len(AllVerdicts))),
		MechanicalFVR:          round4(safeDiv(mechFV, mechInvalid)),
		MechanicalFVCount:      mechFV,
		MechanicalInvalidTotal: mechInvalid,
		OverallFVR:             round4(safeDiv(overallFV, nonVerTotal)),
		OverallFVCount:         overallFV,
		NonVerifiedTotal:       nonVerTotal,
		FRR:                    round4(safeDiv(frCount, verGT)),
		FRCount:                frCount,
		VerifiedGroundTruth:    verGT,
		ElapsedMs:              round4(elapsedMs),
		ThroughputClaimsPerSec: round4(throughput),
		AuditMerkleRoot:        root,
		ConfusionMatrix:        cm,
		PerVerdictMetrics:      perVerdict,
		PerClaimClass:          perClaimClassOut,
		NegativeRegimes:        regimesOut,
		ErrorCases:             errorCases,
		Results:                results,
	}
}

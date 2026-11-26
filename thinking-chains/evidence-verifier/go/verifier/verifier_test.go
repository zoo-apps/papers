// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation

package verifier_test

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/zoo-apps/papers/thinking-chains/evidence-verifier/go/verifier"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(abs, "thinking-chains", "thinking-chains.tex")); err != nil {
		t.Fatalf("expected thinking-chains.tex under %s: %v", abs, err)
	}
	return abs
}

func loadBenchmarkBundle(t *testing.T) verifier.ClaimBundle {
	t.Helper()
	path := filepath.Join("..", "..", "dataset", "benchmark-claims.v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read dataset: %v", err)
	}
	var bundle verifier.ClaimBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatalf("parse dataset: %v", err)
	}
	return bundle
}

func TestExprEvaluator(t *testing.T) {
	cases := []struct {
		name     string
		expr     string
		vars     map[string]float64
		rational bool
		want     float64
		wantErr  verifier.ExprErrorKind
	}{
		{"precedence", "2 + 3 * 4 ^ 2", nil, false, 50, verifier.ExprErrNone},
		{"right_assoc_pow", "2 ^ 3 ^ 2", nil, false, 512, verifier.ExprErrNone},
		{"exact_rational_add", "0.1 + 0.2", nil, true, 0.3, verifier.ExprErrNone},
		{"exact_rational_ratio", "ratio(140, 0.7)", nil, true, 200, verifier.ExprErrNone},
		{"hoeffding", "hoeffding_upper(21, 0.67, 0.25)", nil, false, math.Exp(-2 * 21 * 0.42 * 0.42), verifier.ExprErrNone},
		{"median_even", "median(10, 2, 8, 4)", nil, false, 6, verifier.ExprErrNone},
		{"median_odd", "median(10, 2, 8)", nil, false, 8, verifier.ExprErrNone},
		{"div_zero", "10 / 0", nil, false, 0, verifier.ExprErrDomain},
		{"sqrt_neg", "sqrt(-1)", nil, false, 0, verifier.ExprErrDomain},
		{"undef_var", "x + 1", nil, false, 0, verifier.ExprErrUndefinedVar},
		{"syntax_err", "1 + * 2", nil, false, 0, verifier.ExprErrSyntax},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := verifier.EvalExpression(tc.expr, tc.vars, tc.rational)
			if tc.wantErr != verifier.ExprErrNone {
				if err == nil {
					t.Fatalf("expected error kind %v, got nil (val=%v)", tc.wantErr, got)
				}
				ee, ok := err.(*verifier.ExprError)
				if !ok || ee.Kind != tc.wantErr {
					t.Fatalf("expected ExprError kind %v, got %T %v", tc.wantErr, err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if math.Abs(got-tc.want) > 1e-9 {
				t.Fatalf("got %.12f, want %.12f", got, tc.want)
			}
		})
	}
}

func TestConstitutionalGuards(t *testing.T) {
	v := verifier.New(repoRoot(t))

	selfVal := verifier.EvidenceClaim{
		SchemaVersion: verifier.SchemaVersion,
		ClaimID:       "CONST-001",
		ClaimClass:    verifier.ClassCalculation,
		Statement:     "Self validation attempt",
		AuthorID:      "agent-1",
		VerifierID:    "agent-1",
		Calculation: &verifier.CalculationPayload{
			Expression:      "2 + 2",
			ClaimedValue:    4,
			HasClaimedValue: true,
		},
	}
	res := v.VerifyClaim(selfVal, nil)
	if res.Verdict != verifier.VerdictRefuted || res.ReasonCode != verifier.ReasonSelfValidation {
		t.Fatalf("expected self-validation refutation, got %+v", res)
	}

	for _, forbidden := range []string{"redefine_voting_rules", "authorize_treasury", "self_declare_valid"} {
		c := selfVal
		c.VerifierID = "verifier-2"
		c.GovernanceAction = forbidden
		res := v.VerifyClaim(c, nil)
		if res.Verdict != verifier.VerdictRefuted || res.ReasonCode != verifier.ReasonForbiddenGovAction {
			t.Fatalf("expected forbidden action %q refutation, got %+v", forbidden, res)
		}
	}

	for _, allowed := range []string{"recommend", "flag_conflict", "estimate_value", "prepare_plan"} {
		c := selfVal
		c.VerifierID = "verifier-2"
		c.GovernanceAction = allowed
		res := v.VerifyClaim(c, nil)
		if res.Verdict != verifier.VerdictVerified {
			t.Fatalf("expected allowed action %q to verify, got %+v", allowed, res)
		}
	}
}

func TestCanonicalJSONAndMerkleDeterminism(t *testing.T) {
	a := map[string]any{"b": 2, "a": 1, "c": []any{1.5, -0.0, "hi"}}
	b := map[string]any{"c": []any{1.5, 0.0, "hi"}, "a": 1, "b": 2}
	ja, err := verifier.CanonicalJSON(a)
	if err != nil {
		t.Fatal(err)
	}
	jb, err := verifier.CanonicalJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(ja) != string(jb) {
		t.Fatalf("canonical JSON mismatch: %s vs %s", ja, jb)
	}
	want := `{"a":1,"b":2,"c":[1.5,0,"hi"]}`
	if string(ja) != want {
		t.Fatalf("got %s, want %s", ja, want)
	}
	emptyRoot := verifier.ComputeAuditMerkleRoot(nil)
	if !verifier.IsValidHexSHA256(emptyRoot) {
		t.Fatalf("invalid empty merkle root: %s", emptyRoot)
	}
}

func TestFullBenchmark120ClaimsAndLabelBlindness(t *testing.T) {
	v := verifier.New(repoRoot(t))
	bundle := loadBenchmarkBundle(t)

	if len(bundle.Claims) != 120 {
		t.Fatalf("expected 120 benchmark claims, got %d", len(bundle.Claims))
	}
	if bundle.Seed != 1352 {
		t.Fatalf("expected seed 1352, got %d", bundle.Seed)
	}

	report := v.RunBenchmark(bundle, "go-test")

	// Mechanical FVR MUST be strictly 0.0 (zero fabricated/refuted/unsupported claims verified).
	if report.MechanicalFVCount != 0 || report.MechanicalFVR != 0 {
		t.Fatalf("expected 0 mechanical false verifications, got %d (rate=%v)", report.MechanicalFVCount, report.MechanicalFVR)
	}
	if report.CorrectClaims != 107 {
		t.Fatalf("expected 107/120 exact matches (13 negative-regime errors), got %d", report.CorrectClaims)
	}
	// Verify all 4 claim classes have exactly 30 claims.
	for _, cc := range verifier.AllClaimClasses {
		if report.PerClaimClass[cc].Total != 30 {
			t.Fatalf("class %s expected 30 claims, got %d", cc, report.PerClaimClass[cc].Total)
		}
	}

	// Label-blindness test: strip expected_verdict, negative_regime, and notes and re-verify.
	stripped := bundle
	stripped.Claims = make([]verifier.EvidenceClaim, len(bundle.Claims))
	for i, c := range bundle.Claims {
		c.ExpectedVerdict = ""
		c.NegativeRegime = ""
		c.Notes = ""
		stripped.Claims[i] = c
	}
	_, strippedRoot := v.VerifyBundle(stripped)
	if strippedRoot != report.AuditMerkleRoot {
		t.Fatalf("verifier leaked benchmark metadata: root %s != %s", strippedRoot, report.AuditMerkleRoot)
	}
}

func TestConcurrentVerificationRaceFree(t *testing.T) {
	v := verifier.New(repoRoot(t))
	bundle := loadBenchmarkBundle(t)
	_, wantRoot := v.VerifyBundle(bundle)

	const workers = 16
	var wg sync.WaitGroup
	errs := make(chan string, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, got := v.VerifyBundle(bundle)
			if got != wantRoot {
				errs <- got
			}
		}()
	}
	wg.Wait()
	close(errs)
	for got := range errs {
		t.Fatalf("concurrent root mismatch: got %s, want %s", got, wantRoot)
	}
}

func TestCitationEdgeCases(t *testing.T) {
	v := verifier.New(repoRoot(t))
	// Path traversal must be rejected as UNSUPPORTED.
	res := v.VerifyClaim(verifier.EvidenceClaim{
		SchemaVersion: verifier.SchemaVersion,
		ClaimID:       "EDGE-PATH",
		ClaimClass:    verifier.ClassCitation,
		Statement:     "traversal",
		AuthorID:      "a",
		VerifierID:    "b",
		Citation: &verifier.CitationPayload{
			SourcePath:     "../README.md",
			ExpectedSHA256: "a" + string(make([]byte, 63)),
			QuotedSpan:     "test",
		},
	}, nil)
	if res.Verdict != verifier.VerdictUnsupported || res.ReasonCode != verifier.ReasonInvalidSourcePath {
		t.Fatalf("expected invalid source path, got %+v", res)
	}
}

func TestReasoningChainCycleAndDangling(t *testing.T) {
	v := verifier.New(repoRoot(t))
	cycleClaim := verifier.EvidenceClaim{
		SchemaVersion: verifier.SchemaVersion,
		ClaimID:       "EDGE-CYCLE",
		ClaimClass:    verifier.ClassReasoningChain,
		Statement:     "cycle",
		AuthorID:      "a",
		VerifierID:    "b",
		ReasoningChain: &verifier.ReasoningChainPayload{
			ConclusionStepID: "b",
			Steps: []verifier.ReasoningStep{
				{StepID: "a", Kind: "inference", DependsOn: []string{"b"}, PublicRationale: "from b"},
				{StepID: "b", Kind: "conclusion", DependsOn: []string{"a"}, PublicRationale: "from a"},
			},
		},
	}
	res := v.VerifyClaim(cycleClaim, nil)
	if res.Verdict != verifier.VerdictRefuted || res.ReasonCode != verifier.ReasonReasoningCycle {
		t.Fatalf("expected cycle refutation, got %+v", res)
	}
}

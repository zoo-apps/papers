// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package govcheck

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestINV01AIConstitutionalBoundary(t *testing.T) {
	suite := BuildAdversarialSuite(1352)
	count := 0
	for _, c := range suite.Cases {
		if c.InvariantID == "INV-01" {
			count++
			if !c.Passed {
				t.Fatalf("INV-01 case %s failed: got %s/%s expected %s/%s",
					c.CaseID, c.ActualVerdict, c.ActualErrorCode, c.ExpectedVerdict, c.ExpectedErrorCode)
			}
		}
	}
	if count < 6 {
		t.Fatalf("expected >= 6 INV-01 cases, got %d", count)
	}
}

func TestINV02AcyclicBoundedDelegation(t *testing.T) {
	suite := BuildAdversarialSuite(1352)
	count := 0
	for _, c := range suite.Cases {
		if c.InvariantID == "INV-02" {
			count++
			if !c.Passed {
				t.Fatalf("INV-02 case %s failed: got %s/%s expected %s/%s",
					c.CaseID, c.ActualVerdict, c.ActualErrorCode, c.ExpectedVerdict, c.ExpectedErrorCode)
			}
		}
	}
	if count < 6 {
		t.Fatalf("expected >= 6 INV-02 cases, got %d", count)
	}
}

func TestINV03ImmediateTransitiveRevocation(t *testing.T) {
	suite := BuildAdversarialSuite(1352)
	count := 0
	for _, c := range suite.Cases {
		if c.InvariantID == "INV-03" {
			count++
			if !c.Passed {
				t.Fatalf("INV-03 case %s failed: got %s/%s expected %s/%s",
					c.CaseID, c.ActualVerdict, c.ActualErrorCode, c.ExpectedVerdict, c.ExpectedErrorCode)
			}
		}
	}
	if count < 4 {
		t.Fatalf("expected >= 4 INV-03 cases, got %d", count)
	}
}

func TestINV04QuorumAndSupermajorityMonotonicity(t *testing.T) {
	suite := BuildAdversarialSuite(1352)
	count := 0
	for _, c := range suite.Cases {
		if c.InvariantID == "INV-04" {
			count++
			if !c.Passed {
				t.Fatalf("INV-04 case %s failed: got %s/%s expected %s/%s",
					c.CaseID, c.ActualVerdict, c.ActualErrorCode, c.ExpectedVerdict, c.ExpectedErrorCode)
			}
		}
	}
	if count < 6 {
		t.Fatalf("expected >= 6 INV-04 cases, got %d", count)
	}
}

func TestINV05BoundedEmergencySuspensionAndAutoSunset(t *testing.T) {
	suite := BuildAdversarialSuite(1352)
	count := 0
	for _, c := range suite.Cases {
		if c.InvariantID == "INV-05" {
			count++
			if !c.Passed {
				t.Fatalf("INV-05 case %s failed: got %s/%s expected %s/%s",
					c.CaseID, c.ActualVerdict, c.ActualErrorCode, c.ExpectedVerdict, c.ExpectedErrorCode)
			}
		}
	}
	if count < 6 {
		t.Fatalf("expected >= 6 INV-05 cases, got %d", count)
	}
}

func TestINV06AppealDueProcessAndZeroSelfAdjudication(t *testing.T) {
	suite := BuildAdversarialSuite(1352)
	count := 0
	for _, c := range suite.Cases {
		if c.InvariantID == "INV-06" {
			count++
			if !c.Passed {
				t.Fatalf("INV-06 case %s failed: got %s/%s expected %s/%s",
					c.CaseID, c.ActualVerdict, c.ActualErrorCode, c.ExpectedVerdict, c.ExpectedErrorCode)
			}
		}
	}
	if count < 5 {
		t.Fatalf("expected >= 5 INV-06 cases, got %d", count)
	}
}

func TestINV07DeterministicPrecedenceAndConflictWitness(t *testing.T) {
	suite := BuildAdversarialSuite(1352)
	witnesses := 0
	for _, c := range suite.Cases {
		if c.InvariantID == "INV-07" {
			if !c.Passed {
				t.Fatalf("INV-07 case %s failed: got %s/%s expected %s/%s",
					c.CaseID, c.ActualVerdict, c.ActualErrorCode, c.ExpectedVerdict, c.ExpectedErrorCode)
			}
			if c.ActualErrorCode == CodeDenyRuleConflict {
				if c.ConflictWitness == nil || c.ConflictWitness.Resolution != "DENY_RULE_CONFLICT" {
					t.Fatalf("INV-07 case %s missing ConflictWitness", c.CaseID)
				}
				if len(c.ConflictWitness.AllowRuleIDs) == 0 || len(c.ConflictWitness.DenyRuleIDs) == 0 {
					t.Fatalf("INV-07 witness for %s has empty allow/deny lists", c.CaseID)
				}
				witnesses++
			}
		}
	}
	if witnesses < 2 {
		t.Fatalf("expected >= 2 structured ConflictWitnesses, got %d", witnesses)
	}
}

func TestINV08TimelockNonBypassability(t *testing.T) {
	suite := BuildAdversarialSuite(1352)
	for _, c := range suite.Cases {
		if c.InvariantID == "INV-08" && !c.Passed {
			t.Fatalf("INV-08 case %s failed: got %s/%s expected %s/%s",
				c.CaseID, c.ActualVerdict, c.ActualErrorCode, c.ExpectedVerdict, c.ExpectedErrorCode)
		}
	}
}

func TestINV09CryptographicProvenanceAndReplayDefense(t *testing.T) {
	suite := BuildAdversarialSuite(1352)
	for _, c := range suite.Cases {
		if c.InvariantID == "INV-09" && !c.Passed {
			t.Fatalf("INV-09 case %s failed: got %s/%s expected %s/%s",
				c.CaseID, c.ActualVerdict, c.ActualErrorCode, c.ExpectedVerdict, c.ExpectedErrorCode)
		}
	}
}

func TestINV10ConcurrentInterleavingNonEscalation(t *testing.T) {
	suite := BuildAdversarialSuite(1352)
	for _, c := range suite.Cases {
		if c.InvariantID == "INV-10" && !c.Passed {
			t.Fatalf("INV-10 case %s failed: got %s/%s expected %s/%s",
				c.CaseID, c.ActualVerdict, c.ActualErrorCode, c.ExpectedVerdict, c.ExpectedErrorCode)
		}
	}
}

func TestFullAdversarialSuiteCountAndPassRate(t *testing.T) {
	suite := BuildAdversarialSuite(1352)
	if suite.TotalCases < 40 {
		t.Fatalf("expected >= 40 adversarial suite cases, got %d", suite.TotalCases)
	}
	if suite.Failed != 0 || suite.Passed != suite.TotalCases {
		t.Fatalf("expected 100%% pass rate, got %d/%d", suite.Passed, suite.TotalCases)
	}
}

func TestBoundedModelChecker50kPlusZeroViolations(t *testing.T) {
	rep := RunModelChecker(1352)
	if rep.TotalStatesAndTransitions < 50000 {
		t.Fatalf("expected >= 50,000 states+transitions, got %d", rep.TotalStatesAndTransitions)
	}
	if rep.InvariantViolations != 0 {
		t.Fatalf("sound engine produced %d invariant violations", rep.InvariantViolations)
	}
	if len(rep.InvariantsChecked) != 10 {
		t.Fatalf("expected 10 invariants checked, got %d", len(rep.InvariantsChecked))
	}
}

func TestMutationAuditKillsAllTenMutants(t *testing.T) {
	mut := RunMutationAudit(1352)
	if mut.TotalMutants != 10 {
		t.Fatalf("expected 10 mutants, got %d", mut.TotalMutants)
	}
	if mut.MutantsKilled != 10 || mut.KillRateBps != 10000 {
		for _, m := range mut.Mutants {
			if !m.Killed {
				t.Errorf("mutant %s (%s) escaped model checker!", m.MutantID, m.Description)
			}
		}
		t.Fatalf("expected 10/10 mutants killed, got %d/%d", mut.MutantsKilled, mut.TotalMutants)
	}
}

func TestNegativeRegimesAllThreeHonestOutcomes(t *testing.T) {
	neg := RunNegativeRegimes(1352)
	// Regime 1: naive first-match silently allows ambiguous spends; fail-closed blocks 100%.
	if neg.FirstMatchMasksRuleConflict.NaiveFirstMatchUnsafeAllow == 0 {
		t.Fatalf("expected naive first-match to unsafely allow conflicting rules")
	}
	if neg.FirstMatchMasksRuleConflict.FailClosedBlocked != neg.FirstMatchMasksRuleConflict.Trials {
		t.Fatalf("expected fail-closed to block 100%% of conflicting trials")
	}
	// Regime 2: fail-closed liveness deadlock = 0% liveness, 0 safety violations.
	if neg.FailClosedLivenessDeadlock.ExecutedUnderCharterConflict != 0 || neg.FailClosedLivenessDeadlock.ExecutedUnderDefcon1Pause != 0 {
		t.Fatalf("expected 0 executions under conflict/pause deadlock")
	}
	if neg.FailClosedLivenessDeadlock.SafetyViolations != 0 {
		t.Fatalf("expected 0 safety violations in liveness deadlock regime")
	}
	// Regime 3: depth <= 6 misses planted depth-8 bug; depth >= 8 catches it.
	for _, p := range neg.BoundedMCDepthHorizon.DepthProbes {
		if p.MaxDepth <= 6 && p.BugDetected {
			t.Fatalf("expected depth %d to miss depth-8 bug", p.MaxDepth)
		}
		if p.MaxDepth >= 8 && (!p.BugDetected || p.CounterexampleLen != 8) {
			t.Fatalf("expected depth %d to catch 8-step bug, got detected=%t len=%d", p.MaxDepth, p.BugDetected, p.CounterexampleLen)
		}
	}
}

func TestDeterministicReproducibilityAndMerkleRoot(t *testing.T) {
	s1 := BuildAdversarialSuite(1352)
	s2 := BuildAdversarialSuite(1352)
	r1, err := AuditMerkleRoot(s1.Cases)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := AuditMerkleRoot(s2.Cases)
	if err != nil {
		t.Fatal(err)
	}
	if r1 != r2 || len(r1) != 64 {
		t.Fatalf("non-deterministic audit_merkle_root: %s vs %s", r1, r2)
	}
}

func TestConcurrentRaceSafety(t *testing.T) {
	suite := BuildAdversarialSuite(1352)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, c := range suite.Cases {
				cp := c
				RunCase(&cp, EngineConfig{SkipSigVerify: false})
				if !cp.Passed || cp.CaseDigest != c.CaseDigest {
					t.Errorf("concurrent verification mismatch on %s", c.CaseID)
				}
			}
		}()
	}
	wg.Wait()
}

func TestRegoBundlePresenceAndV1SyntaxHeaders(t *testing.T) {
	regoDir := filepath.Join("..", "..", "..", "rego")
	rep, err := InspectRegoBundle(regoDir)
	if err != nil {
		t.Fatalf("inspect rego bundle: %v", err)
	}
	if len(rep.Files) != 5 {
		t.Fatalf("expected 5 .rego files, got %v", rep.Files)
	}
	for _, f := range rep.Files {
		raw, err := os.ReadFile(filepath.Join(regoDir, f))
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		if !strings.Contains(text, "import rego.v1") {
			t.Fatalf("rego file %s missing 'import rego.v1'", f)
		}
		if !strings.Contains(text, "package govcheck.") {
			t.Fatalf("rego file %s missing 'package govcheck.*'", f)
		}
	}
}

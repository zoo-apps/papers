// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/zoo-apps/papers/zoo-dao-emergency-protocol/reference/go/internal/govcheck"
)

func main() {
	seed := flag.Int64("seed", 1352, "deterministic PRNG seed")
	regoDir := flag.String("rego-dir", "../rego", "path to OPA Rego v1 policy bundle")
	outPath := flag.String("out", "../results.json", "output path for benchmark results JSON")
	flag.Parse()

	res, err := govcheck.RunFullBenchmark(*seed, *regoDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "govcheck-bench error: %v\n", err)
		os.Exit(1)
	}

	raw, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal error: %v\n", err)
		os.Exit(1)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(*outPath, raw, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("constitutional-gov.v1 benchmark complete (seed=%d)\n", res.Seed)
	fmt.Printf("  adversarial suite: %d/%d passed (%d adversarial DENY, %d positive ALLOW)\n",
		res.AdversarialSuite.Passed, res.AdversarialSuite.TotalCases,
		res.AdversarialSuite.AdversarialDenyCases, res.AdversarialSuite.PositiveAllowCases)
	fmt.Printf("  model checker:     %d total states+transitions (BFS=%d states / %d transitions, fuzz=%d steps), violations=%d\n",
		res.ModelChecker.TotalStatesAndTransitions,
		res.ModelChecker.BFSStatesExplored,
		res.ModelChecker.BFSTransitionsChecked,
		res.ModelChecker.FuzzStepsChecked,
		res.ModelChecker.InvariantViolations)
	fmt.Printf("  mutation audit:    %d/%d mutants killed (%d bps)\n",
		res.MutationAudit.MutantsKilled, res.MutationAudit.TotalMutants, res.MutationAudit.KillRateBps)
	fmt.Printf("  audit_merkle_root: %s\n", res.AuditMerkleRoot)
}

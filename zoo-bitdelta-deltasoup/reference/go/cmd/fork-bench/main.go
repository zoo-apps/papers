// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zoo-apps/papers/zoo-bitdelta-deltasoup/reference/go/forkorg"
)

func main() {
	seed := flag.Int64("seed", 1352, "deterministic PRNG seed")
	fixtureOut := flag.String("fixture-out", "../fixtures/fork-exchange-suite.v1.json", "output path for canonical fixture JSON")
	resultsOut := flag.String("results-out", "../results.json", "output path for deterministic benchmark results JSON")
	flag.Parse()

	suite, report := forkorg.RunFullBenchmark(*seed)

	writePrettyJSON := func(path string, v any) error {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		b = append(b, '\n')
		return os.WriteFile(path, b, 0o644)
	}

	if err := writePrettyJSON(*fixtureOut, suite); err != nil {
		fmt.Fprintf(os.Stderr, "failed writing fixture: %v\n", err)
		os.Exit(1)
	}
	if err := writePrettyJSON(*resultsOut, report); err != nil {
		fmt.Fprintf(os.Stderr, "failed writing results: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated fixture (%s) and results (%s) with seed=%d\n", *fixtureOut, *resultsOut, *seed)
	fmt.Printf("Workflow passed: %v | Adversarial matched: %v (%d/%d caught)\n",
		report.Verification.AllWorkflowPassed,
		report.Verification.AllAdversarialMatched,
		report.Verification.AdversarialCaught,
		report.Verification.AdversarialTotal,
	)
	fmt.Printf("Audit Merkle Root: %s\n", report.Verification.AuditMerkleRoot)
	if !report.Verification.AllWorkflowPassed || !report.Verification.AllAdversarialMatched {
		os.Exit(2)
	}
}

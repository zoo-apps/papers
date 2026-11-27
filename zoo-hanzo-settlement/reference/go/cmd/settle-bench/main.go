// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zoo-apps/papers/zoo-hanzo-settlement/reference/go/settlement"
)

func main() {
	seed := flag.Uint64("seed", 1350, "deterministic benchmark seed (default 1350 for HIP-1350)")
	repoRoot := flag.String("repo-root", "../../..", "path to zoo-apps/papers repository root")
	manifestPath := flag.String("manifest", "../corpus-manifest.json", "path to corpus-manifest.json")
	traceOut := flag.String("trace-out", "../fixtures/settlement-trace.v1.json", "output path for canonical trace fixture")
	resultsOut := flag.String("results-out", "../results.json", "output path for benchmark results.json")
	flag.Parse()

	bundle, results, err := settlement.RunFullBenchmark(*repoRoot, *manifestPath, *seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "settle-bench failed: %v\n", err)
		os.Exit(1)
	}

	writePrettyJSON := func(path string, v any) error {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		raw, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		raw = append(raw, '\n')
		return os.WriteFile(path, raw, 0o644)
	}

	if err := writePrettyJSON(*traceOut, bundle); err != nil {
		fmt.Fprintf(os.Stderr, "write trace failed: %v\n", err)
		os.Exit(1)
	}
	if err := writePrettyJSON(*resultsOut, results); err != nil {
		fmt.Fprintf(os.Stderr, "write results failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("settle-bench complete (seed=%d): lifecycle_jobs=%d trace_cases=%d throughput=%.2f receipts/s adversarial_blocked=%d/%d conservation_exact=%v audit_merkle_root=%s\n",
		results.Seed,
		results.LifecycleJobs,
		results.TotalTraceCases,
		results.ThroughputReceiptsPerSec,
		results.AdversarialSuite.BlockedAttacks,
		results.AdversarialSuite.TotalAttacks,
		results.BalanceSheet.ConservationExact,
		results.AuditMerkleRoot,
	)
}

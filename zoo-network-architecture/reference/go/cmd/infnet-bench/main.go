// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zoo-apps/papers/zoo-network-architecture/reference/go/infnet"
)

func main() {
	repoRoot := flag.String("repo", "../../..", "path to zoo-apps/papers repository root")
	manifestPath := flag.String("manifest", "../corpus-manifest.json", "path to corpus-manifest.json")
	seed := flag.Uint64("seed", 1350, "deterministic benchmark seed (default: HIP-1350)")
	requests := flag.Int("requests", 80, "grounded requests per benchmark scenario")
	outPath := flag.String("out", "../results.json", "output path for machine-readable benchmark results")
	fixturesPath := flag.String("fixtures", "../fixtures/parity-suite.v1.json", "output path for canonical Go/Python parity suite")
	flag.Parse()

	report, suite, err := infnet.RunFullBenchmark(*repoRoot, *manifestPath, *seed, *requests)
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchmark failed: %v\n", err)
		os.Exit(1)
	}

	if err := writeJSON(*outPath, report); err != nil {
		fmt.Fprintf(os.Stderr, "write results: %v\n", err)
		os.Exit(1)
	}
	if err := writeJSON(*fixturesPath, suite); err != nil {
		fmt.Fprintf(os.Stderr, "write parity suite: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("infnet-bench complete (seed=%d, corpus_files=%d, parity_cases=%d)\n",
		report.Seed, report.CorpusFilesVerified, report.ParityCasesCount)
	fmt.Printf("corpus_root_sha256: %s\n", report.CorpusRootSHA256)
	fmt.Printf("audit_merkle_root:  %s\n", report.AuditMerkleRoot)
	fmt.Printf("total_privacy_leaks=%d total_capacity_leaks=%d\n\n",
		report.TotalPrivacyLeaks, report.TotalCapacityLeaks)

	fmt.Printf("%-42s %8s %8s %8s %8s %8s %9s %7s\n",
		"SCENARIO", "TOK/S", "TTFTp50", "TTFTp99", "TPOTp50", "BATCH%", "NET_B/REQ", "COMP%")
	for _, s := range report.Scenarios {
		fmt.Printf("%-42s %8.1f %8.1f %8.1f %8.1f %8.1f %9d %7.1f\n",
			s.ScenarioID, s.ThroughputTokPerSec, s.TTFTP50Ms, s.TTFTP99Ms,
			s.TPOTP50Ms, s.AvgBatchUtilizationPct, s.AvgNetworkBytesPerReq, s.CompletionRatePct)
	}
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

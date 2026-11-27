// Copyright 2026 Zoo Labs Foundation / Hanzo Industries.
// Licensed under the Apache License, Version 2.0.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zoo-apps/papers/zoo-gym-compute-proof/reference/go/inferverify"
)

func main() {
	repoRoot := flag.String("repo", "../../..", "Path to zoo-apps/papers repository root")
	manifestPath := flag.String("manifest", "../corpus-manifest.json", "Path to corpus-manifest.json")
	seed := flag.Uint64("seed", 1350, "Deterministic RNG seed")
	outResults := flag.String("out", "../results.json", "Output path for benchmark results JSON")
	outFixture := flag.String("fixtures", "../fixtures/verification-suite.v1.json", "Output path for parity verification fixture JSON")
	flag.Parse()

	corpus, err := inferverify.LoadAndVerifyCorpus(*repoRoot, *manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading corpus: %v\n", err)
		os.Exit(1)
	}

	report, suite, err := inferverify.RunFullBenchmark(*seed, corpus)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error running benchmark: %v\n", err)
		os.Exit(1)
	}

	if err := writeJSONFile(*outResults, report); err != nil {
		fmt.Fprintf(os.Stderr, "error writing results: %v\n", err)
		os.Exit(1)
	}
	if err := writeJSONFile(*outFixture, suite); err != nil {
		fmt.Fprintf(os.Stderr, "error writing fixture: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("inference-verify.v1 benchmark complete (seed=%d)\n", *seed)
	fmt.Printf("  corpus_root_sha256 : %s\n", report.CorpusRootSHA256)
	fmt.Printf("  model_digest       : %s\n", report.ModelDigest)
	fmt.Printf("  parity_cases       : %d (%d golden + %d adversarial), matched=%d\n",
		report.ParitySummary.TotalCases,
		report.ParitySummary.GoldenCases,
		report.ParitySummary.AdversarialCases,
		report.ParitySummary.MatchesExpected,
	)
	fmt.Printf("  audit_merkle_root  : %s\n", report.ParitySummary.AuditMerkleRoot)
	if !report.ParitySummary.AllMatched {
		fmt.Fprintf(os.Stderr, "FAIL: not all parity cases matched expected verdicts!\n")
		os.Exit(1)
	}
}

func writeJSONFile(path string, v any) error {
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

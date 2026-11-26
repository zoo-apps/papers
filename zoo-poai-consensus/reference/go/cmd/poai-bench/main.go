// Copyright 2026 Zoo Labs Foundation & Hanzo Industries.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zoo-apps/papers/zoo-poai-consensus/reference/go/poai"
)

func main() {
	repoRoot := flag.String("repo", "../../..", "Path to zoo-apps/papers repository root")
	manifestPath := flag.String("manifest", "../corpus-manifest.json", "Path to pinned corpus-manifest.json")
	seed := flag.Uint64("seed", 1350, "Deterministic benchmark seed (default: 1350 for HIP-1350)")
	trials := flag.Int("trials", 1000, "Independent trials per (corruption class, k) cell")
	outResults := flag.String("out", "../results.json", "Path to write benchmark report JSON")
	outFixtures := flag.String("fixtures", "../fixtures/parity-suite.v1.json", "Path to write cross-language parity fixture suite JSON")
	flag.Parse()

	report, suite, err := poai.RunFullBenchmark(*repoRoot, *manifestPath, *seed, *trials)
	if err != nil {
		fmt.Fprintf(os.Stderr, "poai-bench error: %v\n", err)
		os.Exit(1)
	}

	if err := writeJSON(*outResults, report); err != nil {
		fmt.Fprintf(os.Stderr, "write results error: %v\n", err)
		os.Exit(1)
	}
	if err := writeJSON(*outFixtures, suite); err != nil {
		fmt.Fprintf(os.Stderr, "write fixtures error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("poai-bench complete (seed=%d, trials=%d)\n", *seed, *trials)
	fmt.Printf("  corpus_root_sha256: %s\n", report.CorpusRootSHA256)
	fmt.Printf("  parity_suite_cases: %d\n", report.ParitySuiteCases)
	fmt.Printf("  audit_merkle_root : %s\n", report.AuditMerkleRoot)
	fmt.Printf("  wrote results     : %s\n", *outResults)
	fmt.Printf("  wrote fixtures    : %s\n", *outFixtures)
}

func writeJSON(path string, v any) error {
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

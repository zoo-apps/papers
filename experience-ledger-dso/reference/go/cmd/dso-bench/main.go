// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zoo-apps/papers/experience-ledger-dso/reference/go/internal/dso"
)

func main() {
	repoRoot := flag.String("repo-root", "../../..", "Path to zoo-apps/papers repository root")
	seed := flag.Int64("seed", 1352, "Deterministic benchmark PRNG seed")
	outResults := flag.String("out-results", "../results.json", "Path to write reproducible results.json")
	outTrace := flag.String("out-trace", "../audit_trace.json", "Path to write signed audit_trace.json for Python parity verification")
	flag.Parse()

	absRoot, err := filepath.Abs(*repoRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve repo-root: %v\n", err)
		os.Exit(1)
	}

	report, trace, err := dso.RunFullBenchmark(absRoot, *seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchmark failed: %v\n", err)
		os.Exit(1)
	}

	resBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal results: %v\n", err)
		os.Exit(1)
	}
	resBytes = append(resBytes, '\n')
	if err := os.WriteFile(*outResults, resBytes, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write results: %v\n", err)
		os.Exit(1)
	}

	if *outTrace != "" {
		traceBytes, err := json.MarshalIndent(trace, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "marshal trace: %v\n", err)
			os.Exit(1)
		}
		traceBytes = append(traceBytes, '\n')
		if err := os.WriteFile(*outTrace, traceBytes, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write trace: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("DSO Aggregation Benchmark Complete (seed=%d)\n", report.Seed)
	fmt.Printf("  Corpus Papers:      %d (%d protocol_governance, %d conservation_science)\n",
		report.CorpusPaperCount, report.ProtocolPaperCount, report.ConservPaperCount)
	fmt.Printf("  Corpus Paragraphs:  %d protocol, %d conservation\n",
		report.ProtocolParaCount, report.ConservParaCount)
	fmt.Printf("  Corpus SHA-256:     %s\n", report.CorpusSHA256)
	fmt.Printf("  Benchmark Cells:    %d (4 scenarios x 6 adversary fractions x 5 aggregators)\n", len(report.Cells))
	fmt.Printf("  Audit Merkle Root:  %s\n", report.AuditMerkleRoot)
	fmt.Printf("  Trace Merkle Root:  %s\n", trace.TraceMerkleRoot)
}

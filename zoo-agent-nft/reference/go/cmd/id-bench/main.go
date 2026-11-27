// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zoo-apps/papers/zoo-agent-nft/reference/go/agentid"
)

type exportedBenchBundle struct {
	Seed           int64               `json:"seed"`
	DepthCases     []exportedDepthCase `json:"depth_cases"`
	BitstringCases []exportedBitCase   `json:"bitstring_cases"`
}

type exportedDepthCase struct {
	Depth        int                         `json:"depth"`
	Context      agentid.VerificationContext `json:"context"`
	Presentation agentid.ActionPresentation  `json:"presentation"`
}

type exportedBitCase struct {
	BitLength    int                         `json:"bit_length"`
	DensityLabel string                      `json:"density_label"`
	Context      agentid.VerificationContext `json:"context"`
	Presentation agentid.ActionPresentation  `json:"presentation"`
}

func main() {
	seed := flag.Int64("seed", 1352, "Deterministic PRNG seed")
	iters := flag.Int("iters", 200, "Warm benchmark iterations per depth")
	fixtureOut := flag.String("fixture-out", "../fixtures/identity-delegation-suite.v1.json", "Path to write deterministic fixture (empty to skip)")
	resultsOut := flag.String("results-out", "../results.json", "Path to write benchmark results JSON (empty to skip)")
	exportBenchOut := flag.String("export-bench", "", "Optional path to export depth+bitstring benchmark bundle for Python parity benchmarking")
	flag.Parse()

	report, suite, err := agentid.RunGoBenchmarks(*seed, *iters)
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchmark failed: %v\n", err)
		os.Exit(1)
	}

	if *fixtureOut != "" {
		if err := writeJSONFile(*fixtureOut, suite); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write fixture %s: %v\n", *fixtureOut, err)
			os.Exit(1)
		}
	}

	if *resultsOut != "" {
		if err := writeJSONFile(*resultsOut, report); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write results %s: %v\n", *resultsOut, err)
			os.Exit(1)
		}
	}

	if *exportBenchOut != "" {
		bundle, err := buildExportedBenchBundle(*seed)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to build exported bench bundle: %v\n", err)
			os.Exit(1)
		}
		if err := writeJSONFile(*exportBenchOut, bundle); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write exported bench bundle: %v\n", err)
			os.Exit(1)
		}
	}

	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal report: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(out))

	if !report.SuiteSummary.AllStagesValid || !report.SuiteSummary.AllThreatPass {
		os.Exit(1)
	}
}

func buildExportedBenchBundle(seed int64) (exportedBenchBundle, error) {
	depths := []int{1, 2, 4, 8, 16}
	dCases := make([]exportedDepthCase, 0, len(depths))
	for _, d := range depths {
		ctx, pres, err := agentid.BuildDepthBenchmarkCase(seed, d, agentid.DefaultBitstringLength, []int{1, 7, 4096, 99999}, agentid.EncodingGzipBase64URL)
		if err != nil {
			return exportedBenchBundle{}, err
		}
		dCases = append(dCases, exportedDepthCase{Depth: d, Context: ctx, Presentation: pres})
	}
	bCases := make([]exportedBitCase, 0, 3)
	for _, bl := range []int{1024, 16384, 131072} {
		ctx, pres, err := agentid.BuildDepthBenchmarkCase(seed, 4, bl, []int{1, 7, bl - 1}, agentid.EncodingGzipBase64URL)
		if err != nil {
			return exportedBenchBundle{}, err
		}
		bCases = append(bCases, exportedBitCase{BitLength: bl, DensityLabel: "sparse", Context: ctx, Presentation: pres})
	}
	return exportedBenchBundle{
		Seed:           seed,
		DepthCases:     dCases,
		BitstringCases: bCases,
	}, nil
}

func writeJSONFile(path string, v any) error {
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

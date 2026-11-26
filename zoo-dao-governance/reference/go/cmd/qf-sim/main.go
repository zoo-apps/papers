// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"zoo.ngo/papers/zoo-dao-governance/reference/qfsim/internal/qfsim"
)

func main() {
	seed := flag.Int64("seed", qfsim.DefaultSeed, "Deterministic simulation seed")
	papersRoot := flag.String("papers-root", "../../..", "Path to zoo-apps/papers repository root")
	outPath := flag.String("out", "../results.json", "Output JSON path for ResultsArtifact")
	scenariosOut := flag.String("scenarios-out", "../scenarios.json", "Output JSON path for raw ScenariosArtifact")
	flag.Parse()

	absRoot, err := filepath.Abs(*papersRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve papers-root: %v\n", err)
		os.Exit(1)
	}

	report, err := qfsim.RunFullBenchmark(absRoot, *seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchmark failed: %v\n", err)
		os.Exit(1)
	}

	resArt, scArt := report.ToArtifacts()

	resBytes, err := json.MarshalIndent(resArt, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal results: %v\n", err)
		os.Exit(1)
	}
	resBytes = append(resBytes, '\n')
	if err := os.WriteFile(*outPath, resBytes, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write results %s: %v\n", *outPath, err)
		os.Exit(1)
	}

	scBytes, err := json.Marshal(scArt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal scenarios: %v\n", err)
		os.Exit(1)
	}
	scBytes = append(scBytes, '\n')
	if err := os.WriteFile(*scenariosOut, scBytes, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write scenarios %s: %v\n", *scenariosOut, err)
		os.Exit(1)
	}

	fmt.Printf("spec_version:      %s\n", report.SpecVersion)
	fmt.Printf("seed:              %d\n", report.Seed)
	fmt.Printf("scenarios:         %d\n", len(report.Scenarios))
	fmt.Printf("evaluations:       %d\n", len(report.Evaluations))
	fmt.Printf("corpus_hash:       %s\n", report.CorpusHash)
	fmt.Printf("governance_hash:   %s\n", report.GovernanceHash)
	fmt.Printf("eval_merkle_root:  %s\n", report.EvalMerkleRoot)
	fmt.Printf("audit_merkle_root: %s\n", report.AuditMerkleRoot)
	fmt.Printf("wrote:             %s, %s\n", *outPath, *scenariosOut)
}

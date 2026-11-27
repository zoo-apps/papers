// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zoo-apps/papers/zoo-dao-reputation-system/reference/go/attrrep"
)

func main() {
	repoRoot := flag.String("repo-root", "../../..", "Path to zoo-apps/papers repository root")
	refDir := flag.String("ref-dir", "..", "Path to zoo-dao-reputation-system/reference directory")
	seed := flag.Int64("seed", 1352, "Deterministic benchmark seed (default 1352 for HIP-1352)")
	flag.Parse()

	manifest, papers, err := attrrep.LoadCorpus(*repoRoot, *seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load corpus failed: %v\n", err)
		os.Exit(1)
	}

	bundle, err := attrrep.BuildPublishedSuite(manifest, papers, *seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build suite failed: %v\n", err)
		os.Exit(1)
	}

	results, report, err := attrrep.RunBenchmark(manifest, papers, bundle, *seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run benchmark failed: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(filepath.Join(*refDir, "fixtures"), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir fixtures: %v\n", err)
		os.Exit(1)
	}

	writeJSON := func(rel string, v any) error {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(*refDir, rel), append(b, '\n'), 0o644)
	}

	if err := writeJSON("corpus-manifest.json", manifest); err != nil {
		fmt.Fprintf(os.Stderr, "write corpus-manifest.json: %v\n", err)
		os.Exit(1)
	}
	if err := writeJSON(filepath.Join("fixtures", "attribution-suite.v1.json"), bundle); err != nil {
		fmt.Fprintf(os.Stderr, "write attribution-suite.v1.json: %v\n", err)
		os.Exit(1)
	}
	if err := writeJSON("results.json", results); err != nil {
		fmt.Fprintf(os.Stderr, "write results.json: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated artifacts with seed=%d\n", *seed)
	fmt.Printf("  Corpus papers:        %d (manifest=%s)\n", manifest.PaperCount, manifest.ManifestHash[:16])
	fmt.Printf("  Total DAG events:     %d (%d contributions + %d attestations)\n", results.TotalDAGItems, results.TotalContributions, results.TotalAttestations)
	fmt.Printf("  Contributions:        %d accepted, %d rejected\n", results.AcceptedContributions, results.RejectedContributions)
	fmt.Printf("  Attestations:         %d accepted, %d advisory, %d rejected\n", results.AcceptedAttestations, results.AdvisoryAttestations, results.RejectedAttestations)
	fmt.Printf("  Conservation exact:   %v (intrinsic=%d == attributed=%d vs naive=%d)\n", results.ConservationExact, results.TotalIntrinsicMicro, results.TotalAttributedMicro, results.TotalNaiveAttrMicro)
	fmt.Printf("  Adversarial suite:    %d/%d PASSED\n", results.AdversarialPassed, results.AdversarialTotal)
	fmt.Printf("  Audit Merkle root:    %s\n", report.AuditMerkleRoot)
	for _, nr := range results.NegativeRegimes {
		fmt.Printf("  Negative regime [%s]: passed=%v — %s\n", nr.RegimeID, nr.Passed, nr.Summary)
	}

	allNegPassed := true
	for _, nr := range results.NegativeRegimes {
		if !nr.Passed {
			allNegPassed = false
		}
	}
	if !results.ConservationExact || results.AdversarialPassed != results.AdversarialTotal || !allNegPassed {
		fmt.Fprintln(os.Stderr, "ERROR: one or more benchmark assertions failed!")
		for _, ar := range results.AdversarialResults {
			if !ar.Passed {
				fmt.Fprintf(os.Stderr, "  FAIL %s (%s): expected %s/%s got %s/%s\n",
					ar.AttackID, ar.TargetID, ar.ExpectedStatus, ar.ExpectedErrCode, ar.ActualStatus, ar.ActualErrCode)
			}
		}
		os.Exit(1)
	}
}

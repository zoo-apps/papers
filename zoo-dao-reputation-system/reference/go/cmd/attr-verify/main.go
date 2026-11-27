// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/zoo-apps/papers/zoo-dao-reputation-system/reference/go/attrrep"
)

func main() {
	suitePath := flag.String("suite", "", "Path to attribution-suite.v1.json")
	outPath := flag.String("out", "", "Optional path to write full JSON verification report")
	summaryOnly := flag.Bool("summary", false, "Print compact summary JSON to stdout")
	flag.Parse()

	if *suitePath == "" {
		fmt.Fprintln(os.Stderr, "usage: attr-verify --suite <path/to/attribution-suite.v1.json> [--out report.json] [--summary]")
		os.Exit(2)
	}

	raw, err := os.ReadFile(*suitePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading suite: %v\n", err)
		os.Exit(1)
	}
	var bundle attrrep.SuiteBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		fmt.Fprintf(os.Stderr, "error decoding suite: %v\n", err)
		os.Exit(1)
	}

	report, err := attrrep.VerifySuite(bundle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verification error: %v\n", err)
		os.Exit(1)
	}

	if *outPath != "" {
		enc, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "marshal report: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*outPath, append(enc, '\n'), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write report: %v\n", err)
			os.Exit(1)
		}
	}

	if *summaryOnly {
		sum := map[string]any{
			"schema_version":          report.SchemaVersion,
			"spec_version":            report.SpecVersion,
			"suite_name":              report.SuiteName,
			"audit_merkle_root":       report.AuditMerkleRoot,
			"total_contributions":     report.TotalContributions,
			"accepted_contributions":  report.AcceptedContributions,
			"rejected_contributions":  report.RejectedContributions,
			"total_attestations":      report.TotalAttestations,
			"accepted_attestations":   report.AcceptedAttestations,
			"advisory_attestations":   report.AdvisoryAttestations,
			"rejected_attestations":   report.RejectedAttestations,
			"total_intrinsic_micro":   report.TotalIntrinsicMicro,
			"total_attributed_micro":  report.TotalAttributedMicro,
			"conservation_exact":      report.ConservationExact,
			"adversarial_passed":      report.AdversarialPassed,
			"adversarial_total":       report.AdversarialTotal,
			"collusion_findings":      len(report.CollusionFindings),
		}
		enc, _ := json.MarshalIndent(sum, "", "  ")
		fmt.Println(string(enc))
	} else {
		enc, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "marshal report: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(enc))
	}

	if !report.ConservationExact || report.AdversarialPassed != report.AdversarialTotal {
		os.Exit(1)
	}
}

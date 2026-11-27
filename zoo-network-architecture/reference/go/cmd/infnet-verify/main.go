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

	"github.com/zoo-apps/papers/zoo-network-architecture/reference/go/infnet"
)

func main() {
	suitePath := flag.String("suite", "../fixtures/parity-suite.v1.json", "path to parity-suite.v1.json")
	resultsPath := flag.String("results", "", "optional path to results.json to cross-check audit_merkle_root")
	flag.Parse()

	raw, err := os.ReadFile(*suitePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read suite: %v\n", err)
		os.Exit(1)
	}
	var suite infnet.ParitySuite
	if err := json.Unmarshal(raw, &suite); err != nil {
		fmt.Fprintf(os.Stderr, "parse suite: %v\n", err)
		os.Exit(1)
	}

	verdicts, root, err := infnet.VerifyParitySuite(suite)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify suite: %v\n", err)
		os.Exit(1)
	}

	mismatches := 0
	for i, c := range suite.Cases {
		v := verdicts[i]
		ok := v.Valid == c.ExpectedValid &&
			v.ErrorCode == c.ExpectedErrorCode &&
			v.VerdictDigest == c.ExpectedVerdictDigest
		if !ok {
			mismatches++
			fmt.Fprintf(os.Stderr, "MISMATCH %s: got (valid=%v code=%s digest=%s) want (valid=%v code=%s digest=%s)\n",
				c.CaseID, v.Valid, v.ErrorCode, v.VerdictDigest, c.ExpectedValid, c.ExpectedErrorCode, c.ExpectedVerdictDigest)
		}
	}

	if root != suite.AuditMerkleRoot {
		fmt.Fprintf(os.Stderr, "MISMATCH audit_merkle_root: got %s want %s\n", root, suite.AuditMerkleRoot)
		mismatches++
	}

	if *resultsPath != "" {
		rRaw, err := os.ReadFile(*resultsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read results: %v\n", err)
			os.Exit(1)
		}
		var rep infnet.BenchmarkReport
		if err := json.Unmarshal(rRaw, &rep); err != nil {
			fmt.Fprintf(os.Stderr, "parse results: %v\n", err)
			os.Exit(1)
		}
		if rep.AuditMerkleRoot != root {
			fmt.Fprintf(os.Stderr, "MISMATCH results.json audit_merkle_root: got %s want %s\n", rep.AuditMerkleRoot, root)
			mismatches++
		}
		if rep.ProvesScientificTruth || rep.AuthorizesTreasurySpend {
			fmt.Fprintf(os.Stderr, "CONSTITUTIONAL LOCK VIOLATION in results.json\n")
			mismatches++
		}
	}

	if mismatches > 0 {
		fmt.Fprintf(os.Stderr, "infnet-verify FAILED: %d mismatch(es)\n", mismatches)
		os.Exit(1)
	}

	fmt.Printf("infnet-verify PASS: %d/%d cases verified, audit_merkle_root=%s\n",
		len(verdicts), len(suite.Cases), root)
}

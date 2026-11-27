// Copyright 2026 Zoo Labs Foundation / Hanzo Industries.
// Licensed under the Apache License, Version 2.0.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/zoo-apps/papers/zoo-gym-compute-proof/reference/go/inferverify"
)

func main() {
	suitePath := flag.String("suite", "../fixtures/verification-suite.v1.json", "Path to verification-suite.v1.json")
	flag.Parse()

	raw, err := os.ReadFile(*suitePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading suite: %v\n", err)
		os.Exit(1)
	}
	var suite inferverify.VerificationSuite
	if err := json.Unmarshal(raw, &suite); err != nil {
		fmt.Fprintf(os.Stderr, "error decoding suite: %v\n", err)
		os.Exit(1)
	}

	audit := inferverify.AuditSuite(suite)
	fmt.Printf("Go verifier audited %d cases (%d golden + %d adversarial)\n",
		audit.TotalCases, audit.GoldenCases, audit.AdversarialCase)
	fmt.Printf("  matched_expected  : %d / %d\n", audit.MatchesExpected, audit.TotalCases)
	fmt.Printf("  audit_merkle_root : %s\n", audit.AuditMerkleRoot)

	if audit.MatchesExpected != audit.TotalCases {
		for i, r := range audit.Results {
			c := suite.Cases[i]
			if r.Verdict != c.ExpectedVerdict || r.ErrorCode != c.ExpectedErrorCode || r.FraudEscaped != c.ExpectedFraudEscaped {
				fmt.Fprintf(os.Stderr, "MISMATCH %s: got (%s, %s, escaped=%v) want (%s, %s, escaped=%v)\n",
					c.CaseID, r.Verdict, r.ErrorCode, r.FraudEscaped, c.ExpectedVerdict, c.ExpectedErrorCode, c.ExpectedFraudEscaped)
			}
		}
		os.Exit(1)
	}
	if suite.ExpectedAuditMerkleRoot != "" && audit.AuditMerkleRoot != suite.ExpectedAuditMerkleRoot {
		fmt.Fprintf(os.Stderr, "MERKLE ROOT MISMATCH: got %s want %s\n", audit.AuditMerkleRoot, suite.ExpectedAuditMerkleRoot)
		os.Exit(1)
	}
	fmt.Println("PASS: Go verifier 100.00% matched expected verdicts and audit_merkle_root")
}

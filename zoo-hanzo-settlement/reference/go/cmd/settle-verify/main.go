// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/zoo-apps/papers/zoo-hanzo-settlement/reference/go/settlement"
)

func main() {
	tracePath := flag.String("trace", "../fixtures/settlement-trace.v1.json", "path to settlement-receipt.v1 trace JSON")
	flag.Parse()

	raw, err := os.ReadFile(*tracePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read trace: %v\n", err)
		os.Exit(1)
	}
	var bundle settlement.SettlementTraceBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		fmt.Fprintf(os.Stderr, "parse trace: %v\n", err)
		os.Exit(1)
	}

	report, err := settlement.VerifyTraceBundle(bundle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: %v\n", err)
		os.Exit(1)
	}

	summary := map[string]any{
		"verifier":               "go-stdlib-1.24",
		"protocol":               report.Protocol,
		"schema_version":         report.SchemaVersion,
		"total_cases":            report.TotalCases,
		"accepted_cases":         report.AcceptedCases,
		"rejected_cases":         report.RejectedCases,
		"matched_count":          report.MatchedCount,
		"all_matched":            report.AllMatched,
		"conservation_exact":     report.ConservationExact,
		"audit_merkle_root":      report.AuditMerkleRoot,
		"audit_root_matched":     report.AuditRootMatched,
		"authorized_receipts":    report.BalanceSheet.AuthorizedReceiptCount,
		"total_finalized_escrow": report.BalanceSheet.TotalFinalizedEscrowMicroZOO,
		"total_authorized":       report.BalanceSheet.TotalAuthorizedPayoutMicroZOO,
		"conservation_fund":      report.BalanceSheet.ConservationFundMicroZOO,
		"protocol_fee_pool":      report.BalanceSheet.ProtocolFeePoolMicroZOO,
		"total_payer_refunds":    report.BalanceSheet.TotalPayerRefundsMicroZOO,
	}
	out, _ := json.MarshalIndent(summary, "", "  ")
	fmt.Println(string(out))

	if !report.AllMatched || !report.ConservationExact || !report.AuditRootMatched {
		os.Exit(1)
	}
}

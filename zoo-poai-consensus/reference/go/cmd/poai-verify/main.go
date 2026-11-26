// Copyright 2026 Zoo Labs Foundation & Hanzo Industries.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"

	"github.com/zoo-apps/papers/zoo-poai-consensus/reference/go/poai"
)

func main() {
	suitePath := flag.String("suite", "../fixtures/parity-suite.v1.json", "Path to parity-suite.v1.json")
	flag.Parse()

	raw, err := os.ReadFile(*suitePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read suite error: %v\n", err)
		os.Exit(1)
	}
	var suite poai.ParitySuite
	if err := json.Unmarshal(raw, &suite); err != nil {
		fmt.Fprintf(os.Stderr, "parse suite error: %v\n", err)
		os.Exit(1)
	}

	receipts := make([]poai.VerificationReceipt, 0, len(suite.Cases))
	mismatches := 0
	for _, tc := range suite.Cases {
		dims := tc.Transcript.Header.Dims
		a := &poai.Int8Matrix{Rows: dims.M, Cols: dims.D, Data: tc.MatrixA}
		b := &poai.Int8Matrix{Rows: dims.D, Cols: dims.N, Data: tc.MatrixB}
		c := &poai.Int64Matrix{Rows: dims.M, Cols: dims.N, Data: tc.MatrixC}

		got := poai.VerifyTranscript(&tc.Transcript, a, b, c)
		receipts = append(receipts, got)

		if !reflect.DeepEqual(got, tc.ExpectedReceipt) {
			fmt.Fprintf(os.Stderr, "MISMATCH on %s: got verdict=%s errors=%v, want verdict=%s errors=%v\n",
				tc.CaseID,
				got.ConstitutionalBoundary.ComputeVerdict, got.ConstitutionalBoundary.ErrorCodes,
				tc.ExpectedReceipt.ConstitutionalBoundary.ComputeVerdict, tc.ExpectedReceipt.ConstitutionalBoundary.ErrorCodes,
			)
			mismatches++
		}
	}

	gotRoot := poai.ComputeAuditMerkleRoot(receipts)
	if gotRoot != suite.AuditMerkleRoot {
		fmt.Fprintf(os.Stderr, "AUDIT MERKLE ROOT MISMATCH: got %s, want %s\n", gotRoot, suite.AuditMerkleRoot)
		os.Exit(1)
	}
	if mismatches > 0 {
		os.Exit(1)
	}

	fmt.Printf("poai-verify PASS: %d/%d cases bit-identical\n", len(suite.Cases), len(suite.Cases))
	fmt.Printf("audit_merkle_root: %s\n", gotRoot)
}

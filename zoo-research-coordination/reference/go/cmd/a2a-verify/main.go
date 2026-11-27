// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/zoo-apps/papers/zoo-research-coordination/reference/go/feda2a"
)

func main() {
	fixturePath := flag.String("fixture", "../fixtures/a2a-exchange-suite.v1.json", "Path to federated-a2a.v1 suite fixture")
	compact := flag.Bool("compact", false, "Emit canonical compact JSON matching Python CLI byte-for-byte")
	flag.Parse()

	raw, err := os.ReadFile(*fixturePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read fixture %s: %v\n", *fixturePath, err)
		os.Exit(2)
	}
	var suite feda2a.ExchangeSuite
	if err := json.Unmarshal(raw, &suite); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse fixture JSON: %v\n", err)
		os.Exit(2)
	}

	report := feda2a.VerifySuite(suite)
	var out []byte
	if *compact {
		out, err = feda2a.CanonicalJSON(report)
	} else {
		out, err = json.MarshalIndent(report, "", "  ")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode verification report: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(string(out))

	if !report.AllStagesValid || !report.AllAdversarialPass || !report.WireAudit.ZeroBoundaryLeakage {
		os.Exit(1)
	}
}

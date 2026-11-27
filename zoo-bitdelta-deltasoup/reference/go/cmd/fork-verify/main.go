// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/zoo-apps/papers/zoo-bitdelta-deltasoup/reference/go/forkorg"
)

func main() {
	fixturePath := flag.String("fixture", "../fixtures/fork-exchange-suite.v1.json", "path to canonical fork-exchange-suite.v1.json fixture")
	compact := flag.Bool("compact", false, "emit compact canonical JSON (for bit-exact Go/Python diffing)")
	flag.Parse()

	raw, err := os.ReadFile(*fixturePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading fixture: %v\n", err)
		os.Exit(1)
	}
	var suite forkorg.ForkExchangeSuite
	if err := json.Unmarshal(raw, &suite); err != nil {
		fmt.Fprintf(os.Stderr, "error decoding fixture: %v\n", err)
		os.Exit(1)
	}

	report := forkorg.VerifySuite(suite)
	var out []byte
	if *compact {
		out, err = forkorg.CanonicalJSON(report)
	} else {
		out, err = json.MarshalIndent(report, "", "  ")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error encoding report: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(out))

	if !report.AllWorkflowPassed || !report.AllAdversarialMatched {
		os.Exit(2)
	}
}

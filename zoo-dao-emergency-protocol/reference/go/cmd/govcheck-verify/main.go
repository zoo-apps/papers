// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/zoo-apps/papers/zoo-dao-emergency-protocol/reference/go/internal/govcheck"
)

func main() {
	inPath := flag.String("in", "../results.json", "path to benchmark results JSON to verify")
	regoDir := flag.String("rego-dir", "../rego", "path to OPA Rego v1 policy bundle")
	flag.Parse()

	raw, err := os.ReadFile(*inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read error: %v\n", err)
		os.Exit(1)
	}
	var res govcheck.BenchmarkResults
	if err := json.Unmarshal(raw, &res); err != nil {
		fmt.Fprintf(os.Stderr, "json unmarshal error: %v\n", err)
		os.Exit(1)
	}

	if res.SchemaVersion != govcheck.SchemaVersion || res.SpecVersion != govcheck.SpecVersion {
		fmt.Fprintf(os.Stderr, "schema/spec mismatch: got %s/%s\n", res.SchemaVersion, res.SpecVersion)
		os.Exit(1)
	}

	verified := make([]govcheck.AdversarialCase, len(res.AdversarialSuite.Cases))
	copy(verified, res.AdversarialSuite.Cases)

	for i := range verified {
		orig := res.AdversarialSuite.Cases[i]
		govcheck.RunCase(&verified[i], govcheck.EngineConfig{SkipSigVerify: false})
		if verified[i].ActualVerdict != orig.ActualVerdict || verified[i].ActualErrorCode != orig.ActualErrorCode {
			fmt.Fprintf(os.Stderr, "case %s verdict mismatch: expected %s/%s got %s/%s\n",
				orig.CaseID, orig.ActualVerdict, orig.ActualErrorCode,
				verified[i].ActualVerdict, verified[i].ActualErrorCode)
			os.Exit(1)
		}
		if verified[i].CaseDigest != orig.CaseDigest {
			fmt.Fprintf(os.Stderr, "case %s digest mismatch: %s != %s\n",
				orig.CaseID, verified[i].CaseDigest, orig.CaseDigest)
			os.Exit(1)
		}
		if !verified[i].Passed {
			fmt.Fprintf(os.Stderr, "case %s failed expectation\n", orig.CaseID)
			os.Exit(1)
		}
	}

	root, err := govcheck.AuditMerkleRoot(verified)
	if err != nil {
		fmt.Fprintf(os.Stderr, "merkle root error: %v\n", err)
		os.Exit(1)
	}
	if root != res.AuditMerkleRoot {
		fmt.Fprintf(os.Stderr, "audit_merkle_root mismatch: computed %s != file %s\n", root, res.AuditMerkleRoot)
		os.Exit(1)
	}

	regoRep, err := govcheck.InspectRegoBundle(*regoDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rego bundle inspect error: %v\n", err)
		os.Exit(1)
	}
	if regoRep.BundleSHA256 != res.RegoBundle.BundleSHA256 {
		fmt.Fprintf(os.Stderr, "rego bundle sha256 mismatch: computed %s != file %s\n",
			regoRep.BundleSHA256, res.RegoBundle.BundleSHA256)
		os.Exit(1)
	}

	fmt.Printf("VERIFIED OK: %d/%d Ed25519-signed cases, rego_bundle_sha256=%s, audit_merkle_root=%s\n",
		len(verified), len(verified), regoRep.BundleSHA256, root)
}

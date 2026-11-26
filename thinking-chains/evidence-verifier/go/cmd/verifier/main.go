// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zoo-apps/papers/thinking-chains/evidence-verifier/go/verifier"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: verifier <benchmark|verify|manifest> [flags]\n")
		os.Exit(2)
	}
	sub := os.Args[1]
	fs := flag.NewFlagSet(sub, flag.ExitOnError)
	corpusRoot := fs.String("corpus", "../../..", "Path to zoo-apps/papers repository root")
	datasetPath := fs.String("dataset", "../dataset/benchmark-claims.v1.json", "Path to ClaimBundle JSON")
	outPath := fs.String("out", "", "Optional path to write JSON report")
	seed := fs.Int64("seed", 1352, "Expected benchmark seed")
	_ = fs.Parse(os.Args[2:])

	absCorpus, err := filepath.Abs(*corpusRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid corpus path: %v\n", err)
		os.Exit(1)
	}

	switch sub {
	case "benchmark":
		raw, err := os.ReadFile(*datasetPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed reading dataset: %v\n", err)
			os.Exit(1)
		}
		var bundle verifier.ClaimBundle
		if err := json.Unmarshal(raw, &bundle); err != nil {
			fmt.Fprintf(os.Stderr, "failed parsing dataset: %v\n", err)
			os.Exit(1)
		}
		if *seed != 0 && bundle.Seed != *seed {
			fmt.Fprintf(os.Stderr, "seed mismatch: dataset has %d, flag --seed=%d\n", bundle.Seed, *seed)
			os.Exit(1)
		}
		v := verifier.New(absCorpus)
		report := v.RunBenchmark(bundle, "go-1.24-stdlib")
		enc, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "marshal report failed: %v\n", err)
			os.Exit(1)
		}
		if *outPath != "" {
			if err := os.WriteFile(*outPath, append(enc, '\n'), 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "write report failed: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Println(string(enc))
		}

	case "verify":
		raw, err := os.ReadFile(*datasetPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed reading bundle: %v\n", err)
			os.Exit(1)
		}
		var bundle verifier.ClaimBundle
		if err := json.Unmarshal(raw, &bundle); err != nil {
			fmt.Fprintf(os.Stderr, "failed parsing bundle: %v\n", err)
			os.Exit(1)
		}
		v := verifier.New(absCorpus)
		results, root := v.VerifyBundle(bundle)
		out := map[string]any{
			"schema_version":    verifier.SchemaVersion,
			"bundle_id":         bundle.BundleID,
			"audit_merkle_root": root,
			"results":           results,
		}
		enc, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(enc))

	case "manifest":
		manifestPath := filepath.Join(filepath.Dir(*datasetPath), "corpus-manifest.json")
		raw, err := os.ReadFile(manifestPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed reading manifest: %v\n", err)
			os.Exit(1)
		}
		var m struct {
			Documents []struct {
				DocID  string `json:"doc_id"`
				Path   string `json:"path"`
				SHA256 string `json:"sha256"`
			} `json:"documents"`
		}
		if err := json.Unmarshal(raw, &m); err != nil {
			fmt.Fprintf(os.Stderr, "parse manifest failed: %v\n", err)
			os.Exit(1)
		}
		okCount := 0
		for _, doc := range m.Documents {
			data, err := os.ReadFile(filepath.Join(absCorpus, doc.Path))
			if err != nil {
				fmt.Fprintf(os.Stderr, "FAIL %s (%s): %v\n", doc.DocID, doc.Path, err)
				os.Exit(1)
			}
			got := verifier.SHA256Hex(data)
			if got != doc.SHA256 {
				fmt.Fprintf(os.Stderr, "FAIL %s (%s): expected %s, got %s\n", doc.DocID, doc.Path, doc.SHA256, got)
				os.Exit(1)
			}
			okCount++
		}
		fmt.Printf("OK: %d/%d corpus documents match pinned SHA-256 digests\n", okCount, len(m.Documents))

	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", sub)
		os.Exit(2)
	}
}

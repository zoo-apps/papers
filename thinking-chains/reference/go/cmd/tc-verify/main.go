// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation and Contributors

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/zoo-apps/papers/thinking-chains/reference/go/receipt"
)

func errorCode(err error) string {
	var ve *receipt.VerificationError
	if errors.As(err, &ve) {
		return ve.Code
	}
	return "ERR_UNKNOWN"
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func cmdVerifyBatch(args []string) int {
	fs := flag.NewFlagSet("verify-batch", flag.ExitOnError)
	policyPath := fs.String("policy", "", "path to policy.json")
	fixturePath := fs.String("fixture", "", "path to fixture JSON")
	_ = fs.Parse(args)

	policy, err := receipt.LoadPolicy(*policyPath)
	if err != nil {
		printJSON(map[string]any{"ok": false, "error_code": errorCode(err), "error": err.Error()})
		return 1
	}
	raw, err := os.ReadFile(*fixturePath)
	if err != nil {
		printJSON(map[string]any{"ok": false, "error_code": "ERR_INVALID_JSON", "error": err.Error()})
		return 1
	}
	parsed, err := receipt.ParseStrictJSON(raw)
	if err != nil {
		printJSON(map[string]any{"ok": false, "error_code": errorCode(err), "error": err.Error()})
		return 1
	}

	var jobs []any
	switch v := parsed.(type) {
	case map[string]any:
		arr, ok := v["jobs"].([]any)
		if !ok {
			printJSON(map[string]any{"ok": false, "error_code": "ERR_SCHEMA_VIOLATION", "error": "fixture object missing jobs array"})
			return 1
		}
		jobs = arr
	case []any:
		jobs = v
	default:
		printJSON(map[string]any{"ok": false, "error_code": "ERR_SCHEMA_VIOLATION", "error": "fixture must be array or object with jobs"})
		return 1
	}

	start := time.Now()
	results, err := receipt.VerifyBatch(jobs, policy)
	elapsedMS := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		printJSON(map[string]any{"ok": false, "error_code": errorCode(err), "error": err.Error()})
		return 1
	}
	printJSON(map[string]any{
		"ok":             true,
		"implementation": "go-stdlib",
		"count":          len(results),
		"elapsed_ms":     elapsedMS,
		"receipts":       results,
	})
	return 0
}

func cmdVerifyOne(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	policyPath := fs.String("policy", "", "path to policy.json")
	receiptPath := fs.String("receipt", "", "path to receipt JSON")
	_ = fs.Parse(args)

	policy, err := receipt.LoadPolicy(*policyPath)
	if err != nil {
		printJSON(map[string]any{"ok": false, "error_code": errorCode(err), "error": err.Error()})
		return 1
	}
	raw, err := os.ReadFile(*receiptPath)
	if err != nil {
		printJSON(map[string]any{"ok": false, "error_code": "ERR_INVALID_JSON", "error": err.Error()})
		return 1
	}
	res, err := receipt.VerifyReceiptBytes(raw, policy)
	if err != nil {
		printJSON(map[string]any{"ok": false, "error_code": errorCode(err), "error": err.Error()})
		return 1
	}
	printJSON(map[string]any{
		"ok":                     true,
		"implementation":         "go-stdlib",
		"job_id":                 res.JobID,
		"canonical_receipt_hash": res.CanonicalReceiptHash,
		"provenance_root":        res.ProvenanceRoot,
		"valid_attestations":     res.ValidAttestationCount,
	})
	return 0
}

type adversarialSuiteFile struct {
	Cases []struct {
		CaseID            string            `json:"case_id"`
		Kind              string            `json:"kind"`
		ExpectedErrorCode string            `json:"expected_error_code"`
		RawJSON           string            `json:"raw_json,omitempty"`
		Receipt           json.RawMessage   `json:"receipt,omitempty"`
		Receipts          []json.RawMessage `json:"receipts,omitempty"`
	} `json:"cases"`
}

func cmdVerifyAdversarial(args []string) int {
	fs := flag.NewFlagSet("verify-adversarial", flag.ExitOnError)
	policyPath := fs.String("policy", "", "path to policy.json")
	suitePath := fs.String("suite", "", "path to adversarial_suite.json")
	_ = fs.Parse(args)

	policy, err := receipt.LoadPolicy(*policyPath)
	if err != nil {
		printJSON(map[string]any{"ok": false, "error_code": errorCode(err), "error": err.Error()})
		return 1
	}
	raw, err := os.ReadFile(*suitePath)
	if err != nil {
		printJSON(map[string]any{"ok": false, "error_code": "ERR_INVALID_JSON", "error": err.Error()})
		return 1
	}
	var suite adversarialSuiteFile
	if err := json.Unmarshal(raw, &suite); err != nil {
		printJSON(map[string]any{"ok": false, "error_code": "ERR_INVALID_JSON", "error": err.Error()})
		return 1
	}

	passed := 0
	report := make([]map[string]any, 0, len(suite.Cases))
	for _, c := range suite.Cases {
		var actual string
		switch c.Kind {
		case "raw_json":
			_, err := receipt.VerifyReceiptBytes([]byte(c.RawJSON), policy)
			if err != nil {
				actual = errorCode(err)
			}
		case "batch":
			parsedList := make([]any, 0, len(c.Receipts))
			var parseErr error
			for _, rm := range c.Receipts {
				p, pe := receipt.ParseStrictJSON(rm)
				if pe != nil {
					parseErr = pe
					break
				}
				parsedList = append(parsedList, p)
			}
			if parseErr != nil {
				actual = errorCode(parseErr)
			} else {
				_, err := receipt.VerifyBatch(parsedList, policy)
				if err != nil {
					actual = errorCode(err)
				}
			}
		default:
			_, err := receipt.VerifyReceiptBytes(c.Receipt, policy)
			if err != nil {
				actual = errorCode(err)
			}
		}
		ok := actual == c.ExpectedErrorCode
		if ok {
			passed++
		}
		report = append(report, map[string]any{
			"case_id":              c.CaseID,
			"expected":             c.ExpectedErrorCode,
			"actual":               actual,
			"rejected_as_expected": ok,
		})
	}
	allOK := passed == len(suite.Cases)
	printJSON(map[string]any{
		"ok":             allOK,
		"implementation": "go-stdlib",
		"total":          len(suite.Cases),
		"passed":         passed,
		"cases":          report,
	})
	if !allOK {
		return 1
	}
	return 0
}

func cmdBench(args []string) int {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	policyPath := fs.String("policy", "", "path to policy.json")
	fixturePath := fs.String("fixture", "", "path to fixture JSON")
	iterations := fs.Int("iterations", 10, "benchmark iterations over fixture")
	_ = fs.Parse(args)

	policy, err := receipt.LoadPolicy(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	raw, err := os.ReadFile(*fixturePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	parsed, err := receipt.ParseStrictJSON(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	jobs := parsed.(map[string]any)["jobs"].([]any)

	// Measure canonical encoding + provenance construction + full verification independently.
	canonTimesUS := make([]float64, 0, *iterations)
	provTimesUS := make([]float64, 0, *iterations)
	verifyTimesUS := make([]float64, 0, *iterations)

	for iter := 0; iter < *iterations; iter++ {
		t0 := time.Now()
		for _, item := range jobs {
			if _, err := receipt.CanonicalReceiptHash(item.(map[string]any)); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				return 1
			}
		}
		canonTimesUS = append(canonTimesUS, float64(time.Since(t0).Nanoseconds())/1000.0)

		t1 := time.Now()
		for _, item := range jobs {
			if _, err := receipt.ComputeProvenance(item.(map[string]any)); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				return 1
			}
		}
		provTimesUS = append(provTimesUS, float64(time.Since(t1).Nanoseconds())/1000.0)

		t2 := time.Now()
		if _, err := receipt.VerifyBatch(jobs, policy); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		verifyTimesUS = append(verifyTimesUS, float64(time.Since(t2).Nanoseconds())/1000.0)
	}

	printJSON(map[string]any{
		"implementation":   "go-stdlib",
		"job_count":        len(jobs),
		"iterations":       *iterations,
		"canonical_hash_us": canonTimesUS,
		"provenance_us":    provTimesUS,
		"full_verify_us":   verifyTimesUS,
	})
	return 0
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: tc-verify <verify-batch|verify|verify-adversarial|bench> [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "verify-batch":
		os.Exit(cmdVerifyBatch(os.Args[2:]))
	case "verify":
		os.Exit(cmdVerifyOne(os.Args[2:]))
	case "verify-adversarial":
		os.Exit(cmdVerifyAdversarial(os.Args[2:]))
	case "bench":
		os.Exit(cmdBench(os.Args[2:]))
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(2)
	}
}

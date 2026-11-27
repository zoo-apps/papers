// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zoo-apps/papers/zoo-research-coordination/reference/go/feda2a"
)

func main() {
	seed := flag.Int64("seed", feda2a.DefaultSeed, "Deterministic seed for federated-a2a.v1 exchange suite")
	fixtureOut := flag.String("fixture-out", "../fixtures/a2a-exchange-suite.v1.json", "Output path for generated live exchange suite fixture")
	resultsOut := flag.String("results-out", "../results.json", "Output path for machine-readable benchmark results")
	flag.Parse()

	suite, sseCount, egressBlocks, err := feda2a.RunLiveExchangeSuite(*seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "live two-deployment exchange failed: %v\n", err)
		os.Exit(1)
	}

	report := feda2a.VerifySuite(suite)
	if !report.AllStagesValid || !report.AllAdversarialPass || !report.WireAudit.ZeroBoundaryLeakage {
		fmt.Fprintf(os.Stderr, "suite self-verification failed: stages=%t adv=%t zero_leak=%t\n",
			report.AllStagesValid, report.AllAdversarialPass, report.WireAudit.ZeroBoundaryLeakage)
		os.Exit(1)
	}

	httpBench, err := feda2a.RunLiveHTTPBenchmarks(*seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "live HTTP benchmarks failed: %v\n", err)
		os.Exit(1)
	}

	var stagesPassed int64
	for _, s := range report.StageOutcomes {
		if s.Valid {
			stagesPassed++
		}
	}

	results := feda2a.BenchmarkResults{
		SchemaVersion:      feda2a.SchemaVersion,
		SpecVersion:        feda2a.SpecVersion,
		Seed:               *seed,
		AuditMerkleRoot:    report.AuditMerkleRoot,
		WireTranscriptRoot: report.WireAudit.WireTranscriptRoot,
		TotalWireFrames:    report.WireAudit.TotalFrames,
		TotalWireBytes:     report.WireAudit.TotalWireBytes,
		CredentialLeaks:    report.WireAudit.CredentialLeakBytes,
		PrivateMemLeaks:    report.WireAudit.PrivateMemoryLeakBytes,
		RawTraceLeaks:      report.WireAudit.RawTraceLeakBytes,
		LiveStagesPassed:   stagesPassed,
		LiveStagesTotal:    int64(len(report.StageOutcomes)),
		AttacksDetected:    report.AttacksDetected,
		AttacksTotal:       report.AttacksTotal,
		PositiveCasesPass:  report.PositiveCasesPass,
		LiveSSEEventsCount: sseCount,
		EgressBlocksCount:  egressBlocks,
		LiveHTTPBenchmarks: httpBench,
		VerificationReport: report,
	}

	if err := os.MkdirAll(filepath.Dir(*fixtureOut), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir fixture dir failed: %v\n", err)
		os.Exit(1)
	}
	fixtureJSON, err := json.MarshalIndent(suite, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal fixture failed: %v\n", err)
		os.Exit(1)
	}
	fixtureJSON = append(fixtureJSON, '\n')
	if err := os.WriteFile(*fixtureOut, fixtureJSON, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write fixture failed: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(filepath.Dir(*resultsOut), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir results dir failed: %v\n", err)
		os.Exit(1)
	}
	resultsJSON, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal results failed: %v\n", err)
		os.Exit(1)
	}
	resultsJSON = append(resultsJSON, '\n')
	if err := os.WriteFile(*resultsOut, resultsJSON, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write results failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("federated-a2a.v1 live benchmark complete (seed=%d)\n", *seed)
	fmt.Printf("  audit_merkle_root    : %s\n", results.AuditMerkleRoot)
	fmt.Printf("  wire_transcript_root : %s\n", results.WireTranscriptRoot)
	fmt.Printf("  wire_frames / bytes  : %d frames / %d bytes (0 cred leaks, 0 priv mem leaks, 0 raw trace leaks)\n",
		results.TotalWireFrames, results.TotalWireBytes)
	fmt.Printf("  live_stages          : %d/%d PASS (SSE events=%d, live egress blocks=%d)\n",
		results.LiveStagesPassed, results.LiveStagesTotal, results.LiveSSEEventsCount, results.EgressBlocksCount)
	fmt.Printf("  adversarial_matrix   : %d/%d attacks caught + %d/1 positive AI advisory\n",
		results.AttacksDetected, results.AttacksTotal, results.PositiveCasesPass)
	for _, row := range results.LiveHTTPBenchmarks {
		fmt.Printf("  http_bench n=%3d (%5d B): passthrough=%4d us (%5d tps) | full_boundary=%4d us (%5d tps) | overhead=%.2fx [%s]\n",
			row.PayloadSamples, row.PayloadBytes, row.PassthroughMedianUs, row.PassthroughTPS,
			row.FullBoundaryMedUs, row.FullBoundaryTPS, float64(row.OverheadBps)/10000.0, row.Regime)
	}
}

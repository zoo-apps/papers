// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation & Open ResearchDAO Contributors.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/zoo-apps/papers/zoo-dao-operating-system/reference/go/internal/daoos"
)

func main() {
	var (
		seed       int64
		papersRoot string
		outPath    string
		exportWAL  string
		verifyWAL  string
	)
	flag.Int64Var(&seed, "seed", 1352, "deterministic PRNG/keygen seed")
	flag.StringVar(&papersRoot, "papers-root", "../../..", "path to zoo-apps/papers root directory")
	flag.StringVar(&outPath, "out", "", "optional path to write JSON benchmark results")
	flag.StringVar(&exportWAL, "export-wal", "", "optional directory to export genesis.json, events.jsonl, and checkpoints for cross-language verification")
	flag.StringVar(&verifyWAL, "verify-wal", "", "optional WAL directory to cold-replay and print state_root_hash & audit_merkle_root")
	flag.Parse()

	if verifyWAL != "" {
		mFull, err := daoos.ReplayFull(verifyWAL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "full replay failed: %v\n", err)
			os.Exit(1)
		}
		srFull, arFull, err := mFull.Roots()
		if err != nil {
			fmt.Fprintf(os.Stderr, "roots failed: %v\n", err)
			os.Exit(1)
		}
		mDelta, cpSeq, err := daoos.ReplayFromLatestCheckpoint(verifyWAL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "checkpoint replay failed: %v\n", err)
			os.Exit(1)
		}
		srDelta, arDelta, err := mDelta.Roots()
		if err != nil {
			fmt.Fprintf(os.Stderr, "delta roots failed: %v\n", err)
			os.Exit(1)
		}
		summary := map[string]any{
			"spec_version":             daoos.SpecVersion,
			"total_events":             mFull.NextSeq() - 1,
			"checkpoint_seq":           cpSeq,
			"full_state_root_hash":     srFull,
			"delta_state_root_hash":    srDelta,
			"full_audit_merkle_root":   arFull,
			"delta_audit_merkle_root":  arDelta,
			"bit_identical":            srFull == srDelta && arFull == arDelta,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(summary)
		if srFull != srDelta || arFull != arDelta {
			os.Exit(2)
		}
		return
	}

	report, err := daoos.RunFullBenchmark(papersRoot, seed, exportWAL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchmark failed: %v\n", err)
		os.Exit(1)
	}

	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal report: %v\n", err)
		os.Exit(1)
	}
	raw = append(raw, '\n')

	if outPath != "" {
		if err := os.WriteFile(outPath, raw, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", outPath, err)
			os.Exit(1)
		}
	}
	fmt.Printf("ResearchDAO OS v1 Benchmark (seed=%d)\n", report.Seed)
	fmt.Printf("  Papers grounded:     %d\n", report.PapersDiscovered)
	fmt.Printf("  Proposals executed:  %d (accepted=%d, vetoed=%d)\n", report.ProposalsExecuted, report.AcceptedProposals, report.VetoedProposals)
	fmt.Printf("  Total signed events: %d (%.1f events/s, wall=%dms)\n", report.TotalEvents, report.ThroughputEventsS, report.LifecycleWallMs)
	fmt.Printf("  Cold restarts:       %d/3 bit-identical\n", len(report.ColdRestarts))
	fmt.Printf("  Adversarial matrix:  %d/%d rejected cleanly\n", report.AdversarialBlocked, report.AdversarialTotal)
	fmt.Printf("  state_root_hash:     %s\n", report.FinalStateRootHash)
	fmt.Printf("  audit_merkle_root:   %s\n", report.FinalAuditMerkle)
}

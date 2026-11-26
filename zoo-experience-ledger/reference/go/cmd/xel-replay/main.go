// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"

	"github.com/zoo-apps/papers/zoo-experience-ledger/reference/go/ledger"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)

	switch cmd {
	case "replay":
		bundlePath := fs.String("bundle", "", "Path to LedgerBundle JSON file")
		outPath := fs.String("out", "", "Optional output path for ReconstructedState JSON")
		_ = fs.Parse(os.Args[2:])
		if *bundlePath == "" {
			fatalf("missing --bundle")
		}
		b := mustLoadBundle(*bundlePath)
		state, err := ledger.Replay(b.Policy, b.Events)
		if err != nil {
			fatalf("replay failed: %v", err)
		}
		enc, _ := json.MarshalIndent(state, "", "  ")
		if *outPath != "" {
			if err := os.WriteFile(*outPath, append(enc, '\n'), 0o644); err != nil {
				fatalf("write output: %v", err)
			}
		} else {
			fmt.Println(string(enc))
		}

	case "permute-check":
		bundlePath := fs.String("bundle", "", "Path to LedgerBundle JSON file")
		perms := fs.Int("perms", 20, "Number of random permutations to test in addition to forward and reverse")
		seed := fs.Int64("seed", 1352, "PRNG seed for permutations")
		_ = fs.Parse(os.Args[2:])
		if *bundlePath == "" {
			fatalf("missing --bundle")
		}
		b := mustLoadBundle(*bundlePath)
		base, err := ledger.Replay(b.Policy, b.Events)
		if err != nil {
			fatalf("forward replay failed: %v", err)
		}

		// Reverse order
		rev := make([]ledger.Event, len(b.Events))
		for i := range b.Events {
			rev[i] = b.Events[len(b.Events)-1-i]
		}
		revState, err := ledger.Replay(b.Policy, rev)
		if err != nil {
			fatalf("reverse replay failed: %v", err)
		}
		if revState.StateRootHash != base.StateRootHash {
			fatalf("DIVERGENCE on reverse order: %s != %s", revState.StateRootHash, base.StateRootHash)
		}

		// Random permutations
		rng := rand.New(rand.NewSource(*seed))
		for p := 0; p < *perms; p++ {
			shuf := make([]ledger.Event, len(b.Events))
			copy(shuf, b.Events)
			rng.Shuffle(len(shuf), func(i, j int) { shuf[i], shuf[j] = shuf[j], shuf[i] })
			st, err := ledger.Replay(b.Policy, shuf)
			if err != nil {
				fatalf("perm %d replay failed: %v", p, err)
			}
			if st.StateRootHash != base.StateRootHash {
				fatalf("DIVERGENCE on perm %d: %s != %s", p, st.StateRootHash, base.StateRootHash)
			}
		}

		summary := map[string]any{
			"status":             "CONVERGED",
			"permutations_tested": *perms + 2,
			"state_root_hash":    base.StateRootHash,
			"active_merkle_root": base.Commitment.ActiveMerkleRoot,
			"active_entries":     len(base.ActiveEventIDs),
			"total_entries":      len(base.Commitment.EntryStates),
			"conflicts":          len(base.Commitment.Conflicts),
			"rejected_events":    len(base.Commitment.RejectedEvents),
		}
		out, _ := json.MarshalIndent(summary, "", "  ")
		fmt.Println(string(out))

	default:
		usage()
		os.Exit(2)
	}
}

func mustLoadBundle(path string) ledger.LedgerBundle {
	raw, err := os.ReadFile(path)
	if err != nil {
		fatalf("read bundle %s: %v", path, err)
	}
	var b ledger.LedgerBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		fatalf("parse bundle %s: %v", path, err)
	}
	return b
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: xel-replay <replay|permute-check> --bundle <path> [--perms 20] [--seed 1352]")
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

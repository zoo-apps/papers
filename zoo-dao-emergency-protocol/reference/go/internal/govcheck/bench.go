// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package govcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
)

// InspectRegoBundle hashes all .rego files in regoDir in canonical sorted order
// and reports whether the `opa` CLI binary is installed in PATH.
func InspectRegoBundle(regoDir string) (RegoBundleReport, error) {
	entries, err := os.ReadDir(regoDir)
	if err != nil {
		return RegoBundleReport{}, fmt.Errorf("read rego dir: %w", err)
	}
	files := make([]string, 0)
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".rego" {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	h := sha256.New()
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(regoDir, f))
		if err != nil {
			return RegoBundleReport{}, err
		}
		h.Write([]byte(f))
		h.Write([]byte{0x00})
		h.Write(data)
		h.Write([]byte{0x00})
	}
	_, lookErr := exec.LookPath("opa")
	return RegoBundleReport{
		RegoVersion:     "v1",
		Files:           files,
		OPACLIAvailable: lookErr == nil,
		BundleSHA256:    hex.EncodeToString(h.Sum(nil)),
	}, nil
}

// RunFullBenchmark runs the complete deterministic constitutional-gov.v1 suite
// for the given seed and rego bundle directory.
func RunFullBenchmark(seed int64, regoDir string) (BenchmarkResults, error) {
	adv := BuildAdversarialSuite(seed)
	mc := RunModelChecker(seed)
	mut := RunMutationAudit(seed)
	neg := RunNegativeRegimes(seed)

	regoRep, err := InspectRegoBundle(regoDir)
	if err != nil {
		return BenchmarkResults{}, err
	}

	root, err := AuditMerkleRoot(adv.Cases)
	if err != nil {
		return BenchmarkResults{}, err
	}

	return BenchmarkResults{
		SchemaVersion:    SchemaVersion,
		SpecVersion:      SpecVersion,
		Seed:             seed,
		Constants:        DefaultConstants(),
		AdversarialSuite: adv,
		ModelChecker:     mc,
		MutationAudit:    mut,
		NegativeRegimes:  neg,
		RegoBundle:       regoRep,
		AuditMerkleRoot:  root,
	}, nil
}

// SPDX-License-Identifier: Apache-2.0

package qfsim

import (
	"fmt"
	"sort"
)

// RunFullBenchmark executes all 15 scenarios across all 6 allocation mechanisms,
// runs the HIP-1352 constitutional governance audit, and computes the canonical
// SHA-256 audit Merkle root.
func RunFullBenchmark(papersRoot string, seed int64) (BenchmarkReport, error) {
	corpus, err := LoadGrantCorpus(papersRoot)
	if err != nil {
		return BenchmarkReport{}, err
	}
	corpusHash := HashCorpus(corpus)

	govChecks := StandardConstitutionalAuditSuite()
	govHash := HashGovernanceChecks(govChecks)

	scenarios := BuildBenchmarkScenarios(seed, corpus)
	mechs := AllMechanisms()

	evals := make([]EvaluationResult, 0, len(scenarios)*len(mechs))
	for _, sc := range scenarios {
		for _, m := range mechs {
			ev, err := EvaluateMechanism(sc, m)
			if err != nil {
				return BenchmarkReport{}, fmt.Errorf("evaluate scenario=%s mech=%s: %w", sc.ID, m, err)
			}
			if !ev.Metrics.PoolConserved {
				return BenchmarkReport{}, fmt.Errorf("pool conservation violated for scenario=%s mech=%s", sc.ID, m)
			}
			evals = append(evals, ev)
		}
	}

	// Deterministic ordering of evaluation leaves by (scenario_id ASC, mechanism_id ASC) for Merkle root.
	orderedLeaves := make([]EvaluationResult, len(evals))
	copy(orderedLeaves, evals)
	sort.Slice(orderedLeaves, func(i, j int) bool {
		if orderedLeaves[i].ScenarioID != orderedLeaves[j].ScenarioID {
			return orderedLeaves[i].ScenarioID < orderedLeaves[j].ScenarioID
		}
		return orderedLeaves[i].MechanismID < orderedLeaves[j].MechanismID
	})
	leafHashes := make([]string, len(orderedLeaves))
	for i, ev := range orderedLeaves {
		leafHashes[i] = ev.LeafHash
	}

	evalMerkleRoot := ComputeMerkleRoot(leafHashes)
	auditMerkleRoot := ComputeAuditMerkleRoot(corpusHash, evalMerkleRoot, govHash)

	return BenchmarkReport{
		SpecVersion:       SpecVersion,
		Seed:              seed,
		MatchingPoolMicro: DefaultMatchingPool,
		CorpusHash:        corpusHash,
		GovernanceHash:    govHash,
		EvalMerkleRoot:    evalMerkleRoot,
		AuditMerkleRoot:   auditMerkleRoot,
		CorpusProposals:   corpus,
		GovernanceChecks:  govChecks,
		Scenarios:         scenarios,
		Evaluations:       evals,
	}, nil
}

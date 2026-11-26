// SPDX-License-Identifier: Apache-2.0

package qfsim

import (
	"math/big"
	"sort"
)

// ComputeGiniBPS computes the exact discrete Gini coefficient in basis points [0, 10000]
// over non-negative integer values using big.Int to avoid overflow.
func ComputeGiniBPS(values []int64) int64 {
	n := len(values)
	if n <= 1 {
		return 0
	}
	sorted := make([]int64, n)
	copy(sorted, values)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	total := big.NewInt(0)
	weighted := big.NewInt(0)
	for i, v := range sorted {
		bv := big.NewInt(v)
		total.Add(total, bv)
		// coeff = 2*(i+1) - n - 1
		coeff := int64(2*(i+1) - n - 1)
		weighted.Add(weighted, new(big.Int).Mul(big.NewInt(coeff), bv))
	}
	if total.Sign() == 0 {
		return 0
	}
	num := new(big.Int).Mul(weighted, bigBPS)
	den := new(big.Int).Mul(big.NewInt(int64(n)), total)
	if num.Sign() < 0 {
		return 0
	}
	return new(big.Int).Quo(num, den).Int64()
}

// ComputeMetrics computes all exact integer-scaled evaluation metrics for a round.
func ComputeMetrics(
	sc ScenarioSpec,
	proposals []GrantProposal,
	allocs []ProjectAllocation,
	unallocated int64,
) EvaluationMetrics {
	var (
		totalMatched     int64
		attackerMatch    int64
		grassrootsMatch  int64
		minorityMatch    int64
		labMatch         int64
		newcomerMatch    int64
		whaleNicheMatch  int64
	)
	meritWeightedNum := big.NewInt(0)
	honestMatches := make([]int64, 0, len(proposals))

	for i, p := range proposals {
		m := allocs[i].MatchMicro
		totalMatched += m
		meritWeightedNum.Add(meritWeightedNum, new(big.Int).Mul(big.NewInt(m), big.NewInt(p.MeritBPS)))

		if p.IsAttackerTarget {
			attackerMatch += m
		} else {
			honestMatches = append(honestMatches, m)
		}
		if p.Archetype == ArchetypeBroadPublicGood || p.Archetype == ArchetypeGrassrootsMinor {
			grassrootsMatch += m
		}
		if p.Archetype == ArchetypeGrassrootsMinor {
			minorityMatch += m
		}
		if p.IsLabGrant {
			labMatch += m
		}
		if p.IsNewcomerGrant {
			newcomerMatch += m
		}
		if p.Archetype == ArchetypeWhaleNiche {
			whaleNicheMatch += m
		}
	}

	pool := sc.MatchingPool
	poolConserved := (totalMatched+unallocated == pool) && totalMatched >= 0 && unallocated >= 0

	var extractionBPS int64
	var directROIBPS int64
	var netROIBPS int64
	if pool > 0 {
		extractionBPS = (attackerMatch * BPS) / pool
	}
	if sc.AttackModel.DirectBudgetMicro > 0 {
		directROIBPS = new(big.Int).Quo(
			new(big.Int).Mul(big.NewInt(attackerMatch), bigBPS),
			big.NewInt(sc.AttackModel.DirectBudgetMicro),
		).Int64()
	}
	if sc.AttackModel.TotalAttackCostMicro > 0 {
		netROIBPS = new(big.Int).Quo(
			new(big.Int).Mul(big.NewInt(attackerMatch), bigBPS),
			big.NewInt(sc.AttackModel.TotalAttackCostMicro),
		).Int64()
	}

	var meritWelfareBPS int64
	if pool > 0 {
		meritWelfareBPS = new(big.Int).Quo(meritWeightedNum, big.NewInt(pool)).Int64()
	}

	return EvaluationMetrics{
		PoolConserved:        poolConserved,
		TotalMatchedMicro:    totalMatched,
		UnallocatedPoolMicro: unallocated,
		AttackerMatchMicro:   attackerMatch,
		PoolExtractionBPS:    extractionBPS,
		DirectCostROIBPS:     directROIBPS,
		NetAttackROIBPS:      netROIBPS,
		MeritWelfareBPS:      meritWelfareBPS,
		GrassrootsShareBPS:   (grassrootsMatch * BPS) / pool,
		MinorityShareBPS:     (minorityMatch * BPS) / pool,
		HonestGiniBPS:        ComputeGiniBPS(honestMatches),
		LabShareBPS:          (labMatch * BPS) / pool,
		NewcomerShareBPS:     (newcomerMatch * BPS) / pool,
		WhaleNicheShareBPS:   (whaleNicheMatch * BPS) / pool,
	}
}

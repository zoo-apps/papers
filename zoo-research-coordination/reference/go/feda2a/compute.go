// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package feda2a

import (
	"fmt"
	"math/big"
)

// truncDiv computes integer quotient truncated toward zero (matches Go big.Int.Quo
// and Python symmetric trunc_div(a, b) = (abs(a)//abs(b)) * sign).
func truncDiv(num, den *big.Int) *big.Int {
	if den.Sign() == 0 {
		return big.NewInt(0)
	}
	return new(big.Int).Quo(num, den)
}

func absInt64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// RunDeterministicZHL executes a ZooCoord ZHL scientific experiment ("COMPARE" or
// "CORRELATE") using exact arbitrary-precision fixed-point arithmetic (MICRO = 1e6).
// Both executing and requesting organizations run this exact deterministic kernel so
// scientific claims can be independently verified bit-for-bit.
func RunDeterministicZHL(taskID string, c ExperimentCommitment) (ScientificResult, error) {
	nA := len(c.GroupAMicro)
	nB := len(c.GroupBMicro)
	if nA < 2 || nB < 2 {
		return ScientificResult{}, fmt.Errorf("insufficient samples: group_a=%d group_b=%d", nA, nB)
	}
	if c.ZHLTemplate == "CORRELATE" && nA != nB {
		return ScientificResult{}, fmt.Errorf("CORRELATE requires equal lengths: %d != %d", nA, nB)
	}

	micro := big.NewInt(MicroScale)

	sumA := big.NewInt(0)
	for _, v := range c.GroupAMicro {
		sumA.Add(sumA, big.NewInt(v))
	}
	meanA := truncDiv(sumA, big.NewInt(int64(nA))).Int64()

	sumB := big.NewInt(0)
	for _, v := range c.GroupBMicro {
		sumB.Add(sumB, big.NewInt(v))
	}
	meanB := truncDiv(sumB, big.NewInt(int64(nB))).Int64()

	ssA := big.NewInt(0)
	for _, v := range c.GroupAMicro {
		d := big.NewInt(v - meanA)
		ssA.Add(ssA, new(big.Int).Mul(d, d))
	}
	varA := truncDiv(ssA, new(big.Int).Mul(big.NewInt(int64(nA)), micro)).Int64()

	ssB := big.NewInt(0)
	for _, v := range c.GroupBMicro {
		d := big.NewInt(v - meanB)
		ssB.Add(ssB, new(big.Int).Mul(d, d))
	}
	varB := truncDiv(ssB, new(big.Int).Mul(big.NewInt(int64(nB)), micro)).Int64()

	var effectMicro int64
	var statMicro int64
	var significant bool
	var summary string
	var sampleCount int64

	switch c.ZHLTemplate {
	case "COMPARE":
		sampleCount = int64(nA + nB)
		effectMicro = meanB - meanA
		// SE^2_micro = (varA / nA + varB / nB) * MicroScale -> SE = isqrt(SE^2_micro)
		termA := truncDiv(new(big.Int).Mul(big.NewInt(varA), micro), big.NewInt(int64(nA)))
		termB := truncDiv(new(big.Int).Mul(big.NewInt(varB), micro), big.NewInt(int64(nB)))
		seSq := new(big.Int).Add(termA, termB)
		se := new(big.Int).Sqrt(seSq)
		if se.Sign() <= 0 {
			se = big.NewInt(1)
		}
		statMicro = truncDiv(new(big.Int).Mul(big.NewInt(effectMicro), micro), se).Int64()
		significant = absInt64(effectMicro) >= c.MinEffectMicro && absInt64(statMicro) >= 2*MicroScale
		summary = fmt.Sprintf("ZHL COMPARE deterministic verification: n=%d effect_micro=%d stat_micro=%d significant=%t",
			sampleCount, effectMicro, statMicro, significant)

	case "CORRELATE":
		sampleCount = int64(nA)
		cov := big.NewInt(0)
		for i := 0; i < nA; i++ {
			da := big.NewInt(c.GroupAMicro[i] - meanA)
			db := big.NewInt(c.GroupBMicro[i] - meanB)
			cov.Add(cov, new(big.Int).Mul(da, db))
		}
		denSq := new(big.Int).Mul(ssA, ssB)
		den := new(big.Int).Sqrt(denSq)
		if den.Sign() > 0 {
			effectMicro = truncDiv(new(big.Int).Mul(cov, micro), den).Int64()
		}
		statMicro = absInt64(effectMicro)
		significant = statMicro >= c.MinEffectMicro
		summary = fmt.Sprintf("ZHL CORRELATE deterministic verification: n=%d r_micro=%d significant=%t",
			sampleCount, effectMicro, significant)

	default:
		return ScientificResult{}, fmt.Errorf("unsupported ZHL template: %s", c.ZHLTemplate)
	}

	commitHash := c.CommitmentHash
	if commitHash == "" {
		commitHash = ComputeCommitmentHash(c)
	}
	res := ScientificResult{
		TaskID:          taskID,
		CommitmentHash:  commitHash,
		ZHLTemplate:     c.ZHLTemplate,
		SampleCount:     sampleCount,
		MeanAMicro:      meanA,
		MeanBMicro:      meanB,
		VarAMicro:       varA,
		VarBMicro:       varB,
		EffectSizeMicro: effectMicro,
		StatMicro:       statMicro,
		Significant:     significant,
		OutputTier:      TierSharedExchange,
		SummaryNote:     summary,
	}
	res.ResultHash = ComputeScientificResultHash(res)
	return res, nil
}

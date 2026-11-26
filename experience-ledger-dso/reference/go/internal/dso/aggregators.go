// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation

package dso

import (
	"fmt"
	"math"
	"sort"
	"time"
)

type coordPair struct {
	val float64
	idx int
}

type scorePair struct {
	score float64
	idx   int
}

// AggregateRound executes one of the 5 benchmarked aggregation rules over N signed contributions.
// It always verifies RFC 8032 Ed25519 signatures first and reports exact verification timing.
func AggregateRound(
	aggregator string,
	envelopes []ContributionEnvelope,
	baseModel [FeatureDim]float64,
	reputations []float64,
	valProto []Example,
	valCons []Example,
	cfg AggregationConfig,
) AggregationResult {
	startTime := time.Now()
	n := len(envelopes)
	res := AggregationResult{
		Aggregator:    aggregator,
		Weights:       make([]float64, n),
		Accepted:      make([]bool, n),
		RejectReasons: make([]string, n),
		ClusterSizes:  make([]int, n),
	}

	// Step 0: Cryptographic Ed25519 verification + decode micro deltas.
	validIndices := make([]int, 0, n)
	deltas := make([][FeatureDim]float64, n)
	for i, env := range envelopes {
		res.ClusterSizes[i] = 1
		if err := VerifyContribution(env); err != nil {
			res.InvalidSigCount++
			res.RejectReasons[i] = err.Error()
			continue
		}
		vec, err := VecFromMicro(env.Body.DeltaMicro)
		if err != nil {
			res.InvalidSchemaCnt++
			res.RejectReasons[i] = "ERR_INVALID_DELTA_DIM"
			continue
		}
		deltas[i] = vec
		validIndices = append(validIndices, i)
	}

	mValid := len(validIndices)
	if mValid == 0 {
		res.AggDeltaMicro = VecToMicro(res.AggregatedDelta)
		res.WeightsMicro = SliceToMicro(res.Weights)
		res.DurationMs = float64(time.Since(startTime).Microseconds()) / 1000.0
		return res
	}

	switch aggregator {
	case AggMeanBaseline:
		aggregateMean(&res, validIndices, deltas)
	case AggCoordMedian:
		aggregateCoordMedian(&res, validIndices, deltas, cfg)
	case AggTrimmedMean:
		aggregateTrimmedMean(&res, validIndices, deltas, cfg)
	case AggMultiKrum:
		aggregateMultiKrum(&res, validIndices, deltas, cfg)
	case AggDSOReputationEvalGated:
		aggregateDSOReputationEvalGated(&res, envelopes, validIndices, deltas, baseModel, reputations, valProto, valCons, cfg)
	default:
		res.RejectReasons[0] = fmt.Sprintf("ERR_UNKNOWN_AGGREGATOR:%s", aggregator)
	}

	res.AggDeltaMicro = VecToMicro(res.AggregatedDelta)
	res.WeightsMicro = SliceToMicro(res.Weights)
	res.DurationMs = float64(time.Since(startTime).Microseconds()) / 1000.0
	return res
}

func aggregateMean(res *AggregationResult, valid []int, deltas [][FeatureDim]float64) {
	inv := 1.0 / float64(len(valid))
	for _, idx := range valid {
		res.Weights[idx] = inv
		res.Accepted[idx] = true
		for d := 0; d < FeatureDim; d++ {
			res.AggregatedDelta[d] += deltas[idx][d] * inv
		}
	}
}

func aggregateCoordMedian(res *AggregationResult, valid []int, deltas [][FeatureDim]float64, cfg AggregationConfig) {
	m := len(valid)
	n := len(deltas)
	survivedEnergy := make([]float64, n)
	totalEnergy := make([]float64, n)
	for _, idx := range valid {
		totalEnergy[idx] = Dot(deltas[idx], deltas[idx])
	}

	pairs := make([]coordPair, m)
	for d := 0; d < FeatureDim; d++ {
		for k, idx := range valid {
			pairs[k] = coordPair{val: deltas[idx][d], idx: idx}
		}
		sort.Slice(pairs, func(i, j int) bool {
			if pairs[i].val != pairs[j].val {
				return pairs[i].val < pairs[j].val
			}
			return pairs[i].idx < pairs[j].idx
		})

		var med float64
		if m%2 == 1 {
			med = pairs[m/2].val
		} else {
			med = 0.5 * (pairs[m/2-1].val + pairs[m/2].val)
		}
		res.AggregatedDelta[d] = med

		// Credit nodes in the central support band around the median whose active signal aligns with med.
		bandLo := (m * 3) / 10
		bandHi := m - 1 - bandLo
		if bandHi < bandLo {
			bandLo, bandHi = m/2, m/2
		}
		for r := bandLo; r <= bandHi; r++ {
			idx := pairs[r].idx
			v := pairs[r].val
			if v*med > 1e-12 {
				survivedEnergy[idx] += v * v
			}
		}
	}

	var sumRatio float64
	ratios := make([]float64, n)
	for _, idx := range valid {
		if totalEnergy[idx] > 1e-12 {
			r := survivedEnergy[idx] / totalEnergy[idx]
			if r > 1.0 {
				r = 1.0
			}
			ratios[idx] = r
			sumRatio += r
		}
	}
	acceptTh := cfg.AcceptanceWeightTh / float64(m)
	for _, idx := range valid {
		if sumRatio > 1e-12 {
			res.Weights[idx] = ratios[idx] / sumRatio
		}
		if res.Weights[idx] >= acceptTh {
			res.Accepted[idx] = true
		} else {
			res.RejectReasons[idx] = "FILTERED_OUT_BY_COORD_MEDIAN"
		}
	}
}

func aggregateTrimmedMean(res *AggregationResult, valid []int, deltas [][FeatureDim]float64, cfg AggregationConfig) {
	m := len(valid)
	n := len(deltas)
	kTrim := int(math.Floor(cfg.TrimBeta * float64(m)))
	if 2*kTrim >= m {
		kTrim = (m - 1) / 2
	}
	keptCount := m - 2*kTrim

	survivedEnergy := make([]float64, n)
	totalEnergy := make([]float64, n)
	for _, idx := range valid {
		totalEnergy[idx] = Dot(deltas[idx], deltas[idx])
	}

	pairs := make([]coordPair, m)
	for d := 0; d < FeatureDim; d++ {
		for p, idx := range valid {
			pairs[p] = coordPair{val: deltas[idx][d], idx: idx}
		}
		sort.Slice(pairs, func(i, j int) bool {
			if pairs[i].val != pairs[j].val {
				return pairs[i].val < pairs[j].val
			}
			return pairs[i].idx < pairs[j].idx
		})

		var sum float64
		for r := kTrim; r < m-kTrim; r++ {
			sum += pairs[r].val
		}
		meanVal := sum / float64(keptCount)
		res.AggregatedDelta[d] = meanVal

		for r := kTrim; r < m-kTrim; r++ {
			idx := pairs[r].idx
			v := pairs[r].val
			if v*meanVal > 1e-12 {
				survivedEnergy[idx] += v * v
			}
		}
	}

	var sumRatio float64
	ratios := make([]float64, n)
	for _, idx := range valid {
		if totalEnergy[idx] > 1e-12 {
			r := survivedEnergy[idx] / totalEnergy[idx]
			if r > 1.0 {
				r = 1.0
			}
			ratios[idx] = r
			sumRatio += r
		}
	}
	acceptTh := cfg.AcceptanceWeightTh / float64(m)
	for _, idx := range valid {
		if sumRatio > 1e-12 {
			res.Weights[idx] = ratios[idx] / sumRatio
		}
		if res.Weights[idx] >= acceptTh {
			res.Accepted[idx] = true
		} else {
			res.RejectReasons[idx] = "FILTERED_OUT_BY_TRIMMED_MEAN"
		}
	}
}

func aggregateMultiKrum(res *AggregationResult, valid []int, deltas [][FeatureDim]float64, cfg AggregationConfig) {
	m := len(valid)
	if m == 1 {
		idx := valid[0]
		res.AggregatedDelta = deltas[idx]
		res.Weights[idx] = 1.0
		res.Accepted[idx] = true
		return
	}

	// Neighbor count kNN = m - f_max - 2 (clamped to [1, m-1]).
	kNN := m - cfg.KrumAssumedByz - 2
	if kNN < 1 {
		kNN = 1
	}
	if kNN >= m {
		kNN = m - 1
	}

	selectM := cfg.KrumSelectM
	if selectM < 1 {
		selectM = 1
	}
	if selectM > m {
		selectM = m
	}

	scores := make([]scorePair, m)
	dists := make([]float64, m-1)
	for i, idxI := range valid {
		p := 0
		for j, idxJ := range valid {
			if i == j {
				continue
			}
			dists[p] = SquaredDist(deltas[idxI], deltas[idxJ])
			p++
		}
		sort.Float64s(dists)
		var sum float64
		for k := 0; k < kNN; k++ {
			sum += dists[k]
		}
		scores[i] = scorePair{score: sum, idx: idxI}
	}

	sort.Slice(scores, func(i, j int) bool {
		if scores[i].score != scores[j].score {
			return scores[i].score < scores[j].score
		}
		return scores[i].idx < scores[j].idx
	})

	selected := make(map[int]bool, selectM)
	inv := 1.0 / float64(selectM)
	for r := 0; r < selectM; r++ {
		idx := scores[r].idx
		selected[idx] = true
		res.Weights[idx] = inv
		res.Accepted[idx] = true
		for d := 0; d < FeatureDim; d++ {
			res.AggregatedDelta[d] += deltas[idx][d] * inv
		}
	}
	for _, idx := range valid {
		if !selected[idx] {
			res.RejectReasons[idx] = "REJECTED_BY_MULTI_KRUM_DISTANCE"
		}
	}
}

func aggregateDSOReputationEvalGated(
	res *AggregationResult,
	envelopes []ContributionEnvelope,
	valid []int,
	deltas [][FeatureDim]float64,
	baseModel [FeatureDim]float64,
	reputations []float64,
	valProto []Example,
	valCons []Example,
	cfg AggregationConfig,
) {
	_, baseLossProto := EvaluateLogistic(baseModel, valProto)
	_, baseLossCons := EvaluateLogistic(baseModel, valCons)

	admitted := make([]int, 0, len(valid))
	gains := make([]float64, len(envelopes))

	// Step 1: DSO semantic schema check + norm sanity + domain-stratified held-out eval + cross-domain safety.
	for _, idx := range valid {
		env := envelopes[idx]
		if err := ValidateExperienceSchema(env.Body.Experience); err != nil {
			res.InvalidSchemaCnt++
			res.RejectReasons[idx] = err.Error()
			continue
		}
		if L2Norm(deltas[idx]) > cfg.DSOMaxDeltaNorm {
			res.RejectReasons[idx] = "ERR_DELTA_NORM_EXCEEDED"
			continue
		}

		var probe [FeatureDim]float64
		for d := 0; d < FeatureDim; d++ {
			probe[d] = baseModel[d] + cfg.DSOEvalStep*deltas[idx][d]
		}
		_, candLossProto := EvaluateLogistic(probe, valProto)
		_, candLossCons := EvaluateLogistic(probe, valCons)

		gainProto := baseLossProto - candLossProto
		gainCons := baseLossCons - candLossCons

		var gainOwn, gainOther float64
		if env.Body.Domain == DomainConservation {
			gainOwn = gainCons
			gainOther = gainProto
		} else {
			gainOwn = gainProto
			gainOther = gainCons
		}

		if gainOwn <= cfg.DSOMinGain {
			res.RejectReasons[idx] = "ERR_INSUFFICIENT_HELD_OUT_GAIN"
			continue
		}
		if gainOther < -cfg.DSOSafetyTol {
			res.RejectReasons[idx] = "ERR_CROSS_DOMAIN_SAFETY_VIOLATION"
			continue
		}

		gains[idx] = gainOwn
		admitted = append(admitted, idx)
	}

	if len(admitted) == 0 {
		return
	}

	// Step 2: Pairwise cosine Sybil collusion-cluster discounting.
	// Any k near-identical updates (cos >= DSOClusterCos) each have weight divided by k.
	for _, idxI := range admitted {
		cSize := 1
		for _, idxJ := range admitted {
			if idxI == idxJ {
				continue
			}
			if CosineSimilarity(deltas[idxI], deltas[idxJ]) >= cfg.DSOClusterCos {
				cSize++
			}
		}
		res.ClusterSizes[idxI] = cSize
	}

	// Step 3: Reputation-weighted, cluster-discounted, domain-balanced attribution.
	rawScore := make([]float64, len(envelopes))
	var protoSum, consSum float64
	var protoIdx, consIdx []int
	for _, idx := range admitted {
		rep := 1.0
		if idx < len(reputations) && reputations[idx] > 0 {
			rep = reputations[idx]
		}
		// Concave gain scaling (sqrt) prevents a single large-step update from dominating honest peers.
		s := rep * math.Sqrt(math.Max(gains[idx], 1e-6)) / float64(res.ClusterSizes[idx])
		rawScore[idx] = s
		if envelopes[idx].Body.Domain == DomainConservation {
			consSum += s
			consIdx = append(consIdx, idx)
		} else {
			protoSum += s
			protoIdx = append(protoIdx, idx)
		}
	}

	protoShare, consShare := 0.0, 0.0
	switch {
	case len(protoIdx) > 0 && len(consIdx) > 0:
		total := protoSum + consSum
		naturalCons := consSum / total
		consShare = naturalCons
		if consShare < cfg.DSOMinorityFloor {
			consShare = cfg.DSOMinorityFloor
		}
		if consShare > 1.0-cfg.DSOMinorityFloor {
			consShare = 1.0 - cfg.DSOMinorityFloor
		}
		protoShare = 1.0 - consShare
	case len(protoIdx) > 0:
		protoShare = 1.0
	case len(consIdx) > 0:
		consShare = 1.0
	}

	for _, idx := range protoIdx {
		w := protoShare * (rawScore[idx] / protoSum)
		res.Weights[idx] = w
		res.Accepted[idx] = true
		for d := 0; d < FeatureDim; d++ {
			res.AggregatedDelta[d] += w * deltas[idx][d]
		}
	}
	for _, idx := range consIdx {
		w := consShare * (rawScore[idx] / consSum)
		res.Weights[idx] = w
		res.Accepted[idx] = true
		for d := 0; d < FeatureDim; d++ {
			res.AggregatedDelta[d] += w * deltas[idx][d]
		}
	}
}

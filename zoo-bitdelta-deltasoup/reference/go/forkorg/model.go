// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package forkorg

import (
	"encoding/hex"
	"fmt"
	"sort"
)

const (
	DefaultNumClasses  = int64(4)
	DefaultNumFeatures = int64(16)
	DefaultModelDim    = DefaultNumClasses * DefaultNumFeatures // 64
	DefaultMarginMicro = int64(1_000_000)
)

// SplitMix64 is a deterministic 64-bit PRNG producing bit-identical streams.
type SplitMix64 struct {
	state uint64
}

func NewSplitMix64(seed int64) *SplitMix64 {
	return &SplitMix64{state: uint64(seed)}
}

func (r *SplitMix64) NextUint64() uint64 {
	r.state += 0x9e3779b97f4a7c15
	z := r.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// NextRange returns a uniform int64 in [-bound, +bound].
func (r *SplitMix64) NextRange(bound int64) int64 {
	if bound <= 0 {
		return 0
	}
	span := uint64(2*bound + 1)
	return int64(r.NextUint64()%span) - bound
}

// NextIntN returns a uniform int64 in [0, n).
func (r *SplitMix64) NextIntN(n int64) int64 {
	if n <= 0 {
		return 0
	}
	return int64(r.NextUint64() % uint64(n))
}

// classPrototype returns the canonical feature center (in micro-units) for class c in [0..3].
// Features 0..11 encode class-distinct + overlapping signals, 12..14 encode safety alignment
// invariants, and feature 15 is the fixed bias term (+1.0).
func classPrototype(c int64) []int64 {
	p := make([]int64, DefaultNumFeatures)
	switch c {
	case 0:
		p[0], p[1], p[2], p[3] = 950_000, 820_000, 680_000, -350_000
		p[4], p[5] = -250_000, 180_000
		p[8], p[9] = -200_000, -150_000
		p[12], p[13], p[14] = 450_000, 300_000, 200_000
	case 1:
		p[0], p[1] = -300_000, 150_000
		p[3], p[4], p[5], p[6] = 750_000, 920_000, 780_000, -280_000
		p[9], p[10] = -220_000, -180_000
		p[12], p[13], p[14] = 380_000, 420_000, 220_000
	case 2:
		p[2], p[3] = -240_000, -190_000
		p[6], p[7], p[8], p[9] = 760_000, 940_000, 860_000, -260_000
		p[11] = 160_000
		p[12], p[13], p[14] = 320_000, 360_000, 460_000
	default: // class 3
		p[1], p[5] = -210_000, -230_000
		p[8], p[9], p[10], p[11] = -220_000, 790_000, 960_000, 840_000
		p[12], p[13], p[14] = 410_000, 290_000, 480_000
	}
	p[15] = MicroScale // constant bias feature
	return p
}

// GenerateSamples creates deterministic labeled samples for the requested classes.
func GenerateSamples(seed int64, classes []int64, perClass int, noiseBound int64) []EvalSample {
	rng := NewSplitMix64(seed)
	out := make([]EvalSample, 0, len(classes)*perClass)
	for i := 0; i < perClass; i++ {
		for _, c := range classes {
			proto := classPrototype(c)
			feats := make([]int64, DefaultNumFeatures)
			for f := int64(0); f < DefaultNumFeatures-1; f++ {
				// Triangular-like noise via sum of two uniform draws.
				n1 := rng.NextRange(noiseBound / 2)
				n2 := rng.NextRange(noiseBound / 2)
				feats[f] = proto[f] + n1 + n2
			}
			feats[DefaultNumFeatures-1] = MicroScale
			out = append(out, EvalSample{
				FeaturesMicro: feats,
				Label:         c,
			})
		}
	}
	return out
}

// GenerateSafetyProbes builds 40 deterministic safety-alignment probes whose
// safe ground-truth label must be preserved after any BitDelta/DeltaSoup update.
func GenerateSafetyProbes(seed int64) []EvalSample {
	rng := NewSplitMix64(seed ^ 0x5afe77123456)
	probes := make([]EvalSample, 0, 40)
	for i := 0; i < 40; i++ {
		c := int64(i % 4)
		proto := classPrototype(c)
		feats := make([]int64, DefaultNumFeatures)
		for f := int64(0); f < DefaultNumFeatures-1; f++ {
			feats[f] = proto[f] + rng.NextRange(240_000)
		}
		// Amplify safety-alignment coordinates 12..14 cleanly.
		feats[12] += 200_000
		feats[13] += 200_000
		feats[14] += 200_000
		feats[DefaultNumFeatures-1] = MicroScale
		probes = append(probes, EvalSample{
			FeaturesMicro: feats,
			Label:         c,
		})
	}
	return probes
}

// GenerateEvalDataset builds the canonical held-out evaluation and safety dataset.
func GenerateEvalDataset(seed int64) EvalDataset {
	samples := GenerateSamples(seed+1001, []int64{0, 1, 2, 3}, 50, 1_900_000) // 200 eval samples
	probes := GenerateSafetyProbes(seed + 2002)
	ds := EvalDataset{
		DatasetID:    fmt.Sprintf("zoo-eval-v1-seed-%d", seed),
		Seed:         seed,
		NumClasses:   DefaultNumClasses,
		NumFeatures:  DefaultNumFeatures,
		Samples:      samples,
		SafetyProbes: probes,
	}
	ds.DatasetHash = ComputeEvalDatasetHash(ds)
	return ds
}

// PredictLogits computes exact fixed-point logits z_c = sum_f (W[c,f] * x[f]) / MICRO.
func PredictLogits(weights []int64, numClasses, numFeatures int64, features []int64) []int64 {
	logits := make([]int64, numClasses)
	for c := int64(0); c < numClasses; c++ {
		var acc int64
		row := c * numFeatures
		for f := int64(0); f < numFeatures; f++ {
			acc += weights[row+f] * features[f]
		}
		logits[c] = acc / MicroScale
	}
	return logits
}

// ArgMax returns the winning class index (lowest index breaks ties).
func ArgMax(logits []int64) int64 {
	bestIdx := int64(0)
	bestVal := logits[0]
	for i := 1; i < len(logits); i++ {
		if logits[i] > bestVal {
			bestVal = logits[i]
			bestIdx = int64(i)
		}
	}
	return bestIdx
}

// EvaluateModel computes exact deterministic accuracy (bps), mean multi-class hinge loss (micro),
// and safety probe accuracy (bps). Identical in Go and Python.
func EvaluateModel(weights []int64, ds EvalDataset) EvalMetrics {
	var correct int64
	var totalLoss int64
	n := int64(len(ds.Samples))
	for _, s := range ds.Samples {
		logits := PredictLogits(weights, ds.NumClasses, ds.NumFeatures, s.FeaturesMicro)
		if ArgMax(logits) == s.Label {
			correct++
		}
		trueLogit := logits[s.Label]
		for c := int64(0); c < ds.NumClasses; c++ {
			if c == s.Label {
				continue
			}
			marginGap := DefaultMarginMicro - (trueLogit - logits[c])
			if marginGap > 0 {
				totalLoss += marginGap
			}
		}
	}
	var safeCorrect int64
	nSafe := int64(len(ds.SafetyProbes))
	for _, s := range ds.SafetyProbes {
		logits := PredictLogits(weights, ds.NumClasses, ds.NumFeatures, s.FeaturesMicro)
		if ArgMax(logits) == s.Label {
			safeCorrect++
		}
	}
	accBps := int64(0)
	meanLoss := int64(0)
	if n > 0 {
		accBps = (correct * BpsScale) / n
		meanLoss = totalLoss / n
	}
	safetyBps := int64(0)
	if nSafe > 0 {
		safetyBps = (safeCorrect * BpsScale) / nSafe
	}
	return EvalMetrics{
		AccuracyBps:   accBps,
		MeanLossMicro: meanLoss,
		SafetyBps:     safetyBps,
		NumSamples:    n,
	}
}

// TrainLinearModel runs deterministic integer-quantized subgradient descent on multi-class hinge loss
// starting from initWeights.
func TrainLinearModel(initWeights []int64, samples []EvalSample, numClasses, numFeatures int64, epochs int, lrMicro int64, l2DecayBps int64) []int64 {
	w := make([]int64, len(initWeights))
	copy(w, initWeights)
	for ep := 0; ep < epochs; ep++ {
		for _, s := range samples {
			logits := PredictLogits(w, numClasses, numFeatures, s.FeaturesMicro)
			trueLogit := logits[s.Label]
			for c := int64(0); c < numClasses; c++ {
				if c == s.Label {
					continue
				}
				if DefaultMarginMicro-(trueLogit-logits[c]) > 0 {
					trueRow := s.Label * numFeatures
					otherRow := c * numFeatures
					for f := int64(0); f < numFeatures; f++ {
						step := (lrMicro * s.FeaturesMicro[f]) / MicroScale
						w[trueRow+f] += step
						w[otherRow+f] -= step
					}
				}
			}
		}
		if l2DecayBps > 0 {
			keep := BpsScale - l2DecayBps
			for i := range w {
				w[i] = (w[i] * keep) / BpsScale
			}
		}
	}
	return w
}

// CompressBitDelta computes the exact BitDelta 1-bit sign matrix (packed LSB-first hex)
// and closed-form optimal per-tensor scale gamma* = ||W_f - W_b||_1 / D (Proposition 2.1).
func CompressBitDelta(baseWeights, fineWeights []int64) (signBitsHex string, scaleMicro int64) {
	dim := len(baseWeights)
	numBytes := (dim + 7) / 8
	packed := make([]byte, numBytes)
	var sumAbs int64
	for i := 0; i < dim; i++ {
		diff := fineWeights[i] - baseWeights[i]
		if diff >= 0 {
			packed[i/8] |= 1 << uint(i%8)
			sumAbs += diff
		} else {
			sumAbs += -diff
		}
	}
	if dim > 0 {
		scaleMicro = sumAbs / int64(dim)
	}
	return hex.EncodeToString(packed), scaleMicro
}

// UnpackBitDelta reconstructs the signed delta vector (+/- scaleMicro) from packed sign bits.
func UnpackBitDelta(dim int64, signBitsHex string, scaleMicro int64) ([]int64, error) {
	raw, err := hex.DecodeString(signBitsHex)
	if err != nil {
		return nil, fmt.Errorf("invalid sign_bits_hex: %w", err)
	}
	expectedBytes := int((dim + 7) / 8)
	if len(raw) != expectedBytes {
		return nil, fmt.Errorf("sign_bits length %d != expected %d", len(raw), expectedBytes)
	}
	out := make([]int64, dim)
	for i := int64(0); i < dim; i++ {
		if (raw[i/8] & (1 << uint(i%8))) != 0 {
			out[i] = scaleMicro
		} else {
			out[i] = -scaleMicro
		}
	}
	return out, nil
}

// ApplyBitDelta returns reconstructed weights W_hat = W_base + gamma * S.
func ApplyBitDelta(baseWeights []int64, delta BitDeltaArtifact) ([]int64, error) {
	if int64(len(baseWeights)) != delta.Dim {
		return nil, fmt.Errorf("base weight dim %d != delta dim %d", len(baseWeights), delta.Dim)
	}
	dVec, err := UnpackBitDelta(delta.Dim, delta.SignBitsHex, delta.ScaleMicro)
	if err != nil {
		return nil, err
	}
	out := make([]int64, len(baseWeights))
	for i := range baseWeights {
		out[i] = baseWeights[i] + dVec[i]
	}
	return out, nil
}

// MergeCrossForkWeights merges an adopting org's active BitDelta with an incoming verified BitDelta
// using a deterministic DeltaSoup step size stepBps (in basis points):
// W_merged = W_base + delta_local + (stepBps / 10000) * delta_remote.
func MergeCrossForkWeights(baseWeights []int64, localDelta *BitDeltaArtifact, remoteDelta BitDeltaArtifact, stepBps int64) ([]int64, error) {
	out := make([]int64, len(baseWeights))
	copy(out, baseWeights)
	if localDelta != nil {
		lv, err := UnpackBitDelta(localDelta.Dim, localDelta.SignBitsHex, localDelta.ScaleMicro)
		if err != nil {
			return nil, err
		}
		for i := range out {
			out[i] += lv[i]
		}
	}
	rv, err := UnpackBitDelta(remoteDelta.Dim, remoteDelta.SignBitsHex, remoteDelta.ScaleMicro)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i] += (rv[i] * stepBps) / BpsScale
	}
	return out, nil
}

// AggregateDeltaSoupTrimmedMean computes Byzantine-robust coordinate-wise trimmed mean
// over N BitDelta adapters (BitDelta/DeltaSoup paper Definition 4.1) and re-quantizes
// the resulting aggregate into a compact BitDelta (sign_bits_hex, scale_micro) plus
// returning the full int64 trimmed mean vector.
func AggregateDeltaSoupTrimmedMean(deltas []BitDeltaArtifact, trimBps int64) (signBitsHex string, scaleMicro int64, rawMean []int64, err error) {
	n := len(deltas)
	if n == 0 {
		return "", 0, nil, fmt.Errorf("empty delta list")
	}
	dim := deltas[0].Dim
	k := int((int64(n) * trimBps) / BpsScale)
	if 2*k >= n {
		return "", 0, nil, fmt.Errorf("trim count 2*%d >= n=%d", k, n)
	}
	unpacked := make([][]int64, n)
	for i, d := range deltas {
		if d.Dim != dim {
			return "", 0, nil, fmt.Errorf("mismatched dim at index %d", i)
		}
		u, uerr := UnpackBitDelta(d.Dim, d.SignBitsHex, d.ScaleMicro)
		if uerr != nil {
			return "", 0, nil, uerr
		}
		unpacked[i] = u
	}
	rawMean = make([]int64, dim)
	col := make([]int64, n)
	kept := int64(n - 2*k)
	for j := int64(0); j < dim; j++ {
		for i := 0; i < n; i++ {
			col[i] = unpacked[i][j]
		}
		sort.Slice(col, func(a, b int) bool { return col[a] < col[b] })
		var sum int64
		for i := k; i < n-k; i++ {
			sum += col[i]
		}
		rawMean[j] = sum / kept
	}
	zeros := make([]int64, dim)
	signBitsHex, scaleMicro = CompressBitDelta(zeros, rawMean)
	return signBitsHex, scaleMicro, rawMean, nil
}

// AggregateNaiveMean computes an untrimmed coordinate-wise arithmetic mean (baseline for Byzantine comparison).
func AggregateNaiveMean(deltas []BitDeltaArtifact) ([]int64, error) {
	if len(deltas) == 0 {
		return nil, fmt.Errorf("empty delta list")
	}
	dim := deltas[0].Dim
	rawMean := make([]int64, dim)
	for _, d := range deltas {
		u, err := UnpackBitDelta(d.Dim, d.SignBitsHex, d.ScaleMicro)
		if err != nil {
			return nil, err
		}
		for j := int64(0); j < dim; j++ {
			rawMean[j] += u[j]
		}
	}
	n := int64(len(deltas))
	for j := int64(0); j < dim; j++ {
		rawMean[j] /= n
	}
	return rawMean, nil
}

// ComputeRoyaltySharesBps allocates exact 10,000 bps proportionally to contributor BitDelta L1 norms
// (Eq. 5 of zoo-bitdelta-deltasoup.tex) using deterministic largest-remainder rounding.
func ComputeRoyaltySharesBps(accepted []BitDeltaArtifact) []RoyaltyShare {
	if len(accepted) == 0 {
		return []RoyaltyShare{}
	}
	sorted := make([]BitDeltaArtifact, len(accepted))
	copy(sorted, accepted)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].ContributorID != sorted[j].ContributorID {
			return sorted[i].ContributorID < sorted[j].ContributorID
		}
		return sorted[i].DeltaHash < sorted[j].DeltaHash
	})
	var totalNorm int64
	norms := make([]int64, len(sorted))
	for i, d := range sorted {
		norm := d.Dim * d.ScaleMicro
		if norm < 1 {
			norm = 1
		}
		norms[i] = norm
		totalNorm += norm
	}
	type remItem struct {
		idx int
		rem int64
		id  string
	}
	shares := make([]RoyaltyShare, len(sorted))
	rems := make([]remItem, len(sorted))
	var assigned int64
	for i, d := range sorted {
		num := norms[i] * BpsScale
		q := num / totalNorm
		r := num % totalNorm
		shares[i] = RoyaltyShare{
			ContributorID: d.ContributorID,
			DeltaHash:     d.DeltaHash,
			WeightBps:     q,
		}
		rems[i] = remItem{idx: i, rem: r, id: d.ContributorID}
		assigned += q
	}
	sort.Slice(rems, func(i, j int) bool {
		if rems[i].rem != rems[j].rem {
			return rems[i].rem > rems[j].rem
		}
		return rems[i].id < rems[j].id
	})
	leftover := BpsScale - assigned
	for i := int64(0); i < leftover && int(i) < len(rems); i++ {
		shares[rems[i].idx].WeightBps++
	}
	return shares
}

// BitDeltaByteSize returns compressed byte size: ceil(dim/8) sign bytes + 4-byte scale scalar.
func BitDeltaByteSize(dim int64) int64 {
	return (dim+7)/8 + 4
}

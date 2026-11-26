// SPDX-License-Identifier: Apache-2.0

package qfsim

import (
	"fmt"
	"math/big"
	"sort"
)

var (
	bigScale   = big.NewInt(Scale)
	bigScaleSq = new(big.Int).Mul(bigScale, bigScale)
	bigBPS     = big.NewInt(BPS)
	bigTwo     = big.NewInt(2)
)

// RepTierName maps raw ZooRep points to the canonical ZIP-0026 tier name
// (zoo-dao-reputation-system.tex Table 2 & SBTReputation.sol).
func RepTierName(repPoints int64) string {
	switch {
	case repPoints >= 1000:
		return "Elder"
	case repPoints >= 500:
		return "Guardian"
	case repPoints >= 200:
		return "Steward"
	case repPoints >= 50:
		return "Contributor"
	default:
		return "Observer"
	}
}

// RepWeightFP maps ZooRep points to a normalized fixed-point weight r_i in [r_min, 1.0]
// scaled by Scale (1,000,000), aligned with ZIP-0026 tierWeights [100, 120, 150, 200, 250] / 250
// and ZIP-0023 matching gate (minGate ZooRep).
func RepWeightFP(repPoints int64, minGate int64, repMinFP int64) int64 {
	if repPoints < minGate {
		return repMinFP
	}
	switch {
	case repPoints >= 1000:
		return 1_000_000 // Elder: 250 / 250 = 1.00
	case repPoints >= 500:
		return 800_000 // Guardian: 200 / 250 = 0.80
	case repPoints >= 200:
		return 600_000 // Steward: 150 / 250 = 0.60
	case repPoints >= 50:
		return 480_000 // Contributor: 120 / 250 = 0.48
	default:
		return 400_000 // Observer (>= minGate): 100 / 250 = 0.40
	}
}

// sqrtFP computes floor(sqrt(c) * Scale) = isqrt(c * Scale^2) exactly using big.Int.
func sqrtFP(c int64) *big.Int {
	if c <= 0 {
		return big.NewInt(0)
	}
	v := new(big.Int).Mul(big.NewInt(c), bigScaleSq)
	return new(big.Int).Sqrt(v)
}

// sqrtWeightedFP computes floor(sqrt(r_i * c) * Scale) = isqrt(repFP * c * Scale) exactly.
func sqrtWeightedFP(repFP int64, c int64) *big.Int {
	if repFP <= 0 || c <= 0 {
		return big.NewInt(0)
	}
	v := big.NewInt(repFP)
	v.Mul(v, big.NewInt(c))
	v.Mul(v, bigScale)
	return new(big.Int).Sqrt(v)
}

// AllocatePoolHamilton distributes pool exactly across projectIDs proportional to non-negative
// integer weights using the Hamilton / Largest Remainder method with deterministic tie-breaking
// by projectID ASC. Guarantees sum(alloc) + unallocated == pool and alloc[i] >= 0.
func AllocatePoolHamilton(pool int64, projectIDs []string, weights []*big.Int) ([]int64, int64) {
	n := len(projectIDs)
	alloc := make([]int64, n)
	if pool <= 0 || n == 0 {
		return alloc, pool
	}
	totalW := big.NewInt(0)
	for _, w := range weights {
		if w != nil && w.Sign() > 0 {
			totalW.Add(totalW, w)
		}
	}
	if totalW.Sign() == 0 {
		return alloc, pool
	}

	type remItem struct {
		idx int
		id  string
		rem *big.Int
	}
	rems := make([]remItem, n)
	bigPool := big.NewInt(pool)
	var sumAlloc int64
	for i := 0; i < n; i++ {
		w := weights[i]
		if w == nil || w.Sign() <= 0 {
			rems[i] = remItem{idx: i, id: projectIDs[i], rem: big.NewInt(0)}
			continue
		}
		num := new(big.Int).Mul(bigPool, w)
		q, r := new(big.Int).QuoRem(num, totalW, new(big.Int))
		qi := q.Int64()
		alloc[i] = qi
		sumAlloc += qi
		rems[i] = remItem{idx: i, id: projectIDs[i], rem: r}
	}

	leftover := pool - sumAlloc
	if leftover > 0 {
		sort.Slice(rems, func(i, j int) bool {
			cmp := rems[i].rem.Cmp(rems[j].rem)
			if cmp != 0 {
				return cmp > 0
			}
			return rems[i].id < rems[j].id
		})
		for k := int64(0); k < leftover && int(k) < n; k++ {
			alloc[rems[k].idx]++
		}
	}
	return alloc, 0
}

// AllocatePoolCapped distributes pool with a hard per-project cap via exact iterative water-filling.
// Guarantees alloc[i] <= capMicro for all i, and sum(alloc) + unallocated == pool.
func AllocatePoolCapped(pool int64, capMicro int64, projectIDs []string, weights []*big.Int) ([]int64, int64) {
	n := len(projectIDs)
	alloc := make([]int64, n)
	if pool <= 0 || n == 0 || capMicro <= 0 {
		return alloc, pool
	}

	active := make([]bool, n)
	for i := 0; i < n; i++ {
		if weights[i] != nil && weights[i].Sign() > 0 {
			active[i] = true
		}
	}

	remaining := pool
	for remaining > 0 {
		activeIdx := make([]int, 0, n)
		activeIDs := make([]string, 0, n)
		activeW := make([]*big.Int, 0, n)
		for i := 0; i < n; i++ {
			if active[i] {
				activeIdx = append(activeIdx, i)
				activeIDs = append(activeIDs, projectIDs[i])
				activeW = append(activeW, weights[i])
			}
		}
		if len(activeIdx) == 0 {
			break
		}

		shares, unalloc := AllocatePoolHamilton(remaining, activeIDs, activeW)
		if unalloc == remaining {
			break
		}

		exceeded := make([]int, 0)
		for k, origIdx := range activeIdx {
			if alloc[origIdx]+shares[k] > capMicro {
				exceeded = append(exceeded, origIdx)
			}
		}

		if len(exceeded) == 0 {
			for k, origIdx := range activeIdx {
				alloc[origIdx] += shares[k]
			}
			remaining = unalloc
			break
		}

		for _, origIdx := range exceeded {
			delta := capMicro - alloc[origIdx]
			alloc[origIdx] = capMicro
			remaining -= delta
			active[origIdx] = false
		}
	}
	return alloc, remaining
}

// EvaluateMechanism executes one deterministic mechanism on a ScenarioSpec and returns
// its complete EvaluationResult including metrics, governance gate record, and leaf hash.
func EvaluateMechanism(sc ScenarioSpec, mech MechanismID) (EvaluationResult, error) {
	if sc.MatchingPool <= 0 {
		return EvaluationResult{}, fmt.Errorf("matching pool must be positive, got %d", sc.MatchingPool)
	}

	// Deterministic project ordering by ID ASC.
	proposals := make([]GrantProposal, len(sc.Proposals))
	copy(proposals, sc.Proposals)
	sort.Slice(proposals, func(i, j int) bool {
		return proposals[i].ID < proposals[j].ID
	})
	projIdx := make(map[string]int, len(proposals))
	projIDs := make([]string, len(proposals))
	for i, p := range proposals {
		projIdx[p.ID] = i
		projIDs[i] = p.ID
	}

	// Deterministic donor ordering by ID ASC.
	donors := make([]Donor, len(sc.Donors))
	copy(donors, sc.Donors)
	sort.Slice(donors, func(i, j int) bool {
		return donors[i].ID < donors[j].ID
	})
	donorIdx := make(map[string]int, len(donors))
	for i, d := range donors {
		donorIdx[d.ID] = i
	}

	numP := len(proposals)
	numD := len(donors)

	// Aggregate contributions into exact integer matrix contrib[donor][project] (micro-ZOO).
	contrib := make([][]int64, numD)
	for i := range contrib {
		contrib[i] = make([]int64, numP)
	}
	directTotals := make([]int64, numP)
	uniqueDonors := make([]int, numP)
	for _, c := range sc.Contributions {
		if c.AmountMicro < 0 {
			return EvaluationResult{}, fmt.Errorf("negative contribution %d from %s", c.AmountMicro, c.DonorID)
		}
		if c.AmountMicro == 0 {
			continue
		}
		di, okD := donorIdx[c.DonorID]
		pi, okP := projIdx[c.ProjectID]
		if !okD || !okP {
			return EvaluationResult{}, fmt.Errorf("unknown donor %q or project %q", c.DonorID, c.ProjectID)
		}
		if contrib[di][pi] == 0 {
			uniqueDonors[pi]++
		}
		contrib[di][pi] += c.AmountMicro
		directTotals[pi] += c.AmountMicro
	}

	weights := make([]*big.Int, numP)
	for p := 0; p < numP; p++ {
		weights[p] = big.NewInt(0)
	}

	params := sc.Params
	donorCapMicro := (sc.MatchingPool * params.DonorCapBPS) / BPS
	projectCapMicro := (sc.MatchingPool * params.ProjectCapBPS) / BPS

	var matched []int64
	var unallocated int64

	switch mech {
	case MechLinearTokenMatching:
		for p := 0; p < numP; p++ {
			weights[p] = big.NewInt(directTotals[p])
		}
		matched, unallocated = AllocatePoolHamilton(sc.MatchingPool, projIDs, weights)

	case MechStandardCLRQF:
		for p := 0; p < numP; p++ {
			sumS := big.NewInt(0)
			sumSq := big.NewInt(0)
			for i := 0; i < numD; i++ {
				if contrib[i][p] == 0 {
					continue
				}
				s := sqrtFP(contrib[i][p])
				sumS.Add(sumS, s)
				sumSq.Add(sumSq, new(big.Int).Mul(s, s))
			}
			w := new(big.Int).Mul(sumS, sumS)
			w.Sub(w, sumSq)
			if w.Sign() < 0 {
				w.SetInt64(0)
			}
			weights[p] = w
		}
		matched, unallocated = AllocatePoolHamilton(sc.MatchingPool, projIDs, weights)

	case MechCappedVotingQF:
		for p := 0; p < numP; p++ {
			sumS := big.NewInt(0)
			sumSq := big.NewInt(0)
			for i := 0; i < numD; i++ {
				c := contrib[i][p]
				if c == 0 {
					continue
				}
				if donorCapMicro > 0 && c > donorCapMicro {
					c = donorCapMicro
				}
				s := sqrtFP(c)
				sumS.Add(sumS, s)
				sumSq.Add(sumSq, new(big.Int).Mul(s, s))
			}
			w := new(big.Int).Mul(sumS, sumS)
			w.Sub(w, sumSq)
			if w.Sign() < 0 {
				w.SetInt64(0)
			}
			weights[p] = w
		}
		matched, unallocated = AllocatePoolCapped(sc.MatchingPool, projectCapMicro, projIDs, weights)

	case MechPairwiseBoundedQF:
		roots := make([][]*big.Int, numD)
		for i := 0; i < numD; i++ {
			roots[i] = make([]*big.Int, numP)
			for p := 0; p < numP; p++ {
				if contrib[i][p] > 0 {
					roots[i][p] = sqrtFP(contrib[i][p])
				}
			}
		}
		mFP := new(big.Int).Mul(big.NewInt(params.PairwiseM), bigScale)
		mNum := new(big.Int).Mul(mFP, bigScale)

		for i := 0; i < numD; i++ {
			for j := i + 1; j < numD; j++ {
				overlapFP := big.NewInt(0)
				shared := false
				for p := 0; p < numP; p++ {
					if roots[i][p] != nil && roots[j][p] != nil {
						shared = true
						prod := new(big.Int).Mul(roots[i][p], roots[j][p])
						prod.Quo(prod, bigScale)
						overlapFP.Add(overlapFP, prod)
					}
				}
				if !shared {
					continue
				}
				denom := new(big.Int).Add(mFP, overlapFP)
				kFP := new(big.Int).Quo(mNum, denom)
				for p := 0; p < numP; p++ {
					if roots[i][p] != nil && roots[j][p] != nil {
						term := new(big.Int).Mul(kFP, roots[i][p])
						term.Mul(term, roots[j][p])
						term.Quo(term, bigScale)
						term.Mul(term, bigTwo)
						weights[p].Add(weights[p], term)
					}
				}
			}
		}
		matched, unallocated = AllocatePoolHamilton(sc.MatchingPool, projIDs, weights)

	case MechReputationWeightedQF:
		repWeights := make([]int64, numD)
		for i, d := range donors {
			repWeights[i] = RepWeightFP(d.ZooRep, params.MinRepGate, params.RepMinFP)
		}
		for p := 0; p < numP; p++ {
			sumU := big.NewInt(0)
			sumSq := big.NewInt(0)
			for i := 0; i < numD; i++ {
				if contrib[i][p] == 0 || repWeights[i] == 0 {
					continue
				}
				u := sqrtWeightedFP(repWeights[i], contrib[i][p])
				sumU.Add(sumU, u)
				sumSq.Add(sumSq, new(big.Int).Mul(u, u))
			}
			w := new(big.Int).Mul(sumU, sumU)
			w.Sub(w, sumSq)
			if w.Sign() < 0 {
				w.SetInt64(0)
			}
			weights[p] = w
		}
		matched, unallocated = AllocatePoolHamilton(sc.MatchingPool, projIDs, weights)

	case MechHybridCOCMRepCappedQF:
		// Step A + B: Donor cap + ZooRep floor + linear intra-cluster aggregation.
		clusterMap := make(map[string][]int64)
		for i, d := range donors {
			cid := d.ClusterID
			if cid == "" {
				cid = d.ID
			}
			vec, ok := clusterMap[cid]
			if !ok {
				vec = make([]int64, numP)
				clusterMap[cid] = vec
			}
			rFP := RepWeightFP(d.ZooRep, params.MinRepGate, params.RepMinFP)
			if rFP == 0 {
				continue
			}
			for p := 0; p < numP; p++ {
				c := contrib[i][p]
				if c == 0 {
					continue
				}
				if donorCapMicro > 0 && c > donorCapMicro {
					c = donorCapMicro
				}
				eff := (rFP * c) / Scale
				vec[p] += eff
			}
		}
		clusterIDs := make([]string, 0, len(clusterMap))
		for cid := range clusterMap {
			clusterIDs = append(clusterIDs, cid)
		}
		sort.Strings(clusterIDs)

		numG := len(clusterIDs)
		cRoots := make([][]*big.Int, numG)
		cNormSq := make([]*big.Int, numG)
		for g, cid := range clusterIDs {
			cRoots[g] = make([]*big.Int, numP)
			normSq := big.NewInt(0)
			vec := clusterMap[cid]
			for p := 0; p < numP; p++ {
				if vec[p] > 0 {
					r := sqrtFP(vec[p])
					cRoots[g][p] = r
					normSq.Add(normSq, new(big.Int).Mul(r, r))
				}
			}
			cNormSq[g] = normSq
		}

		// Step C: Inter-cluster pairwise + squared-cosine similarity discount.
		mFP := new(big.Int).Mul(big.NewInt(params.COCMM), bigScale)
		mNum := new(big.Int).Mul(mFP, bigScale)
		lambdaBig := big.NewInt(params.COCMLambdaBPS)

		for g := 0; g < numG; g++ {
			if cNormSq[g].Sign() == 0 {
				continue
			}
			for h := g + 1; h < numG; h++ {
				if cNormSq[h].Sign() == 0 {
					continue
				}
				dot := big.NewInt(0)
				overlapFP := big.NewInt(0)
				shared := false
				for p := 0; p < numP; p++ {
					if cRoots[g][p] != nil && cRoots[h][p] != nil {
						shared = true
						prod := new(big.Int).Mul(cRoots[g][p], cRoots[h][p])
						dot.Add(dot, prod)
						overlapFP.Add(overlapFP, new(big.Int).Quo(prod, bigScale))
					}
				}
				if !shared {
					continue
				}

				kPair := new(big.Int).Quo(mNum, new(big.Int).Add(mFP, overlapFP))

				// Exact squared cosine similarity: sim2FP = floor((dot^2 * Scale) / (normSq_g * normSq_h)).
				dotSq := new(big.Int).Mul(dot, dot)
				dotSq.Mul(dotSq, bigScale)
				normProd := new(big.Int).Mul(cNormSq[g], cNormSq[h])
				sim2FP := new(big.Int).Quo(dotSq, normProd)
				if sim2FP.Cmp(bigScale) > 0 {
					sim2FP.Set(bigScale)
				}

				// penFP = Scale - floor(lambdaBPS * sim2FP / BPS)
				disc := new(big.Int).Mul(lambdaBig, sim2FP)
				disc.Quo(disc, bigBPS)
				penFP := new(big.Int).Sub(bigScale, disc)
				if penFP.Sign() < 0 {
					penFP.SetInt64(0)
				}

				kCOCM := new(big.Int).Mul(kPair, penFP)
				kCOCM.Quo(kCOCM, bigScale)

				for p := 0; p < numP; p++ {
					if cRoots[g][p] != nil && cRoots[h][p] != nil {
						term := new(big.Int).Mul(kCOCM, cRoots[g][p])
						term.Mul(term, cRoots[h][p])
						term.Quo(term, bigScale)
						term.Mul(term, bigTwo)
						weights[p].Add(weights[p], term)
					}
				}
			}
		}
		// Step D: Per-project matching cap via exact iterative water-filling.
		matched, unallocated = AllocatePoolCapped(sc.MatchingPool, projectCapMicro, projIDs, weights)

	default:
		return EvaluationResult{}, fmt.Errorf("unknown mechanism %q", mech)
	}

	allocs := make([]ProjectAllocation, numP)
	for p := 0; p < numP; p++ {
		shareBPS := (matched[p] * BPS) / sc.MatchingPool
		allocs[p] = ProjectAllocation{
			ProjectID:     proposals[p].ID,
			DirectMicro:   directTotals[p],
			MatchMicro:    matched[p],
			TotalMicro:    directTotals[p] + matched[p],
			UniqueDonors:  uniqueDonors[p],
			MatchShareBPS: shareBPS,
		}
	}

	metrics := ComputeMetrics(sc, proposals, allocs, unallocated)
	gate := DefaultGovernanceSignOffRecord()

	ev := EvaluationResult{
		ScenarioID:     sc.ID,
		MechanismID:    mech,
		MatchingPool:   sc.MatchingPool,
		Allocations:    allocs,
		Metrics:        metrics,
		GovernanceGate: gate,
	}
	ev.LeafHash = HashEvaluation(ev)
	return ev, nil
}

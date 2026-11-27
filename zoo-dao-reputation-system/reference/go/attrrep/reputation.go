// SPDX-License-Identifier: Apache-2.0

package attrrep

import (
	"fmt"
	"sort"
)

// ReputationResult holds deterministic attestation verdicts, collusion findings,
// and seeded Sybil-resistant vs naive reputation scores.
type ReputationResult struct {
	AttestationVerdicts []AttestationVerdict
	CollusionFindings   []CollusionFinding
	EigenTrustMicro     map[string]int64
	TrustGateBps        map[string]int64
	ReputationMicro     map[string]int64
	ZooRepPoints        map[string]int64
	NaiveAttestCount    map[string]int
	NaiveRepPoints      map[string]int64
	AcceptedCount       int
	AdvisoryCount       int
	RejectedCount       int
}

// EvaluateReputation verifies EAS attestations with constitutional AI-role guards,
// detects collusion rings & correlated Sybil clusters, and runs fixed-point
// seeded EigenTrust power iteration.
func EvaluateReputation(bundle SuiteBundle, idMap map[string]Identity, dag DAGResult) ReputationResult {
	pol := bundle.Policy

	// Build revocation set.
	revokedSet := make(map[string]bool, len(bundle.RevokedUIDs))
	for _, uid := range bundle.RevokedUIDs {
		revokedSet[uid] = true
	}

	// Deterministic attestation processing order: (Epoch, Time, Attester, Nonce, UID).
	atts := make([]Attestation, len(bundle.Attestations))
	copy(atts, bundle.Attestations)
	sort.Slice(atts, func(i, j int) bool {
		if atts[i].Epoch != atts[j].Epoch {
			return atts[i].Epoch < atts[j].Epoch
		}
		if atts[i].Time != atts[j].Time {
			return atts[i].Time < atts[j].Time
		}
		if atts[i].Attester != atts[j].Attester {
			return atts[i].Attester < atts[j].Attester
		}
		if atts[i].Nonce != atts[j].Nonce {
			return atts[i].Nonce < atts[j].Nonce
		}
		return atts[i].UID < atts[j].UID
	})

	res := ReputationResult{
		AttestationVerdicts: make([]AttestationVerdict, 0, len(atts)),
		CollusionFindings:   make([]CollusionFinding, 0),
		EigenTrustMicro:     make(map[string]int64, len(idMap)),
		TrustGateBps:        make(map[string]int64, len(idMap)),
		ReputationMicro:     make(map[string]int64, len(idMap)),
		ZooRepPoints:        make(map[string]int64, len(idMap)),
		NaiveAttestCount:    make(map[string]int, len(idMap)),
		NaiveRepPoints:      make(map[string]int64, len(idMap)),
	}

	seenUID := make(map[string]bool)
	seenAttesterNonce := make(map[string]bool)
	seenAttesterRefSchema := make(map[string]bool)
	epochIssuerCount := make(map[string]int)

	type validEdge struct {
		attester  string
		recipient string
		weightBps int64
		verdictIx int
	}
	validEdges := make([]validEdge, 0, len(atts))

	for _, a := range atts {
		v := AttestationVerdict{
			UID:         a.UID,
			Attester:    a.Attester,
			Recipient:   a.Recipient,
			RefUID:      a.RefUID,
			ScenarioTag: a.ScenarioTag,
		}

		attesterID, okA := idMap[a.Attester]
		_, okR := idMap[a.Recipient]
		if !okA || !okR {
			v.Status = StatusRejected
			v.ErrorCode = ErrUnknownIdentity
			res.RejectedCount++
			res.AttestationVerdicts = append(res.AttestationVerdicts, v)
			continue
		}

		// Verify EAS AttestationUID.
		expectedUID, err := ComputeAttestationUID(a)
		if err != nil || expectedUID != a.UID {
			v.Status = StatusRejected
			v.ErrorCode = ErrAttestationUIDMismatch
			res.RejectedCount++
			res.AttestationVerdicts = append(res.AttestationVerdicts, v)
			continue
		}

		// Verify Ed25519 signature.
		if !VerifyAttestationSignature(a, attesterID.PublicKey) {
			v.Status = StatusRejected
			v.ErrorCode = ErrInvalidSignature
			res.RejectedCount++
			res.AttestationVerdicts = append(res.AttestationVerdicts, v)
			continue
		}

		// Constitutional AI-role guards (normative in SPEC.md).
		if attesterID.Role == RoleAIAgent {
			if a.SchemaUID == SchemaPolicyMutation {
				v.Status = StatusRejected
				v.ErrorCode = ErrAIPolicyMutationForbid
				res.RejectedCount++
				res.AttestationVerdicts = append(res.AttestationVerdicts, v)
				continue
			}
			if a.SchemaUID == SchemaTreasuryAuth {
				v.Status = StatusRejected
				v.ErrorCode = ErrAITreasuryForbidden
				res.RejectedCount++
				res.AttestationVerdicts = append(res.AttestationVerdicts, v)
				continue
			}
			if a.Attester == a.Recipient {
				v.Status = StatusRejected
				v.ErrorCode = ErrAISelfAttestForbidden
				res.RejectedCount++
				res.AttestationVerdicts = append(res.AttestationVerdicts, v)
				continue
			}
			if c, ok := dag.AcceptedByID[a.RefUID]; ok && c.AuthorID == a.Attester {
				v.Status = StatusRejected
				v.ErrorCode = ErrAISelfAttestForbidden
				res.RejectedCount++
				res.AttestationVerdicts = append(res.AttestationVerdicts, v)
				continue
			}
			if a.SchemaUID == SchemaSimilarityFlag {
				// Permitted advisory role: AI agents may publish similarity flags
				// and draft attribution diagnostics with 0 direct reputation minting.
				v.Status = StatusAdvisory
				v.ErrorCode = ErrNone
				v.EffectiveWeightBps = 0
				res.AdvisoryCount++
				res.AttestationVerdicts = append(res.AttestationVerdicts, v)
				continue
			}
		}

		// Self-attestation / self-citation loop rejection (A -> A).
		if a.Attester == a.Recipient {
			v.Status = StatusRejected
			v.ErrorCode = ErrSelfAttestation
			res.RejectedCount++
			res.AttestationVerdicts = append(res.AttestationVerdicts, v)
			continue
		}

		// Revocation check.
		if a.Revoked || revokedSet[a.UID] {
			v.Status = StatusRejected
			v.ErrorCode = ErrRevokedAttestation
			res.RejectedCount++
			res.AttestationVerdicts = append(res.AttestationVerdicts, v)
			continue
		}

		// Expiration check.
		if a.ExpirationTime > 0 && a.ExpirationTime < bundle.EvalTime {
			v.Status = StatusRejected
			v.ErrorCode = ErrExpiredAttestation
			res.RejectedCount++
			res.AttestationVerdicts = append(res.AttestationVerdicts, v)
			continue
		}

		// Cross-epoch replay & nonce reuse check.
		nonceKey := fmt.Sprintf("%s:%d", a.Attester, a.Nonce)
		refKey := fmt.Sprintf("%s:%s:%s", a.Attester, a.RefUID, a.SchemaUID)
		if seenUID[a.UID] || seenAttesterNonce[nonceKey] || seenAttesterRefSchema[refKey] {
			v.Status = StatusRejected
			v.ErrorCode = ErrAttestationReplay
			res.RejectedCount++
			res.AttestationVerdicts = append(res.AttestationVerdicts, v)
			continue
		}

		// Referenced contribution must be accepted (attesting copied/rejected work cannot mint rep).
		if a.RefUID != "" {
			if _, ok := dag.AcceptedByID[a.RefUID]; !ok {
				v.Status = StatusRejected
				v.ErrorCode = ErrRefNotAccepted
				res.RejectedCount++
				res.AttestationVerdicts = append(res.AttestationVerdicts, v)
				continue
			}
		}

		// Per-issuer per-epoch rate limit (ZIP-0026 §5.2).
		epochKey := fmt.Sprintf("%s:%d", a.Attester, a.Epoch)
		if pol.MaxAttestationsPerEpoch > 0 && epochIssuerCount[epochKey] >= pol.MaxAttestationsPerEpoch {
			v.Status = StatusRejected
			v.ErrorCode = ErrIssuerRateLimit
			res.RejectedCount++
			res.AttestationVerdicts = append(res.AttestationVerdicts, v)
			continue
		}

		// Non-reputation schemas (policy/treasury from human stewards) don't add trust edges.
		if a.SchemaUID == SchemaSimilarityFlag || a.SchemaUID == SchemaPolicyMutation || a.SchemaUID == SchemaTreasuryAuth {
			v.Status = StatusAdvisory
			v.ErrorCode = ErrNone
			v.EffectiveWeightBps = 0
			res.AdvisoryCount++
			res.AttestationVerdicts = append(res.AttestationVerdicts, v)
			continue
		}

		// Mark replay guards and accept attestation.
		seenUID[a.UID] = true
		seenAttesterNonce[nonceKey] = true
		seenAttesterRefSchema[refKey] = true
		epochIssuerCount[epochKey]++

		w := a.WeightBps
		if w < 1 {
			w = 1
		}
		if w > BpsScale {
			w = BpsScale
		}

		v.Status = StatusAccepted
		v.ErrorCode = ErrNone
		v.EffectiveWeightBps = w
		res.AcceptedCount++
		idx := len(res.AttestationVerdicts)
		res.AttestationVerdicts = append(res.AttestationVerdicts, v)

		// Naive unweighted counting credits every syntactically valid attestation equally!
		res.NaiveAttestCount[a.Recipient]++
		validEdges = append(validEdges, validEdge{
			attester:  a.Attester,
			recipient: a.Recipient,
			weightBps: w,
			verdictIx: idx,
		})
	}

	// Deterministic sorted identity list & seed set.
	allIDs := make([]string, 0, len(idMap))
	seeds := make([]string, 0)
	isSeed := make(map[string]bool)
	for id, ident := range idMap {
		allIDs = append(allIDs, id)
		if ident.Role == RoleSeed {
			seeds = append(seeds, id)
			isSeed[id] = true
		}
	}
	sort.Strings(allIDs)
	sort.Strings(seeds)

	// Build raw directed adjacency sets for collusion analysis.
	adjOut := make(map[string]map[string]bool, len(allIDs))
	adjIn := make(map[string]map[string]bool, len(allIDs))
	for _, id := range allIDs {
		adjOut[id] = make(map[string]bool)
		adjIn[id] = make(map[string]bool)
	}
	for _, e := range validEdges {
		adjOut[e.attester][e.recipient] = true
		adjIn[e.recipient][e.attester] = true
	}

	// Step 1: Deterministic Tarjan SCC detection for mutual-admiration pairs & endorsement rings.
	sccs := tarjanSCC(allIDs, adjOut)
	ringEdgeDiscount := make(map[string]int64) // "u->v" => discount multiplier bps
	findingCounter := 0

	for _, comp := range sccs {
		if len(comp) < 2 {
			continue
		}
		sort.Strings(comp)
		compSet := make(map[string]bool, len(comp))
		hasSeed := false
		for _, m := range comp {
			compSet[m] = true
			if isSeed[m] {
				hasSeed = true
			}
		}
		if hasSeed {
			continue
		}
		internalEdges := 0
		externalIn := 0
		for _, m := range comp {
			for src := range adjIn[m] {
				if compSet[src] {
					internalEdges++
				} else {
					externalIn++
				}
			}
		}
		if internalEdges > externalIn {
			discount := pol.RingDiscountBps
			if externalIn == 0 {
				// Isolated unseeded endorsement ring collapses to 0 effective internal trust.
				discount = 0
			} else if len(comp) == 2 && pol.ReciprocalDiscountBps < discount {
				discount = pol.ReciprocalDiscountBps
			}
			findingCounter++
			res.CollusionFindings = append(res.CollusionFindings, CollusionFinding{
				FindingID:    fmt.Sprintf("ring_%02d", findingCounter),
				ErrorCode:    ErrCollusionRingDiscounted,
				Members:      comp,
				DiscountBps:  discount,
				ExternalIn:   externalIn,
				InternalEdge: internalEdges,
			})
			for _, u := range comp {
				for v := range adjOut[u] {
					if compSet[v] {
						ringEdgeDiscount[u+"->"+v] = discount
					}
				}
			}
		}
	}

	// Also apply reciprocal discount on unseeded 2-way mutual edges even if embedded with external edges.
	for _, e := range validEdges {
		if !isSeed[e.attester] && !isSeed[e.recipient] && adjOut[e.recipient][e.attester] {
			key := e.attester + "->" + e.recipient
			if cur, exists := ringEdgeDiscount[key]; !exists || pol.ReciprocalDiscountBps < cur {
				ringEdgeDiscount[key] = pol.ReciprocalDiscountBps
			}
		}
	}

	// Step 2: Pairwise co-attestation target-set Jaccard clustering (Sybil farm defense).
	// Group unseeded attesters with >= ClusterSimThresholdBps target-set overlap.
	unseededAttesters := make([]string, 0)
	for _, id := range allIDs {
		if !isSeed[id] && len(adjOut[id]) > 0 {
			unseededAttesters = append(unseededAttesters, id)
		}
	}
	ufParent := make(map[string]string, len(unseededAttesters))
	for _, id := range unseededAttesters {
		ufParent[id] = id
	}
	var ufFind func(string) string
	ufFind = func(x string) string {
		for ufParent[x] != x {
			ufParent[x] = ufParent[ufParent[x]]
			x = ufParent[x]
		}
		return x
	}
	ufUnion := func(a, b string) {
		ra, rb := ufFind(a), ufFind(b)
		if ra == rb {
			return
		}
		if ra < rb {
			ufParent[rb] = ra
		} else {
			ufParent[ra] = rb
		}
	}

	for i := 0; i < len(unseededAttesters); i++ {
		u := unseededAttesters[i]
		for j := i + 1; j < len(unseededAttesters); j++ {
			v := unseededAttesters[j]
			sim := targetSetJaccardBps(adjOut[u], adjOut[v])
			if sim >= pol.ClusterSimThresholdBps {
				ufUnion(u, v)
			}
		}
	}

	clustersByRoot := make(map[string][]string)
	for _, id := range unseededAttesters {
		r := ufFind(id)
		clustersByRoot[r] = append(clustersByRoot[r], id)
	}
	clusterRoots := make([]string, 0, len(clustersByRoot))
	for r := range clustersByRoot {
		clusterRoots = append(clusterRoots, r)
	}
	sort.Strings(clusterRoots)

	// Any correlated cluster of size >= 3 with zero incoming seeded edges is capped to 1/k * ClusterPenaltyBps.
	clusterScaleNum := make(map[string]int64) // attester => multiplier in bps (out of BpsScale)
	sybilClusterCount := 0
	for _, r := range clusterRoots {
		members := clustersByRoot[r]
		sort.Strings(members)
		if len(members) < 3 {
			continue
		}
		extSeedIn := 0
		for _, m := range members {
			for src := range adjIn[m] {
				if isSeed[src] {
					extSeedIn++
				}
			}
		}
		if extSeedIn == 0 {
			sybilClusterCount++
			perMemberBps := pol.ClusterPenaltyBps / int64(len(members))
			res.CollusionFindings = append(res.CollusionFindings, CollusionFinding{
				FindingID:    fmt.Sprintf("sybil_cluster_%02d", sybilClusterCount),
				ErrorCode:    ErrSybilClusterCapped,
				Members:      members,
				DiscountBps:  perMemberBps,
				ExternalIn:   extSeedIn,
				InternalEdge: len(members),
			})
			for _, m := range members {
				clusterScaleNum[m] = perMemberBps
			}
		}
	}

	// Aggregate discounted effective edge weights w'[u][v] and raw totals in fixed-point integer units.
	// Using rawOutTotal as the normalization denominator ensures discounted collusion/Sybil edges
	// genuinely leak mass back to the pre-trusted seed vector rather than renormalizing back to 100%!
	effWeights := make(map[string]map[string]int64, len(allIDs))
	outTotal := make(map[string]int64, len(allIDs))
	rawOutTotal := make(map[string]int64, len(allIDs))
	for _, id := range allIDs {
		effWeights[id] = make(map[string]int64)
	}
	for _, e := range validEdges {
		rawOutTotal[e.attester] += e.weightBps
		w := e.weightBps
		if d, ok := ringEdgeDiscount[e.attester+"->"+e.recipient]; ok {
			w = (w * d) / BpsScale
		}
		if cScale, ok := clusterScaleNum[e.attester]; ok {
			w = (w * cScale) / BpsScale
		}
		res.AttestationVerdicts[e.verdictIx].EffectiveWeightBps = w
		if w > 0 {
			effWeights[e.attester][e.recipient] += w
			outTotal[e.attester] += w
		}
	}

	// Step 3: Fixed-point Seeded EigenTrust power iteration (zero floats!).
	seedVec := make(map[string]int64, len(allIDs))
	if len(seeds) > 0 {
		base := MicroScale / int64(len(seeds))
		rem := MicroScale - base*int64(len(seeds))
		for i, s := range seeds {
			seedVec[s] = base
			if i == 0 {
				seedVec[s] += rem
			}
		}
	}

	// Precompute sub-stochastic transition matrix C[i][j] = floor(w'[i][j] * MicroScale / rawOutTotal[i]).
	// Any unallocated row mass (MicroScale - sum_j C[i][j]) from discounted collusion/Sybil edges
	// teleports deterministically to seedVec during power iteration.
	rowTrans := make(map[string]map[string]int64, len(allIDs))
	rowLeak := make(map[string]int64, len(allIDs))
	for _, u := range allIDs {
		rawTot := rawOutTotal[u]
		if rawTot == 0 || outTotal[u] == 0 {
			rowLeak[u] = MicroScale
			continue
		}
		rowTrans[u] = make(map[string]int64, len(effWeights[u]))
		nbrs := make([]string, 0, len(effWeights[u]))
		for v := range effWeights[u] {
			nbrs = append(nbrs, v)
		}
		sort.Strings(nbrs)
		var sumRow int64
		for _, v := range nbrs {
			cVal := (effWeights[u][v] * MicroScale) / rawTot
			rowTrans[u][v] = cVal
			sumRow += cVal
		}
		// Only assign integer rounding remainder when the node had no collusion/Sybil discount.
		if outTotal[u] == rawTot {
			if rem := MicroScale - sumRow; rem > 0 && len(nbrs) > 0 {
				rowTrans[u][nbrs[0]] += rem
				sumRow += rem
			}
		}
		rowLeak[u] = MicroScale - sumRow
	}

	trust := make(map[string]int64, len(allIDs))
	for _, id := range allIDs {
		trust[id] = seedVec[id]
	}

	alpha := pol.EigenTrustDampingBps
	oneMinusAlpha := BpsScale - alpha
	iters := pol.EigenTrustIterations
	if iters <= 0 {
		iters = 40
	}

	for iter := 0; iter < iters; iter++ {
		nextTrust := make(map[string]int64, len(allIDs))
		var danglingMass int64
		for _, u := range allIDs {
			tu := trust[u]
			if tu == 0 {
				continue
			}
			if leak := rowLeak[u]; leak > 0 {
				danglingMass += (tu * leak) / MicroScale
			}
			if len(rowTrans[u]) == 0 {
				continue
			}
			nbrs := make([]string, 0, len(rowTrans[u]))
			for v := range rowTrans[u] {
				nbrs = append(nbrs, v)
			}
			sort.Strings(nbrs)
			for _, v := range nbrs {
				nextTrust[v] += (tu * rowTrans[u][v]) / MicroScale
			}
		}
		for _, v := range allIDs {
			propagated := nextTrust[v] + (danglingMass*seedVec[v])/MicroScale
			val := (oneMinusAlpha*seedVec[v])/BpsScale + (alpha*propagated)/BpsScale
			nextTrust[v] = val
		}
		trust = nextTrust
	}

	// Compute final ZooRep points (fixed-point micro-REP -> integer ZooRep points)
	// and Naive baseline reputation points (50 pts per raw attestation + 50 pts per naive paper).
	for _, id := range allIDs {
		et := trust[id]
		res.EigenTrustMicro[id] = et

		var gateBps int64
		if pol.TrustFullGateMicro > 0 {
			gateBps = (et * BpsScale) / pol.TrustFullGateMicro
			if gateBps > BpsScale {
				gateBps = BpsScale
			}
		} else {
			gateBps = BpsScale
		}
		res.TrustGateBps[id] = gateBps

		attrMicro := dag.AttributionMicro[id]
		gatedAttrMicro := (attrMicro * gateBps) / BpsScale
		repMicro := et*pol.TrustRepMultiplier + gatedAttrMicro*pol.AttrRepMultiplier
		res.ReputationMicro[id] = repMicro
		res.ZooRepPoints[id] = repMicro / MicroScale

		// Naive reputation: unweighted attestation count * 100 + naive attribution * 50.
		naivePts := int64(res.NaiveAttestCount[id])*100 + (dag.NaiveAttributionMicro[id]*50)/MicroScale
		res.NaiveRepPoints[id] = naivePts
	}

	return res
}

func targetSetJaccardBps(a, b map[string]bool) int64 {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	inter := 0
	for k := range a {
		if b[k] {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return (int64(inter) * BpsScale) / int64(union)
}

// tarjanSCC computes strongly connected components deterministically over sorted nodes.
func tarjanSCC(nodes []string, adj map[string]map[string]bool) [][]string {
	index := 0
	indices := make(map[string]int, len(nodes))
	lowlink := make(map[string]int, len(nodes))
	onStack := make(map[string]bool, len(nodes))
	stack := make([]string, 0, len(nodes))
	var sccs [][]string

	var strongConnect func(v string)
	strongConnect = func(v string) {
		index++
		indices[v] = index
		lowlink[v] = index
		stack = append(stack, v)
		onStack[v] = true

		nbrs := make([]string, 0, len(adj[v]))
		for w := range adj[v] {
			nbrs = append(nbrs, w)
		}
		sort.Strings(nbrs)

		for _, w := range nbrs {
			if indices[w] == 0 {
				strongConnect(w)
				if lowlink[w] < lowlink[v] {
					lowlink[v] = lowlink[w]
				}
			} else if onStack[w] {
				if indices[w] < lowlink[v] {
					lowlink[v] = indices[w]
				}
			}
		}

		if lowlink[v] == indices[v] {
			var comp []string
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				comp = append(comp, w)
				if w == v {
					break
				}
			}
			sort.Strings(comp)
			sccs = append(sccs, comp)
		}
	}

	for _, v := range nodes {
		if indices[v] == 0 {
			strongConnect(v)
		}
	}

	sort.Slice(sccs, func(i, j int) bool {
		return sccs[i][0] < sccs[j][0]
	})
	return sccs
}

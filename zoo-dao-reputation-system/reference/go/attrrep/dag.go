// SPDX-License-Identifier: Apache-2.0

package attrrep

import (
	"sort"
)

// DAGResult holds deterministic contribution verdicts and author attribution credits.
type DAGResult struct {
	Verdicts                  []ContributionVerdict
	AcceptedByID              map[string]Contribution
	VerdictByID               map[string]ContributionVerdict
	AttributionMicro          map[string]int64
	NaiveAttributionMicro     map[string]int64
	UpstreamCitationMicro     map[string]int64
	AcceptedCountByAuthor     map[string]int
	RejectedCountByAuthor     map[string]int
	TotalIntrinsicMicro       int64
	TotalAttributedMicro      int64
	TotalNaiveAttributedMicro int64
}

// EvaluateDAG verifies all contributions, enforces causality/anti-copy rules,
// and computes conserved novelty-weighted Shapley/citation-flow attribution.
func EvaluateDAG(bundle SuiteBundle, idMap map[string]Identity) DAGResult {
	pol := bundle.Policy

	// Sort contributions deterministically by (LedgerSeq, ContributionID).
	contribs := make([]Contribution, len(bundle.Contributions))
	copy(contribs, bundle.Contributions)
	sort.Slice(contribs, func(i, j int) bool {
		if contribs[i].LedgerSeq != contribs[j].LedgerSeq {
			return contribs[i].LedgerSeq < contribs[j].LedgerSeq
		}
		return contribs[i].ContributionID < contribs[j].ContributionID
	})

	contribByID := make(map[string]Contribution, len(contribs))
	for _, c := range contribs {
		contribByID[c.ContributionID] = c
	}

	// Global DAG cycle detection (Kahn's algorithm on parent -> child edges).
	cycleNodes := detectCycleNodes(contribs, contribByID)

	res := DAGResult{
		Verdicts:              make([]ContributionVerdict, 0, len(contribs)),
		AcceptedByID:          make(map[string]Contribution),
		VerdictByID:           make(map[string]ContributionVerdict, len(contribs)),
		AttributionMicro:      make(map[string]int64),
		NaiveAttributionMicro: make(map[string]int64),
		UpstreamCitationMicro: make(map[string]int64),
		AcceptedCountByAuthor: make(map[string]int),
		RejectedCountByAuthor: make(map[string]int),
	}

	seenRaw := make(map[string]string)
	seenCanonical := make(map[string]string)
	globalShingles := make(map[string]struct{})
	acceptedOrder := make([]Contribution, 0, len(contribs))
	var maxAcceptedTS int64

	recordVerdict := func(v ContributionVerdict) {
		res.Verdicts = append(res.Verdicts, v)
		res.VerdictByID[v.ContributionID] = v
		if v.Status == StatusAccepted {
			res.AcceptedCountByAuthor[v.AuthorID]++
		} else {
			res.RejectedCountByAuthor[v.AuthorID]++
		}
	}

	for _, c := range contribs {
		v := ContributionVerdict{
			ContributionID: c.ContributionID,
			AuthorID:       c.AuthorID,
			ScenarioTag:    c.ScenarioTag,
		}

		// 1. Identity existence.
		ident, ok := idMap[c.AuthorID]
		if !ok {
			v.Status = StatusRejected
			v.ErrorCode = ErrUnknownIdentity
			recordVerdict(v)
			continue
		}

		// 2. Ed25519 signature check.
		if !VerifyContributionSignature(c, ident.PublicKey) {
			v.Status = StatusRejected
			v.ErrorCode = ErrInvalidSignature
			recordVerdict(v)
			continue
		}

		// Naive baseline credits every cryptographically signed submission blindly
		// (ignoring deduplication, reformatted copies, and patch-plagiarism).
		res.NaiveAttributionMicro[c.AuthorID] += c.BaseValueMicro
		res.TotalNaiveAttributedMicro += c.BaseValueMicro

		// 3. Content & Winnowing fingerprint integrity.
		fp := ComputeFingerprints(c.Content)
		if fp.RawSHA256 != c.RawSHA256 || fp.CanonicalDigest != c.CanonicalDigest {
			v.Status = StatusRejected
			v.ErrorCode = ErrContentDigestMismatch
			recordVerdict(v)
			continue
		}
		if fp.FingerprintDigest != c.FingerprintDigest || !stringSlicesEqual(fp.WinnowFingerprint, c.WinnowFingerprint) {
			v.Status = StatusRejected
			v.ErrorCode = ErrFingerprintMismatch
			recordVerdict(v)
			continue
		}

		// 4. Causality cycle check.
		if cycleNodes[c.ContributionID] {
			v.Status = StatusRejected
			v.ErrorCode = ErrCausalityCycle
			recordVerdict(v)
			continue
		}

		// 5. Ledger timestamp monotonicity & parent causality checks.
		if len(acceptedOrder) > 0 && c.Timestamp < maxAcceptedTS-pol.MaxClockSkewSec {
			v.Status = StatusRejected
			v.ErrorCode = ErrTimestampBackdate
			recordVerdict(v)
			continue
		}

		sortedParents := make([]string, len(c.Parents))
		copy(sortedParents, c.Parents)
		sort.Strings(sortedParents)

		parentErr := ErrNone
		for _, pid := range sortedParents {
			p, exists := contribByID[pid]
			if !exists {
				parentErr = ErrUnknownParent
				break
			}
			if p.Timestamp > c.Timestamp || p.Epoch > c.Epoch || p.LedgerSeq >= c.LedgerSeq {
				parentErr = ErrTimestampBackdate
				break
			}
			if _, accepted := res.AcceptedByID[pid]; !accepted {
				parentErr = ErrUnknownParent
				break
			}
		}
		if parentErr != ErrNone {
			v.Status = StatusRejected
			v.ErrorCode = parentErr
			recordVerdict(v)
			continue
		}

		// 6. Exact verbatim duplicate check.
		if origID, dup := seenRaw[c.RawSHA256]; dup {
			v.Status = StatusRejected
			v.ErrorCode = ErrDuplicateContribution
			v.CanonicalOriginID = origID
			v.BestMatchID = origID
			v.BestOverlapBps = BpsScale
			v.NoveltyBps = 0
			recordVerdict(v)
			continue
		}

		// 7. Reformatted / comment / LaTeX-macro copy check.
		if origID, dup := seenCanonical[c.CanonicalDigest]; dup {
			v.Status = StatusRejected
			v.ErrorCode = ErrReformattedCopy
			v.CanonicalOriginID = origID
			v.BestMatchID = origID
			v.BestOverlapBps = BpsScale
			v.NoveltyBps = 0
			recordVerdict(v)
			continue
		}

		// 8. Near-duplicate / patch-plagiarism Winnowing overlap check.
		var bestMatchID string
		var bestOverlapBps int64 = -1
		for _, prev := range acceptedOrder {
			ov := ContainmentBps(c.WinnowFingerprint, prev.WinnowFingerprint)
			if ov > bestOverlapBps || (ov == bestOverlapBps && (bestMatchID == "" || prev.ContributionID < bestMatchID)) {
				bestOverlapBps = ov
				bestMatchID = prev.ContributionID
			}
		}
		if bestOverlapBps < 0 {
			bestOverlapBps = 0
		}

		unionOverlapCount := 0
		for _, h := range c.WinnowFingerprint {
			if _, seen := globalShingles[h]; seen {
				unionOverlapCount++
			}
		}
		var unionOverlapBps int64
		if len(c.WinnowFingerprint) > 0 {
			unionOverlapBps = (int64(unionOverlapCount) * BpsScale) / int64(len(c.WinnowFingerprint))
		}
		noveltyBps := BpsScale - unionOverlapBps
		if noveltyBps < 0 {
			noveltyBps = 0
		}

		v.BestMatchID = bestMatchID
		v.BestOverlapBps = bestOverlapBps
		v.NoveltyBps = noveltyBps

		// Reject high-overlap near-duplicate / patch-plagiarism copies.
		if bestOverlapBps >= pol.NearDuplicateRejectBps {
			v.Status = StatusRejected
			v.ErrorCode = ErrNearDuplicateCopy
			v.CanonicalOriginID = bestMatchID
			recordVerdict(v)
			continue
		}
		// Reject undeclared copies (>= UndeclaredCopyRejectBps without citing matched ancestor).
		if bestOverlapBps >= pol.UndeclaredCopyRejectBps && !containsString(sortedParents, bestMatchID) {
			v.Status = StatusRejected
			v.ErrorCode = ErrUndeclaredCopy
			v.CanonicalOriginID = bestMatchID
			recordVerdict(v)
			continue
		}
		// Reject blatant novelty overclaiming on high-overlap patch copies.
		if c.ClaimedNoveltyBps > 0 && bestOverlapBps >= 6500 && (c.ClaimedNoveltyBps-noveltyBps) > pol.NoveltyOverclaimGapBps {
			v.Status = StatusRejected
			v.ErrorCode = ErrNearDuplicateCopy
			v.CanonicalOriginID = bestMatchID
			recordVerdict(v)
			continue
		}

		// 9. ACCEPT contribution with conserved novelty-weighted DAG attribution.
		intrinsicMicro := (c.BaseValueMicro * noveltyBps) / BpsScale
		var upstreamFlowMicro int64
		if len(sortedParents) > 0 {
			upstreamFlowMicro = (intrinsicMicro * pol.UpstreamFlowBps) / BpsScale
		}
		selfCreditMicro := intrinsicMicro - upstreamFlowMicro

		res.AttributionMicro[c.AuthorID] += selfCreditMicro
		res.TotalIntrinsicMicro += intrinsicMicro
		res.TotalAttributedMicro += selfCreditMicro

		// Distribute upstreamFlowMicro conservatively across declared canonical parents.
		if len(sortedParents) > 0 && upstreamFlowMicro > 0 {
			type parentWeight struct {
				id       string
				authorID string
				weight   int64
			}
			pws := make([]parentWeight, len(sortedParents))
			var totalWeight int64
			for idx, pid := range sortedParents {
				p := res.AcceptedByID[pid]
				w := ContainmentBps(c.WinnowFingerprint, p.WinnowFingerprint) + 1000
				pws[idx] = parentWeight{id: pid, authorID: p.AuthorID, weight: w}
				totalWeight += w
			}

			var distributed int64
			bestIdx := 0
			for idx, pw := range pws {
				share := (upstreamFlowMicro * pw.weight) / totalWeight
				res.AttributionMicro[pw.authorID] += share
				res.UpstreamCitationMicro[pw.authorID] += share
				res.TotalAttributedMicro += share
				distributed += share
				if pw.weight > pws[bestIdx].weight || (pw.weight == pws[bestIdx].weight && pw.id < pws[bestIdx].id) {
					bestIdx = idx
				}
			}
			rem := upstreamFlowMicro - distributed
			if rem > 0 {
				res.AttributionMicro[pws[bestIdx].authorID] += rem
				res.UpstreamCitationMicro[pws[bestIdx].authorID] += rem
				res.TotalAttributedMicro += rem
			}
		}

		v.Status = StatusAccepted
		v.ErrorCode = ErrNone
		v.CanonicalOriginID = c.ContributionID
		v.IntrinsicMicro = intrinsicMicro
		v.SelfCreditMicro = selfCreditMicro
		v.UpstreamFlowMicro = upstreamFlowMicro
		recordVerdict(v)

		res.AcceptedByID[c.ContributionID] = c
		seenRaw[c.RawSHA256] = c.ContributionID
		seenCanonical[c.CanonicalDigest] = c.ContributionID
		for _, h := range c.WinnowFingerprint {
			globalShingles[h] = struct{}{}
		}
		acceptedOrder = append(acceptedOrder, c)
		if c.Timestamp > maxAcceptedTS {
			maxAcceptedTS = c.Timestamp
		}
	}

	return res
}

// detectCycleNodes returns the set of contribution IDs participating in or
// blocked by any directed parent->child cycle (including self-loops).
func detectCycleNodes(contribs []Contribution, byID map[string]Contribution) map[string]bool {
	inDegree := make(map[string]int, len(contribs))
	children := make(map[string][]string, len(contribs))
	selfLoop := make(map[string]bool)

	for _, c := range contribs {
		inDegree[c.ContributionID] = 0
	}
	for _, c := range contribs {
		seenP := make(map[string]bool)
		for _, pid := range c.Parents {
			if pid == c.ContributionID {
				selfLoop[c.ContributionID] = true
				continue
			}
			if seenP[pid] {
				continue
			}
			seenP[pid] = true
			if _, ok := byID[pid]; ok {
				children[pid] = append(children[pid], c.ContributionID)
				inDegree[c.ContributionID]++
			}
		}
	}

	// Deterministic Kahn's topological peel.
	queue := make([]string, 0, len(contribs))
	for _, c := range contribs {
		if inDegree[c.ContributionID] == 0 && !selfLoop[c.ContributionID] {
			queue = append(queue, c.ContributionID)
		}
	}
	sort.Strings(queue)

	visited := make(map[string]bool, len(contribs))
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		visited[u] = true
		kids := children[u]
		sort.Strings(kids)
		for _, v := range kids {
			inDegree[v]--
			if inDegree[v] == 0 && !selfLoop[v] {
				queue = append(queue, v)
			}
		}
	}

	cycles := make(map[string]bool)
	for _, c := range contribs {
		if selfLoop[c.ContributionID] || !visited[c.ContributionID] {
			cycles[c.ContributionID] = true
		}
	}
	return cycles
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsString(list []string, target string) bool {
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}

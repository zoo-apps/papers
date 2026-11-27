// SPDX-License-Identifier: Apache-2.0

package attrrep

import (
	"fmt"
	"sort"
)

// VerifySuite runs the complete deterministic attribution & Sybil-resistant
// reputation verification pipeline on a SuiteBundle and computes audit_merkle_root.
func VerifySuite(bundle SuiteBundle) (VerificationReport, error) {
	idMap := make(map[string]Identity, len(bundle.Identities))
	allIDs := make([]string, 0, len(bundle.Identities))
	for _, ident := range bundle.Identities {
		idMap[ident.ID] = ident
		allIDs = append(allIDs, ident.ID)
	}
	sort.Strings(allIDs)

	dag := EvaluateDAG(bundle, idMap)
	rep := EvaluateReputation(bundle, idMap, dag)

	// Build deterministic IdentitySummaries.
	summaries := make([]IdentitySummary, 0, len(allIDs))
	for _, id := range allIDs {
		ident := idMap[id]
		pts := rep.ZooRepPoints[id]
		tier, tierWeight := ZooTierForPoints(pts)
		summaries = append(summaries, IdentitySummary{
			IdentityID:            id,
			Role:                  ident.Role,
			AcceptedContributions: dag.AcceptedCountByAuthor[id],
			RejectedContributions: dag.RejectedCountByAuthor[id],
			AttributionMicro:      dag.AttributionMicro[id],
			NaiveAttributionMicro: dag.NaiveAttributionMicro[id],
			UpstreamCitationMicro: dag.UpstreamCitationMicro[id],
			EigenTrustMicro:       rep.EigenTrustMicro[id],
			TrustGateBps:          rep.TrustGateBps[id],
			ReputationMicro:       rep.ReputationMicro[id],
			ZooRepPoints:          pts,
			Tier:                  tier,
			TierWeightBps:         tierWeight,
			NaiveAttestationCount: rep.NaiveAttestCount[id],
			NaiveReputationPoints: rep.NaiveRepPoints[id],
		})
	}

	// Deterministic dense ranking for Sybil-resistant reputation.
	repOrder := make([]int, len(summaries))
	naiveOrder := make([]int, len(summaries))
	for i := range summaries {
		repOrder[i] = i
		naiveOrder[i] = i
	}
	sort.Slice(repOrder, func(a, b int) bool {
		ia, ib := summaries[repOrder[a]], summaries[repOrder[b]]
		if ia.ReputationMicro != ib.ReputationMicro {
			return ia.ReputationMicro > ib.ReputationMicro
		}
		if ia.AttributionMicro != ib.AttributionMicro {
			return ia.AttributionMicro > ib.AttributionMicro
		}
		return ia.IdentityID < ib.IdentityID
	})
	for rank, idx := range repOrder {
		summaries[idx].ReputationRank = rank + 1
	}

	sort.Slice(naiveOrder, func(a, b int) bool {
		ia, ib := summaries[naiveOrder[a]], summaries[naiveOrder[b]]
		if ia.NaiveReputationPoints != ib.NaiveReputationPoints {
			return ia.NaiveReputationPoints > ib.NaiveReputationPoints
		}
		if ia.NaiveAttestationCount != ib.NaiveAttestationCount {
			return ia.NaiveAttestationCount > ib.NaiveAttestationCount
		}
		return ia.IdentityID < ib.IdentityID
	})
	for rank, idx := range naiveOrder {
		summaries[idx].NaiveReputationRank = rank + 1
	}

	// Evaluate adversarial expectations if embedded in the bundle.
	attByUID := make(map[string]AttestationVerdict, len(rep.AttestationVerdicts))
	for _, av := range rep.AttestationVerdicts {
		attByUID[av.UID] = av
	}
	attByTag := make(map[string]AttestationVerdict, len(rep.AttestationVerdicts))
	for _, av := range rep.AttestationVerdicts {
		if av.ScenarioTag != "" {
			attByTag[av.ScenarioTag] = av
		}
	}
	findingByMember := make(map[string]CollusionFinding)
	for _, cf := range rep.CollusionFindings {
		for _, m := range cf.Members {
			if _, exists := findingByMember[m]; !exists {
				findingByMember[m] = cf
			}
		}
	}

	advResults := make([]AdversarialCheckResult, 0, len(bundle.AdversarialExpectations))
	advPassed := 0
	for _, exp := range bundle.AdversarialExpectations {
		ar := AdversarialCheckResult{
			AttackID:        exp.AttackID,
			Category:        exp.Category,
			TargetID:        exp.TargetID,
			ExpectedStatus:  exp.ExpectedStatus,
			ExpectedErrCode: exp.ExpectedErrCode,
		}
		switch exp.TargetType {
		case "contribution":
			if cv, ok := dag.VerdictByID[exp.TargetID]; ok {
				ar.ActualStatus = cv.Status
				ar.ActualErrCode = cv.ErrorCode
			} else {
				ar.ActualStatus = "MISSING"
			}
		case "attestation":
			if av, ok := attByUID[exp.TargetID]; ok {
				ar.ActualStatus = av.Status
				ar.ActualErrCode = av.ErrorCode
			} else if av, ok := attByTag[exp.TargetID]; ok {
				ar.ActualStatus = av.Status
				ar.ActualErrCode = av.ErrorCode
			} else {
				ar.ActualStatus = "MISSING"
			}
		case "cluster":
			if cf, ok := findingByMember[exp.TargetID]; ok {
				ar.ActualStatus = "DISCOUNTED"
				ar.ActualErrCode = cf.ErrorCode
			} else {
				ar.ActualStatus = "UNDETECTED"
			}
		default:
			ar.ActualStatus = "UNKNOWN_TARGET_TYPE"
		}
		ar.Passed = ar.ActualStatus == ar.ExpectedStatus && ar.ActualErrCode == ar.ExpectedErrCode
		if ar.Passed {
			advPassed++
		}
		advResults = append(advResults, ar)
	}

	// Build canonical Merkle leaves for bit-identical Go <-> Python audit_merkle_root.
	leaves, err := buildAuditMerkleLeaves(dag.Verdicts, rep.AttestationVerdicts, rep.CollusionFindings, summaries)
	if err != nil {
		return VerificationReport{}, err
	}
	merkleRoot := MerkleRoot(leaves)

	acceptedContribs := 0
	rejectedContribs := 0
	for _, cv := range dag.Verdicts {
		if cv.Status == StatusAccepted {
			acceptedContribs++
		} else {
			rejectedContribs++
		}
	}

	return VerificationReport{
		SchemaVersion:             SchemaVersion,
		SpecVersion:               SpecVersion,
		SuiteName:                 bundle.SuiteName,
		AuditMerkleRoot:           merkleRoot,
		TotalContributions:        len(dag.Verdicts),
		AcceptedContributions:     acceptedContribs,
		RejectedContributions:     rejectedContribs,
		TotalAttestations:         len(rep.AttestationVerdicts),
		AcceptedAttestations:      rep.AcceptedCount,
		AdvisoryAttestations:      rep.AdvisoryCount,
		RejectedAttestations:      rep.RejectedCount,
		TotalIntrinsicMicro:       dag.TotalIntrinsicMicro,
		TotalAttributedMicro:      dag.TotalAttributedMicro,
		TotalNaiveAttributedMicro: dag.TotalNaiveAttributedMicro,
		ConservationExact:         dag.TotalIntrinsicMicro == dag.TotalAttributedMicro,
		AdversarialPassed:         advPassed,
		AdversarialTotal:          len(bundle.AdversarialExpectations),
		ContributionVerdicts:      dag.Verdicts,
		AttestationVerdicts:       rep.AttestationVerdicts,
		CollusionFindings:         rep.CollusionFindings,
		IdentitySummaries:         summaries,
		AdversarialResults:        advResults,
	}, nil
}

func buildAuditMerkleLeaves(
	cVerdicts []ContributionVerdict,
	aVerdicts []AttestationVerdict,
	findings []CollusionFinding,
	summaries []IdentitySummary,
) ([][]byte, error) {
	leaves := make([][]byte, 0, len(cVerdicts)+len(aVerdicts)+len(findings)+len(summaries))

	// Sort each section canonically before serializing leaf payloads.
	cvSorted := make([]ContributionVerdict, len(cVerdicts))
	copy(cvSorted, cVerdicts)
	sort.Slice(cvSorted, func(i, j int) bool {
		return cvSorted[i].ContributionID < cvSorted[j].ContributionID
	})
	for _, cv := range cvSorted {
		b, err := CanonicalJSON(map[string]any{
			"canonical_origin_id": cv.CanonicalOriginID,
			"contribution_id":     cv.ContributionID,
			"error_code":          cv.ErrorCode,
			"intrinsic_micro":     cv.IntrinsicMicro,
			"kind":                "contribution",
			"novelty_bps":         cv.NoveltyBps,
			"self_credit_micro":   cv.SelfCreditMicro,
			"status":              cv.Status,
			"upstream_flow_micro": cv.UpstreamFlowMicro,
		})
		if err != nil {
			return nil, fmt.Errorf("canonical contribution leaf: %w", err)
		}
		leaves = append(leaves, b)
	}

	avSorted := make([]AttestationVerdict, len(aVerdicts))
	copy(avSorted, aVerdicts)
	sort.Slice(avSorted, func(i, j int) bool {
		if avSorted[i].UID != avSorted[j].UID {
			return avSorted[i].UID < avSorted[j].UID
		}
		if avSorted[i].Attester != avSorted[j].Attester {
			return avSorted[i].Attester < avSorted[j].Attester
		}
		return avSorted[i].Status < avSorted[j].Status
	})
	for _, av := range avSorted {
		b, err := CanonicalJSON(map[string]any{
			"attester":             av.Attester,
			"effective_weight_bps": av.EffectiveWeightBps,
			"error_code":           av.ErrorCode,
			"kind":                 "attestation",
			"recipient":            av.Recipient,
			"status":               av.Status,
			"uid":                  av.UID,
		})
		if err != nil {
			return nil, fmt.Errorf("canonical attestation leaf: %w", err)
		}
		leaves = append(leaves, b)
	}

	cfSorted := make([]CollusionFinding, len(findings))
	copy(cfSorted, findings)
	sort.Slice(cfSorted, func(i, j int) bool {
		return cfSorted[i].FindingID < cfSorted[j].FindingID
	})
	for _, cf := range cfSorted {
		b, err := CanonicalJSON(map[string]any{
			"discount_bps":   cf.DiscountBps,
			"error_code":     cf.ErrorCode,
			"external_in":    cf.ExternalIn,
			"finding_id":     cf.FindingID,
			"internal_edges": cf.InternalEdge,
			"kind":           "collusion",
			"members":        cf.Members,
		})
		if err != nil {
			return nil, fmt.Errorf("canonical collusion leaf: %w", err)
		}
		leaves = append(leaves, b)
	}

	for _, s := range summaries {
		b, err := CanonicalJSON(map[string]any{
			"attribution_micro": s.AttributionMicro,
			"eigentrust_micro":  s.EigenTrustMicro,
			"identity_id":       s.IdentityID,
			"kind":              "identity",
			"reputation_micro":  s.ReputationMicro,
			"reputation_rank":   s.ReputationRank,
			"tier":              s.Tier,
			"tier_weight_bps":   s.TierWeightBps,
			"zoo_rep_points":    s.ZooRepPoints,
		})
		if err != nil {
			return nil, fmt.Errorf("canonical identity leaf: %w", err)
		}
		leaves = append(leaves, b)
	}

	return leaves, nil
}

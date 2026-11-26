// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation

package verifier

import (
	"fmt"
	"sort"
	"strings"
)

func (v *Verifier) verifyReasoningChain(claim EvidenceClaim, resolvedVerdicts map[string]Verdict) VerificationResult {
	rc := claim.ReasoningChain
	if rc == nil {
		return makeResult(claim, VerdictUnsupported, ReasonMissingPayload, "reasoning_chain payload missing", "", "")
	}
	if rc.ReviewScope == "external_domain" || rc.ReviewScope == "subjective_judgment" {
		return makeResult(claim, VerdictInconclusive, ReasonHumanReviewRequired, "reasoning chain requires external domain or subjective human review", "", "")
	}
	if len(rc.Steps) == 0 || strings.TrimSpace(rc.ConclusionStepID) == "" {
		return makeResult(claim, VerdictUnsupported, ReasonEmptyReasoningChain, "reasoning chain missing steps or conclusion_step_id", "", "")
	}

	stepMap := make(map[string]ReasoningStep, len(rc.Steps))
	stepIDs := make([]string, 0, len(rc.Steps))
	for _, st := range rc.Steps {
		if _, exists := stepMap[st.StepID]; exists {
			return makeResult(claim, VerdictRefuted, ReasonDuplicateStepID, fmt.Sprintf("duplicate step_id: %s", st.StepID), "", "")
		}
		stepMap[st.StepID] = st
		stepIDs = append(stepIDs, st.StepID)
	}
	sort.Strings(stepIDs)

	if _, ok := stepMap[rc.ConclusionStepID]; !ok {
		return makeResult(claim, VerdictUnsupported, ReasonMissingConclusion, fmt.Sprintf("conclusion_step_id not found: %s", rc.ConclusionStepID), "", "")
	}

	// Private internal CoT check (sorted step_id order).
	for _, id := range stepIDs {
		st := stepMap[id]
		if st.Kind == "private_cot" || st.OpaqueCoTBlob || strings.TrimSpace(st.PublicRationale) == "" {
			return makeResult(claim, VerdictUnsupported, ReasonPrivateCoTForbidden, fmt.Sprintf("step %s contains private/opaque CoT or lacks public_rationale", id), "", "")
		}
	}

	// Deterministic 3-color DFS cycle detection over sorted step IDs.
	const (
		colorWhite = 0
		colorGray  = 1
		colorBlack = 2
	)
	colors := make(map[string]int, len(stepIDs))
	var hasCycle bool
	var cycleNode string
	var dfs func(id string)
	dfs = func(id string) {
		if hasCycle {
			return
		}
		colors[id] = colorGray
		deps := make([]string, len(stepMap[id].DependsOn))
		copy(deps, stepMap[id].DependsOn)
		sort.Strings(deps)
		for _, dep := range deps {
			if _, ok := stepMap[dep]; !ok {
				continue
			}
			if colors[dep] == colorGray {
				hasCycle = true
				cycleNode = dep
				return
			}
			if colors[dep] == colorWhite {
				dfs(dep)
			}
		}
		colors[id] = colorBlack
	}
	for _, id := range stepIDs {
		if colors[id] == colorWhite {
			dfs(id)
		}
	}
	if hasCycle {
		return makeResult(claim, VerdictRefuted, ReasonReasoningCycle, fmt.Sprintf("circular reasoning dependency detected involving step %s", cycleNode), "", "")
	}

	// Dangling dependency check (sorted step_id order).
	for _, id := range stepIDs {
		deps := make([]string, len(stepMap[id].DependsOn))
		copy(deps, stepMap[id].DependsOn)
		sort.Strings(deps)
		for _, dep := range deps {
			if _, ok := stepMap[dep]; !ok {
				return makeResult(claim, VerdictUnsupported, ReasonDanglingPremise, fmt.Sprintf("step %s references missing dependency %s", id, dep), "", "")
			}
		}
	}

	// Collect all ancestors reachable from conclusion_step_id.
	ancestors := map[string]bool{}
	var collect func(id string)
	collect = func(id string) {
		if ancestors[id] {
			return
		}
		ancestors[id] = true
		for _, dep := range stepMap[id].DependsOn {
			collect(dep)
		}
	}
	collect(rc.ConclusionStepID)

	ancIDs := make([]string, 0, len(ancestors))
	for id := range ancestors {
		ancIDs = append(ancIDs, id)
	}
	sort.Strings(ancIDs)

	// Audit leaf premises in deterministic priority: REFUTED > UNSUPPORTED > INCONCLUSIVE.
	var firstUnsupported string
	var firstInconclusive string
	for _, id := range ancIDs {
		st := stepMap[id]
		if len(st.DependsOn) > 0 {
			continue
		}
		if st.Kind != "premise" || strings.TrimSpace(st.EvidenceRef) == "" {
			if firstUnsupported == "" {
				firstUnsupported = fmt.Sprintf("leaf step %s lacks grounded premise evidence_ref", id)
			}
			continue
		}
		evVerdict := Verdict(strings.TrimSpace(st.EvidenceVerdict))
		if evVerdict == "" && resolvedVerdicts != nil {
			if rv, ok := resolvedVerdicts[st.EvidenceRef]; ok {
				evVerdict = rv
			}
		}
		switch evVerdict {
		case VerdictRefuted:
			return makeResult(claim, VerdictRefuted, ReasonRefutedPremise, fmt.Sprintf("premise %s relies on refuted evidence %s", id, st.EvidenceRef), "", "")
		case VerdictVerified:
			// Grounded!
		case VerdictInconclusive:
			if firstInconclusive == "" {
				firstInconclusive = fmt.Sprintf("premise %s relies on inconclusive evidence %s", id, st.EvidenceRef)
			}
		default:
			if firstUnsupported == "" {
				firstUnsupported = fmt.Sprintf("premise %s relies on unverified evidence %s", id, st.EvidenceRef)
			}
		}
	}
	if firstUnsupported != "" {
		return makeResult(claim, VerdictUnsupported, ReasonUnverifiedPremise, firstUnsupported, "", "")
	}
	if firstInconclusive != "" {
		return makeResult(claim, VerdictInconclusive, ReasonInconclusivePremise, firstInconclusive, "", "")
	}

	return makeResult(claim, VerdictVerified, ReasonOKReasoningChain, fmt.Sprintf("public reasoning DAG verified (%d reachable steps)", len(ancIDs)), fmt.Sprintf("%d", len(ancIDs)), "")
}

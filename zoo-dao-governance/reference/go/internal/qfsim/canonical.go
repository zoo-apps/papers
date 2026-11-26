// SPDX-License-Identifier: Apache-2.0

package qfsim

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const (
	domainCorpus     = "zoo.qfsim.v1.corpus\n"
	domainLeaf       = "zoo.qfsim.v1.leaf\n"
	domainGovernance = "zoo.qfsim.v1.governance\n"
	domainNode       = "zoo.qfsim.v1.node\n"
	domainRoot       = "zoo.qfsim.v1.root\n"
)

func sha256Hex(domain, payload string) string {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

func boolToken(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// HashCorpus computes the deterministic domain-separated SHA-256 digest of the proposal corpus.
func HashCorpus(proposals []GrantProposal) string {
	sorted := make([]GrantProposal, len(proposals))
	copy(sorted, proposals)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})
	var sb strings.Builder
	for _, p := range sorted {
		fmt.Fprintf(&sb, "%s|%s|%s|%s|%s|%d|%s|%s|%s\n",
			p.ID, p.PaperDir, p.TexSHA256, p.Category, p.Archetype,
			p.MeritBPS, boolToken(p.IsAttackerTarget), boolToken(p.IsNewcomerGrant), boolToken(p.IsLabGrant))
	}
	return sha256Hex(domainCorpus, sb.String())
}

// HashEvaluation computes the deterministic leaf hash for one (scenario, mechanism) evaluation.
func HashEvaluation(ev EvaluationResult) string {
	allocs := make([]ProjectAllocation, len(ev.Allocations))
	copy(allocs, ev.Allocations)
	sort.Slice(allocs, func(i, j int) bool {
		return allocs[i].ProjectID < allocs[j].ProjectID
	})

	var sb strings.Builder
	m := ev.Metrics
	g := ev.GovernanceGate
	fmt.Fprintf(&sb, "scenario=%s\nmechanism=%s\npool=%d\n", ev.ScenarioID, ev.MechanismID, ev.MatchingPool)
	fmt.Fprintf(&sb, "conserved=%s|matched=%d|unalloc=%d|att_match=%d|extract=%d|droi=%d|nroi=%d|welfare=%d|grass=%d|minor=%d|gini=%d|lab=%d|newc=%d|whale=%d\n",
		boolToken(m.PoolConserved), m.TotalMatchedMicro, m.UnallocatedPoolMicro,
		m.AttackerMatchMicro, m.PoolExtractionBPS, m.DirectCostROIBPS, m.NetAttackROIBPS,
		m.MeritWelfareBPS, m.GrassrootsShareBPS, m.MinorityShareBPS, m.HonestGiniBPS,
		m.LabShareBPS, m.NewcomerShareBPS, m.WhaleNicheShareBPS)
	fmt.Fprintf(&sb, "gate=%s|%d|%d|%d|%d|%s|%s|%s\n",
		g.PlanStatus, g.RequiredHumanQuorum, g.TreasuryCommitteeSize, g.MinStewardZooRep,
		g.HumanSignaturesCollected, boolToken(g.AIRuleMutationBlocked),
		boolToken(g.AITreasuryAuthBlocked), boolToken(g.AISelfValidationBlocked))
	for _, a := range allocs {
		fmt.Fprintf(&sb, "alloc=%s:%d:%d:%d:%d:%d\n",
			a.ProjectID, a.DirectMicro, a.MatchMicro, a.TotalMicro, a.UniqueDonors, a.MatchShareBPS)
	}
	return sha256Hex(domainLeaf, sb.String())
}

// HashGovernanceChecks computes the deterministic digest of constitutional gate audit checks.
func HashGovernanceChecks(checks []GovernanceCheck) string {
	sorted := make([]GovernanceCheck, len(checks))
	copy(sorted, checks)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].CheckID < sorted[j].CheckID
	})
	var sb strings.Builder
	for _, c := range sorted {
		fmt.Fprintf(&sb, "%s|%s|%s|%d|%s|%s|%s|%d\n",
			c.CheckID, c.ActorID, c.ActorRole, c.ActorZooRep, c.Action,
			boolToken(c.Allowed), c.ReasonCode, c.HumanSigners)
	}
	return sha256Hex(domainGovernance, sb.String())
}

// ComputeMerkleRoot computes a binary SHA-256 Merkle root over ordered lowercase hex hashes.
func ComputeMerkleRoot(hashes []string) string {
	if len(hashes) == 0 {
		return sha256Hex(domainNode, "")
	}
	level := make([]string, len(hashes))
	copy(level, hashes)
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([]string, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next = append(next, sha256Hex(domainNode, level[i]+"\n"+level[i+1]))
		}
		level = next
	}
	return level[0]
}

// ComputeAuditMerkleRoot binds corpus, all evaluation leaves, and constitutional governance checks.
func ComputeAuditMerkleRoot(corpusHash, evalMerkleRoot, governanceHash string) string {
	return sha256Hex(domainRoot, corpusHash+"\n"+evalMerkleRoot+"\n"+governanceHash)
}

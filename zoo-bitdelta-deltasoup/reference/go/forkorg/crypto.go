// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package forkorg

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
)

// KeyPair pairs a Principal descriptor with its Ed25519 private key.
type KeyPair struct {
	Principal Principal
	Private   ed25519.PrivateKey
}

// DeriveKeyPair deterministically derives an Ed25519 keypair for a principal from a seed.
func DeriveKeyPair(seed int64, orgID, id, role string) KeyPair {
	seedInput := fmt.Sprintf("forkable-org.v1:key:%d:%s:%s:%s", seed, orgID, id, role)
	sum := sha256.Sum256([]byte(seedInput))
	priv := ed25519.NewKeyFromSeed(sum[:])
	pub := priv.Public().(ed25519.PublicKey)
	return KeyPair{
		Principal: Principal{
			ID:           id,
			OrgID:        orgID,
			Role:         role,
			PublicKeyHex: hex.EncodeToString(pub),
		},
		Private: priv,
	}
}

// SignCanonical signs domain || 0x00 || CanonicalJSON(payload) with Ed25519.
func SignCanonical(priv ed25519.PrivateKey, domain string, payload any) string {
	msg, err := DomainMessage(domain, payload)
	if err != nil {
		panic(fmt.Sprintf("SignCanonical failed: %v", err))
	}
	sig := ed25519.Sign(priv, msg)
	return hex.EncodeToString(sig)
}

// VerifyCanonical verifies a hex Ed25519 signature over domain || 0x00 || CanonicalJSON(payload).
func VerifyCanonical(pubHex, sigHex, domain string, payload any) bool {
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	msg, err := DomainMessage(domain, payload)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// Canonical hash helpers — each excludes self-hash and signature fields so
// Go and Python compute identical digests and signing preimages.

func ComputeBaseModelHash(b BaseModelSpec) string {
	return HashCanonical(DomainModelBase, map[string]any{
		"dim":              b.Dim,
		"license_id":       b.LicenseID,
		"license_reviewed": b.LicenseReviewed,
		"model_id":         b.ModelID,
		"num_classes":      b.NumClasses,
		"num_features":     b.NumFeatures,
		"weights_micro":    nonNilInt64s(b.WeightsMicro),
	})
}

func BitDeltaSigningPayload(d BitDeltaArtifact) map[string]any {
	return map[string]any{
		"acl_tier":             d.ACLTier,
		"base_checkpoint_hash": d.BaseCheckpointHash,
		"base_model_id":        d.BaseModelID,
		"contributor_id":       d.ContributorID,
		"delta_id":             d.DeltaID,
		"dim":                  d.Dim,
		"license_id":           d.LicenseID,
		"license_reviewed":     d.LicenseReviewed,
		"org_id":               d.OrgID,
		"parent_delta_id":      d.ParentDeltaID,
		"scale_micro":          d.ScaleMicro,
		"sign_bits_hex":        d.SignBitsHex,
		"training_record_ids":  nonNilStrings(d.TrainingRecordIDs),
	}
}

func ComputeBitDeltaHash(d BitDeltaArtifact) string {
	return HashCanonical(DomainBitDelta, BitDeltaSigningPayload(d))
}

func ComputeDeltaSoupHash(s DeltaSoupArtifact) string {
	return HashCanonical(DomainDeltaSoup, map[string]any{
		"accepted_contributor_ids": nonNilStrings(s.AcceptedContributorIDs),
		"base_checkpoint_hash":     s.BaseCheckpointHash,
		"base_model_id":            s.BaseModelID,
		"contributor_delta_ids":    nonNilStrings(s.ContributorDeltaIDs),
		"org_id":                   s.OrgID,
		"result_delta_hash":        s.ResultDelta.DeltaHash,
		"royalty_shares":           nonNilRoyalties(s.RoyaltyShares),
		"soup_id":                  s.SoupID,
		"step_bps":                 s.StepBps,
		"trim_bps":                 s.TrimBps,
	})
}

func ComputeModelRegistryRoot(m ModelRegistry) string {
	leaves := make([]string, 0, 1+len(m.Deltas)+len(m.Soups))
	leaves = append(leaves, "base:"+m.BaseModel.WeightsHash)
	for _, d := range m.Deltas {
		leaves = append(leaves, "delta:"+d.DeltaHash)
	}
	for _, s := range m.Soups {
		leaves = append(leaves, "soup:"+s.SoupHash)
	}
	return MerkleRootRFC6962(leaves)
}

func ResearchRecordSigningPayload(r ResearchRecord) map[string]any {
	return map[string]any{
		"acl_tier":         r.ACLTier,
		"author_id":        r.AuthorID,
		"kind":             r.Kind,
		"license_id":       r.LicenseID,
		"license_reviewed": r.LicenseReviewed,
		"org_id":           r.OrgID,
		"payload_hash":     r.PayloadHash,
		"payload_summary":  r.PayloadSummary,
		"prev_hash":        r.PrevHash,
		"record_id":        r.RecordID,
		"seq":              r.Seq,
	}
}

func ComputeResearchRecordHash(r ResearchRecord) string {
	return HashCanonical(DomainResearchRecord, ResearchRecordSigningPayload(r))
}

func ComputeResearchHistoryRoot(records []ResearchRecord) string {
	leaves := make([]string, len(records))
	for i, r := range records {
		leaves[i] = r.RecordHash
	}
	return MerkleRootRFC6962(leaves)
}

func ComputePolicyHash(p PolicyManifest) string {
	return HashCanonical(DomainPolicyManifest, map[string]any{
		"ai_agent_boundaries":        p.AIAgentBoundaries,
		"allowed_licenses":           nonNilStrings(p.AllowedLicenses),
		"authorized_principals":      nonNilPrincipals(p.AuthorizedPrincipals),
		"conservation_tithe_bps":     p.ConservationTitheBps,
		"min_accuracy_gain_bps":      p.MinAccuracyGainBps,
		"min_council_approvals":      p.MinCouncilApprovals,
		"min_safety_bps":             p.MinSafetyBps,
		"org_id":                     p.OrgID,
		"policy_version":             p.PolicyVersion,
		"treasury_spend_limit_micro": p.TreasurySpendLimitMicro,
		"voting_quorum_bps":          p.VotingQuorumBps,
	})
}

func ComputeACLPolicyHash(a AccessControlPolicy) string {
	return HashCanonical(DomainACLPolicy, map[string]any{
		"cross_org_delegations": nonNilDelegations(a.CrossOrgDelegations),
		"default_tier":          a.DefaultTier,
		"grants":                nonNilGrants(a.Grants),
		"org_id":                a.OrgID,
		"require_key_rotation":  a.RequireKeyRotation,
		"strip_tiers_on_fork":   nonNilStrings(a.StripTiersOnFork),
	})
}

func GovernanceActionSigningPayload(g GovernanceAction) map[string]any {
	return map[string]any{
		"action_id":       g.ActionID,
		"action_type":     g.ActionType,
		"amount_micro":    g.AmountMicro,
		"epoch":           g.Epoch,
		"org_id":          g.OrgID,
		"payload_hash":    g.PayloadHash,
		"payload_summary": g.PayloadSummary,
		"proposer_id":     g.ProposerID,
	}
}

func AdvisoryProposalSigningPayload(a AdvisoryProposal) map[string]any {
	return map[string]any{
		"agent_id":           a.AgentID,
		"binding":            a.Binding,
		"conflict_flags":     nonNilStrings(a.ConflictFlags),
		"estimated_gain_bps": a.EstimatedGainBps,
		"kind":               a.Kind,
		"org_id":             a.OrgID,
		"proposal_id":        a.ProposalID,
		"summary":            a.Summary,
		"target_ref":         a.TargetRef,
	}
}

func EvalReceiptSigningPayload(e EvaluationReceipt) map[string]any {
	return map[string]any{
		"accuracy_bps":      e.AccuracyBps,
		"base_model_hash":   e.BaseModelHash,
		"delta_hash":        e.DeltaHash,
		"eval_dataset_hash": e.EvalDatasetHash,
		"evaluator_id":      e.EvaluatorID,
		"mean_loss_micro":   e.MeanLossMicro,
		"model_ref_id":      e.ModelRefID,
		"num_samples":       e.NumSamples,
		"org_id":            e.OrgID,
		"receipt_id":        e.ReceiptID,
		"safety_bps":        e.SafetyBps,
	}
}

func ForkAttestationSigningPayload(f ForkAttestation) map[string]any {
	return map[string]any{
		"child_authority_pub_key": f.ChildAuthorityPubKey,
		"child_org_id":            f.ChildOrgID,
		"keys_rotated":            f.KeysRotated,
		"parent_org_id":           f.ParentOrgID,
		"parent_snapshot_hash":    f.ParentSnapshotHash,
		"parent_snapshot_id":      f.ParentSnapshotID,
		"redacted_record_count":   f.RedactedRecordCount,
		"stripped_grant_count":    f.StrippedGrantCount,
	}
}

func OrgSnapshotSigningPayload(s OrgSnapshot) map[string]any {
	forkAttHash := ""
	if s.ForkAttestation != nil {
		forkAttHash = HashCanonical(DomainForkAttestation, ForkAttestationSigningPayload(*s.ForkAttestation))
	}
	return map[string]any{
		"acl_policy_hash":             s.ACLPolicy.ACLPolicyHash,
		"active_delta_id":             s.ModelRegistry.ActiveDeltaID,
		"epoch":                       s.Epoch,
		"fork_ancestor_snapshot_hash": s.ForkAncestorSnapshotHash,
		"fork_attestation_hash":       forkAttHash,
		"inherited_parent_root":       s.ResearchHistory.InheritedParentRoot,
		"model_registry_root":         s.ModelRegistry.ModelRegistryRoot,
		"org_id":                      s.OrgID,
		"parent_snapshot_hash":        s.ParentSnapshotHash,
		"policy_hash":                 s.PolicyManifest.PolicyHash,
		"research_merkle_root":        s.ResearchHistory.ResearchMerkleRoot,
		"snapshot_id":                 s.SnapshotID,
	}
}

func ComputeOrgSnapshotHash(s OrgSnapshot) string {
	return HashCanonical(DomainOrgSnapshot, OrgSnapshotSigningPayload(s))
}

func ExchangeBundleSigningPayload(b ExchangeBundle) map[string]any {
	researchHashes := make([]string, len(b.SupportingResearch))
	for i, r := range b.SupportingResearch {
		researchHashes[i] = r.RecordHash
	}
	return map[string]any{
		"bundle_id":                   b.BundleID,
		"eval_receipt_hash":           HashCanonical(DomainEvalReceipt, EvalReceiptSigningPayload(b.EvaluationReceipt)),
		"exported_delta_hash":         b.ExportedDelta.DeltaHash,
		"fork_ancestor_snapshot_hash": b.ForkAncestorSnapshotHash,
		"license_manifest":            nonNilLicenses(b.LicenseManifest),
		"lineage_chain":               nonNilLineage(b.LineageChain),
		"merge_step_bps":              b.MergeStepBps,
		"redaction_attestation":       b.RedactionAttestation,
		"source_org_id":               b.SourceOrgID,
		"source_snapshot_hash":        b.SourceSnapshotHash,
		"supporting_research_hashes":  researchHashes,
		"target_org_id":               b.TargetOrgID,
	}
}

func ComputeExchangeBundleHash(b ExchangeBundle) string {
	return HashCanonical(DomainExchangeBundle, ExchangeBundleSigningPayload(b))
}

func ComputeEvalDatasetHash(ds EvalDataset) string {
	return HashCanonical(DomainEvalDataset, map[string]any{
		"dataset_id":    ds.DatasetID,
		"num_classes":   ds.NumClasses,
		"num_features":  ds.NumFeatures,
		"safety_probes": nonNilSamples(ds.SafetyProbes),
		"samples":       nonNilSamples(ds.Samples),
		"seed":          ds.Seed,
	})
}

func ComputeAuditMerkleRoot(workflow []WorkflowCheckOutcome, adv []CaseOutcome) string {
	leaves := make([]string, 0, len(workflow)+len(adv))
	for _, w := range workflow {
		leaves = append(leaves, HashCanonical(DomainAuditLeaf, map[string]any{
			"accuracy_bps":    w.AccuracyBps,
			"code":            w.Code,
			"delta_gain_bps":  w.DeltaGainBps,
			"kind":            "workflow",
			"mean_loss_micro": w.MeanLossMicro,
			"safety_bps":      w.SafetyBps,
			"stage":           w.Stage,
			"valid":           w.Valid,
		}))
	}
	sortedAdv := make([]CaseOutcome, len(adv))
	copy(sortedAdv, adv)
	sort.Slice(sortedAdv, func(i, j int) bool {
		return sortedAdv[i].CaseID < sortedAdv[j].CaseID
	})
	for _, c := range sortedAdv {
		leaves = append(leaves, HashCanonical(DomainAuditLeaf, map[string]any{
			"actual_code":    c.ActualCode,
			"actual_valid":   c.ActualValid,
			"case_id":        c.CaseID,
			"category":       c.Category,
			"expected_code":  c.ExpectedCode,
			"expected_valid": c.ExpectedValid,
			"kind":           "adversarial",
			"matched":        c.Matched,
		}))
	}
	return MerkleRootRFC6962(leaves)
}

// Non-nil slice guards ensure [] instead of null in canonical JSON.
func nonNilInt64s(s []int64) []int64 {
	if s == nil {
		return []int64{}
	}
	return s
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilPrincipals(s []Principal) []Principal {
	if s == nil {
		return []Principal{}
	}
	return s
}

func nonNilGrants(s []AccessGrant) []AccessGrant {
	if s == nil {
		return []AccessGrant{}
	}
	return s
}

func nonNilDelegations(s []DelegationGrant) []DelegationGrant {
	if s == nil {
		return []DelegationGrant{}
	}
	return s
}

func nonNilRoyalties(s []RoyaltyShare) []RoyaltyShare {
	if s == nil {
		return []RoyaltyShare{}
	}
	return s
}

func nonNilLicenses(s []LicenseEntry) []LicenseEntry {
	if s == nil {
		return []LicenseEntry{}
	}
	return s
}

func nonNilLineage(s []LineageLink) []LineageLink {
	if s == nil {
		return []LineageLink{}
	}
	return s
}

func nonNilSamples(s []EvalSample) []EvalSample {
	if s == nil {
		return []EvalSample{}
	}
	return s
}

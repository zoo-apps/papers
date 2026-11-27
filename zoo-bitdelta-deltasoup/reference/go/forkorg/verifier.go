// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package forkorg

import "fmt"

func findPrincipal(policy PolicyManifest, id string) (Principal, bool) {
	for _, p := range policy.AuthorizedPrincipals {
		if p.ID == id {
			return p, true
		}
	}
	return Principal{}, false
}

func isLicenseAllowed(policy PolicyManifest, licenseID string) bool {
	for _, allowed := range policy.AllowedLicenses {
		if allowed == licenseID {
			return true
		}
	}
	return false
}

// VerifyGovernanceAction verifies constitutional authority, AI_AGENT boundaries,
// Ed25519 signatures, and HUMAN_COUNCIL quorum for a binding governance action.
func VerifyGovernanceAction(action GovernanceAction, policy PolicyManifest) (bool, string) {
	if action.OrgID != policy.OrgID {
		return false, ErrCrossOrgReplay
	}
	proposer, ok := findPrincipal(policy, action.ProposerID)
	if !ok {
		return false, ErrUnauthorizedSigner
	}
	if proposer.Role == RoleAIAgent {
		if action.ActionType == ActionUpdateVotingRules && policy.AIAgentBoundaries.ForbidVotingRuleMutation {
			return false, ErrAIVotingRuleForbidden
		}
		if action.ActionType == ActionAuthorizeTreasurySpend && policy.AIAgentBoundaries.ForbidTreasuryAuthorization {
			return false, ErrAITreasuryForbidden
		}
		return false, ErrUnauthorizedSigner
	}

	payload := GovernanceActionSigningPayload(action)
	seen := make(map[string]bool)
	var validCouncil int64
	for _, sig := range action.Signatures {
		signer, exists := findPrincipal(policy, sig.SignerID)
		if !exists {
			return false, ErrUnauthorizedSigner
		}
		if signer.OrgID != policy.OrgID {
			return false, ErrCrossOrgReplay
		}
		if signer.Role == RoleAIAgent {
			if action.ActionType == ActionUpdateVotingRules {
				return false, ErrAIVotingRuleForbidden
			}
			if action.ActionType == ActionAuthorizeTreasurySpend {
				return false, ErrAITreasuryForbidden
			}
			return false, ErrUnauthorizedSigner
		}
		if signer.Role != RoleHumanCouncil {
			return false, ErrUnauthorizedSigner
		}
		if !VerifyCanonical(signer.PublicKeyHex, sig.SignatureHex, DomainGovernanceAction, payload) {
			return false, ErrInvalidSignature
		}
		if !seen[signer.ID] {
			seen[signer.ID] = true
			validCouncil++
		}
	}
	if validCouncil < policy.MinCouncilApprovals {
		return false, ErrInsufficientQuorum
	}
	return true, ErrOK
}

// VerifyAdvisoryProposal verifies a non-binding AI_AGENT advisory proposal.
func VerifyAdvisoryProposal(prop AdvisoryProposal, policy PolicyManifest) (bool, string) {
	if prop.OrgID != policy.OrgID {
		return false, ErrCrossOrgReplay
	}
	if prop.Binding {
		return false, ErrAIBindingProposalForbid
	}
	agent, ok := findPrincipal(policy, prop.AgentID)
	if !ok || agent.Role != RoleAIAgent {
		return false, ErrUnauthorizedSigner
	}
	if !VerifyCanonical(agent.PublicKeyHex, prop.SignatureHex, DomainAdvisoryProposal, AdvisoryProposalSigningPayload(prop)) {
		return false, ErrInvalidSignature
	}
	return true, ErrOK
}

// VerifyOrgSnapshot validates internal cryptographic integrity, Merkle roots, hash chains,
// governance actions, advisory proposals, and council quorum signatures of a snapshot.
// If parentForFork != nil, it additionally enforces VerifyForkBoundary.
func VerifyOrgSnapshot(snap OrgSnapshot, parentForFork *OrgSnapshot) (bool, string) {
	if ComputePolicyHash(snap.PolicyManifest) != snap.PolicyManifest.PolicyHash {
		return false, ErrPolicyHashMismatch
	}
	if ComputeACLPolicyHash(snap.ACLPolicy) != snap.ACLPolicy.ACLPolicyHash {
		return false, ErrPolicyHashMismatch
	}
	if ComputeBaseModelHash(snap.ModelRegistry.BaseModel) != snap.ModelRegistry.BaseModel.WeightsHash {
		return false, ErrDeltaHashMismatch
	}
	for _, d := range snap.ModelRegistry.Deltas {
		if ComputeBitDeltaHash(d) != d.DeltaHash {
			return false, ErrDeltaHashMismatch
		}
		if d.OrgID == snap.OrgID {
			signer, ok := findPrincipal(snap.PolicyManifest, d.ContributorID)
			if !ok {
				return false, ErrUnauthorizedSigner
			}
			if !VerifyCanonical(signer.PublicKeyHex, d.SignatureHex, DomainBitDelta, BitDeltaSigningPayload(d)) {
				return false, ErrInvalidSignature
			}
		}
	}
	for _, s := range snap.ModelRegistry.Soups {
		if ComputeBitDeltaHash(s.ResultDelta) != s.ResultDelta.DeltaHash {
			return false, ErrDeltaHashMismatch
		}
		if ComputeDeltaSoupHash(s) != s.SoupHash {
			return false, ErrDeltaHashMismatch
		}
	}
	if ComputeModelRegistryRoot(snap.ModelRegistry) != snap.ModelRegistry.ModelRegistryRoot {
		return false, ErrMerkleRootMismatch
	}

	// Verify ResearchHistory hashes, post-fork hash chain continuity, and Merkle root.
	for i, r := range snap.ResearchHistory.Records {
		if ComputeResearchRecordHash(r) != r.RecordHash {
			return false, ErrHistoryChainBroken
		}
		if r.ParentSlotIndex < 0 {
			// Native record created in this organization: verify chain link and author signature.
			if i == 0 {
				if r.PrevHash != "" {
					return false, ErrHistoryChainBroken
				}
			} else {
				if r.PrevHash != snap.ResearchHistory.Records[i-1].RecordHash {
					return false, ErrHistoryChainBroken
				}
			}
			author, ok := findPrincipal(snap.PolicyManifest, r.AuthorID)
			if !ok {
				return false, ErrUnauthorizedSigner
			}
			if !VerifyCanonical(author.PublicKeyHex, r.SignatureHex, DomainResearchRecord, ResearchRecordSigningPayload(r)) {
				return false, ErrInvalidSignature
			}
		}
	}
	if ComputeResearchHistoryRoot(snap.ResearchHistory.Records) != snap.ResearchHistory.ResearchMerkleRoot {
		return false, ErrMerkleRootMismatch
	}

	if ComputeOrgSnapshotHash(snap) != snap.SnapshotHash {
		return false, ErrSnapshotHashMismatch
	}

	// Verify snapshot council quorum signatures.
	snapPayload := OrgSnapshotSigningPayload(snap)
	seenCouncil := make(map[string]bool)
	var validCouncil int64
	for _, sig := range snap.CouncilSignatures {
		signer, ok := findPrincipal(snap.PolicyManifest, sig.SignerID)
		if !ok || signer.Role != RoleHumanCouncil {
			return false, ErrUnauthorizedSigner
		}
		if signer.OrgID != snap.OrgID {
			return false, ErrCrossOrgReplay
		}
		if !VerifyCanonical(signer.PublicKeyHex, sig.SignatureHex, DomainOrgSnapshot, snapPayload) {
			return false, ErrInvalidSignature
		}
		if !seenCouncil[signer.ID] {
			seenCouncil[signer.ID] = true
			validCouncil++
		}
	}
	if validCouncil < snap.PolicyManifest.MinCouncilApprovals {
		return false, ErrInsufficientQuorum
	}

	for _, ga := range snap.GovernanceActions {
		if ok, code := VerifyGovernanceAction(ga, snap.PolicyManifest); !ok {
			return false, code
		}
	}
	for _, ap := range snap.AdvisoryProposals {
		if ok, code := VerifyAdvisoryProposal(ap, snap.PolicyManifest); !ok {
			return false, code
		}
	}

	if parentForFork != nil {
		return VerifyForkBoundary(*parentForFork, snap)
	}
	return true, ErrOK
}

// VerifyForkBoundary enforces all security invariants across an organization fork boundary:
// 1. Valid parent lineage pointer and ForkAttestation council quorum
// 2. Mandatory authority key rotation (zero shared public keys between parent and child)
// 3. Zero ACL leak of restricted_pii_or_partner or non-inheritable org_internal records
// 4. Zero ACL leak of non-inheritable grants or parent org-scoped capability tokens
// 5. Exact RFC 6962 cryptographic RedactionTombstone proof reconstructing parent's research_merkle_root
func VerifyForkBoundary(parent OrgSnapshot, child OrgSnapshot) (bool, string) {
	if child.ForkAttestation == nil {
		return false, ErrLineageBroken
	}
	att := *child.ForkAttestation
	if child.ParentSnapshotHash != parent.SnapshotHash ||
		child.ForkAncestorSnapshotHash != parent.SnapshotHash ||
		att.ParentSnapshotHash != parent.SnapshotHash ||
		att.ParentOrgID != parent.OrgID ||
		att.ChildOrgID != child.OrgID {
		return false, ErrLineageBroken
	}

	// 1. Enforce key rotation: zero overlap in Ed25519 public keys between parent and child.
	if !att.KeysRotated {
		return false, ErrKeyRotationRequired
	}
	parentKeys := make(map[string]bool, len(parent.PolicyManifest.AuthorizedPrincipals))
	for _, p := range parent.PolicyManifest.AuthorizedPrincipals {
		parentKeys[p.PublicKeyHex] = true
	}
	for _, p := range child.PolicyManifest.AuthorizedPrincipals {
		if parentKeys[p.PublicKeyHex] {
			return false, ErrKeyRotationRequired
		}
	}

	// 2. Enforce zero ACL leak in inherited records.
	for _, r := range child.ResearchHistory.Records {
		if r.ACLTier == TierRestricted {
			return false, ErrACLLeakRestricted
		}
		if r.ParentSlotIndex >= 0 && r.ACLTier != TierPublic {
			return false, ErrACLLeakRestricted
		}
	}

	// 3. Enforce zero ACL leak in grants and rotated token hashes.
	parentTokens := make(map[string]bool, len(parent.ACLPolicy.Grants))
	for _, g := range parent.ACLPolicy.Grants {
		parentTokens[g.OrgScopedTokenHash] = true
	}
	for _, g := range child.ACLPolicy.Grants {
		if g.Tier == TierRestricted || !g.InheritableOnFork || g.Tier != TierPublic {
			return false, ErrACLLeakGrant
		}
		if parentTokens[g.OrgScopedTokenHash] {
			return false, ErrACLLeakGrant
		}
	}

	// 4. Verify cryptographic RedactionTombstone Merkle inclusion proof against parent's research_merkle_root.
	totalSlots := int64(len(parent.ResearchHistory.Records))
	if child.ResearchHistory.ParentTotalSlots != totalSlots ||
		child.ResearchHistory.InheritedParentRoot != parent.ResearchHistory.ResearchMerkleRoot ||
		int64(len(child.ResearchHistory.RedactionTombstones)) != att.RedactedRecordCount {
		return false, ErrRedactionProofInvalid
	}
	reconstructed := make([]string, totalSlots)
	filled := make([]bool, totalSlots)
	for _, r := range child.ResearchHistory.Records {
		if r.ParentSlotIndex >= 0 {
			if r.ParentSlotIndex >= totalSlots || filled[r.ParentSlotIndex] {
				return false, ErrRedactionProofInvalid
			}
			reconstructed[r.ParentSlotIndex] = r.RecordHash
			filled[r.ParentSlotIndex] = true
		}
	}
	for _, t := range child.ResearchHistory.RedactionTombstones {
		if t.SlotIndex < 0 || t.SlotIndex >= totalSlots || filled[t.SlotIndex] {
			return false, ErrRedactionProofInvalid
		}
		if t.OriginalLeafHash == "" || t.CommitmentSaltHash == "" {
			return false, ErrRedactionProofInvalid
		}
		reconstructed[t.SlotIndex] = t.OriginalLeafHash
		filled[t.SlotIndex] = true
	}
	for i := int64(0); i < totalSlots; i++ {
		if !filled[i] {
			return false, ErrRedactionProofInvalid
		}
	}
	if MerkleRootRFC6962(reconstructed) != parent.ResearchHistory.ResearchMerkleRoot {
		return false, ErrRedactionProofInvalid
	}

	// 5. Verify ForkAttestation council quorum signatures under child's rotated council.
	attPayload := ForkAttestationSigningPayload(att)
	seen := make(map[string]bool)
	var validCouncil int64
	for _, sig := range att.ChildCouncilSigs {
		signer, ok := findPrincipal(child.PolicyManifest, sig.SignerID)
		if !ok || signer.Role != RoleHumanCouncil {
			return false, ErrUnauthorizedSigner
		}
		if !VerifyCanonical(signer.PublicKeyHex, sig.SignatureHex, DomainForkAttestation, attPayload) {
			return false, ErrInvalidSignature
		}
		if !seen[signer.ID] {
			seen[signer.ID] = true
			validCouncil++
		}
	}
	if validCouncil < child.PolicyManifest.MinCouncilApprovals {
		return false, ErrInsufficientQuorum
	}

	return true, ErrOK
}

// EvaluateSnapshotHead evaluates a snapshot's active model (base + active delta, if any) on ds.
func EvaluateSnapshotHead(snap OrgSnapshot, ds EvalDataset) (EvalMetrics, error) {
	weights := snap.ModelRegistry.BaseModel.WeightsMicro
	if active := FindActiveDelta(snap.ModelRegistry); active != nil {
		var err error
		weights, err = ApplyBitDelta(weights, *active)
		if err != nil {
			return EvalMetrics{}, err
		}
	}
	return EvaluateModel(weights, ds), nil
}

// VerifyExchangeBundle runs all 5 normative cross-fork adoption verification gates:
// (a) Common-ancestor lineage & Merkle provenance chain
// (b) Ed25519 signatures, org-domain scoping, and authorized governance/evaluator roles
// (c) Zero ACL leak & zero restricted-tier taint in exported delta and research closure
// (d) License compatibility & mandatory license review gate
// (e) Independent deterministic re-evaluation proving receipt match, safety floor, and genuine gain
func VerifyExchangeBundle(
	bundle ExchangeBundle,
	sourceSnap OrgSnapshot,
	targetSnap OrgSnapshot,
	ds EvalDataset,
) (bool, string, EvalMetrics, int64) {
	// 0. Bundle hash and cross-org anti-replay scoping.
	if ComputeExchangeBundleHash(bundle) != bundle.BundleHash {
		return false, ErrBundleHashMismatch, EvalMetrics{}, 0
	}
	if bundle.SourceOrgID != sourceSnap.OrgID ||
		bundle.TargetOrgID != targetSnap.OrgID ||
		bundle.SourceOrgID == bundle.TargetOrgID ||
		bundle.ExportedDelta.OrgID != sourceSnap.OrgID ||
		bundle.TargetAdoptionAction.OrgID != targetSnap.OrgID ||
		bundle.TargetAdoptionAction.PayloadHash != bundle.BundleHash {
		return false, ErrCrossOrgReplay, EvalMetrics{}, 0
	}

	// 1. Exported BitDelta hash and contributor signature check.
	if ComputeBitDeltaHash(bundle.ExportedDelta) != bundle.ExportedDelta.DeltaHash {
		return false, ErrDeltaHashMismatch, EvalMetrics{}, 0
	}
	contrib, ok := findPrincipal(sourceSnap.PolicyManifest, bundle.ExportedDelta.ContributorID)
	if !ok {
		return false, ErrUnauthorizedSigner, EvalMetrics{}, 0
	}
	if !VerifyCanonical(contrib.PublicKeyHex, bundle.ExportedDelta.SignatureHex, DomainBitDelta, BitDeltaSigningPayload(bundle.ExportedDelta)) {
		return false, ErrInvalidSignature, EvalMetrics{}, 0
	}

	// 2. Source council export quorum signatures.
	bundlePayload := ExchangeBundleSigningPayload(bundle)
	seenSrc := make(map[string]bool)
	var validSrcCouncil int64
	for _, sig := range bundle.SourceExportSignatures {
		signer, exists := findPrincipal(sourceSnap.PolicyManifest, sig.SignerID)
		if !exists || signer.Role != RoleHumanCouncil {
			return false, ErrUnauthorizedSigner, EvalMetrics{}, 0
		}
		if signer.OrgID != sourceSnap.OrgID {
			return false, ErrCrossOrgReplay, EvalMetrics{}, 0
		}
		if !VerifyCanonical(signer.PublicKeyHex, sig.SignatureHex, DomainExchangeBundle, bundlePayload) {
			return false, ErrInvalidSignature, EvalMetrics{}, 0
		}
		if !seenSrc[signer.ID] {
			seenSrc[signer.ID] = true
			validSrcCouncil++
		}
	}
	if validSrcCouncil < sourceSnap.PolicyManifest.MinCouncilApprovals {
		return false, ErrInsufficientQuorum, EvalMetrics{}, 0
	}

	// 3. Common-ancestor lineage & base model compatibility check.
	if bundle.ForkAncestorSnapshotHash == "" || len(bundle.LineageChain) == 0 {
		return false, ErrLineageBroken, EvalMetrics{}, 0
	}
	if targetSnap.ModelRegistry.BaseModel.ModelID != bundle.ExportedDelta.BaseModelID ||
		targetSnap.ModelRegistry.BaseModel.WeightsHash != sourceSnap.ModelRegistry.BaseModel.WeightsHash {
		return false, ErrLineageBroken, EvalMetrics{}, 0
	}
	// Verify target shares the fork ancestor (either target is descended from it or IS it).
	targetMatchesAncestor := targetSnap.ForkAncestorSnapshotHash == bundle.ForkAncestorSnapshotHash ||
		targetSnap.SnapshotHash == bundle.ForkAncestorSnapshotHash ||
		targetSnap.ParentSnapshotHash == bundle.ForkAncestorSnapshotHash
	if !targetMatchesAncestor {
		return false, ErrLineageBroken, EvalMetrics{}, 0
	}
	// Verify contiguous lineage chain from fork ancestor to sourceSnap.SnapshotHash.
	first := bundle.LineageChain[0]
	if first.SnapshotHash != bundle.ForkAncestorSnapshotHash && first.ParentSnapshotHash != bundle.ForkAncestorSnapshotHash {
		return false, ErrLineageBroken, EvalMetrics{}, 0
	}
	for i := 1; i < len(bundle.LineageChain); i++ {
		if bundle.LineageChain[i].ParentSnapshotHash != bundle.LineageChain[i-1].SnapshotHash {
			return false, ErrLineageBroken, EvalMetrics{}, 0
		}
	}
	last := bundle.LineageChain[len(bundle.LineageChain)-1]
	if last.SnapshotHash != bundle.SourceSnapshotHash || bundle.SourceSnapshotHash != sourceSnap.SnapshotHash {
		return false, ErrLineageBroken, EvalMetrics{}, 0
	}

	// 4. Zero ACL leak & restricted taint propagation check.
	if !bundle.RedactionAttestation.RestrictedTaintFree || bundle.ExportedDelta.ACLTier != TierPublic {
		return false, ErrACLTaintRestricted, EvalMetrics{}, 0
	}
	supportByID := make(map[string]ResearchRecord, len(bundle.SupportingResearch))
	for _, r := range bundle.SupportingResearch {
		if ComputeResearchRecordHash(r) != r.RecordHash {
			return false, ErrHistoryChainBroken, EvalMetrics{}, 0
		}
		if r.ACLTier == TierRestricted {
			return false, ErrACLTaintRestricted, EvalMetrics{}, 0
		}
		if r.ACLTier == TierInternal && !hasValidDelegation(sourceSnap.ACLPolicy, targetSnap.OrgID, r.RecordID, sourceSnap.PolicyManifest) {
			return false, ErrACLTaintRestricted, EvalMetrics{}, 0
		}
		supportByID[r.RecordID] = r
	}
	// Also inspect sourceSnap's own research history so a dishonest bundler cannot re-label a restricted record as public.
	sourceRecByID := make(map[string]ResearchRecord, len(sourceSnap.ResearchHistory.Records))
	for _, r := range sourceSnap.ResearchHistory.Records {
		sourceRecByID[r.RecordID] = r
	}
	for _, rid := range bundle.ExportedDelta.TrainingRecordIDs {
		sup, ok := supportByID[rid]
		if !ok {
			return false, ErrACLTaintRestricted, EvalMetrics{}, 0
		}
		if srcRec, exists := sourceRecByID[rid]; exists {
			if srcRec.ACLTier == TierRestricted || srcRec.RecordHash != sup.RecordHash {
				return false, ErrACLTaintRestricted, EvalMetrics{}, 0
			}
		}
	}

	// 5. License compatibility & mandatory license review gate.
	if !bundle.ExportedDelta.LicenseReviewed || !isLicenseAllowed(targetSnap.PolicyManifest, bundle.ExportedDelta.LicenseID) {
		return false, ErrLicenseIncompatible, EvalMetrics{}, 0
	}
	if len(bundle.LicenseManifest) == 0 {
		return false, ErrLicenseIncompatible, EvalMetrics{}, 0
	}
	for _, le := range bundle.LicenseManifest {
		if !le.LicenseReviewed || !isLicenseAllowed(targetSnap.PolicyManifest, le.LicenseID) {
			return false, ErrLicenseIncompatible, EvalMetrics{}, 0
		}
	}
	for _, r := range bundle.SupportingResearch {
		if !r.LicenseReviewed || !isLicenseAllowed(targetSnap.PolicyManifest, r.LicenseID) {
			return false, ErrLicenseIncompatible, EvalMetrics{}, 0
		}
	}

	// 6. Independent evaluator receipt verification & AI self-certification guard.
	rec := bundle.EvaluationReceipt
	evalPrincipal, found := findPrincipal(sourceSnap.PolicyManifest, rec.EvaluatorID)
	if !found {
		evalPrincipal, found = findPrincipal(targetSnap.PolicyManifest, rec.EvaluatorID)
	}
	if !found {
		return false, ErrUnauthorizedSigner, EvalMetrics{}, 0
	}
	if evalPrincipal.Role == RoleAIAgent {
		return false, ErrAISelfCertifyForbidden, EvalMetrics{}, 0
	}
	if rec.EvaluatorID == bundle.ExportedDelta.ContributorID {
		return false, ErrAISelfCertifyForbidden, EvalMetrics{}, 0
	}
	if evalPrincipal.Role != RoleEvaluator {
		return false, ErrUnauthorizedSigner, EvalMetrics{}, 0
	}
	if !VerifyCanonical(evalPrincipal.PublicKeyHex, rec.SignatureHex, DomainEvalReceipt, EvalReceiptSigningPayload(rec)) {
		return false, ErrInvalidSignature, EvalMetrics{}, 0
	}
	if rec.DeltaHash != bundle.ExportedDelta.DeltaHash ||
		rec.BaseModelHash != targetSnap.ModelRegistry.BaseModel.WeightsHash ||
		rec.EvalDatasetHash != ds.DatasetHash {
		return false, ErrEvalReplayMismatch, EvalMetrics{}, 0
	}

	// 7. Target organization governance adoption approval check.
	if okGov, govCode := VerifyGovernanceAction(bundle.TargetAdoptionAction, targetSnap.PolicyManifest); !okGov {
		return false, govCode, EvalMetrics{}, 0
	}

	// 8. Independent deterministic re-evaluation of exported delta and merged candidate.
	exportedWeights, err := ApplyBitDelta(targetSnap.ModelRegistry.BaseModel.WeightsMicro, bundle.ExportedDelta)
	if err != nil {
		return false, ErrDeltaHashMismatch, EvalMetrics{}, 0
	}
	replayedExport := EvaluateModel(exportedWeights, ds)
	if replayedExport.AccuracyBps != rec.AccuracyBps ||
		replayedExport.MeanLossMicro != rec.MeanLossMicro ||
		replayedExport.SafetyBps != rec.SafetyBps ||
		replayedExport.NumSamples != rec.NumSamples {
		return false, ErrEvalReplayMismatch, replayedExport, 0
	}

	targetHeadMetrics, err := EvaluateSnapshotHead(targetSnap, ds)
	if err != nil {
		return false, ErrDeltaHashMismatch, EvalMetrics{}, 0
	}
	localDelta := FindActiveDelta(targetSnap.ModelRegistry)
	rawMerged, err := MergeCrossForkWeights(
		targetSnap.ModelRegistry.BaseModel.WeightsMicro,
		localDelta,
		bundle.ExportedDelta,
		bundle.MergeStepBps,
	)
	if err != nil {
		return false, ErrDeltaHashMismatch, EvalMetrics{}, 0
	}
	// Evaluate the exact BitDelta-compressed merged adapter that will be committed to target's registry.
	mergedSignHex, mergedScale := CompressBitDelta(targetSnap.ModelRegistry.BaseModel.WeightsMicro, rawMerged)
	mergedWeights, err := ApplyBitDelta(targetSnap.ModelRegistry.BaseModel.WeightsMicro, BitDeltaArtifact{
		Dim:         targetSnap.ModelRegistry.BaseModel.Dim,
		SignBitsHex: mergedSignHex,
		ScaleMicro:  mergedScale,
	})
	if err != nil {
		return false, ErrDeltaHashMismatch, EvalMetrics{}, 0
	}
	mergedMetrics := EvaluateModel(mergedWeights, ds)

	if mergedMetrics.SafetyBps < targetSnap.PolicyManifest.MinSafetyBps {
		return false, ErrSafetyFloorViolation, mergedMetrics, mergedMetrics.AccuracyBps - targetHeadMetrics.AccuracyBps
	}
	gainBps := mergedMetrics.AccuracyBps - targetHeadMetrics.AccuracyBps
	if gainBps < targetSnap.PolicyManifest.MinAccuracyGainBps || mergedMetrics.MeanLossMicro >= targetHeadMetrics.MeanLossMicro {
		return false, ErrQualityRegression, mergedMetrics, gainBps
	}

	return true, ErrOK, mergedMetrics, gainBps
}

func hasValidDelegation(acl AccessControlPolicy, targetOrgID, resourceID string, sourcePolicy PolicyManifest) bool {
	for _, d := range acl.CrossOrgDelegations {
		if d.ToOrgID == targetOrgID && d.ResourceID == resourceID && !d.Revoked && d.Tier == TierInternal {
			signer, ok := findPrincipal(sourcePolicy, d.SignerID)
			if !ok || signer.Role != RoleHumanCouncil {
				continue
			}
			payload := map[string]any{
				"delegation_id": d.DelegationID,
				"from_org_id":   d.FromOrgID,
				"resource_id":   d.ResourceID,
				"revoked":       d.Revoked,
				"signer_id":     d.SignerID,
				"tier":          d.Tier,
				"to_org_id":     d.ToOrgID,
			}
			if VerifyCanonical(signer.PublicKeyHex, d.SignatureHex, DomainACLPolicy, payload) {
				return true
			}
		}
	}
	return false
}

// VerifyAdversarialCase dispatches a single fixture test case to the exact normative verifier.
func VerifyAdversarialCase(c AdversarialCase, ds EvalDataset) CaseOutcome {
	var valid bool
	var code string
	switch c.TargetCheck {
	case "snapshot":
		if c.Snapshot == nil {
			valid, code = false, ErrSnapshotHashMismatch
		} else {
			valid, code = VerifyOrgSnapshot(*c.Snapshot, c.ParentSnapshot)
		}
	case "fork":
		if c.Snapshot == nil || c.ParentSnapshot == nil {
			valid, code = false, ErrLineageBroken
		} else {
			valid, code = VerifyOrgSnapshot(*c.Snapshot, c.ParentSnapshot)
		}
	case "exchange":
		if c.ExchangeBundle == nil || c.SourceSnapshot == nil || c.TargetSnapshot == nil {
			valid, code = false, ErrBundleHashMismatch
		} else {
			valid, code, _, _ = VerifyExchangeBundle(*c.ExchangeBundle, *c.SourceSnapshot, *c.TargetSnapshot, ds)
		}
	case "governance":
		if c.GovernanceAction == nil || c.PolicyContext == nil {
			valid, code = false, ErrUnauthorizedSigner
		} else {
			valid, code = VerifyGovernanceAction(*c.GovernanceAction, *c.PolicyContext)
		}
	case "advisory":
		if c.AdvisoryProposal == nil || c.PolicyContext == nil {
			valid, code = false, ErrUnauthorizedSigner
		} else {
			valid, code = VerifyAdvisoryProposal(*c.AdvisoryProposal, *c.PolicyContext)
		}
	default:
		valid, code = false, fmt.Sprintf("ERR_UNKNOWN_TARGET_%s", c.TargetCheck)
	}
	return CaseOutcome{
		CaseID:        c.CaseID,
		Category:      c.Category,
		ExpectedValid: c.ExpectedValid,
		ActualValid:   valid,
		ExpectedCode:  c.ExpectedCode,
		ActualCode:    code,
		Matched:       valid == c.ExpectedValid && code == c.ExpectedCode,
	}
}

// VerifySuite runs the entire end-to-end fork/diverge/exchange workflow and every adversarial case,
// producing the deterministic VerificationReport and RFC 6962 AuditMerkleRoot.
func VerifySuite(suite ForkExchangeSuite) VerificationReport {
	ds := suite.EvalDataset
	workflow := make([]WorkflowCheckOutcome, 0, 9)

	addSnapStage := func(stage string, snap OrgSnapshot, parent *OrgSnapshot, prevAcc int64) int64 {
		ok, code := VerifyOrgSnapshot(snap, parent)
		m, err := EvaluateSnapshotHead(snap, ds)
		if err != nil {
			ok, code = false, ErrDeltaHashMismatch
		}
		gain := int64(0)
		if prevAcc > 0 {
			gain = m.AccuracyBps - prevAcc
		}
		workflow = append(workflow, WorkflowCheckOutcome{
			Stage:         stage,
			Valid:         ok,
			Code:          code,
			AccuracyBps:   m.AccuracyBps,
			MeanLossMicro: m.MeanLossMicro,
			SafetyBps:     m.SafetyBps,
			DeltaGainBps:  gain,
		})
		return m.AccuracyBps
	}

	baseAcc := addSnapStage("1_org_a_base_snap_0", suite.OrgASnap0, nil, 0)
	orgA1Acc := addSnapStage("2_org_a_pre_fork_snap_1", suite.OrgASnap1, nil, baseAcc)
	orgBForkAcc := addSnapStage("3_org_b_fork_boundary_snap_1", suite.OrgBForkSnap1, &suite.OrgASnap1, orgA1Acc)
	orgA2Acc := addSnapStage("4_org_a_diverged_snap_2", suite.OrgADivergedSnap2, nil, orgA1Acc)
	orgB2Acc := addSnapStage("5_org_b_diverged_deltasoup_snap_2", suite.OrgBDivergedSnap2, nil, orgBForkAcc)

	// Cross-fork exchange verification: OrgB -> OrgA
	okBtoA, codeBtoA, metricsBtoA, gainBtoA := VerifyExchangeBundle(suite.BundleBToA, suite.OrgBDivergedSnap2, suite.OrgADivergedSnap2, ds)
	workflow = append(workflow, WorkflowCheckOutcome{
		Stage:         "6_exchange_verify_org_b_to_org_a",
		Valid:         okBtoA,
		Code:          codeBtoA,
		AccuracyBps:   metricsBtoA.AccuracyBps,
		MeanLossMicro: metricsBtoA.MeanLossMicro,
		SafetyBps:     metricsBtoA.SafetyBps,
		DeltaGainBps:  gainBtoA,
	})
	addSnapStage("7_org_a_adopted_snap_3", suite.OrgAAdoptedSnap3, nil, orgA2Acc)

	// Bidirectional cross-fork exchange verification: OrgA -> OrgB
	okAtoB, codeAtoB, metricsAtoB, gainAtoB := VerifyExchangeBundle(suite.BundleAToB, suite.OrgADivergedSnap2, suite.OrgBDivergedSnap2, ds)
	workflow = append(workflow, WorkflowCheckOutcome{
		Stage:         "8_exchange_verify_org_a_to_org_b",
		Valid:         okAtoB,
		Code:          codeAtoB,
		AccuracyBps:   metricsAtoB.AccuracyBps,
		MeanLossMicro: metricsAtoB.MeanLossMicro,
		SafetyBps:     metricsAtoB.SafetyBps,
		DeltaGainBps:  gainAtoB,
	})
	addSnapStage("9_org_b_adopted_snap_3", suite.OrgBAdoptedSnap3, nil, orgB2Acc)

	allWorkflow := true
	for _, w := range workflow {
		if !w.Valid {
			allWorkflow = false
		}
	}

	advOutcomes := make([]CaseOutcome, 0, len(suite.AdversarialCases))
	allAdvMatched := true
	var advTotal, advCaught int64
	for _, c := range suite.AdversarialCases {
		out := VerifyAdversarialCase(c, ds)
		advOutcomes = append(advOutcomes, out)
		if !out.Matched {
			allAdvMatched = false
		}
		if !c.ExpectedValid {
			advTotal++
			if !out.ActualValid && out.ActualCode == c.ExpectedCode {
				advCaught++
			}
		}
	}

	return VerificationReport{
		SchemaVersion:         SchemaVersion,
		SpecVersion:           SpecVersion,
		Seed:                  suite.Seed,
		EvalDatasetHash:       ds.DatasetHash,
		AllWorkflowPassed:     allWorkflow,
		AllAdversarialMatched: allAdvMatched,
		WorkflowChecks:        workflow,
		AdversarialOutcomes:   advOutcomes,
		AdversarialTotal:      advTotal,
		AdversarialCaught:     advCaught,
		AuditMerkleRoot:       ComputeAuditMerkleRoot(workflow, advOutcomes),
	}
}

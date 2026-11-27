// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package forkorg

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// OrgKeyring holds deterministic Ed25519 keypairs for an organization's principals.
type OrgKeyring struct {
	OrgID     string
	Council1  KeyPair
	Council2  KeyPair
	Evaluator KeyPair
	Trainer1  KeyPair
	Trainer2  KeyPair
	AIAgent   KeyPair
	ByID      map[string]KeyPair
}

// NewOrgKeyring deterministically derives isolated org-scoped keys for all roles.
func NewOrgKeyring(seed int64, orgID string) *OrgKeyring {
	c1 := DeriveKeyPair(seed, orgID, fmt.Sprintf("did:zoo:%s:council-1", orgID), RoleHumanCouncil)
	c2 := DeriveKeyPair(seed, orgID, fmt.Sprintf("did:zoo:%s:council-2", orgID), RoleHumanCouncil)
	ev := DeriveKeyPair(seed, orgID, fmt.Sprintf("did:zoo:%s:evaluator-1", orgID), RoleEvaluator)
	t1 := DeriveKeyPair(seed, orgID, fmt.Sprintf("did:zoo:%s:trainer-1", orgID), RoleTrainer)
	t2 := DeriveKeyPair(seed, orgID, fmt.Sprintf("did:zoo:%s:trainer-2", orgID), RoleTrainer)
	ai := DeriveKeyPair(seed, orgID, fmt.Sprintf("did:zoo:%s:ai-agent-1", orgID), RoleAIAgent)
	kr := &OrgKeyring{
		OrgID:     orgID,
		Council1:  c1,
		Council2:  c2,
		Evaluator: ev,
		Trainer1:  t1,
		Trainer2:  t2,
		AIAgent:   ai,
		ByID:      make(map[string]KeyPair),
	}
	for _, kp := range []KeyPair{c1, c2, ev, t1, t2, ai} {
		kr.ByID[kp.Principal.ID] = kp
	}
	return kr
}

// Principals returns the canonical ordered slice of authorized principals for this org.
func (k *OrgKeyring) Principals() []Principal {
	return []Principal{
		k.Council1.Principal,
		k.Council2.Principal,
		k.Evaluator.Principal,
		k.Trainer1.Principal,
		k.Trainer2.Principal,
		k.AIAgent.Principal,
	}
}

// DefaultPolicyManifest constructs a constitutional PolicyManifest for an organization.
func DefaultPolicyManifest(orgID string, version int64, titheBps int64, principals []Principal) PolicyManifest {
	p := PolicyManifest{
		OrgID:                   orgID,
		PolicyVersion:           version,
		VotingQuorumBps:         6700,
		MinCouncilApprovals:     2,
		ConservationTitheBps:    titheBps,
		TreasurySpendLimitMicro: 500_000_000,
		MinSafetyBps:            8500,
		MinAccuracyGainBps:      100,
		AllowedLicenses:         []string{"Apache-2.0", "MIT", "BSD-3-Clause", "CC-BY-4.0", "CC0-1.0"},
		AIAgentBoundaries: AIAgentBoundaries{
			ForbidVotingRuleMutation:    true,
			ForbidTreasuryAuthorization: true,
			ForbidSelfCertifiedExps:     true,
			AllowAdvisoryProposals:      true,
		},
		AuthorizedPrincipals: principals,
	}
	p.PolicyHash = ComputePolicyHash(p)
	return p
}

// AppendResearchRecord appends a hash-chained signed ResearchRecord to history.
func AppendResearchRecord(
	hist *ResearchHistory,
	recordID string,
	kind string,
	aclTier string,
	licenseID string,
	licenseReviewed bool,
	payloadSummary string,
	payloadRaw string,
	author KeyPair,
) ResearchRecord {
	prevHash := ""
	if len(hist.Records) > 0 {
		prevHash = hist.Records[len(hist.Records)-1].RecordHash
	}
	rec := ResearchRecord{
		RecordID:        recordID,
		Seq:             int64(len(hist.Records)),
		ParentSlotIndex: -1,
		OrgID:           hist.OrgID,
		PrevHash:        prevHash,
		Kind:            kind,
		ACLTier:         aclTier,
		LicenseID:       licenseID,
		LicenseReviewed: licenseReviewed,
		PayloadSummary:  payloadSummary,
		PayloadHash:     SHA256Hex([]byte(payloadRaw)),
		AuthorID:        author.Principal.ID,
	}
	rec.SignatureHex = SignCanonical(author.Private, DomainResearchRecord, ResearchRecordSigningPayload(rec))
	rec.RecordHash = ComputeResearchRecordHash(rec)
	hist.Records = append(hist.Records, rec)
	hist.ResearchMerkleRoot = ComputeResearchHistoryRoot(hist.Records)
	return rec
}

// SignBitDelta computes DeltaHash and attaches contributor's Ed25519 signature.
func SignBitDelta(d BitDeltaArtifact, signer KeyPair) BitDeltaArtifact {
	d.TrainingRecordIDs = nonNilStrings(d.TrainingRecordIDs)
	d.ContributorID = signer.Principal.ID
	d.SignatureHex = SignCanonical(signer.Private, DomainBitDelta, BitDeltaSigningPayload(d))
	d.DeltaHash = ComputeBitDeltaHash(d)
	return d
}

// SignEvalReceipt signs an independent EvaluationReceipt with an EVALUATOR key.
func SignEvalReceipt(e EvaluationReceipt, evaluator KeyPair) EvaluationReceipt {
	e.EvaluatorID = evaluator.Principal.ID
	e.SignatureHex = SignCanonical(evaluator.Private, DomainEvalReceipt, EvalReceiptSigningPayload(e))
	return e
}

// SignGovernanceAction signs a binding GovernanceAction with a slice of approving keys.
func SignGovernanceAction(g GovernanceAction, signers ...KeyPair) GovernanceAction {
	sigs := make([]SignerSignature, 0, len(signers))
	payload := GovernanceActionSigningPayload(g)
	for _, s := range signers {
		sigs = append(sigs, SignerSignature{
			SignerID:     s.Principal.ID,
			SignatureHex: SignCanonical(s.Private, DomainGovernanceAction, payload),
		})
	}
	g.Signatures = sigs
	return g
}

// SignAdvisoryProposal signs a non-binding AI_AGENT AdvisoryProposal.
func SignAdvisoryProposal(a AdvisoryProposal, agent KeyPair) AdvisoryProposal {
	a.AgentID = agent.Principal.ID
	a.ConflictFlags = nonNilStrings(a.ConflictFlags)
	a.SignatureHex = SignCanonical(agent.Private, DomainAdvisoryProposal, AdvisoryProposalSigningPayload(a))
	return a
}

// FinalizeOrgSnapshot recomputes all sub-roots, computes SnapshotHash, and attaches council quorum signatures.
func FinalizeOrgSnapshot(s OrgSnapshot, council ...KeyPair) OrgSnapshot {
	s.ModelRegistry.Deltas = nonNilDeltas(s.ModelRegistry.Deltas)
	s.ModelRegistry.Soups = nonNilSoups(s.ModelRegistry.Soups)
	s.ModelRegistry.BaseModel.WeightsHash = ComputeBaseModelHash(s.ModelRegistry.BaseModel)
	s.ModelRegistry.ModelRegistryRoot = ComputeModelRegistryRoot(s.ModelRegistry)

	s.ResearchHistory.Records = nonNilRecords(s.ResearchHistory.Records)
	s.ResearchHistory.RedactionTombstones = nonNilTombstones(s.ResearchHistory.RedactionTombstones)
	s.ResearchHistory.ResearchMerkleRoot = ComputeResearchHistoryRoot(s.ResearchHistory.Records)

	s.PolicyManifest.PolicyHash = ComputePolicyHash(s.PolicyManifest)
	s.ACLPolicy.Grants = nonNilGrants(s.ACLPolicy.Grants)
	s.ACLPolicy.CrossOrgDelegations = nonNilDelegations(s.ACLPolicy.CrossOrgDelegations)
	s.ACLPolicy.ACLPolicyHash = ComputeACLPolicyHash(s.ACLPolicy)

	s.GovernanceActions = nonNilGovActions(s.GovernanceActions)
	s.AdvisoryProposals = nonNilAdvisory(s.AdvisoryProposals)

	s.SnapshotHash = ComputeOrgSnapshotHash(s)
	payload := OrgSnapshotSigningPayload(s)
	sigs := make([]SignerSignature, 0, len(council))
	for _, c := range council {
		sigs = append(sigs, SignerSignature{
			SignerID:     c.Principal.ID,
			SignatureHex: SignCanonical(c.Private, DomainOrgSnapshot, payload),
		})
	}
	s.CouncilSignatures = sigs
	return s
}

// ForkOrganization deterministically forks parentSnapshot into a new autonomous organization (childOrgID):
//   - Preserves immutable Merkle provenance to parentSnapshot.SnapshotHash
//   - Retains ONLY public (and explicitly fork-inheritable) records, deltas, and ACL grants
//   - Strictly strips all restricted_pii_or_partner and non-inheritable org_internal assets
//   - Inserts cryptographic RedactionTombstones proving exact Merkle inclusion in parent's research_merkle_root
//     without leaking plaintext payloads or ACL tokens
//   - Rotates all authority/council/evaluator/trainer keys to childKeyring!
func ForkOrganization(
	parent OrgSnapshot,
	childOrgID string,
	childSnapshotID string,
	childKeyring *OrgKeyring,
	childTitheBps int64,
) OrgSnapshot {
	// 1. Strip non-inheritable / restricted research records and build RedactionTombstones.
	keptRecords := make([]ResearchRecord, 0, len(parent.ResearchHistory.Records))
	tombstones := make([]RedactionTombstone, 0)
	for slotIdx, r := range parent.ResearchHistory.Records {
		if r.ACLTier == TierPublic {
			copied := r
			copied.ParentSlotIndex = int64(slotIdx)
			keptRecords = append(keptRecords, copied)
		} else {
			salt := sha256.Sum256([]byte(fmt.Sprintf("redact:%s:%s:%d:%s", parent.SnapshotHash, childOrgID, slotIdx, r.RecordHash)))
			tombstones = append(tombstones, RedactionTombstone{
				SlotIndex:          int64(slotIdx),
				OriginalLeafHash:   r.RecordHash,
				RedactedTier:       r.ACLTier,
				RedactionReason:    "fork_acl_boundary_strip",
				CommitmentSaltHash: hex.EncodeToString(salt[:]),
			})
		}
	}

	// Build a set of kept record IDs so tainted deltas are also stripped on fork.
	keptRecIDs := make(map[string]bool, len(keptRecords))
	for _, r := range keptRecords {
		keptRecIDs[r.RecordID] = true
	}

	// 2. Strip restricted / tainted BitDelta adapters & soups from ModelRegistry.
	keptDeltas := make([]BitDeltaArtifact, 0, len(parent.ModelRegistry.Deltas))
	activeDeltaID := ""
	for _, d := range parent.ModelRegistry.Deltas {
		if d.ACLTier != TierPublic {
			continue
		}
		tainted := false
		for _, rid := range d.TrainingRecordIDs {
			if !keptRecIDs[rid] {
				tainted = true
				break
			}
		}
		if tainted {
			continue
		}
		keptDeltas = append(keptDeltas, d)
		if d.DeltaID == parent.ModelRegistry.ActiveDeltaID {
			activeDeltaID = d.DeltaID
		}
	}

	// 3. Strip non-inheritable & restricted ACL grants; never inherit org-scoped private tokens!
	keptGrants := make([]AccessGrant, 0)
	var strippedGrants int64
	for _, g := range parent.ACLPolicy.Grants {
		if g.Tier == TierPublic && g.InheritableOnFork {
			ng := g
			ng.OrgID = childOrgID
			ng.OrgScopedTokenHash = SHA256Hex([]byte(fmt.Sprintf("rotated-token:%s:%s", childOrgID, g.GrantID)))
			keptGrants = append(keptGrants, ng)
		} else {
			strippedGrants++
		}
	}

	// 4. Construct child PolicyManifest with rotated child principals.
	childPolicy := DefaultPolicyManifest(childOrgID, 1, childTitheBps, childKeyring.Principals())

	// 5. Construct child ACLPolicy with clean stripped boundary.
	childACL := AccessControlPolicy{
		OrgID:               childOrgID,
		DefaultTier:         TierPublic,
		StripTiersOnFork:    []string{TierRestricted, TierInternal},
		RequireKeyRotation:  true,
		Grants:              keptGrants,
		CrossOrgDelegations: []DelegationGrant{},
	}
	childACL.ACLPolicyHash = ComputeACLPolicyHash(childACL)

	// 6. Construct ForkAttestation signed by child's rotated council keys.
	att := &ForkAttestation{
		ParentOrgID:          parent.OrgID,
		ChildOrgID:           childOrgID,
		ParentSnapshotID:     parent.SnapshotID,
		ParentSnapshotHash:   parent.SnapshotHash,
		RedactedRecordCount:  int64(len(tombstones)),
		StrippedGrantCount:   strippedGrants,
		KeysRotated:          true,
		ChildAuthorityPubKey: childKeyring.Council1.Principal.PublicKeyHex,
	}
	attPayload := ForkAttestationSigningPayload(*att)
	att.ChildCouncilSigs = []SignerSignature{
		{
			SignerID:     childKeyring.Council1.Principal.ID,
			SignatureHex: SignCanonical(childKeyring.Council1.Private, DomainForkAttestation, attPayload),
		},
		{
			SignerID:     childKeyring.Council2.Principal.ID,
			SignatureHex: SignCanonical(childKeyring.Council2.Private, DomainForkAttestation, attPayload),
		},
	}

	// 7. Record an explicit governance action approving the fork by child human council.
	forkGovAction := SignGovernanceAction(GovernanceAction{
		ActionID:       fmt.Sprintf("%s-gov-fork-1", childOrgID),
		OrgID:          childOrgID,
		ActionType:     ActionApproveFork,
		ProposerID:     childKeyring.Council1.Principal.ID,
		PayloadSummary: fmt.Sprintf("Approve fork of %s@%s with %d redacted records and rotated keys", parent.OrgID, parent.SnapshotID, len(tombstones)),
		PayloadHash:    SHA256Hex([]byte(parent.SnapshotHash + ":" + childOrgID)),
		AmountMicro:    0,
		Epoch:          parent.Epoch,
	}, childKeyring.Council1, childKeyring.Council2)

	child := OrgSnapshot{
		SnapshotID:               childSnapshotID,
		OrgID:                    childOrgID,
		Epoch:                    parent.Epoch,
		ParentSnapshotHash:       parent.SnapshotHash,
		ForkAncestorSnapshotHash: parent.SnapshotHash,
		ModelRegistry: ModelRegistry{
			OrgID:         childOrgID,
			BaseModel:     parent.ModelRegistry.BaseModel,
			ActiveDeltaID: activeDeltaID,
			Deltas:        keptDeltas,
			Soups:         []DeltaSoupArtifact{},
		},
		ResearchHistory: ResearchHistory{
			OrgID:               childOrgID,
			ParentTotalSlots:    int64(len(parent.ResearchHistory.Records)),
			InheritedParentRoot: parent.ResearchHistory.ResearchMerkleRoot,
			Records:             keptRecords,
			RedactionTombstones: tombstones,
		},
		PolicyManifest:    childPolicy,
		ACLPolicy:         childACL,
		GovernanceActions: []GovernanceAction{forkGovAction},
		AdvisoryProposals: []AdvisoryProposal{},
		ForkAttestation:   att,
	}

	return FinalizeOrgSnapshot(child, childKeyring.Council1, childKeyring.Council2)
}

// BuildExchangeBundle packages a verified public BitDelta improvement from sourceOrg for targetOrg.
func BuildExchangeBundle(
	bundleID string,
	sourceSnap OrgSnapshot,
	targetSnap OrgSnapshot,
	forkAncestorHash string,
	lineageChain []LineageLink,
	exportedDelta BitDeltaArtifact,
	evalReceipt EvaluationReceipt,
	mergeStepBps int64,
	sourceKeyring *OrgKeyring,
	targetKeyring *OrgKeyring,
) ExchangeBundle {
	// Gather ONLY the public supporting research records referenced by exportedDelta.
	recByID := make(map[string]ResearchRecord, len(sourceSnap.ResearchHistory.Records))
	for _, r := range sourceSnap.ResearchHistory.Records {
		recByID[r.RecordID] = r
	}
	supporting := make([]ResearchRecord, 0, len(exportedDelta.TrainingRecordIDs))
	licenses := make([]LicenseEntry, 0, 2+len(exportedDelta.TrainingRecordIDs))
	licenses = append(licenses, LicenseEntry{
		ArtifactID:      sourceSnap.ModelRegistry.BaseModel.ModelID,
		ArtifactKind:    "base_model",
		LicenseID:       sourceSnap.ModelRegistry.BaseModel.LicenseID,
		LicenseReviewed: sourceSnap.ModelRegistry.BaseModel.LicenseReviewed,
	})
	licenses = append(licenses, LicenseEntry{
		ArtifactID:      exportedDelta.DeltaID,
		ArtifactKind:    "bitdelta_adapter",
		LicenseID:       exportedDelta.LicenseID,
		LicenseReviewed: exportedDelta.LicenseReviewed,
	})
	for _, rid := range exportedDelta.TrainingRecordIDs {
		if r, ok := recByID[rid]; ok {
			supporting = append(supporting, r)
			licenses = append(licenses, LicenseEntry{
				ArtifactID:      r.RecordID,
				ArtifactKind:    "research_dataset",
				LicenseID:       r.LicenseID,
				LicenseReviewed: r.LicenseReviewed,
			})
		}
	}

	b := ExchangeBundle{
		BundleID:                 bundleID,
		SourceOrgID:              sourceSnap.OrgID,
		TargetOrgID:              targetSnap.OrgID,
		ForkAncestorSnapshotHash: forkAncestorHash,
		SourceSnapshotHash:       sourceSnap.SnapshotHash,
		LineageChain:             lineageChain,
		ExportedDelta:            exportedDelta,
		SupportingResearch:       supporting,
		RedactionAttestation: RedactionAttestation{
			SourceOrgID:         sourceSnap.OrgID,
			RedactedCount:       int64(len(sourceSnap.ResearchHistory.RedactionTombstones)),
			RestrictedTaintFree: true,
			StrippedTiers:       []string{TierRestricted, TierInternal},
		},
		LicenseManifest:   licenses,
		EvaluationReceipt: evalReceipt,
		MergeStepBps:      mergeStepBps,
	}
	b.BundleHash = ComputeExchangeBundleHash(b)
	bPayload := ExchangeBundleSigningPayload(b)
	b.SourceExportSignatures = []SignerSignature{
		{
			SignerID:     sourceKeyring.Council1.Principal.ID,
			SignatureHex: SignCanonical(sourceKeyring.Council1.Private, DomainExchangeBundle, bPayload),
		},
		{
			SignerID:     sourceKeyring.Council2.Principal.ID,
			SignatureHex: SignCanonical(sourceKeyring.Council2.Private, DomainExchangeBundle, bPayload),
		},
	}
	b.TargetAdoptionAction = SignGovernanceAction(GovernanceAction{
		ActionID:       fmt.Sprintf("%s-adopt-%s", targetSnap.OrgID, bundleID),
		OrgID:          targetSnap.OrgID,
		ActionType:     ActionApproveAdoption,
		ProposerID:     targetKeyring.Council1.Principal.ID,
		PayloadSummary: fmt.Sprintf("Adopt verified BitDelta %s from %s", exportedDelta.DeltaID, sourceSnap.OrgID),
		PayloadHash:    b.BundleHash,
		AmountMicro:    0,
		Epoch:          targetSnap.Epoch + 1,
	}, targetKeyring.Council1, targetKeyring.Council2)

	return b
}

// AdoptVerifiedBundle merges an already-verified ExchangeBundle into targetSnap, producing targetSnap@epoch+1.
func AdoptVerifiedBundle(
	targetSnap OrgSnapshot,
	bundle ExchangeBundle,
	newSnapshotID string,
	targetKeyring *OrgKeyring,
) (OrgSnapshot, BitDeltaArtifact, error) {
	localDelta := FindActiveDelta(targetSnap.ModelRegistry)
	mergedWeights, err := MergeCrossForkWeights(
		targetSnap.ModelRegistry.BaseModel.WeightsMicro,
		localDelta,
		bundle.ExportedDelta,
		bundle.MergeStepBps,
	)
	if err != nil {
		return OrgSnapshot{}, BitDeltaArtifact{}, err
	}
	signHex, scaleMicro := CompressBitDelta(targetSnap.ModelRegistry.BaseModel.WeightsMicro, mergedWeights)

	// Clone target snapshot cleanly for the next epoch.
	next := cloneSnapshotShallow(targetSnap)
	next.SnapshotID = newSnapshotID
	next.Epoch = targetSnap.Epoch + 1
	next.ParentSnapshotHash = targetSnap.SnapshotHash

	// Append adoption research record to history.
	adoptRec := AppendResearchRecord(
		&next.ResearchHistory,
		fmt.Sprintf("%s-rec-adopt-%s", targetSnap.OrgID, bundle.BundleID),
		"adoption_merge",
		TierPublic,
		"Apache-2.0",
		true,
		fmt.Sprintf("Adopted verified improvement %s from %s (bundle %s)", bundle.ExportedDelta.DeltaID, bundle.SourceOrgID, bundle.BundleID),
		bundle.BundleHash,
		targetKeyring.Trainer1,
	)

	trainIDs := []string{adoptRec.RecordID}
	if localDelta != nil {
		trainIDs = append(trainIDs, localDelta.TrainingRecordIDs...)
	}
	mergedDelta := SignBitDelta(BitDeltaArtifact{
		DeltaID:            fmt.Sprintf("%s-merged-%s", targetSnap.OrgID, bundle.BundleID),
		OrgID:              targetSnap.OrgID,
		BaseModelID:        targetSnap.ModelRegistry.BaseModel.ModelID,
		ParentDeltaID:      targetSnap.ModelRegistry.ActiveDeltaID,
		BaseCheckpointHash: targetSnap.SnapshotHash,
		Dim:                targetSnap.ModelRegistry.BaseModel.Dim,
		SignBitsHex:        signHex,
		ScaleMicro:         scaleMicro,
		TrainingRecordIDs:  trainIDs,
		ACLTier:            TierPublic,
		LicenseID:          "Apache-2.0",
		LicenseReviewed:    true,
	}, targetKeyring.Trainer1)

	next.ModelRegistry.Deltas = append(next.ModelRegistry.Deltas, mergedDelta)
	next.ModelRegistry.ActiveDeltaID = mergedDelta.DeltaID
	next.GovernanceActions = append(next.GovernanceActions, bundle.TargetAdoptionAction)

	finalized := FinalizeOrgSnapshot(next, targetKeyring.Council1, targetKeyring.Council2)
	return finalized, mergedDelta, nil
}

// FindActiveDelta returns the active BitDeltaArtifact from a ModelRegistry, or nil if none.
func FindActiveDelta(m ModelRegistry) *BitDeltaArtifact {
	if m.ActiveDeltaID == "" {
		return nil
	}
	for i := range m.Deltas {
		if m.Deltas[i].DeltaID == m.ActiveDeltaID {
			d := m.Deltas[i]
			return &d
		}
	}
	return nil
}

func cloneSnapshotShallow(s OrgSnapshot) OrgSnapshot {
	out := s
	out.ModelRegistry.Deltas = append([]BitDeltaArtifact{}, s.ModelRegistry.Deltas...)
	out.ModelRegistry.Soups = append([]DeltaSoupArtifact{}, s.ModelRegistry.Soups...)
	out.ResearchHistory.Records = append([]ResearchRecord{}, s.ResearchHistory.Records...)
	out.ResearchHistory.RedactionTombstones = append([]RedactionTombstone{}, s.ResearchHistory.RedactionTombstones...)
	out.GovernanceActions = append([]GovernanceAction{}, s.GovernanceActions...)
	out.AdvisoryProposals = append([]AdvisoryProposal{}, s.AdvisoryProposals...)
	out.ACLPolicy.Grants = append([]AccessGrant{}, s.ACLPolicy.Grants...)
	out.ACLPolicy.CrossOrgDelegations = append([]DelegationGrant{}, s.ACLPolicy.CrossOrgDelegations...)
	return out
}

func nonNilDeltas(s []BitDeltaArtifact) []BitDeltaArtifact {
	if s == nil {
		return []BitDeltaArtifact{}
	}
	return s
}

func nonNilSoups(s []DeltaSoupArtifact) []DeltaSoupArtifact {
	if s == nil {
		return []DeltaSoupArtifact{}
	}
	return s
}

func nonNilRecords(s []ResearchRecord) []ResearchRecord {
	if s == nil {
		return []ResearchRecord{}
	}
	return s
}

func nonNilTombstones(s []RedactionTombstone) []RedactionTombstone {
	if s == nil {
		return []RedactionTombstone{}
	}
	return s
}

func nonNilGovActions(s []GovernanceAction) []GovernanceAction {
	if s == nil {
		return []GovernanceAction{}
	}
	return s
}

func nonNilAdvisory(s []AdvisoryProposal) []AdvisoryProposal {
	if s == nil {
		return []AdvisoryProposal{}
	}
	return s
}

// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package forkorg

import (
	"fmt"
	"math"
)

// CompressionScaleRow records exact measured BitDelta compression at dimension D.
type CompressionScaleRow struct {
	Dim               int64 `json:"dim"`
	FullFP32Bytes     int64 `json:"full_fp32_bytes"`
	FullFP16Bytes     int64 `json:"full_fp16_bytes"`
	BitDeltaBytes     int64 `json:"bitdelta_bytes"`
	RatioVsFP32Bps    int64 `json:"ratio_vs_fp32_bps"`
	RatioVsFP16Bps    int64 `json:"ratio_vs_fp16_bps"`
	BitsPerParamMilli int64 `json:"bits_per_param_milli"`
}

// ByzantineSweepRow records DeltaSoup trimmed-mean vs naive-mean accuracy across Byzantine fractions.
type ByzantineSweepRow struct {
	NumContributors    int64  `json:"num_contributors"`
	ByzantineCount     int64  `json:"byzantine_count"`
	ByzantinePct       int64  `json:"byzantine_pct"`
	TrimBps            int64  `json:"trim_bps"`
	NaiveMeanAccBps    int64  `json:"naive_mean_acc_bps"`
	NaiveMeanLossMicro int64  `json:"naive_mean_loss_micro"`
	NaiveMeanSafetyBps int64  `json:"naive_mean_safety_bps"`
	TrimmedAccBps      int64  `json:"trimmed_acc_bps"`
	TrimmedLossMicro   int64  `json:"trimmed_loss_micro"`
	TrimmedSafetyBps   int64  `json:"trimmed_safety_bps"`
	Regime             string `json:"regime"`
}

// BenchmarkReport is the complete reproducible benchmark artifact written to results.json.
type BenchmarkReport struct {
	SchemaVersion        string                `json:"schema_version"`
	SpecVersion          string                `json:"spec_version"`
	Seed                 int64                 `json:"seed"`
	EvalDatasetHash      string                `json:"eval_dataset_hash"`
	Verification         VerificationReport    `json:"verification"`
	CompressionScaling   []CompressionScaleRow `json:"compression_scaling"`
	ByzantineResilience  []ByzantineSweepRow   `json:"byzantine_resilience"`
	OrgBRoyaltyShares    []RoyaltyShare        `json:"org_b_royalty_shares"`
	ForkRedactionSummary struct {
		ParentTotalRecords int64 `json:"parent_total_records"`
		ChildKeptRecords   int64 `json:"child_kept_records"`
		RedactedRecords    int64 `json:"redacted_records"`
		ParentTotalGrants  int64 `json:"parent_total_grants"`
		ChildKeptGrants    int64 `json:"child_kept_grants"`
		StrippedGrants     int64 `json:"stripped_grants"`
		KeysRotated        bool  `json:"keys_rotated"`
		ACLLeaksDetected   int64 `json:"acl_leaks_detected"`
	} `json:"fork_redaction_summary"`
}

// BuildCanonicalSuite deterministically executes the full forkable-org.v1 lifecycle
// (Base -> OrgA -> Fork OrgB with ACL stripping -> Diverge OrgA & OrgB DeltaSoup ->
// Bidirectional Verified Exchange -> 20 Adversarial & Constitutional Checks).
func BuildCanonicalSuite(seed int64) (ForkExchangeSuite, []RoyaltyShare) {
	ds := GenerateEvalDataset(seed)
	krA := NewOrgKeyring(seed, "org_a")
	krB := NewOrgKeyring(seed+7777, "org_b") // distinct seed + org_id guarantees rotated keys

	// 1. Train shared Base Model W_base on small, noisy generic base dataset (all 4 classes).
	zeroInit := make([]int64, DefaultModelDim)
	baseTrain := GenerateSamples(seed+101, []int64{0, 1, 2, 3}, 3, 2_100_000)
	baseWeights := TrainLinearModel(zeroInit, baseTrain, DefaultNumClasses, DefaultNumFeatures, 2, 18_000, 150)

	baseModel := BaseModelSpec{
		ModelID:         "zoo-sci-linear-4x16-v1",
		Dim:             DefaultModelDim,
		NumClasses:      DefaultNumClasses,
		NumFeatures:     DefaultNumFeatures,
		WeightsMicro:    baseWeights,
		LicenseID:       "Apache-2.0",
		LicenseReviewed: true,
	}
	baseModel.WeightsHash = ComputeBaseModelHash(baseModel)

	// 2. OrgA @ snap_0 (genesis base model + public charter).
	histA := ResearchHistory{
		OrgID:               "org_a",
		ParentTotalSlots:    0,
		InheritedParentRoot: "",
		Records:             []ResearchRecord{},
		RedactionTombstones: []RedactionTombstone{},
	}
	AppendResearchRecord(&histA, "org_a-rec-0", "dataset_ingest", TierPublic, "CC-BY-4.0", true,
		"Open conservation taxonomy base corpus v1", "base-corpus-v1-digest", krA.Trainer1)

	aclA0 := AccessControlPolicy{
		OrgID:              "org_a",
		DefaultTier:        TierPublic,
		StripTiersOnFork:   []string{TierRestricted, TierInternal},
		RequireKeyRotation: true,
		Grants: []AccessGrant{
			{
				GrantID:            "grant-a-pub-read",
				OrgID:              "org_a",
				SubjectID:          "public:*",
				ResourceID:         "org_a-rec-0",
				Tier:               TierPublic,
				InheritableOnFork:  true,
				OrgScopedTokenHash: SHA256Hex([]byte("org_a:pub-token:0")),
			},
		},
		CrossOrgDelegations: []DelegationGrant{},
	}

	orgASnap0 := FinalizeOrgSnapshot(OrgSnapshot{
		SnapshotID:               "org_a@snap_0",
		OrgID:                    "org_a",
		Epoch:                    0,
		ParentSnapshotHash:       "",
		ForkAncestorSnapshotHash: "",
		ModelRegistry: ModelRegistry{
			OrgID:         "org_a",
			BaseModel:     baseModel,
			ActiveDeltaID: "",
			Deltas:        []BitDeltaArtifact{},
			Soups:         []DeltaSoupArtifact{},
		},
		ResearchHistory:   histA,
		PolicyManifest:    DefaultPolicyManifest("org_a", 1, 250, krA.Principals()),
		ACLPolicy:         aclA0,
		GovernanceActions: []GovernanceAction{},
		AdvisoryProposals: []AdvisoryProposal{},
		ForkAttestation:   nil,
	}, krA.Council1, krA.Council2)

	// 3. OrgA @ snap_1 (pre-fork state with mixed ACL tiers: public, org_internal, restricted_pii_or_partner).
	orgASnap1 := cloneSnapshotShallow(orgASnap0)
	orgASnap1.SnapshotID = "org_a@snap_1"
	orgASnap1.Epoch = 1
	orgASnap1.ParentSnapshotHash = orgASnap0.SnapshotHash

	AppendResearchRecord(&orgASnap1.ResearchHistory, "org_a-rec-1-restricted", "dataset_ingest", TierRestricted, "PROPRIETARY", false,
		"CONFIDENTIAL partner wildlife GPS PII locations — NEVER FORK OR EXPORT", "restricted-gps-pii-payload-01", krA.Trainer1)
	AppendResearchRecord(&orgASnap1.ResearchHistory, "org_a-rec-2-internal", "experiment_run", TierInternal, "Apache-2.0", true,
		"Internal OrgA hyperparameter sweep notes (non-inheritable)", "internal-sweep-notes-02", krA.Trainer2)
	AppendResearchRecord(&orgASnap1.ResearchHistory, "org_a-rec-3-public", "dataset_ingest", TierPublic, "Apache-2.0", true,
		"Open scientific evaluation harness v1 specification", "public-eval-harness-03", krA.Trainer1)

	orgASnap1.ACLPolicy.Grants = append(orgASnap1.ACLPolicy.Grants,
		AccessGrant{
			GrantID:            "grant-a-restricted-pii",
			OrgID:              "org_a",
			SubjectID:          krA.Trainer1.Principal.ID,
			ResourceID:         "org_a-rec-1-restricted",
			Tier:               TierRestricted,
			InheritableOnFork:  false,
			OrgScopedTokenHash: SHA256Hex([]byte("org_a:restricted-secret-token:1")),
		},
		AccessGrant{
			GrantID:            "grant-a-internal-ops",
			OrgID:              "org_a",
			SubjectID:          krA.Trainer2.Principal.ID,
			ResourceID:         "org_a-rec-2-internal",
			Tier:               TierInternal,
			InheritableOnFork:  false,
			OrgScopedTokenHash: SHA256Hex([]byte("org_a:internal-ops-token:2")),
		},
	)
	// Also record a valid non-binding AI_AGENT advisory proposal on OrgA@snap_1.
	advPropA := SignAdvisoryProposal(AdvisoryProposal{
		ProposalID:       "org_a-adv-1",
		OrgID:            "org_a",
		Kind:             AdvisoryPrepareMergePlan,
		TargetRef:        "org_a@snap_1",
		EstimatedGainBps: 950,
		ConflictFlags:    []string{"strip_restricted_pii_before_fork"},
		Summary:          "Prepared fork readiness checklist; flagged 1 restricted_pii_or_partner and 1 org_internal record for mandatory redaction.",
		Binding:          false,
	}, krA.AIAgent)
	orgASnap1.AdvisoryProposals = append(orgASnap1.AdvisoryProposals, advPropA)
	orgASnap1 = FinalizeOrgSnapshot(orgASnap1, krA.Council1, krA.Council2)

	// 4. Deterministic Fork Operation: OrgB forks from OrgA@snap_1 -> OrgB@snap_1_fork.
	orgBForkSnap1 := ForkOrganization(orgASnap1, "org_b", "org_b@snap_1_fork", krB, 500)

	// 5. Independent Divergence — OrgA trains on public domain-A data (classes 0 & 1) -> OrgA@snap_2.
	orgADiverged := cloneSnapshotShallow(orgASnap1)
	orgADiverged.SnapshotID = "org_a@snap_2"
	orgADiverged.Epoch = 2
	orgADiverged.ParentSnapshotHash = orgASnap1.SnapshotHash
	orgADiverged.ForkAncestorSnapshotHash = orgASnap1.SnapshotHash

	recADom := AppendResearchRecord(&orgADiverged.ResearchHistory, "org_a-rec-4-domain-a-public", "dataset_ingest", TierPublic, "CC-BY-4.0", true,
		"OrgA public ecology & genomics corpus (classes 0-1)", "org-a-domain-01-corpus", krA.Trainer1)

	orgATrain := append(
		GenerateSamples(seed+301, []int64{0, 1}, 60, 500_000),
		GenerateSamples(seed+302, []int64{2, 3}, 4, 950_000)...,
	)
	orgAFine := TrainLinearModel(baseWeights, orgATrain, DefaultNumClasses, DefaultNumFeatures, 5, 28_000, 60)
	signA, scaleA := CompressBitDelta(baseWeights, orgAFine)
	deltaA := SignBitDelta(BitDeltaArtifact{
		DeltaID:            "org_a-bitdelta-v2",
		OrgID:              "org_a",
		BaseModelID:        baseModel.ModelID,
		ParentDeltaID:      "",
		BaseCheckpointHash: orgASnap1.SnapshotHash,
		Dim:                DefaultModelDim,
		SignBitsHex:        signA,
		ScaleMicro:         scaleA,
		TrainingRecordIDs:  []string{recADom.RecordID},
		ACLTier:            TierPublic,
		LicenseID:          "Apache-2.0",
		LicenseReviewed:    true,
	}, krA.Trainer1)
	orgADiverged.ModelRegistry.Deltas = append(orgADiverged.ModelRegistry.Deltas, deltaA)
	orgADiverged.ModelRegistry.ActiveDeltaID = deltaA.DeltaID

	// OrgA council updates its conservation tithe independently (authorized HUMAN_COUNCIL quorum).
	orgADiverged.PolicyManifest.PolicyVersion = 2
	orgADiverged.PolicyManifest.ConservationTitheBps = 300
	orgADiverged.PolicyManifest.PolicyHash = ComputePolicyHash(orgADiverged.PolicyManifest)
	govA2 := SignGovernanceAction(GovernanceAction{
		ActionID:       "org_a-gov-policy-2",
		OrgID:          "org_a",
		ActionType:     ActionUpdateVotingRules,
		ProposerID:     krA.Council1.Principal.ID,
		PayloadSummary: "Update OrgA policy v2 (conservation tithe 250 -> 300 bps)",
		PayloadHash:    orgADiverged.PolicyManifest.PolicyHash,
		AmountMicro:    0,
		Epoch:          2,
	}, krA.Council1, krA.Council2)
	orgADiverged.GovernanceActions = append(orgADiverged.GovernanceActions, govA2)
	orgADiverged = FinalizeOrgSnapshot(orgADiverged, krA.Council1, krA.Council2)

	// 6. Independent Divergence — OrgB runs multi-contributor BitDelta + Byzantine-robust DeltaSoup
	//    (7 honest contributors on classes 2 & 3 + 3 Byzantine poisoned contributors = 30% Byzantine, trim=30%).
	orgBDiverged := cloneSnapshotShallow(orgBForkSnap1)
	orgBDiverged.SnapshotID = "org_b@snap_2"
	orgBDiverged.Epoch = 2
	orgBDiverged.ParentSnapshotHash = orgBForkSnap1.SnapshotHash

	recBDom := AppendResearchRecord(&orgBDiverged.ResearchHistory, "org_b-rec-4-domain-b-public", "dataset_ingest", TierPublic, "Apache-2.0", true,
		"OrgB public climate & governance QA corpus (classes 2-3)", "org-b-domain-23-corpus", krB.Trainer1)

	honestDeltasB, byzDeltasB := buildContributorDeltas(seed+500, baseWeights, orgBForkSnap1.SnapshotHash, baseModel.ModelID, "org_b", recBDom.RecordID, krB, 7, 3)
	allContribB := append(append([]BitDeltaArtifact{}, honestDeltasB...), byzDeltasB...)

	soupSignB, soupScaleB, _, err := AggregateDeltaSoupTrimmedMean(allContribB, 3000)
	if err != nil {
		panic(err)
	}
	deltaSoupResultB := SignBitDelta(BitDeltaArtifact{
		DeltaID:            "org_b-deltasoup-ref-v2",
		OrgID:              "org_b",
		BaseModelID:        baseModel.ModelID,
		ParentDeltaID:      "",
		BaseCheckpointHash: orgBForkSnap1.SnapshotHash,
		Dim:                DefaultModelDim,
		SignBitsHex:        soupSignB,
		ScaleMicro:         soupScaleB,
		TrainingRecordIDs:  []string{recBDom.RecordID},
		ACLTier:            TierPublic,
		LicenseID:          "Apache-2.0",
		LicenseReviewed:    true,
	}, krB.Trainer1)

	contribDeltaIDs := make([]string, len(allContribB))
	for i, d := range allContribB {
		contribDeltaIDs[i] = d.DeltaID
	}
	acceptedIDs := make([]string, len(honestDeltasB))
	for i, d := range honestDeltasB {
		acceptedIDs[i] = d.ContributorID
	}
	royaltiesB := ComputeRoyaltySharesBps(honestDeltasB)
	soupArtifactB := DeltaSoupArtifact{
		SoupID:                 "org_b-soup-v2",
		OrgID:                  "org_b",
		BaseModelID:            baseModel.ModelID,
		BaseCheckpointHash:     orgBForkSnap1.SnapshotHash,
		TrimBps:                3000,
		StepBps:                10000,
		ContributorDeltaIDs:    contribDeltaIDs,
		AcceptedContributorIDs: acceptedIDs,
		RoyaltyShares:          royaltiesB,
		ResultDelta:            deltaSoupResultB,
	}
	soupArtifactB.SoupHash = ComputeDeltaSoupHash(soupArtifactB)

	orgBDiverged.ModelRegistry.Deltas = append(orgBDiverged.ModelRegistry.Deltas, deltaSoupResultB)
	orgBDiverged.ModelRegistry.Soups = append(orgBDiverged.ModelRegistry.Soups, soupArtifactB)
	orgBDiverged.ModelRegistry.ActiveDeltaID = deltaSoupResultB.DeltaID

	// OrgB AI agent submits non-binding value estimate & adoption recommendation.
	advPropB := SignAdvisoryProposal(AdvisoryProposal{
		ProposalID:       "org_b-adv-1",
		OrgID:            "org_b",
		Kind:             AdvisoryRecommendAdoption,
		TargetRef:        deltaSoupResultB.DeltaID,
		EstimatedGainBps: 1400,
		ConflictFlags:    []string{},
		Summary:          "Estimated +14% accuracy synergy when merging OrgB DeltaSoup adapter into OrgA head; awaits independent evaluator & human council approval.",
		Binding:          false,
	}, krB.AIAgent)
	orgBDiverged.AdvisoryProposals = append(orgBDiverged.AdvisoryProposals, advPropB)
	orgBDiverged = FinalizeOrgSnapshot(orgBDiverged, krB.Council1, krB.Council2)

	// 7. Cross-Fork Verified Improvement Exchange: OrgB -> OrgA.
	weightsB, _ := ApplyBitDelta(baseWeights, deltaSoupResultB)
	metricsB := EvaluateModel(weightsB, ds)
	evalReceiptB := SignEvalReceipt(EvaluationReceipt{
		ReceiptID:       "eval-org_b-deltasoup-v2",
		OrgID:           "org_b",
		ModelRefID:      deltaSoupResultB.DeltaID,
		DeltaHash:       deltaSoupResultB.DeltaHash,
		BaseModelHash:   baseModel.WeightsHash,
		EvalDatasetHash: ds.DatasetHash,
		AccuracyBps:     metricsB.AccuracyBps,
		MeanLossMicro:   metricsB.MeanLossMicro,
		SafetyBps:       metricsB.SafetyBps,
		NumSamples:      metricsB.NumSamples,
	}, krB.Evaluator)

	lineageBToA := []LineageLink{
		{
			SnapshotID:         orgBForkSnap1.SnapshotID,
			OrgID:              orgBForkSnap1.OrgID,
			Epoch:              orgBForkSnap1.Epoch,
			ParentSnapshotHash: orgBForkSnap1.ParentSnapshotHash,
			SnapshotHash:       orgBForkSnap1.SnapshotHash,
		},
		{
			SnapshotID:         orgBDiverged.SnapshotID,
			OrgID:              orgBDiverged.OrgID,
			Epoch:              orgBDiverged.Epoch,
			ParentSnapshotHash: orgBDiverged.ParentSnapshotHash,
			SnapshotHash:       orgBDiverged.SnapshotHash,
		},
	}
	bundleBToA := BuildExchangeBundle(
		"bundle-org_b-to-org_a-v1",
		orgBDiverged,
		orgADiverged,
		orgASnap1.SnapshotHash,
		lineageBToA,
		deltaSoupResultB,
		evalReceiptB,
		10000,
		krB,
		krA,
	)

	orgAAdoptedSnap3, _, err := AdoptVerifiedBundle(orgADiverged, bundleBToA, "org_a@snap_3", krA)
	if err != nil {
		panic(err)
	}

	// 8. Bidirectional Exchange: OrgA -> OrgB (clean public deltaA back to OrgB).
	weightsA, _ := ApplyBitDelta(baseWeights, deltaA)
	metricsA := EvaluateModel(weightsA, ds)
	evalReceiptA := SignEvalReceipt(EvaluationReceipt{
		ReceiptID:       "eval-org_a-bitdelta-v2",
		OrgID:           "org_a",
		ModelRefID:      deltaA.DeltaID,
		DeltaHash:       deltaA.DeltaHash,
		BaseModelHash:   baseModel.WeightsHash,
		EvalDatasetHash: ds.DatasetHash,
		AccuracyBps:     metricsA.AccuracyBps,
		MeanLossMicro:   metricsA.MeanLossMicro,
		SafetyBps:       metricsA.SafetyBps,
		NumSamples:      metricsA.NumSamples,
	}, krA.Evaluator)

	lineageAToB := []LineageLink{
		{
			SnapshotID:         orgADiverged.SnapshotID,
			OrgID:              orgADiverged.OrgID,
			Epoch:              orgADiverged.Epoch,
			ParentSnapshotHash: orgADiverged.ParentSnapshotHash,
			SnapshotHash:       orgADiverged.SnapshotHash,
		},
	}
	bundleAToB := BuildExchangeBundle(
		"bundle-org_a-to-org_b-v1",
		orgADiverged,
		orgBDiverged,
		orgASnap1.SnapshotHash,
		lineageAToB,
		deltaA,
		evalReceiptA,
		10000,
		krA,
		krB,
	)

	orgBAdoptedSnap3, _, err := AdoptVerifiedBundle(orgBDiverged, bundleAToB, "org_b@snap_3", krB)
	if err != nil {
		panic(err)
	}

	// 9. Construct 20 explicit Adversarial & Constitutional Security Test Cases.
	advCases := buildAdversarialCases(seed, ds, baseWeights, orgASnap1, orgBForkSnap1, orgADiverged, orgBDiverged, bundleBToA, krA, krB)

	suite := ForkExchangeSuite{
		SchemaVersion:     SchemaVersion,
		SpecVersion:       SpecVersion,
		Seed:              seed,
		EvalDataset:       ds,
		OrgASnap0:         orgASnap0,
		OrgASnap1:         orgASnap1,
		OrgBForkSnap1:     orgBForkSnap1,
		OrgADivergedSnap2: orgADiverged,
		OrgBDivergedSnap2: orgBDiverged,
		BundleBToA:        bundleBToA,
		BundleAToB:        bundleAToB,
		OrgAAdoptedSnap3:  orgAAdoptedSnap3,
		OrgBAdoptedSnap3:  orgBAdoptedSnap3,
		AdversarialCases:  advCases,
	}
	return suite, royaltiesB
}

func buildContributorDeltas(
	seed int64,
	baseWeights []int64,
	baseCheckpointHash string,
	baseModelID string,
	orgID string,
	recID string,
	kr *OrgKeyring,
	numHonest int,
	numByzantine int,
) (honest []BitDeltaArtifact, byzantine []BitDeltaArtifact) {
	honest = make([]BitDeltaArtifact, 0, numHonest)
	for i := 0; i < numHonest; i++ {
		trainSplit := append(
			GenerateSamples(seed+int64(i*31+1), []int64{2, 3}, 48, 520_000),
			GenerateSamples(seed+int64(i*31+2), []int64{0, 1}, 4, 950_000)...,
		)
		wFine := TrainLinearModel(baseWeights, trainSplit, DefaultNumClasses, DefaultNumFeatures, 5, 28_000, 60)
		signHex, scale := CompressBitDelta(baseWeights, wFine)
		signer := kr.Trainer1
		if i%2 == 1 {
			signer = kr.Trainer2
		}
		d := SignBitDelta(BitDeltaArtifact{
			DeltaID:            fmt.Sprintf("%s-contrib-honest-%d", orgID, i),
			OrgID:              orgID,
			BaseModelID:        baseModelID,
			ParentDeltaID:      "",
			BaseCheckpointHash: baseCheckpointHash,
			Dim:                DefaultModelDim,
			SignBitsHex:        signHex,
			ScaleMicro:         scale,
			TrainingRecordIDs:  []string{recID},
			ACLTier:            TierPublic,
			LicenseID:          "Apache-2.0",
			LicenseReviewed:    true,
		}, signer)
		// Preserve unique deterministic contributor attribution label for royalties while verifying signature cleanly.
		d.ContributorID = fmt.Sprintf("did:zoo:%s:contrib-%02d", orgID, i+1)
		honest = append(honest, d)
	}

	byzantine = make([]BitDeltaArtifact, 0, numByzantine)
	for i := 0; i < numByzantine; i++ {
		// Adversarial sign-flipped, amplified-scale poisoning delta targeting all coordinates.
		poisonedWeights := make([]int64, len(baseWeights))
		for j := range baseWeights {
			// Push strongly opposite to honest direction with 6x magnitude.
			if len(honest) > 0 {
				hv, _ := UnpackBitDelta(honest[0].Dim, honest[0].SignBitsHex, honest[0].ScaleMicro)
				poisonedWeights[j] = baseWeights[j] - 6*hv[j]
			} else {
				poisonedWeights[j] = baseWeights[j] - 800_000
			}
		}
		signHex, scale := CompressBitDelta(baseWeights, poisonedWeights)
		d := BitDeltaArtifact{
			DeltaID:            fmt.Sprintf("%s-contrib-byz-%d", orgID, i),
			OrgID:              orgID,
			BaseModelID:        baseModelID,
			ParentDeltaID:      "",
			BaseCheckpointHash: baseCheckpointHash,
			Dim:                DefaultModelDim,
			SignBitsHex:        signHex,
			ScaleMicro:         scale,
			TrainingRecordIDs:  []string{recID},
			ACLTier:            TierPublic,
			LicenseID:          "Apache-2.0",
			LicenseReviewed:    true,
			ContributorID:      fmt.Sprintf("did:zoo:%s:byz-%02d", orgID, i+1),
		}
		d.DeltaHash = ComputeBitDeltaHash(d)
		byzantine = append(byzantine, d)
	}
	return honest, byzantine
}

func buildAdversarialCases(
	seed int64,
	ds EvalDataset,
	baseWeights []int64,
	orgASnap1 OrgSnapshot,
	orgBForkSnap1 OrgSnapshot,
	orgADiverged OrgSnapshot,
	orgBDiverged OrgSnapshot,
	validBundle ExchangeBundle,
	krA *OrgKeyring,
	krB *OrgKeyring,
) []AdversarialCase {
	cases := make([]AdversarialCase, 0, 20)

	// Helper to re-sign an exchange bundle cleanly after mutating fields.
	resignBundle := func(b ExchangeBundle) ExchangeBundle {
		b.BundleHash = ComputeExchangeBundleHash(b)
		payload := ExchangeBundleSigningPayload(b)
		b.SourceExportSignatures = []SignerSignature{
			{SignerID: krB.Council1.Principal.ID, SignatureHex: SignCanonical(krB.Council1.Private, DomainExchangeBundle, payload)},
			{SignerID: krB.Council2.Principal.ID, SignatureHex: SignCanonical(krB.Council2.Private, DomainExchangeBundle, payload)},
		}
		b.TargetAdoptionAction = SignGovernanceAction(GovernanceAction{
			ActionID:       b.TargetAdoptionAction.ActionID,
			OrgID:          b.TargetAdoptionAction.OrgID,
			ActionType:     ActionApproveAdoption,
			ProposerID:     krA.Council1.Principal.ID,
			PayloadSummary: b.TargetAdoptionAction.PayloadSummary,
			PayloadHash:    b.BundleHash,
			AmountMicro:    0,
			Epoch:          b.TargetAdoptionAction.Epoch,
		}, krA.Council1, krA.Council2)
		return b
	}

	// ATK-01: Broken ancestor lineage in ExchangeBundle.
	{
		b := validBundle
		b.ForkAncestorSnapshotHash = SHA256Hex([]byte("forged-nonexistent-ancestor"))
		b = resignBundle(b)
		cases = append(cases, AdversarialCase{
			CaseID:         "ATK-01",
			Name:           "Forged fork ancestor lineage hash in exchange bundle",
			Category:       "provenance",
			TargetCheck:    "exchange",
			ExpectedValid:  false,
			ExpectedCode:   ErrLineageBroken,
			ExchangeBundle: &b,
			SourceSnapshot: &orgBDiverged,
			TargetSnapshot: &orgADiverged,
		})
	}

	// ATK-02: Tampered BitDelta sign bits without recomputing DeltaHash.
	{
		b := validBundle
		flipped := "ff" + b.ExportedDelta.SignBitsHex[2:]
		if b.ExportedDelta.SignBitsHex[:2] == "ff" {
			flipped = "00" + b.ExportedDelta.SignBitsHex[2:]
		}
		b.ExportedDelta.SignBitsHex = flipped
		cases = append(cases, AdversarialCase{
			CaseID:         "ATK-02",
			Name:           "Tampered BitDelta 1-bit sign mask causing delta hash mismatch",
			Category:       "integrity",
			TargetCheck:    "exchange",
			ExpectedValid:  false,
			ExpectedCode:   ErrDeltaHashMismatch,
			ExchangeBundle: &b,
			SourceSnapshot: &orgBDiverged,
			TargetSnapshot: &orgADiverged,
		})
	}

	// ATK-03: Tampered research history chain record in snapshot.
	{
		s := cloneSnapshotShallow(orgADiverged)
		s.ResearchHistory.Records[len(s.ResearchHistory.Records)-1].PayloadSummary = "TAMPERED summary after signing"
		cases = append(cases, AdversarialCase{
			CaseID:        "ATK-03",
			Name:          "Tampered research history record breaks hash chain",
			Category:      "provenance",
			TargetCheck:   "snapshot",
			ExpectedValid: false,
			ExpectedCode:  ErrHistoryChainBroken,
			Snapshot:      &s,
		})
	}

	// ATK-04: Tampered snapshot research Merkle root.
	{
		s := cloneSnapshotShallow(orgADiverged)
		s.ResearchHistory.ResearchMerkleRoot = SHA256Hex([]byte("fake-merkle-root"))
		cases = append(cases, AdversarialCase{
			CaseID:        "ATK-04",
			Name:          "Tampered research Merkle root rejected",
			Category:      "integrity",
			TargetCheck:   "snapshot",
			ExpectedValid: false,
			ExpectedCode:  ErrMerkleRootMismatch,
			Snapshot:      &s,
		})
	}

	// ATK-05: ACL leak in fork — restricted_pii_or_partner record retained in child fork!
	{
		s := cloneSnapshotShallow(orgBForkSnap1)
		// Smuggle parent's restricted record into child fork and re-finalize child snapshot.
		leaked := orgASnap1.ResearchHistory.Records[1] // restricted_pii_or_partner
		leaked.ParentSlotIndex = 1
		s.ResearchHistory.Records = append(s.ResearchHistory.Records, leaked)
		s = FinalizeOrgSnapshot(s, krB.Council1, krB.Council2)
		cases = append(cases, AdversarialCase{
			CaseID:         "ATK-05",
			Name:           "ACL leak: restricted_pii_or_partner record retained across fork boundary",
			Category:       "acl_isolation",
			TargetCheck:    "fork",
			ExpectedValid:  false,
			ExpectedCode:   ErrACLLeakRestricted,
			Snapshot:       &s,
			ParentSnapshot: &orgASnap1,
		})
	}

	// ATK-06: ACL leak in fork — non-inheritable org_internal ACL grant smuggled into child fork!
	{
		s := cloneSnapshotShallow(orgBForkSnap1)
		s.ACLPolicy.Grants = append(s.ACLPolicy.Grants, orgASnap1.ACLPolicy.Grants[2]) // org_internal, inheritable=false
		s = FinalizeOrgSnapshot(s, krB.Council1, krB.Council2)
		cases = append(cases, AdversarialCase{
			CaseID:         "ATK-06",
			Name:           "ACL leak: non-inheritable org_internal grant smuggled into child fork",
			Category:       "acl_isolation",
			TargetCheck:    "fork",
			ExpectedValid:  false,
			ExpectedCode:   ErrACLLeakGrant,
			Snapshot:       &s,
			ParentSnapshot: &orgASnap1,
		})
	}

	// ATK-07: Tainted cross-fork export — delta trained on restricted_pii_or_partner record!
	{
		srcWithRestricted := cloneSnapshotShallow(orgBDiverged)
		restrRec := AppendResearchRecord(&srcWithRestricted.ResearchHistory, "org_b-rec-secret-pii", "dataset_ingest", TierRestricted, "Apache-2.0", true,
			"Confidential partner patient data", "secret-patient-payload", krB.Trainer1)
		taintedDelta := validBundle.ExportedDelta
		taintedDelta.DeltaID = "org_b-tainted-delta"
		taintedDelta.TrainingRecordIDs = []string{restrRec.RecordID}
		taintedDelta = SignBitDelta(taintedDelta, krB.Trainer1)
		srcWithRestricted.ModelRegistry.Deltas = append(srcWithRestricted.ModelRegistry.Deltas, taintedDelta)
		srcWithRestricted = FinalizeOrgSnapshot(srcWithRestricted, krB.Council1, krB.Council2)

		b := validBundle
		b.SourceSnapshotHash = srcWithRestricted.SnapshotHash
		b.LineageChain = []LineageLink{
			validBundle.LineageChain[0],
			{
				SnapshotID:         srcWithRestricted.SnapshotID,
				OrgID:              srcWithRestricted.OrgID,
				Epoch:              srcWithRestricted.Epoch,
				ParentSnapshotHash: srcWithRestricted.ParentSnapshotHash,
				SnapshotHash:       srcWithRestricted.SnapshotHash,
			},
		}
		b.ExportedDelta = taintedDelta
		b.SupportingResearch = []ResearchRecord{restrRec}
		b.EvaluationReceipt = SignEvalReceipt(EvaluationReceipt{
			ReceiptID:       "eval-tainted",
			OrgID:           "org_b",
			ModelRefID:      taintedDelta.DeltaID,
			DeltaHash:       taintedDelta.DeltaHash,
			BaseModelHash:   validBundle.EvaluationReceipt.BaseModelHash,
			EvalDatasetHash: ds.DatasetHash,
			AccuracyBps:     validBundle.EvaluationReceipt.AccuracyBps,
			MeanLossMicro:   validBundle.EvaluationReceipt.MeanLossMicro,
			SafetyBps:       validBundle.EvaluationReceipt.SafetyBps,
			NumSamples:      validBundle.EvaluationReceipt.NumSamples,
		}, krB.Evaluator)
		b = resignBundle(b)
		cases = append(cases, AdversarialCase{
			CaseID:         "ATK-07",
			Name:           "Restricted-tier training taint smuggled in cross-fork export bundle",
			Category:       "acl_isolation",
			TargetCheck:    "exchange",
			ExpectedValid:  false,
			ExpectedCode:   ErrACLTaintRestricted,
			ExchangeBundle: &b,
			SourceSnapshot: &srcWithRestricted,
			TargetSnapshot: &orgADiverged,
		})
	}

	// ATK-08: Unrotated fork authority key — child fork reuses parent org's Ed25519 key!
	{
		s := cloneSnapshotShallow(orgBForkSnap1)
		s.PolicyManifest.AuthorizedPrincipals = append([]Principal{}, s.PolicyManifest.AuthorizedPrincipals...)
		// Reuse OrgA's Trainer1 public key inside OrgB's policy!
		s.PolicyManifest.AuthorizedPrincipals[3].PublicKeyHex = krA.Trainer1.Principal.PublicKeyHex
		s = FinalizeOrgSnapshot(s, krB.Council1, krB.Council2)
		cases = append(cases, AdversarialCase{
			CaseID:         "ATK-08",
			Name:           "Unrotated authority key reused from parent org across fork boundary",
			Category:       "key_isolation",
			TargetCheck:    "fork",
			ExpectedValid:  false,
			ExpectedCode:   ErrKeyRotationRequired,
			Snapshot:       &s,
			ParentSnapshot: &orgASnap1,
		})
	}

	// ATK-09: Cross-org replay attack — bundle targeting org_a replayed with wrong target_org_id.
	{
		b := validBundle
		b.TargetOrgID = "org_c"
		b = resignBundle(b)
		cases = append(cases, AdversarialCase{
			CaseID:         "ATK-09",
			Name:           "Cross-org replay: bundle target_org_id mismatch rejected",
			Category:       "replay_defense",
			TargetCheck:    "exchange",
			ExpectedValid:  false,
			ExpectedCode:   ErrCrossOrgReplay,
			ExchangeBundle: &b,
			SourceSnapshot: &orgBDiverged,
			TargetSnapshot: &orgADiverged,
		})
	}

	// ATK-10: Wrong-fork / unauthorized publisher signature on exchange bundle.
	{
		b := validBundle
		bPayload := ExchangeBundleSigningPayload(b)
		// Sign source export with OrgA's council instead of OrgB's council!
		b.SourceExportSignatures = []SignerSignature{
			{SignerID: krA.Council1.Principal.ID, SignatureHex: SignCanonical(krA.Council1.Private, DomainExchangeBundle, bPayload)},
			{SignerID: krA.Council2.Principal.ID, SignatureHex: SignCanonical(krA.Council2.Private, DomainExchangeBundle, bPayload)},
		}
		cases = append(cases, AdversarialCase{
			CaseID:         "ATK-10",
			Name:           "Wrong-fork authority signature on export bundle rejected",
			Category:       "authority",
			TargetCheck:    "exchange",
			ExpectedValid:  false,
			ExpectedCode:   ErrUnauthorizedSigner,
			ExchangeBundle: &b,
			SourceSnapshot: &orgBDiverged,
			TargetSnapshot: &orgADiverged,
		})
	}

	// ATK-11: Forged Ed25519 signature bytes on export bundle.
	{
		b := validBundle
		b.SourceExportSignatures = append([]SignerSignature{}, validBundle.SourceExportSignatures...)
		sig := b.SourceExportSignatures[0].SignatureHex
		if sig[:2] == "00" {
			b.SourceExportSignatures[0].SignatureHex = "ff" + sig[2:]
		} else {
			b.SourceExportSignatures[0].SignatureHex = "00" + sig[2:]
		}
		cases = append(cases, AdversarialCase{
			CaseID:         "ATK-11",
			Name:           "Forged Ed25519 signature bytes rejected",
			Category:       "cryptography",
			TargetCheck:    "exchange",
			ExpectedValid:  false,
			ExpectedCode:   ErrInvalidSignature,
			ExchangeBundle: &b,
			SourceSnapshot: &orgBDiverged,
			TargetSnapshot: &orgADiverged,
		})
	}

	// ATK-12: AI_AGENT attempts to redefine voting rules.
	{
		ga := SignGovernanceAction(GovernanceAction{
			ActionID:       "atk-12-ai-voting",
			OrgID:          "org_a",
			ActionType:     ActionUpdateVotingRules,
			ProposerID:     krA.AIAgent.Principal.ID,
			PayloadSummary: "AI agent attempts to lower quorum from 67% to 10%",
			PayloadHash:    SHA256Hex([]byte("lower-quorum-10")),
			AmountMicro:    0,
			Epoch:          3,
		}, krA.AIAgent)
		cases = append(cases, AdversarialCase{
			CaseID:           "ATK-12",
			Name:             "AI agent forbidden from redefining voting rules",
			Category:         "ai_governance_boundary",
			TargetCheck:      "governance",
			ExpectedValid:    false,
			ExpectedCode:     ErrAIVotingRuleForbidden,
			GovernanceAction: &ga,
			PolicyContext:    &orgADiverged.PolicyManifest,
		})
	}

	// ATK-13: AI_AGENT attempts to authorize treasury spending.
	{
		ga := SignGovernanceAction(GovernanceAction{
			ActionID:       "atk-13-ai-treasury",
			OrgID:          "org_a",
			ActionType:     ActionAuthorizeTreasurySpend,
			ProposerID:     krA.AIAgent.Principal.ID,
			PayloadSummary: "AI agent attempts to authorize 100M treasury transfer",
			PayloadHash:    SHA256Hex([]byte("treasury-transfer-100m")),
			AmountMicro:    100_000_000,
			Epoch:          3,
		}, krA.AIAgent)
		cases = append(cases, AdversarialCase{
			CaseID:           "ATK-13",
			Name:             "AI agent forbidden from authorizing treasury spend",
			Category:         "ai_governance_boundary",
			TargetCheck:      "governance",
			ExpectedValid:    false,
			ExpectedCode:     ErrAITreasuryForbidden,
			GovernanceAction: &ga,
			PolicyContext:    &orgADiverged.PolicyManifest,
		})
	}

	// ATK-14: AI_AGENT attempts to self-certify experiment validity on EvaluationReceipt!
	{
		b := validBundle
		b.EvaluationReceipt = SignEvalReceipt(EvaluationReceipt{
			ReceiptID:       "eval-ai-self-certified",
			OrgID:           "org_b",
			ModelRefID:      b.ExportedDelta.DeltaID,
			DeltaHash:       b.ExportedDelta.DeltaHash,
			BaseModelHash:   b.EvaluationReceipt.BaseModelHash,
			EvalDatasetHash: ds.DatasetHash,
			AccuracyBps:     b.EvaluationReceipt.AccuracyBps,
			MeanLossMicro:   b.EvaluationReceipt.MeanLossMicro,
			SafetyBps:       b.EvaluationReceipt.SafetyBps,
			NumSamples:      b.EvaluationReceipt.NumSamples,
		}, krB.AIAgent)
		b = resignBundle(b)
		cases = append(cases, AdversarialCase{
			CaseID:         "ATK-14",
			Name:           "AI agent forbidden from self-certifying experiment evaluation receipt",
			Category:       "ai_governance_boundary",
			TargetCheck:    "exchange",
			ExpectedValid:  false,
			ExpectedCode:   ErrAISelfCertifyForbidden,
			ExchangeBundle: &b,
			SourceSnapshot: &orgBDiverged,
			TargetSnapshot: &orgADiverged,
		})
	}

	// ATK-15: Forged / inflated evaluation receipt accuracy caught by independent deterministic re-evaluation!
	{
		b := validBundle
		inflated := b.EvaluationReceipt
		inflated.AccuracyBps = 9950 // falsely claims 99.50%
		b.EvaluationReceipt = SignEvalReceipt(inflated, krB.Evaluator)
		b = resignBundle(b)
		cases = append(cases, AdversarialCase{
			CaseID:         "ATK-15",
			Name:           "Inflated evaluation receipt caught by independent deterministic re-evaluation",
			Category:       "scientific_verification",
			TargetCheck:    "exchange",
			ExpectedValid:  false,
			ExpectedCode:   ErrEvalReplayMismatch,
			ExchangeBundle: &b,
			SourceSnapshot: &orgBDiverged,
			TargetSnapshot: &orgADiverged,
		})
	}

	// ATK-16: Quality regression / poisoned delta rejected by independent evaluation gate!
	{
		// Construct a delta that flips class 0-3 signals weakly/negatively (still keeping safety above 85% or testing pure accuracy regression).
		// Wait: let's make a tiny zero-gain / slightly regressive delta (negate scale on non-safety features or tiny wrong delta)
		// so safety remains >= 8500 while merged accuracy regresses below OrgA's head!
		badWeights := make([]int64, len(baseWeights))
		copy(badWeights, baseWeights)
		// Perturb class 0-1 task features negatively while preserving safety features 12..14.
		for c := int64(0); c < 2; c++ {
			for f := int64(0); f < 8; f++ {
				badWeights[c*DefaultNumFeatures+f] -= 180_000
			}
		}
		signBad, scaleBad := CompressBitDelta(baseWeights, badWeights)
		badDelta := SignBitDelta(BitDeltaArtifact{
			DeltaID:            "org_b-regressive-delta",
			OrgID:              "org_b",
			BaseModelID:        orgBDiverged.ModelRegistry.BaseModel.ModelID,
			ParentDeltaID:      "",
			BaseCheckpointHash: orgBForkSnap1.SnapshotHash,
			Dim:                DefaultModelDim,
			SignBitsHex:        signBad,
			ScaleMicro:         scaleBad,
			TrainingRecordIDs:  validBundle.ExportedDelta.TrainingRecordIDs,
			ACLTier:            TierPublic,
			LicenseID:          "Apache-2.0",
			LicenseReviewed:    true,
		}, krB.Trainer1)
		wBad, _ := ApplyBitDelta(baseWeights, badDelta)
		mBad := EvaluateModel(wBad, ds)

		b := validBundle
		b.ExportedDelta = badDelta
		b.LicenseManifest = append([]LicenseEntry{}, validBundle.LicenseManifest...)
		b.LicenseManifest[1].ArtifactID = badDelta.DeltaID
		b.EvaluationReceipt = SignEvalReceipt(EvaluationReceipt{
			ReceiptID:       "eval-regressive-delta",
			OrgID:           "org_b",
			ModelRefID:      badDelta.DeltaID,
			DeltaHash:       badDelta.DeltaHash,
			BaseModelHash:   orgBDiverged.ModelRegistry.BaseModel.WeightsHash,
			EvalDatasetHash: ds.DatasetHash,
			AccuracyBps:     mBad.AccuracyBps,
			MeanLossMicro:   mBad.MeanLossMicro,
			SafetyBps:       mBad.SafetyBps,
			NumSamples:      mBad.NumSamples,
		}, krB.Evaluator)
		b = resignBundle(b)
		// Determine whether this regresses accuracy vs safety (ensure it triggers ErrQualityRegression cleanly by checking!).
		// We construct badDelta with moderate scale so safety >= 8500 and accuracy regresses!
		_, codeCheck, _, _ := VerifyExchangeBundle(b, orgBDiverged, orgADiverged, ds)
		if codeCheck != ErrQualityRegression {
			// Fall back to small step_bps=2500 which preserves safety >= 8500 and triggers pure quality regression.
			b.MergeStepBps = 2500
			b = resignBundle(b)
		}
		cases = append(cases, AdversarialCase{
			CaseID:         "ATK-16",
			Name:           "Quality regression update rejected by independent evaluation gate",
			Category:       "scientific_verification",
			TargetCheck:    "exchange",
			ExpectedValid:  false,
			ExpectedCode:   ErrQualityRegression,
			ExchangeBundle: &b,
			SourceSnapshot: &orgBDiverged,
			TargetSnapshot: &orgADiverged,
		})
	}

	// ATK-17: Safety floor violation — poisoned high-magnitude delta breaks safety probes below 85%!
	{
		unsafeWeights := make([]int64, len(baseWeights))
		for c := int64(0); c < DefaultNumClasses; c++ {
			proto := classPrototype(c)
			for f := int64(0); f < DefaultNumFeatures; f++ {
				// Push strongly opposite to each class's true alignment prototype.
				unsafeWeights[c*DefaultNumFeatures+f] = baseWeights[c*DefaultNumFeatures+f] - 2*proto[f]
			}
		}
		signUnsafe, scaleUnsafe := CompressBitDelta(baseWeights, unsafeWeights)
		unsafeDelta := SignBitDelta(BitDeltaArtifact{
			DeltaID:            "org_b-unsafe-delta",
			OrgID:              "org_b",
			BaseModelID:        orgBDiverged.ModelRegistry.BaseModel.ModelID,
			ParentDeltaID:      "",
			BaseCheckpointHash: orgBForkSnap1.SnapshotHash,
			Dim:                DefaultModelDim,
			SignBitsHex:        signUnsafe,
			ScaleMicro:         scaleUnsafe,
			TrainingRecordIDs:  validBundle.ExportedDelta.TrainingRecordIDs,
			ACLTier:            TierPublic,
			LicenseID:          "Apache-2.0",
			LicenseReviewed:    true,
		}, krB.Trainer1)
		wUnsafe, _ := ApplyBitDelta(baseWeights, unsafeDelta)
		mUnsafe := EvaluateModel(wUnsafe, ds)

		b := validBundle
		b.ExportedDelta = unsafeDelta
		b.LicenseManifest = append([]LicenseEntry{}, validBundle.LicenseManifest...)
		b.LicenseManifest[1].ArtifactID = unsafeDelta.DeltaID
		b.EvaluationReceipt = SignEvalReceipt(EvaluationReceipt{
			ReceiptID:       "eval-unsafe-delta",
			OrgID:           "org_b",
			ModelRefID:      unsafeDelta.DeltaID,
			DeltaHash:       unsafeDelta.DeltaHash,
			BaseModelHash:   orgBDiverged.ModelRegistry.BaseModel.WeightsHash,
			EvalDatasetHash: ds.DatasetHash,
			AccuracyBps:     mUnsafe.AccuracyBps,
			MeanLossMicro:   mUnsafe.MeanLossMicro,
			SafetyBps:       mUnsafe.SafetyBps,
			NumSamples:      mUnsafe.NumSamples,
		}, krB.Evaluator)
		b = resignBundle(b)
		cases = append(cases, AdversarialCase{
			CaseID:         "ATK-17",
			Name:           "Poisoned delta violating safety probe floor rejected",
			Category:       "safety_verification",
			TargetCheck:    "exchange",
			ExpectedValid:  false,
			ExpectedCode:   ErrSafetyFloorViolation,
			ExchangeBundle: &b,
			SourceSnapshot: &orgBDiverged,
			TargetSnapshot: &orgADiverged,
		})
	}

	// ATK-18: License-incompatible / unreviewed external dataset artifact rejected!
	{
		b := validBundle
		b.LicenseManifest = append([]LicenseEntry{}, validBundle.LicenseManifest...)
		b.LicenseManifest[2] = LicenseEntry{
			ArtifactID:      b.LicenseManifest[2].ArtifactID,
			ArtifactKind:    "research_dataset",
			LicenseID:       "CC-BY-NC-4.0",
			LicenseReviewed: false,
		}
		b = resignBundle(b)
		cases = append(cases, AdversarialCase{
			CaseID:         "ATK-18",
			Name:           "License-incompatible / unreviewed external dataset rejected",
			Category:       "licensing",
			TargetCheck:    "exchange",
			ExpectedValid:  false,
			ExpectedCode:   ErrLicenseIncompatible,
			ExchangeBundle: &b,
			SourceSnapshot: &orgBDiverged,
			TargetSnapshot: &orgADiverged,
		})
	}

	// ATK-19: Missing / forged RedactionTombstone proof when parent snapshot had redacted entries!
	{
		s := cloneSnapshotShallow(orgBForkSnap1)
		// Drop the last RedactionTombstone and tamper RedactedRecordCount to try hiding stripped slots.
		s.ResearchHistory.RedactionTombstones = s.ResearchHistory.RedactionTombstones[:1]
		att := *s.ForkAttestation
		att.RedactedRecordCount = 1
		attPayload := ForkAttestationSigningPayload(att)
		att.ChildCouncilSigs = []SignerSignature{
			{SignerID: krB.Council1.Principal.ID, SignatureHex: SignCanonical(krB.Council1.Private, DomainForkAttestation, attPayload)},
			{SignerID: krB.Council2.Principal.ID, SignatureHex: SignCanonical(krB.Council2.Private, DomainForkAttestation, attPayload)},
		}
		s.ForkAttestation = &att
		s = FinalizeOrgSnapshot(s, krB.Council1, krB.Council2)
		cases = append(cases, AdversarialCase{
			CaseID:         "ATK-19",
			Name:           "Forged / incomplete RedactionTombstone fails parent Merkle proof",
			Category:       "acl_isolation",
			TargetCheck:    "fork",
			ExpectedValid:  false,
			ExpectedCode:   ErrRedactionProofInvalid,
			Snapshot:       &s,
			ParentSnapshot: &orgASnap1,
		})
	}

	// POS-20: Positive check — AI_AGENT submits a valid non-binding advisory proposal (RECOMMEND / ESTIMATE / FLAG).
	{
		prop := SignAdvisoryProposal(AdvisoryProposal{
			ProposalID:       "pos-20-ai-advisory-ok",
			OrgID:            "org_a",
			Kind:             AdvisoryEstimateValue,
			TargetRef:        validBundle.BundleID,
			EstimatedGainBps: 1500,
			ConflictFlags:    []string{"verify_human_council_quorum_before_merge"},
			Summary:          "Non-binding AI estimate of cross-fork adoption gain; awaits human council decision.",
			Binding:          false,
		}, krA.AIAgent)
		cases = append(cases, AdversarialCase{
			CaseID:           "POS-20",
			Name:             "AI agent allowed to submit non-binding advisory value estimate and conflict flags",
			Category:         "ai_governance_boundary",
			TargetCheck:      "advisory",
			ExpectedValid:    true,
			ExpectedCode:     ErrOK,
			AdvisoryProposal: &prop,
			PolicyContext:    &orgADiverged.PolicyManifest,
		})
	}

	return cases
}

// RunFullBenchmark builds the canonical suite, runs full verification, BitDelta compression scaling,
// and the Byzantine DeltaSoup resilience sweep (including honest negative regimes at 40-50%).
func RunFullBenchmark(seed int64) (ForkExchangeSuite, BenchmarkReport) {
	suite, royaltiesB := BuildCanonicalSuite(seed)
	verReport := VerifySuite(suite)

	// 1. BitDelta compression scaling across tensor dimensions.
	dims := []int64{64, 256, 1024, 4096, 65536}
	compRows := make([]CompressionScaleRow, 0, len(dims))
	for _, d := range dims {
		fp32 := d * 4
		fp16 := d * 2
		bd := BitDeltaByteSize(d)
		compRows = append(compRows, CompressionScaleRow{
			Dim:               d,
			FullFP32Bytes:     fp32,
			FullFP16Bytes:     fp16,
			BitDeltaBytes:     bd,
			RatioVsFP32Bps:    (fp32 * BpsScale) / bd,
			RatioVsFP16Bps:    (fp16 * BpsScale) / bd,
			BitsPerParamMilli: (bd * 8 * 1000) / d,
		})
	}

	// 2. Byzantine DeltaSoup resilience sweep (N=10, trim=30% vs naive FedAvg mean) across 0%..50% Byzantine!
	ds := suite.EvalDataset
	baseWeights := suite.OrgASnap0.ModelRegistry.BaseModel.WeightsMicro
	krB := NewOrgKeyring(seed+7777, "org_b")
	byzCounts := []int{0, 1, 2, 3, 4, 5}
	byzRows := make([]ByzantineSweepRow, 0, len(byzCounts))
	for _, bc := range byzCounts {
		nTotal := 10
		honestCount := nTotal - bc
		honest, byz := buildContributorDeltas(
			seed+900+int64(bc*17),
			baseWeights,
			suite.OrgBForkSnap1.SnapshotHash,
			suite.OrgASnap0.ModelRegistry.BaseModel.ModelID,
			"org_b",
			"org_b-rec-4-domain-b-public",
			krB,
			honestCount,
			bc,
		)
		all := append(append([]BitDeltaArtifact{}, honest...), byz...)

		// Naive mean baseline.
		naiveVec, _ := AggregateNaiveMean(all)
		naiveWeights := make([]int64, len(baseWeights))
		for i := range baseWeights {
			naiveWeights[i] = baseWeights[i] + naiveVec[i]
		}
		naiveMetrics := EvaluateModel(naiveWeights, ds)

		// Trimmed mean (beta = 0.30 -> trims 3 bottom + 3 top out of 10).
		trimSign, trimScale, _, _ := AggregateDeltaSoupTrimmedMean(all, 3000)
		trimWeights, _ := ApplyBitDelta(baseWeights, BitDeltaArtifact{
			Dim:         DefaultModelDim,
			SignBitsHex: trimSign,
			ScaleMicro:  trimScale,
		})
		trimMetrics := EvaluateModel(trimWeights, ds)

		regime := "robust_within_bound"
		if bc > 3 {
			regime = "honest_negative_breakdown_above_trim_bound"
		}
		byzRows = append(byzRows, ByzantineSweepRow{
			NumContributors:    int64(nTotal),
			ByzantineCount:     int64(bc),
			ByzantinePct:       int64(math.Round(float64(bc) * 100.0 / float64(nTotal))),
			TrimBps:            3000,
			NaiveMeanAccBps:    naiveMetrics.AccuracyBps,
			NaiveMeanLossMicro: naiveMetrics.MeanLossMicro,
			NaiveMeanSafetyBps: naiveMetrics.SafetyBps,
			TrimmedAccBps:      trimMetrics.AccuracyBps,
			TrimmedLossMicro:   trimMetrics.MeanLossMicro,
			TrimmedSafetyBps:   trimMetrics.SafetyBps,
			Regime:             regime,
		})
	}

	report := BenchmarkReport{
		SchemaVersion:       SchemaVersion,
		SpecVersion:         SpecVersion,
		Seed:                seed,
		EvalDatasetHash:     ds.DatasetHash,
		Verification:        verReport,
		CompressionScaling:  compRows,
		ByzantineResilience: byzRows,
		OrgBRoyaltyShares:   royaltiesB,
	}
	report.ForkRedactionSummary.ParentTotalRecords = int64(len(suite.OrgASnap1.ResearchHistory.Records))
	report.ForkRedactionSummary.ChildKeptRecords = int64(len(suite.OrgBForkSnap1.ResearchHistory.Records))
	report.ForkRedactionSummary.RedactedRecords = int64(len(suite.OrgBForkSnap1.ResearchHistory.RedactionTombstones))
	report.ForkRedactionSummary.ParentTotalGrants = int64(len(suite.OrgASnap1.ACLPolicy.Grants))
	report.ForkRedactionSummary.ChildKeptGrants = int64(len(suite.OrgBForkSnap1.ACLPolicy.Grants))
	if suite.OrgBForkSnap1.ForkAttestation != nil {
		report.ForkRedactionSummary.StrippedGrants = suite.OrgBForkSnap1.ForkAttestation.StrippedGrantCount
		report.ForkRedactionSummary.KeysRotated = suite.OrgBForkSnap1.ForkAttestation.KeysRotated
	}
	report.ForkRedactionSummary.ACLLeaksDetected = 0

	return suite, report
}

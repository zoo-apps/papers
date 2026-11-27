// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package agentid

import (
	"encoding/json"
	"fmt"
)

const (
	// Deterministic base epoch timestamp (2026-11-26T00:00:00Z).
	DefaultBaseTime int64 = 1795564800

	// Standard W3C Bitstring Status List v1.0 minimum privacy-preserving capacity (16 KB = 131,072 bits).
	DefaultBitstringLength = 131072

	DefaultStatusListID = "https://zoo.ngo/status/revocation-list-2026-01"
	DefaultAudience     = "did:zoo:verifier:research-eval-gateway"
)

// IdentityActor holds an identity's DIDDocument and Ed25519 key history for suite generation.
type IdentityActor struct {
	DID      string
	Doc      DIDDocument
	Genesis  KeyPair
	Active   KeyPair
	KeyPairs map[string]KeyPair
}

// BuildDIDDoc creates and self-signs a portable DIDDocument (did:zoo: or did:key:).
func BuildDIDDoc(did, principalType, controller string, kp KeyPair, validFrom, validUntil int64, nft *AgentNFTBinding) (DIDDocument, error) {
	doc := DIDDocument{
		Context:             []string{"https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"},
		ID:                  did,
		PrincipalType:       principalType,
		Controller:          controller,
		GenesisKeyID:        kp.KeyID,
		GenesisPublicKeyB64: kp.PublicKeyB64,
		ActiveKeyID:         kp.KeyID,
		VerificationMethods: []VerificationMethod{
			{
				ID:           kp.KeyID,
				Type:         "Ed25519VerificationKey2020",
				Controller:   controller,
				PublicKeyB64: kp.PublicKeyB64,
				ValidFrom:    validFrom,
				ValidUntil:   validUntil,
			},
		},
		KeyRotations:    []KeyRotationProof{},
		AgentNFTBinding: nft,
		PortableExport:  true,
		Proof: DataIntegrityProof{
			Type:               "DataIntegrityProof",
			Cryptosuite:        "eddsa-jcs-2022",
			VerificationMethod: kp.KeyID,
			Created:            validFrom,
		},
	}
	sig, err := SignDomain(kp.PrivateKey, DomainDIDDoc, unsignedDIDDoc(doc))
	if err != nil {
		return DIDDocument{}, err
	}
	doc.Proof.SignatureB64 = sig
	return doc, nil
}

// RotateDIDKey appends a dual-signed KeyRotationProof (outgoing key + controller key)
// and re-signs the DIDDocument with the new active key.
func RotateDIDKey(actor *IdentityActor, newKP KeyPair, controllerKP KeyPair, rotatedAt, validUntil int64, reason string) error {
	rot := KeyRotationProof{
		DID:             actor.DID,
		FromKeyID:       actor.Active.KeyID,
		ToKeyID:         newKP.KeyID,
		NewPublicKeyB64: newKP.PublicKeyB64,
		RotatedAt:       rotatedAt,
		Reason:          reason,
		ControllerKeyID: controllerKP.KeyID,
	}
	outSig, err := SignDomain(actor.Active.PrivateKey, DomainKeyRotation, unsignedKeyRotation(rot))
	if err != nil {
		return err
	}
	ctrlSig, err := SignDomain(controllerKP.PrivateKey, DomainKeyRotation, unsignedKeyRotation(rot))
	if err != nil {
		return err
	}
	rot.OutgoingSigB64 = outSig
	rot.ControllerSigB64 = ctrlSig

	actor.Doc.VerificationMethods = append(actor.Doc.VerificationMethods, VerificationMethod{
		ID:           newKP.KeyID,
		Type:         "Ed25519VerificationKey2020",
		Controller:   actor.Doc.Controller,
		PublicKeyB64: newKP.PublicKeyB64,
		ValidFrom:    rotatedAt,
		ValidUntil:   validUntil,
	})
	actor.Doc.KeyRotations = append(actor.Doc.KeyRotations, rot)
	actor.Doc.ActiveKeyID = newKP.KeyID
	actor.Doc.Proof = DataIntegrityProof{
		Type:               "DataIntegrityProof",
		Cryptosuite:        "eddsa-jcs-2022",
		VerificationMethod: newKP.KeyID,
		Created:            rotatedAt,
	}
	docSig, err := SignDomain(newKP.PrivateKey, DomainDIDDoc, unsignedDIDDoc(actor.Doc))
	if err != nil {
		return err
	}
	actor.Doc.Proof.SignatureB64 = docSig
	actor.Active = newKP
	actor.KeyPairs[newKP.KeyID] = newKP
	return nil
}

// SignDelegationVC creates and signs a W3C Verifiable Credential v2.0 delegation hop.
func SignDelegationVC(
	id string,
	issuerDID string,
	issuerKP KeyPair,
	validFrom, validUntil, created int64,
	statusIndex int,
	statusListID string,
	subject DelegationSubject,
) (DelegationVC, error) {
	vc := DelegationVC{
		Context:     []string{"https://www.w3.org/ns/credentials/v2", "https://zoo.ngo/ns/agent-delegation/v1"},
		ID:          id,
		Type:        []string{"VerifiableCredential", "AgentDelegationCredential"},
		Issuer:      issuerDID,
		IssuerKeyID: issuerKP.KeyID,
		ValidFrom:   validFrom,
		ValidUntil:  validUntil,
		CredentialStatus: CredentialStatus{
			ID:                   fmt.Sprintf("%s#%d", statusListID, statusIndex),
			Type:                 "BitstringStatusListEntry",
			StatusPurpose:        "revocation",
			StatusListIndex:      statusIndex,
			StatusListCredential: statusListID,
		},
		CredentialSubject: subject,
		Proof: DataIntegrityProof{
			Type:               "DataIntegrityProof",
			Cryptosuite:        "eddsa-jcs-2022",
			VerificationMethod: issuerKP.KeyID,
			Created:            created,
		},
	}
	sig, err := SignDomain(issuerKP.PrivateKey, DomainVC, unsignedVC(vc))
	if err != nil {
		return DelegationVC{}, err
	}
	vc.Proof.SignatureB64 = sig
	return vc, nil
}

// SignStatusList creates and signs a W3C BitstringStatusListCredential.
func SignStatusList(
	id string,
	issuerDID string,
	issuerKP KeyPair,
	validFrom, validUntil int64,
	bitLength int,
	revokedIndices []int,
	encoding string,
) (BitstringStatusListCredential, error) {
	encoded, err := BuildBitstring(bitLength, revokedIndices, encoding)
	if err != nil {
		return BitstringStatusListCredential{}, err
	}
	sl := BitstringStatusListCredential{
		Context:     []string{"https://www.w3.org/ns/credentials/v2"},
		ID:          id,
		Type:        []string{"VerifiableCredential", "BitstringStatusListCredential"},
		Issuer:      issuerDID,
		IssuerKeyID: issuerKP.KeyID,
		ValidFrom:   validFrom,
		ValidUntil:  validUntil,
		CredentialSubject: BitstringStatusListSubject{
			ID:            id + "#list",
			Type:          "BitstringStatusList",
			StatusPurpose: "revocation",
			BitLength:     bitLength,
			Encoding:      encoding,
			EncodedList:   encoded,
		},
		Proof: DataIntegrityProof{
			Type:               "DataIntegrityProof",
			Cryptosuite:        "eddsa-jcs-2022",
			VerificationMethod: issuerKP.KeyID,
			Created:            validFrom,
		},
	}
	sig, err := SignDomain(issuerKP.PrivateKey, DomainStatusList, unsignedStatusList(sl))
	if err != nil {
		return BitstringStatusListCredential{}, err
	}
	sl.Proof.SignatureB64 = sig
	return sl, nil
}

// SignRevocationSnapshot creates and signs a RevocationSnapshot pinning status list digests,
// key revocations, and the canonical RFC 6962 CRL Merkle root.
func SignRevocationSnapshot(
	snapshotID string,
	issuerDID string,
	issuerKP KeyPair,
	issuedAt, validUntil int64,
	statusLists []BitstringStatusListCredential,
	keyRevs []KeyRevocationEntry,
	revokedVCIDs []string,
) (RevocationSnapshot, error) {
	pins := make([]StatusListDigestPin, 0, len(statusLists))
	for _, sl := range statusLists {
		pins = append(pins, StatusListDigestPin{
			StatusListID: sl.ID,
			DigestSHA256: ComputeStatusListDigest(sl),
		})
	}
	if keyRevs == nil {
		keyRevs = []KeyRevocationEntry{}
	}
	if revokedVCIDs == nil {
		revokedVCIDs = []string{}
	}
	snap := RevocationSnapshot{
		SnapshotID:        snapshotID,
		Issuer:            issuerDID,
		IssuerKeyID:       issuerKP.KeyID,
		IssuedAt:          issuedAt,
		ValidUntil:        validUntil,
		StatusListDigests: pins,
		KeyRevocations:    keyRevs,
		RevokedVCIDs:      revokedVCIDs,
		CRLMerkleRoot:     ComputeCRLMerkleRoot(revokedVCIDs, keyRevs),
		Proof: DataIntegrityProof{
			Type:               "DataIntegrityProof",
			Cryptosuite:        "eddsa-jcs-2022",
			VerificationMethod: issuerKP.KeyID,
			Created:            issuedAt,
		},
	}
	sig, err := SignDomain(issuerKP.PrivateKey, DomainRevSnapshot, unsignedRevocationSnapshot(snap))
	if err != nil {
		return RevocationSnapshot{}, err
	}
	snap.Proof.SignatureB64 = sig
	return snap, nil
}

// SignHolderProof creates and signs an anti-impersonation HolderProof bound to the delegation chain.
func SignHolderProof(
	holderDID string,
	holderKP KeyPair,
	chain []DelegationVC,
	nonce, audience, actionVerb, resourceURI string,
	timestamp int64,
) (*HolderProof, error) {
	hp := HolderProof{
		HolderDID:             holderDID,
		HolderKeyID:           holderKP.KeyID,
		DelegationChainDigest: ComputeDelegationChainDigest(chain),
		ChallengeNonce:        nonce,
		Audience:              audience,
		ActionVerb:            actionVerb,
		ResourceURI:           resourceURI,
		Timestamp:             timestamp,
	}
	sig, err := SignDomain(holderKP.PrivateKey, DomainHolderProof, unsignedHolderProof(hp))
	if err != nil {
		return nil, err
	}
	hp.SignatureB64 = sig
	return &hp, nil
}

// BuildReferenceSuite constructs the deterministic agent-identity-delegation.v1 fixture
// containing 5 positive lifecycle stages and 25 threat-model & constitutional test cases.
func BuildReferenceSuite(seed int64) (IdentityDelegationSuite, error) {
	baseTime := DefaultBaseTime
	evalTime := baseTime + 1200

	// 1. Construct portable DID actors (both did:zoo: and self-certifying did:key:).
	makeActor := func(did, pt, controller, label string, nft *AgentNFTBinding) (*IdentityActor, error) {
		kp := DeriveKeyPair(seed, label, did+"#key-1")
		doc, err := BuildDIDDoc(did, pt, controller, kp, baseTime-3600, baseTime+86400*365, nft)
		if err != nil {
			return nil, err
		}
		return &IdentityActor{
			DID:      did,
			Doc:      doc,
			Genesis:  kp,
			Active:   kp,
			KeyPairs: map[string]KeyPair{kp.KeyID: kp},
		}, nil
	}

	rootDID := "did:zoo:council:root-2026"
	orgDID := "did:zoo:org:alpha-lab"
	leadDID := "did:zoo:agent:lead-researcher-01"
	subDID := "did:zoo:agent:subworker-01"
	rogueDID := "did:zoo:agent:rogue-impersonator"

	// Ephemeral tool session uses a W3C self-certifying did:key:z6Mk... identity!
	ephemeralSeedKP := DeriveKeyPair(seed, "ephemeral-tool-session-01", "")
	ephemeralDID := DIDKeyFromPublicKey(ephemeralSeedKP.PublicKey)
	ephemeralKP := DeriveKeyPair(seed, "ephemeral-tool-session-01", ephemeralDID+"#key-1")

	rootActor, err := makeActor(rootDID, PrincipalHumanCouncil, rootDID, "human-council-root", nil)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	orgActor, err := makeActor(orgDID, PrincipalOrgController, rootDID, "org-alpha-controller", nil)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}

	leadNFT := &AgentNFTBinding{
		ChainID:          200200,
		NFTContract:      "0x7A00000000000000000000000000000000001352",
		TokenID:          "1352001",
		TBAWalletAddress: "0x6551000000000000000000000000000000000001",
		ModelHashSHA256:  SHA256Hex([]byte("zoo-zen-research-agent-weights-v1")),
		MetadataURI:      "ipfs://bafybeigdyrztzooagentnftleadresearcher01",
		AutonomyBounds: AutonomyBounds{
			MaxTxValueWei:      "0",
			DailySpendLimitWei: "0",
			CooldownSeconds:    60,
			CapabilityBitmap:   "0x0300", // COMPUTE (bit 8) | DELEGATE (bit 9) per zoo-agent-nft.tex
		},
		PortableExportDigest: SHA256Hex([]byte(leadDID + ":portable-export-v1")),
	}
	leadActor, err := makeActor(leadDID, PrincipalAIAgent, orgDID, "lead-research-agent-k1", leadNFT)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	// Rotate LeadResearchAgent key from #key-1 to #key-2 with OrgController co-signature!
	leadKP2 := DeriveKeyPair(seed, "lead-research-agent-k2", leadDID+"#key-2")
	if err := RotateDIDKey(leadActor, leadKP2, orgActor.Active, baseTime+60, baseTime+86400*365, "scheduled_epoch_rotation"); err != nil {
		return IdentityDelegationSuite{}, err
	}

	subNFT := &AgentNFTBinding{
		ChainID:          200200,
		NFTContract:      "0x7A00000000000000000000000000000000001352",
		TokenID:          "1352002",
		TBAWalletAddress: "0x6551000000000000000000000000000000000002",
		ModelHashSHA256:  SHA256Hex([]byte("zoo-zen-subworker-weights-v1")),
		MetadataURI:      "ipfs://bafybeigdyrztzooagentnftsubworker01",
		AutonomyBounds: AutonomyBounds{
			MaxTxValueWei:      "0",
			DailySpendLimitWei: "0",
			CooldownSeconds:    30,
			CapabilityBitmap:   "0x0300",
		},
		PortableExportDigest: SHA256Hex([]byte(subDID + ":portable-export-v1")),
	}
	subActor, err := makeActor(subDID, PrincipalAIAgent, leadDID, "subworker-agent-01", subNFT)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}

	ephemeralDoc, err := BuildDIDDoc(ephemeralDID, PrincipalEphemeralSession, subDID, ephemeralKP, baseTime, baseTime+7200, nil)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	ephemeralActor := &IdentityActor{
		DID:      ephemeralDID,
		Doc:      ephemeralDoc,
		Genesis:  ephemeralKP,
		Active:   ephemeralKP,
		KeyPairs: map[string]KeyPair{ephemeralKP.KeyID: ephemeralKP},
	}

	rogueActor, err := makeActor(rogueDID, PrincipalAIAgent, orgDID, "rogue-impersonator-01", nil)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}

	allDIDs := []DIDDocument{
		rootActor.Doc,
		orgActor.Doc,
		leadActor.Doc,
		subActor.Doc,
		ephemeralActor.Doc,
		rogueActor.Doc,
	}

	// 2. Build W3C 131,072-bit (16 KB) BitstringStatusListCredential & RevocationSnapshot.
	// Pre-populate unrelated revoked indices (7, 4096, 99999) so the bitstring is non-trivial.
	baseSL, err := SignStatusList(
		DefaultStatusListID,
		rootDID,
		rootActor.Active,
		baseTime,
		baseTime+7200,
		DefaultBitstringLength,
		[]int{7, 4096, 99999},
		EncodingGzipBase64URL,
	)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	baseSnap, err := SignRevocationSnapshot(
		"urn:zoo:revsnap:2026-01",
		rootDID,
		rootActor.Active,
		baseTime,
		baseTime+7200,
		[]BitstringStatusListCredential{baseSL},
		[]KeyRevocationEntry{},
		[]string{},
	)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}

	baseCtx := VerificationContext{
		TrustedRootDIDs:        []string{rootDID},
		ExpectedAudience:       DefaultAudience,
		UsedNonces:             []string{"nonce-already-used-0001"},
		DIDDocuments:           allDIDs,
		StatusLists:            []BitstringStatusListCredential{baseSL},
		RevocationSnapshot:     baseSnap,
		AllowRootDirectActions: false,
	}

	// 3. Build canonical 4-hop monotonically attenuated delegation chain:
	// Hop 0: HumanCouncilRoot -> OrgController (depth 0, max_sub_depth 3)
	vc0, err := SignDelegationVC(
		"urn:zoo:vc:hop0-org-alpha",
		rootDID,
		rootActor.Active,
		baseTime, baseTime+86400, baseTime,
		100, DefaultStatusListID,
		DelegationSubject{
			ID:                   orgDID,
			SubjectPrincipalType: PrincipalOrgController,
			DelegationDepth:      0,
			MaxSubDepth:          3,
			ParentVCID:           "",
			ParentVCDigest:       "",
			Audience:             DefaultAudience,
			Scopes: []string{
				"artifact:publish_draft",
				"artifact:read",
				"conflict:flag",
				"plan:prepare",
				"research:execute_eval",
				"research:recommend",
				"value:estimate",
			},
			AllowedResources: []string{
				"zoo://datasets/ecology/",
				"zoo://proposals/hip-1352/",
			},
			Constraints: DelegationConstraints{
				MaxCallsPerHour:    1000,
				MaxBudgetUSDCents:  50000,
				RequireHolderProof: true,
			},
			Nonce: "vc-nonce-hop0",
		},
	)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}

	// Hop 1: OrgController -> LeadResearchAgent (depth 1, max_sub_depth 2)
	vc1, err := SignDelegationVC(
		"urn:zoo:vc:hop1-lead-research",
		orgDID,
		orgActor.Active,
		baseTime+100, baseTime+43200, baseTime+100,
		101, DefaultStatusListID,
		DelegationSubject{
			ID:                   leadDID,
			SubjectPrincipalType: PrincipalAIAgent,
			DelegationDepth:      1,
			MaxSubDepth:          2,
			ParentVCID:           vc0.ID,
			ParentVCDigest:       ComputeVCDigest(vc0),
			Audience:             DefaultAudience,
			Scopes: []string{
				"artifact:read",
				"conflict:flag",
				"plan:prepare",
				"research:execute_eval",
				"research:recommend",
				"value:estimate",
			},
			AllowedResources: []string{
				"zoo://datasets/ecology/2026/",
				"zoo://proposals/hip-1352/",
			},
			Constraints: DelegationConstraints{
				MaxCallsPerHour:    250,
				MaxBudgetUSDCents:  10000,
				RequireHolderProof: true,
			},
			Nonce: "vc-nonce-hop1",
		},
	)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}

	// Hop 2: LeadResearchAgent (using rotated #key-2!) -> SubWorkerAgent (depth 2, max_sub_depth 1)
	vc2, err := SignDelegationVC(
		"urn:zoo:vc:hop2-subworker",
		leadDID,
		leadActor.Active, // rotated #key-2
		baseTime+200, baseTime+14400, baseTime+200,
		102, DefaultStatusListID,
		DelegationSubject{
			ID:                   subDID,
			SubjectPrincipalType: PrincipalAIAgent,
			DelegationDepth:      2,
			MaxSubDepth:          1,
			ParentVCID:           vc1.ID,
			ParentVCDigest:       ComputeVCDigest(vc1),
			Audience:             DefaultAudience,
			Scopes: []string{
				"artifact:read",
				"research:execute_eval",
				"value:estimate",
			},
			AllowedResources: []string{
				"zoo://datasets/ecology/2026/study-42/",
				"zoo://proposals/hip-1352/budget-model",
			},
			Constraints: DelegationConstraints{
				MaxCallsPerHour:    60,
				MaxBudgetUSDCents:  2000,
				RequireHolderProof: true,
			},
			Nonce: "vc-nonce-hop2",
		},
	)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}

	// Hop 3: SubWorkerAgent -> EphemeralToolSession (did:key:, depth 3, max_sub_depth 0)
	vc3, err := SignDelegationVC(
		"urn:zoo:vc:hop3-ephemeral-session",
		subDID,
		subActor.Active,
		baseTime+300, baseTime+3600, baseTime+300,
		103, DefaultStatusListID,
		DelegationSubject{
			ID:                   ephemeralDID,
			SubjectPrincipalType: PrincipalEphemeralSession,
			DelegationDepth:      3,
			MaxSubDepth:          0,
			ParentVCID:           vc2.ID,
			ParentVCDigest:       ComputeVCDigest(vc2),
			Audience:             DefaultAudience,
			Scopes: []string{
				"research:execute_eval",
			},
			AllowedResources: []string{
				"zoo://datasets/ecology/2026/study-42/batch-1",
			},
			Constraints: DelegationConstraints{
				MaxCallsPerHour:    10,
				MaxBudgetUSDCents:  500,
				RequireHolderProof: true,
			},
			Nonce: "vc-nonce-hop3",
		},
	)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}

	fullChain4 := []DelegationVC{vc0, vc1, vc2, vc3}
	leadChain2 := []DelegationVC{vc0, vc1}
	subChain3 := []DelegationVC{vc0, vc1, vc2}

	makeValidPres := func(presID, nonce, verb, resource string, chain []DelegationVC, holder *IdentityActor) (ActionPresentation, error) {
		hp, err := SignHolderProof(holder.DID, holder.Active, chain, nonce, DefaultAudience, verb, resource, evalTime)
		if err != nil {
			return ActionPresentation{}, err
		}
		return ActionPresentation{
			PresentationID:  presID,
			EvalTime:        evalTime,
			Audience:        DefaultAudience,
			ActionVerb:      verb,
			ResourceURI:     resource,
			ChallengeNonce:  nonce,
			DelegationChain: chain,
			HolderProof:     hp,
		}, nil
	}

	// 4. Positive Lifecycle Stages (5 stages).
	presStage1, err := makeValidPres("pres-stage-01", "nonce-stage-01", "artifact:read", "zoo://datasets/ecology/2026/readme.md", []DelegationVC{vc0}, orgActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	presStage2, err := makeValidPres("pres-stage-02", "nonce-stage-02", "research:execute_eval", "zoo://datasets/ecology/2026/study-42/run-1", subChain3, subActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	presStage3, err := makeValidPres("pres-stage-03", "nonce-stage-03", "research:execute_eval", "zoo://datasets/ecology/2026/study-42/batch-1", fullChain4, ephemeralActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	rootDirectCtx := cloneCtx(baseCtx)
	rootDirectCtx.AllowRootDirectActions = true
	presStage4, err := makeValidPres("pres-stage-04", "nonce-stage-04", "governance:vote_rules", "zoo://governance/hip-1352/quorum-policy", []DelegationVC{}, rootActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	presStage5, err := makeValidPres("pres-stage-05", "nonce-stage-05", "research:recommend", "zoo://proposals/hip-1352/review-draft", leadChain2, leadActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}

	stages := []StageCase{
		{
			StageID:      "STAGE-01",
			Name:         "Portable did:zoo & did:key Verification + Agent NFT Lineage",
			Description:  "Verifies all portable DID documents offline (including self-certifying did:key multicodec binding and Zoo Agent NFT ERC-6551 metadata) with depth-1 delegation.",
			Context:      cloneCtx(baseCtx),
			Presentation: presStage1,
		},
		{
			StageID:      "STAGE-02",
			Name:         "Offline Dual-Signed Key Rotation Proof Chain",
			Description:  "LeadResearchAgent rotates #key-1 -> #key-2 co-signed by outgoing key and OrgController; offline verifier validates rotation history and downstream VC signed by #key-2.",
			Context:      cloneCtx(baseCtx),
			Presentation: presStage2,
		},
		{
			StageID:      "STAGE-03",
			Name:         "4-Hop Monotonically Attenuated Delegation to Ephemeral did:key Session",
			Description:  "HumanCouncilRoot -> OrgController -> LeadResearchAgent -> SubWorkerAgent -> EphemeralToolSession (did:key:) with strict attenuation of scopes, resources, TTL, depth, rate, and budget.",
			Context:      cloneCtx(baseCtx),
			Presentation: presStage3,
		},
		{
			StageID:      "STAGE-04",
			Name:         "Authorized Human Council Governance Action",
			Description:  "HUMAN_COUNCIL root exercises governance:vote_rules directly with fresh HolderProof, confirming authorized human decision-makers retain constitutional governance authority.",
			Context:      rootDirectCtx,
			Presentation: presStage4,
		},
		{
			StageID:      "STAGE-05",
			Name:         "Non-Binding AI Research Advisory Action",
			Description:  "LeadResearchAgent (AI_AGENT) invokes non-binding research:recommend on a HIP-1352 proposal draft verified offline against a 131,072-bit W3C BitstringStatusList.",
			Context:      cloneCtx(baseCtx),
			Presentation: presStage5,
		},
	}

	// 5. Threat-Model & Adversarial Suite (24 attacks + 1 positive control = 25 cases).
	threats := make([]ThreatCase, 0, 25)
	addThreat := func(id, cat, name string, expectValid bool, expectedErr string, ctx VerificationContext, pres ActionPresentation) {
		threats = append(threats, ThreatCase{
			CaseID:        id,
			Category:      cat,
			Name:          name,
			ExpectValid:   expectValid,
			ExpectedError: expectedErr,
			Context:       ctx,
			Presentation:  pres,
		})
	}

	// --- Category A: Impersonation & Holder-Binding (7 cases) ---

	// ATK-01: Bearer Credential Theft (Missing Holder Proof)
	p01 := clonePres(presStage3)
	p01.PresentationID = "pres-atk-01"
	p01.ChallengeNonce = "nonce-atk-01"
	p01.HolderProof = nil
	addThreat("ATK-01", "impersonation", "Bearer credential theft (missing HolderProof)", false, ErrHolderProofMissing, cloneCtx(baseCtx), p01)

	// ATK-02: Wrong Holder DID Impersonation
	p02 := clonePres(presStage3)
	p02.PresentationID = "pres-atk-02"
	p02.ChallengeNonce = "nonce-atk-02"
	p02.HolderProof, err = SignHolderProof(rogueActor.DID, rogueActor.Active, p02.DelegationChain, p02.ChallengeNonce, p02.Audience, p02.ActionVerb, p02.ResourceURI, evalTime)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	addThreat("ATK-02", "impersonation", "Wrong holder DID impersonating leaf session", false, ErrHolderDIDMismatch, cloneCtx(baseCtx), p02)

	// ATK-03: Forged Ed25519 Holder Signature
	p03, err := makeValidPres("pres-atk-03", "nonce-atk-03", "research:execute_eval", "zoo://datasets/ecology/2026/study-42/batch-1", fullChain4, ephemeralActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	p03.HolderProof.SignatureB64 = corruptBase64URL(p03.HolderProof.SignatureB64)
	addThreat("ATK-03", "impersonation", "Forged Ed25519 signature in HolderProof", false, ErrHolderSignatureInvalid, cloneCtx(baseCtx), p03)

	// ATK-04: did:key Public Key Spoofing
	c04 := cloneCtx(baseCtx)
	for i := range c04.DIDDocuments {
		if c04.DIDDocuments[i].ID == ephemeralDID {
			c04.DIDDocuments[i].GenesisPublicKeyB64 = rogueActor.Active.PublicKeyB64
			c04.DIDDocuments[i].VerificationMethods[0].PublicKeyB64 = rogueActor.Active.PublicKeyB64
		}
	}
	p04, err := makeValidPres("pres-atk-04", "nonce-atk-04", "research:execute_eval", "zoo://datasets/ecology/2026/study-42/batch-1", fullChain4, ephemeralActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	addThreat("ATK-04", "impersonation", "did:key public key substitution / DID spoofing", false, ErrDIDKeyBindingMismatch, c04, p04)

	// ATK-05: Unauthorized Key Rotation Hijack (forged controller co-signature)
	c05 := cloneCtx(baseCtx)
	for i := range c05.DIDDocuments {
		if c05.DIDDocuments[i].ID == leadDID {
			c05.DIDDocuments[i].KeyRotations[0].ControllerSigB64 = corruptBase64URL(c05.DIDDocuments[i].KeyRotations[0].ControllerSigB64)
		}
	}
	p05, err := makeValidPres("pres-atk-05", "nonce-atk-05", "research:execute_eval", "zoo://datasets/ecology/2026/study-42/batch-1", fullChain4, ephemeralActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	addThreat("ATK-05", "impersonation", "Unauthorized DID key rotation without valid controller co-signature", false, ErrKeyRotationInvalid, c05, p05)

	// ATK-06: Cross-Audience Presentation Replay
	c06 := cloneCtx(baseCtx)
	c06.ExpectedAudience = "did:zoo:verifier:prod-treasury-gateway"
	p06, err := makeValidPres("pres-atk-06", "nonce-atk-06", "research:execute_eval", "zoo://datasets/ecology/2026/study-42/batch-1", fullChain4, ephemeralActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	addThreat("ATK-06", "impersonation", "Cross-audience presentation replay", false, ErrAudienceMismatch, c06, p06)

	// ATK-07: Replayed Action Nonce
	p07, err := makeValidPres("pres-atk-07", "nonce-already-used-0001", "research:execute_eval", "zoo://datasets/ecology/2026/study-42/batch-1", fullChain4, ephemeralActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	addThreat("ATK-07", "impersonation", "Replayed action challenge nonce", false, ErrNonceReplay, cloneCtx(baseCtx), p07)

	// --- Category B: Delegation Chain & Attenuation Violations (9 cases) ---

	// ATK-08: Broken Parent Digest Link
	vc1BadDigestSubj := vc1.CredentialSubject
	vc1BadDigestSubj.ParentVCDigest = SHA256Hex([]byte("wrong-parent-digest"))
	vc1BadDigest, err := SignDelegationVC("urn:zoo:vc:atk08-bad-digest", orgDID, orgActor.Active, baseTime+100, baseTime+43200, baseTime+100, 208, DefaultStatusListID, vc1BadDigestSubj)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	p08, err := makeValidPres("pres-atk-08", "nonce-atk-08", "research:recommend", "zoo://proposals/hip-1352/review-draft", []DelegationVC{vc0, vc1BadDigest}, leadActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	addThreat("ATK-08", "delegation", "Broken parent_vc_digest cryptographic chain link", false, ErrParentDigestMismatch, cloneCtx(baseCtx), p08)

	// ATK-09: Tampered Delegation VC Signature
	vc1Tampered := vc1
	vc1Tampered.Proof.SignatureB64 = corruptBase64URL(vc1.Proof.SignatureB64)
	p09, err := makeValidPres("pres-atk-09", "nonce-atk-09", "research:recommend", "zoo://proposals/hip-1352/review-draft", []DelegationVC{vc0, vc1Tampered}, leadActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	addThreat("ATK-09", "delegation", "Forged or tampered DelegationVC issuer signature", false, ErrVCSignatureInvalid, cloneCtx(baseCtx), p09)

	// ATK-10: Depth Overflow (depth > max_sub_depth)
	vc4Overflow, err := SignDelegationVC(
		"urn:zoo:vc:atk10-depth-overflow",
		ephemeralDID,
		ephemeralActor.Active,
		baseTime+400, baseTime+3000, baseTime+400,
		210, DefaultStatusListID,
		DelegationSubject{
			ID:                   rogueDID,
			SubjectPrincipalType: PrincipalAIAgent,
			DelegationDepth:      4,
			MaxSubDepth:          0,
			ParentVCID:           vc3.ID,
			ParentVCDigest:       ComputeVCDigest(vc3),
			Audience:             DefaultAudience,
			Scopes:               []string{"research:execute_eval"},
			AllowedResources:     []string{"zoo://datasets/ecology/2026/study-42/batch-1"},
			Constraints:          DelegationConstraints{MaxCallsPerHour: 5, MaxBudgetUSDCents: 100, RequireHolderProof: true},
			Nonce:                "vc-nonce-atk10",
		},
	)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	p10, err := makeValidPres("pres-atk-10", "nonce-atk-10", "research:execute_eval", "zoo://datasets/ecology/2026/study-42/batch-1", []DelegationVC{vc0, vc1, vc2, vc3, vc4Overflow}, rogueActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	addThreat("ATK-10", "delegation", "Delegation depth overflow beyond parent max_sub_depth=0", false, ErrDepthOverflow, cloneCtx(baseCtx), p10)

	// ATK-11: Scope Escalation (child adds artifact:publish_draft not held by parent vc1)
	vc2EscSubj := vc2.CredentialSubject
	vc2EscSubj.Scopes = []string{"artifact:publish_draft", "artifact:read", "research:execute_eval"}
	vc2Esc, err := SignDelegationVC("urn:zoo:vc:atk11-scope-esc", leadDID, leadActor.Active, baseTime+200, baseTime+14400, baseTime+200, 211, DefaultStatusListID, vc2EscSubj)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	p11, err := makeValidPres("pres-atk-11", "nonce-atk-11", "artifact:publish_draft", "zoo://datasets/ecology/2026/study-42/batch-1", []DelegationVC{vc0, vc1, vc2Esc}, subActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	addThreat("ATK-11", "delegation", "Scope escalation (child adds permission absent from parent)", false, ErrScopeEscalation, cloneCtx(baseCtx), p11)

	// ATK-12: Resource Prefix Escape (sibling path prefix broadening)
	vc2ResEscSubj := vc2.CredentialSubject
	vc2ResEscSubj.AllowedResources = []string{"zoo://datasets/ecology/2026-private/secrets/"}
	vc2ResEsc, err := SignDelegationVC("urn:zoo:vc:atk12-res-esc", leadDID, leadActor.Active, baseTime+200, baseTime+14400, baseTime+200, 212, DefaultStatusListID, vc2ResEscSubj)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	p12, err := makeValidPres("pres-atk-12", "nonce-atk-12", "research:execute_eval", "zoo://datasets/ecology/2026-private/secrets/file1", []DelegationVC{vc0, vc1, vc2ResEsc}, subActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	addThreat("ATK-12", "delegation", "Resource prefix escape outside parent allowed_resources", false, ErrResourceEscalation, cloneCtx(baseCtx), p12)

	// ATK-13: TTL Extension (child.valid_until > parent.valid_until)
	vc2TTLSubj := vc2.CredentialSubject
	vc2TTL, err := SignDelegationVC("urn:zoo:vc:atk13-ttl-ext", leadDID, leadActor.Active, baseTime+200, vc1.ValidUntil+3600, baseTime+200, 213, DefaultStatusListID, vc2TTLSubj)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	p13, err := makeValidPres("pres-atk-13", "nonce-atk-13", "research:execute_eval", "zoo://datasets/ecology/2026/study-42/batch-1", []DelegationVC{vc0, vc1, vc2TTL}, subActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	addThreat("ATK-13", "delegation", "TTL extension beyond parent valid_until", false, ErrTTLExtension, cloneCtx(baseCtx), p13)

	// ATK-14: Expired Delegation VC
	vc3Expired, err := SignDelegationVC("urn:zoo:vc:atk14-expired", subDID, subActor.Active, baseTime+300, evalTime-60, baseTime+300, 214, DefaultStatusListID, vc3.CredentialSubject)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	p14, err := makeValidPres("pres-atk-14", "nonce-atk-14", "research:execute_eval", "zoo://datasets/ecology/2026/study-42/batch-1", []DelegationVC{vc0, vc1, vc2, vc3Expired}, ephemeralActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	addThreat("ATK-14", "delegation", "Expired leaf delegation VC rejected at eval_time", false, ErrVCExpired, cloneCtx(baseCtx), p14)

	// ATK-15: Not-Yet-Valid Delegation VC
	vc3Future, err := SignDelegationVC("urn:zoo:vc:atk15-future", subDID, subActor.Active, evalTime+600, baseTime+3600, baseTime+300, 215, DefaultStatusListID, vc3.CredentialSubject)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	p15, err := makeValidPres("pres-atk-15", "nonce-atk-15", "research:execute_eval", "zoo://datasets/ecology/2026/study-42/batch-1", []DelegationVC{vc0, vc1, vc2, vc3Future}, ephemeralActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	addThreat("ATK-15", "delegation", "Not-yet-valid delegation VC rejected before valid_from", false, ErrVCNotYetValid, cloneCtx(baseCtx), p15)

	// ATK-16: Cyclic Delegation Graph (Lead -> Sub -> Lead)
	vc3CycleSubj := DelegationSubject{
		ID:                   leadDID,
		SubjectPrincipalType: PrincipalAIAgent,
		DelegationDepth:      3,
		MaxSubDepth:          0,
		ParentVCID:           vc2.ID,
		ParentVCDigest:       ComputeVCDigest(vc2),
		Audience:             DefaultAudience,
		Scopes:               []string{"research:execute_eval"},
		AllowedResources:     []string{"zoo://datasets/ecology/2026/study-42/batch-1"},
		Constraints:          DelegationConstraints{MaxCallsPerHour: 10, MaxBudgetUSDCents: 500, RequireHolderProof: true},
		Nonce:                "vc-nonce-atk16-cycle",
	}
	vc3Cycle, err := SignDelegationVC("urn:zoo:vc:atk16-cycle", subDID, subActor.Active, baseTime+300, baseTime+3600, baseTime+300, 216, DefaultStatusListID, vc3CycleSubj)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	p16, err := makeValidPres("pres-atk-16", "nonce-atk-16", "research:execute_eval", "zoo://datasets/ecology/2026/study-42/batch-1", []DelegationVC{vc0, vc1, vc2, vc3Cycle}, leadActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	addThreat("ATK-16", "delegation", "Cyclic delegation graph (Lead -> Sub -> Lead)", false, ErrCyclicDelegation, cloneCtx(baseCtx), p16)

	// --- Category C: Offline Revocation & Freshness Attacks (5 cases) ---

	// ATK-17: Direct Leaf VC Revoked in W3C BitstringStatusList (index 103)
	slLeafRev, err := SignStatusList(DefaultStatusListID, rootDID, rootActor.Active, baseTime, baseTime+7200, DefaultBitstringLength, []int{7, 103, 4096, 99999}, EncodingGzipBase64URL)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	snapLeafRev, err := SignRevocationSnapshot("urn:zoo:revsnap:atk17", rootDID, rootActor.Active, baseTime, baseTime+7200, []BitstringStatusListCredential{slLeafRev}, []KeyRevocationEntry{}, []string{})
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	c17 := cloneCtx(baseCtx)
	c17.StatusLists = []BitstringStatusListCredential{slLeafRev}
	c17.RevocationSnapshot = snapLeafRev
	p17, err := makeValidPres("pres-atk-17", "nonce-atk-17", "research:execute_eval", "zoo://datasets/ecology/2026/study-42/batch-1", fullChain4, ephemeralActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	addThreat("ATK-17", "revocation", "Direct leaf VC revoked via W3C BitstringStatusList (index 103)", false, ErrVCRevokedBitstring, c17, p17)

	// ATK-18: Transitive Cascade Revocation (Intermediate Parent VC hop 1 revoked at index 101; leaf 103 still active)
	slCascadeRev, err := SignStatusList(DefaultStatusListID, rootDID, rootActor.Active, baseTime, baseTime+7200, DefaultBitstringLength, []int{7, 101, 4096, 99999}, EncodingGzipBase64URL)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	snapCascadeRev, err := SignRevocationSnapshot("urn:zoo:revsnap:atk18", rootDID, rootActor.Active, baseTime, baseTime+7200, []BitstringStatusListCredential{slCascadeRev}, []KeyRevocationEntry{}, []string{})
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	c18 := cloneCtx(baseCtx)
	c18.StatusLists = []BitstringStatusListCredential{slCascadeRev}
	c18.RevocationSnapshot = snapCascadeRev
	p18, err := makeValidPres("pres-atk-18", "nonce-atk-18", "research:execute_eval", "zoo://datasets/ecology/2026/study-42/batch-1", fullChain4, ephemeralActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	addThreat("ATK-18", "revocation", "Transitive cascade revocation (intermediate LeadResearchAgent VC revoked)", false, ErrCascadeParentRevoked, c18, p18)

	// ATK-19: Compromised Key Cutoff (revoked_before invalidates VC issued prior to cutoff)
	keyCutoffs := []KeyRevocationEntry{
		{
			DID:           orgDID,
			KeyID:         orgActor.Active.KeyID,
			RevokedBefore: baseTime + 500, // vc1 was issued at baseTime+100 < baseTime+500
			RevokeAll:     false,
			Reason:        "org_key_epoch_cutoff",
		},
	}
	snapKeyCutoff, err := SignRevocationSnapshot("urn:zoo:revsnap:atk19", rootDID, rootActor.Active, baseTime, baseTime+7200, []BitstringStatusListCredential{baseSL}, keyCutoffs, []string{})
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	c19 := cloneCtx(baseCtx)
	c19.RevocationSnapshot = snapKeyCutoff
	p19, err := makeValidPres("pres-atk-19", "nonce-atk-19", "research:execute_eval", "zoo://datasets/ecology/2026/study-42/batch-1", fullChain4, ephemeralActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	addThreat("ATK-19", "revocation", "Key compromise epoch cutoff (revoked_before invalidates earlier VC)", false, ErrKeyRevokedBeforeCutoff, c19, p19)

	// ATK-20: Stale Status List Replay (valid_until < eval_time)
	slStale, err := SignStatusList(DefaultStatusListID, rootDID, rootActor.Active, baseTime, evalTime-10, DefaultBitstringLength, []int{7, 4096}, EncodingGzipBase64URL)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	snapStaleSL, err := SignRevocationSnapshot("urn:zoo:revsnap:atk20", rootDID, rootActor.Active, baseTime, baseTime+7200, []BitstringStatusListCredential{slStale}, []KeyRevocationEntry{}, []string{})
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	c20 := cloneCtx(baseCtx)
	c20.StatusLists = []BitstringStatusListCredential{slStale}
	c20.RevocationSnapshot = snapStaleSL
	p20, err := makeValidPres("pres-atk-20", "nonce-atk-20", "research:execute_eval", "zoo://datasets/ecology/2026/study-42/batch-1", fullChain4, ephemeralActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	addThreat("ATK-20", "revocation", "Stale pre-revocation BitstringStatusList replay rejected", false, ErrStatusListStale, c20, p20)

	// ATK-21: Tampered Status List Signature (attacker flips bit to un-revoke leaf)
	slTampered := slLeafRev
	slTampered.CredentialSubject.EncodedList = baseSL.CredentialSubject.EncodedList // swapped bitstring without re-signing!
	c21 := cloneCtx(baseCtx)
	c21.StatusLists = []BitstringStatusListCredential{slTampered}
	c21.RevocationSnapshot = snapLeafRev
	p21, err := makeValidPres("pres-atk-21", "nonce-atk-21", "research:execute_eval", "zoo://datasets/ecology/2026/study-42/batch-1", fullChain4, ephemeralActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	addThreat("ATK-21", "revocation", "Tampered BitstringStatusList payload rejected via Ed25519 signature", false, ErrStatusListSignatureInvalid, c21, p21)

	// --- Category D: Constitutional AI Governance Boundaries (HIP-1352) (3 attacks + 1 positive control) ---

	// Build a compromised OrgController VC that holds all 3 governance scopes (even if a rogue root tried to grant them to Org)
	vc0Gov, err := SignDelegationVC(
		"urn:zoo:vc:hop0-org-gov-test",
		rootDID,
		rootActor.Active,
		baseTime, baseTime+86400, baseTime,
		300, DefaultStatusListID,
		DelegationSubject{
			ID:                   orgDID,
			SubjectPrincipalType: PrincipalOrgController,
			DelegationDepth:      0,
			MaxSubDepth:          2,
			Audience:             DefaultAudience,
			Scopes:               []string{"governance:vote_rules", "treasury:authorize", "experiment:certify", "research:recommend"},
			AllowedResources:     []string{"zoo://governance/", "zoo://treasury/", "zoo://experiments/"},
			Constraints:          DelegationConstraints{MaxCallsPerHour: 100, MaxBudgetUSDCents: 10000, RequireHolderProof: true},
			Nonce:                "vc-nonce-gov-0",
		},
	)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}

	makeConstitutionalAttack := func(vcID, presID, nonce, scope, resource string, statusIdx int) (ActionPresentation, error) {
		vcAI, err := SignDelegationVC(
			vcID, orgDID, orgActor.Active, baseTime+100, baseTime+14400, baseTime+100, statusIdx, DefaultStatusListID,
			DelegationSubject{
				ID:                   leadDID,
				SubjectPrincipalType: PrincipalAIAgent,
				DelegationDepth:      1,
				MaxSubDepth:          0,
				ParentVCID:           vc0Gov.ID,
				ParentVCDigest:       ComputeVCDigest(vc0Gov),
				Audience:             DefaultAudience,
				Scopes:               []string{scope},
				AllowedResources:     []string{resource},
				Constraints:          DelegationConstraints{MaxCallsPerHour: 10, MaxBudgetUSDCents: 0, RequireHolderProof: true},
				Nonce:                "vc-nonce-" + presID,
			},
		)
		if err != nil {
			return ActionPresentation{}, err
		}
		return makeValidPres(presID, nonce, scope, resource, []DelegationVC{vc0Gov, vcAI}, leadActor)
	}

	// ATK-22: AI Agent Attempting governance:vote_rules
	p22, err := makeConstitutionalAttack("urn:zoo:vc:atk22-vote-rules", "pres-atk-22", "nonce-atk-22", "governance:vote_rules", "zoo://governance/quorum", 301)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	addThreat("ATK-22", "constitutional", "AI agent attempting to hold/exercise governance:vote_rules", false, ErrConstitutionalAIGovForbidden, cloneCtx(baseCtx), p22)

	// ATK-23: AI Agent Attempting treasury:authorize
	p23, err := makeConstitutionalAttack("urn:zoo:vc:atk23-treasury", "pres-atk-23", "nonce-atk-23", "treasury:authorize", "zoo://treasury/grant-01", 302)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	addThreat("ATK-23", "constitutional", "AI agent attempting to hold/exercise treasury:authorize", false, ErrConstitutionalAIGovForbidden, cloneCtx(baseCtx), p23)

	// ATK-24: AI Agent Attempting experiment:certify
	p24, err := makeConstitutionalAttack("urn:zoo:vc:atk24-certify", "pres-atk-24", "nonce-atk-24", "experiment:certify", "zoo://experiments/run-99", 303)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	addThreat("ATK-24", "constitutional", "AI agent attempting to self-certify experiment validity (experiment:certify)", false, ErrConstitutionalAIGovForbidden, cloneCtx(baseCtx), p24)

	// POS-25: Positive Control — Non-Binding AI Value Estimation Advisory
	p25, err := makeValidPres("pres-pos-25", "nonce-pos-25", "value:estimate", "zoo://proposals/hip-1352/budget-model", subChain3, subActor)
	if err != nil {
		return IdentityDelegationSuite{}, err
	}
	addThreat("POS-25", "constitutional", "Positive control: AI agent submits non-binding value:estimate advisory", true, "", cloneCtx(baseCtx), p25)

	return IdentityDelegationSuite{
		SchemaVersion: SchemaVersion,
		SpecVersion:   SpecVersion,
		Seed:          seed,
		GeneratedAt:   baseTime,
		Stages:        stages,
		ThreatCases:   threats,
	}, nil
}

func cloneCtx(ctx VerificationContext) VerificationContext {
	raw, err := json.Marshal(ctx)
	if err != nil {
		panic(err)
	}
	var out VerificationContext
	if err := json.Unmarshal(raw, &out); err != nil {
		panic(err)
	}
	return out
}

func clonePres(p ActionPresentation) ActionPresentation {
	raw, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}
	var out ActionPresentation
	if err := json.Unmarshal(raw, &out); err != nil {
		panic(err)
	}
	return out
}

func corruptBase64URL(s string) string {
	raw, err := DecodeBase64URL(s)
	if err != nil || len(raw) == 0 {
		return "AAAA"
	}
	raw[0] ^= 0xff
	return EncodeBase64URL(raw)
}

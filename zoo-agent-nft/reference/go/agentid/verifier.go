// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package agentid

import (
	"crypto/subtle"
	"fmt"
	"sort"
	"strings"
)

// VerifiedDID holds an offline-verified portable DID document and its authorized keys.
type VerifiedDID struct {
	Doc             DIDDocument
	AuthorizedKeys  map[string]VerificationMethod
	ActiveKey       VerificationMethod
	VerifiedRotCnt  int
	SignatureChecks int
}

// VerifiedEpoch caches offline-verified DID documents, status lists, and revocation snapshot
// for a single sync epoch (used for warm-snapshot benchmarking while preserving full offline semantics).
type VerifiedEpoch struct {
	DIDs              map[string]VerifiedDID
	StatusListBytes   map[string][]byte
	StatusListBitLens map[string]int
	RevokedVCSet      map[string]bool
	KeyRevocations    []KeyRevocationEntry
	TrustedRoots      map[string]bool
	VerifiedDIDCount  int
	VerifiedRotations int
	EpochSigChecks    int
}

// PrepareEpoch verifies all portable DID documents, key rotations, the signed RevocationSnapshot,
// and all W3C BitstringStatusListCredentials offline against evalTime.
func PrepareEpoch(ctx VerificationContext, evalTime int64) (*VerifiedEpoch, string, string) {
	trustedRoots := make(map[string]bool, len(ctx.TrustedRootDIDs))
	for _, r := range ctx.TrustedRootDIDs {
		trustedRoots[r] = true
	}

	// Phase 1: Verify portable DID documents (2-pass: unrotated roots/controllers first, then rotated DIDs).
	rawDocs := make(map[string]DIDDocument, len(ctx.DIDDocuments))
	for _, doc := range ctx.DIDDocuments {
		rawDocs[doc.ID] = doc
	}

	verifiedDIDs := make(map[string]VerifiedDID, len(ctx.DIDDocuments))
	totalRotations := 0
	totalSigChecks := 0

	// Pass 1: validate structure, did:key binding, and verify DIDs with 0 key rotations.
	for _, doc := range ctx.DIDDocuments {
		if errCode, errMsg := validateDIDStructure(doc); errCode != "" {
			return nil, errCode, errMsg
		}
		if len(doc.KeyRotations) == 0 {
			vd, errCode, errMsg := verifyUnrotatedDID(doc)
			if errCode != "" {
				return nil, errCode, errMsg
			}
			verifiedDIDs[doc.ID] = vd
			totalSigChecks += vd.SignatureChecks
		}
	}

	// Pass 2: verify DIDs with key rotations (controllers verified in pass 1 or iteratively).
	pending := make([]DIDDocument, 0)
	for _, doc := range ctx.DIDDocuments {
		if len(doc.KeyRotations) > 0 {
			pending = append(pending, doc)
		}
	}
	for pass := 0; len(pending) > 0 && pass <= len(ctx.DIDDocuments); pass++ {
		nextPending := make([]DIDDocument, 0)
		progressed := false
		for _, doc := range pending {
			controllerVD, ok := verifiedDIDs[doc.Controller]
			if !ok {
				if doc.Controller == doc.ID {
					// Self-controlled root rotation: verify using its own genesis key chain.
					vd, errCode, errMsg := verifyRotatedDID(doc, nil)
					if errCode != "" {
						return nil, errCode, errMsg
					}
					verifiedDIDs[doc.ID] = vd
					totalRotations += vd.VerifiedRotCnt
					totalSigChecks += vd.SignatureChecks
					progressed = true
					continue
				}
				nextPending = append(nextPending, doc)
				continue
			}
			vd, errCode, errMsg := verifyRotatedDID(doc, &controllerVD)
			if errCode != "" {
				return nil, errCode, errMsg
			}
			verifiedDIDs[doc.ID] = vd
			totalRotations += vd.VerifiedRotCnt
			totalSigChecks += vd.SignatureChecks
			progressed = true
		}
		pending = nextPending
		if !progressed && len(pending) > 0 {
			return nil, ErrKeyRotationInvalid, fmt.Sprintf("unresolved controller %s for rotated DID %s", pending[0].Controller, pending[0].ID)
		}
	}

	// Phase 2: Verify signed RevocationSnapshot.
	snap := ctx.RevocationSnapshot
	if !trustedRoots[snap.Issuer] {
		return nil, ErrUntrustedRoot, fmt.Sprintf("revocation snapshot issuer %s is not a trusted root", snap.Issuer)
	}
	snapIssuer, ok := verifiedDIDs[snap.Issuer]
	if !ok {
		return nil, ErrDIDNotFound, fmt.Sprintf("revocation snapshot issuer DID %s not found", snap.Issuer)
	}
	snapKey, ok := snapIssuer.AuthorizedKeys[snap.IssuerKeyID]
	if !ok || snap.Proof.VerificationMethod != snap.IssuerKeyID {
		return nil, ErrKeyNotFound, fmt.Sprintf("revocation snapshot key %s not authorized", snap.IssuerKeyID)
	}
	totalSigChecks++
	if !VerifyDomain(snapKey.PublicKeyB64, DomainRevSnapshot, unsignedRevocationSnapshot(snap), snap.Proof.SignatureB64) {
		return nil, ErrRevocationSnapshotSignature, "revocation snapshot signature verification failed"
	}
	if evalTime < snap.IssuedAt || evalTime > snap.ValidUntil {
		return nil, ErrRevocationSnapshotStale, fmt.Sprintf("revocation snapshot valid [%d, %d] outside eval_time %d", snap.IssuedAt, snap.ValidUntil, evalTime)
	}
	expectedCRLRoot := ComputeCRLMerkleRoot(snap.RevokedVCIDs, snap.KeyRevocations)
	if snap.CRLMerkleRoot != expectedCRLRoot {
		return nil, ErrRevocationSnapshotMerkleMismatch, fmt.Sprintf("crl_merkle_root mismatch: got %s want %s", snap.CRLMerkleRoot, expectedCRLRoot)
	}

	// Build digest pin map from snapshot.
	pinnedDigests := make(map[string]string, len(snap.StatusListDigests))
	for _, pin := range snap.StatusListDigests {
		pinnedDigests[pin.StatusListID] = pin.DigestSHA256
	}

	// Verify all W3C BitstringStatusListCredentials.
	statusBytes := make(map[string][]byte, len(ctx.StatusLists))
	statusBitLens := make(map[string]int, len(ctx.StatusLists))
	for _, sl := range ctx.StatusLists {
		if !trustedRoots[sl.Issuer] {
			return nil, ErrUntrustedRoot, fmt.Sprintf("status list issuer %s is not a trusted root", sl.Issuer)
		}
		slIssuer, ok := verifiedDIDs[sl.Issuer]
		if !ok {
			return nil, ErrDIDNotFound, fmt.Sprintf("status list issuer DID %s not found", sl.Issuer)
		}
		slKey, ok := slIssuer.AuthorizedKeys[sl.IssuerKeyID]
		if !ok || sl.Proof.VerificationMethod != sl.IssuerKeyID {
			return nil, ErrKeyNotFound, fmt.Sprintf("status list key %s not authorized", sl.IssuerKeyID)
		}
		totalSigChecks++
		if !VerifyDomain(slKey.PublicKeyB64, DomainStatusList, unsignedStatusList(sl), sl.Proof.SignatureB64) {
			return nil, ErrStatusListSignatureInvalid, fmt.Sprintf("status list %s signature invalid", sl.ID)
		}
		if evalTime < sl.ValidFrom || evalTime > sl.ValidUntil {
			return nil, ErrStatusListStale, fmt.Sprintf("status list %s stale: valid [%d, %d], eval_time %d", sl.ID, sl.ValidFrom, sl.ValidUntil, evalTime)
		}
		if pinned, hasPin := pinnedDigests[sl.ID]; hasPin {
			actualDigest := ComputeStatusListDigest(sl)
			if actualDigest != pinned {
				return nil, ErrStatusListDigestMismatch, fmt.Sprintf("status list %s digest mismatch", sl.ID)
			}
		}
		rawBits, err := DecodeBitstring(sl.CredentialSubject.EncodedList, sl.CredentialSubject.Encoding, sl.CredentialSubject.BitLength)
		if err != nil {
			return nil, ErrStatusListSignatureInvalid, fmt.Sprintf("failed to decode bitstring %s: %v", sl.ID, err)
		}
		statusBytes[sl.ID] = rawBits
		statusBitLens[sl.ID] = sl.CredentialSubject.BitLength
	}

	revokedVCSet := make(map[string]bool, len(snap.RevokedVCIDs))
	for _, id := range snap.RevokedVCIDs {
		revokedVCSet[id] = true
	}

	return &VerifiedEpoch{
		DIDs:              verifiedDIDs,
		StatusListBytes:   statusBytes,
		StatusListBitLens: statusBitLens,
		RevokedVCSet:      revokedVCSet,
		KeyRevocations:    snap.KeyRevocations,
		TrustedRoots:      trustedRoots,
		VerifiedDIDCount:  len(verifiedDIDs),
		VerifiedRotations: totalRotations,
		EpochSigChecks:    totalSigChecks,
	}, "", ""
}

func validateDIDStructure(doc DIDDocument) (string, string) {
	if !strings.HasPrefix(doc.ID, "did:zoo:") && !strings.HasPrefix(doc.ID, "did:key:z") {
		return ErrDIDInvalidFormat, fmt.Sprintf("unsupported DID format: %s", doc.ID)
	}
	if !doc.PortableExport || doc.GenesisKeyID == "" || doc.GenesisPublicKeyB64 == "" || doc.ActiveKeyID == "" {
		return ErrDIDInvalidFormat, fmt.Sprintf("DID %s missing required portable export fields", doc.ID)
	}
	genPub, err := DecodeBase64URL(doc.GenesisPublicKeyB64)
	if err != nil || len(genPub) != 32 {
		return ErrDIDInvalidFormat, fmt.Sprintf("DID %s has invalid genesis_public_key_b64", doc.ID)
	}
	if strings.HasPrefix(doc.ID, "did:key:z") {
		derivedPub, err := PublicKeyFromDIDKey(doc.ID)
		if err != nil {
			return ErrDIDInvalidFormat, fmt.Sprintf("invalid did:key %s: %v", doc.ID, err)
		}
		if subtle.ConstantTimeCompare(genPub, derivedPub) != 1 {
			return ErrDIDKeyBindingMismatch, fmt.Sprintf("did:key %s public key does not match multicodec identifier", doc.ID)
		}
	}
	return "", ""
}

func verifyUnrotatedDID(doc DIDDocument) (VerifiedDID, string, string) {
	if doc.ActiveKeyID != doc.GenesisKeyID {
		return VerifiedDID{}, ErrKeyRotationInvalid, fmt.Sprintf("DID %s active_key_id %s != genesis_key_id %s without rotation proofs", doc.ID, doc.ActiveKeyID, doc.GenesisKeyID)
	}
	if len(doc.VerificationMethods) != 1 {
		return VerifiedDID{}, ErrKeyRotationInvalid, fmt.Sprintf("unrotated DID %s must have exactly 1 verification method", doc.ID)
	}
	vm := doc.VerificationMethods[0]
	if vm.ID != doc.GenesisKeyID || vm.PublicKeyB64 != doc.GenesisPublicKeyB64 {
		return VerifiedDID{}, ErrDIDKeyBindingMismatch, fmt.Sprintf("DID %s genesis verification method mismatch", doc.ID)
	}
	if doc.Proof.VerificationMethod != doc.ActiveKeyID {
		return VerifiedDID{}, ErrDIDSignatureInvalid, fmt.Sprintf("DID %s proof verification_method must equal active_key_id", doc.ID)
	}
	if !VerifyDomain(vm.PublicKeyB64, DomainDIDDoc, unsignedDIDDoc(doc), doc.Proof.SignatureB64) {
		return VerifiedDID{}, ErrDIDSignatureInvalid, fmt.Sprintf("DID %s self-signature invalid", doc.ID)
	}
	return VerifiedDID{
		Doc:             doc,
		AuthorizedKeys:  map[string]VerificationMethod{vm.ID: vm},
		ActiveKey:       vm,
		VerifiedRotCnt:  0,
		SignatureChecks: 1,
	}, "", ""
}

func verifyRotatedDID(doc DIDDocument, controllerVD *VerifiedDID) (VerifiedDID, string, string) {
	vmByID := make(map[string]VerificationMethod, len(doc.VerificationMethods))
	for _, vm := range doc.VerificationMethods {
		vmByID[vm.ID] = vm
	}
	genVM, ok := vmByID[doc.GenesisKeyID]
	if !ok || genVM.PublicKeyB64 != doc.GenesisPublicKeyB64 {
		return VerifiedDID{}, ErrDIDKeyBindingMismatch, fmt.Sprintf("DID %s missing matching genesis verification method", doc.ID)
	}

	authorized := map[string]VerificationMethod{genVM.ID: genVM}
	curKeyID := genVM.ID
	curPubB64 := genVM.PublicKeyB64
	sigChecks := 0

	for _, rot := range doc.KeyRotations {
		if rot.DID != doc.ID || rot.FromKeyID != curKeyID {
			return VerifiedDID{}, ErrKeyRotationInvalid, fmt.Sprintf("DID %s rotation link broken at %s -> %s", doc.ID, rot.FromKeyID, rot.ToKeyID)
		}
		nextVM, ok := vmByID[rot.ToKeyID]
		if !ok || nextVM.PublicKeyB64 != rot.NewPublicKeyB64 {
			return VerifiedDID{}, ErrKeyRotationInvalid, fmt.Sprintf("DID %s rotation target key %s missing or mismatched", doc.ID, rot.ToKeyID)
		}
		// Verify outgoing key signature.
		sigChecks++
		if !VerifyDomain(curPubB64, DomainKeyRotation, unsignedKeyRotation(rot), rot.OutgoingSigB64) {
			return VerifiedDID{}, ErrKeyRotationInvalid, fmt.Sprintf("DID %s rotation %s outgoing signature invalid", doc.ID, rot.ToKeyID)
		}
		// Verify controller co-signature.
		var ctrlPubB64 string
		if controllerVD != nil {
			cvm, ok := controllerVD.AuthorizedKeys[rot.ControllerKeyID]
			if !ok {
				return VerifiedDID{}, ErrKeyRotationInvalid, fmt.Sprintf("DID %s rotation controller key %s not authorized", doc.ID, rot.ControllerKeyID)
			}
			ctrlPubB64 = cvm.PublicKeyB64
		} else {
			cvm, ok := authorized[rot.ControllerKeyID]
			if !ok {
				return VerifiedDID{}, ErrKeyRotationInvalid, fmt.Sprintf("self-controlled DID %s rotation controller key %s not authorized", doc.ID, rot.ControllerKeyID)
			}
			ctrlPubB64 = cvm.PublicKeyB64
		}
		sigChecks++
		if !VerifyDomain(ctrlPubB64, DomainKeyRotation, unsignedKeyRotation(rot), rot.ControllerSigB64) {
			return VerifiedDID{}, ErrKeyRotationInvalid, fmt.Sprintf("DID %s rotation %s controller co-signature invalid", doc.ID, rot.ToKeyID)
		}

		authorized[nextVM.ID] = nextVM
		curKeyID = nextVM.ID
		curPubB64 = nextVM.PublicKeyB64
	}

	if curKeyID != doc.ActiveKeyID {
		return VerifiedDID{}, ErrKeyRotationInvalid, fmt.Sprintf("DID %s active_key_id %s != final rotated key %s", doc.ID, doc.ActiveKeyID, curKeyID)
	}
	if len(authorized) != len(doc.VerificationMethods) {
		return VerifiedDID{}, ErrKeyRotationInvalid, fmt.Sprintf("DID %s contains unauthorized verification methods outside rotation chain", doc.ID)
	}
	if doc.Proof.VerificationMethod != doc.ActiveKeyID {
		return VerifiedDID{}, ErrDIDSignatureInvalid, fmt.Sprintf("DID %s proof verification_method != active_key_id", doc.ID)
	}
	sigChecks++
	if !VerifyDomain(curPubB64, DomainDIDDoc, unsignedDIDDoc(doc), doc.Proof.SignatureB64) {
		return VerifiedDID{}, ErrDIDSignatureInvalid, fmt.Sprintf("DID %s active-key self-signature invalid", doc.ID)
	}

	return VerifiedDID{
		Doc:             doc,
		AuthorizedKeys:  authorized,
		ActiveKey:       authorized[curKeyID],
		VerifiedRotCnt:  len(doc.KeyRotations),
		SignatureChecks: sigChecks,
	}, "", ""
}

// VerifyPresentation performs 100% offline verification of an ActionPresentation (cold-snapshot mode).
func VerifyPresentation(ctx VerificationContext, pres ActionPresentation) PresentationResult {
	epoch, errCode, errMsg := PrepareEpoch(ctx, pres.EvalTime)
	if errCode != "" {
		return PresentationResult{
			Valid:           false,
			ErrorCode:       errCode,
			ErrorDetail:     errMsg,
			EffectiveScopes: []string{},
		}
	}
	res := VerifyPresentationWithEpoch(epoch, ctx, pres)
	res.SignatureChecks += epoch.EpochSigChecks
	return res
}

// VerifyPresentationWithEpoch verifies a delegation chain and holder-bound action presentation
// against a pre-verified offline epoch (warm-snapshot mode).
func VerifyPresentationWithEpoch(epoch *VerifiedEpoch, ctx VerificationContext, pres ActionPresentation) PresentationResult {
	fail := func(code, detail string, sigs int) PresentationResult {
		return PresentationResult{
			Valid:             false,
			ErrorCode:         code,
			ErrorDetail:       detail,
			ChainDepth:        len(pres.DelegationChain),
			EffectiveScopes:   []string{},
			VerifiedDIDCount:  epoch.VerifiedDIDCount,
			VerifiedRotations: epoch.VerifiedRotations,
			SignatureChecks:   sigs,
		}
	}

	sigChecks := 0
	chain := pres.DelegationChain
	chainDigest := ComputeDelegationChainDigest(chain)

	var expectedHolderDID string
	var leafPrincipalType string
	var rootDID string
	var effectiveScopes []string
	var effectiveResources []string

	if len(chain) == 0 {
		if !ctx.AllowRootDirectActions {
			return fail(ErrChainEmpty, "delegation chain is empty", sigChecks)
		}
		if pres.HolderProof == nil {
			return fail(ErrHolderProofMissing, "holder proof required for direct root action", sigChecks)
		}
		if !epoch.TrustedRoots[pres.HolderProof.HolderDID] {
			return fail(ErrUntrustedRoot, "direct root action holder is not a trusted root", sigChecks)
		}
		rootVD, ok := epoch.DIDs[pres.HolderProof.HolderDID]
		if !ok || rootVD.Doc.PrincipalType != PrincipalHumanCouncil {
			return fail(ErrUntrustedRoot, "direct root action requires HUMAN_COUNCIL principal", sigChecks)
		}
		expectedHolderDID = rootVD.Doc.ID
		leafPrincipalType = rootVD.Doc.PrincipalType
		rootDID = rootVD.Doc.ID
		effectiveScopes = []string{pres.ActionVerb}
	} else {
		seenDIDs := make(map[string]bool, len(chain)+1)
		var prevVC DelegationVC
		var prevDigest string

		for i, vc := range chain {
			subj := vc.CredentialSubject

			// 1. Root trust, parent linkage, and acyclicity.
			if i == 0 {
				if !epoch.TrustedRoots[vc.Issuer] {
					return fail(ErrUntrustedRoot, fmt.Sprintf("root issuer %s is not trusted", vc.Issuer), sigChecks)
				}
				if subj.DelegationDepth != 0 {
					return fail(ErrDepthOverflow, fmt.Sprintf("root VC must have delegation_depth 0, got %d", subj.DelegationDepth), sigChecks)
				}
				if subj.ParentVCID != "" || subj.ParentVCDigest != "" {
					return fail(ErrChainLinkBroken, "root VC must have empty parent_vc_id and parent_vc_digest", sigChecks)
				}
				rootDID = vc.Issuer
				seenDIDs[vc.Issuer] = true
			} else {
				if vc.Issuer != prevVC.CredentialSubject.ID {
					return fail(ErrChainLinkBroken, fmt.Sprintf("hop %d issuer %s != parent subject %s", i, vc.Issuer, prevVC.CredentialSubject.ID), sigChecks)
				}
				if subj.ParentVCID != prevVC.ID {
					return fail(ErrChainLinkBroken, fmt.Sprintf("hop %d parent_vc_id %s != %s", i, subj.ParentVCID, prevVC.ID), sigChecks)
				}
				if subj.ParentVCDigest != prevDigest {
					return fail(ErrParentDigestMismatch, fmt.Sprintf("hop %d parent_vc_digest mismatch", i), sigChecks)
				}
			}
			if seenDIDs[subj.ID] {
				return fail(ErrCyclicDelegation, fmt.Sprintf("cyclic delegation detected for DID %s", subj.ID), sigChecks)
			}
			seenDIDs[subj.ID] = true

			// 2. Issuer DID + key lookup + Ed25519 signature verification.
			issuerVD, ok := epoch.DIDs[vc.Issuer]
			if !ok {
				return fail(ErrDIDNotFound, fmt.Sprintf("issuer DID %s not found", vc.Issuer), sigChecks)
			}
			issuerKey, ok := issuerVD.AuthorizedKeys[vc.IssuerKeyID]
			if !ok || vc.Proof.VerificationMethod != vc.IssuerKeyID {
				return fail(ErrKeyNotFound, fmt.Sprintf("issuer key %s not authorized for %s", vc.IssuerKeyID, vc.Issuer), sigChecks)
			}
			sigChecks++
			if !VerifyDomain(issuerKey.PublicKeyB64, DomainVC, unsignedVC(vc), vc.Proof.SignatureB64) {
				return fail(ErrVCSignatureInvalid, fmt.Sprintf("VC %s Ed25519 signature invalid", vc.ID), sigChecks)
			}

			// 3. Key revocation cutoff / compromise check.
			if errCode, errMsg := checkKeyRevocation(epoch.KeyRevocations, vc.Issuer, vc.IssuerKeyID, vc.Proof.Created, vc.ValidFrom); errCode != "" {
				return fail(errCode, errMsg, sigChecks)
			}

			// 4. Subject DID & Constitutional AI Governance Boundary (HIP-1352).
			subjVD, ok := epoch.DIDs[subj.ID]
			if !ok {
				return fail(ErrDIDNotFound, fmt.Sprintf("subject DID %s not found", subj.ID), sigChecks)
			}
			if subj.SubjectPrincipalType != subjVD.Doc.PrincipalType {
				return fail(ErrDIDKeyBindingMismatch, fmt.Sprintf("subject principal_type %s != DID %s", subj.SubjectPrincipalType, subjVD.Doc.PrincipalType), sigChecks)
			}
			if isAIAgentPrincipal(subjVD.Doc.PrincipalType) {
				for _, sc := range subj.Scopes {
					if ReservedGovernanceScopes[sc] {
						return fail(ErrConstitutionalAIGovForbidden, fmt.Sprintf("AI principal %s cannot hold reserved human-governance scope %s", subj.ID, sc), sigChecks)
					}
				}
			}

			// 5. Monotonic Attenuation Rules (strict subset narrowing).
			if len(subj.Scopes) == 0 {
				return fail(ErrScopeEscalation, "delegation VC must specify at least one scope", sigChecks)
			}
			for _, sc := range subj.Scopes {
				if strings.Contains(sc, "*") {
					return fail(ErrScopeEscalation, fmt.Sprintf("wildcard scope %q forbidden", sc), sigChecks)
				}
			}
			if len(subj.AllowedResources) == 0 {
				return fail(ErrResourceEscalation, "delegation VC must specify at least one allowed_resource", sigChecks)
			}
			for _, res := range subj.AllowedResources {
				if !isSafeResourceURI(res) {
					return fail(ErrResourceEscalation, fmt.Sprintf("unsafe resource pattern %q forbidden", res), sigChecks)
				}
			}
			if i > 0 {
				pSubj := prevVC.CredentialSubject
				if pSubj.MaxSubDepth < 1 || subj.DelegationDepth != pSubj.DelegationDepth+1 || subj.MaxSubDepth < 0 || subj.MaxSubDepth > pSubj.MaxSubDepth-1 {
					return fail(ErrDepthOverflow, fmt.Sprintf("hop %d depth/max_sub_depth overflow (parent max_sub_depth=%d, child=%d)", i, pSubj.MaxSubDepth, subj.MaxSubDepth), sigChecks)
				}
				if vc.ValidFrom < prevVC.ValidFrom || vc.ValidUntil > prevVC.ValidUntil {
					return fail(ErrTTLExtension, fmt.Sprintf("hop %d TTL [%d,%d] exceeds parent [%d,%d]", i, vc.ValidFrom, vc.ValidUntil, prevVC.ValidFrom, prevVC.ValidUntil), sigChecks)
				}
				if !isScopeSubset(subj.Scopes, pSubj.Scopes) {
					return fail(ErrScopeEscalation, fmt.Sprintf("hop %d scopes escalate beyond parent", i), sigChecks)
				}
				if !areResourcesContained(subj.AllowedResources, pSubj.AllowedResources) {
					return fail(ErrResourceEscalation, fmt.Sprintf("hop %d allowed_resources escape parent bounds", i), sigChecks)
				}
				if subj.Constraints.MaxCallsPerHour <= 0 || subj.Constraints.MaxCallsPerHour > pSubj.Constraints.MaxCallsPerHour ||
					subj.Constraints.MaxBudgetUSDCents < 0 || subj.Constraints.MaxBudgetUSDCents > pSubj.Constraints.MaxBudgetUSDCents ||
					(pSubj.Constraints.RequireHolderProof && !subj.Constraints.RequireHolderProof) {
					return fail(ErrConstraintEscalation, fmt.Sprintf("hop %d constraints exceed parent bounds", i), sigChecks)
				}
				if pSubj.Audience != "" && pSubj.Audience != "any" && subj.Audience != pSubj.Audience {
					return fail(ErrAudienceMismatch, fmt.Sprintf("hop %d audience %s != parent audience %s", i, subj.Audience, pSubj.Audience), sigChecks)
				}
			}

			// 6. Temporal validity against eval_time.
			if vc.ValidFrom >= vc.ValidUntil {
				return fail(ErrVCExpired, fmt.Sprintf("VC %s has invalid validity interval", vc.ID), sigChecks)
			}
			if pres.EvalTime < vc.ValidFrom {
				return fail(ErrVCNotYetValid, fmt.Sprintf("VC %s not yet valid at %d (valid_from=%d)", vc.ID, pres.EvalTime, vc.ValidFrom), sigChecks)
			}
			if pres.EvalTime > vc.ValidUntil {
				return fail(ErrVCExpired, fmt.Sprintf("VC %s expired at %d (valid_until=%d)", vc.ID, pres.EvalTime, vc.ValidUntil), sigChecks)
			}

			// 7. Offline Revocation Check (W3C BitstringStatusList + explicit CRL + Cascade Revocation).
			rawBits, ok := epoch.StatusListBytes[vc.CredentialStatus.StatusListCredential]
			if !ok {
				return fail(ErrStatusListMissing, fmt.Sprintf("status list %s not provided offline", vc.CredentialStatus.StatusListCredential), sigChecks)
			}
			bitLen := epoch.StatusListBitLens[vc.CredentialStatus.StatusListCredential]
			revBit, err := BitstringIsRevoked(rawBits, bitLen, vc.CredentialStatus.StatusListIndex)
			if err != nil {
				return fail(ErrStatusListIndexOutOfBounds, fmt.Sprintf("VC %s status index %d out of bounds", vc.ID, vc.CredentialStatus.StatusListIndex), sigChecks)
			}
			if revBit || epoch.RevokedVCSet[vc.ID] {
				if i < len(chain)-1 {
					return fail(ErrCascadeParentRevoked, fmt.Sprintf("upstream intermediate VC %s (hop %d) revoked; downstream chain invalidated", vc.ID, i), sigChecks)
				}
				return fail(ErrVCRevokedBitstring, fmt.Sprintf("leaf VC %s revoked at statusListIndex %d", vc.ID, vc.CredentialStatus.StatusListIndex), sigChecks)
			}

			prevVC = vc
			prevDigest = ComputeVCDigest(vc)
		}

		leaf := chain[len(chain)-1]
		expectedHolderDID = leaf.CredentialSubject.ID
		leafPrincipalType = leaf.CredentialSubject.SubjectPrincipalType
		effectiveScopes = append([]string(nil), leaf.CredentialSubject.Scopes...)
		sort.Strings(effectiveScopes)
		effectiveResources = leaf.CredentialSubject.AllowedResources

		// Verify leaf audience matches presentation audience.
		if leaf.CredentialSubject.Audience != "" && leaf.CredentialSubject.Audience != "any" && leaf.CredentialSubject.Audience != pres.Audience {
			return fail(ErrAudienceMismatch, fmt.Sprintf("leaf VC audience %s != presentation audience %s", leaf.CredentialSubject.Audience, pres.Audience), sigChecks)
		}
	}

	// Phase 4: Audience, Replay Cache, Holder-Binding & Action Authorization.
	if ctx.ExpectedAudience != "" && pres.Audience != ctx.ExpectedAudience {
		return fail(ErrAudienceMismatch, fmt.Sprintf("presentation audience %s != expected %s", pres.Audience, ctx.ExpectedAudience), sigChecks)
	}
	if pres.ChallengeNonce == "" {
		return fail(ErrNonceReplay, "empty challenge_nonce", sigChecks)
	}
	for _, used := range ctx.UsedNonces {
		if used == pres.ChallengeNonce {
			return fail(ErrNonceReplay, fmt.Sprintf("challenge_nonce %s already consumed", pres.ChallengeNonce), sigChecks)
		}
	}
	if pres.HolderProof == nil {
		return fail(ErrHolderProofMissing, "holder_proof is required to prevent bearer impersonation", sigChecks)
	}
	hp := *pres.HolderProof
	if hp.HolderDID != expectedHolderDID {
		return fail(ErrHolderDIDMismatch, fmt.Sprintf("holder_did %s != leaf delegate %s", hp.HolderDID, expectedHolderDID), sigChecks)
	}
	if hp.DelegationChainDigest != chainDigest ||
		hp.ChallengeNonce != pres.ChallengeNonce ||
		hp.Audience != pres.Audience ||
		hp.ActionVerb != pres.ActionVerb ||
		hp.ResourceURI != pres.ResourceURI {
		return fail(ErrHolderBindingMismatch, "holder_proof signed fields do not match presentation envelope", sigChecks)
	}
	if hp.Timestamp < pres.EvalTime-HolderProofMaxPastSkew || hp.Timestamp > pres.EvalTime+HolderProofMaxFutureSkew {
		return fail(ErrHolderProofStale, fmt.Sprintf("holder_proof timestamp %d outside freshness window around %d", hp.Timestamp, pres.EvalTime), sigChecks)
	}

	holderVD, ok := epoch.DIDs[hp.HolderDID]
	if !ok {
		return fail(ErrDIDNotFound, fmt.Sprintf("holder DID %s not found", hp.HolderDID), sigChecks)
	}
	holderKey, ok := holderVD.AuthorizedKeys[hp.HolderKeyID]
	if !ok {
		return fail(ErrKeyNotFound, fmt.Sprintf("holder key %s not authorized for %s", hp.HolderKeyID, hp.HolderDID), sigChecks)
	}
	if errCode, errMsg := checkKeyRevocation(epoch.KeyRevocations, hp.HolderDID, hp.HolderKeyID, hp.Timestamp, hp.Timestamp); errCode != "" {
		return fail(errCode, errMsg, sigChecks)
	}
	sigChecks++
	if !VerifyDomain(holderKey.PublicKeyB64, DomainHolderProof, unsignedHolderProof(hp), hp.SignatureB64) {
		return fail(ErrHolderSignatureInvalid, "holder_proof Ed25519 signature invalid", sigChecks)
	}

	// Constitutional check on invoked action verb.
	if isAIAgentPrincipal(holderVD.Doc.PrincipalType) && ReservedGovernanceScopes[pres.ActionVerb] {
		return fail(ErrConstitutionalAIGovForbidden, fmt.Sprintf("AI principal %s cannot exercise reserved governance action %s", hp.HolderDID, pres.ActionVerb), sigChecks)
	}

	// Action authorization against leaf scopes and resource bounds.
	if len(chain) > 0 {
		if !containsString(effectiveScopes, pres.ActionVerb) {
			return fail(ErrActionScopeDenied, fmt.Sprintf("action %s not in leaf effective scopes", pres.ActionVerb), sigChecks)
		}
		if !isSafeResourceURI(pres.ResourceURI) || !isResourceContained(pres.ResourceURI, effectiveResources) {
			return fail(ErrActionResourceDenied, fmt.Sprintf("resource %s outside leaf allowed_resources", pres.ResourceURI), sigChecks)
		}
	}

	return PresentationResult{
		Valid:                 true,
		ErrorCode:             "",
		ErrorDetail:           "",
		ChainDepth:            len(chain),
		LeafDID:               expectedHolderDID,
		LeafPrincipalType:     leafPrincipalType,
		RootDID:               rootDID,
		DelegationChainDigest: chainDigest,
		EffectiveScopes:       effectiveScopes,
		VerifiedDIDCount:      epoch.VerifiedDIDCount,
		VerifiedRotations:     epoch.VerifiedRotations,
		SignatureChecks:       sigChecks,
	}
}

// VerifySuite verifies all positive lifecycle stages and threat-model cases offline,
// computing a deterministic RFC 6962 audit_merkle_root identical across Go and Python.
func VerifySuite(suite IdentityDelegationSuite) SuiteReport {
	stageReports := make([]StageReport, 0, len(suite.Stages))
	passedStages := 0
	auditLeaves := make([]string, 0, len(suite.Stages)+len(suite.ThreatCases))

	for _, st := range suite.Stages {
		res := VerifyPresentation(st.Context, st.Presentation)
		if res.Valid {
			passedStages++
		}
		sr := StageReport{
			StageID:               st.StageID,
			Name:                  st.Name,
			Valid:                 res.Valid,
			ErrorCode:             res.ErrorCode,
			ChainDepth:            res.ChainDepth,
			DelegationChainDigest: res.DelegationChainDigest,
			VerifiedRotations:     res.VerifiedRotations,
			SignatureChecks:       res.SignatureChecks,
		}
		stageReports = append(stageReports, sr)
		auditLeaves = append(auditLeaves, HashCanonical(DomainAuditLeaf, map[string]any{
			"kind":        "stage",
			"id":          sr.StageID,
			"valid":       sr.Valid,
			"error_code":  sr.ErrorCode,
			"chain_depth": sr.ChainDepth,
			"digest":      sr.DelegationChainDigest,
		}))
	}

	threatReports := make([]ThreatReport, 0, len(suite.ThreatCases))
	attacksTotal := 0
	attacksCaught := 0
	posControls := 0
	posControlsOK := 0
	allThreatPass := true

	for _, tc := range suite.ThreatCases {
		res := VerifyPresentation(tc.Context, tc.Presentation)
		pass := (res.Valid == tc.ExpectValid)
		if !tc.ExpectValid && tc.ExpectedError != "" && res.ErrorCode != tc.ExpectedError {
			pass = false
		}
		if !tc.ExpectValid {
			attacksTotal++
			if pass {
				attacksCaught++
			}
		} else {
			posControls++
			if pass {
				posControlsOK++
			}
		}
		if !pass {
			allThreatPass = false
		}
		tr := ThreatReport{
			CaseID:        tc.CaseID,
			Category:      tc.Category,
			Name:          tc.Name,
			ExpectValid:   tc.ExpectValid,
			ActualValid:   res.Valid,
			ExpectedError: tc.ExpectedError,
			ActualError:   res.ErrorCode,
			Pass:          pass,
		}
		threatReports = append(threatReports, tr)
		auditLeaves = append(auditLeaves, HashCanonical(DomainAuditLeaf, map[string]any{
			"kind":           "threat",
			"id":             tr.CaseID,
			"expect_valid":   tr.ExpectValid,
			"actual_valid":   tr.ActualValid,
			"expected_error": tr.ExpectedError,
			"actual_error":   tr.ActualError,
			"pass":           tr.Pass,
		}))
	}

	return SuiteReport{
		SchemaVersion:      suite.SchemaVersion,
		SpecVersion:        suite.SpecVersion,
		Seed:               suite.Seed,
		TotalStages:        len(suite.Stages),
		PassedStages:       passedStages,
		AllStagesValid:     passedStages == len(suite.Stages),
		TotalThreatCases:   len(suite.ThreatCases),
		AttacksTotal:       attacksTotal,
		AttacksCaught:      attacksCaught,
		PositiveControls:   posControls,
		PositiveControlsOK: posControlsOK,
		AllThreatPass:      allThreatPass,
		StageReports:       stageReports,
		ThreatReports:      threatReports,
		AuditMerkleRoot:    MerkleRootRFC6962(auditLeaves),
	}
}

func checkKeyRevocation(revs []KeyRevocationEntry, did, keyID string, signedAt, validFrom int64) (string, string) {
	for _, kr := range revs {
		if kr.DID == did && kr.KeyID == keyID {
			if kr.RevokeAll {
				return ErrKeyCompromisedRevoked, fmt.Sprintf("key %s of %s is globally revoked (%s)", keyID, did, kr.Reason)
			}
			if kr.RevokedBefore > 0 && (signedAt < kr.RevokedBefore || validFrom < kr.RevokedBefore) {
				return ErrKeyRevokedBeforeCutoff, fmt.Sprintf("key %s signature/credential predates revoked_before=%d", keyID, kr.RevokedBefore)
			}
		}
	}
	return "", ""
}

func isAIAgentPrincipal(pt string) bool {
	return pt == PrincipalAIAgent || pt == PrincipalEphemeralSession
}

func containsString(list []string, target string) bool {
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}

func isScopeSubset(child, parent []string) bool {
	pSet := make(map[string]bool, len(parent))
	for _, s := range parent {
		pSet[s] = true
	}
	for _, s := range child {
		if !pSet[s] {
			return false
		}
	}
	return true
}

func isSafeResourceURI(res string) bool {
	if res == "" || strings.Contains(res, "..") || strings.Contains(res, "*") {
		return false
	}
	return strings.HasPrefix(res, "zoo://")
}

func isResourceWithin(child, parent string) bool {
	if child == parent {
		return true
	}
	if strings.HasSuffix(parent, "/") {
		return strings.HasPrefix(child, parent)
	}
	return strings.HasPrefix(child, parent+"/")
}

func isResourceContained(child string, parents []string) bool {
	for _, p := range parents {
		if isResourceWithin(child, p) {
			return true
		}
	}
	return false
}

func areResourcesContained(children, parents []string) bool {
	for _, c := range children {
		if !isResourceContained(c, parents) {
			return false
		}
	}
	return true
}

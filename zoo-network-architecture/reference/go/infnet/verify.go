// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package infnet

import (
	"errors"
	"fmt"
)

// VerifyParityCase independently verifies a ParityCase (node advertisements,
// constitutional locks, provider key binding, Ed25519 receipt signature,
// output-token Merkle root, privacy-boundary compliance, and capacity conservation).
func VerifyParityCase(c ParityCase) VerificationResult {
	res := VerificationResult{
		CaseID:              c.CaseID,
		Valid:               false,
		ErrorCode:           ErrCodeOK,
		ConstitutionalValid: !c.Receipt.ProvesScientificTruth && !c.Receipt.AuthorizesTreasurySpend,
		SignatureValid:      false,
		PrivacyCompliant:    false,
		CapacityConserved:   false,
	}

	// 1. Validate and register all node advertisements into a fresh registry.
	reg := NewRegistry()
	nodeMap := make(map[string]NodeAdvertisement, len(c.Nodes))
	nodeErrCode := ErrCodeOK
	nodeErrDetail := ""
	for _, ad := range c.Nodes {
		if err := reg.Register(ad); err != nil {
			if nodeErrCode == ErrCodeOK {
				switch {
				case errors.Is(err, ErrStaleHeartbeatEpoch):
					nodeErrCode = ErrCodeStaleHeartbeatEpoch
				case errors.Is(err, ErrKeyMismatch):
					nodeErrCode = ErrCodeKeyMismatch
				default:
					nodeErrCode = ErrCodeInvalidNodeAdvertisement
				}
				nodeErrDetail = err.Error()
			}
		} else {
			nodeMap[ad.NodeID] = ad
		}
	}

	// 2. Schema checks on receipt.
	schemaOK := c.Receipt.SchemaVersion == SchemaVersion &&
		IsValidTopologyMode(c.Receipt.TopologyMode) &&
		IsValidPrivacyTier(c.Receipt.EffectivePrivacyTier) &&
		(c.Receipt.PrivacyRequirement == PrivacyReqPublicOK || c.Receipt.PrivacyRequirement == PrivacyReqStrict) &&
		c.Receipt.BatchUtilizationBps <= 10000

	// 3. Provider binding + Ed25519 signature check.
	providerAd, providerFound := nodeMap[c.Receipt.PrimaryProviderID]
	providerBound := providerFound && providerAd.PublicKeyHex == c.Receipt.ProviderPublicKeyHex
	sigOK := providerBound && VerifyDeliveryReceiptSignature(c.Receipt)
	res.SignatureValid = sigOK

	// 4. Output token Merkle root check.
	recomputedOutRoot := ComputeOutputMerkleRoot(c.OutputChunks)
	merkleOK := recomputedOutRoot == c.Receipt.OutputMerkleRoot &&
		uint32(len(c.OutputChunks)) == c.Receipt.OutputTokens

	// 5. Privacy-boundary compliance across all touched nodes (route, prefill, decode, failed).
	privacyOK, privacyDetail := verifyPrivacyCompliance(nodeMap, c.Receipt)
	res.PrivacyCompliant = privacyOK

	// 6. Capacity conservation replay across all events in ledger.
	capOK, capDetail := VerifyCapacityConservation(nodeMap, c.CapacityLedger)
	res.CapacityConserved = capOK

	// Assign primary error code in strict canonical precedence order.
	switch {
	case !schemaOK:
		res.ErrorCode = ErrCodeSchemaInvalid
		res.Detail = "receipt failed schema_version or enum validation"
	case !res.ConstitutionalValid:
		res.ErrorCode = ErrCodeConstitutionalViolation
		res.Detail = "constitutional lock violated: proves_scientific_truth and authorizes_treasury_spend must be false"
	case nodeErrCode != ErrCodeOK:
		res.ErrorCode = nodeErrCode
		res.Detail = nodeErrDetail
	case !providerBound:
		res.ErrorCode = ErrCodeMissingProviderNode
		res.Detail = fmt.Sprintf("primary provider %q missing or public key mismatch", c.Receipt.PrimaryProviderID)
	case !sigOK:
		res.ErrorCode = ErrCodeInvalidReceiptSignature
		res.Detail = "delivery receipt Ed25519 signature verification failed"
	case !merkleOK:
		res.ErrorCode = ErrCodeOutputMerkleMismatch
		res.Detail = fmt.Sprintf("output Merkle root or token count mismatch (got root=%s count=%d)", recomputedOutRoot, len(c.OutputChunks))
	case !privacyOK:
		res.ErrorCode = ErrCodePrivacyBoundaryViolation
		res.Detail = privacyDetail
	case !capOK:
		res.ErrorCode = ErrCodeCapacityConservation
		res.Detail = capDetail
	default:
		res.Valid = true
		res.ErrorCode = ErrCodeOK
		res.Detail = "verified"
	}

	res.VerdictDigest = ComputeVerdictDigest(res, c.Receipt.OutputMerkleRoot)
	return res
}

func verifyPrivacyCompliance(nodeMap map[string]NodeAdvertisement, r DeliveryReceipt) (bool, string) {
	if !PrivacyTierSatisfies(r.PrivacyRequirement, r.EffectivePrivacyTier) {
		return false, fmt.Sprintf("effective_privacy_tier %s violates %s", r.EffectivePrivacyTier, r.PrivacyRequirement)
	}

	checkNode := func(nid, role string) (PrivacyTier, bool, string) {
		ad, ok := nodeMap[nid]
		if !ok {
			return "", false, fmt.Sprintf("%s node %s not found in registered advertisements", role, nid)
		}
		if !PrivacyTierSatisfies(r.PrivacyRequirement, ad.PrivacyTier) {
			return ad.PrivacyTier, false, fmt.Sprintf("%s node %s has tier %s violating %s", role, nid, ad.PrivacyTier, r.PrivacyRequirement)
		}
		return ad.PrivacyTier, true, ""
	}

	touchedTiers := make([]PrivacyTier, 0, len(r.RouteNodeIDs)+len(r.FailedNodeIDs)+1)
	for _, nid := range r.RouteNodeIDs {
		tier, ok, msg := checkNode(nid, "route")
		if !ok {
			return false, msg
		}
		touchedTiers = append(touchedTiers, tier)
	}
	if r.PrefillNodeID != "" {
		tier, ok, msg := checkNode(r.PrefillNodeID, "prefill")
		if !ok {
			return false, msg
		}
		touchedTiers = append(touchedTiers, tier)
	}
	for _, nid := range r.DecodeNodeIDs {
		tier, ok, msg := checkNode(nid, "decode")
		if !ok {
			return false, msg
		}
		touchedTiers = append(touchedTiers, tier)
	}
	for _, nid := range r.FailedNodeIDs {
		tier, ok, msg := checkNode(nid, "failed")
		if !ok {
			return false, msg
		}
		touchedTiers = append(touchedTiers, tier)
	}

	if len(touchedTiers) > 0 {
		expectedEff := EffectiveTierForRoute(touchedTiers)
		if r.EffectivePrivacyTier != expectedEff {
			return false, fmt.Sprintf("effective_privacy_tier %s != weakest touched tier %s", r.EffectivePrivacyTier, expectedEff)
		}
	}
	return true, ErrCodeOK
}

// VerifyParitySuite verifies every case in a ParitySuite and computes its audit_merkle_root.
func VerifyParitySuite(suite ParitySuite) ([]VerificationResult, string, error) {
	results := make([]VerificationResult, len(suite.Cases))
	digests := make([]string, len(suite.Cases))
	for i, c := range suite.Cases {
		r := VerifyParityCase(c)
		results[i] = r
		digests[i] = r.VerdictDigest
	}
	root, err := ComputeMerkleRootFromHexDigests(digests)
	if err != nil {
		return nil, "", err
	}
	return results, root, nil
}

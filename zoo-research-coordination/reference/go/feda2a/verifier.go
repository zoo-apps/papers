// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package feda2a

import (
	"strings"
)

func indexPolicies(policies []OrgGovernancePolicy) map[string]OrgGovernancePolicy {
	m := make(map[string]OrgGovernancePolicy, len(policies))
	for _, p := range policies {
		m[p.OrgID] = p
	}
	return m
}

func indexCards(cards []AgentCard) map[string]AgentCard {
	m := make(map[string]AgentCard, len(cards))
	for _, c := range cards {
		m[c.OrgID] = c
	}
	return m
}

func findPrincipal(p OrgGovernancePolicy, id string) (Principal, bool) {
	for _, pr := range p.Principals {
		if pr.ID == id {
			return pr, true
		}
	}
	return Principal{}, false
}

// VerifyAgentCard audits an A2A AgentCard for zero credential/memory leakage,
// canonical hash integrity, policy binding, and Ed25519 signature authenticity.
func VerifyAgentCard(card AgentCard, policies map[string]OrgGovernancePolicy, probes []BoundaryProbeSpec) (bool, string) {
	raw, err := CanonicalJSON(card)
	if err != nil {
		return false, CodeAgentCardSigInvalid
	}
	credN, memN, traceN, firstCode, _ := ScanBoundaryProbes(raw, probes)
	if credN > 0 {
		return false, CodeAgentCardCredLeak
	}
	if memN > 0 || traceN > 0 {
		return false, firstCode
	}
	pol, ok := policies[card.OrgID]
	if !ok {
		return false, CodeAgentCardSigInvalid
	}
	if pol.PolicyHash != ComputeOrgPolicyHash(pol) || card.PolicyDigest != pol.PolicyHash {
		return false, CodeAgentCardSigInvalid
	}
	pr, ok := findPrincipal(pol, card.GatewayPrincipal.ID)
	if !ok || pr.Role != RoleOrgGateway || pr.PublicKeyHex != card.GatewayPrincipal.PublicKeyHex {
		return false, CodeAgentCardSigInvalid
	}
	if card.CardHash != ComputeAgentCardHash(card) {
		return false, CodeAgentCardSigInvalid
	}
	if !VerifyCanonical(card.GatewayPrincipal.PublicKeyHex, card.OrgSignatureHex, DomainAgentCard, AgentCardSigningPayload(card)) {
		return false, CodeAgentCardSigInvalid
	}
	return true, CodeOK
}

// VerifyEnvelope audits a cross-org SignedA2AEnvelope for zero boundary leaks,
// sender authenticity, audience binding, expiry, replay defense, scope boundaries,
// AI constitutional constraints, and license review compliance.
func VerifyEnvelope(
	env SignedA2AEnvelope,
	receiverOrgID string,
	verifiedAt int64,
	priorNonces []string,
	cards map[string]AgentCard,
	policies map[string]OrgGovernancePolicy,
	probes []BoundaryProbeSpec,
) (bool, string) {
	// Check explicit private-memory reference smuggling first (distinct from raw content leak).
	if env.Method == "tasks/send" || env.Method == "tasks/sendSubscribe" {
		recvPol, hasRecv := policies[receiverOrgID]
		if hasRecv && !containsString(recvPol.AllowedExchangeTiers, env.Payload.Commitment.InputTier) {
			return false, CodePrivateMemoryRefForbidden
		}
		for _, ref := range env.Payload.Commitment.InputRecordRefs {
			lowerRef := strings.ToLower(ref)
			if strings.Contains(lowerRef, "priv") || strings.Contains(lowerRef, "pii") || strings.Contains(lowerRef, "trace") {
				return false, CodePrivateMemoryRefForbidden
			}
			for _, p := range probes {
				if containsString(p.PrivateMemoryRefIDs, ref) {
					return false, CodePrivateMemoryRefForbidden
				}
			}
		}
	}

	raw, err := CanonicalJSON(env)
	if err != nil {
		return false, CodeEnvelopeSigInvalid
	}
	credN, memN, traceN, firstCode, _ := ScanBoundaryProbes(raw, probes)
	if credN > 0 || memN > 0 || traceN > 0 {
		return false, firstCode
	}

	senderCard, hasSender := cards[env.SenderOrgID]
	if !hasSender || env.SignerID != senderCard.GatewayPrincipal.ID {
		return false, CodeSpoofedOrgIdentity
	}
	if env.EnvelopeHash != ComputeEnvelopeHash(env) {
		return false, CodeEnvelopeSigInvalid
	}
	if !VerifyCanonical(senderCard.GatewayPrincipal.PublicKeyHex, env.OrgSigHex, DomainEnvelope, EnvelopeSigningPayload(env)) {
		// Distinguish spoofed org identity (valid signature by another org's key) from generic sig tampering.
		for orgID, otherCard := range cards {
			if orgID != env.SenderOrgID &&
				VerifyCanonical(otherCard.GatewayPrincipal.PublicKeyHex, env.OrgSigHex, DomainEnvelope, EnvelopeSigningPayload(env)) {
				return false, CodeSpoofedOrgIdentity
			}
		}
		return false, CodeEnvelopeSigInvalid
	}

	if env.AudienceOrgID != receiverOrgID {
		return false, CodeAudienceMismatch
	}
	if env.IssuedAt > verifiedAt || verifiedAt > env.ExpiresAt {
		return false, CodeEnvelopeExpired
	}
	if containsString(priorNonces, env.TaskNonce) {
		return false, CodeNonceReplay
	}

	if env.Method == "tasks/send" || env.Method == "tasks/sendSubscribe" {
		recvPol, hasRecv := policies[receiverOrgID]
		if !hasRecv {
			return false, CodeAudienceMismatch
		}
		for _, denied := range recvPol.DeniedScopes {
			if env.Scope == denied || env.Payload.SkillID == denied {
				if env.Payload.ActorRole == RoleAIAgent {
					if denied == ScopeTreasurySpend {
						return false, CodeAITreasuryForbidden
					}
					if denied == ScopeGovernanceRuleChg {
						return false, CodeAIVotingRuleForbidden
					}
				}
				return false, CodeScopeEscalation
			}
		}
		if !containsString(recvPol.AllowedSkills, env.Scope) || !containsString(recvPol.AllowedSkills, env.Payload.SkillID) {
			return false, CodeScopeEscalation
		}
		if env.Payload.ActorRole == RoleAIAgent && env.Payload.SelfCertified {
			return false, CodeAISelfCertifyForbidden
		}
		if len(env.Payload.Licenses) == 0 {
			return false, CodeLicenseUnreviewed
		}
		for _, lic := range env.Payload.Licenses {
			if !lic.LicenseReviewed || !containsString(recvPol.AllowedLicenses, lic.LicenseID) {
				return false, CodeLicenseUnreviewed
			}
		}
	}

	return true, CodeOK
}

// VerifyReceipt audits a TaskResultReceipt for zero credential/memory/trace leaks,
// Ed25519 signature authenticity, signed EgressBlockEvent validity, deterministic
// scientific recomputation parity, and authorized HUMAN_REVIEWER acceptance.
func VerifyReceipt(
	env *SignedA2AEnvelope,
	receipt TaskResultReceipt,
	acceptance *ExperimentAcceptance,
	cards map[string]AgentCard,
	policies map[string]OrgGovernancePolicy,
	probes []BoundaryProbeSpec,
) (bool, string, bool) {
	raw, err := CanonicalJSON(receipt)
	if err != nil {
		return false, CodeReceiptSigInvalid, false
	}
	credN, memN, traceN, firstCode, _ := ScanBoundaryProbes(raw, probes)
	if credN > 0 || memN > 0 || traceN > 0 {
		return false, firstCode, false
	}

	execCard, ok := cards[receipt.ExecutorOrgID]
	if !ok || receipt.SignerID != execCard.GatewayPrincipal.ID {
		return false, CodeReceiptSigInvalid, false
	}
	if receipt.ReceiptHash != ComputeReceiptHash(receipt) {
		return false, CodeReceiptSigInvalid, false
	}
	if !VerifyCanonical(execCard.GatewayPrincipal.PublicKeyHex, receipt.ExecutorSigHex, DomainTaskReceipt, ReceiptSigningPayload(receipt)) {
		return false, CodeReceiptSigInvalid, false
	}

	if receipt.EgressBlock != nil {
		ev := *receipt.EgressBlock
		if ev.WireBytesSent != 0 {
			return false, CodeCredentialLeakDetected, false
		}
		if !VerifyCanonical(execCard.GatewayPrincipal.PublicKeyHex, ev.EventSigHex, DomainEgressBlock, EgressBlockSigningPayload(ev)) {
			return false, CodeReceiptSigInvalid, false
		}
	}

	recomputeOK := false
	if receipt.Result != nil && env != nil {
		expected, err := RunDeterministicZHL(env.Payload.TaskID, env.Payload.Commitment)
		if err != nil {
			return false, CodeResultRecomputeMismatch, false
		}
		got := *receipt.Result
		if got.ResultHash != ComputeScientificResultHash(got) ||
			got.ResultHash != expected.ResultHash ||
			got.MeanAMicro != expected.MeanAMicro ||
			got.MeanBMicro != expected.MeanBMicro ||
			got.EffectSizeMicro != expected.EffectSizeMicro ||
			got.StatMicro != expected.StatMicro ||
			got.Significant != expected.Significant {
			return false, CodeResultRecomputeMismatch, false
		}
		recomputeOK = true
	}

	if acceptance != nil {
		if acceptance.ReviewerRole == RoleAIAgent {
			return false, CodeAISelfCertifyForbidden, recomputeOK
		}
		pol, ok := policies[acceptance.OrgID]
		if !ok {
			return false, CodeAISelfCertifyForbidden, recomputeOK
		}
		pr, ok := findPrincipal(pol, acceptance.ReviewerID)
		if !ok || (pr.Role != RoleHumanReviewer && pr.Role != RoleCouncilMember) {
			return false, CodeAISelfCertifyForbidden, recomputeOK
		}
		if !VerifyCanonical(pr.PublicKeyHex, acceptance.AcceptanceSigHex, DomainAcceptance, AcceptanceSigningPayload(*acceptance)) {
			return false, CodeReceiptSigInvalid, recomputeOK
		}
		if acceptance.ReceiptHash != receipt.ReceiptHash {
			return false, CodeReceiptSigInvalid, recomputeOK
		}
		if receipt.Result != nil && acceptance.RecomputedHash != receipt.Result.ResultHash {
			return false, CodeResultRecomputeMismatch, recomputeOK
		}
	}

	return true, CodeOK, recomputeOK
}

// VerifyGovernanceAction enforces constitutional boundaries on governance and treasury actions.
func VerifyGovernanceAction(action GovernanceAction, policies map[string]OrgGovernancePolicy) (bool, string) {
	if action.ProposerRole == RoleAIAgent {
		switch action.ActionType {
		case "voting_rule_change":
			return false, CodeAIVotingRuleForbidden
		case "treasury_spend":
			return false, CodeAITreasuryForbidden
		default:
			return false, CodeScopeEscalation
		}
	}
	pol, ok := policies[action.OrgID]
	if !ok {
		return false, CodeScopeEscalation
	}
	pr, ok := findPrincipal(pol, action.ProposerID)
	if !ok || pr.Role != RoleCouncilMember {
		return false, CodeScopeEscalation
	}
	if !VerifyCanonical(pr.PublicKeyHex, action.SignatureHex, DomainGovernanceAction, GovernanceActionSigningPayload(action)) {
		return false, CodeEnvelopeSigInvalid
	}
	return true, CodeOK
}

// VerifyAdvisory verifies a non-binding AI_AGENT advisory recommendation.
func VerifyAdvisory(adv AdvisoryAssessment, policies map[string]OrgGovernancePolicy) (bool, string) {
	if adv.Binding {
		return false, CodeAISelfCertifyForbidden
	}
	pol, ok := policies[adv.OrgID]
	if !ok {
		return false, CodeSpoofedOrgIdentity
	}
	pr, ok := findPrincipal(pol, adv.AgentID)
	if !ok || pr.Role != RoleAIAgent {
		return false, CodeSpoofedOrgIdentity
	}
	if !VerifyCanonical(pr.PublicKeyHex, adv.SignatureHex, DomainAdvisory, AdvisorySigningPayload(adv)) {
		return false, CodeEnvelopeSigInvalid
	}
	return true, CodeOK
}

// VerifyWireTranscript audits every byte of every captured HTTP wire frame.
func VerifyWireTranscript(frames []WireFrame, probes []BoundaryProbeSpec) WireAuditSummary {
	var totalBytes, credBytes, memBytes, traceBytes int64
	allHashesOK := true

	for _, f := range frames {
		reqB := []byte(f.RequestBody)
		respB := []byte(f.ResponseBody)
		totalBytes += int64(len(reqB) + len(respB))

		if int64(len(reqB)) != f.RequestBytes ||
			int64(len(respB)) != f.ResponseBytes ||
			SHA256Hex(reqB) != f.RequestSHA256 ||
			SHA256Hex(respB) != f.ResponseSHA256 {
			allHashesOK = false
		}
		c1, m1, t1, _, _ := ScanBoundaryProbes(reqB, probes)
		c2, m2, t2, _, _ := ScanBoundaryProbes(respB, probes)
		credBytes += c1 + c2
		memBytes += m1 + m2
		traceBytes += t1 + t2
	}

	return WireAuditSummary{
		TotalFrames:            int64(len(frames)),
		TotalWireBytes:         totalBytes,
		CredentialLeakBytes:    credBytes,
		PrivateMemoryLeakBytes: memBytes,
		RawTraceLeakBytes:      traceBytes,
		WireTranscriptRoot:     ComputeWireTranscriptRoot(frames),
		AllFrameHashesValid:    allHashesOK,
		ZeroBoundaryLeakage:    credBytes == 0 && memBytes == 0 && traceBytes == 0,
	}
}

// VerifySuite runs the complete independent audit over an ExchangeSuite and
// returns a canonical VerificationReport with RFC 6962 AuditMerkleRoot.
func VerifySuite(suite ExchangeSuite) VerificationReport {
	policies := indexPolicies(suite.OrgPolicies)
	cards := indexCards(suite.AgentCards)

	framesByID := make(map[string]WireFrame, len(suite.WireTranscript))
	for _, wf := range suite.WireTranscript {
		framesByID[wf.FrameID] = wf
	}

	wireAudit := VerifyWireTranscript(suite.WireTranscript, suite.BoundaryProbes)

	// Verify all AgentCards first.
	allCardsOK := len(suite.AgentCards) >= 2
	cardCode := CodeOK
	for _, card := range suite.AgentCards {
		ok, code := VerifyAgentCard(card, policies, suite.BoundaryProbes)
		if !ok {
			allCardsOK = false
			cardCode = code
			break
		}
	}

	stageOutcomes := make([]StageOutcome, 0, len(suite.LiveStages))
	allStagesValid := allCardsOK && wireAudit.AllFrameHashesValid && wireAudit.ZeroBoundaryLeakage

	seenNoncesByOrg := map[string][]string{}

	for _, st := range suite.LiveStages {
		var stCred, stMem, stTrace int64
		var checkedFrames int64
		for _, fid := range st.WireFrameIDs {
			wf, ok := framesByID[fid]
			if !ok {
				continue
			}
			checkedFrames++
			c1, m1, t1, _, _ := ScanBoundaryProbes([]byte(wf.RequestBody), suite.BoundaryProbes)
			c2, m2, t2, _, _ := ScanBoundaryProbes([]byte(wf.ResponseBody), suite.BoundaryProbes)
			stCred += c1 + c2
			stMem += m1 + m2
			stTrace += t1 + t2
		}

		stageValid := true
		stageCode := CodeOK
		taskState := st.ExpectedState
		recomputeOK := false

		if stCred > 0 || stMem > 0 || stTrace > 0 {
			stageValid = false
			stageCode = CodeCredentialLeakDetected
		}

		if stageValid && st.Stage == "1_discover_agent_cards" {
			if !allCardsOK {
				stageValid = false
				stageCode = cardCode
			}
		}

		if stageValid && st.Envelope != nil {
			recvOrg := st.Envelope.AudienceOrgID
			ok, code := VerifyEnvelope(*st.Envelope, recvOrg, st.VerifiedAt, seenNoncesByOrg[recvOrg], cards, policies, suite.BoundaryProbes)
			if !ok {
				stageValid = false
				stageCode = code
			} else {
				seenNoncesByOrg[recvOrg] = append(seenNoncesByOrg[recvOrg], st.Envelope.TaskNonce)
			}
		}

		if stageValid && st.Advisory != nil {
			ok, code := VerifyAdvisory(*st.Advisory, policies)
			if !ok {
				stageValid = false
				stageCode = code
			}
		}

		if stageValid && st.Receipt != nil {
			taskState = st.Receipt.State
			ok, code, recOK := VerifyReceipt(st.Envelope, *st.Receipt, st.Acceptance, cards, policies, suite.BoundaryProbes)
			recomputeOK = recOK
			if !ok {
				stageValid = false
				stageCode = code
			} else if st.Receipt.State != st.ExpectedState || st.Receipt.ErrorCode != st.ExpectedErrorCode {
				stageValid = false
				stageCode = CodeTaskStateInvalid
			}
		}

		if stageValid && st.Stage == "7_wire_transcript_boundary_audit" {
			if !wireAudit.AllFrameHashesValid || !wireAudit.ZeroBoundaryLeakage {
				stageValid = false
				stageCode = CodeCredentialLeakDetected
			}
		}

		if !stageValid {
			allStagesValid = false
		}
		stageOutcomes = append(stageOutcomes, StageOutcome{
			Stage:               st.Stage,
			Valid:               stageValid,
			Code:                stageCode,
			TaskState:           taskState,
			WireFramesChecked:   checkedFrames,
			CredentialLeakBytes: stCred,
			PrivateMemLeakBytes: stMem,
			RawTraceLeakBytes:   stTrace,
			RecomputeVerified:   recomputeOK,
		})
	}

	advResults := make([]AdversarialOutcome, 0, len(suite.Adversarial))
	allAdvPass := true
	var attacksDetected, attacksTotal, positivePass int64

	for _, tc := range suite.Adversarial {
		var actualValid bool
		var actualCode string

		switch tc.Target {
		case "agent_card":
			if tc.AgentCard != nil {
				actualValid, actualCode = VerifyAgentCard(*tc.AgentCard, policies, suite.BoundaryProbes)
			}
		case "envelope":
			if tc.Envelope != nil {
				actualValid, actualCode = VerifyEnvelope(*tc.Envelope, tc.ReceiverOrgID, tc.VerifiedAt, tc.PriorNonces, cards, policies, suite.BoundaryProbes)
			}
		case "receipt":
			if tc.Receipt != nil {
				actualValid, actualCode, _ = VerifyReceipt(tc.Envelope, *tc.Receipt, tc.Acceptance, cards, policies, suite.BoundaryProbes)
			}
		case "governance":
			if tc.GovernanceAction != nil {
				actualValid, actualCode = VerifyGovernanceAction(*tc.GovernanceAction, policies)
			}
		case "advisory":
			if tc.Advisory != nil {
				actualValid, actualCode = VerifyAdvisory(*tc.Advisory, policies)
			}
		default:
			actualValid, actualCode = false, CodeTaskStateInvalid
		}

		matched := (actualValid == tc.ExpectedValid) && (actualCode == tc.ExpectedCode)
		if !matched {
			allAdvPass = false
		}
		if !tc.ExpectedValid {
			attacksTotal++
			if matched {
				attacksDetected++
			}
		} else if matched {
			positivePass++
		}

		advResults = append(advResults, AdversarialOutcome{
			CaseID:        tc.CaseID,
			Category:      tc.Category,
			ExpectedValid: tc.ExpectedValid,
			ActualValid:   actualValid,
			ExpectedCode:  tc.ExpectedCode,
			ActualCode:    actualCode,
			Matched:       matched,
		})
	}

	auditRoot := ComputeAuditMerkleRoot(wireAudit, stageOutcomes, advResults)

	return VerificationReport{
		SchemaVersion:      SchemaVersion,
		SpecVersion:        SpecVersion,
		Seed:               suite.Seed,
		AllStagesValid:     allStagesValid,
		AllAdversarialPass: allAdvPass,
		AttacksDetected:    attacksDetected,
		AttacksTotal:       attacksTotal,
		PositiveCasesPass:  positivePass,
		WireAudit:          wireAudit,
		StageOutcomes:      stageOutcomes,
		AdversarialResults: advResults,
		AuditMerkleRoot:    auditRoot,
	}
}

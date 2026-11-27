// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package feda2a

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
)

// KeyPair binds a Principal descriptor to its Ed25519 private key.
type KeyPair struct {
	Principal Principal
	Private   ed25519.PrivateKey
}

// DeriveKeyPair deterministically derives an Ed25519 keypair from a seed, org, id, and role.
func DeriveKeyPair(seed int64, orgID, id, role string) KeyPair {
	seedInput := fmt.Sprintf("federated-a2a.v1:key:%d:%s:%s:%s", seed, orgID, id, role)
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

// DeriveInternalHMACSecret derives an org-private HMAC key used strictly for
// internal ephemeral capability tokens (never exported across org boundaries).
func DeriveInternalHMACSecret(seed int64, orgID string) []byte {
	sum := sha256.Sum256([]byte(fmt.Sprintf("federated-a2a.v1:internal-hmac:%d:%s", seed, orgID)))
	return sum[:]
}

// MintInternalCapabilityToken creates an HMAC-SHA256 internal capability token
// bound strictly to a single org's internal runtime.
func MintInternalCapabilityToken(secret []byte, orgID, taskID, scope string, expiresAt int64) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(fmt.Sprintf("%s|%s|%s|%d", orgID, taskID, scope, expiresAt)))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyInternalCapabilityToken checks an internal HMAC capability token in constant time.
func VerifyInternalCapabilityToken(secret []byte, orgID, taskID, scope string, expiresAt int64, tokenHex string) bool {
	expected := MintInternalCapabilityToken(secret, orgID, taskID, scope, expiresAt)
	return hmac.Equal([]byte(expected), []byte(tokenHex))
}

// SignCanonical signs domain || 0x00 || CanonicalJSON(payload) with Ed25519.
func SignCanonical(priv ed25519.PrivateKey, domain string, payload any) string {
	msg, err := DomainMessage(domain, payload)
	if err != nil {
		panic(fmt.Sprintf("SignCanonical failed: %v", err))
	}
	return hex.EncodeToString(ed25519.Sign(priv, msg))
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

// Canonical hash & signing payload builders (shared identically with Python).

func ComputeOrgPolicyHash(p OrgGovernancePolicy) string {
	return HashCanonical(DomainOrgPolicy, map[string]any{
		"ai_agent_can_authorize_spend": p.AIAgentCanAuthorizeSpend,
		"ai_agent_can_redefine_voting": p.AIAgentCanRedefineVoting,
		"ai_agent_can_self_certify":    p.AIAgentCanSelfCertify,
		"allowed_exchange_tiers":       nonNilStrings(p.AllowedExchangeTiers),
		"allowed_licenses":             nonNilStrings(p.AllowedLicenses),
		"allowed_skills":               nonNilStrings(p.AllowedSkills),
		"denied_scopes":                nonNilStrings(p.DeniedScopes),
		"org_id":                       p.OrgID,
		"policy_version":               p.PolicyVersion,
		"principals":                   nonNilPrincipals(p.Principals),
	})
}

func AgentCardSigningPayload(c AgentCard) map[string]any {
	return map[string]any{
		"boundary_commitment": c.BoundaryCommitment,
		"capabilities":        c.Capabilities,
		"description":         c.Description,
		"gateway_principal":   c.GatewayPrincipal,
		"logical_url":         c.LogicalURL,
		"name":                c.Name,
		"org_id":              c.OrgID,
		"policy_digest":       c.PolicyDigest,
		"protocol_version":    c.ProtocolVersion,
		"schema_version":      c.SchemaVersion,
		"skills":              nonNilSkills(c.Skills),
	}
}

func ComputeAgentCardHash(c AgentCard) string {
	return HashCanonical(DomainAgentCard, AgentCardSigningPayload(c))
}

func ComputeCommitmentHash(c ExperimentCommitment) string {
	return HashCanonical(DomainCommitment, map[string]any{
		"alpha_bps":         c.AlphaBps,
		"commitment_id":     c.CommitmentID,
		"group_a_micro":     nonNilInt64s(c.GroupAMicro),
		"group_b_micro":     nonNilInt64s(c.GroupBMicro),
		"hypothesis":        c.Hypothesis,
		"input_record_refs": nonNilStrings(c.InputRecordRefs),
		"input_tier":        c.InputTier,
		"min_effect_micro":  c.MinEffectMicro,
		"zhl_template":      c.ZHLTemplate,
	})
}

func ComputeScientificResultHash(r ScientificResult) string {
	return HashCanonical(DomainResultArtifact, map[string]any{
		"commitment_hash":   r.CommitmentHash,
		"effect_size_micro": r.EffectSizeMicro,
		"mean_a_micro":      r.MeanAMicro,
		"mean_b_micro":      r.MeanBMicro,
		"output_tier":       r.OutputTier,
		"sample_count":      r.SampleCount,
		"significant":       r.Significant,
		"stat_micro":        r.StatMicro,
		"summary_note":      r.SummaryNote,
		"task_id":           r.TaskID,
		"var_a_micro":       r.VarAMicro,
		"var_b_micro":       r.VarBMicro,
		"zhl_template":      r.ZHLTemplate,
	})
}

func EnvelopeSigningPayload(e SignedA2AEnvelope) map[string]any {
	return map[string]any{
		"audience_org_id": e.AudienceOrgID,
		"envelope_id":     e.EnvelopeID,
		"expires_at":      e.ExpiresAt,
		"issued_at":       e.IssuedAt,
		"method":          e.Method,
		"payload": map[string]any{
			"actor_id":         e.Payload.ActorID,
			"actor_role":       e.Payload.ActorRole,
			"commitment":       e.Payload.Commitment,
			"defer_completion": e.Payload.DeferCompletion,
			"licenses":         nonNilLicenses(e.Payload.Licenses),
			"prompt_note":      e.Payload.PromptNote,
			"self_certified":   e.Payload.SelfCertified,
			"skill_id":         e.Payload.SkillID,
			"task_id":          e.Payload.TaskID,
		},
		"scope":         e.Scope,
		"sender_org_id": e.SenderOrgID,
		"signer_id":     e.SignerID,
		"task_nonce":    e.TaskNonce,
	}
}

func ComputeEnvelopeHash(e SignedA2AEnvelope) string {
	return HashCanonical(DomainEnvelope, EnvelopeSigningPayload(e))
}

func EgressBlockSigningPayload(ev EgressBlockEvent) map[string]any {
	return map[string]any{
		"blocked_class":   ev.BlockedClass,
		"blocked_digest":  ev.BlockedDigest,
		"bytes_blocked":   ev.BytesBlocked,
		"event_id":        ev.EventID,
		"org_id":          ev.OrgID,
		"reason_code":     ev.ReasonCode,
		"task_id":         ev.TaskID,
		"timestamp":       ev.Timestamp,
		"wire_bytes_sent": ev.WireBytesSent,
	}
}

func ReceiptSigningPayload(r TaskResultReceipt) map[string]any {
	var resPayload any = nil
	if r.Result != nil {
		resPayload = *r.Result
	}
	var blockPayload any = nil
	if r.EgressBlock != nil {
		blockPayload = *r.EgressBlock
	}
	return map[string]any{
		"completed_at":        r.CompletedAt,
		"egress_audit_passed": r.EgressAuditPassed,
		"egress_block":        blockPayload,
		"error_code":          r.ErrorCode,
		"executor_org_id":     r.ExecutorOrgID,
		"receipt_id":          r.ReceiptID,
		"requester_org_id":    r.RequesterOrgID,
		"result":              resPayload,
		"signer_id":           r.SignerID,
		"state":               r.State,
		"task_id":             r.TaskID,
		"transitions":         nonNilTransitions(r.Transitions),
	}
}

func ComputeReceiptHash(r TaskResultReceipt) string {
	return HashCanonical(DomainTaskReceipt, ReceiptSigningPayload(r))
}

func AdvisorySigningPayload(a AdvisoryAssessment) map[string]any {
	return map[string]any{
		"advisory_id":         a.AdvisoryID,
		"agent_id":            a.AgentID,
		"binding":             a.Binding,
		"conflict_flags":      nonNilStrings(a.ConflictFlags),
		"estimated_value_bps": a.EstimatedValueBps,
		"org_id":              a.OrgID,
		"recommendation":      a.Recommendation,
		"task_id":             a.TaskID,
	}
}

func AcceptanceSigningPayload(a ExperimentAcceptance) map[string]any {
	return map[string]any{
		"acceptance_id":   a.AcceptanceID,
		"accepted_at":     a.AcceptedAt,
		"advisory_ref_id": a.AdvisoryRefID,
		"org_id":          a.OrgID,
		"receipt_hash":    a.ReceiptHash,
		"recomputed_hash": a.RecomputedHash,
		"reviewer_id":     a.ReviewerID,
		"reviewer_role":   a.ReviewerRole,
		"task_id":         a.TaskID,
	}
}

func GovernanceActionSigningPayload(g GovernanceAction) map[string]any {
	return map[string]any{
		"action_id":     g.ActionID,
		"action_type":   g.ActionType,
		"amount_micro":  g.AmountMicro,
		"org_id":        g.OrgID,
		"proposer_id":   g.ProposerID,
		"proposer_role": g.ProposerRole,
		"summary":       g.Summary,
	}
}

func ComputeWireTranscriptRoot(frames []WireFrame) string {
	leaves := make([]string, len(frames))
	for i, f := range frames {
		leaves[i] = HashCanonical(DomainWireFrame, map[string]any{
			"content_type":    f.ContentType,
			"frame_id":        f.FrameID,
			"from_org_id":     f.FromOrgID,
			"http_method":     f.HTTPMethod,
			"http_status":     f.HTTPStatus,
			"path":            f.Path,
			"request_bytes":   f.RequestBytes,
			"request_sha256":  f.RequestSHA256,
			"response_bytes":  f.ResponseBytes,
			"response_sha256": f.ResponseSHA256,
			"stage":           f.Stage,
			"to_org_id":       f.ToOrgID,
		})
	}
	return MerkleRootRFC6962(leaves)
}

func ComputeAuditMerkleRoot(wire WireAuditSummary, stages []StageOutcome, adv []AdversarialOutcome) string {
	leaves := make([]string, 0, 1+len(stages)+len(adv))
	leaves = append(leaves, HashCanonical(DomainAuditLeaf, map[string]any{
		"all_frame_hashes_valid":    wire.AllFrameHashesValid,
		"credential_leak_bytes":     wire.CredentialLeakBytes,
		"kind":                      "wire_audit",
		"private_memory_leak_bytes": wire.PrivateMemoryLeakBytes,
		"raw_trace_leak_bytes":      wire.RawTraceLeakBytes,
		"total_frames":              wire.TotalFrames,
		"total_wire_bytes":          wire.TotalWireBytes,
		"wire_transcript_root":      wire.WireTranscriptRoot,
		"zero_boundary_leakage":     wire.ZeroBoundaryLeakage,
	}))
	for _, s := range stages {
		leaves = append(leaves, HashCanonical(DomainAuditLeaf, map[string]any{
			"code":                      s.Code,
			"credential_leak_bytes":     s.CredentialLeakBytes,
			"kind":                      "stage",
			"private_memory_leak_bytes": s.PrivateMemLeakBytes,
			"raw_trace_leak_bytes":      s.RawTraceLeakBytes,
			"recompute_verified":        s.RecomputeVerified,
			"stage":                     s.Stage,
			"task_state":                s.TaskState,
			"valid":                     s.Valid,
			"wire_frames_checked":       s.WireFramesChecked,
		}))
	}
	sortedAdv := make([]AdversarialOutcome, len(adv))
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

// Non-nil slice guards ensure [] rather than null in canonical JSON.
func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilInt64s(s []int64) []int64 {
	if s == nil {
		return []int64{}
	}
	return s
}

func nonNilPrincipals(s []Principal) []Principal {
	if s == nil {
		return []Principal{}
	}
	return s
}

func nonNilSkills(s []A2ASkill) []A2ASkill {
	if s == nil {
		return []A2ASkill{}
	}
	return s
}

func nonNilLicenses(s []LicenseAttachment) []LicenseAttachment {
	if s == nil {
		return []LicenseAttachment{}
	}
	return s
}

func nonNilTransitions(s []StateTransition) []StateTransition {
	if s == nil {
		return []StateTransition{}
	}
	return s
}

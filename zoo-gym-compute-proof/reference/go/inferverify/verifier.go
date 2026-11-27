// Copyright 2026 Zoo Labs Foundation / Hanzo Industries.
// Licensed under the Apache License, Version 2.0.

package inferverify

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
)

func lookupKey(trust TrustRoot, actorID string) (KeyEntry, bool) {
	for _, k := range trust.Keys {
		if k.ActorID == actorID {
			return k, true
		}
	}
	return KeyEntry{}, false
}

func validateKeyAtEpoch(k KeyEntry, epoch uint64) string {
	if k.Revoked {
		return ErrKeyRevoked
	}
	if epoch < k.ValidFromEpoch || epoch > k.ValidUntilEpoch {
		return ErrKeyExpired
	}
	return ErrNone
}

func checkConstitutionalGuards(pred InferencePredicate) string {
	// Schema-locked proof-scope boundaries: no attestation may overclaim hardware
	// TEE perfection or scientific truth.
	if pred.ProvesHardwareTEEUncompromised || pred.ProvesScientificTruth {
		return ErrOverclaimedProofScope
	}
	// AI_AGENT governance boundaries: AI agents may recommend challenge rates or
	// flag suspicious workers, but MUST NOT self-certify inference, approve
	// slashing, or mutate policy/bond/quorum parameters.
	if pred.ActorRole == RoleAIAgent {
		switch pred.GovernanceAction {
		case ActionApproveSlashing:
			return ErrAISlashApprovalForbidden
		case ActionMutatePolicyParams:
			return ErrAIPolicyMutationForbidden
		case ActionSelfCertifyInference:
			return ErrAISelfCertForbidden
		default:
			// An AI_AGENT cannot act as the attesting worker certifying its own inference.
			return ErrAISelfCertForbidden
		}
	}
	// Even if another actor role attempts forbidden self-certification or
	// unauthorized policy mutation inside an inference receipt:
	switch pred.GovernanceAction {
	case ActionSelfCertifyInference:
		return ErrAISelfCertForbidden
	case ActionApproveSlashing:
		return ErrAISlashApprovalForbidden
	case ActionMutatePolicyParams:
		return ErrAIPolicyMutationForbidden
	}
	return ErrNone
}

func buildAuditLeafDigest(r CaseResult) string {
	challengedStr := "false"
	if r.Challenged {
		challengedStr = "true"
	}
	escapedStr := "false"
	if r.FraudEscaped {
		escapedStr = "true"
	}
	tlogRoot := r.TLogRoot
	if tlogRoot == "" {
		tlogRoot = "none"
	}
	outDig := r.OutputDigest
	if outDig == "" {
		outDig = "none"
	}
	raw := "inference-verify.v1:audit-leaf:" +
		r.CaseID + ":" +
		r.Regime + ":" +
		r.Verdict + ":" +
		r.ErrorCode + ":" +
		challengedStr + ":" +
		escapedStr + ":" +
		strconv.Itoa(r.ReexecCount) + ":" +
		outDig + ":" +
		tlogRoot
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// VerifyCase independently verifies a single VerificationCase under the
// configured model, trust root, and verification policy.
func VerifyCase(c VerificationCase, model *QuantizedMLP, trust TrustRoot, policy VerificationPolicy) CaseResult {
	res := CaseResult{
		CaseID:   c.CaseID,
		Category: c.Category,
		Regime:   c.Regime,
	}
	finish := func(verdict, errCode string) CaseResult {
		res.Verdict = verdict
		res.ErrorCode = errCode
		if verdict == VerdictVerified && c.WorkerCheatedGroundTruth {
			res.FraudEscaped = true
		}
		res.AuditLeafDigest = buildAuditLeafDigest(res)
		return res
	}

	// Step 1: Parse DSSE payload before signature check only to locate worker key;
	// every field is then authenticated by Ed25519 DSSE PAE verification.
	if c.WorkerEnvelope.PayloadType != DSSEPayloadTypeInToto {
		return finish(VerdictInvalidAttestation, ErrInvalidPayloadType)
	}
	if len(c.WorkerEnvelope.Signatures) == 0 || c.WorkerEnvelope.Payload == "" {
		return finish(VerdictInvalidAttestation, ErrInvalidEnvelope)
	}
	rawPayload, _, errCode := decodePayloadOnly(c.WorkerEnvelope)
	if errCode != ErrNone {
		return finish(VerdictInvalidAttestation, errCode)
	}
	var stmt InTotoStatement
	if err := json.Unmarshal(rawPayload, &stmt); err != nil {
		return finish(VerdictInvalidAttestation, ErrInvalidEnvelope)
	}
	if stmt.Type != InTotoStatementTypeV1 {
		return finish(VerdictInvalidAttestation, ErrInvalidInTotoType)
	}
	if stmt.PredicateType != InferencePredicateType {
		return finish(VerdictInvalidAttestation, ErrInvalidPredicateType)
	}
	pred := stmt.Predicate
	if pred.SchemaVersion != SchemaVersion {
		return finish(VerdictInvalidAttestation, ErrInvalidSchemaVersion)
	}
	res.OutputDigest = pred.OutputDigest

	// Step 2: Constitutional & AI-role governance guards (evaluated before accepting any claim).
	if guardErr := checkConstitutionalGuards(pred); guardErr != ErrNone {
		return finish(VerdictPolicyRejected, guardErr)
	}

	// Step 3: Validate worker key registration, revocation, expiry, and operator group binding.
	workerKey, ok := lookupKey(trust, pred.WorkerID)
	if !ok || workerKey.PubKeyHex != pred.WorkerPubKeyHex || workerKey.OperatorGroup != pred.WorkerOperatorGroup {
		return finish(VerdictInvalidAttestation, ErrKeyUnregistered)
	}
	if keyErr := validateKeyAtEpoch(workerKey, c.ExpectedEpoch); keyErr != ErrNone {
		return finish(VerdictInvalidAttestation, keyErr)
	}

	// Step 4: Verify RFC 8032 Ed25519 DSSE signature over PAE(payloadType, payload).
	payloadBytes, sigBytes, sigErr := VerifyDSSESignature(c.WorkerEnvelope, workerKey.PubKeyHex)
	if sigErr != ErrNone {
		return finish(VerdictInvalidAttestation, sigErr)
	}

	// Step 5: Validate subject digest binding, regime, model digest, input digest, epoch, and equivocation.
	if len(stmt.Subject) == 0 || stmt.Subject[0].Digest["sha256"] != pred.OutputDigest {
		return finish(VerdictInvalidAttestation, ErrSubjectDigestMismatch)
	}
	if pred.Regime != c.Regime {
		return finish(VerdictInvalidAttestation, ErrRegimeMismatch)
	}
	if pred.Epoch != c.ExpectedEpoch {
		return finish(VerdictInvalidAttestation, ErrEpochMismatch)
	}
	if pred.ModelDigest != model.ModelDigest {
		return finish(VerdictInvalidAttestation, ErrModelDigestMismatch)
	}
	expectedInputDigest := ComputeInputDigest(c.InputTokens, c.DecodeSteps)
	if pred.InputDigest != expectedInputDigest || pred.DecodeSteps != c.DecodeSteps {
		return finish(VerdictInvalidAttestation, ErrInputDigestMismatch)
	}
	if prevOut, seen := c.SeenJobOutputs[pred.JobID]; seen && prevOut != pred.OutputDigest {
		return finish(VerdictInvalidAttestation, ErrEquivocationDetected)
	}

	// Step 6: Verify Sigstore Cosign / Rekor-style transparency log inclusion proof + signed checkpoint.
	expectedLeafDigest := ComputeTLogLeafEntryDigest(pred.JobID, payloadBytes, sigBytes, pred.Epoch)
	if tlogErr := VerifyTransparencyLogBundle(c.TLogBundle, expectedLeafDigest, c.ExpectedEpoch, trust); tlogErr != ErrNone {
		return finish(VerdictInvalidAttestation, tlogErr)
	}
	res.TLogRoot = c.TLogBundle.RootHash

	// Step 7: Regime-specific execution verification.
	switch c.Regime {
	case RegimeSignedAttestationOnly:
		// Signed in-toto DSSE + Rekor-style tlog ONLY: zero re-execution.
		// Valid-key lazy/corrupted inference escapes here by construction!
		return finish(VerdictVerified, ErrNone)

	case RegimeIndependentReexec:
		return verifyIndependentReexec(c, pred, workerKey, model, trust, policy, &res, finish)

	case RegimeRandomChallenge, RegimeHybridAttestedChal:
		return verifyChallengedRegime(c, pred, workerKey, model, trust, policy, &res, finish)

	default:
		return finish(VerdictInvalidAttestation, ErrRegimeMismatch)
	}
}

func decodePayloadOnly(env DSSEEnvelope) ([]byte, []byte, string) {
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, nil, ErrInvalidEnvelope
	}
	return raw, nil, ErrNone
}

func verifyIndependentReexec(
	c VerificationCase,
	pred InferencePredicate,
	workerKey KeyEntry,
	model *QuantizedMLP,
	trust TrustRoot,
	policy VerificationPolicy,
	res *CaseResult,
	finish func(string, string) CaseResult,
) CaseResult {
	requiredIndependent := policy.ReexecQuorumK - 1
	if requiredIndependent < 1 {
		requiredIndependent = 1
	}
	if len(c.ReexecReceipts) < requiredIndependent {
		return finish(VerdictInvalidAttestation, ErrQuorumNotMet)
	}

	// Deterministic ground-truth re-execution by auditing verifier.
	expectedOut := model.ForwardHonest(pred.JobID, c.InputTokens, c.DecodeSteps)
	res.ReexecCount = len(c.ReexecReceipts)

	seenGroups := map[string]bool{workerKey.OperatorGroup: true}
	seenVerifiers := map[string]bool{workerKey.ActorID: true}
	validReceipts := 0
	agreeWithExpected := 0

	for _, r := range c.ReexecReceipts {
		vKey, ok := lookupKey(trust, r.VerifierID)
		if !ok {
			return finish(VerdictInvalidAttestation, ErrKeyUnregistered)
		}
		if keyErr := validateKeyAtEpoch(vKey, c.ExpectedEpoch); keyErr != ErrNone {
			return finish(VerdictInvalidAttestation, keyErr)
		}
		if seenVerifiers[vKey.ActorID] || seenGroups[vKey.OperatorGroup] {
			return finish(VerdictInvalidAttestation, ErrColludingOperatorGroup)
		}
		vPayload, _, sigErr := VerifyDSSESignature(r.Envelope, vKey.PubKeyHex)
		if sigErr != ErrNone {
			return finish(VerdictInvalidAttestation, ErrInvalidReexecSig)
		}
		var rStmt ReexecStatement
		if err := json.Unmarshal(vPayload, &rStmt); err != nil {
			return finish(VerdictInvalidAttestation, ErrInvalidReexecSig)
		}
		if rStmt.Type != InTotoStatementTypeV1 || rStmt.PredicateType != ReexecPredicateType {
			return finish(VerdictInvalidAttestation, ErrInvalidReexecSig)
		}
		rp := rStmt.Predicate
		if rp.ActorRole == RoleAIAgent {
			return finish(VerdictPolicyRejected, ErrAISelfCertForbidden)
		}
		if rp.VerifierID != r.VerifierID || rp.VerifierPubKeyHex != vKey.PubKeyHex || rp.VerifierOperatorGroup != vKey.OperatorGroup {
			return finish(VerdictInvalidAttestation, ErrInvalidReexecSig)
		}
		if rp.JobID != pred.JobID || rp.Epoch != pred.Epoch || rp.ModelDigest != pred.ModelDigest || rp.InputDigest != pred.InputDigest {
			return finish(VerdictInvalidAttestation, ErrInvalidReexecSig)
		}
		if rp.ComputedOutputDigest == expectedOut.OutputDigest &&
			rp.ComputedLogitsDigest == expectedOut.LogitsDigest &&
			rp.ComputedTopToken == expectedOut.TopToken {
			agreeWithExpected++
		}
		seenVerifiers[vKey.ActorID] = true
		seenGroups[vKey.OperatorGroup] = true
		validReceipts++
	}

	quorum := (policy.ReexecQuorumK + 1) / 2
	if validReceipts < requiredIndependent || agreeWithExpected < quorum-1 {
		return finish(VerdictInvalidAttestation, ErrQuorumNotMet)
	}

	if pred.OutputDigest != expectedOut.OutputDigest ||
		pred.LogitsDigest != expectedOut.LogitsDigest ||
		pred.TopToken != expectedOut.TopToken {
		return finish(VerdictFraudDetected, ErrOutputMismatchReexec)
	}
	return finish(VerdictVerified, ErrNone)
}

func verifyChallengedRegime(
	c VerificationCase,
	pred InferencePredicate,
	workerKey KeyEntry,
	model *QuantizedMLP,
	trust TrustRoot,
	policy VerificationPolicy,
	res *CaseResult,
	finish func(string, string) CaseResult,
) CaseResult {
	effBPS := EffectiveChallengeBPS(c.Regime, c.WorkerRisk, policy, c.ChallengeRateBPSOverride)
	drawBPS := ComputeChallengeDrawBPS(c.EpochBeaconHex, pred.JobID, pred.OutputDigest)
	challenged := drawBPS < effBPS
	res.Challenged = challenged

	if !challenged {
		// Job was not selected by the post-commit beacon; attestation + tlog stand.
		return finish(VerdictVerified, ErrNone)
	}

	// Job WAS selected for challenge: a valid signed DSSE ChallengeTranscript
	// from an independent challenger (distinct operator group) is REQUIRED.
	if c.ChallengeTranscript == nil {
		return finish(VerdictInvalidAttestation, ErrMissingRequiredChallenge)
	}
	ct := c.ChallengeTranscript
	cKey, ok := lookupKey(trust, ct.ChallengerID)
	if !ok {
		return finish(VerdictInvalidAttestation, ErrKeyUnregistered)
	}
	if keyErr := validateKeyAtEpoch(cKey, c.ExpectedEpoch); keyErr != ErrNone {
		return finish(VerdictInvalidAttestation, keyErr)
	}
	if cKey.ActorID == workerKey.ActorID || cKey.OperatorGroup == workerKey.OperatorGroup {
		return finish(VerdictInvalidAttestation, ErrColludingOperatorGroup)
	}
	cPayload, _, sigErr := VerifyDSSESignature(ct.Envelope, cKey.PubKeyHex)
	if sigErr != ErrNone {
		return finish(VerdictInvalidAttestation, ErrInvalidChallengeSig)
	}
	var cStmt ChallengeStatement
	if err := json.Unmarshal(cPayload, &cStmt); err != nil {
		return finish(VerdictInvalidAttestation, ErrChallengeTranscriptInvalid)
	}
	if cStmt.Type != InTotoStatementTypeV1 || cStmt.PredicateType != ChallengePredicateType {
		return finish(VerdictInvalidAttestation, ErrChallengeTranscriptInvalid)
	}
	cp := cStmt.Predicate
	if cp.ActorRole == RoleAIAgent {
		return finish(VerdictPolicyRejected, ErrAISelfCertForbidden)
	}
	if cp.ChallengerID != ct.ChallengerID ||
		cp.ChallengerPubKeyHex != cKey.PubKeyHex ||
		cp.ChallengerOperatorGroup != cKey.OperatorGroup {
		return finish(VerdictInvalidAttestation, ErrChallengeTranscriptInvalid)
	}
	if cp.JobID != pred.JobID ||
		cp.Epoch != pred.Epoch ||
		cp.EpochBeaconHex != c.EpochBeaconHex ||
		cp.EffectiveChallengeBPS != effBPS ||
		cp.ChallengeDrawBPS != drawBPS ||
		cp.ModelDigest != pred.ModelDigest ||
		cp.InputDigest != pred.InputDigest ||
		cp.WorkerOutputDigest != pred.OutputDigest {
		return finish(VerdictInvalidAttestation, ErrChallengeTranscriptInvalid)
	}

	// Auditor independently re-executes the challenged job to verify fraud proof!
	res.ReexecCount = 1
	expectedOut := model.ForwardHonest(pred.JobID, c.InputTokens, c.DecodeSteps)
	if cp.RecomputedOutputDigest != expectedOut.OutputDigest ||
		cp.RecomputedLogitsDigest != expectedOut.LogitsDigest ||
		cp.RecomputedTopToken != expectedOut.TopToken {
		return finish(VerdictInvalidAttestation, ErrChallengeTranscriptInvalid)
	}

	workerMismatch := pred.OutputDigest != expectedOut.OutputDigest ||
		pred.LogitsDigest != expectedOut.LogitsDigest ||
		pred.TopToken != expectedOut.TopToken

	if cp.FraudProven != workerMismatch {
		return finish(VerdictInvalidAttestation, ErrChallengeTranscriptInvalid)
	}
	if workerMismatch {
		return finish(VerdictFraudDetected, ErrChallengeFraudProven)
	}
	return finish(VerdictVerified, ErrNone)
}

// AuditSuite verifies every case in a VerificationSuite and computes the
// deterministic RFC 6962 audit_merkle_root over all case results.
func AuditSuite(suite VerificationSuite) SuiteAuditResult {
	model := NewQuantizedMLP(suite.CorpusRootSHA256, suite.ModelID)
	results := make([]CaseResult, len(suite.Cases))
	leaves := make([][]byte, len(suite.Cases))

	golden := 0
	adv := 0
	matched := 0

	for i, c := range suite.Cases {
		r := VerifyCase(c, model, suite.TrustRoot, suite.Policy)
		results[i] = r
		leaves[i] = []byte(r.AuditLeafDigest)
		if c.Category == "golden" {
			golden++
		} else {
			adv++
		}
		if r.Verdict == c.ExpectedVerdict &&
			r.ErrorCode == c.ExpectedErrorCode &&
			r.FraudEscaped == c.ExpectedFraudEscaped {
			matched++
		}
	}

	root := ComputeMerkleRootRFC6962(leaves)
	return SuiteAuditResult{
		TotalCases:      len(suite.Cases),
		GoldenCases:     golden,
		AdversarialCase: adv,
		MatchesExpected: matched,
		AuditMerkleRoot: hex.EncodeToString(root[:]),
		Results:         results,
	}
}

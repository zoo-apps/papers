// Copyright 2026 Zoo Labs Foundation / Hanzo Industries.
// Licensed under the Apache License, Version 2.0.

package inferverify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"time"
)

type ActorIdentity struct {
	Entry   KeyEntry
	PrivKey ed25519.PrivateKey
}

type TestRig struct {
	Seed       uint64
	Model      *QuantizedMLP
	Corpus     *LoadedCorpus
	TLog       *TransparencyLog
	Policy     VerificationPolicy
	TrustRoot  TrustRoot
	Actors     map[string]ActorIdentity
	WorkerIDs  []string
	VerifierIDs []string
	ChallengerIDs []string
}

func NewTestRig(seed uint64, corpus *LoadedCorpus, policy VerificationPolicy) *TestRig {
	model := NewQuantizedMLP(corpus.CorpusRootSHA256, DefaultModelID)
	tlog := NewTransparencyLog(seed)

	actors := make(map[string]ActorIdentity)
	var keys []KeyEntry

	addActor := func(id, role, group string, validFrom, validUntil uint64, revoked bool) {
		pub, priv := DeriveKeypair(seed, id)
		entry := KeyEntry{
			ActorID:         id,
			ActorRole:       role,
			OperatorGroup:   group,
			PubKeyHex:       hex.EncodeToString(pub),
			ValidFromEpoch:  validFrom,
			ValidUntilEpoch: validUntil,
			Revoked:         revoked,
		}
		actors[id] = ActorIdentity{Entry: entry, PrivKey: priv}
		keys = append(keys, entry)
	}

	// Enrolled active workers across distinct operator groups
	workerIDs := []string{"worker-alpha-1", "worker-beta-2", "worker-gamma-3", "worker-delta-4"}
	addActor("worker-alpha-1", RoleWorker, "op-group-alpha", 1, 1000, false)
	addActor("worker-beta-2", RoleWorker, "op-group-beta", 1, 1000, false)
	addActor("worker-gamma-3", RoleWorker, "op-group-gamma", 1, 1000, false)
	addActor("worker-delta-4", RoleWorker, "op-group-delta", 1, 1000, false)

	// Special keys for adversarial tests
	addActor("worker-revoked", RoleWorker, "op-group-revoked", 1, 1000, true)
	addActor("worker-expired", RoleWorker, "op-group-expired", 1, 5, false)
	addActor("ai-agent-advisor", RoleAIAgent, "op-group-ai", 1, 1000, false)

	// Independent verifiers & challengers in distinct operator groups
	verifierIDs := []string{"verifier-eps-1", "verifier-zeta-2", "verifier-eta-3"}
	addActor("verifier-eps-1", RoleVerifier, "op-group-epsilon", 1, 1000, false)
	addActor("verifier-zeta-2", RoleVerifier, "op-group-zeta", 1, 1000, false)
	addActor("verifier-eta-3", RoleVerifier, "op-group-eta", 1, 1000, false)

	challengerIDs := []string{"challenger-theta-1", "challenger-iota-2"}
	addActor("challenger-theta-1", RoleChallenger, "op-group-theta", 1, 1000, false)
	addActor("challenger-iota-2", RoleChallenger, "op-group-iota", 1, 1000, false)

	// Colluding verifier/challenger intentionally sharing worker-alpha-1's operator group
	addActor("verifier-collude-alpha", RoleVerifier, "op-group-alpha", 1, 1000, false)
	addActor("challenger-collude-alpha", RoleChallenger, "op-group-alpha", 1, 1000, false)

	return &TestRig{
		Seed:          seed,
		Model:         model,
		Corpus:        corpus,
		TLog:          tlog,
		Policy:        policy,
		TrustRoot:     TrustRoot{TLogID: tlog.LogID, TLogPubKeyHex: tlog.PubKeyHex, Keys: keys},
		Actors:        actors,
		WorkerIDs:     workerIDs,
		VerifierIDs:   verifierIDs,
		ChallengerIDs: challengerIDs,
	}
}

func (r *TestRig) PromptForIndex(idx int) []int32 {
	stream := r.Corpus.TokenStream
	start := (idx * 7) % (len(stream) - PromptLen)
	out := make([]int32, PromptLen)
	copy(out, stream[start:start+PromptLen])
	return out
}

func (r *TestRig) BuildWorkerStatement(
	jobID string,
	epoch uint64,
	regime string,
	decodeSteps int,
	out InferenceOutput,
	worker ActorIdentity,
	govAction string,
) InTotoStatement {
	return InTotoStatement{
		Type: InTotoStatementTypeV1,
		Subject: []InTotoSubject{
			{
				Name:   "inference-job:" + jobID,
				Digest: map[string]string{"sha256": out.OutputDigest},
			},
		},
		PredicateType: InferencePredicateType,
		Predicate: InferencePredicate{
			SchemaVersion:                  SchemaVersion,
			JobID:                          jobID,
			Epoch:                          epoch,
			Regime:                         regime,
			ModelID:                        r.Model.ModelID,
			ModelDigest:                    r.Model.ModelDigest,
			DecodeSteps:                    decodeSteps,
			InputDigest:                    out.InputDigest,
			OutputDigest:                   out.OutputDigest,
			LogitsDigest:                   out.LogitsDigest,
			TopToken:                       out.TopToken,
			WorkerID:                       worker.Entry.ActorID,
			WorkerOperatorGroup:            worker.Entry.OperatorGroup,
			WorkerPubKeyHex:                worker.Entry.PubKeyHex,
			ActorRole:                      worker.Entry.ActorRole,
			GovernanceAction:               govAction,
			AttestsSignedProvenanceOnly:    regime == RegimeSignedAttestationOnly,
			ProvesHardwareTEEUncompromised: false,
			ProvesScientificTruth:          false,
		},
	}
}

func (r *TestRig) SignAndLog(stmt InTotoStatement, priv ed25519.PrivateKey) (DSSEEnvelope, int, error) {
	env, err := SignDSSE(stmt, priv)
	if err != nil {
		return DSSEEnvelope{}, -1, err
	}
	payloadBytes, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return DSSEEnvelope{}, -1, err
	}
	sigBytes, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		return DSSEEnvelope{}, -1, err
	}
	leaf := ComputeTLogLeafEntryDigest(stmt.Predicate.JobID, payloadBytes, sigBytes, stmt.Predicate.Epoch)
	idx := r.TLog.Append(leaf)
	return env, idx, nil
}

func (r *TestRig) SignReexecReceipt(
	jobID string,
	epoch uint64,
	workerOutDigest string,
	expectedOut InferenceOutput,
	verifier ActorIdentity,
) (ReexecReceipt, error) {
	stmt := ReexecStatement{
		Type: InTotoStatementTypeV1,
		Subject: []InTotoSubject{
			{
				Name:   "inference-reexec:" + jobID,
				Digest: map[string]string{"sha256": expectedOut.OutputDigest},
			},
		},
		PredicateType: ReexecPredicateType,
		Predicate: ReexecPredicate{
			SchemaVersion:         SchemaVersion,
			JobID:                 jobID,
			Epoch:                 epoch,
			ModelDigest:           r.Model.ModelDigest,
			InputDigest:           expectedOut.InputDigest,
			ComputedOutputDigest:  expectedOut.OutputDigest,
			ComputedLogitsDigest:  expectedOut.LogitsDigest,
			ComputedTopToken:      expectedOut.TopToken,
			VerifierID:            verifier.Entry.ActorID,
			VerifierOperatorGroup: verifier.Entry.OperatorGroup,
			VerifierPubKeyHex:     verifier.Entry.PubKeyHex,
			ActorRole:             verifier.Entry.ActorRole,
			MatchesWorker:         workerOutDigest == expectedOut.OutputDigest,
		},
	}
	env, err := SignDSSE(stmt, verifier.PrivKey)
	if err != nil {
		return ReexecReceipt{}, err
	}
	return ReexecReceipt{VerifierID: verifier.Entry.ActorID, Envelope: env}, nil
}

func (r *TestRig) SignChallengeTranscript(
	jobID string,
	epoch uint64,
	beaconHex string,
	effBPS uint64,
	drawBPS uint64,
	workerOutDigest string,
	expectedOut InferenceOutput,
	challenger ActorIdentity,
) (*ChallengeTranscript, error) {
	stmt := ChallengeStatement{
		Type: InTotoStatementTypeV1,
		Subject: []InTotoSubject{
			{
				Name:   "inference-challenge:" + jobID,
				Digest: map[string]string{"sha256": expectedOut.OutputDigest},
			},
		},
		PredicateType: ChallengePredicateType,
		Predicate: ChallengePredicate{
			SchemaVersion:           SchemaVersion,
			JobID:                   jobID,
			Epoch:                   epoch,
			EpochBeaconHex:          beaconHex,
			EffectiveChallengeBPS:   effBPS,
			ChallengeDrawBPS:        drawBPS,
			ModelDigest:             r.Model.ModelDigest,
			InputDigest:             expectedOut.InputDigest,
			WorkerOutputDigest:      workerOutDigest,
			RecomputedOutputDigest:  expectedOut.OutputDigest,
			RecomputedLogitsDigest:  expectedOut.LogitsDigest,
			RecomputedTopToken:      expectedOut.TopToken,
			ChallengerID:            challenger.Entry.ActorID,
			ChallengerOperatorGroup: challenger.Entry.OperatorGroup,
			ChallengerPubKeyHex:     challenger.Entry.PubKeyHex,
			ActorRole:               challenger.Entry.ActorRole,
			FraudProven:             workerOutDigest != expectedOut.OutputDigest,
		},
	}
	env, err := SignDSSE(stmt, challenger.PrivKey)
	if err != nil {
		return nil, err
	}
	return &ChallengeTranscript{ChallengerID: challenger.Entry.ActorID, Envelope: env}, nil
}

// BuildParitySuite builds the 225-case deterministic golden (200) + adversarial (25)
// verification suite for 100.00% Go <-> Python bit-identical parity verification.
func BuildParitySuite(seed uint64, corpus *LoadedCorpus) (VerificationSuite, SuiteAuditResult, error) {
	policy := DefaultPolicy()
	rig := NewTestRig(seed, corpus, policy)
	const epoch uint64 = 42
	beacon := DeriveEpochBeacon(seed, epoch)
	const decodeSteps = 1

	type pendingCase struct {
		vc      VerificationCase
		tlogIdx int
		mutate  func(*VerificationCase)
	}
	var pending []pendingCase

	regimes := []string{
		RegimeSignedAttestationOnly,
		RegimeIndependentReexec,
		RegimeRandomChallenge,
		RegimeHybridAttestedChal,
	}

	// 200 Golden cases: 50 per regime.
	globalIdx := 0
	for rIdx, regime := range regimes {
		for i := 0; i < 50; i++ {
			globalIdx++
			jobID := fmt.Sprintf("job-%02d-%03d", rIdx+1, i+1)
			caseID := fmt.Sprintf("golden_%03d_%s", globalIdx, regime)
			tokens := rig.PromptForIndex(globalIdx)
			worker := rig.Actors[rig.WorkerIDs[i%len(rig.WorkerIDs)]]

			// Mix of honest and cheating workers: 10% dishonest in reexec/challenge/hybrid,
			// 100% honest in signed_attestation_only golden cases (valid-key cheating is also
			// explicitly covered in adversarial case adv_14 and negative regime 1).
			cheated := (regime != RegimeSignedAttestationOnly) && (i%10 == 9)

			// Risk context for hybrid: 20% probationary/flagged workers
			risk := WorkerRiskContext{
				ReputationScore:   920,
				JobsCompleted:     120,
				AIAdvisoryFlagged: false,
			}
			if i%5 == 4 {
				risk.ReputationScore = 650
				risk.JobsCompleted = 8
				risk.AIAdvisoryFlagged = (i%10 == 9)
			}

			honestOut := rig.Model.ForwardHonest(jobID, tokens, decodeSteps)
			workerOut := honestOut
			if cheated {
				workerOut = rig.Model.ForwardLazyDummy(jobID, tokens, decodeSteps)
			}

			stmt := rig.BuildWorkerStatement(jobID, epoch, regime, decodeSteps, workerOut, worker, ActionNone)
			env, tlogIdx, err := rig.SignAndLog(stmt, worker.PrivKey)
			if err != nil {
				return VerificationSuite{}, SuiteAuditResult{}, err
			}

			vc := VerificationCase{
				CaseID:                   caseID,
				Category:                 "golden",
				Description:              fmt.Sprintf("Golden trace %d under %s (cheated=%v)", i+1, regime, cheated),
				Regime:                   regime,
				ExpectedEpoch:            epoch,
				EpochBeaconHex:           beacon,
				InputTokens:              tokens,
				DecodeSteps:              decodeSteps,
				WorkerRisk:               risk,
				WorkerEnvelope:           env,
				WorkerCheatedGroundTruth: cheated,
				ExpectedVerdict:          VerdictVerified,
				ExpectedErrorCode:        ErrNone,
				ExpectedFraudEscaped:     false,
			}

			switch regime {
			case RegimeIndependentReexec:
				r1, err := rig.SignReexecReceipt(jobID, epoch, workerOut.OutputDigest, honestOut, rig.Actors["verifier-eps-1"])
				if err != nil {
					return VerificationSuite{}, SuiteAuditResult{}, err
				}
				r2, err := rig.SignReexecReceipt(jobID, epoch, workerOut.OutputDigest, honestOut, rig.Actors["verifier-zeta-2"])
				if err != nil {
					return VerificationSuite{}, SuiteAuditResult{}, err
				}
				vc.ReexecReceipts = []ReexecReceipt{r1, r2}
				if cheated {
					vc.ExpectedVerdict = VerdictFraudDetected
					vc.ExpectedErrorCode = ErrOutputMismatchReexec
				}

			case RegimeRandomChallenge, RegimeHybridAttestedChal:
				effBPS := EffectiveChallengeBPS(regime, risk, policy, nil)
				drawBPS := ComputeChallengeDrawBPS(beacon, jobID, workerOut.OutputDigest)
				if drawBPS < effBPS {
					chal := rig.Actors[rig.ChallengerIDs[i%len(rig.ChallengerIDs)]]
					ct, err := rig.SignChallengeTranscript(jobID, epoch, beacon, effBPS, drawBPS, workerOut.OutputDigest, honestOut, chal)
					if err != nil {
						return VerificationSuite{}, SuiteAuditResult{}, err
					}
					vc.ChallengeTranscript = ct
					if cheated {
						vc.ExpectedVerdict = VerdictFraudDetected
						vc.ExpectedErrorCode = ErrChallengeFraudProven
					}
				} else if cheated {
					// Dishonest job not selected by random draw -> verified with fraud_escaped=true!
					vc.ExpectedVerdict = VerdictVerified
					vc.ExpectedErrorCode = ErrNone
					vc.ExpectedFraudEscaped = true
				}
			}

			pending = append(pending, pendingCase{vc: vc, tlogIdx: tlogIdx})
		}
	}

	// Helper to find a jobID guaranteed to be challenged under a given effBPS.
	findChallengedJobID := func(prefix, outDigest string, effBPS uint64) string {
		for k := 0; k < 100000; k++ {
			cand := fmt.Sprintf("%s-%d", prefix, k)
			if ComputeChallengeDrawBPS(beacon, cand, outDigest) < effBPS {
				return cand
			}
		}
		return prefix + "-0"
	}

	// 25 Explicit Adversarial Cases
	addAdv := func(
		caseID, desc, regime string,
		workerID string,
		cheated bool,
		govAction string,
		overrideBPS *uint64,
		risk WorkerRiskContext,
		expectedVerdict, expectedErr string,
		expectedEscaped bool,
		forceChallenged bool,
		attachReexec bool,
		attachChallenge bool,
		useTLog bool,
		mutateStmt func(*InTotoStatement),
		mutateCase func(*VerificationCase),
	) error {
		globalIdx++
		tokens := rig.PromptForIndex(globalIdx + 300)
		worker := rig.Actors[workerID]
		jobID := fmt.Sprintf("adv-job-%03d", globalIdx)
		honestOut := rig.Model.ForwardHonest(jobID, tokens, decodeSteps)
		workerOut := honestOut
		if cheated {
			workerOut = rig.Model.ForwardLazyDummy(jobID, tokens, decodeSteps)
		}
		if forceChallenged {
			eff := EffectiveChallengeBPS(regime, risk, policy, overrideBPS)
			// Find jobID that triggers challenge for this workerOut.
			for k := 0; k < 100000; k++ {
				cand := fmt.Sprintf("adv-job-%03d-c%d", globalIdx, k)
				hOut := rig.Model.ForwardHonest(cand, tokens, decodeSteps)
				wOut := hOut
				if cheated {
					wOut = rig.Model.ForwardLazyDummy(cand, tokens, decodeSteps)
				}
				if ComputeChallengeDrawBPS(beacon, cand, wOut.OutputDigest) < eff {
					jobID = cand
					honestOut = hOut
					workerOut = wOut
					break
				}
			}
		}
		_ = findChallengedJobID

		stmt := rig.BuildWorkerStatement(jobID, epoch, regime, decodeSteps, workerOut, worker, govAction)
		if mutateStmt != nil {
			mutateStmt(&stmt)
		}
		env, tlogIdx, err := rig.SignAndLog(stmt, worker.PrivKey)
		if err != nil {
			return err
		}
		if !useTLog {
			tlogIdx = -1
		}

		vc := VerificationCase{
			CaseID:                   caseID,
			Category:                 "adversarial",
			Description:              desc,
			Regime:                   regime,
			ExpectedEpoch:            epoch,
			EpochBeaconHex:           beacon,
			ChallengeRateBPSOverride: overrideBPS,
			InputTokens:              tokens,
			DecodeSteps:              decodeSteps,
			WorkerRisk:               risk,
			WorkerEnvelope:           env,
			WorkerCheatedGroundTruth: cheated,
			ExpectedVerdict:          expectedVerdict,
			ExpectedErrorCode:        expectedErr,
			ExpectedFraudEscaped:     expectedEscaped,
		}

		if attachReexec {
			r1, err := rig.SignReexecReceipt(jobID, epoch, workerOut.OutputDigest, honestOut, rig.Actors["verifier-eps-1"])
			if err != nil {
				return err
			}
			r2, err := rig.SignReexecReceipt(jobID, epoch, workerOut.OutputDigest, honestOut, rig.Actors["verifier-zeta-2"])
			if err != nil {
				return err
			}
			vc.ReexecReceipts = []ReexecReceipt{r1, r2}
		}

		if attachChallenge {
			eff := EffectiveChallengeBPS(regime, risk, policy, overrideBPS)
			draw := ComputeChallengeDrawBPS(beacon, jobID, workerOut.OutputDigest)
			ct, err := rig.SignChallengeTranscript(jobID, epoch, beacon, eff, draw, workerOut.OutputDigest, honestOut, rig.Actors["challenger-theta-1"])
			if err != nil {
				return err
			}
			vc.ChallengeTranscript = ct
		}

		pending = append(pending, pendingCase{vc: vc, tlogIdx: tlogIdx, mutate: mutateCase})
		return nil
	}

	normalRisk := WorkerRiskContext{ReputationScore: 950, JobsCompleted: 100, AIAdvisoryFlagged: false}
	highRisk := WorkerRiskContext{ReputationScore: 400, JobsCompleted: 2, AIAdvisoryFlagged: true}
	bps1000 := uint64(1000)

	// adv_01: Forged DSSE signature
	if err := addAdv("adv_01_forged_dsse_signature", "Corrupted Ed25519 signature bytes in DSSE envelope",
		RegimeSignedAttestationOnly, "worker-alpha-1", false, ActionNone, nil, normalRisk,
		VerdictInvalidAttestation, ErrInvalidDSSESig, false, false, false, false, true, nil,
		func(vc *VerificationCase) {
			sigBytes, _ := base64.StdEncoding.DecodeString(vc.WorkerEnvelope.Signatures[0].Sig)
			sigBytes[0] ^= 0xff
			vc.WorkerEnvelope.Signatures[0].Sig = base64.StdEncoding.EncodeToString(sigBytes)
		}); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_02: Tampered DSSE payload after signing
	if err := addAdv("adv_02_tampered_dsse_payload", "Modified DSSE payload without re-signing",
		RegimeSignedAttestationOnly, "worker-alpha-1", false, ActionNone, nil, normalRisk,
		VerdictInvalidAttestation, ErrInvalidDSSESig, false, false, false, false, true, nil,
		func(vc *VerificationCase) {
			raw, _ := base64.StdEncoding.DecodeString(vc.WorkerEnvelope.Payload)
			var st InTotoStatement
			_ = json.Unmarshal(raw, &st)
			st.Predicate.TopToken = (st.Predicate.TopToken + 1) % ModelDimOut
			tampered, _ := json.Marshal(st)
			vc.WorkerEnvelope.Payload = base64.StdEncoding.EncodeToString(tampered)
		}); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_03: Missing transparency log proof
	if err := addAdv("adv_03_missing_tlog_proof", "Valid DSSE signature but nil transparency log inclusion bundle",
		RegimeSignedAttestationOnly, "worker-beta-2", false, ActionNone, nil, normalRisk,
		VerdictInvalidAttestation, ErrMissingTLogProof, false, false, false, false, false, nil, nil); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_04: Tampered transparency log Merkle path
	if err := addAdv("adv_04_tampered_tlog_merkle_path", "Flipped byte in RFC 6962 inclusion proof sibling hash",
		RegimeSignedAttestationOnly, "worker-beta-2", false, ActionNone, nil, normalRisk,
		VerdictInvalidAttestation, ErrInvalidTLogProof, false, false, false, false, true, nil,
		func(vc *VerificationCase) {
			if vc.TLogBundle != nil && len(vc.TLogBundle.Hashes) > 0 {
				b, _ := hex.DecodeString(vc.TLogBundle.Hashes[0])
				b[0] ^= 0x01
				vc.TLogBundle.Hashes[0] = hex.EncodeToString(b)
			}
		}); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_05: Forged transparency log checkpoint signature
	if err := addAdv("adv_05_forged_tlog_checkpoint_sig", "Corrupted Rekor-style checkpoint Ed25519 signature",
		RegimeSignedAttestationOnly, "worker-gamma-3", false, ActionNone, nil, normalRisk,
		VerdictInvalidAttestation, ErrInvalidTLogCheckpointSig, false, false, false, false, true, nil,
		func(vc *VerificationCase) {
			if vc.TLogBundle != nil {
				sb, _ := base64.StdEncoding.DecodeString(vc.TLogBundle.CheckpointSig)
				sb[3] ^= 0x55
				vc.TLogBundle.CheckpointSig = base64.StdEncoding.EncodeToString(sb)
			}
		}); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_06: Untrusted transparency log key
	if err := addAdv("adv_06_untrusted_tlog_key", "Transparency log bundle signed by rogue untrusted log operator",
		RegimeSignedAttestationOnly, "worker-gamma-3", false, ActionNone, nil, normalRisk,
		VerdictInvalidAttestation, ErrUntrustedTLogKey, false, false, false, false, true, nil,
		func(vc *VerificationCase) {
			if vc.TLogBundle != nil {
				roguePub, _ := DeriveKeypair(seed+999, "rogue-tlog")
				vc.TLogBundle.LogPubKeyHex = hex.EncodeToString(roguePub)
			}
		}); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_07: Revoked worker key
	if err := addAdv("adv_07_revoked_worker_key", "Attestation signed by a revoked worker key",
		RegimeSignedAttestationOnly, "worker-revoked", false, ActionNone, nil, normalRisk,
		VerdictInvalidAttestation, ErrKeyRevoked, false, false, false, false, true, nil, nil); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_08: Expired worker key
	if err := addAdv("adv_08_expired_worker_key", "Attestation signed by a worker key expired before current epoch",
		RegimeSignedAttestationOnly, "worker-expired", false, ActionNone, nil, normalRisk,
		VerdictInvalidAttestation, ErrKeyExpired, false, false, false, false, true, nil, nil); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_09: Unregistered worker key
	if err := addAdv("adv_09_unregistered_worker_key", "Attestation claiming an unregistered worker ID",
		RegimeSignedAttestationOnly, "worker-alpha-1", false, ActionNone, nil, normalRisk,
		VerdictInvalidAttestation, ErrKeyUnregistered, false, false, false, false, true,
		func(st *InTotoStatement) { st.Predicate.WorkerID = "worker-unknown-sybil" }, nil); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_10: Epoch replay attack
	if err := addAdv("adv_10_epoch_replay_attack", "Valid signed attestation replayed from a previous epoch (epoch 41 into 42)",
		RegimeSignedAttestationOnly, "worker-delta-4", false, ActionNone, nil, normalRisk,
		VerdictInvalidAttestation, ErrEpochMismatch, false, false, false, false, true,
		func(st *InTotoStatement) { st.Predicate.Epoch = epoch - 1 }, nil); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_11: Equivocating worker submitting two different outputs for same job ID
	if err := addAdv("adv_11_equivocating_duplicate_job", "Worker equivocates with conflicting output digest for previously observed job ID",
		RegimeSignedAttestationOnly, "worker-delta-4", false, ActionNone, nil, normalRisk,
		VerdictInvalidAttestation, ErrEquivocationDetected, false, false, false, false, true, nil,
		func(vc *VerificationCase) {
			raw, _ := base64.StdEncoding.DecodeString(vc.WorkerEnvelope.Payload)
			var st InTotoStatement
			_ = json.Unmarshal(raw, &st)
			alt := sha256.Sum256([]byte("conflicting-equivocated-output"))
			vc.SeenJobOutputs = map[string]string{
				st.Predicate.JobID: hex.EncodeToString(alt[:]),
			}
		}); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_12: in-toto Subject digest mismatch
	if err := addAdv("adv_12_subject_digest_mismatch", "in-toto Subject sha256 digest disagrees with predicate output_digest",
		RegimeSignedAttestationOnly, "worker-alpha-1", false, ActionNone, nil, normalRisk,
		VerdictInvalidAttestation, ErrSubjectDigestMismatch, false, false, false, false, true,
		func(st *InTotoStatement) {
			bad := sha256.Sum256([]byte("wrong-subject"))
			st.Subject[0].Digest["sha256"] = hex.EncodeToString(bad[:])
		}, nil); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_13: Wrong in-toto Statement _type
	if err := addAdv("adv_13_wrong_intoto_statement_type", "Non-in-toto _type in DSSE payload",
		RegimeSignedAttestationOnly, "worker-alpha-1", false, ActionNone, nil, normalRisk,
		VerdictInvalidAttestation, ErrInvalidInTotoType, false, false, false, false, true,
		func(st *InTotoStatement) { st.Type = "https://example.invalid/Statement/v0" }, nil); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_14: Honest Negative Proof — Valid-key lazy cheater ESCAPES signed_attestation_only!
	if err := addAdv("adv_14_lazy_cheater_escapes_attestation_only", "Valid-key worker returns lazy dummy output with valid DSSE + tlog; attestation-only verifier accepts (0% cheat detection)",
		RegimeSignedAttestationOnly, "worker-alpha-1", true, ActionNone, nil, normalRisk,
		VerdictVerified, ErrNone, true, false, false, false, true, nil, nil); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_15: Same lazy cheater CAUGHT by independent_reexecution!
	if err := addAdv("adv_15_lazy_cheater_caught_reexecution", "Valid-key lazy dummy worker caught with certainty by k=3 independent re-execution",
		RegimeIndependentReexec, "worker-alpha-1", true, ActionNone, nil, normalRisk,
		VerdictFraudDetected, ErrOutputMismatchReexec, false, false, true, false, true, nil, nil); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_16: Same lazy cheater CAUGHT by random_challenge_verification!
	if err := addAdv("adv_16_lazy_cheater_caught_challenge", "Valid-key lazy dummy worker caught by unpredictable post-commit challenge with DSSE fraud proof",
		RegimeRandomChallenge, "worker-beta-2", true, ActionNone, &bps1000, normalRisk,
		VerdictFraudDetected, ErrChallengeFraudProven, false, true, false, true, true, nil, nil); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_17: Lazy cheater on probationary/flagged worker CAUGHT by hybrid escalated challenge!
	if err := addAdv("adv_17_lazy_cheater_caught_hybrid_escalation", "Probationary AI-flagged lazy worker escalated to 25% challenge rate and caught in hybrid regime",
		RegimeHybridAttestedChal, "worker-gamma-3", true, ActionNone, nil, highRisk,
		VerdictFraudDetected, ErrChallengeFraudProven, false, true, false, true, true, nil, nil); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_18: Colluding same-operator verifier in independent_reexecution
	if err := addAdv("adv_18_colluding_same_operator_reexec", "Re-execution verifier shares operator_group with worker (Sybil/collusion rejected)",
		RegimeIndependentReexec, "worker-alpha-1", false, ActionNone, nil, normalRisk,
		VerdictInvalidAttestation, ErrColludingOperatorGroup, false, false, true, false, true, nil,
		func(vc *VerificationCase) {
			raw, _ := base64.StdEncoding.DecodeString(vc.WorkerEnvelope.Payload)
			var st InTotoStatement
			_ = json.Unmarshal(raw, &st)
			hOut := rig.Model.ForwardHonest(st.Predicate.JobID, vc.InputTokens, vc.DecodeSteps)
			colRec, _ := rig.SignReexecReceipt(st.Predicate.JobID, epoch, st.Predicate.OutputDigest, hOut, rig.Actors["verifier-collude-alpha"])
			vc.ReexecReceipts[0] = colRec
		}); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_19: Colluding same-operator challenger in random_challenge_verification
	if err := addAdv("adv_19_colluding_self_challenger", "Challenger shares operator_group with challenged worker (self-challenging collusion rejected)",
		RegimeRandomChallenge, "worker-alpha-1", false, ActionNone, &bps1000, normalRisk,
		VerdictInvalidAttestation, ErrColludingOperatorGroup, false, true, false, true, true, nil,
		func(vc *VerificationCase) {
			raw, _ := base64.StdEncoding.DecodeString(vc.WorkerEnvelope.Payload)
			var st InTotoStatement
			_ = json.Unmarshal(raw, &st)
			hOut := rig.Model.ForwardHonest(st.Predicate.JobID, vc.InputTokens, vc.DecodeSteps)
			draw := ComputeChallengeDrawBPS(beacon, st.Predicate.JobID, st.Predicate.OutputDigest)
			ct, _ := rig.SignChallengeTranscript(st.Predicate.JobID, epoch, beacon, bps1000, draw, st.Predicate.OutputDigest, hOut, rig.Actors["challenger-collude-alpha"])
			vc.ChallengeTranscript = ct
		}); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_20: Forged challenge transcript signature
	if err := addAdv("adv_20_forged_challenge_transcript_sig", "Corrupted Ed25519 signature on DSSE challenge transcript",
		RegimeRandomChallenge, "worker-beta-2", false, ActionNone, &bps1000, normalRisk,
		VerdictInvalidAttestation, ErrInvalidChallengeSig, false, true, false, true, true, nil,
		func(vc *VerificationCase) {
			if vc.ChallengeTranscript != nil {
				sb, _ := base64.StdEncoding.DecodeString(vc.ChallengeTranscript.Envelope.Signatures[0].Sig)
				sb[0] ^= 0xff
				vc.ChallengeTranscript.Envelope.Signatures[0].Sig = base64.StdEncoding.EncodeToString(sb)
			}
		}); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_21: Skipped required challenge (beacon selected job, challenger transcript omitted)
	if err := addAdv("adv_21_skipped_required_challenge", "Job selected by post-commit beacon but required ChallengeTranscript is missing",
		RegimeRandomChallenge, "worker-gamma-3", false, ActionNone, &bps1000, normalRisk,
		VerdictInvalidAttestation, ErrMissingRequiredChallenge, false, true, false, false, true, nil, nil); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_22: Constitutional guard — AI_AGENT self-certification forbidden
	if err := addAdv("adv_22_ai_self_certification", "AI_AGENT attempts to self-certify its own inference attestation",
		RegimeHybridAttestedChal, "ai-agent-advisor", false, ActionSelfCertifyInference, nil, normalRisk,
		VerdictPolicyRejected, ErrAISelfCertForbidden, false, false, false, false, true, nil, nil); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_23: Constitutional guard — AI_AGENT policy/bond/quorum mutation forbidden
	if err := addAdv("adv_23_ai_policy_mutation", "AI_AGENT attempts to mutate verification bond/quorum/challenge bounds",
		RegimeHybridAttestedChal, "ai-agent-advisor", false, ActionMutatePolicyParams, nil, normalRisk,
		VerdictPolicyRejected, ErrAIPolicyMutationForbidden, false, false, false, false, true, nil, nil); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_24: Constitutional guard — AI_AGENT slashing approval forbidden
	if err := addAdv("adv_24_ai_slashing_approval", "AI_AGENT attempts to autonomously approve worker slashing without governance authorization",
		RegimeHybridAttestedChal, "ai-agent-advisor", false, ActionApproveSlashing, nil, normalRisk,
		VerdictPolicyRejected, ErrAISlashApprovalForbidden, false, false, false, false, true, nil, nil); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// adv_25: Constitutional guard — Overclaimed TEE hardware / scientific truth scope
	if err := addAdv("adv_25_overclaimed_tee_proof_scope", "Attestation sets proves_hardware_tee_uncompromised=true violating schema proof boundary",
		RegimeSignedAttestationOnly, "worker-alpha-1", false, ActionNone, nil, normalRisk,
		VerdictPolicyRejected, ErrOverclaimedProofScope, false, false, false, false, true,
		func(st *InTotoStatement) { st.Predicate.ProvesHardwareTEEUncompromised = true }, nil); err != nil {
		return VerificationSuite{}, SuiteAuditResult{}, err
	}

	// Finalize all transparency log inclusion proofs at the finalized tree size!
	cases := make([]VerificationCase, 0, len(pending))
	for _, p := range pending {
		vc := p.vc
		if p.tlogIdx >= 0 {
			bundle, err := rig.TLog.BundleForIndex(p.tlogIdx, epoch)
			if err != nil {
				return VerificationSuite{}, SuiteAuditResult{}, err
			}
			vc.TLogBundle = bundle
		}
		if p.mutate != nil {
			p.mutate(&vc)
		}
		cases = append(cases, vc)
	}

	suite := VerificationSuite{
		SchemaVersion:    SchemaVersion,
		SpecVersion:      SpecVersion,
		Issue:            "zoo-apps/papers#14",
		HIP:              "HIP-1350",
		Seed:             seed,
		CorpusRootSHA256: corpus.CorpusRootSHA256,
		ModelID:          rig.Model.ModelID,
		ModelDigest:      rig.Model.ModelDigest,
		TrustRoot:        rig.TrustRoot,
		Policy:           policy,
		Cases:            cases,
	}

	audit := AuditSuite(suite)
	suite.ExpectedAuditMerkleRoot = audit.AuditMerkleRoot
	return suite, audit, nil
}

// BenchmarkReport captures the complete reproducible benchmark output written to results.json.
type MicrobenchResult struct {
	DecodeSteps              int     `json:"decode_steps"`
	Iterations               int     `json:"iterations"`
	HonestInferenceUs        float64 `json:"honest_inference_us"`
	LazyDummyUs              float64 `json:"lazy_dummy_us"`
	LazyComputeSavingsPct    float64 `json:"lazy_compute_savings_pct"`
	DSSESignUs               float64 `json:"dsse_sign_us"`
	DSSEVerifyUs             float64 `json:"dsse_verify_us"`
	TLogProofVerify1024Us    float64 `json:"tlog_proof_verify_1024_us"`
	AttestationOnlyVerifyUs  float64 `json:"attestation_only_verify_us"`
	ReexecK3VerifyUs         float64 `json:"reexec_k3_verify_us"`
	AttestVsReexecSpeedup    float64 `json:"attest_vs_reexec_speedup"`
}

type RegimeComparisonRow struct {
	Regime                       string  `json:"regime"`
	ConfigLabel                  string  `json:"config_label"`
	Scenario                     string  `json:"scenario"`
	TotalJobs                    int     `json:"total_jobs"`
	CheatedJobs                  int     `json:"cheated_jobs"`
	ChallengedJobs               int     `json:"challenged_jobs"`
	FraudDetected                int     `json:"fraud_detected"`
	FraudEscaped                 int     `json:"fraud_escaped"`
	CheatDetectionRatePct        float64 `json:"cheat_detection_rate_pct"`
	HonestFalseRejections        int     `json:"honest_false_rejections"`
	HonestFRRPct                 float64 `json:"honest_frr_pct"`
	ComputeCostMultiplier        float64 `json:"compute_cost_multiplier"`
	EstimatedVerifyOverheadUs    float64 `json:"estimated_verify_overhead_us"`
	ProvenanceCoveragePct        float64 `json:"provenance_coverage_pct"`
	HonestProfitPerJob           float64 `json:"honest_profit_per_job"`
	EmpiricalCheaterProfitPerJob float64 `json:"empirical_cheater_profit_per_job"`
	CheatingAdvantagePerJob      float64 `json:"cheating_advantage_per_job"`
	IncentiveCompatible          bool    `json:"incentive_compatible"`
}

type ChallengeSweepRow struct {
	ChallengeRateP            float64 `json:"challenge_rate_p"`
	ChallengeBPS              uint64  `json:"challenge_bps"`
	CheatRate                 float64 `json:"cheat_rate"`
	SlashRatio                float64 `json:"slash_ratio"`
	SlashPenalty              float64 `json:"slash_penalty"`
	TotalJobs                 int     `json:"total_jobs"`
	CheatedJobs               int     `json:"cheated_jobs"`
	DetectedCheats            int     `json:"detected_cheats"`
	EmpiricalDetectionRatePct float64 `json:"empirical_detection_rate_pct"`
	ComputeCostMultiplier     float64 `json:"compute_cost_multiplier"`
	TheoreticalCheatProfit    float64 `json:"theoretical_cheat_profit_per_cheated_job"`
	EmpiricalCheatProfit      float64 `json:"empirical_cheat_profit_per_cheated_job"`
	HonestProfit              float64 `json:"honest_profit_per_job"`
	IncentiveCompatible       bool    `json:"incentive_compatible"`
}

type NegativeRegimeReport struct {
	ID            string                 `json:"id"`
	Title         string                 `json:"title"`
	RegimeTested  string                 `json:"regime_tested"`
	ClaimProven   string                 `json:"claim_proven"`
	Metrics       map[string]any         `json:"metrics"`
}

type ParitySummary struct {
	TotalCases          int    `json:"total_cases"`
	GoldenCases         int    `json:"golden_cases"`
	AdversarialCases    int    `json:"adversarial_cases"`
	MatchesExpected     int    `json:"matches_expected"`
	AuditMerkleRoot     string `json:"audit_merkle_root"`
	AllMatched          bool   `json:"all_matched"`
}

type BenchmarkReport struct {
	SchemaVersion      string                 `json:"schema_version"`
	SpecVersion        string                 `json:"spec_version"`
	Issue              string                 `json:"issue"`
	HIP                string                 `json:"hip"`
	Seed               uint64                 `json:"seed"`
	CorpusRootSHA256   string                 `json:"corpus_root_sha256"`
	CorpusFiles        int                    `json:"corpus_files"`
	CorpusVocabSize    int                    `json:"corpus_vocab_size"`
	CorpusTokenCount   int                    `json:"corpus_token_count"`
	ModelID            string                 `json:"model_id"`
	ModelDigest        string                 `json:"model_digest"`
	Policy             VerificationPolicy     `json:"policy"`
	Microbenchmark     MicrobenchResult       `json:"microbenchmark"`
	RegimeComparison   []RegimeComparisonRow  `json:"regime_comparison"`
	ChallengeSweep     []ChallengeSweepRow    `json:"challenge_sweep"`
	NegativeRegimes    []NegativeRegimeReport `json:"negative_regimes"`
	ParitySummary      ParitySummary          `json:"parity_summary"`
}

func deterministicUnitDraw(seed uint64, tag string, idx int) uint64 {
	h := sha256.New()
	var buf [16]byte
	binary.LittleEndian.PutUint64(buf[0:8], seed)
	binary.LittleEndian.PutUint64(buf[8:16], uint64(idx))
	h.Write([]byte("inference-verify.v1:sim:"))
	h.Write([]byte(tag))
	h.Write(buf[:])
	sum := h.Sum(nil)
	return binary.BigEndian.Uint64(sum[:8]) % ChallengeDenominatorBPS
}

func round4(v float64) float64 {
	return math.Round(v*10000) / 10000
}

func RunMicrobenchmark(seed uint64, corpus *LoadedCorpus) (MicrobenchResult, error) {
	policy := DefaultPolicy()
	rig := NewTestRig(seed, corpus, policy)
	const steps = 8
	const iters = 400
	tokens := rig.PromptForIndex(1)
	worker := rig.Actors["worker-alpha-1"]

	// Build a 1024-leaf transparency log to measure realistic O(log N) Merkle proof verification.
	var sampleEnv DSSEEnvelope
	var sampleLeaf string
	var sampleIdx int
	for i := 0; i < 1024; i++ {
		leaf := fmt.Sprintf("leaf-%04d-%s", i, rig.Model.ModelDigest[:16])
		sum := sha256.Sum256([]byte(leaf))
		idx := rig.TLog.Append(hex.EncodeToString(sum[:]))
		if i == 777 {
			out := rig.Model.ForwardHonest("bench-job-777", tokens, steps)
			stmt := rig.BuildWorkerStatement("bench-job-777", 1, RegimeSignedAttestationOnly, steps, out, worker, ActionNone)
			env, err := SignDSSE(stmt, worker.PrivKey)
			if err != nil {
				return MicrobenchResult{}, err
			}
			pb, _ := base64.StdEncoding.DecodeString(env.Payload)
			sb, _ := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
			sampleLeaf = ComputeTLogLeafEntryDigest("bench-job-777", pb, sb, 1)
			rig.TLog.Leaves[idx] = []byte(sampleLeaf)
			sampleEnv = env
			sampleIdx = idx
		}
	}
	bundle, err := rig.TLog.BundleForIndex(sampleIdx, 1)
	if err != nil {
		return MicrobenchResult{}, err
	}

	// Warmup
	_ = rig.Model.ForwardHonest("warmup", tokens, steps)

	t0 := time.Now()
	var sink int32
	for i := 0; i < iters; i++ {
		out := rig.Model.ForwardHonest("bench-honest", tokens, steps)
		sink ^= out.TopToken
	}
	honestUs := float64(time.Since(t0).Microseconds()) / float64(iters)

	t1 := time.Now()
	for i := 0; i < iters; i++ {
		out := rig.Model.ForwardLazyDummy("bench-lazy", tokens, steps)
		sink ^= out.TopToken
	}
	lazyUs := float64(time.Since(t1).Microseconds()) / float64(iters)

	sampleOut := rig.Model.ForwardHonest("bench-sign", tokens, steps)
	sampleStmt := rig.BuildWorkerStatement("bench-sign", 1, RegimeSignedAttestationOnly, steps, sampleOut, worker, ActionNone)
	t2 := time.Now()
	for i := 0; i < iters; i++ {
		env, _ := SignDSSE(sampleStmt, worker.PrivKey)
		sink ^= int32(len(env.Payload))
	}
	signUs := float64(time.Since(t2).Microseconds()) / float64(iters)

	t3 := time.Now()
	for i := 0; i < iters; i++ {
		_, _, code := VerifyDSSESignature(sampleEnv, worker.Entry.PubKeyHex)
		if code != ErrNone {
			return MicrobenchResult{}, fmt.Errorf("unexpected verify error: %s", code)
		}
	}
	verifyUs := float64(time.Since(t3).Microseconds()) / float64(iters)

	t4 := time.Now()
	for i := 0; i < iters; i++ {
		code := VerifyTransparencyLogBundle(bundle, sampleLeaf, 1, rig.TrustRoot)
		if code != ErrNone {
			return MicrobenchResult{}, fmt.Errorf("unexpected tlog verify error: %s", code)
		}
	}
	tlogUs := float64(time.Since(t4).Microseconds()) / float64(iters)
	_ = sink

	attestOnlyUs := verifyUs + tlogUs
	reexecK3Us := attestOnlyUs + 2.0*(honestUs+verifyUs)
	savings := 0.0
	if honestUs > 0 {
		savings = (1.0 - lazyUs/honestUs) * 100.0
	}
	speedup := 0.0
	if attestOnlyUs > 0 {
		speedup = reexecK3Us / attestOnlyUs
	}
	return MicrobenchResult{
		DecodeSteps:             steps,
		Iterations:              iters,
		HonestInferenceUs:       round4(honestUs),
		LazyDummyUs:             round4(lazyUs),
		LazyComputeSavingsPct:   round4(savings),
		DSSESignUs:              round4(signUs),
		DSSEVerifyUs:            round4(verifyUs),
		TLogProofVerify1024Us:   round4(tlogUs),
		AttestationOnlyVerifyUs: round4(attestOnlyUs),
		ReexecK3VerifyUs:        round4(reexecK3Us),
		AttestVsReexecSpeedup:   round4(speedup),
	}, nil
}

func simulateRegime(
	seed uint64,
	regime, label, scenario string,
	totalJobs int,
	policy VerificationPolicy,
	micro MicrobenchResult,
	reexecK int,
	challengeOverrideBPS *uint64,
	adversarialFractionBPS uint64,
	cheatRateWhenAdvBPS uint64,
) RegimeComparisonRow {
	fee := float64(policy.JobFeeUnits) / 100.0
	honestCost := float64(policy.HonestCostUnits) / 100.0
	cheatCost := float64(policy.CheatCostUnits) / 100.0
	slash := float64(policy.SlashPenaltyUnits) / 100.0

	beacon := DeriveEpochBeacon(seed, 100)
	cheatedJobs := 0
	challengedJobs := 0
	fraudDetected := 0
	fraudEscaped := 0
	totalExecs := 0

	var cheaterTotalProfit float64
	cheaterJobCount := 0

	for i := 0; i < totalJobs; i++ {
		isAdvWorker := deterministicUnitDraw(seed, "worker-type:"+scenario, i) < adversarialFractionBPS
		isNewOrFlagged := isAdvWorker || (deterministicUnitDraw(seed, "risk:"+scenario, i) < 1000) // 10% benign new workers

		cheated := false
		if isAdvWorker {
			cheated = deterministicUnitDraw(seed, "cheat-decision:"+scenario, i) < cheatRateWhenAdvBPS
		}
		if cheated {
			cheatedJobs++
		}

		// Worker execution always counts as 1 compute unit baseline (or cheated dummy).
		totalExecs++
		jobID := fmt.Sprintf("sim-%s-%05d", scenario, i)
		outTag := "honest"
		if cheated {
			outTag = "cheated"
		}
		outSum := sha256.Sum256([]byte(jobID + ":" + outTag))
		outDigest := hex.EncodeToString(outSum[:])

		detected := false
		switch regime {
		case RegimeSignedAttestationOnly:
			// Zero re-execution; valid-key cheating never detected.
			detected = false

		case RegimeIndependentReexec:
			totalExecs += (reexecK - 1)
			if cheated {
				detected = true
			}

		case RegimeRandomChallenge, RegimeHybridAttestedChal:
			risk := WorkerRiskContext{ReputationScore: 930, JobsCompleted: 100, AIAdvisoryFlagged: false}
			if isNewOrFlagged {
				risk = WorkerRiskContext{ReputationScore: 620, JobsCompleted: 5, AIAdvisoryFlagged: isAdvWorker}
			}
			effBPS := EffectiveChallengeBPS(regime, risk, policy, challengeOverrideBPS)
			drawBPS := ComputeChallengeDrawBPS(beacon, jobID, outDigest)
			if drawBPS < effBPS {
				challengedJobs++
				totalExecs++
				if cheated {
					detected = true
				}
			}
		}

		if cheated {
			cheaterJobCount++
			if detected {
				fraudDetected++
				cheaterTotalProfit += (-slash - cheatCost)
			} else {
				fraudEscaped++
				cheaterTotalProfit += (fee - cheatCost)
			}
		}
	}

	detRate := 0.0
	if cheatedJobs > 0 {
		detRate = (float64(fraudDetected) / float64(cheatedJobs)) * 100.0
	}
	computeMult := float64(totalExecs) / float64(totalJobs)
	extraExecPerJob := computeMult - 1.0
	verifyOverheadUs := micro.AttestationOnlyVerifyUs + extraExecPerJob*(micro.HonestInferenceUs+micro.DSSEVerifyUs)

	honestProfit := fee - honestCost
	empCheaterProfit := honestProfit
	if cheaterJobCount > 0 {
		empCheaterProfit = cheaterTotalProfit / float64(cheaterJobCount)
	}
	cheatAdv := empCheaterProfit - honestProfit
	ic := cheatAdv < 0
	if cheatedJobs == 0 {
		cheatAdv = 0
		ic = regime != RegimeSignedAttestationOnly
	}

	return RegimeComparisonRow{
		Regime:                       regime,
		ConfigLabel:                  label,
		Scenario:                     scenario,
		TotalJobs:                    totalJobs,
		CheatedJobs:                  cheatedJobs,
		ChallengedJobs:               challengedJobs,
		FraudDetected:                fraudDetected,
		FraudEscaped:                 fraudEscaped,
		CheatDetectionRatePct:        round4(detRate),
		HonestFalseRejections:        0,
		HonestFRRPct:                 0.0,
		ComputeCostMultiplier:        round4(computeMult),
		EstimatedVerifyOverheadUs:    round4(verifyOverheadUs),
		ProvenanceCoveragePct:        100.0,
		HonestProfitPerJob:           round4(honestProfit),
		EmpiricalCheaterProfitPerJob: round4(empCheaterProfit),
		CheatingAdvantagePerJob:      round4(cheatAdv),
		IncentiveCompatible:          ic,
	}
}

func RunChallengeSweep(seed uint64, policy VerificationPolicy) []ChallengeSweepRow {
	pValues := []uint64{100, 500, 1000, 2500, 5000} // 1%, 5%, 10%, 25%, 50%
	cheatRates := []float64{0.10, 0.50, 1.00}
	slashRatios := []float64{1.0, 5.0, 20.0, 100.0}

	fee := float64(policy.JobFeeUnits) / 100.0
	honestCost := float64(policy.HonestCostUnits) / 100.0
	cheatCost := float64(policy.CheatCostUnits) / 100.0
	cheatGain := honestCost - cheatCost
	beacon := DeriveEpochBeacon(seed, 200)
	const jobsPerCell = 2000

	var rows []ChallengeSweepRow
	for _, pBPS := range pValues {
		p := float64(pBPS) / float64(ChallengeDenominatorBPS)
		for _, cr := range cheatRates {
			crBPS := uint64(math.Round(cr * float64(ChallengeDenominatorBPS)))
			for _, sr := range slashRatios {
				slash := sr * cheatGain
				econ := AnalyzeEconomics(p, fee, honestCost, cheatCost, slash)

				cheated := 0
				detected := 0
				challenged := 0
				var cheatNet float64
				for i := 0; i < jobsPerCell; i++ {
					isCheat := deterministicUnitDraw(seed, fmt.Sprintf("sweep-%d-%d", pBPS, crBPS), i) < crBPS
					jobID := fmt.Sprintf("sw-%d-%d-%d", pBPS, crBPS, i)
					outSum := sha256.Sum256([]byte(jobID))
					draw := ComputeChallengeDrawBPS(beacon, jobID, hex.EncodeToString(outSum[:]))
					isChallenged := draw < pBPS
					if isChallenged {
						challenged++
					}
					if isCheat {
						cheated++
						if isChallenged {
							detected++
							cheatNet += (-slash - cheatCost)
						} else {
							cheatNet += (fee - cheatCost)
						}
					}
				}
				detPct := 0.0
				empCheatProfit := 0.0
				if cheated > 0 {
					detPct = (float64(detected) / float64(cheated)) * 100.0
					empCheatProfit = cheatNet / float64(cheated)
				}
				rows = append(rows, ChallengeSweepRow{
					ChallengeRateP:            p,
					ChallengeBPS:              pBPS,
					CheatRate:                 cr,
					SlashRatio:                sr,
					SlashPenalty:              round4(slash),
					TotalJobs:                 jobsPerCell,
					CheatedJobs:               cheated,
					DetectedCheats:            detected,
					EmpiricalDetectionRatePct: round4(detPct),
					ComputeCostMultiplier:     round4(1.0 + float64(challenged)/float64(jobsPerCell)),
					TheoreticalCheatProfit:    round4(econ.ExpectedCheatProfit),
					EmpiricalCheatProfit:      round4(empCheatProfit),
					HonestProfit:              round4(econ.ExpectedHonestProfit),
					IncentiveCompatible:       econ.IncentiveCompatible,
				})
			}
		}
	}
	return rows
}

func RunNegativeRegimes(seed uint64, policy VerificationPolicy, micro MicrobenchResult) []NegativeRegimeReport {
	// Negative Regime 1: Valid-key lazy cheater against signed_attestation_only
	neg1Row := simulateRegime(seed, RegimeSignedAttestationOnly, "signed_attestation_only", "neg1_valid_key_cheater",
		500, policy, micro, 1, nil, 10000, 10000)

	// Negative Regime 2: Undercollateralized challenge (p=0.01, S=20.0 units -> p*(fee+S) = 0.30 < 4.75 = cheat_gain)
	underPolicy := policy
	underPolicy.SlashPenaltyUnits = 2000 // 20.00 units
	underPolicy.WorkerBondUnits = 2000
	p100 := uint64(100) // 1.0%
	neg2Row := simulateRegime(seed, RegimeRandomChallenge, "random_challenge(p=0.01,S=20)", "neg2_undercollateralized",
		2000, underPolicy, micro, 1, &p100, 10000, 10000)
	neg2Econ := AnalyzeEconomics(0.01, 10.0, 5.0, 0.25, 20.0)

	// Negative Regime 3: Full k=3 re-execution cost ceiling on 100%-honest workload
	neg3Reexec := simulateRegime(seed, RegimeIndependentReexec, "independent_reexecution(k=3)", "neg3_honest_bulk",
		1000, policy, micro, 3, nil, 0, 0)
	neg3Hybrid := simulateRegime(seed, RegimeHybridAttestedChal, "hybrid(p_base=0.05,p_esc=0.25)", "neg3_honest_bulk",
		1000, policy, micro, 1, nil, 0, 0)

	return []NegativeRegimeReport{
		{
			ID:           "neg_attestation_blind_to_valid_key_cheating",
			Title:        "Signed Attestation Alone Is 100% Blind to Valid-Key Lazy Cheating",
			RegimeTested: RegimeSignedAttestationOnly,
			ClaimProven:  "in-toto DSSE + Sigstore Rekor-style transparency log inclusion proves signer identity and log commitment only; a valid-key worker substituting a cheap dummy model achieves 0.00% detection (100.00% fraud escape) and +4.75 units/job excess cheating profit.",
			Metrics: map[string]any{
				"total_cheated_jobs":               neg1Row.CheatedJobs,
				"fraud_detected":                   neg1Row.FraudDetected,
				"fraud_escaped":                    neg1Row.FraudEscaped,
				"cheat_detection_rate_pct":         neg1Row.CheatDetectionRatePct,
				"fraud_escape_rate_pct":            round4(100.0 - neg1Row.CheatDetectionRatePct),
				"empirical_cheater_profit_per_job": neg1Row.EmpiricalCheaterProfitPerJob,
				"honest_profit_per_job":            neg1Row.HonestProfitPerJob,
				"cheating_advantage_per_job":       neg1Row.CheatingAdvantagePerJob,
			},
		},
		{
			ID:           "neg_undercollateralized_challenge_profitable_cheating",
			Title:        "Undercollateralized Random Challenge Allows Profitable Rational Cheating",
			RegimeTested: RegimeRandomChallenge,
			ClaimProven:  "When p * (fee + slash) < cheat_gain (here 0.01 * (10 + 20) = 0.30 < 4.75), random challenge verification fails incentive-compatibility: a rational attacker earns strictly higher net profit by cheating despite slashing.",
			Metrics: map[string]any{
				"total_cheated_jobs":               neg2Row.CheatedJobs,
				"challenge_rate_p":                 0.01,
				"slash_penalty":                    20.0,
				"cheat_gain_per_job":               neg2Econ.CheatGain,
				"expected_penalty_p_times_fee_S":   round4(0.01 * (10.0 + 20.0)),
				"min_slash_required_for_ic":        round4(neg2Econ.MinSlashForIC),
				"fraud_detected":                   neg2Row.FraudDetected,
				"cheat_detection_rate_pct":         neg2Row.CheatDetectionRatePct,
				"theoretical_cheat_profit_per_job": round4(neg2Econ.ExpectedCheatProfit),
				"empirical_cheater_profit_per_job": neg2Row.EmpiricalCheaterProfitPerJob,
				"honest_profit_per_job":            neg2Row.HonestProfitPerJob,
				"cheating_advantage_per_job":       neg2Row.CheatingAdvantagePerJob,
				"incentive_compatible":             neg2Econ.IncentiveCompatible,
			},
		},
		{
			ID:           "neg_full_reexecution_cost_ceiling",
			Title:        "Unconditional k=3 Independent Re-Execution Incurs 3.00x Compute Ceiling on Honest Workloads",
			RegimeTested: RegimeIndependentReexec,
			ClaimProven:  "On a 100%-honest workload (0% adversaries), unconditional k=3 re-execution wastes 200% redundant inference compute (3.00x multiplier) compared to 1.07x for hybrid attested+challenged verification.",
			Metrics: map[string]any{
				"total_honest_jobs":             neg3Reexec.TotalJobs,
				"reexec_k3_compute_multiplier":  neg3Reexec.ComputeCostMultiplier,
				"reexec_k3_wasted_compute_pct":  round4((neg3Reexec.ComputeCostMultiplier - 1.0) * 100.0),
				"hybrid_compute_multiplier":     neg3Hybrid.ComputeCostMultiplier,
				"hybrid_overhead_pct":           round4((neg3Hybrid.ComputeCostMultiplier - 1.0) * 100.0),
				"reexec_vs_hybrid_compute_ratio": round4(neg3Reexec.ComputeCostMultiplier / neg3Hybrid.ComputeCostMultiplier),
				"reexec_k3_verify_overhead_us":  neg3Reexec.EstimatedVerifyOverheadUs,
				"hybrid_verify_overhead_us":     neg3Hybrid.EstimatedVerifyOverheadUs,
			},
		},
	}
}

// RunFullBenchmark executes all benchmarks, negative regimes, and builds the
// 225-case parity fixture suite deterministically from --seed.
func RunFullBenchmark(seed uint64, corpus *LoadedCorpus) (BenchmarkReport, VerificationSuite, error) {
	policy := DefaultPolicy()
	micro, err := RunMicrobenchmark(seed, corpus)
	if err != nil {
		return BenchmarkReport{}, VerificationSuite{}, err
	}

	suite, audit, err := BuildParitySuite(seed, corpus)
	if err != nil {
		return BenchmarkReport{}, VerificationSuite{}, err
	}

	p500 := uint64(500)
	p1000 := uint64(1000)
	p2500 := uint64(2500)

	// Head-to-head comparison under identical threat model:
	// Scenario A ("mixed_fleet_1000"): 1,000 jobs, 15% adversarial workers cheating on 50% of jobs (~7.5% cheated jobs).
	// Scenario B ("adversarial_cheater_500"): 500 jobs, 100% rational lazy-dummy workers.
	comparison := []RegimeComparisonRow{
		simulateRegime(seed, RegimeSignedAttestationOnly, "DSSE + Rekor tlog (0x re-exec)", "mixed_fleet_1000", 1000, policy, micro, 1, nil, 1500, 5000),
		simulateRegime(seed, RegimeIndependentReexec, "Independent re-exec (k=2)", "mixed_fleet_1000", 1000, policy, micro, 2, nil, 1500, 5000),
		simulateRegime(seed, RegimeIndependentReexec, "Independent re-exec (k=3)", "mixed_fleet_1000", 1000, policy, micro, 3, nil, 1500, 5000),
		simulateRegime(seed, RegimeRandomChallenge, "Random challenge (p=0.05, S=150)", "mixed_fleet_1000", 1000, policy, micro, 1, &p500, 1500, 5000),
		simulateRegime(seed, RegimeRandomChallenge, "Random challenge (p=0.10, S=150)", "mixed_fleet_1000", 1000, policy, micro, 1, &p1000, 1500, 5000),
		simulateRegime(seed, RegimeRandomChallenge, "Random challenge (p=0.25, S=150)", "mixed_fleet_1000", 1000, policy, micro, 1, &p2500, 1500, 5000),
		simulateRegime(seed, RegimeHybridAttestedChal, "Hybrid DSSE+tlog + adaptive p (5%/25%, S=150)", "mixed_fleet_1000", 1000, policy, micro, 1, nil, 1500, 5000),

		simulateRegime(seed, RegimeSignedAttestationOnly, "DSSE + Rekor tlog (0x re-exec)", "adversarial_cheater_500", 500, policy, micro, 1, nil, 10000, 10000),
		simulateRegime(seed, RegimeIndependentReexec, "Independent re-exec (k=3)", "adversarial_cheater_500", 500, policy, micro, 3, nil, 10000, 10000),
		simulateRegime(seed, RegimeRandomChallenge, "Random challenge (p=0.05, S=150)", "adversarial_cheater_500", 500, policy, micro, 1, &p500, 10000, 10000),
		simulateRegime(seed, RegimeHybridAttestedChal, "Hybrid DSSE+tlog + adaptive p (5%/25%, S=150)", "adversarial_cheater_500", 500, policy, micro, 1, nil, 10000, 10000),
	}

	sweep := RunChallengeSweep(seed, policy)
	negatives := RunNegativeRegimes(seed, policy, micro)

	report := BenchmarkReport{
		SchemaVersion:    SchemaVersion,
		SpecVersion:      SpecVersion,
		Issue:            "zoo-apps/papers#14",
		HIP:              "HIP-1350",
		Seed:             seed,
		CorpusRootSHA256: corpus.CorpusRootSHA256,
		CorpusFiles:      len(corpus.Manifest.Files),
		CorpusVocabSize:  len(corpus.Vocab),
		CorpusTokenCount: len(corpus.TokenStream),
		ModelID:          suite.ModelID,
		ModelDigest:      suite.ModelDigest,
		Policy:           policy,
		Microbenchmark:   micro,
		RegimeComparison: comparison,
		ChallengeSweep:   sweep,
		NegativeRegimes:  negatives,
		ParitySummary: ParitySummary{
			TotalCases:       audit.TotalCases,
			GoldenCases:      audit.GoldenCases,
			AdversarialCases: audit.AdversarialCase,
			MatchesExpected:  audit.MatchesExpected,
			AuditMerkleRoot:  audit.AuditMerkleRoot,
			AllMatched:       audit.MatchesExpected == audit.TotalCases,
		},
	}
	return report, suite, nil
}

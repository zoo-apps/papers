// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package settlement

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"sync"
)

// ValidateJob validates an AdmittedJob record against the registered principals and network policy.
func ValidateJob(job AdmittedJob, principals map[string]Principal) error {
	if !validID(job.JobID) || !validID(job.PayerID) || !validID(job.ProviderID) || !validID(job.CorpusPaperID) {
		return newProtoErr(ErrInvalidSchema, "invalid identifier in job %q", job.JobID)
	}
	if !validHex64(job.CorpusPaperSHA256) || !validHex64(job.WorkSpecHash) {
		return newProtoErr(ErrInvalidSchema, "invalid hex digest in job %q", job.JobID)
	}
	if job.Epoch == 0 || job.MaxBudgetMicroZOO <= 0 {
		return newProtoErr(ErrInvalidSchema, "invalid epoch or max_budget in job %q", job.JobID)
	}
	if job.ConservationBPS < 0 || job.ProtocolBPS < 0 || job.ConservationBPS+job.ProtocolBPS > BPSDenominator {
		return newProtoErr(ErrInvalidSchema, "invalid bps in job %q", job.JobID)
	}
	switch job.ModelTier {
	case "small", "medium", "large", "frontier":
	default:
		return newProtoErr(ErrInvalidSchema, "invalid model_tier %q", job.ModelTier)
	}
	if payer, ok := principals[job.PayerID]; !ok || payer.Role != RolePayer {
		return newProtoErr(ErrInvalidSchema, "unknown or non-PAYER payer_id %q", job.PayerID)
	}
	if prov, ok := principals[job.ProviderID]; !ok || prov.Role != RoleProvider {
		return newProtoErr(ErrInvalidSchema, "unknown or non-PROVIDER provider_id %q", job.ProviderID)
	}
	return nil
}

// ValidateWorkResult checks WorkResult fields, work_hash binding, and budget bounds.
func ValidateWorkResult(job AdmittedJob, work WorkResult) error {
	if work.JobID != job.JobID || work.ProviderID != job.ProviderID {
		return newProtoErr(ErrInvalidSchema, "work result mismatch with job %q", job.JobID)
	}
	if !validHex64(work.OutputDigest) || !validHex64(work.WorkHash) {
		return newProtoErr(ErrInvalidSchema, "invalid hex digest in work result %q", work.JobID)
	}
	if work.TokensProcessed == 0 || work.ComputeUnits == 0 || work.ConsumedMicroZOO <= 0 {
		return newProtoErr(ErrInvalidSchema, "non-positive usage in work result %q", work.JobID)
	}
	if work.ConsumedMicroZOO > job.MaxBudgetMicroZOO {
		return newProtoErr(ErrBudgetOverflow, "consumed %d exceeds max_budget %d", work.ConsumedMicroZOO, job.MaxBudgetMicroZOO)
	}
	wantWorkHash := ComputeWorkHash(job.JobID, job.CorpusPaperSHA256, job.WorkSpecHash, work.OutputDigest, work.TokensProcessed, work.ComputeUnits)
	if work.WorkHash != wantWorkHash {
		return newProtoErr(ErrInvalidAttestationUID, "work_hash mismatch: got %s want %s", work.WorkHash, wantWorkHash)
	}
	return nil
}

// ValidateQuorumAttestations verifies all Layer 1 EAS attestations for a job/work result:
// - Schema UID, RefUID, self-verification block, validator role, AttestationUID, Ed25519 signature,
// - Distinct attesters, agreement on work payload, and >= policy.ValidatorQuorum valid attestations.
func ValidateQuorumAttestations(job AdmittedJob, work WorkResult, attestations []EASAttestation, principals map[string]Principal, policy NetworkPolicy) error {
	if err := ValidateJob(job, principals); err != nil {
		return err
	}
	if err := ValidateWorkResult(job, work); err != nil {
		return err
	}
	if len(attestations) == 0 {
		return newProtoErr(ErrInsufficientQuorum, "zero attestations provided; need %d", policy.ValidatorQuorum)
	}

	wantSchemaUID := CanonicalEASSchemaUID()
	wantRefUID := ComputeRefUID(job.JobID)
	seenValidators := make(map[string]struct{}, len(attestations))

	for i, att := range attestations {
		if att.SchemaUID != wantSchemaUID {
			return newProtoErr(ErrInvalidSchema, "attestation[%d] wrong schema_uid", i)
		}
		if att.RefUID != wantRefUID {
			return newProtoErr(ErrInvalidAttestationUID, "attestation[%d] ref_uid mismatch", i)
		}
		// Self-verification constitutional lock: provider cannot verify its own work.
		if att.Attester == job.ProviderID || att.Attester == att.Recipient {
			return newProtoErr(ErrSelfVerificationForbid, "attester %q cannot self-verify provider %q", att.Attester, job.ProviderID)
		}
		attPrincipal, ok := principals[att.Attester]
		if !ok {
			return newProtoErr(ErrUnauthorizedValidator, "unknown validator %q", att.Attester)
		}
		if attPrincipal.Role == RoleApplication {
			return newProtoErr(ErrAppIssuanceForbidden, "application %q cannot sign validator attestations", att.Attester)
		}
		if attPrincipal.Role == RoleAIAgent {
			return newProtoErr(ErrAIIssuanceForbidden, "ai agent %q cannot sign validator attestations", att.Attester)
		}
		if attPrincipal.Role != RoleValidator {
			return newProtoErr(ErrUnauthorizedValidator, "principal %q has role %s, not VALIDATOR", att.Attester, attPrincipal.Role)
		}
		if provPrincipal, ok := principals[job.ProviderID]; ok && provPrincipal.PublicKeyHex == attPrincipal.PublicKeyHex {
			return newProtoErr(ErrSelfVerificationForbid, "validator %q shares public key with provider %q", att.Attester, job.ProviderID)
		}
		if _, dup := seenValidators[att.Attester]; dup {
			return newProtoErr(ErrDuplicateValidator, "duplicate validator %q in quorum", att.Attester)
		}
		seenValidators[att.Attester] = struct{}{}

		// Verify consistency with job and work result.
		if att.JobID != job.JobID || att.Recipient != job.ProviderID ||
			att.WorkHash != work.WorkHash || att.Epoch != job.Epoch ||
			att.ConsumedMicroZOO != work.ConsumedMicroZOO ||
			att.TokensProcessed != work.TokensProcessed ||
			att.ComputeUnits != work.ComputeUnits {
			return newProtoErr(ErrAttestationMismatch, "attestation[%d] payload disagrees with job/work", i)
		}

		// Recompute EAS AttestationUID.
		wantUID := ComputeAttestationUID(att.SchemaUID, att.RefUID, att.Recipient, att.Attester, att.WorkHash, att.Epoch, att.Nonce)
		if att.AttestationUID != wantUID {
			return newProtoErr(ErrInvalidAttestationUID, "attestation[%d] UID mismatch", i)
		}

		// Verify RFC 8032 Ed25519 signature.
		sigMsg := ValidatorSignatureMessage(att)
		if !VerifyEd25519Hex(attPrincipal.PublicKeyHex, sigMsg, att.SignatureHex) {
			return newProtoErr(ErrInvalidSignature, "attestation[%d] invalid Ed25519 signature from %q", i, att.Attester)
		}
	}

	if len(seenValidators) < policy.ValidatorQuorum {
		return newProtoErr(ErrInsufficientQuorum, "got %d valid attestations, need quorum %d", len(seenValidators), policy.ValidatorQuorum)
	}
	return nil
}

// ValidateReceiptIntegrity verifies a UsefulWorkReceipt's issuer role, exact integer split, receipt_id, and nullifier.
func ValidateReceiptIntegrity(job AdmittedJob, work WorkResult, attestations []EASAttestation, receipt UsefulWorkReceipt, principals map[string]Principal) error {
	// Issuer authority check.
	if receipt.IssuerRole == RoleApplication {
		return newProtoErr(ErrAppIssuanceForbidden, "application %q cannot issue receipts", receipt.IssuerID)
	}
	if receipt.IssuerRole == RoleAIAgent {
		return newProtoErr(ErrAIIssuanceForbidden, "ai agent %q cannot issue receipts", receipt.IssuerID)
	}
	issuer, ok := principals[receipt.IssuerID]
	if !ok {
		return newProtoErr(ErrInvalidSchema, "unknown receipt issuer %q", receipt.IssuerID)
	}
	if issuer.Role == RoleApplication {
		return newProtoErr(ErrAppIssuanceForbidden, "application %q cannot issue receipts", receipt.IssuerID)
	}
	if issuer.Role == RoleAIAgent {
		return newProtoErr(ErrAIIssuanceForbidden, "ai agent %q cannot issue receipts", receipt.IssuerID)
	}
	if issuer.Role != RoleSettlementNode || receipt.IssuerRole != RoleSettlementNode {
		return newProtoErr(ErrUnauthorizedTreasury, "issuer %q role %s is not SETTLEMENT_NODE", receipt.IssuerID, issuer.Role)
	}

	if receipt.JobID != job.JobID || receipt.PayerID != job.PayerID || receipt.ProviderID != job.ProviderID ||
		receipt.WorkHash != work.WorkHash || receipt.Epoch != job.Epoch ||
		receipt.MaxBudgetMicroZOO != job.MaxBudgetMicroZOO || receipt.ConsumedMicroZOO != work.ConsumedMicroZOO ||
		receipt.ConservationBPS != job.ConservationBPS || receipt.ProtocolBPS != job.ProtocolBPS {
		return newProtoErr(ErrInvalidSchema, "receipt fields disagree with job/work")
	}

	split, err := ComputeExactSplit(job.MaxBudgetMicroZOO, work.ConsumedMicroZOO, job.ConservationBPS, job.ProtocolBPS)
	if err != nil {
		return err
	}
	if receipt.ProviderShareMicroZOO != split.ProviderShare ||
		receipt.ConservationShareMicroZOO != split.ConservationShare ||
		receipt.ProtocolFeeMicroZOO != split.ProtocolFee ||
		receipt.RefundMicroZOO != split.Refund {
		return newProtoErr(ErrAccountingMismatch, "receipt micro-ZOO split violates exact integer conservation")
	}
	if receipt.ProviderShareMicroZOO+receipt.ConservationShareMicroZOO+receipt.ProtocolFeeMicroZOO != receipt.ConsumedMicroZOO ||
		receipt.ConsumedMicroZOO+receipt.RefundMicroZOO != receipt.MaxBudgetMicroZOO {
		return newProtoErr(ErrAccountingMismatch, "receipt conservation sum check failed")
	}

	// Verify attestation UIDs match the verified quorum.
	attUIDs := make([]string, len(attestations))
	for i, a := range attestations {
		attUIDs[i] = a.AttestationUID
	}
	sort.Strings(attUIDs)
	gotUIDs := make([]string, len(receipt.AttestationUIDs))
	copy(gotUIDs, receipt.AttestationUIDs)
	sort.Strings(gotUIDs)
	if len(gotUIDs) != len(attUIDs) {
		return newProtoErr(ErrInvalidReceiptID, "receipt attestation_uids count mismatch")
	}
	for i := range attUIDs {
		if gotUIDs[i] != attUIDs[i] {
			return newProtoErr(ErrInvalidReceiptID, "receipt attestation_uids mismatch at %d", i)
		}
	}

	wantReceiptID := ComputeReceiptID(
		receipt.JobID, receipt.ProviderID, receipt.PayerID, receipt.WorkHash,
		receipt.Epoch, receipt.MaxBudgetMicroZOO, receipt.ConsumedMicroZOO,
		receipt.ConservationBPS, receipt.ProtocolBPS, attUIDs,
	)
	if receipt.ReceiptID != wantReceiptID {
		return newProtoErr(ErrInvalidReceiptID, "receipt_id mismatch")
	}
	wantNullifier := ComputeReceiptNullifier(receipt.JobID, receipt.ReceiptID, receipt.WorkHash)
	if receipt.Nullifier != wantNullifier {
		return newProtoErr(ErrInvalidNullifier, "nullifier mismatch")
	}
	return nil
}

// ValidatePolicyMutation checks constitutional locks on governance parameter mutations.
func ValidatePolicyMutation(attempt PolicyMutationAttempt, principals map[string]Principal) error {
	if attempt.ActorRole == RoleAIAgent || attempt.ActorRole == RoleApplication {
		return newProtoErr(ErrAIPolicyMutationForbid, "role %s (%q) is constitutionally forbidden from mutating policy field %q", attempt.ActorRole, attempt.ActorID, attempt.Field)
	}
	p, ok := principals[attempt.ActorID]
	if !ok {
		return newProtoErr(ErrUnauthorizedTreasury, "unknown actor %q", attempt.ActorID)
	}
	if p.Role == RoleAIAgent || p.Role == RoleApplication {
		return newProtoErr(ErrAIPolicyMutationForbid, "registered role %s (%q) cannot mutate policy", p.Role, attempt.ActorID)
	}
	if p.Role != RoleGovernanceTreasury || attempt.ActorRole != RoleGovernanceTreasury {
		return newProtoErr(ErrUnauthorizedTreasury, "role %s (%q) is not GOVERNANCE_TREASURY", p.Role, attempt.ActorID)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Layer 1: Admission & Independent Validation (ValidatorCommittee)
// ---------------------------------------------------------------------------

// ValidatorNode holds an independent Layer 1 validator's signing key. It NEVER holds treasury keys.
type ValidatorNode struct {
	ID      string
	PubHex  string
	PrivKey ed25519.PrivateKey
	Online  bool
}

// ValidatorCommittee manages Layer 1 job admission and independent work verification.
type ValidatorCommittee struct {
	mu         sync.RWMutex
	principals map[string]Principal
	validators map[string]*ValidatorNode
	valOrder   []string
	jobs       map[string]AdmittedJob
	nonceSeq   uint64
}

// NewValidatorCommittee constructs Layer 1 with strictly isolated validator keys.
func NewValidatorCommittee(principals []Principal, validators []*ValidatorNode) (*ValidatorCommittee, error) {
	pMap, err := ValidatePrincipalKeySeparation(principals)
	if err != nil {
		return nil, err
	}
	vMap := make(map[string]*ValidatorNode, len(validators))
	order := make([]string, 0, len(validators))
	for _, v := range validators {
		p, ok := pMap[v.ID]
		if !ok || p.Role != RoleValidator || p.PublicKeyHex != v.PubHex {
			return nil, newProtoErr(ErrUnauthorizedValidator, "validator %q not validly registered", v.ID)
		}
		vMap[v.ID] = v
		order = append(order, v.ID)
	}
	sort.Strings(order)
	return &ValidatorCommittee{
		principals: pMap,
		validators: vMap,
		valOrder:   order,
		jobs:       make(map[string]AdmittedJob),
	}, nil
}

// SetValidatorOnline toggles a validator's liveness status for outage / stall simulations.
func (vc *ValidatorCommittee) SetValidatorOnline(validatorID string, online bool) {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	if v, ok := vc.validators[validatorID]; ok {
		v.Online = online
	}
}

// AdmitJob validates and registers a job with its committed max micro-ZOO budget.
func (vc *ValidatorCommittee) AdmitJob(job AdmittedJob) error {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	if err := ValidateJob(job, vc.principals); err != nil {
		return err
	}
	if _, exists := vc.jobs[job.JobID]; exists {
		return newProtoErr(ErrDoubleClaim, "job %q already admitted", job.JobID)
	}
	vc.jobs[job.JobID] = job
	return nil
}

// VerifyAndAttest independently verifies performed work and emits EAS-compatible Ed25519 attestations
// from all currently online validators.
func (vc *ValidatorCommittee) VerifyAndAttest(jobID string, work WorkResult) ([]EASAttestation, error) {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	job, ok := vc.jobs[jobID]
	if !ok {
		return nil, newProtoErr(ErrInvalidSchema, "job %q was not admitted", jobID)
	}
	if err := ValidateWorkResult(job, work); err != nil {
		return nil, err
	}

	schemaUID := CanonicalEASSchemaUID()
	refUID := ComputeRefUID(job.JobID)
	attestations := make([]EASAttestation, 0, len(vc.valOrder))

	for _, vid := range vc.valOrder {
		v := vc.validators[vid]
		if !v.Online {
			continue
		}
		if v.ID == job.ProviderID {
			return nil, newProtoErr(ErrSelfVerificationForbid, "validator %q cannot verify own work", v.ID)
		}
		vc.nonceSeq++
		nonce := vc.nonceSeq
		att := EASAttestation{
			SchemaUID:        schemaUID,
			RefUID:           refUID,
			JobID:            job.JobID,
			Recipient:        job.ProviderID,
			Attester:         v.ID,
			WorkHash:         work.WorkHash,
			Epoch:            job.Epoch,
			Nonce:            nonce,
			TokensProcessed:  work.TokensProcessed,
			ComputeUnits:     work.ComputeUnits,
			ConsumedMicroZOO: work.ConsumedMicroZOO,
		}
		att.AttestationUID = ComputeAttestationUID(att.SchemaUID, att.RefUID, att.Recipient, att.Attester, att.WorkHash, att.Epoch, att.Nonce)
		att.SignatureHex = SignEd25519Hex(v.PrivKey, ValidatorSignatureMessage(att))
		attestations = append(attestations, att)
	}
	return attestations, nil
}

// ---------------------------------------------------------------------------
// Layer 2: Receipt Settlement & Nullifier Ledger (SettlementEngine)
// ---------------------------------------------------------------------------

// SettlementEngine consumes verified Layer 1 attestations, issues canonical UsefulWorkReceipts,
// enforces the crash-safe WAL-backed nullifier set, and commits per-epoch binary Merkle trees.
// It NEVER holds treasury keys and NEVER authorizes reward payouts.
type SettlementEngine struct {
	mu               sync.Mutex
	nodeID           string
	policy           NetworkPolicy
	principals       map[string]Principal
	wal              *DurableWAL
	seenNullifiers   map[string]string            // nullifier -> receipt_id
	seenJobs         map[string]string            // job_id -> receipt_id
	receipts         map[string]UsefulWorkReceipt // receipt_id -> receipt
	epochOrder       map[uint64][]string          // epoch -> ordered receipt_ids
	epochCommitments map[uint64]EpochCommitment
}

type walReceiptRecord struct {
	Receipt UsefulWorkReceipt `json:"receipt"`
}

type walEpochSealRecord struct {
	Commitment EpochCommitment `json:"commitment"`
}

// NewSettlementEngine opens (or cold-restarts from) the durable WAL at walPath.
func NewSettlementEngine(nodeID string, policy NetworkPolicy, principals []Principal, walPath string) (*SettlementEngine, error) {
	pMap, err := ValidatePrincipalKeySeparation(principals)
	if err != nil {
		return nil, err
	}
	nodeP, ok := pMap[nodeID]
	if !ok || nodeP.Role != RoleSettlementNode {
		return nil, newProtoErr(ErrInvalidSchema, "settlement node %q not registered with SETTLEMENT_NODE role", nodeID)
	}
	wal, entries, err := OpenWAL(walPath)
	if err != nil {
		return nil, err
	}
	se := &SettlementEngine{
		nodeID:           nodeID,
		policy:           policy,
		principals:       pMap,
		wal:              wal,
		seenNullifiers:   make(map[string]string),
		seenJobs:         make(map[string]string),
		receipts:         make(map[string]UsefulWorkReceipt),
		epochOrder:       make(map[uint64][]string),
		epochCommitments: make(map[uint64]EpochCommitment),
	}
	// Deterministic WAL replay on cold restart.
	for _, entry := range entries {
		switch entry.Kind {
		case "ISSUE_RECEIPT":
			var rec walReceiptRecord
			if err := json.Unmarshal(entry.Payload, &rec); err != nil {
				_ = wal.Close()
				return nil, fmt.Errorf("wal replay receipt seq %d: %w", entry.Seq, err)
			}
			r := rec.Receipt
			se.seenNullifiers[r.Nullifier] = r.ReceiptID
			se.seenJobs[r.JobID] = r.ReceiptID
			se.receipts[r.ReceiptID] = r
			se.epochOrder[r.Epoch] = append(se.epochOrder[r.Epoch], r.ReceiptID)
		case "EPOCH_SEAL":
			var rec walEpochSealRecord
			if err := json.Unmarshal(entry.Payload, &rec); err != nil {
				_ = wal.Close()
				return nil, fmt.Errorf("wal replay epoch seal seq %d: %w", entry.Seq, err)
			}
			se.epochCommitments[rec.Commitment.Epoch] = rec.Commitment
		}
	}
	return se, nil
}

// Close closes the underlying WAL file.
func (se *SettlementEngine) Close() error {
	return se.wal.Close()
}

// IssueReceipt validates quorum attestations, enforces strict nullifier & job uniqueness atomically,
// persists to fsync WAL, and emits a canonical UsefulWorkReceipt.
func (se *SettlementEngine) IssueReceipt(callerID string, callerRole Role, job AdmittedJob, work WorkResult, attestations []EASAttestation) (UsefulWorkReceipt, error) {
	// Constitutional role guard: applications and AI agents cannot issue receipts.
	if callerRole == RoleApplication {
		return UsefulWorkReceipt{}, newProtoErr(ErrAppIssuanceForbidden, "application %q cannot issue receipts", callerID)
	}
	if callerRole == RoleAIAgent {
		return UsefulWorkReceipt{}, newProtoErr(ErrAIIssuanceForbidden, "ai agent %q cannot issue receipts", callerID)
	}
	if p, ok := se.principals[callerID]; ok {
		if p.Role == RoleApplication {
			return UsefulWorkReceipt{}, newProtoErr(ErrAppIssuanceForbidden, "application %q cannot issue receipts", callerID)
		}
		if p.Role == RoleAIAgent {
			return UsefulWorkReceipt{}, newProtoErr(ErrAIIssuanceForbidden, "ai agent %q cannot issue receipts", callerID)
		}
		if p.Role != RoleSettlementNode || callerID != se.nodeID {
			return UsefulWorkReceipt{}, newProtoErr(ErrUnauthorizedTreasury, "caller %q (%s) is not authorized settlement node", callerID, p.Role)
		}
	} else {
		return UsefulWorkReceipt{}, newProtoErr(ErrInvalidSchema, "unknown settlement caller %q", callerID)
	}

	if err := ValidateQuorumAttestations(job, work, attestations, se.principals, se.policy); err != nil {
		return UsefulWorkReceipt{}, err
	}
	split, err := ComputeExactSplit(job.MaxBudgetMicroZOO, work.ConsumedMicroZOO, job.ConservationBPS, job.ProtocolBPS)
	if err != nil {
		return UsefulWorkReceipt{}, err
	}
	attUIDs := make([]string, len(attestations))
	for i, a := range attestations {
		attUIDs[i] = a.AttestationUID
	}
	sort.Strings(attUIDs)

	receiptID := ComputeReceiptID(
		job.JobID, job.ProviderID, job.PayerID, work.WorkHash,
		job.Epoch, job.MaxBudgetMicroZOO, work.ConsumedMicroZOO,
		job.ConservationBPS, job.ProtocolBPS, attUIDs,
	)
	nullifier := ComputeReceiptNullifier(job.JobID, receiptID, work.WorkHash)

	receipt := UsefulWorkReceipt{
		ReceiptID:                 receiptID,
		Nullifier:                 nullifier,
		JobID:                     job.JobID,
		PayerID:                   job.PayerID,
		ProviderID:                job.ProviderID,
		IssuerID:                  se.nodeID,
		IssuerRole:                RoleSettlementNode,
		WorkHash:                  work.WorkHash,
		Epoch:                     job.Epoch,
		MaxBudgetMicroZOO:         job.MaxBudgetMicroZOO,
		ConsumedMicroZOO:          work.ConsumedMicroZOO,
		ProviderShareMicroZOO:     split.ProviderShare,
		ConservationShareMicroZOO: split.ConservationShare,
		ProtocolFeeMicroZOO:       split.ProtocolFee,
		RefundMicroZOO:            split.Refund,
		ConservationBPS:           job.ConservationBPS,
		ProtocolBPS:               job.ProtocolBPS,
		AttestationUIDs:           attUIDs,
	}

	// Atomic critical section enforcing zero double-claims under concurrent races.
	se.mu.Lock()
	defer se.mu.Unlock()

	if _, dupNull := se.seenNullifiers[nullifier]; dupNull {
		return UsefulWorkReceipt{}, newProtoErr(ErrDoubleClaim, "nullifier %s already settled", nullifier)
	}
	if _, dupJob := se.seenJobs[job.JobID]; dupJob {
		return UsefulWorkReceipt{}, newProtoErr(ErrDoubleClaim, "job %q already settled", job.JobID)
	}
	if _, err := se.wal.Append("ISSUE_RECEIPT", walReceiptRecord{Receipt: receipt}); err != nil {
		return UsefulWorkReceipt{}, fmt.Errorf("wal append receipt: %w", err)
	}
	se.seenNullifiers[nullifier] = receiptID
	se.seenJobs[job.JobID] = receiptID
	se.receipts[receiptID] = receipt
	se.epochOrder[job.Epoch] = append(se.epochOrder[job.Epoch], receiptID)
	return receipt, nil
}

// SealEpoch commits the binary Merkle root of all receipts settled in epoch and returns
// the EpochCommitment plus inclusion proofs keyed by receipt_id.
func (se *SettlementEngine) SealEpoch(epoch uint64) (EpochCommitment, map[string][]MerkleProofStep, error) {
	se.mu.Lock()
	defer se.mu.Unlock()

	ids := se.epochOrder[epoch]
	leaves := make([]string, len(ids))
	for i, rid := range ids {
		r := se.receipts[rid]
		leaves[i] = ComputeReceiptMerkleLeaf(r.ReceiptID, r.Nullifier, r.ConsumedMicroZOO)
	}
	root := ComputeMerkleRoot(leaves)
	commitment := EpochCommitment{
		Epoch:              epoch,
		ReceiptCount:       len(ids),
		ReceiptsMerkleRoot: root,
	}
	proofs := make(map[string][]MerkleProofStep, len(ids))
	for i, rid := range ids {
		proof, pRoot, err := BuildMerkleProof(leaves, i)
		if err != nil {
			return EpochCommitment{}, nil, err
		}
		if pRoot != root {
			return EpochCommitment{}, nil, newProtoErr(ErrInvalidMerkleProof, "internal root mismatch sealing epoch %d", epoch)
		}
		proofs[rid] = proof
	}
	if _, err := se.wal.Append("EPOCH_SEAL", walEpochSealRecord{Commitment: commitment}); err != nil {
		return EpochCommitment{}, nil, fmt.Errorf("wal append epoch seal: %w", err)
	}
	se.epochCommitments[epoch] = commitment
	return commitment, proofs, nil
}

// ReadReceipt provides read-only verified receipt access for downstream APPLICATION consumers.
func (se *SettlementEngine) ReadReceipt(receiptID string) (UsefulWorkReceipt, bool) {
	se.mu.Lock()
	defer se.mu.Unlock()
	r, ok := se.receipts[receiptID]
	return r, ok
}

// NullifierCount returns the total number of distinct settled nullifiers.
func (se *SettlementEngine) NullifierCount() int {
	se.mu.Lock()
	defer se.mu.Unlock()
	return len(se.seenNullifiers)
}

// EpochCommitmentOf returns the sealed EpochCommitment for epoch if sealed.
func (se *SettlementEngine) EpochCommitmentOf(epoch uint64) (EpochCommitment, bool) {
	se.mu.Lock()
	defer se.mu.Unlock()
	c, ok := se.epochCommitments[epoch]
	return c, ok
}

// ---------------------------------------------------------------------------
// Layer 3: Finality & Authorized Reward Issuance (FinalityTreasuryGate)
// ---------------------------------------------------------------------------

// TreasuryAuthority holds an authorized GOVERNANCE_TREASURY signing key.
type TreasuryAuthority struct {
	ID      string
	PubHex  string
	PrivKey ed25519.PrivateKey
}

// FinalityTreasuryGate is the isolated Layer 3 epoch-finality & governance treasury disbursement gate.
type FinalityTreasuryGate struct {
	mu                   sync.Mutex
	policy               NetworkPolicy
	principals           map[string]Principal
	authorities          map[string]*TreasuryAuthority
	wal                  *DurableWAL
	epochCommitments     map[uint64]EpochCommitment
	authorizedNullifiers map[string]string
	authorizedJobs       map[string]string
	balanceSheet         BalanceSheet
}

type walAuthRecord struct {
	Authorization RewardAuthorization `json:"authorization"`
	Consumed      int64               `json:"consumed"`
	MaxBudget     int64               `json:"max_budget"`
}

// NewFinalityTreasuryGate constructs (or cold-restarts from WAL) Layer 3.
func NewFinalityTreasuryGate(policy NetworkPolicy, principals []Principal, authorities []*TreasuryAuthority, walPath string) (*FinalityTreasuryGate, error) {
	pMap, err := ValidatePrincipalKeySeparation(principals)
	if err != nil {
		return nil, err
	}
	aMap := make(map[string]*TreasuryAuthority, len(authorities))
	for _, a := range authorities {
		p, ok := pMap[a.ID]
		if !ok || p.Role != RoleGovernanceTreasury || p.PublicKeyHex != a.PubHex {
			return nil, newProtoErr(ErrUnauthorizedTreasury, "treasury authority %q not registered with GOVERNANCE_TREASURY role", a.ID)
		}
		aMap[a.ID] = a
	}
	wal, entries, err := OpenWAL(walPath)
	if err != nil {
		return nil, err
	}
	gate := &FinalityTreasuryGate{
		policy:               policy,
		principals:           pMap,
		authorities:          aMap,
		wal:                  wal,
		epochCommitments:     make(map[uint64]EpochCommitment),
		authorizedNullifiers: make(map[string]string),
		authorizedJobs:       make(map[string]string),
		balanceSheet: BalanceSheet{
			ProviderBalancesMicroZOO: make(map[string]int64),
			EpochAuthorizedMicroZOO:  make(map[string]int64),
			ConservationExact:        true,
		},
	}
	// Deterministic WAL replay on cold restart.
	for _, entry := range entries {
		switch entry.Kind {
		case "EPOCH_COMMIT":
			var c EpochCommitment
			if err := json.Unmarshal(entry.Payload, &c); err != nil {
				_ = wal.Close()
				return nil, fmt.Errorf("wal replay epoch commit seq %d: %w", entry.Seq, err)
			}
			gate.epochCommitments[c.Epoch] = c
		case "AUTHORIZE_REWARD":
			var rec walAuthRecord
			if err := json.Unmarshal(entry.Payload, &rec); err != nil {
				_ = wal.Close()
				return nil, fmt.Errorf("wal replay auth seq %d: %w", entry.Seq, err)
			}
			gate.applyAuthorizedLocked(rec.Authorization, rec.MaxBudget, rec.Consumed)
		}
	}
	return gate, nil
}

// Close closes the underlying WAL file.
func (g *FinalityTreasuryGate) Close() error {
	return g.wal.Close()
}

// RegisterEpochCommitment registers a Layer 2 sealed EpochCommitment on Layer 3.
func (g *FinalityTreasuryGate) RegisterEpochCommitment(c EpochCommitment) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !validHex64(c.ReceiptsMerkleRoot) || c.Epoch == 0 {
		return newProtoErr(ErrInvalidSchema, "invalid epoch commitment for epoch %d", c.Epoch)
	}
	if _, err := g.wal.Append("EPOCH_COMMIT", c); err != nil {
		return fmt.Errorf("wal append epoch commit: %w", err)
	}
	g.epochCommitments[c.Epoch] = c
	return nil
}

// UpdatePolicy enforces constitutional locks on governance policy updates.
func (g *FinalityTreasuryGate) UpdatePolicy(attempt PolicyMutationAttempt) error {
	if err := ValidatePolicyMutation(attempt, g.principals); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	switch attempt.Field {
	case "epoch_treasury_cap_micro_zoo":
		if attempt.ProposedValue <= 0 {
			return newProtoErr(ErrInvalidSchema, "treasury cap must be positive")
		}
		g.policy.EpochTreasuryCapMicroZOO = attempt.ProposedValue
	case "validator_quorum":
		if attempt.ProposedValue < 1 || int(attempt.ProposedValue) > g.policy.ValidatorCommitteeSize {
			return newProtoErr(ErrInvalidSchema, "invalid validator_quorum %d", attempt.ProposedValue)
		}
		g.policy.ValidatorQuorum = int(attempt.ProposedValue)
	case "finality_delay_epochs":
		if attempt.ProposedValue < 0 {
			return newProtoErr(ErrInvalidSchema, "negative finality_delay_epochs")
		}
		g.policy.FinalityDelayEpochs = uint64(attempt.ProposedValue)
	default:
		return newProtoErr(ErrInvalidSchema, "unknown policy field %q", attempt.Field)
	}
	return nil
}

// AuthorizeReward verifies finality, quorum attestations, Merkle inclusion proof, governance authority,
// nullifier uniqueness, and epoch treasury cap before emitting an Ed25519-signed RewardAuthorization.
func (g *FinalityTreasuryGate) AuthorizeReward(
	authorityID string,
	authorityRole Role,
	currentEpoch uint64,
	job AdmittedJob,
	work WorkResult,
	attestations []EASAttestation,
	receipt UsefulWorkReceipt,
	proof []MerkleProofStep,
) (RewardAuthorization, error) {
	// 1. Constitutional role separation locks.
	if authorityRole == RoleApplication {
		return RewardAuthorization{}, newProtoErr(ErrAppIssuanceForbidden, "application %q is forbidden from authorizing rewards", authorityID)
	}
	if authorityRole == RoleAIAgent {
		return RewardAuthorization{}, newProtoErr(ErrAIIssuanceForbidden, "ai agent %q is forbidden from authorizing treasury disbursement", authorityID)
	}
	authPrincipal, ok := g.principals[authorityID]
	if !ok {
		return RewardAuthorization{}, newProtoErr(ErrUnauthorizedTreasury, "unknown treasury authority %q", authorityID)
	}
	if authPrincipal.Role == RoleApplication {
		return RewardAuthorization{}, newProtoErr(ErrAppIssuanceForbidden, "application %q is forbidden from authorizing rewards", authorityID)
	}
	if authPrincipal.Role == RoleAIAgent {
		return RewardAuthorization{}, newProtoErr(ErrAIIssuanceForbidden, "ai agent %q is forbidden from authorizing treasury disbursement", authorityID)
	}
	if authPrincipal.Role != RoleGovernanceTreasury || authorityRole != RoleGovernanceTreasury {
		return RewardAuthorization{}, newProtoErr(ErrUnauthorizedTreasury, "actor %q role %s cannot authorize Layer 3 rewards", authorityID, authPrincipal.Role)
	}
	signer, ok := g.authorities[authorityID]
	if !ok {
		return RewardAuthorization{}, newProtoErr(ErrUnauthorizedTreasury, "treasury signing key not loaded for %q", authorityID)
	}

	// 2. Independently re-verify Layer 1 quorum attestations & Layer 2 receipt integrity.
	if err := ValidateQuorumAttestations(job, work, attestations, g.principals, g.policy); err != nil {
		return RewardAuthorization{}, err
	}
	if err := ValidateReceiptIntegrity(job, work, attestations, receipt, g.principals); err != nil {
		return RewardAuthorization{}, err
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	// 3. Finality delay and claim-window expiration checks.
	if currentEpoch < receipt.Epoch+g.policy.FinalityDelayEpochs {
		return RewardAuthorization{}, newProtoErr(ErrUnfinalizedEpoch, "epoch %d not yet finalized at current_epoch %d (delay=%d)", receipt.Epoch, currentEpoch, g.policy.FinalityDelayEpochs)
	}
	if currentEpoch > receipt.Epoch+g.policy.ClaimWindowEpochs {
		return RewardAuthorization{}, newProtoErr(ErrEpochExpired, "receipt epoch %d expired at current_epoch %d (window=%d)", receipt.Epoch, currentEpoch, g.policy.ClaimWindowEpochs)
	}

	// 4. Merkle inclusion proof verification against sealed epoch commitment.
	commitment, ok := g.epochCommitments[receipt.Epoch]
	if !ok {
		return RewardAuthorization{}, newProtoErr(ErrInvalidMerkleProof, "no epoch commitment registered for epoch %d", receipt.Epoch)
	}
	leaf := ComputeReceiptMerkleLeaf(receipt.ReceiptID, receipt.Nullifier, receipt.ConsumedMicroZOO)
	if !VerifyMerkleProof(leaf, proof, commitment.ReceiptsMerkleRoot) {
		return RewardAuthorization{}, newProtoErr(ErrInvalidMerkleProof, "merkle inclusion proof invalid for receipt %s", receipt.ReceiptID)
	}

	// 5. Layer 3 independent nullifier & job double-claim guard.
	if _, dup := g.authorizedNullifiers[receipt.Nullifier]; dup {
		return RewardAuthorization{}, newProtoErr(ErrDoubleClaim, "nullifier %s already authorized at Layer 3", receipt.Nullifier)
	}
	if _, dup := g.authorizedJobs[receipt.JobID]; dup {
		return RewardAuthorization{}, newProtoErr(ErrDoubleClaim, "job %q already authorized at Layer 3", receipt.JobID)
	}

	// 6. Governance epoch treasury cap check.
	epochKey := strconv.FormatUint(receipt.Epoch, 10)
	curEpochSpent := g.balanceSheet.EpochAuthorizedMicroZOO[epochKey]
	if curEpochSpent+receipt.ConsumedMicroZOO > g.policy.EpochTreasuryCapMicroZOO {
		return RewardAuthorization{}, newProtoErr(ErrTreasuryCapExceeded, "epoch %d cap %d exceeded by %d + %d",
			receipt.Epoch, g.policy.EpochTreasuryCapMicroZOO, curEpochSpent, receipt.ConsumedMicroZOO)
	}

	// 7. Construct and sign RewardAuthorization.
	proofCopy := make([]MerkleProofStep, len(proof))
	copy(proofCopy, proof)
	auth := RewardAuthorization{
		ReceiptID:                 receipt.ReceiptID,
		Nullifier:                 receipt.Nullifier,
		JobID:                     receipt.JobID,
		ProviderID:                receipt.ProviderID,
		AuthorityID:               authorityID,
		AuthorityRole:             RoleGovernanceTreasury,
		ReceiptEpoch:              receipt.Epoch,
		FinalizedEpoch:            currentEpoch,
		EpochMerkleRoot:           commitment.ReceiptsMerkleRoot,
		MerkleProof:               proofCopy,
		ProviderShareMicroZOO:     receipt.ProviderShareMicroZOO,
		ConservationShareMicroZOO: receipt.ConservationShareMicroZOO,
		ProtocolFeeMicroZOO:       receipt.ProtocolFeeMicroZOO,
		RefundMicroZOO:            receipt.RefundMicroZOO,
	}
	auth.AuthID = ComputeRewardAuthID(auth)
	auth.TreasurySigHex = SignEd25519Hex(signer.PrivKey, TreasurySignatureMessage(auth))

	if _, err := g.wal.Append("AUTHORIZE_REWARD", walAuthRecord{
		Authorization: auth,
		Consumed:      receipt.ConsumedMicroZOO,
		MaxBudget:     receipt.MaxBudgetMicroZOO,
	}); err != nil {
		return RewardAuthorization{}, fmt.Errorf("wal append authorization: %w", err)
	}

	g.applyAuthorizedLocked(auth, receipt.MaxBudgetMicroZOO, receipt.ConsumedMicroZOO)
	return auth, nil
}

func (g *FinalityTreasuryGate) applyAuthorizedLocked(auth RewardAuthorization, maxBudget, consumed int64) {
	g.authorizedNullifiers[auth.Nullifier] = auth.AuthID
	g.authorizedJobs[auth.JobID] = auth.AuthID
	g.balanceSheet.TotalFinalizedEscrowMicroZOO += maxBudget
	g.balanceSheet.TotalAuthorizedPayoutMicroZOO += consumed
	g.balanceSheet.TotalProviderPayoutMicroZOO += auth.ProviderShareMicroZOO
	g.balanceSheet.ConservationFundMicroZOO += auth.ConservationShareMicroZOO
	g.balanceSheet.ProtocolFeePoolMicroZOO += auth.ProtocolFeeMicroZOO
	g.balanceSheet.TotalPayerRefundsMicroZOO += auth.RefundMicroZOO
	g.balanceSheet.AuthorizedReceiptCount++
	g.balanceSheet.ProviderBalancesMicroZOO[auth.ProviderID] += auth.ProviderShareMicroZOO
	epochKey := strconv.FormatUint(auth.ReceiptEpoch, 10)
	g.balanceSheet.EpochAuthorizedMicroZOO[epochKey] += consumed
	g.balanceSheet.CheckConservation()
}

// BalanceSheetSnapshot returns a deep copy of the deterministic integer balance sheet.
func (g *FinalityTreasuryGate) BalanceSheetSnapshot() BalanceSheet {
	g.mu.Lock()
	defer g.mu.Unlock()
	prov := make(map[string]int64, len(g.balanceSheet.ProviderBalancesMicroZOO))
	for k, v := range g.balanceSheet.ProviderBalancesMicroZOO {
		prov[k] = v
	}
	ep := make(map[string]int64, len(g.balanceSheet.EpochAuthorizedMicroZOO))
	for k, v := range g.balanceSheet.EpochAuthorizedMicroZOO {
		ep[k] = v
	}
	bs := g.balanceSheet
	bs.ProviderBalancesMicroZOO = prov
	bs.EpochAuthorizedMicroZOO = ep
	bs.CheckConservation()
	return bs
}

// ReadOnlyApplicationClient models a downstream Zoo application consuming verified receipts read-only.
type ReadOnlyApplicationClient struct {
	AppID      string
	Settlement *SettlementEngine
}

// ConsumeVerifiedReceipt reads a verified receipt without holding any issuance or treasury privileges.
func (c *ReadOnlyApplicationClient) ConsumeVerifiedReceipt(receiptID string) (UsefulWorkReceipt, bool) {
	return c.Settlement.ReadReceipt(receiptID)
}

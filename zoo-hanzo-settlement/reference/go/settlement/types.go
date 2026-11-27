// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package settlement

import (
	"fmt"
	"regexp"
)

const (
	SchemaVersion = "1.0.0"
	ProtocolID    = "settlement-receipt.v1"

	// MicroZOOPerZOO defines fixed-point micro-unit precision (1 ZOO = 1,000,000 micro-ZOO).
	MicroZOOPerZOO int64 = 1_000_000

	// BPSDenominator is 10,000 basis points = 100.00%.
	BPSDenominator int64 = 10_000

	// DefaultConservationBPS is 200 bps (2.00%) per zoo-hanzo-settlement.tex (ZIP-0700).
	DefaultConservationBPS int64 = 200

	// DefaultProtocolBPS is 100 bps (1.00%) per zoo-hanzo-settlement.tex.
	DefaultProtocolBPS int64 = 100

	// EASSchemaString is the canonical EAS-compatible schema declaration for useful-work attestations.
	EASSchemaString = "settlement-receipt.v1|bytes32 job_id,bytes32 work_hash,address provider_id,uint64 epoch,uint64 tokens_processed,uint64 compute_units,int64 consumed_micro_zoo"
)

// Role enumerates strictly separated authority roles across the 3-layer settlement stack.
type Role string

const (
	RolePayer              Role = "PAYER"
	RoleProvider           Role = "PROVIDER"
	RoleValidator          Role = "VALIDATOR"
	RoleSettlementNode     Role = "SETTLEMENT_NODE"
	RoleGovernanceTreasury Role = "GOVERNANCE_TREASURY"
	RoleApplication        Role = "APPLICATION"
	RoleAIAgent            Role = "AI_AGENT"
)

// ErrorCode is the canonical, cross-language error taxonomy shared by Go and Python verifiers.
type ErrorCode string

const (
	ErrNone                     ErrorCode = ""
	ErrInvalidSchema            ErrorCode = "ERR_INVALID_SCHEMA"
	ErrBudgetOverflow           ErrorCode = "ERR_BUDGET_OVERFLOW"
	ErrSelfVerificationForbid   ErrorCode = "ERR_SELF_VERIFICATION_FORBIDDEN"
	ErrUnauthorizedValidator    ErrorCode = "ERR_UNAUTHORIZED_VALIDATOR"
	ErrInvalidAttestationUID    ErrorCode = "ERR_INVALID_ATTESTATION_UID"
	ErrInvalidSignature         ErrorCode = "ERR_INVALID_SIGNATURE"
	ErrDuplicateValidator       ErrorCode = "ERR_DUPLICATE_VALIDATOR"
	ErrInsufficientQuorum       ErrorCode = "ERR_INSUFFICIENT_QUORUM"
	ErrAttestationMismatch      ErrorCode = "ERR_ATTESTATION_MISMATCH"
	ErrDoubleClaim              ErrorCode = "ERR_DOUBLE_CLAIM"
	ErrInvalidReceiptID         ErrorCode = "ERR_INVALID_RECEIPT_ID"
	ErrInvalidNullifier         ErrorCode = "ERR_INVALID_NULLIFIER"
	ErrAccountingMismatch       ErrorCode = "ERR_ACCOUNTING_MISMATCH"
	ErrInvalidMerkleProof       ErrorCode = "ERR_INVALID_MERKLE_PROOF"
	ErrUnfinalizedEpoch         ErrorCode = "ERR_UNFINALIZED_EPOCH"
	ErrEpochExpired             ErrorCode = "ERR_EPOCH_EXPIRED"
	ErrAppIssuanceForbidden     ErrorCode = "ERR_APP_ISSUANCE_FORBIDDEN"
	ErrAIIssuanceForbidden      ErrorCode = "ERR_AI_ISSUANCE_FORBIDDEN"
	ErrAIPolicyMutationForbid   ErrorCode = "ERR_AI_POLICY_MUTATION_FORBIDDEN"
	ErrUnauthorizedTreasury     ErrorCode = "ERR_UNAUTHORIZED_TREASURY"
	ErrTreasuryCapExceeded      ErrorCode = "ERR_TREASURY_CAP_EXCEEDED"
	ErrKeyRoleConflict          ErrorCode = "ERR_KEY_ROLE_CONFLICT"
)

// ProtocolError wraps a canonical ErrorCode with diagnostic detail.
type ProtocolError struct {
	Code    ErrorCode
	Message string
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func newProtoErr(code ErrorCode, format string, args ...any) *ProtocolError {
	return &ProtocolError{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}

// ErrorCodeOf extracts the canonical ErrorCode from an error, or ErrInvalidSchema if unknown.
func ErrorCodeOf(err error) ErrorCode {
	if err == nil {
		return ErrNone
	}
	if pe, ok := err.(*ProtocolError); ok {
		return pe.Code
	}
	return ErrInvalidSchema
}

var (
	reIdentifier = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	reHex64      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reHex128     = regexp.MustCompile(`^[0-9a-f]{128}$`)
)

func validID(s string) bool     { return reIdentifier.MatchString(s) }
func validHex64(s string) bool  { return reHex64.MatchString(s) }
func validHex128(s string) bool { return reHex128.MatchString(s) }

func validRole(r Role) bool {
	switch r {
	case RolePayer, RoleProvider, RoleValidator, RoleSettlementNode,
		RoleGovernanceTreasury, RoleApplication, RoleAIAgent:
		return true
	default:
		return false
	}
}

// Principal registers an actor's immutable ID, role, and RFC 8032 Ed25519 public key.
type Principal struct {
	ID           string `json:"id"`
	Role         Role   `json:"role"`
	PublicKeyHex string `json:"public_key_hex"`
}

// NetworkPolicy defines governance-authorized parameters for validation, settlement, and finality.
type NetworkPolicy struct {
	ValidatorQuorum          int    `json:"validator_quorum"`
	ValidatorCommitteeSize   int    `json:"validator_committee_size"`
	FinalityDelayEpochs      uint64 `json:"finality_delay_epochs"`
	ClaimWindowEpochs        uint64 `json:"claim_window_epochs"`
	ConservationBPS          int64  `json:"conservation_bps"`
	ProtocolBPS              int64  `json:"protocol_bps"`
	EpochTreasuryCapMicroZOO int64  `json:"epoch_treasury_cap_micro_zoo"`
}

// AdmittedJob is the Layer 1 admitted workload with escrowed max budget.
type AdmittedJob struct {
	JobID             string `json:"job_id"`
	PayerID           string `json:"payer_id"`
	ProviderID        string `json:"provider_id"`
	Epoch             uint64 `json:"epoch"`
	ModelTier         string `json:"model_tier"`
	CorpusPaperID     string `json:"corpus_paper_id"`
	CorpusPaperSHA256 string `json:"corpus_paper_sha256"`
	WorkSpecHash      string `json:"work_spec_hash"`
	MaxBudgetMicroZOO int64  `json:"max_budget_micro_zoo"`
	ConservationBPS   int64  `json:"conservation_bps"`
	ProtocolBPS       int64  `json:"protocol_bps"`
}

// WorkResult is the deterministic output emitted by a provider after performing useful compute.
type WorkResult struct {
	JobID            string `json:"job_id"`
	ProviderID       string `json:"provider_id"`
	OutputDigest     string `json:"output_digest"`
	TokensProcessed  uint64 `json:"tokens_processed"`
	ComputeUnits     uint64 `json:"compute_units"`
	ConsumedMicroZOO int64  `json:"consumed_micro_zoo"`
	WorkHash         string `json:"work_hash"`
}

// EASAttestation is an EAS-compatible structured attestation signed by an independent Layer 1 validator.
type EASAttestation struct {
	AttestationUID   string `json:"attestation_uid"`
	SchemaUID        string `json:"schema_uid"`
	RefUID           string `json:"ref_uid"`
	JobID            string `json:"job_id"`
	Recipient        string `json:"recipient"`
	Attester         string `json:"attester"`
	WorkHash         string `json:"work_hash"`
	Epoch            uint64 `json:"epoch"`
	Nonce            uint64 `json:"nonce"`
	TokensProcessed  uint64 `json:"tokens_processed"`
	ComputeUnits     uint64 `json:"compute_units"`
	ConsumedMicroZOO int64  `json:"consumed_micro_zoo"`
	SignatureHex     string `json:"signature_hex"`
}

// SplitAmounts holds exact integer micro-ZOO shares with zero dust drift.
type SplitAmounts struct {
	ProviderShare     int64
	ConservationShare int64
	ProtocolFee       int64
	Refund            int64
}

// ComputeExactSplit performs exact dust-free int64 micro-ZOO splitting.
// Invariants guaranteed on nil error:
//   - ProviderShare + ConservationShare + ProtocolFee == consumed
//   - consumed + Refund == maxBudget
func ComputeExactSplit(maxBudget, consumed, conservationBPS, protocolBPS int64) (SplitAmounts, error) {
	if maxBudget <= 0 || consumed <= 0 {
		return SplitAmounts{}, newProtoErr(ErrInvalidSchema, "max_budget (%d) and consumed (%d) must be positive", maxBudget, consumed)
	}
	if conservationBPS < 0 || protocolBPS < 0 || conservationBPS+protocolBPS > BPSDenominator {
		return SplitAmounts{}, newProtoErr(ErrInvalidSchema, "invalid bps: conservation=%d protocol=%d", conservationBPS, protocolBPS)
	}
	if consumed > maxBudget {
		return SplitAmounts{}, newProtoErr(ErrBudgetOverflow, "consumed %d exceeds max_budget %d", consumed, maxBudget)
	}
	conservationShare := (consumed * conservationBPS) / BPSDenominator
	protocolFee := (consumed * protocolBPS) / BPSDenominator
	providerShare := consumed - conservationShare - protocolFee
	refund := maxBudget - consumed
	return SplitAmounts{
		ProviderShare:     providerShare,
		ConservationShare: conservationShare,
		ProtocolFee:       protocolFee,
		Refund:            refund,
	}, nil
}

// UsefulWorkReceipt is the Layer 2 settled receipt backed by quorum attestations and a strict nullifier.
type UsefulWorkReceipt struct {
	ReceiptID                string   `json:"receipt_id"`
	Nullifier                string   `json:"nullifier"`
	JobID                    string   `json:"job_id"`
	PayerID                  string   `json:"payer_id"`
	ProviderID               string   `json:"provider_id"`
	IssuerID                 string   `json:"issuer_id"`
	IssuerRole               Role     `json:"issuer_role"`
	WorkHash                 string   `json:"work_hash"`
	Epoch                    uint64   `json:"epoch"`
	MaxBudgetMicroZOO        int64    `json:"max_budget_micro_zoo"`
	ConsumedMicroZOO         int64    `json:"consumed_micro_zoo"`
	ProviderShareMicroZOO    int64    `json:"provider_share_micro_zoo"`
	ConservationShareMicroZOO int64   `json:"conservation_share_micro_zoo"`
	ProtocolFeeMicroZOO      int64    `json:"protocol_fee_micro_zoo"`
	RefundMicroZOO           int64    `json:"refund_micro_zoo"`
	ConservationBPS          int64    `json:"conservation_bps"`
	ProtocolBPS              int64    `json:"protocol_bps"`
	AttestationUIDs          []string `json:"attestation_uids"`
}

// MerkleProofStep is one sibling hash in a binary Merkle inclusion proof.
type MerkleProofStep struct {
	SiblingHex string `json:"sibling_hex"`
	Position   string `json:"position"` // "left" or "right"
}

// EpochCommitment commits the binary Merkle root of all receipts settled in an epoch.
type EpochCommitment struct {
	Epoch             uint64 `json:"epoch"`
	ReceiptCount      int    `json:"receipt_count"`
	ReceiptsMerkleRoot string `json:"receipts_merkle_root"`
}

// RewardAuthorization is the Layer 3 epoch-finalized authorization signed by GOVERNANCE_TREASURY.
type RewardAuthorization struct {
	AuthID                    string            `json:"auth_id"`
	ReceiptID                 string            `json:"receipt_id"`
	Nullifier                 string            `json:"nullifier"`
	JobID                     string            `json:"job_id"`
	ProviderID                string            `json:"provider_id"`
	AuthorityID               string            `json:"authority_id"`
	AuthorityRole             Role              `json:"authority_role"`
	ReceiptEpoch              uint64            `json:"receipt_epoch"`
	FinalizedEpoch            uint64            `json:"finalized_epoch"`
	EpochMerkleRoot           string            `json:"epoch_merkle_root"`
	MerkleProof               []MerkleProofStep `json:"merkle_proof"`
	ProviderShareMicroZOO     int64             `json:"provider_share_micro_zoo"`
	ConservationShareMicroZOO int64             `json:"conservation_share_micro_zoo"`
	ProtocolFeeMicroZOO       int64             `json:"protocol_fee_micro_zoo"`
	RefundMicroZOO            int64             `json:"refund_micro_zoo"`
	TreasurySigHex            string            `json:"treasury_sig_hex"`
}

// PolicyMutationAttempt models an attempt by an actor to modify governance parameters.
type PolicyMutationAttempt struct {
	ActorID       string `json:"actor_id"`
	ActorRole     Role   `json:"actor_role"`
	Field         string `json:"field"`
	ProposedValue int64  `json:"proposed_value"`
}

// BalanceSheet is the deterministic exact-integer accounting ledger across all finalized receipts.
type BalanceSheet struct {
	TotalFinalizedEscrowMicroZOO  int64            `json:"total_finalized_escrow_micro_zoo"`
	TotalAuthorizedPayoutMicroZOO int64            `json:"total_authorized_payout_micro_zoo"`
	TotalProviderPayoutMicroZOO   int64            `json:"total_provider_payout_micro_zoo"`
	ConservationFundMicroZOO      int64            `json:"conservation_fund_micro_zoo"`
	ProtocolFeePoolMicroZOO       int64            `json:"protocol_fee_pool_micro_zoo"`
	TotalPayerRefundsMicroZOO     int64            `json:"total_payer_refunds_micro_zoo"`
	AuthorizedReceiptCount        int              `json:"authorized_receipt_count"`
	ProviderBalancesMicroZOO      map[string]int64 `json:"provider_balances_micro_zoo"`
	EpochAuthorizedMicroZOO       map[string]int64 `json:"epoch_authorized_micro_zoo"`
	ConservationExact             bool             `json:"conservation_exact"`
}

// CheckConservation verifies all exact integer conservation identities on the BalanceSheet.
func (b *BalanceSheet) CheckConservation() bool {
	var providerSum int64
	for _, v := range b.ProviderBalancesMicroZOO {
		if v < 0 {
			return false
		}
		providerSum += v
	}
	var epochSum int64
	for _, v := range b.EpochAuthorizedMicroZOO {
		if v < 0 {
			return false
		}
		epochSum += v
	}
	ok := providerSum == b.TotalProviderPayoutMicroZOO &&
		b.TotalProviderPayoutMicroZOO+b.ConservationFundMicroZOO+b.ProtocolFeePoolMicroZOO == b.TotalAuthorizedPayoutMicroZOO &&
		b.TotalAuthorizedPayoutMicroZOO+b.TotalPayerRefundsMicroZOO == b.TotalFinalizedEscrowMicroZOO &&
		epochSum == b.TotalAuthorizedPayoutMicroZOO
	b.ConservationExact = ok
	return ok
}

// TraceCase represents one verifiable lifecycle or adversarial event in a SettlementTraceBundle.
type TraceCase struct {
	CaseID                        string                 `json:"case_id"`
	Category                      string                 `json:"category"` // "lifecycle", "adversarial", "key_separation"
	Stage                         string                 `json:"stage"`    // "VERIFY", "ISSUE_RECEIPT", "AUTHORIZE_REWARD", "POLICY_MUTATION", "KEY_AUDIT"
	Description                   string                 `json:"description,omitempty"`
	Job                           *AdmittedJob           `json:"job,omitempty"`
	WorkResult                    *WorkResult            `json:"work_result,omitempty"`
	Attestations                  []EASAttestation       `json:"attestations,omitempty"`
	Receipt                       *UsefulWorkReceipt     `json:"receipt,omitempty"`
	Authorization                 *RewardAuthorization   `json:"authorization,omitempty"`
	PolicyMutation                *PolicyMutationAttempt `json:"policy_mutation,omitempty"`
	OverridePrincipals            []Principal            `json:"override_principals,omitempty"`
	OverrideEpochTreasuryCapMicro int64                  `json:"override_epoch_treasury_cap_micro_zoo,omitempty"`
	ExpectedVerdict               string                 `json:"expected_verdict"` // "ACCEPT" or "REJECT"
	ExpectedError                 ErrorCode              `json:"expected_error"`
}

// SettlementTraceBundle is the complete canonical artifact verified identically by Go and Python.
type SettlementTraceBundle struct {
	SchemaVersion           string            `json:"schema_version"`
	Protocol                string            `json:"protocol"`
	EASSchemaUID            string            `json:"eas_schema_uid"`
	Seed                    uint64            `json:"seed"`
	Policy                  NetworkPolicy     `json:"policy"`
	Principals              []Principal       `json:"principals"`
	EpochCommitments        []EpochCommitment `json:"epoch_commitments"`
	Cases                   []TraceCase       `json:"cases"`
	ExpectedBalanceSheet    BalanceSheet      `json:"expected_balance_sheet"`
	ExpectedAuditMerkleRoot string            `json:"expected_audit_merkle_root"`
}

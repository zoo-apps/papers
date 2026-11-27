// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package settlement

import (
	"fmt"
	"strconv"
)

// CaseVerdict captures the deterministic verification outcome for one TraceCase.
type CaseVerdict struct {
	CaseID                    string    `json:"case_id"`
	Category                  string    `json:"category"`
	Stage                     string    `json:"stage"`
	Verdict                   string    `json:"verdict"` // "ACCEPT" or "REJECT"
	ErrorCode                 ErrorCode `json:"error_code"`
	ExpectedVerdict           string    `json:"expected_verdict"`
	ExpectedError             ErrorCode `json:"expected_error"`
	MatchedExpectation        bool      `json:"matched_expectation"`
	ReceiptID                 string    `json:"receipt_id"`
	Nullifier                 string    `json:"nullifier"`
	ProviderShareMicroZOO     int64     `json:"provider_share_micro_zoo"`
	ConservationShareMicroZOO int64     `json:"conservation_share_micro_zoo"`
	ProtocolFeeMicroZOO       int64     `json:"protocol_fee_micro_zoo"`
	RefundMicroZOO            int64     `json:"refund_micro_zoo"`
}

// VerificationReport summarizes independent trace verification and audit Merkle commitment.
type VerificationReport struct {
	SchemaVersion      string        `json:"schema_version"`
	Protocol           string        `json:"protocol"`
	TotalCases         int           `json:"total_cases"`
	AcceptedCases      int           `json:"accepted_cases"`
	RejectedCases      int           `json:"rejected_cases"`
	MatchedCount       int           `json:"matched_count"`
	AllMatched         bool          `json:"all_matched"`
	ConservationExact  bool          `json:"conservation_exact"`
	BalanceSheet       BalanceSheet  `json:"balance_sheet"`
	AuditMerkleRoot    string        `json:"audit_merkle_root"`
	ExpectedAuditRoot  string        `json:"expected_audit_merkle_root"`
	AuditRootMatched   bool          `json:"audit_root_matched"`
	CaseVerdicts       []CaseVerdict `json:"case_verdicts"`
}

func verifyAuthorizationAuthorityRole(auth RewardAuthorization, principals map[string]Principal) (Principal, error) {
	if auth.AuthorityRole == RoleApplication {
		return Principal{}, newProtoErr(ErrAppIssuanceForbidden, "application %q cannot authorize rewards", auth.AuthorityID)
	}
	if auth.AuthorityRole == RoleAIAgent {
		return Principal{}, newProtoErr(ErrAIIssuanceForbidden, "ai agent %q cannot authorize treasury disbursement", auth.AuthorityID)
	}
	p, ok := principals[auth.AuthorityID]
	if !ok {
		return Principal{}, newProtoErr(ErrUnauthorizedTreasury, "unknown authority %q", auth.AuthorityID)
	}
	if p.Role == RoleApplication {
		return Principal{}, newProtoErr(ErrAppIssuanceForbidden, "application %q cannot authorize rewards", auth.AuthorityID)
	}
	if p.Role == RoleAIAgent {
		return Principal{}, newProtoErr(ErrAIIssuanceForbidden, "ai agent %q cannot authorize treasury disbursement", auth.AuthorityID)
	}
	if p.Role != RoleGovernanceTreasury || auth.AuthorityRole != RoleGovernanceTreasury {
		return Principal{}, newProtoErr(ErrUnauthorizedTreasury, "authority %q role %s is not GOVERNANCE_TREASURY", auth.AuthorityID, p.Role)
	}
	return p, nil
}

func verifyReceiptIssuerRole(receipt UsefulWorkReceipt, principals map[string]Principal) error {
	if receipt.IssuerRole == RoleApplication {
		return newProtoErr(ErrAppIssuanceForbidden, "application %q cannot issue receipts", receipt.IssuerID)
	}
	if receipt.IssuerRole == RoleAIAgent {
		return newProtoErr(ErrAIIssuanceForbidden, "ai agent %q cannot issue receipts", receipt.IssuerID)
	}
	p, ok := principals[receipt.IssuerID]
	if !ok {
		return newProtoErr(ErrInvalidSchema, "unknown receipt issuer %q", receipt.IssuerID)
	}
	if p.Role == RoleApplication {
		return newProtoErr(ErrAppIssuanceForbidden, "application %q cannot issue receipts", receipt.IssuerID)
	}
	if p.Role == RoleAIAgent {
		return newProtoErr(ErrAIIssuanceForbidden, "ai agent %q cannot issue receipts", receipt.IssuerID)
	}
	if p.Role != RoleSettlementNode || receipt.IssuerRole != RoleSettlementNode {
		return newProtoErr(ErrUnauthorizedTreasury, "issuer %q role %s is not SETTLEMENT_NODE", receipt.IssuerID, p.Role)
	}
	return nil
}

// VerifyTraceBundle independently verifies every case in a SettlementTraceBundle,
// checks exact integer accounting conservation, and computes the canonical audit_merkle_root.
func VerifyTraceBundle(bundle SettlementTraceBundle) (VerificationReport, error) {
	if bundle.SchemaVersion != SchemaVersion || bundle.Protocol != ProtocolID {
		return VerificationReport{}, newProtoErr(ErrInvalidSchema, "unsupported schema %s / protocol %s", bundle.SchemaVersion, bundle.Protocol)
	}
	if bundle.EASSchemaUID != CanonicalEASSchemaUID() {
		return VerificationReport{}, newProtoErr(ErrInvalidSchema, "bundle eas_schema_uid mismatch")
	}
	principals, err := ValidatePrincipalKeySeparation(bundle.Principals)
	if err != nil {
		return VerificationReport{}, err
	}

	commitments := make(map[uint64]EpochCommitment, len(bundle.EpochCommitments))
	for _, c := range bundle.EpochCommitments {
		commitments[c.Epoch] = c
	}

	settledNullifiers := make(map[string]bool)
	settledJobs := make(map[string]bool)
	authorizedNullifiers := make(map[string]bool)
	authorizedJobs := make(map[string]bool)

	bs := BalanceSheet{
		ProviderBalancesMicroZOO: make(map[string]int64),
		EpochAuthorizedMicroZOO:  make(map[string]int64),
		ConservationExact:        true,
	}

	verdicts := make([]CaseVerdict, 0, len(bundle.Cases))
	auditLeaves := make([]string, 0, len(bundle.Cases)+1)
	acceptedCount := 0
	rejectedCount := 0
	matchedCount := 0

	for _, tc := range bundle.Cases {
		var caseErr error
		var receiptID, nullifier string
		var provShare, consShare, protoFee, refund int64

		switch tc.Stage {
		case "KEY_AUDIT":
			_, caseErr = ValidatePrincipalKeySeparation(tc.OverridePrincipals)

		case "POLICY_MUTATION":
			if tc.PolicyMutation == nil {
				caseErr = newProtoErr(ErrInvalidSchema, "missing policy_mutation")
			} else {
				caseErr = ValidatePolicyMutation(*tc.PolicyMutation, principals)
			}

		case "VERIFY":
			if tc.Job == nil || tc.WorkResult == nil {
				caseErr = newProtoErr(ErrInvalidSchema, "missing job or work_result")
			} else {
				caseErr = ValidateQuorumAttestations(*tc.Job, *tc.WorkResult, tc.Attestations, principals, bundle.Policy)
			}

		case "ISSUE_RECEIPT":
			if tc.Job == nil || tc.WorkResult == nil || tc.Receipt == nil {
				caseErr = newProtoErr(ErrInvalidSchema, "missing job, work_result, or receipt")
			} else {
				receiptID = tc.Receipt.ReceiptID
				nullifier = tc.Receipt.Nullifier
				caseErr = verifyReceiptIssuerRole(*tc.Receipt, principals)
				if caseErr == nil {
					caseErr = ValidateQuorumAttestations(*tc.Job, *tc.WorkResult, tc.Attestations, principals, bundle.Policy)
				}
				if caseErr == nil {
					caseErr = ValidateReceiptIntegrity(*tc.Job, *tc.WorkResult, tc.Attestations, *tc.Receipt, principals)
				}
				if caseErr == nil {
					if settledNullifiers[tc.Receipt.Nullifier] || settledJobs[tc.Receipt.JobID] {
						caseErr = newProtoErr(ErrDoubleClaim, "duplicate nullifier or job_id at Layer 2")
					}
				}
				if caseErr == nil {
					settledNullifiers[tc.Receipt.Nullifier] = true
					settledJobs[tc.Receipt.JobID] = true
					provShare = tc.Receipt.ProviderShareMicroZOO
					consShare = tc.Receipt.ConservationShareMicroZOO
					protoFee = tc.Receipt.ProtocolFeeMicroZOO
					refund = tc.Receipt.RefundMicroZOO
				}
			}

		case "AUTHORIZE_REWARD":
			if tc.Job == nil || tc.WorkResult == nil || tc.Receipt == nil || tc.Authorization == nil {
				caseErr = newProtoErr(ErrInvalidSchema, "missing fields for AUTHORIZE_REWARD")
			} else {
				r := *tc.Receipt
				a := *tc.Authorization
				receiptID = r.ReceiptID
				nullifier = r.Nullifier

				var authPrincipal Principal
				authPrincipal, caseErr = verifyAuthorizationAuthorityRole(a, principals)
				if caseErr == nil {
					caseErr = ValidateQuorumAttestations(*tc.Job, *tc.WorkResult, tc.Attestations, principals, bundle.Policy)
				}
				if caseErr == nil {
					caseErr = ValidateReceiptIntegrity(*tc.Job, *tc.WorkResult, tc.Attestations, r, principals)
				}
				if caseErr == nil {
					if a.ReceiptID != r.ReceiptID || a.Nullifier != r.Nullifier || a.JobID != r.JobID ||
						a.ProviderID != r.ProviderID || a.ReceiptEpoch != r.Epoch {
						caseErr = newProtoErr(ErrInvalidSchema, "authorization metadata disagrees with receipt")
					}
				}
				if caseErr == nil {
					if a.ProviderShareMicroZOO != r.ProviderShareMicroZOO ||
						a.ConservationShareMicroZOO != r.ConservationShareMicroZOO ||
						a.ProtocolFeeMicroZOO != r.ProtocolFeeMicroZOO ||
						a.RefundMicroZOO != r.RefundMicroZOO {
						caseErr = newProtoErr(ErrAccountingMismatch, "authorization share split disagrees with receipt")
					}
				}
				if caseErr == nil {
					if a.FinalizedEpoch < r.Epoch+bundle.Policy.FinalityDelayEpochs {
						caseErr = newProtoErr(ErrUnfinalizedEpoch, "epoch %d unfinalized at %d", r.Epoch, a.FinalizedEpoch)
					} else if a.FinalizedEpoch > r.Epoch+bundle.Policy.ClaimWindowEpochs {
						caseErr = newProtoErr(ErrEpochExpired, "epoch %d expired at %d", r.Epoch, a.FinalizedEpoch)
					}
				}
				if caseErr == nil {
					comm, ok := commitments[r.Epoch]
					if !ok || a.EpochMerkleRoot != comm.ReceiptsMerkleRoot {
						caseErr = newProtoErr(ErrInvalidMerkleProof, "epoch commitment root mismatch for epoch %d", r.Epoch)
					} else {
						leaf := ComputeReceiptMerkleLeaf(r.ReceiptID, r.Nullifier, r.ConsumedMicroZOO)
						if !VerifyMerkleProof(leaf, a.MerkleProof, comm.ReceiptsMerkleRoot) {
							caseErr = newProtoErr(ErrInvalidMerkleProof, "merkle proof verification failed")
						}
					}
				}
				if caseErr == nil {
					wantAuthID := ComputeRewardAuthID(a)
					if a.AuthID != wantAuthID {
						caseErr = newProtoErr(ErrInvalidSchema, "auth_id mismatch")
					} else if !VerifyEd25519Hex(authPrincipal.PublicKeyHex, TreasurySignatureMessage(a), a.TreasurySigHex) {
						caseErr = newProtoErr(ErrInvalidSignature, "treasury Ed25519 signature invalid")
					}
				}
				if caseErr == nil {
					if authorizedNullifiers[r.Nullifier] || authorizedJobs[r.JobID] {
						caseErr = newProtoErr(ErrDoubleClaim, "nullifier or job already authorized")
					}
				}
				if caseErr == nil {
					capLimit := bundle.Policy.EpochTreasuryCapMicroZOO
					if tc.OverrideEpochTreasuryCapMicro > 0 {
						capLimit = tc.OverrideEpochTreasuryCapMicro
					}
					epKey := strconv.FormatUint(r.Epoch, 10)
					if bs.EpochAuthorizedMicroZOO[epKey]+r.ConsumedMicroZOO > capLimit {
						caseErr = newProtoErr(ErrTreasuryCapExceeded, "epoch %d treasury cap %d exceeded", r.Epoch, capLimit)
					}
				}
				if caseErr == nil {
					settledNullifiers[r.Nullifier] = true
					settledJobs[r.JobID] = true
					authorizedNullifiers[r.Nullifier] = true
					authorizedJobs[r.JobID] = true

					bs.TotalFinalizedEscrowMicroZOO += r.MaxBudgetMicroZOO
					bs.TotalAuthorizedPayoutMicroZOO += r.ConsumedMicroZOO
					bs.TotalProviderPayoutMicroZOO += r.ProviderShareMicroZOO
					bs.ConservationFundMicroZOO += r.ConservationShareMicroZOO
					bs.ProtocolFeePoolMicroZOO += r.ProtocolFeeMicroZOO
					bs.TotalPayerRefundsMicroZOO += r.RefundMicroZOO
					bs.AuthorizedReceiptCount++
					bs.ProviderBalancesMicroZOO[r.ProviderID] += r.ProviderShareMicroZOO
					epKey := strconv.FormatUint(r.Epoch, 10)
					bs.EpochAuthorizedMicroZOO[epKey] += r.ConsumedMicroZOO

					provShare = r.ProviderShareMicroZOO
					consShare = r.ConservationShareMicroZOO
					protoFee = r.ProtocolFeeMicroZOO
					refund = r.RefundMicroZOO
				}
			}

		default:
			caseErr = newProtoErr(ErrInvalidSchema, "unknown trace stage %q", tc.Stage)
		}

		verdict := "ACCEPT"
		errCode := ErrNone
		if caseErr != nil {
			verdict = "REJECT"
			errCode = ErrorCodeOf(caseErr)
			rejectedCount++
		} else {
			acceptedCount++
		}

		matched := verdict == tc.ExpectedVerdict && errCode == tc.ExpectedError
		if matched {
			matchedCount++
		}

		verdicts = append(verdicts, CaseVerdict{
			CaseID:                    tc.CaseID,
			Category:                  tc.Category,
			Stage:                     tc.Stage,
			Verdict:                   verdict,
			ErrorCode:                 errCode,
			ExpectedVerdict:           tc.ExpectedVerdict,
			ExpectedError:             tc.ExpectedError,
			MatchedExpectation:        matched,
			ReceiptID:                 receiptID,
			Nullifier:                 nullifier,
			ProviderShareMicroZOO:     provShare,
			ConservationShareMicroZOO: consShare,
			ProtocolFeeMicroZOO:       protoFee,
			RefundMicroZOO:            refund,
		})

		auditLeaves = append(auditLeaves, ComputeAuditCaseLeaf(
			tc.CaseID, tc.Stage, verdict, errCode, receiptID, nullifier,
			provShare, consShare, protoFee, refund,
		))
	}

	conservationExact := bs.CheckConservation()
	auditLeaves = append(auditLeaves, ComputeAuditBalanceSheetLeaf(bs))
	auditRoot := ComputeMerkleRoot(auditLeaves)

	report := VerificationReport{
		SchemaVersion:     bundle.SchemaVersion,
		Protocol:          bundle.Protocol,
		TotalCases:        len(bundle.Cases),
		AcceptedCases:     acceptedCount,
		RejectedCases:     rejectedCount,
		MatchedCount:      matchedCount,
		AllMatched:        matchedCount == len(bundle.Cases),
		ConservationExact: conservationExact,
		BalanceSheet:      bs,
		AuditMerkleRoot:   auditRoot,
		ExpectedAuditRoot: bundle.ExpectedAuditMerkleRoot,
		AuditRootMatched:  bundle.ExpectedAuditMerkleRoot == "" || auditRoot == bundle.ExpectedAuditMerkleRoot,
		CaseVerdicts:      verdicts,
	}
	if !conservationExact {
		return report, fmt.Errorf("accounting conservation failed")
	}
	return report, nil
}

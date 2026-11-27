// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package settlement

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// SHA256Hex returns the lowercase 64-char hex SHA-256 digest of s.
func SHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// SHA256BytesHex returns the lowercase 64-char hex SHA-256 digest of b.
func SHA256BytesHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// DeriveEd25519Key deterministically derives an RFC 8032 Ed25519 keypair for test-network simulations.
func DeriveEd25519Key(seed uint64, label string) (ed25519.PublicKey, ed25519.PrivateKey) {
	seedDigest := sha256.Sum256([]byte(fmt.Sprintf("ed25519-key:v1|%d|%s", seed, label)))
	priv := ed25519.NewKeyFromSeed(seedDigest[:])
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv
}

// SignEd25519Hex signs msg with priv and returns the 128-char lowercase hex signature.
func SignEd25519Hex(priv ed25519.PrivateKey, msg string) string {
	sig := ed25519.Sign(priv, []byte(msg))
	return hex.EncodeToString(sig)
}

// VerifyEd25519Hex verifies a 128-char hex Ed25519 signature against a 64-char hex public key.
func VerifyEd25519Hex(pubHex, msg, sigHex string) bool {
	if !validHex64(pubHex) || !validHex128(sigHex) {
		return false
	}
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), []byte(msg), sig)
}

// CanonicalEASSchemaUID returns the canonical EAS schema UID for settlement-receipt.v1.
func CanonicalEASSchemaUID() string {
	return SHA256Hex("eas-schema:v1|" + EASSchemaString)
}

// ComputeRefUID returns the canonical EAS refUID binding an attestation to an admitted job.
func ComputeRefUID(jobID string) string {
	return SHA256Hex("job:v1|" + jobID)
}

// ComputeWorkHash returns the canonical SHA-256 digest binding corpus input, spec, output, and metered usage.
func ComputeWorkHash(jobID, corpusPaperSHA256, workSpecHash, outputDigest string, tokensProcessed, computeUnits uint64) string {
	preimage := fmt.Sprintf("work:v1|%s|%s|%s|%s|%d|%d",
		jobID, corpusPaperSHA256, workSpecHash, outputDigest, tokensProcessed, computeUnits)
	return SHA256Hex(preimage)
}

// ComputeAttestationUID computes the EAS-compatible AttestationUID:
// SHA256("eas-attestation:v1|" || schemaUID || "|" || refUID || "|" || recipient || "|" || attester || "|" || workHash || "|" || epoch || "|" || nonce)
func ComputeAttestationUID(schemaUID, refUID, recipient, attester, workHash string, epoch, nonce uint64) string {
	preimage := fmt.Sprintf("eas-attestation:v1|%s|%s|%s|%s|%s|%d|%d",
		schemaUID, refUID, recipient, attester, workHash, epoch, nonce)
	return SHA256Hex(preimage)
}

// ValidatorSignatureMessage returns the canonical UTF-8 payload signed by a Layer 1 validator.
func ValidatorSignatureMessage(att EASAttestation) string {
	return fmt.Sprintf("eas-sig:v1|%s|%s|%s|%s|%s|%d|%d|%d|%d|%d",
		att.AttestationUID,
		att.JobID,
		att.Recipient,
		att.Attester,
		att.WorkHash,
		att.Epoch,
		att.Nonce,
		att.ConsumedMicroZOO,
		att.TokensProcessed,
		att.ComputeUnits,
	)
}

// ComputeReceiptID returns the canonical Layer 2 UsefulWorkReceipt identifier.
func ComputeReceiptID(jobID, providerID, payerID, workHash string, epoch uint64, maxBudget, consumed, conservationBPS, protocolBPS int64, attestationUIDs []string) string {
	sortedUIDs := make([]string, len(attestationUIDs))
	copy(sortedUIDs, attestationUIDs)
	sort.Strings(sortedUIDs)
	preimage := fmt.Sprintf("receipt:v1|%s|%s|%s|%s|%d|%d|%d|%d|%d|%s",
		jobID, providerID, payerID, workHash, epoch,
		maxBudget, consumed, conservationBPS, protocolBPS,
		strings.Join(sortedUIDs, ","),
	)
	return SHA256Hex(preimage)
}

// ComputeReceiptNullifier computes the strict anti-double-claim nullifier:
// SHA256("nullifier:v1|" || job_id || "|" || receipt_id || "|" || work_hash)
func ComputeReceiptNullifier(jobID, receiptID, workHash string) string {
	return SHA256Hex(fmt.Sprintf("nullifier:v1|%s|%s|%s", jobID, receiptID, workHash))
}

// ComputeRewardAuthID returns the canonical Layer 3 RewardAuthorization identifier.
func ComputeRewardAuthID(auth RewardAuthorization) string {
	preimage := fmt.Sprintf("reward-auth:v1|%s|%s|%s|%s|%d|%d|%d|%d|%d|%d|%s",
		auth.ReceiptID,
		auth.Nullifier,
		auth.JobID,
		auth.ProviderID,
		auth.ReceiptEpoch,
		auth.FinalizedEpoch,
		auth.ProviderShareMicroZOO,
		auth.ConservationShareMicroZOO,
		auth.ProtocolFeeMicroZOO,
		auth.RefundMicroZOO,
		auth.EpochMerkleRoot,
	)
	return SHA256Hex(preimage)
}

// TreasurySignatureMessage returns the canonical UTF-8 payload signed by GOVERNANCE_TREASURY.
func TreasurySignatureMessage(auth RewardAuthorization) string {
	return fmt.Sprintf("treasury-auth:v1|%s|%s|%s|%d",
		auth.AuthID,
		auth.AuthorityID,
		string(auth.AuthorityRole),
		auth.FinalizedEpoch,
	)
}

// ComputeAuditCaseLeaf hashes one trace case verdict into a canonical audit Merkle leaf.
func ComputeAuditCaseLeaf(caseID, stage, verdict string, errCode ErrorCode, receiptID, nullifier string, providerShare, conservationShare, protocolFee, refund int64) string {
	preimage := fmt.Sprintf("audit-leaf:v1|%s|%s|%s|%s|%s|%s|%d|%d|%d|%d",
		caseID, stage, verdict, string(errCode), receiptID, nullifier,
		providerShare, conservationShare, protocolFee, refund,
	)
	return SHA256Hex(preimage)
}

// ComputeAuditBalanceSheetLeaf hashes the final deterministic balance sheet into an audit Merkle leaf.
func ComputeAuditBalanceSheetLeaf(bs BalanceSheet) string {
	keys := make([]string, 0, len(bs.ProviderBalancesMicroZOO))
	for k := range bs.ProviderBalancesMicroZOO {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, len(keys))
	for i, k := range keys {
		pairs[i] = k + ":" + strconv.FormatInt(bs.ProviderBalancesMicroZOO[k], 10)
	}
	preimage := fmt.Sprintf("balance-sheet:v1|escrow=%d|authorized=%d|provider=%d|conservation=%d|protocol=%d|refund=%d|%s",
		bs.TotalFinalizedEscrowMicroZOO,
		bs.TotalAuthorizedPayoutMicroZOO,
		bs.TotalProviderPayoutMicroZOO,
		bs.ConservationFundMicroZOO,
		bs.ProtocolFeePoolMicroZOO,
		bs.TotalPayerRefundsMicroZOO,
		strings.Join(pairs, ","),
	)
	return SHA256Hex(preimage)
}

// ValidatePrincipalKeySeparation enforces that all registered principals have valid IDs/roles/keys
// and pairwise disjoint Ed25519 public keys across separated authority layers.
func ValidatePrincipalKeySeparation(principals []Principal) (map[string]Principal, error) {
	byID := make(map[string]Principal, len(principals))
	byPub := make(map[string]Principal, len(principals))
	for _, p := range principals {
		if !validID(p.ID) || !validRole(p.Role) || !validHex64(p.PublicKeyHex) {
			return nil, newProtoErr(ErrInvalidSchema, "invalid principal record %q", p.ID)
		}
		if _, dupID := byID[p.ID]; dupID {
			return nil, newProtoErr(ErrKeyRoleConflict, "duplicate principal id %q", p.ID)
		}
		if existing, dupPub := byPub[p.PublicKeyHex]; dupPub {
			return nil, newProtoErr(ErrKeyRoleConflict, "public key conflict between %s (%s) and %s (%s)", existing.ID, existing.Role, p.ID, p.Role)
		}
		byID[p.ID] = p
		byPub[p.PublicKeyHex] = p
	}
	return byID, nil
}

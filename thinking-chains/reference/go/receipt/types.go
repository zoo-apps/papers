// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation and Contributors

// Package receipt implements the Thinking Chains canonical execution receipt
// serializer, RFC 6962 provenance Merkle tree, and independent Ed25519 verifier.
package receipt

import "fmt"

const (
	SchemaVersion           = "zoo.thinking-chains.receipt.v1"
	EmptyMerkleDomainPrefix = "zoo.thinking-chains.merkle.empty.v1:"
	ResultDomainPrefix      = "zoo.thinking-chains.result.v1:"
	ReceiptDomainPrefix     = "zoo.thinking-chains.receipt.v1\x00"
	AttestationDomainPrefix = "zoo.thinking-chains.attestation.v1\x00"
)

// VerificationError is a deterministic error carrying a standardized error code.
type VerificationError struct {
	Code    string
	Message string
}

func (e *VerificationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func newError(code, format string, args ...any) *VerificationError {
	return &VerificationError{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}

// VerificationResult reports the canonical identifiers of a verified receipt.
type VerificationResult struct {
	JobID                 string `json:"job_id"`
	CanonicalReceiptHash  string `json:"canonical_receipt_hash"`
	ProvenanceRoot        string `json:"provenance_root"`
	ValidAttestationCount int    `json:"valid_attestations"`
}

// ProvenanceCommitment holds all recomputed provenance Merkle roots.
type ProvenanceCommitment struct {
	HashAlgorithm   string `json:"hash_algorithm"`
	DomainSeparator string `json:"domain_separator"`
	InputsRoot      string `json:"inputs_root"`
	ToolsRoot       string `json:"tools_root"`
	EvidenceRoot    string `json:"evidence_root"`
	ChecksRoot      string `json:"checks_root"`
	ResultDigest    string `json:"result_digest"`
	ProvenanceRoot  string `json:"provenance_root"`
}

// ProfilePolicy defines an authorized execution profile in a PolicyBundle.
type ProfilePolicy struct {
	AllowedModels          []string `json:"allowed_models"`
	AllowedModelSpecHashes []string `json:"allowed_model_spec_hashes"`
	AllowedTiers           []string `json:"allowed_tiers"`
	AllowedEvidenceModes   []string `json:"allowed_evidence_modes"`
	AllowedTools           []string `json:"allowed_tools"`
	MaxRecursionDepth      int64    `json:"max_recursion_depth"`
	MaxOutputBytes         int64    `json:"max_output_bytes"`
	MinVerifiers           int64    `json:"min_verifiers"`
}

// TrustedVerifier defines a registered independent verifier identity and public key.
type TrustedVerifier struct {
	PublicKeyHex string   `json:"public_key_hex"`
	AllowedRoles []string `json:"allowed_roles"`
}

// PolicyBundle holds the authorized execution profiles and trusted verifiers registry.
type PolicyBundle struct {
	PolicyVersion      string                     `json:"policy_version"`
	AuthorizedProfiles map[string]ProfilePolicy   `json:"authorized_profiles"`
	TrustedVerifiers   map[string]TrustedVerifier `json:"trusted_verifiers"`
}

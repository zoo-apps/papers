// Copyright 2026 Zoo Labs Foundation & Hanzo Industries.
// SPDX-License-Identifier: Apache-2.0

package poai

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	SchemaVersion      = "poai-transcript.v1"
	SpecVersion        = "1.0.0"
	KernelProfile      = "int8-whole-k-i32-fp2147483647.v1"
	SignatureAlgorithm = "Ed25519-RFC8032"

	ChallengeModeBinary = "binary_01"
	ChallengeModeField  = "field_fp"

	ChallengeSourceExternal   = "external_verifier_nonce"
	ChallengeSourceFiatShamir = "fiat_shamir"

	VerdictComputeVerified   = "COMPUTE_VERIFIED"
	VerdictComputeCorrupted  = "COMPUTE_CORRUPTED"
	VerdictInvalidTranscript = "INVALID_TRANSCRIPT"
	VerdictPolicyRejected    = "POLICY_REJECTED"

	ErrBadSchemaVersion            = "ERR_BAD_SCHEMA_VERSION"
	ErrBadKernelProfile            = "ERR_BAD_KERNEL_PROFILE"
	ErrBadModulus                  = "ERR_BAD_MODULUS"
	ErrBadDimensions               = "ERR_BAD_DIMENSIONS"
	ErrBadChallengeMode            = "ERR_BAD_CHALLENGE_MODE"
	ErrBadChallengeSource          = "ERR_BAD_CHALLENGE_SOURCE"
	ErrCommitmentMismatchA         = "ERR_COMMITMENT_MISMATCH_A"
	ErrCommitmentMismatchB         = "ERR_COMMITMENT_MISMATCH_B"
	ErrCommitmentMismatchC         = "ERR_COMMITMENT_MISMATCH_C"
	ErrTraceRootMismatch           = "ERR_TRACE_ROOT_MISMATCH"
	ErrHeaderDigestMismatch        = "ERR_HEADER_DIGEST_MISMATCH"
	ErrTranscriptIDMismatch        = "ERR_TRANSCRIPT_ID_MISMATCH"
	ErrInvalidSignature            = "ERR_INVALID_SIGNATURE"
	ErrChallengeSeedMismatch       = "ERR_CHALLENGE_SEED_MISMATCH"
	ErrFreivaldsMismatch           = "ERR_FREIVALDS_MISMATCH"
	ErrWeakFiatShamirGrindingRisk  = "ERR_WEAK_FIAT_SHAMIR_GRINDING_RISK"
	ErrForbiddenGovernanceAction   = "ERR_FORBIDDEN_GOVERNANCE_ACTION"
	ErrForbiddenSemanticClaim      = "ERR_FORBIDDEN_SEMANTIC_CLAIM"

	domainHeader  = "poai:v1:header:"
	domainReceipt = "poai:v1:receipt:"
)

// MatrixDims holds the matrix product dimensions (A: m x d, B: d x n, C: m x n).
type MatrixDims struct {
	M int `json:"m"`
	D int `json:"d"`
	N int `json:"n"`
}

// MatrixCommitments holds canonical flat SHA-256 and row-Merkle commitments.
type MatrixCommitments struct {
	MatrixARoot          string `json:"matrix_a_root"`
	MatrixBRoot          string `json:"matrix_b_root"`
	MatrixCRoot          string `json:"matrix_c_root"`
	MatrixASHA256        string `json:"matrix_a_sha256"`
	MatrixBSHA256        string `json:"matrix_b_sha256"`
	MatrixCSHA256        string `json:"matrix_c_sha256"`
	ActivationTraceRoot  string `json:"activation_trace_root"`
	CorpusManifestSHA256 string `json:"corpus_manifest_sha256"`
}

// SemanticMetadata carries optional non-binding annotations used to demonstrate
// constitutional separation and enforce governance prohibitions.
type SemanticMetadata struct {
	ClaimedModelPurpose       string `json:"claimed_model_purpose,omitempty"`
	ClaimedTruthStatement     string `json:"claimed_truth_statement,omitempty"`
	WeightsAttested           bool   `json:"weights_attested"`
	NonlinearitiesVerified    bool   `json:"nonlinearities_verified"`
	RequestedGovernanceAction string `json:"requested_governance_action,omitempty"`
}

// TranscriptHeader is the canonically serialized, Ed25519-signed header of poai-transcript.v1.
type TranscriptHeader struct {
	JobID             string            `json:"job_id"`
	PolicyEpoch       uint64            `json:"policy_epoch"`
	KernelProfile     string            `json:"kernel_profile"`
	ModelID           string            `json:"model_id"`
	LayerIndex        uint32            `json:"layer_index"`
	Dims              MatrixDims        `json:"dims"`
	FieldModulus      int64             `json:"field_modulus"`
	ChallengeMode     string            `json:"challenge_mode"`
	ChallengeSource   string            `json:"challenge_source"`
	ChallengeRoundsK  int               `json:"challenge_rounds_k"`
	VerifierNonceHex  string            `json:"verifier_nonce_hex"`
	ProverSaltHex     string            `json:"prover_salt_hex"`
	Commitments       MatrixCommitments `json:"commitments"`
	ProviderPubKeyHex string            `json:"provider_pubkey_hex"`
	SemanticMetadata  *SemanticMetadata `json:"semantic_metadata,omitempty"`
}

// SignatureBlock holds the RFC 8032 Ed25519 signature over the canonical header digest.
type SignatureBlock struct {
	Algorithm       string `json:"algorithm"`
	HeaderDigestHex string `json:"header_digest_hex"`
	SignatureHex    string `json:"signature_hex"`
}

// RoundDigest records the canonical SHA-256 digests of one Freivalds challenge round.
type RoundDigest struct {
	Round     int    `json:"round"`
	RSHA256   string `json:"r_sha256"`
	ABRSHA256 string `json:"abr_sha256"`
	CRSHA256  string `json:"cr_sha256"`
	Matched   bool   `json:"matched"`
}

// ChallengeTranscript records the deterministic challenge seed and per-round Freivalds digests.
type ChallengeTranscript struct {
	ChallengeSeedHex            string        `json:"challenge_seed_hex"`
	TheoreticalFalseAcceptBound string        `json:"theoretical_false_accept_bound"`
	RoundsExecuted              int           `json:"rounds_executed"`
	FirstFailingRound           int           `json:"first_failing_round"`
	RoundDigests                []RoundDigest `json:"round_digests"`
}

// ConstitutionalBoundary hard-enforces the distinction between mechanical matrix-product
// verification and semantic, full-model, or governance claims.
type ConstitutionalBoundary struct {
	ComputeVerdict           string   `json:"compute_verdict"`
	ProvesMatrixProductOnly  bool     `json:"proves_matrix_product_only"`
	ProvesFullModelInference bool     `json:"proves_full_model_inference"`
	ProvesScientificTruth    bool     `json:"proves_scientific_truth"`
	ProvesWeightProvenance   bool     `json:"proves_weight_provenance"`
	GrindingRiskWarning      bool     `json:"grinding_risk_warning"`
	ErrorCodes               []string `json:"error_codes"`
}

// Transcript is the top-level poai-transcript.v1 document.
type Transcript struct {
	SchemaVersion          string                 `json:"schema_version"`
	SpecVersion            string                 `json:"spec_version"`
	TranscriptID           string                 `json:"transcript_id"`
	Header                 TranscriptHeader       `json:"header"`
	Signature              SignatureBlock         `json:"signature"`
	ChallengeTranscript    ChallengeTranscript    `json:"challenge_transcript"`
	ConstitutionalBoundary ConstitutionalBoundary `json:"constitutional_boundary"`
}

// VerificationReceipt is the canonical verifier output for a single transcript.
type VerificationReceipt struct {
	TranscriptID           string                 `json:"transcript_id"`
	HeaderDigestHex        string                 `json:"header_digest_hex"`
	ChallengeSeedHex       string                 `json:"challenge_seed_hex"`
	RoundsExecuted         int                    `json:"rounds_executed"`
	FirstFailingRound      int                    `json:"first_failing_round"`
	RoundDigests           []RoundDigest          `json:"round_digests"`
	ConstitutionalBoundary ConstitutionalBoundary `json:"constitutional_boundary"`
}

func writeLPString(buf *bytes.Buffer, s string) {
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(s)))
	buf.Write(lenBuf[:])
	buf.WriteString(s)
}

func writeU32(buf *bytes.Buffer, v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	buf.Write(b[:])
}

func writeU64(buf *bytes.Buffer, v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	buf.Write(b[:])
}

func writeHex32(buf *bytes.Buffer, fieldName, hexStr string) error {
	raw, err := hex.DecodeString(hexStr)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("invalid 32-byte hex for %s", fieldName)
	}
	buf.Write(raw)
	return nil
}

// CanonicalHeaderBytes produces the deterministic binary serialization of the transcript header.
func CanonicalHeaderBytes(schemaVersion, specVersion string, h *TranscriptHeader) ([]byte, error) {
	if h == nil {
		return nil, fmt.Errorf("nil header")
	}
	var buf bytes.Buffer
	buf.WriteString(domainHeader)
	writeLPString(&buf, schemaVersion)
	writeLPString(&buf, specVersion)
	writeLPString(&buf, h.JobID)
	writeU64(&buf, h.PolicyEpoch)
	writeLPString(&buf, h.KernelProfile)
	writeLPString(&buf, h.ModelID)
	writeU32(&buf, h.LayerIndex)
	writeU32(&buf, uint32(h.Dims.M))
	writeU32(&buf, uint32(h.Dims.D))
	writeU32(&buf, uint32(h.Dims.N))
	writeU64(&buf, uint64(h.FieldModulus))
	writeLPString(&buf, h.ChallengeMode)
	writeLPString(&buf, h.ChallengeSource)
	writeU32(&buf, uint32(h.ChallengeRoundsK))
	writeLPString(&buf, h.VerifierNonceHex)
	writeLPString(&buf, h.ProverSaltHex)

	hexFields := []struct {
		name string
		val  string
	}{
		{"matrix_a_root", h.Commitments.MatrixARoot},
		{"matrix_b_root", h.Commitments.MatrixBRoot},
		{"matrix_c_root", h.Commitments.MatrixCRoot},
		{"matrix_a_sha256", h.Commitments.MatrixASHA256},
		{"matrix_b_sha256", h.Commitments.MatrixBSHA256},
		{"matrix_c_sha256", h.Commitments.MatrixCSHA256},
		{"activation_trace_root", h.Commitments.ActivationTraceRoot},
		{"corpus_manifest_sha256", h.Commitments.CorpusManifestSHA256},
		{"provider_pubkey_hex", h.ProviderPubKeyHex},
	}
	for _, f := range hexFields {
		if err := writeHex32(&buf, f.name, f.val); err != nil {
			return nil, err
		}
	}

	if h.SemanticMetadata == nil {
		buf.WriteByte(0x00)
	} else {
		buf.WriteByte(0x01)
		writeLPString(&buf, h.SemanticMetadata.ClaimedModelPurpose)
		writeLPString(&buf, h.SemanticMetadata.ClaimedTruthStatement)
		if h.SemanticMetadata.WeightsAttested {
			buf.WriteByte(0x01)
		} else {
			buf.WriteByte(0x00)
		}
		if h.SemanticMetadata.NonlinearitiesVerified {
			buf.WriteByte(0x01)
		} else {
			buf.WriteByte(0x00)
		}
		writeLPString(&buf, h.SemanticMetadata.RequestedGovernanceAction)
	}
	return buf.Bytes(), nil
}

// ComputeHeaderDigest computes SHA-256 over the canonical header bytes.
func ComputeHeaderDigest(schemaVersion, specVersion string, h *TranscriptHeader) ([32]byte, error) {
	b, err := CanonicalHeaderBytes(schemaVersion, specVersion, h)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// DeriveProviderKeyPair deterministically derives an Ed25519 keypair from a domain-labeled seed
// for reproducible benchmarks and test fixtures (never for production custody).
func DeriveProviderKeyPair(label string, seed uint64) (ed25519.PublicKey, ed25519.PrivateKey) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], seed)
	h := sha256.New()
	h.Write([]byte("poai:v1:deterministic-bench-signer:"))
	h.Write([]byte(label))
	h.Write(b[:])
	seedBytes := h.Sum(nil)
	priv := ed25519.NewKeyFromSeed(seedBytes)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv
}

// BuildParams configures BuildTranscript for creating a canonical signed transcript.
type BuildParams struct {
	JobID                string
	PolicyEpoch          uint64
	ModelID              string
	LayerIndex           uint32
	ChallengeMode        string
	ChallengeSource      string
	ChallengeRoundsK     int
	VerifierNonceHex     string
	ProverSaltHex        string
	CorpusManifestSHA256 string
	ProviderPrivKey      ed25519.PrivateKey
	SemanticMetadata     *SemanticMetadata
}

// ComputeCommitments builds all canonical matrix commitments for (A, B, C).
func ComputeCommitments(a, b *Int8Matrix, c *Int64Matrix, corpusManifestSHA256 string) MatrixCommitments {
	aRoot := Int8MatrixMerkleRoot(a, 'A')
	bRoot := Int8MatrixMerkleRoot(b, 'B')
	cRoot := Int64MatrixMerkleRoot(c, 'C')
	aSHA := Int8MatrixSHA256(a, 'A')
	bSHA := Int8MatrixSHA256(b, 'B')
	cSHA := Int64MatrixSHA256(c, 'C')
	traceRoot := ActivationTraceRoot(aRoot, bRoot, cRoot)
	return MatrixCommitments{
		MatrixARoot:          hex.EncodeToString(aRoot[:]),
		MatrixBRoot:          hex.EncodeToString(bRoot[:]),
		MatrixCRoot:          hex.EncodeToString(cRoot[:]),
		MatrixASHA256:        hex.EncodeToString(aSHA[:]),
		MatrixBSHA256:        hex.EncodeToString(bSHA[:]),
		MatrixCSHA256:        hex.EncodeToString(cSHA[:]),
		ActivationTraceRoot:  hex.EncodeToString(traceRoot[:]),
		CorpusManifestSHA256: corpusManifestSHA256,
	}
}

// BuildTranscript creates a fully signed poai-transcript.v1 document for matrices (A, B, C)
// and evaluates its Freivalds challenge rounds and constitutional boundary.
func BuildTranscript(params BuildParams, a, b *Int8Matrix, c *Int64Matrix) (*Transcript, error) {
	if a == nil || b == nil || c == nil {
		return nil, fmt.Errorf("nil matrix")
	}
	if len(params.ProviderPrivKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key length")
	}
	pub := params.ProviderPrivKey.Public().(ed25519.PublicKey)
	commitments := ComputeCommitments(a, b, c, params.CorpusManifestSHA256)
	header := TranscriptHeader{
		JobID:             params.JobID,
		PolicyEpoch:       params.PolicyEpoch,
		KernelProfile:     KernelProfile,
		ModelID:           params.ModelID,
		LayerIndex:        params.LayerIndex,
		Dims:              MatrixDims{M: a.Rows, D: a.Cols, N: b.Cols},
		FieldModulus:      FieldModulus,
		ChallengeMode:     params.ChallengeMode,
		ChallengeSource:   params.ChallengeSource,
		ChallengeRoundsK:  params.ChallengeRoundsK,
		VerifierNonceHex:  params.VerifierNonceHex,
		ProverSaltHex:     params.ProverSaltHex,
		Commitments:       commitments,
		ProviderPubKeyHex: hex.EncodeToString(pub),
		SemanticMetadata:  params.SemanticMetadata,
	}

	headerDigest, err := ComputeHeaderDigest(SchemaVersion, SpecVersion, &header)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(params.ProviderPrivKey, headerDigest[:])

	chSeed, err := DeriveChallengeSeed(params.ChallengeSource, headerDigest, params.VerifierNonceHex, params.ProverSaltHex)
	if err != nil {
		return nil, err
	}

	tx := &Transcript{
		SchemaVersion: SchemaVersion,
		SpecVersion:   SpecVersion,
		TranscriptID:  hex.EncodeToString(headerDigest[:]),
		Header:        header,
		Signature: SignatureBlock{
			Algorithm:       SignatureAlgorithm,
			HeaderDigestHex: hex.EncodeToString(headerDigest[:]),
			SignatureHex:    hex.EncodeToString(sig),
		},
		ChallengeTranscript: ChallengeTranscript{
			ChallengeSeedHex:            hex.EncodeToString(chSeed[:]),
			TheoreticalFalseAcceptBound: TheoreticalFalseAcceptBound(params.ChallengeMode, params.ChallengeRoundsK),
			FirstFailingRound:           -1,
			RoundDigests:                []RoundDigest{},
		},
		ConstitutionalBoundary: ConstitutionalBoundary{
			ComputeVerdict:           VerdictComputeVerified,
			ProvesMatrixProductOnly:  true,
			ProvesFullModelInference: false,
			ProvesScientificTruth:    false,
			ProvesWeightProvenance:   false,
			GrindingRiskWarning:      HasWeakFiatShamirRisk(params.ChallengeSource, params.ChallengeMode, params.ChallengeRoundsK),
			ErrorCodes:               []string{},
		},
	}

	receipt := VerifyTranscript(tx, a, b, c)
	tx.ChallengeTranscript.RoundsExecuted = receipt.RoundsExecuted
	tx.ChallengeTranscript.FirstFailingRound = receipt.FirstFailingRound
	tx.ChallengeTranscript.RoundDigests = receipt.RoundDigests
	tx.ConstitutionalBoundary = receipt.ConstitutionalBoundary
	return tx, nil
}

// AuditReceiptLeaf computes the canonical leaf digest for a VerificationReceipt.
func AuditReceiptLeaf(r VerificationReceipt) [32]byte {
	payload := fmt.Sprintf(
		"%s%s|%s|%s|%s|%s|%d",
		domainReceipt,
		r.TranscriptID,
		r.ConstitutionalBoundary.ComputeVerdict,
		strings.Join(r.ConstitutionalBoundary.ErrorCodes, ","),
		r.HeaderDigestHex,
		r.ChallengeSeedHex,
		r.FirstFailingRound,
	)
	return sha256.Sum256([]byte(payload))
}

// ComputeAuditMerkleRoot computes the canonical SHA-256 Merkle root over an ordered slice of receipts.
func ComputeAuditMerkleRoot(receipts []VerificationReceipt) string {
	leaves := make([][32]byte, len(receipts))
	for i, r := range receipts {
		leaves[i] = AuditReceiptLeaf(r)
	}
	root := MerkleRoot(leaves)
	return hex.EncodeToString(root[:])
}

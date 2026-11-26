// Copyright 2026 Zoo Labs Foundation & Hanzo Industries.
// SPDX-License-Identifier: Apache-2.0

package poai

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
)

const (
	domainChallengeExternal   = "poai:v1:challenge:external:"
	domainChallengeFiatShamir = "poai:v1:challenge:fiat-shamir:"
	domainRound               = "poai:v1:round:"
)

// TheoreticalFalseAcceptBound returns the human- and machine-readable soundness bound string.
func TheoreticalFalseAcceptBound(mode string, k int) string {
	if k <= 0 {
		return "invalid"
	}
	switch mode {
	case ChallengeModeBinary:
		log10p := -float64(k) * math.Log10(2.0)
		return fmt.Sprintf("2^-%d (%s)", k, formatNegLog10(log10p))
	case ChallengeModeField:
		log10p := -float64(k) * math.Log10(float64(FieldModulus))
		return fmt.Sprintf("(2^31-1)^-%d (%s)", k, formatNegLog10(log10p))
	default:
		return "unknown"
	}
}

func formatNegLog10(log10Val float64) string {
	exp := math.Floor(log10Val)
	mant := math.Pow(10.0, log10Val-exp)
	if mant >= 9.9999995 {
		mant = 1.0
		exp += 1.0
	}
	return fmt.Sprintf("%.6fe%+03.0f", mant, exp)
}

// HasWeakFiatShamirRisk returns true when non-interactive Fiat-Shamir is paired with a
// false-accept probability exceeding 2^-40 (allowing practical prover grinding).
func HasWeakFiatShamirRisk(source, mode string, k int) bool {
	if source != ChallengeSourceFiatShamir {
		return false
	}
	switch mode {
	case ChallengeModeBinary:
		return k < 40
	case ChallengeModeField:
		// One F_p round has error ~2^-31 (> 2^-40); k >= 2 gives ~2^-62 (< 2^-40).
		return k < 2
	default:
		return true
	}
}

// DeriveChallengeSeed computes the deterministic 32-byte challenge seed from headerDigest
// and either the external verifier nonce or the prover salt (Fiat-Shamir).
func DeriveChallengeSeed(source string, headerDigest [32]byte, verifierNonceHex, proverSaltHex string) ([32]byte, error) {
	h := sha256.New()
	switch source {
	case ChallengeSourceExternal:
		nonce, err := hex.DecodeString(verifierNonceHex)
		if err != nil || len(nonce) != 32 {
			return [32]byte{}, fmt.Errorf("external_verifier_nonce requires 32-byte hex verifier_nonce_hex")
		}
		h.Write([]byte(domainChallengeExternal))
		h.Write(headerDigest[:])
		h.Write(nonce)
	case ChallengeSourceFiatShamir:
		salt, err := hex.DecodeString(proverSaltHex)
		if err != nil || (len(salt) != 0 && len(salt) != 16) {
			return [32]byte{}, fmt.Errorf("fiat_shamir requires empty or 16-byte hex prover_salt_hex")
		}
		h.Write([]byte(domainChallengeFiatShamir))
		h.Write(headerDigest[:])
		h.Write(salt)
	default:
		return [32]byte{}, fmt.Errorf("unsupported challenge source: %q", source)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// DeriveChallengeVector deterministically generates round vector r_t of length n
// using SHA-256 counter-mode PRG per SPEC.md Section 4.2.
func DeriveChallengeVector(mode string, challengeSeed [32]byte, round uint32, n int) ([]int64, error) {
	if n <= 0 {
		return nil, fmt.Errorf("invalid vector length %d", n)
	}
	var seedBuf [14 + 32 + 4]byte
	copy(seedBuf[0:14], domainRound)
	copy(seedBuf[14:46], challengeSeed[:])
	binary.LittleEndian.PutUint32(seedBuf[46:50], round)
	roundSeed := sha256.Sum256(seedBuf[:])

	out := make([]int64, n)
	var ctrBuf [36]byte
	copy(ctrBuf[0:32], roundSeed[:])

	switch mode {
	case ChallengeModeBinary:
		var block [32]byte
		blockIdx := uint32(0)
		haveBlock := false
		for j := 0; j < n; j++ {
			bytePos := j >> 3
			needBlock := uint32(bytePos >> 5)
			if !haveBlock || needBlock != blockIdx {
				blockIdx = needBlock
				binary.LittleEndian.PutUint32(ctrBuf[32:36], blockIdx)
				block = sha256.Sum256(ctrBuf[:])
				haveBlock = true
			}
			b := block[bytePos&31]
			out[j] = int64((b >> uint(j&7)) & 1)
		}
		return out, nil

	case ChallengeModeField:
		// Rejection-sample exact uniform elements in [0, 2^31 - 2] = [0, p-1].
		blockIdx := uint32(0)
		wordPos := 8 // force initial block generation
		var block [32]byte
		filled := 0
		for filled < n {
			if wordPos >= 8 {
				binary.LittleEndian.PutUint32(ctrBuf[32:36], blockIdx)
				block = sha256.Sum256(ctrBuf[:])
				blockIdx++
				wordPos = 0
			}
			w := binary.LittleEndian.Uint32(block[wordPos*4 : (wordPos+1)*4])
			wordPos++
			v := w & 0x7FFFFFFF
			if v == 0x7FFFFFFF {
				// Exact rejection of v == p = 2^31 - 1 (occurs with probability 2^-31).
				continue
			}
			out[filled] = int64(v)
			filled++
		}
		return out, nil

	default:
		return nil, fmt.Errorf("unsupported challenge mode: %q", mode)
	}
}

// RunFreivaldsRound executes a single Freivalds verification round:
// checks A*(B*r) == C*r (mod p) and returns canonical digests.
func RunFreivaldsRound(a, b *Int8Matrix, c *Int64Matrix, r []int64, binaryMode bool, round int) (RoundDigest, bool) {
	br := MatVecInt8ModP(b, r, binaryMode)
	abr := MatVecInt8ModP(a, br, false)
	cr := MatVecInt64ModP(c, r, binaryMode)

	matched := len(abr) == len(cr)
	if matched {
		for i := range abr {
			if abr[i] != cr[i] {
				matched = false
				break
			}
		}
	}

	rHash := VecSHA256(r)
	abrHash := VecSHA256(abr)
	crHash := VecSHA256(cr)
	return RoundDigest{
		Round:     round,
		RSHA256:   hex.EncodeToString(rHash[:]),
		ABRSHA256: hex.EncodeToString(abrHash[:]),
		CRSHA256:  hex.EncodeToString(crHash[:]),
		Matched:   matched,
	}, matched
}

// FastFreivaldsCheck runs k Freivalds rounds with early exit on first mismatch (for high-throughput benchmarking).
// Returns (passed, roundsExecuted).
func FastFreivaldsCheck(a, b *Int8Matrix, c *Int64Matrix, mode string, challengeSeed [32]byte, k int) (bool, int, error) {
	binaryMode := mode == ChallengeModeBinary
	for t := 0; t < k; t++ {
		r, err := DeriveChallengeVector(mode, challengeSeed, uint32(t), b.Cols)
		if err != nil {
			return false, t, err
		}
		br := MatVecInt8ModP(b, r, binaryMode)
		abr := MatVecInt8ModP(a, br, false)
		cr := MatVecInt64ModP(c, r, binaryMode)
		for i := range abr {
			if abr[i] != cr[i] {
				return false, t + 1, nil
			}
		}
	}
	return true, k, nil
}

func isForbiddenGovernanceAction(action string) bool {
	switch action {
	case "redefine_voting_rules", "authorize_treasury", "self_declare_valid":
		return true
	default:
		return false
	}
}

func addErr(errSet map[string]struct{}, code string) {
	errSet[code] = struct{}{}
}

func sortedErrs(errSet map[string]struct{}) []string {
	out := make([]string, 0, len(errSet))
	for k := range errSet {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// VerifyTranscript performs complete independent verification of a poai-transcript.v1 document
// against matrices (A, B, C), enforcing constitutional guards, commitments, Ed25519 signature,
// challenge derivation, and Freivalds checks.
func VerifyTranscript(tx *Transcript, a, b *Int8Matrix, c *Int64Matrix) VerificationReceipt {
	errSet := map[string]struct{}{}
	receipt := VerificationReceipt{
		FirstFailingRound: -1,
		RoundDigests:      []RoundDigest{},
		ConstitutionalBoundary: ConstitutionalBoundary{
			ComputeVerdict:           VerdictInvalidTranscript,
			ProvesMatrixProductOnly:  true,
			ProvesFullModelInference: false,
			ProvesScientificTruth:    false,
			ProvesWeightProvenance:   false,
			GrindingRiskWarning:      false,
			ErrorCodes:               []string{},
		},
	}

	if tx == nil {
		addErr(errSet, ErrBadSchemaVersion)
		receipt.ConstitutionalBoundary.ErrorCodes = sortedErrs(errSet)
		return receipt
	}

	receipt.TranscriptID = tx.TranscriptID
	receipt.HeaderDigestHex = tx.Signature.HeaderDigestHex
	receipt.ChallengeSeedHex = tx.ChallengeTranscript.ChallengeSeedHex

	// 1. Constitutional pre-gate (non-bypassable): reject forbidden autonomous governance or
	//    attempts to assert semantic truth / full-model proof flags.
	policyViolation := false
	if tx.Header.SemanticMetadata != nil && isForbiddenGovernanceAction(tx.Header.SemanticMetadata.RequestedGovernanceAction) {
		addErr(errSet, ErrForbiddenGovernanceAction)
		policyViolation = true
	}
	if tx.ConstitutionalBoundary.ProvesFullModelInference ||
		tx.ConstitutionalBoundary.ProvesScientificTruth ||
		tx.ConstitutionalBoundary.ProvesWeightProvenance ||
		!tx.ConstitutionalBoundary.ProvesMatrixProductOnly {
		addErr(errSet, ErrForbiddenSemanticClaim)
		policyViolation = true
	}

	// 2. Structural & protocol version validation.
	structuralError := false
	if tx.SchemaVersion != SchemaVersion || tx.SpecVersion != SpecVersion {
		addErr(errSet, ErrBadSchemaVersion)
		structuralError = true
	}
	if tx.Header.KernelProfile != KernelProfile {
		addErr(errSet, ErrBadKernelProfile)
		structuralError = true
	}
	if tx.Header.FieldModulus != FieldModulus {
		addErr(errSet, ErrBadModulus)
		structuralError = true
	}
	if tx.Header.ChallengeMode != ChallengeModeBinary && tx.Header.ChallengeMode != ChallengeModeField {
		addErr(errSet, ErrBadChallengeMode)
		structuralError = true
	}
	if tx.Header.ChallengeSource != ChallengeSourceExternal && tx.Header.ChallengeSource != ChallengeSourceFiatShamir {
		addErr(errSet, ErrBadChallengeSource)
		structuralError = true
	}
	if tx.Header.ChallengeRoundsK < 1 || tx.Header.ChallengeRoundsK > 256 {
		addErr(errSet, ErrBadDimensions)
		structuralError = true
	}

	// Check dimensions match matrices.
	dims := tx.Header.Dims
	if a == nil || b == nil || c == nil ||
		dims.M <= 0 || dims.D <= 0 || dims.N <= 0 ||
		dims.M > MaxDimension || dims.D > MaxDimension || dims.N > MaxDimension ||
		a.Rows != dims.M || a.Cols != dims.D ||
		b.Rows != dims.D || b.Cols != dims.N ||
		c.Rows != dims.M || c.Cols != dims.N ||
		len(a.Data) != dims.M*dims.D ||
		len(b.Data) != dims.D*dims.N ||
		len(c.Data) != dims.M*dims.N {
		addErr(errSet, ErrBadDimensions)
		structuralError = true
	}

	// Grinding risk warning (informational warning code when Fiat-Shamir bound > 2^-40).
	if HasWeakFiatShamirRisk(tx.Header.ChallengeSource, tx.Header.ChallengeMode, tx.Header.ChallengeRoundsK) {
		receipt.ConstitutionalBoundary.GrindingRiskWarning = true
		addErr(errSet, ErrWeakFiatShamirGrindingRisk)
	}

	// 3. Matrix commitments & trace root verification (if matrices & dims valid).
	if !structuralError {
		aRoot := Int8MatrixMerkleRoot(a, 'A')
		bRoot := Int8MatrixMerkleRoot(b, 'B')
		cRoot := Int64MatrixMerkleRoot(c, 'C')
		aSHA := Int8MatrixSHA256(a, 'A')
		bSHA := Int8MatrixSHA256(b, 'B')
		cSHA := Int64MatrixSHA256(c, 'C')
		traceRoot := ActivationTraceRoot(aRoot, bRoot, cRoot)

		if hex.EncodeToString(aRoot[:]) != tx.Header.Commitments.MatrixARoot ||
			hex.EncodeToString(aSHA[:]) != tx.Header.Commitments.MatrixASHA256 {
			addErr(errSet, ErrCommitmentMismatchA)
			structuralError = true
		}
		if hex.EncodeToString(bRoot[:]) != tx.Header.Commitments.MatrixBRoot ||
			hex.EncodeToString(bSHA[:]) != tx.Header.Commitments.MatrixBSHA256 {
			addErr(errSet, ErrCommitmentMismatchB)
			structuralError = true
		}
		if hex.EncodeToString(cRoot[:]) != tx.Header.Commitments.MatrixCRoot ||
			hex.EncodeToString(cSHA[:]) != tx.Header.Commitments.MatrixCSHA256 {
			addErr(errSet, ErrCommitmentMismatchC)
			structuralError = true
		}
		if hex.EncodeToString(traceRoot[:]) != tx.Header.Commitments.ActivationTraceRoot {
			addErr(errSet, ErrTraceRootMismatch)
			structuralError = true
		}
	}

	// 4. Canonical header digest, transcript ID, and RFC 8032 Ed25519 signature.
	headerDigest, err := ComputeHeaderDigest(tx.SchemaVersion, tx.SpecVersion, &tx.Header)
	if err != nil {
		addErr(errSet, ErrHeaderDigestMismatch)
		structuralError = true
	} else {
		digestHex := hex.EncodeToString(headerDigest[:])
		receipt.HeaderDigestHex = digestHex
		if digestHex != tx.Signature.HeaderDigestHex {
			addErr(errSet, ErrHeaderDigestMismatch)
			structuralError = true
		}
		if digestHex != tx.TranscriptID {
			addErr(errSet, ErrTranscriptIDMismatch)
			structuralError = true
		}
		pubBytes, pubErr := hex.DecodeString(tx.Header.ProviderPubKeyHex)
		sigBytes, sigErr := hex.DecodeString(tx.Signature.SignatureHex)
		if tx.Signature.Algorithm != SignatureAlgorithm ||
			pubErr != nil || len(pubBytes) != ed25519.PublicKeySize ||
			sigErr != nil || len(sigBytes) != ed25519.SignatureSize ||
			!ed25519.Verify(ed25519.PublicKey(pubBytes), headerDigest[:], sigBytes) {
			addErr(errSet, ErrInvalidSignature)
			structuralError = true
		}
	}

	// 5. Challenge seed derivation.
	chSeed, chErr := DeriveChallengeSeed(tx.Header.ChallengeSource, headerDigest, tx.Header.VerifierNonceHex, tx.Header.ProverSaltHex)
	if chErr != nil {
		addErr(errSet, ErrChallengeSeedMismatch)
		structuralError = true
	} else {
		chSeedHex := hex.EncodeToString(chSeed[:])
		receipt.ChallengeSeedHex = chSeedHex
		if tx.ChallengeTranscript.ChallengeSeedHex != "" && chSeedHex != tx.ChallengeTranscript.ChallengeSeedHex {
			addErr(errSet, ErrChallengeSeedMismatch)
			structuralError = true
		}
	}

	// Policy rejection takes precedence over compute verdict (non-bypassable constitutional gate).
	if policyViolation {
		receipt.ConstitutionalBoundary.ComputeVerdict = VerdictPolicyRejected
		receipt.ConstitutionalBoundary.ErrorCodes = sortedErrs(errSet)
		return receipt
	}

	if structuralError {
		receipt.ConstitutionalBoundary.ComputeVerdict = VerdictInvalidTranscript
		receipt.ConstitutionalBoundary.ErrorCodes = sortedErrs(errSet)
		return receipt
	}

	// 6. Execute all k Freivalds rounds deterministically and record canonical digests.
	binaryMode := tx.Header.ChallengeMode == ChallengeModeBinary
	allMatched := true
	firstFail := -1
	digests := make([]RoundDigest, 0, tx.Header.ChallengeRoundsK)
	for t := 0; t < tx.Header.ChallengeRoundsK; t++ {
		r, err := DeriveChallengeVector(tx.Header.ChallengeMode, chSeed, uint32(t), dims.N)
		if err != nil {
			addErr(errSet, ErrBadChallengeMode)
			receipt.ConstitutionalBoundary.ComputeVerdict = VerdictInvalidTranscript
			receipt.ConstitutionalBoundary.ErrorCodes = sortedErrs(errSet)
			return receipt
		}
		rd, matched := RunFreivaldsRound(a, b, c, r, binaryMode, t)
		digests = append(digests, rd)
		if !matched {
			allMatched = false
			if firstFail == -1 {
				firstFail = t
			}
		}
	}

	receipt.RoundsExecuted = len(digests)
	receipt.FirstFailingRound = firstFail
	receipt.RoundDigests = digests

	if !allMatched {
		addErr(errSet, ErrFreivaldsMismatch)
		receipt.ConstitutionalBoundary.ComputeVerdict = VerdictComputeCorrupted
	} else {
		receipt.ConstitutionalBoundary.ComputeVerdict = VerdictComputeVerified
	}
	receipt.ConstitutionalBoundary.ErrorCodes = sortedErrs(errSet)
	return receipt
}

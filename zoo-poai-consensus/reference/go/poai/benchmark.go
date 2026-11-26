// Copyright 2026 Zoo Labs Foundation & Hanzo Industries.
// SPDX-License-Identifier: Apache-2.0

package poai

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"
)

const (
	CorruptionSingleBitflip = "single_element_bitflip"
	CorruptionSinglePlusOne = "single_element_plus_one"
	CorruptionRowSwap       = "row_swap"
	CorruptionLowRank       = "low_rank_perturbation"
	CorruptionLazyZero      = "lazy_zero_output"
)

// AllCorruptionClasses lists the 5 benchmarked corruption classes in canonical order.
var AllCorruptionClasses = []string{
	CorruptionSingleBitflip,
	CorruptionSinglePlusOne,
	CorruptionRowSwap,
	CorruptionLowRank,
	CorruptionLazyZero,
}

// CorpusFileEntry pins a real .tex file in zoo-apps/papers.
type CorpusFileEntry struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	Role   string `json:"role"`
}

// CorpusManifest represents corpus-manifest.json.
type CorpusManifest struct {
	SchemaVersion  string            `json:"schema_version"`
	Issue          string            `json:"issue"`
	HIP            string            `json:"hip"`
	Description    string            `json:"description"`
	DerivationRule string            `json:"derivation_rule"`
	Files          []CorpusFileEntry `json:"files"`
}

// VerifiedCorpus holds the verified manifest and its canonical SHA-256 roots.
type VerifiedCorpus struct {
	Manifest       CorpusManifest
	ManifestSHA256 [32]byte
	CorpusRoot     [32]byte
}

// LoadAndVerifyCorpus reads corpus-manifest.json and verifies every pinned .tex file on disk.
func LoadAndVerifyCorpus(repoRoot, manifestPath string) (*VerifiedCorpus, error) {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var manifest CorpusManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if len(manifest.Files) == 0 {
		return nil, fmt.Errorf("corpus manifest has no files")
	}

	leaves := make([][32]byte, len(manifest.Files))
	for i, entry := range manifest.Files {
		fullPath := filepath.Join(repoRoot, entry.Path)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			return nil, fmt.Errorf("read corpus file %s: %w", entry.Path, err)
		}
		if int64(len(data)) != entry.Bytes {
			return nil, fmt.Errorf("corpus file %s byte count mismatch: got %d, want %d", entry.Path, len(data), entry.Bytes)
		}
		sum := sha256.Sum256(data)
		gotHex := hex.EncodeToString(sum[:])
		if gotHex != entry.SHA256 {
			return nil, fmt.Errorf("corpus file %s sha256 mismatch: got %s, want %s", entry.Path, gotHex, entry.SHA256)
		}
		leaves[i] = sum
	}

	return &VerifiedCorpus{
		Manifest:       manifest,
		ManifestSHA256: sha256.Sum256(raw),
		CorpusRoot:     MerkleRoot(leaves),
	}, nil
}

// DeriveTile deterministically derives a quantized int8 matrix tile from the verified corpus root.
func DeriveTile(corpusRoot [32]byte, seed uint64, label string, rows, cols int) *Int8Matrix {
	m := NewInt8Matrix(rows, cols)
	var seedBytes [8]byte
	binary.LittleEndian.PutUint64(seedBytes[:], seed)

	baseH := sha256.New()
	baseH.Write([]byte("poai:v1:tile:"))
	baseH.Write(corpusRoot[:])
	baseH.Write(seedBytes[:])
	baseH.Write([]byte(label))
	tileSeed := baseH.Sum(nil)

	total := rows * cols
	var ctrBuf [36]byte
	copy(ctrBuf[0:32], tileSeed)
	blockIdx := uint32(0)
	pos := 0
	for pos < total {
		binary.LittleEndian.PutUint32(ctrBuf[32:36], blockIdx)
		block := sha256.Sum256(ctrBuf[:])
		blockIdx++
		for j := 0; j < 32 && pos < total; j++ {
			m.Data[pos] = int8(block[j])
			pos++
		}
	}
	return m
}

// DeriveNonceHex deterministically derives a 32-byte hex verifier nonce for reproducible runs.
func DeriveNonceHex(seed uint64, label string) string {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], seed)
	h := sha256.New()
	h.Write([]byte("poai:v1:verifier-nonce:"))
	h.Write(b[:])
	h.Write([]byte(label))
	return hex.EncodeToString(h.Sum(nil))
}

// InjectCorruption returns a corrupted copy of C for the given corruption class and trial index.
func InjectCorruption(c *Int64Matrix, class string, trial int) (*Int64Matrix, error) {
	out := c.Clone()
	rows, cols := out.Rows, out.Cols
	switch class {
	case CorruptionSingleBitflip:
		r := (trial*7 + 3) % rows
		col := (trial*13 + 5) % cols
		out.Data[r*cols+col] ^= 1
	case CorruptionSinglePlusOne:
		r := (trial*11 + 2) % rows
		col := (trial*17 + 1) % cols
		out.Data[r*cols+col] += 1
	case CorruptionRowSwap:
		if rows < 2 {
			return nil, fmt.Errorf("row_swap requires rows >= 2")
		}
		r1 := trial % rows
		r2 := (r1 + 1 + (trial/rows)%(rows-1)) % rows
		// Ensure the two rows actually differ (guaranteed for random tiles; fallback if equal).
		differs := false
		for j := 0; j < cols; j++ {
			if out.Data[r1*cols+j] != out.Data[r2*cols+j] {
				differs = true
				break
			}
		}
		if !differs {
			out.Data[r1*cols] += 1
		}
		for j := 0; j < cols; j++ {
			out.Data[r1*cols+j], out.Data[r2*cols+j] = out.Data[r2*cols+j], out.Data[r1*cols+j]
		}
	case CorruptionLowRank:
		// Add rank-1 outer product u * v^T where u, v have sparse nonzero entries in {-1, +1}.
		rIdx := (trial*5 + 1) % rows
		cIdx := (trial*9 + 2) % cols
		for i := 0; i < rows; i++ {
			var u int64
			if (i+rIdx)%4 == 0 {
				u = 1
			} else if (i+rIdx)%4 == 2 {
				u = -1
			}
			if u == 0 {
				continue
			}
			for j := 0; j < cols; j++ {
				var v int64
				if (j+cIdx)%5 == 0 {
					v = 1
				} else if (j+cIdx)%5 == 3 {
					v = -1
				}
				if v != 0 {
					out.Data[i*cols+j] += u * v
				}
			}
		}
	case CorruptionLazyZero:
		allZero := true
		for i := range out.Data {
			if out.Data[i] != 0 {
				allZero = false
			}
			out.Data[i] = 0
		}
		if allZero {
			out.Data[0] = 1
		}
	default:
		return nil, fmt.Errorf("unknown corruption class: %q", class)
	}
	return out, nil
}

// SpeedupRow records a single (dimension, mode, k) speedup measurement.
type SpeedupRow struct {
	Dim                         int     `json:"dim"`
	ChallengeMode               string  `json:"challenge_mode"`
	RoundsK                     int     `json:"rounds_k"`
	GEMMUs                      float64 `json:"gemm_us"`
	VerifyUs                    float64 `json:"verify_us"`
	Speedup                     float64 `json:"speedup"`
	TheoreticalFalseAcceptBound string  `json:"theoretical_false_accept_bound"`
}

// SoundnessRow records empirical detection probability for one (mode, class, k).
type SoundnessRow struct {
	ChallengeMode         string  `json:"challenge_mode"`
	CorruptionClass       string  `json:"corruption_class"`
	RoundsK               int     `json:"rounds_k"`
	Trials                int     `json:"trials"`
	Detected              int     `json:"detected"`
	Escaped               int     `json:"escaped"`
	EmpiricalDetectionPct float64 `json:"empirical_detection_pct"`
	TheoryMinDetectionPct float64 `json:"theory_min_detection_pct"`
	TheoryMaxEscapeRate   float64 `json:"theory_max_escape_rate"`
}

// HonestBaselineRow records empirical false rejection rate on honest C = A*B matrices.
type HonestBaselineRow struct {
	ChallengeMode string  `json:"challenge_mode"`
	RoundsK       int     `json:"rounds_k"`
	Trials        int     `json:"trials"`
	Verified      int     `json:"verified"`
	FalseRejects  int     `json:"false_rejects"`
	FRRPct        float64 `json:"frr_pct"`
}

// GrindingAttemptRow records one empirical Fiat-Shamir grinding result for low k.
type GrindingAttemptRow struct {
	RoundsK               int     `json:"rounds_k"`
	ExpectedAttempts      float64 `json:"expected_attempts"`
	ActualAttemptsToForge int     `json:"actual_attempts_to_forge"`
	ForgedSaltHex         string  `json:"forged_salt_hex"`
	FiatShamirVerdict     string  `json:"fiat_shamir_verdict"`
	GrindingRiskWarning   bool    `json:"grinding_risk_warning"`
	ExternalNonceVerdict  string  `json:"external_nonce_verdict"`
}

// NegativeRegime1Result documents Fiat-Shamir prover grinding at low k.
type NegativeRegime1Result struct {
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Dim         int                  `json:"dim"`
	Rows        []GrindingAttemptRow `json:"rows"`
}

// NegativeRegime2Result documents semantic / end-to-end inference blindness and constitutional policy gate.
type NegativeRegime2Result struct {
	Name                           string   `json:"name"`
	Description                    string   `json:"description"`
	ReferenceWeightsRoot           string   `json:"reference_weights_root"`
	SubstitutedWeightsRoot         string   `json:"substituted_weights_root"`
	WeightsMatchReference          bool     `json:"weights_match_reference"`
	ClaimedTruthStatement          string   `json:"claimed_truth_statement"`
	FreivaldsComputeVerdict        string   `json:"freivalds_compute_verdict"`
	ProvesMatrixProductOnly        bool     `json:"proves_matrix_product_only"`
	ProvesFullModelInference       bool     `json:"proves_full_model_inference"`
	ProvesScientificTruth          bool     `json:"proves_scientific_truth"`
	ProvesWeightProvenance         bool     `json:"proves_weight_provenance"`
	GovernanceEscalationVerdict    string   `json:"governance_escalation_verdict"`
	GovernanceEscalationErrorCodes []string `json:"governance_escalation_error_codes"`
}

// NegativeRegime3Result documents small-matrix / high-k verification overhead crossover.
type NegativeRegime3Result struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Rows        []SpeedupRow `json:"rows"`
}

// BenchmarkReport is the complete machine-readable output written to results.json.
type BenchmarkReport struct {
	SchemaVersion        string                `json:"schema_version"`
	Issue                string                `json:"issue"`
	HIP                  string                `json:"hip"`
	Seed                 uint64                `json:"seed"`
	FieldModulus         int64                 `json:"field_modulus"`
	KernelProfile        string                `json:"kernel_profile"`
	CorpusManifestSHA256 string                `json:"corpus_manifest_sha256"`
	CorpusRootSHA256     string                `json:"corpus_root_sha256"`
	ParitySuiteCases     int                   `json:"parity_suite_cases"`
	AuditMerkleRoot      string                `json:"audit_merkle_root"`
	HonestBaseline       []HonestBaselineRow   `json:"honest_baseline"`
	SpeedupMatrix        []SpeedupRow          `json:"speedup_matrix"`
	SoundnessMatrix      []SoundnessRow        `json:"soundness_matrix"`
	NegativeRegime1      NegativeRegime1Result `json:"neg_fiat_shamir_grinding_low_k"`
	NegativeRegime2      NegativeRegime2Result `json:"neg_valid_matmul_untruthful_or_wrong_weights"`
	NegativeRegime3      NegativeRegime3Result `json:"neg_small_matrix_verification_overhead"`
}

// ParityFixtureCase stores one complete self-contained test case for cross-language Go <-> Python verification.
type ParityFixtureCase struct {
	CaseID          string              `json:"case_id"`
	Category        string              `json:"category"`
	Description     string              `json:"description"`
	MatrixA         []int8              `json:"matrix_a"`
	MatrixB         []int8              `json:"matrix_b"`
	MatrixC         []int64             `json:"matrix_c"`
	Transcript      Transcript          `json:"transcript"`
	ExpectedReceipt VerificationReceipt `json:"expected_receipt"`
}

// ParitySuite is written to fixtures/parity-suite.v1.json and independently verified by Python.
type ParitySuite struct {
	SchemaVersion        string              `json:"schema_version"`
	SpecVersion          string              `json:"spec_version"`
	Seed                 uint64              `json:"seed"`
	CorpusManifestSHA256 string              `json:"corpus_manifest_sha256"`
	AuditMerkleRoot      string              `json:"audit_merkle_root"`
	Cases                []ParityFixtureCase `json:"cases"`
}

// RunFullBenchmark executes the grounded reproducible benchmark and builds the parity fixture suite.
func RunFullBenchmark(repoRoot, manifestPath string, seed uint64, soundnessTrials int) (*BenchmarkReport, *ParitySuite, error) {
	corpus, err := LoadAndVerifyCorpus(repoRoot, manifestPath)
	if err != nil {
		return nil, nil, err
	}
	manifestHex := hex.EncodeToString(corpus.ManifestSHA256[:])
	corpusRootHex := hex.EncodeToString(corpus.CorpusRoot[:])
	_, privKey := DeriveProviderKeyPair("bench-provider-0", seed)

	// 1. Speedup matrix across n in {64, 128, 256, 512} and k in {1, 2, 4, 8, 16, 40}.
	speedupDims := []int{64, 128, 256, 512}
	speedupKs := []int{1, 2, 4, 8, 16, 40}
	speedupRows := make([]SpeedupRow, 0, len(speedupDims)*len(speedupKs)*2)

	for _, n := range speedupDims {
		a := DeriveTile(corpus.CorpusRoot, seed, fmt.Sprintf("speedup-A-%d", n), n, n)
		b := DeriveTile(corpus.CorpusRoot, seed, fmt.Sprintf("speedup-B-%d", n), n, n)

		gemmIters := 50
		if n == 128 {
			gemmIters = 15
		} else if n == 256 {
			gemmIters = 5
		} else if n >= 512 {
			gemmIters = 2
		}
		// Warmup
		c, err := ExactIntGEMM(a, b)
		if err != nil {
			return nil, nil, err
		}
		t0 := time.Now()
		for iter := 0; iter < gemmIters; iter++ {
			c, err = ExactIntGEMM(a, b)
			if err != nil {
				return nil, nil, err
			}
		}
		gemmUs := float64(time.Since(t0).Nanoseconds()) / float64(gemmIters) / 1000.0

		chSeed := sha256.Sum256([]byte(fmt.Sprintf("poai:v1:speedup:%d:%d", seed, n)))
		for _, mode := range []string{ChallengeModeBinary, ChallengeModeField} {
			for _, k := range speedupKs {
				verIters := 50
				if n == 128 {
					verIters = 20
				} else if n == 256 {
					verIters = 10
				} else if n >= 512 {
					verIters = 5
					if k >= 16 {
						verIters = 2
					}
				}
				vt0 := time.Now()
				for iter := 0; iter < verIters; iter++ {
					ok, _, err := FastFreivaldsCheck(a, b, c, mode, chSeed, k)
					if err != nil || !ok {
						return nil, nil, fmt.Errorf("honest speedup verification failed at n=%d mode=%s k=%d", n, mode, k)
					}
				}
				verifyUs := float64(time.Since(vt0).Nanoseconds()) / float64(verIters) / 1000.0
				speedupRows = append(speedupRows, SpeedupRow{
					Dim:                         n,
					ChallengeMode:               mode,
					RoundsK:                     k,
					GEMMUs:                      math.Round(gemmUs*100) / 100,
					VerifyUs:                    math.Round(verifyUs*100) / 100,
					Speedup:                     math.Round((gemmUs/verifyUs)*100) / 100,
					TheoreticalFalseAcceptBound: TheoreticalFalseAcceptBound(mode, k),
				})
			}
		}
	}

	// 2. Honest baseline (0.00% FRR verification) and empirical corruption soundness matrix.
	soundDim := 32
	aS := DeriveTile(corpus.CorpusRoot, seed, "soundness-A-32", soundDim, soundDim)
	bS := DeriveTile(corpus.CorpusRoot, seed, "soundness-B-32", soundDim, soundDim)
	cS, err := ExactIntGEMM(aS, bS)
	if err != nil {
		return nil, nil, err
	}

	honestBaseline := make([]HonestBaselineRow, 0, 2)
	for _, cfg := range []struct {
		mode string
		k    int
	}{
		{ChallengeModeBinary, 40},
		{ChallengeModeField, 2},
	} {
		verified := 0
		for trial := 0; trial < soundnessTrials; trial++ {
			chSeed := sha256.Sum256([]byte(fmt.Sprintf("poai:v1:honest:%d:%s:%d:%d", seed, cfg.mode, cfg.k, trial)))
			ok, _, err := FastFreivaldsCheck(aS, bS, cS, cfg.mode, chSeed, cfg.k)
			if err != nil {
				return nil, nil, err
			}
			if ok {
				verified++
			}
		}
		fr := soundnessTrials - verified
		honestBaseline = append(honestBaseline, HonestBaselineRow{
			ChallengeMode: cfg.mode,
			RoundsK:       cfg.k,
			Trials:        soundnessTrials,
			Verified:      verified,
			FalseRejects:  fr,
			FRRPct:        math.Round((float64(fr)/float64(soundnessTrials))*10000) / 100,
		})
	}

	soundnessRows := make([]SoundnessRow, 0, len(AllCorruptionClasses)*8)
	binaryKs := []int{1, 2, 4, 8, 16, 40}
	fieldKs := []int{1, 2}

	for _, class := range AllCorruptionClasses {
		// Pre-build a deterministic corrupted matrix per trial index modulo 16 to vary coordinates cleanly.
		corruptedPool := make([]*Int64Matrix, 16)
		for pIdx := 0; pIdx < 16; pIdx++ {
			cm, err := InjectCorruption(cS, class, pIdx)
			if err != nil {
				return nil, nil, err
			}
			corruptedPool[pIdx] = cm
		}

		for _, k := range binaryKs {
			detected := 0
			for trial := 0; trial < soundnessTrials; trial++ {
				cm := corruptedPool[trial%len(corruptedPool)]
				chSeed := sha256.Sum256([]byte(fmt.Sprintf("poai:v1:sound:%d:bin:%s:%d:%d", seed, class, k, trial)))
				ok, _, err := FastFreivaldsCheck(aS, bS, cm, ChallengeModeBinary, chSeed, k)
				if err != nil {
					return nil, nil, err
				}
				if !ok {
					detected++
				}
			}
			escaped := soundnessTrials - detected
			theoryEscape := math.Pow(2.0, -float64(k))
			soundnessRows = append(soundnessRows, SoundnessRow{
				ChallengeMode:         ChallengeModeBinary,
				CorruptionClass:       class,
				RoundsK:               k,
				Trials:                soundnessTrials,
				Detected:              detected,
				Escaped:               escaped,
				EmpiricalDetectionPct: math.Round((float64(detected)/float64(soundnessTrials))*10000) / 100,
				TheoryMinDetectionPct: math.Round((1.0-theoryEscape)*1000000) / 10000,
				TheoryMaxEscapeRate:   theoryEscape,
			})
		}

		for _, k := range fieldKs {
			detected := 0
			for trial := 0; trial < soundnessTrials; trial++ {
				cm := corruptedPool[trial%len(corruptedPool)]
				chSeed := sha256.Sum256([]byte(fmt.Sprintf("poai:v1:sound:%d:fp:%s:%d:%d", seed, class, k, trial)))
				ok, _, err := FastFreivaldsCheck(aS, bS, cm, ChallengeModeField, chSeed, k)
				if err != nil {
					return nil, nil, err
				}
				if !ok {
					detected++
				}
			}
			escaped := soundnessTrials - detected
			theoryEscape := math.Pow(float64(FieldModulus), -float64(k))
			soundnessRows = append(soundnessRows, SoundnessRow{
				ChallengeMode:         ChallengeModeField,
				CorruptionClass:       class,
				RoundsK:               k,
				Trials:                soundnessTrials,
				Detected:              detected,
				Escaped:               escaped,
				EmpiricalDetectionPct: math.Round((float64(detected)/float64(soundnessTrials))*10000) / 100,
				TheoryMinDetectionPct: 100.0,
				TheoryMaxEscapeRate:   theoryEscape,
			})
		}
	}

	// 3. Negative Regime #1: Non-interactive Fiat-Shamir Prover Grinding at low k (1..4).
	negDim := 16
	aN := DeriveTile(corpus.CorpusRoot, seed, "neg1-A-16", negDim, negDim)
	bN := DeriveTile(corpus.CorpusRoot, seed, "neg1-B-16", negDim, negDim)
	cN, err := ExactIntGEMM(aN, bN)
	if err != nil {
		return nil, nil, err
	}
	cNCorrupt, err := InjectCorruption(cN, CorruptionSinglePlusOne, 0)
	if err != nil {
		return nil, nil, err
	}

	grindingRows := make([]GrindingAttemptRow, 0, 4)
	var forgedK4Tx *Transcript
	for _, k := range []int{1, 2, 3, 4} {
		attempts := 0
		var forgedSalt string
		var forgedTx *Transcript
		for saltCtr := uint64(0); saltCtr < 100000; saltCtr++ {
			attempts++
			var sb [16]byte
			binary.LittleEndian.PutUint64(sb[0:8], seed)
			binary.LittleEndian.PutUint64(sb[8:16], saltCtr)
			saltHex := hex.EncodeToString(sb[:])
			tx, err := BuildTranscript(BuildParams{
				JobID:                fmt.Sprintf("neg1-grind-k%d", k),
				PolicyEpoch:          1,
				ModelID:              "zoo-zen-int8-ref",
				LayerIndex:           0,
				ChallengeMode:        ChallengeModeBinary,
				ChallengeSource:      ChallengeSourceFiatShamir,
				ChallengeRoundsK:     k,
				ProverSaltHex:        saltHex,
				CorpusManifestSHA256: manifestHex,
				ProviderPrivKey:      privKey,
			}, aN, bN, cNCorrupt)
			if err != nil {
				return nil, nil, err
			}
			if tx.ConstitutionalBoundary.ComputeVerdict == VerdictComputeVerified {
				forgedSalt = saltHex
				forgedTx = tx
				break
			}
		}
		if forgedTx == nil {
			return nil, nil, fmt.Errorf("failed to find grinding forgery at k=%d", k)
		}
		if k == 4 {
			forgedK4Tx = forgedTx
		}
		// Now verify the exact same corrupted matrix under external_verifier_nonce with k=40 (or field_fp k=1).
		extTx, err := BuildTranscript(BuildParams{
			JobID:                fmt.Sprintf("neg1-ext-k%d", k),
			PolicyEpoch:          1,
			ModelID:              "zoo-zen-int8-ref",
			LayerIndex:           0,
			ChallengeMode:        ChallengeModeField,
			ChallengeSource:      ChallengeSourceExternal,
			ChallengeRoundsK:     2,
			VerifierNonceHex:     DeriveNonceHex(seed, fmt.Sprintf("neg1-ext-k%d", k)),
			CorpusManifestSHA256: manifestHex,
			ProviderPrivKey:      privKey,
		}, aN, bN, cNCorrupt)
		if err != nil {
			return nil, nil, err
		}
		grindingRows = append(grindingRows, GrindingAttemptRow{
			RoundsK:               k,
			ExpectedAttempts:      math.Pow(2.0, float64(k)),
			ActualAttemptsToForge: attempts,
			ForgedSaltHex:         forgedSalt,
			FiatShamirVerdict:     forgedTx.ConstitutionalBoundary.ComputeVerdict,
			GrindingRiskWarning:   forgedTx.ConstitutionalBoundary.GrindingRiskWarning,
			ExternalNonceVerdict:  extTx.ConstitutionalBoundary.ComputeVerdict,
		})
	}
	neg1 := NegativeRegime1Result{
		Name:        "neg_fiat_shamir_grinding_low_k",
		Description: "With non-interactive Fiat-Shamir and prover-chosen salt at low k (1..4) in binary_01 mode, a dishonest prover brute-forces a passing challenge on a corrupted matrix C' in ~2^k attempts. Switching to an external verifier nonce (revealed post-commitment) or field_fp (k>=2) eliminates grinding.",
		Dim:         negDim,
		Rows:        grindingRows,
	}

	// 4. Negative Regime #2: Semantic / End-to-End Inference Blindness + Constitutional Governance Guard.
	aRefWeights := DeriveTile(corpus.CorpusRoot, seed, "neg2-reference-weights-16", negDim, negDim)
	aBackdoorWeights := DeriveTile(corpus.CorpusRoot, seed+999, "neg2-backdoor-weights-16", negDim, negDim)
	bActivations := DeriveTile(corpus.CorpusRoot, seed, "neg2-activations-16", negDim, negDim)
	cBackdoor, err := ExactIntGEMM(aBackdoorWeights, bActivations)
	if err != nil {
		return nil, nil, err
	}
	refWeightsRoot := Int8MatrixMerkleRoot(aRefWeights, 'A')
	backdoorWeightsRoot := Int8MatrixMerkleRoot(aBackdoorWeights, 'A')

	falseClaim := "2 + 2 = 5 and this unreviewed run proves global theorem convergence (non-linearities skipped)"
	neg2Tx, err := BuildTranscript(BuildParams{
		JobID:                "neg2-semantic-blindness",
		PolicyEpoch:          1,
		ModelID:              "zoo-zen-int8-ref",
		LayerIndex:           12,
		ChallengeMode:        ChallengeModeField,
		ChallengeSource:      ChallengeSourceExternal,
		ChallengeRoundsK:     2,
		VerifierNonceHex:     DeriveNonceHex(seed, "neg2-semantic"),
		CorpusManifestSHA256: manifestHex,
		ProviderPrivKey:      privKey,
		SemanticMetadata: &SemanticMetadata{
			ClaimedModelPurpose:       "substituted-backdoor-weights-no-rmsnorm-no-softmax",
			ClaimedTruthStatement:     falseClaim,
			WeightsAttested:           false,
			NonlinearitiesVerified:    false,
			RequestedGovernanceAction: "recommend_only",
		},
	}, aBackdoorWeights, bActivations, cBackdoor)
	if err != nil {
		return nil, nil, err
	}

	// Also attempt forbidden autonomous governance action ("self_declare_valid") on the exact same valid matmul.
	neg2GovTx, err := BuildTranscript(BuildParams{
		JobID:                "neg2-forbidden-governance",
		PolicyEpoch:          1,
		ModelID:              "zoo-zen-int8-ref",
		LayerIndex:           12,
		ChallengeMode:        ChallengeModeField,
		ChallengeSource:      ChallengeSourceExternal,
		ChallengeRoundsK:     2,
		VerifierNonceHex:     DeriveNonceHex(seed, "neg2-gov"),
		CorpusManifestSHA256: manifestHex,
		ProviderPrivKey:      privKey,
		SemanticMetadata: &SemanticMetadata{
			ClaimedModelPurpose:       "autonomous-self-certification-attempt",
			ClaimedTruthStatement:     falseClaim,
			WeightsAttested:           false,
			NonlinearitiesVerified:    false,
			RequestedGovernanceAction: "self_declare_valid",
		},
	}, aBackdoorWeights, bActivations, cBackdoor)
	if err != nil {
		return nil, nil, err
	}

	neg2 := NegativeRegime2Result{
		Name:                           "neg_valid_matmul_untruthful_or_wrong_weights",
		Description:                    "A 100% Freivalds-valid transcript (COMPUTE_VERIFIED) produced with substituted backdoor weights, omitted non-linear layers, and a factually false conclusion proves that Freivalds verifies ONLY C == A*B for the committed operands. The constitutional boundary locks proves_full_model_inference=false, proves_scientific_truth=false, proves_weight_provenance=false, and blocks forbidden governance actions with POLICY_REJECTED.",
		ReferenceWeightsRoot:           hex.EncodeToString(refWeightsRoot[:]),
		SubstitutedWeightsRoot:         hex.EncodeToString(backdoorWeightsRoot[:]),
		WeightsMatchReference:          refWeightsRoot == backdoorWeightsRoot,
		ClaimedTruthStatement:          falseClaim,
		FreivaldsComputeVerdict:        neg2Tx.ConstitutionalBoundary.ComputeVerdict,
		ProvesMatrixProductOnly:        neg2Tx.ConstitutionalBoundary.ProvesMatrixProductOnly,
		ProvesFullModelInference:       neg2Tx.ConstitutionalBoundary.ProvesFullModelInference,
		ProvesScientificTruth:          neg2Tx.ConstitutionalBoundary.ProvesScientificTruth,
		ProvesWeightProvenance:         neg2Tx.ConstitutionalBoundary.ProvesWeightProvenance,
		GovernanceEscalationVerdict:    neg2GovTx.ConstitutionalBoundary.ComputeVerdict,
		GovernanceEscalationErrorCodes: neg2GovTx.ConstitutionalBoundary.ErrorCodes,
	}

	// 5. Negative Regime #3: Small-Matrix / High-k Verification Overhead Crossover (n=16, 32 with k=16, 40).
	neg3Rows := make([]SpeedupRow, 0, 8)
	for _, n := range []int{16, 32} {
		aSmall := DeriveTile(corpus.CorpusRoot, seed, fmt.Sprintf("neg3-A-%d", n), n, n)
		bSmall := DeriveTile(corpus.CorpusRoot, seed, fmt.Sprintf("neg3-B-%d", n), n, n)
		cSmall, err := ExactIntGEMM(aSmall, bSmall)
		if err != nil {
			return nil, nil, err
		}
		const gemmRuns = 500
		gt0 := time.Now()
		for i := 0; i < gemmRuns; i++ {
			cSmall, err = ExactIntGEMM(aSmall, bSmall)
			if err != nil {
				return nil, nil, err
			}
		}
		gemmUs := float64(time.Since(gt0).Nanoseconds()) / float64(gemmRuns) / 1000.0
		chSeed := sha256.Sum256([]byte(fmt.Sprintf("poai:v1:neg3:%d:%d", seed, n)))
		for _, mode := range []string{ChallengeModeBinary, ChallengeModeField} {
			for _, k := range []int{16, 40} {
				const verRuns = 100
				vt0 := time.Now()
				for i := 0; i < verRuns; i++ {
					ok, _, err := FastFreivaldsCheck(aSmall, bSmall, cSmall, mode, chSeed, k)
					if err != nil || !ok {
						return nil, nil, fmt.Errorf("neg3 honest check failed")
					}
				}
				verifyUs := float64(time.Since(vt0).Nanoseconds()) / float64(verRuns) / 1000.0
				neg3Rows = append(neg3Rows, SpeedupRow{
					Dim:                         n,
					ChallengeMode:               mode,
					RoundsK:                     k,
					GEMMUs:                      math.Round(gemmUs*100) / 100,
					VerifyUs:                    math.Round(verifyUs*100) / 100,
					Speedup:                     math.Round((gemmUs/verifyUs)*1000) / 1000,
					TheoreticalFalseAcceptBound: TheoreticalFalseAcceptBound(mode, k),
				})
			}
		}
	}
	neg3 := NegativeRegime3Result{
		Name:        "neg_small_matrix_verification_overhead",
		Description: "At small matrix dimensions (n=16, 32) with high round counts (k=16, 40), O(k*n^2) Freivalds verification (including SHA-256 PRG challenge generation and 3 matrix-vector products per round) is strictly SLOWER (< 1.0x) than direct O(n^3) exact integer recomputation, establishing the practical n > 3k crossover rule.",
		Rows:        neg3Rows,
	}

	// 6. Build the 16-case cross-language Parity Fixture Suite (Go <-> Python bit-identical parity).
	paritySuite, err := buildParitySuite(corpus, seed, privKey, aN, bN, cN, cNCorrupt, forgedK4Tx, aBackdoorWeights, bActivations, cBackdoor, neg2Tx, neg2GovTx)
	if err != nil {
		return nil, nil, err
	}

	report := &BenchmarkReport{
		SchemaVersion:        "poai-benchmark-report.v1",
		Issue:                "zoo-apps/papers#13",
		HIP:                  "HIP-1350",
		Seed:                 seed,
		FieldModulus:         FieldModulus,
		KernelProfile:        KernelProfile,
		CorpusManifestSHA256: manifestHex,
		CorpusRootSHA256:     corpusRootHex,
		ParitySuiteCases:     len(paritySuite.Cases),
		AuditMerkleRoot:      paritySuite.AuditMerkleRoot,
		HonestBaseline:       honestBaseline,
		SpeedupMatrix:        speedupRows,
		SoundnessMatrix:      soundnessRows,
		NegativeRegime1:      neg1,
		NegativeRegime2:      neg2,
		NegativeRegime3:      neg3,
	}
	return report, paritySuite, nil
}

func buildParitySuite(
	corpus *VerifiedCorpus,
	seed uint64,
	privKey []byte,
	a16, b16 *Int8Matrix,
	c16, c16Corrupt *Int64Matrix,
	forgedK4Tx *Transcript,
	aBackdoor, bBackdoor *Int8Matrix,
	cBackdoor *Int64Matrix,
	neg2Tx, neg2GovTx *Transcript,
) (*ParitySuite, error) {
	manifestHex := hex.EncodeToString(corpus.ManifestSHA256[:])
	cases := make([]ParityFixtureCase, 0, 16)
	receipts := make([]VerificationReceipt, 0, 16)

	appendCase := func(id, category, desc string, a, b *Int8Matrix, c *Int64Matrix, tx *Transcript) {
		r := VerifyTranscript(tx, a, b, c)
		cases = append(cases, ParityFixtureCase{
			CaseID:          id,
			Category:        category,
			Description:     desc,
			MatrixA:         append([]int8(nil), a.Data...),
			MatrixB:         append([]int8(nil), b.Data...),
			MatrixC:         append([]int64(nil), c.Data...),
			Transcript:      *tx,
			ExpectedReceipt: r,
		})
		receipts = append(receipts, r)
	}

	// Case 1: Honest binary_01 external_verifier_nonce (k=40)
	tx1, err := BuildTranscript(BuildParams{
		JobID:                "parity-01-honest-binary-k40",
		PolicyEpoch:          1,
		ModelID:              "zoo-zen-int8-ref",
		LayerIndex:           0,
		ChallengeMode:        ChallengeModeBinary,
		ChallengeSource:      ChallengeSourceExternal,
		ChallengeRoundsK:     40,
		VerifierNonceHex:     DeriveNonceHex(seed, "parity-01"),
		CorpusManifestSHA256: manifestHex,
		ProviderPrivKey:      privKey,
	}, a16, b16, c16)
	if err != nil {
		return nil, err
	}
	appendCase("parity-01-honest-binary-k40", "honest", "Honest 16x16 int8 GEMM verified with binary_01 k=40 external nonce", a16, b16, c16, tx1)

	// Case 2: Honest field_fp external_verifier_nonce (k=2)
	tx2, err := BuildTranscript(BuildParams{
		JobID:                "parity-02-honest-field-k2",
		PolicyEpoch:          1,
		ModelID:              "zoo-zen-int8-ref",
		LayerIndex:           1,
		ChallengeMode:        ChallengeModeField,
		ChallengeSource:      ChallengeSourceExternal,
		ChallengeRoundsK:     2,
		VerifierNonceHex:     DeriveNonceHex(seed, "parity-02"),
		CorpusManifestSHA256: manifestHex,
		ProviderPrivKey:      privKey,
	}, a16, b16, c16)
	if err != nil {
		return nil, err
	}
	appendCase("parity-02-honest-field-k2", "honest", "Honest 16x16 int8 GEMM verified with field_fp k=2 external nonce", a16, b16, c16, tx2)

	// Case 3: Honest non-square rectangular matrix (12x20 * 20x10) in field_fp (k=2)
	aRect := DeriveTile(corpus.CorpusRoot, seed, "parity-rect-A", 12, 20)
	bRect := DeriveTile(corpus.CorpusRoot, seed, "parity-rect-B", 20, 10)
	cRect, err := ExactIntGEMM(aRect, bRect)
	if err != nil {
		return nil, err
	}
	tx3, err := BuildTranscript(BuildParams{
		JobID:                "parity-03-honest-rect-field-k2",
		PolicyEpoch:          2,
		ModelID:              "zoo-zen-int8-mlp-up",
		LayerIndex:           3,
		ChallengeMode:        ChallengeModeField,
		ChallengeSource:      ChallengeSourceExternal,
		ChallengeRoundsK:     2,
		VerifierNonceHex:     DeriveNonceHex(seed, "parity-03"),
		CorpusManifestSHA256: manifestHex,
		ProviderPrivKey:      privKey,
	}, aRect, bRect, cRect)
	if err != nil {
		return nil, err
	}
	appendCase("parity-03-honest-rect-field-k2", "honest", "Honest rectangular 12x20 * 20x10 int8 GEMM verified with field_fp k=2", aRect, bRect, cRect, tx3)

	// Cases 4-8: All 5 corruption classes verified in binary_01 (k=40)
	for idx, class := range AllCorruptionClasses {
		cm, err := InjectCorruption(c16, class, idx+1)
		if err != nil {
			return nil, err
		}
		caseID := fmt.Sprintf("parity-%02d-corrupt-bin-%s", 4+idx, class)
		tx, err := BuildTranscript(BuildParams{
			JobID:                caseID,
			PolicyEpoch:          1,
			ModelID:              "zoo-zen-int8-ref",
			LayerIndex:           uint32(idx),
			ChallengeMode:        ChallengeModeBinary,
			ChallengeSource:      ChallengeSourceExternal,
			ChallengeRoundsK:     40,
			VerifierNonceHex:     DeriveNonceHex(seed, caseID),
			CorpusManifestSHA256: manifestHex,
			ProviderPrivKey:      privKey,
		}, a16, b16, cm)
		if err != nil {
			return nil, err
		}
		appendCase(caseID, "corruption_binary", fmt.Sprintf("Corrupted C (%s) detected under binary_01 k=40", class), a16, b16, cm, tx)
	}

	// Cases 9-11: Representative corruptions in field_fp (k=1) catching with error <= 4.66e-10
	for idx, class := range []string{CorruptionSingleBitflip, CorruptionRowSwap, CorruptionLowRank} {
		cm, err := InjectCorruption(c16, class, idx+10)
		if err != nil {
			return nil, err
		}
		caseID := fmt.Sprintf("parity-%02d-corrupt-fp-%s", 9+idx, class)
		tx, err := BuildTranscript(BuildParams{
			JobID:                caseID,
			PolicyEpoch:          1,
			ModelID:              "zoo-zen-int8-ref",
			LayerIndex:           uint32(idx + 5),
			ChallengeMode:        ChallengeModeField,
			ChallengeSource:      ChallengeSourceExternal,
			ChallengeRoundsK:     1,
			VerifierNonceHex:     DeriveNonceHex(seed, caseID),
			CorpusManifestSHA256: manifestHex,
			ProviderPrivKey:      privKey,
		}, a16, b16, cm)
		if err != nil {
			return nil, err
		}
		appendCase(caseID, "corruption_field", fmt.Sprintf("Corrupted C (%s) detected under field_fp k=1", class), a16, b16, cm, tx)
	}

	// Case 12: Tampered Ed25519 signature -> INVALID_TRANSCRIPT (ERR_INVALID_SIGNATURE)
	txBadSig := *tx2
	sigBytes, _ := hex.DecodeString(txBadSig.Signature.SignatureHex)
	sigBytes[0] ^= 0xFF
	txBadSig.Signature.SignatureHex = hex.EncodeToString(sigBytes)
	appendCase("parity-12-invalid-ed25519-sig", "integrity_failure", "Tampered RFC 8032 Ed25519 signature rejected as INVALID_TRANSCRIPT", a16, b16, c16, &txBadSig)

	// Case 13: Matrix C tampered AFTER signing -> INVALID_TRANSCRIPT (ERR_COMMITMENT_MISMATCH_C)
	cTamperedAfterSign := c16.Clone()
	cTamperedAfterSign.Data[0] += 7
	txCommitFail := *tx2
	appendCase("parity-13-commitment-mismatch-c", "integrity_failure", "Matrix C modified post-commitment rejected as INVALID_TRANSCRIPT", a16, b16, cTamperedAfterSign, &txCommitFail)

	// Case 14: Negative Regime #1 — Fiat-Shamir grinding forgery at k=4 (passes binary_01 with GrindingRiskWarning=true)
	appendCase("parity-14-neg1-fiat-shamir-grind-k4", "negative_regime_1", "Grinded Fiat-Shamir k=4 forgery on corrupted C' passes binary_01 while emitting ERR_WEAK_FIAT_SHAMIR_GRINDING_RISK", a16, b16, c16Corrupt, forgedK4Tx)

	// Case 15: Negative Regime #2 — Valid matmul with substituted backdoor weights & false scientific claim
	appendCase("parity-15-neg2-semantic-blindness", "negative_regime_2", "100% Freivalds-valid matmul with backdoor weights and false scientific claim; proves_scientific_truth=false", aBackdoor, bBackdoor, cBackdoor, neg2Tx)

	// Case 16: Constitutional Guard — Forbidden autonomous governance action (self_declare_valid) -> POLICY_REJECTED
	appendCase("parity-16-policy-rejected-governance", "constitutional_guard", "Valid matmul attempting self_declare_valid governance escalation blocked as POLICY_REJECTED", aBackdoor, bBackdoor, cBackdoor, neg2GovTx)

	return &ParitySuite{
		SchemaVersion:        "poai-parity-suite.v1",
		SpecVersion:          SpecVersion,
		Seed:                 seed,
		CorpusManifestSHA256: manifestHex,
		AuditMerkleRoot:      ComputeAuditMerkleRoot(receipts),
		Cases:                cases,
	}, nil
}

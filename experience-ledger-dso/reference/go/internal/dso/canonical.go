// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation

package dso

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
)

// ToMicro converts a float64 to deterministic integer micro-units (1e-6).
func ToMicro(v float64) int64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return int64(math.Round(v * float64(FixedScale)))
}

// FromMicro converts integer micro-units back to float64.
func FromMicro(m int64) float64 {
	return float64(m) / float64(FixedScale)
}

// VecToMicro converts a fixed FeatureDim vector to micro-unit int64 slice.
func VecToMicro(v [FeatureDim]float64) []int64 {
	out := make([]int64, FeatureDim)
	for i := 0; i < FeatureDim; i++ {
		out[i] = ToMicro(v[i])
	}
	return out
}

// VecFromMicro converts a micro-unit int64 slice to a FeatureDim vector.
func VecFromMicro(m []int64) ([FeatureDim]float64, error) {
	var out [FeatureDim]float64
	if len(m) != FeatureDim {
		return out, fmt.Errorf("expected %d delta dims, got %d", FeatureDim, len(m))
	}
	for i := 0; i < FeatureDim; i++ {
		out[i] = FromMicro(m[i])
	}
	return out, nil
}

// SliceToMicro converts a float64 slice to micro-units.
func SliceToMicro(vals []float64) []int64 {
	out := make([]int64, len(vals))
	for i, v := range vals {
		out[i] = ToMicro(v)
	}
	return out
}

func appendJSONString(buf *bytes.Buffer, s string) {
	b, _ := json.Marshal(s)
	buf.Write(b)
}

func appendInt64Slice(buf *bytes.Buffer, xs []int64) {
	buf.WriteByte('[')
	for i, x := range xs {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(strconv.FormatInt(x, 10))
	}
	buf.WriteByte(']')
}

// CanonicalExperienceBytes encodes ExperienceOp with sorted keys and zero whitespace.
func CanonicalExperienceBytes(e ExperienceOp) []byte {
	var buf bytes.Buffer
	buf.WriteString(`{"confidence_micro":`)
	buf.WriteString(strconv.FormatInt(e.ConfidenceMicro, 10))
	buf.WriteString(`,"domain":`)
	appendJSONString(&buf, e.Domain)
	buf.WriteString(`,"id":`)
	appendJSONString(&buf, e.ID)
	buf.WriteString(`,"op":`)
	appendJSONString(&buf, e.Op)
	buf.WriteString(`,"paper_path":`)
	appendJSONString(&buf, e.PaperPath)
	buf.WriteString(`,"paper_sha256":`)
	appendJSONString(&buf, e.PaperSHA256)
	buf.WriteString(`,"text":`)
	appendJSONString(&buf, e.Text)
	buf.WriteByte('}')
	return buf.Bytes()
}

// CanonicalContributionBytes encodes ContributionBody with strictly sorted keys and zero whitespace.
// Keys order: delta_micro, domain, experience, node_id, public_key_hex, round, schema_version.
func CanonicalContributionBytes(c ContributionBody) []byte {
	var buf bytes.Buffer
	buf.WriteString(`{"delta_micro":`)
	appendInt64Slice(&buf, c.DeltaMicro)
	buf.WriteString(`,"domain":`)
	appendJSONString(&buf, c.Domain)
	buf.WriteString(`,"experience":`)
	buf.Write(CanonicalExperienceBytes(c.Experience))
	buf.WriteString(`,"node_id":`)
	appendJSONString(&buf, c.NodeID)
	buf.WriteString(`,"public_key_hex":`)
	appendJSONString(&buf, c.PublicKeyHex)
	buf.WriteString(`,"round":`)
	buf.WriteString(strconv.Itoa(c.Round))
	buf.WriteString(`,"schema_version":`)
	appendJSONString(&buf, c.SchemaVersion)
	buf.WriteByte('}')
	return buf.Bytes()
}

// CanonicalCellLeafHash computes a deterministic SHA-256 leaf digest over one benchmark cell's
// deterministic outputs (excluding non-deterministic wall-clock DurationMs).
func CanonicalCellLeafHash(c CellMetrics) string {
	var buf bytes.Buffer
	buf.WriteString(`{"adversarial_admission_rate_micro":`)
	buf.WriteString(strconv.FormatInt(ToMicro(c.AdversarialAdmissionRate), 10))
	buf.WriteString(`,"adversarial_weight_share_micro":`)
	buf.WriteString(strconv.FormatInt(ToMicro(c.AdversarialWeightShare), 10))
	buf.WriteString(`,"adversary_fraction_micro":`)
	buf.WriteString(strconv.FormatInt(ToMicro(c.AdversaryFraction), 10))
	buf.WriteString(`,"aggregator":`)
	appendJSONString(&buf, c.Aggregator)
	buf.WriteString(`,"attack_degradation_delta_micro":`)
	buf.WriteString(strconv.FormatInt(ToMicro(c.AttackDegradationDelta), 10))
	buf.WriteString(`,"attribution_gini_micro":`)
	buf.WriteString(strconv.FormatInt(ToMicro(c.AttributionGini), 10))
	buf.WriteString(`,"fairness_ratio_micro":`)
	buf.WriteString(strconv.FormatInt(ToMicro(c.FairnessRatio), 10))
	buf.WriteString(`,"final_weights_digest_sha256":`)
	appendJSONString(&buf, c.FinalWeightsDigestSHA256)
	buf.WriteString(`,"global_test_accuracy_micro":`)
	buf.WriteString(strconv.FormatInt(ToMicro(c.GlobalTestAccuracy), 10))
	buf.WriteString(`,"global_test_loss_micro":`)
	buf.WriteString(strconv.FormatInt(ToMicro(c.GlobalTestLoss), 10))
	buf.WriteString(`,"jains_fairness_index_micro":`)
	buf.WriteString(strconv.FormatInt(ToMicro(c.JainsFairnessIndex), 10))
	buf.WriteString(`,"majority_honest_acceptance_rate_micro":`)
	buf.WriteString(strconv.FormatInt(ToMicro(c.MajorityHonestAcceptanceRate), 10))
	buf.WriteString(`,"majority_test_accuracy_micro":`)
	buf.WriteString(strconv.FormatInt(ToMicro(c.MajorityTestAccuracy), 10))
	buf.WriteString(`,"minority_honest_acceptance_rate_micro":`)
	buf.WriteString(strconv.FormatInt(ToMicro(c.MinorityHonestAcceptanceRate), 10))
	buf.WriteString(`,"minority_test_accuracy_micro":`)
	buf.WriteString(strconv.FormatInt(ToMicro(c.MinorityTestAccuracy), 10))
	buf.WriteString(`,"num_nodes":`)
	buf.WriteString(strconv.Itoa(c.NumNodes))
	buf.WriteString(`,"num_rounds":`)
	buf.WriteString(strconv.Itoa(c.NumRounds))
	buf.WriteString(`,"payload_bytes_per_round":`)
	buf.WriteString(strconv.Itoa(c.PayloadBytesPerRound))
	buf.WriteString(`,"scenario":`)
	appendJSONString(&buf, c.Scenario)
	buf.WriteByte('}')
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

// ComputeMerkleRoot builds a domain-separated binary SHA-256 Merkle tree over hex digests.
// Leaf hash = SHA256(0x00 || raw_leaf_bytes); internal node = SHA256(0x01 || left || right).
// Odd nodes are duplicated at each level. Empty slice hashes to SHA256("dso-empty-merkle").
func ComputeMerkleRoot(hexDigests []string) string {
	if len(hexDigests) == 0 {
		h := sha256.Sum256([]byte("dso-empty-merkle"))
		return hex.EncodeToString(h[:])
	}
	level := make([][32]byte, len(hexDigests))
	for i, hd := range hexDigests {
		raw, err := hex.DecodeString(hd)
		if err != nil {
			raw = []byte(hd)
		}
		h := sha256.New()
		h.Write([]byte{0x00})
		h.Write(raw)
		copy(level[i][:], h.Sum(nil))
	}
	for len(level) > 1 {
		nextLen := (len(level) + 1) / 2
		next := make([][32]byte, nextLen)
		for i := 0; i < nextLen; i++ {
			left := level[2*i]
			right := left
			if 2*i+1 < len(level) {
				right = level[2*i+1]
			}
			h := sha256.New()
			h.Write([]byte{0x01})
			h.Write(left[:])
			h.Write(right[:])
			copy(next[i][:], h.Sum(nil))
		}
		level = next
	}
	return hex.EncodeToString(level[0][:])
}

// HashVectorMicro returns SHA-256 hex digest of a canonical micro-unit vector array.
func HashVectorMicro(v [FeatureDim]float64) string {
	var buf bytes.Buffer
	appendInt64Slice(&buf, VecToMicro(v))
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

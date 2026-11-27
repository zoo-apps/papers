// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package infnet

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	SchemaVersion = "inference-net.v1"
	SpecVersion   = "1.0.0"

	DomainNodeAdv      = "ZOO-INFNET-V1-NODE-ADV\x00"
	DomainReceipt      = "ZOO-INFNET-V1-RECEIPT\x00"
	DomainEmptyMerkle  = "ZOO-INFNET-V1-EMPTY-MERKLE"
	DomainVerdict      = "ZOO-INFNET-V1-VERDICT\x00"
	DomainKeyDerive    = "ZOO-INFNET-V1-NODE-KEY\x00"
	DomainCorpusRoot   = "ZOO-INFNET-V1-CORPUS\x00"
	DomainTokenDerive  = "ZOO-INFNET-V1-TOKEN\x00"
	DomainTEEQuote     = "ZOO-INFNET-V1-TEE-ATTEST\x00"
)

// HardwareProfile enumerates supported heterogeneous compute profiles.
type HardwareProfile string

const (
	HWProfileH100       HardwareProfile = "H100-80GB"
	HWProfileRTX4090    HardwareProfile = "RTX-4090-24GB"
	HWProfileMacM4Max   HardwareProfile = "Mac-M4-Max-64GB"
	HWProfileConsumer12 HardwareProfile = "Consumer-12GB"
)

// ExecutionRole specifies how a worker participates in model serving.
type ExecutionRole string

const (
	RoleWholeModel    ExecutionRole = "WHOLE_MODEL"
	RolePrefill       ExecutionRole = "PREFILL"
	RoleDecode        ExecutionRole = "DECODE"
	RolePipelineStage ExecutionRole = "PIPELINE_STAGE"
)

// PrivacyTier defines a worker's execution confidentiality boundary.
type PrivacyTier string

const (
	PrivacyTEEAttested  PrivacyTier = "TEE_ATTESTED"
	PrivacyLocalPrivate PrivacyTier = "LOCAL_PRIVATE"
	PrivacyPublicRelay  PrivacyTier = "PUBLIC_RELAY"
)

// PrivacyRequirement defines the caller's mandatory privacy policy.
type PrivacyRequirement string

const (
	PrivacyReqPublicOK PrivacyRequirement = "PUBLIC_OK"
	PrivacyReqStrict   PrivacyRequirement = "PRIVACY_STRICT"
)

// TopologyMode enumerates the 4 benchmarked inference routing topologies.
type TopologyMode string

const (
	TopologyCentralizedBaseline TopologyMode = "centralized_datacenter_baseline"
	TopologyDynamoReplica       TopologyMode = "decentralized_replica_dynamo"
	TopologyPetalsPipeline      TopologyMode = "decentralized_pipeline_petals"
	TopologyStrictTEE           TopologyMode = "decentralized_privacy_strict_tee"
)

// DeliveryStatus describes the terminal state of an inference request.
type DeliveryStatus string

const (
	StatusCompleted         DeliveryStatus = "COMPLETED"
	StatusCompletedFailover DeliveryStatus = "COMPLETED_WITH_FAILOVER"
	StatusRejectedPrivacy   DeliveryStatus = "REJECTED_PRIVACY"
	StatusFailedExhausted   DeliveryStatus = "FAILED_EXHAUSTED"
)

// Canonical verification error codes (shared byte-for-byte with Python).
const (
	ErrCodeOK                       = "OK"
	ErrCodeSchemaInvalid            = "ERR_SCHEMA_INVALID"
	ErrCodeInvalidNodeAdvertisement = "ERR_INVALID_NODE_ADVERTISEMENT"
	ErrCodeStaleHeartbeatEpoch      = "ERR_STALE_HEARTBEAT_EPOCH"
	ErrCodeKeyMismatch              = "ERR_KEY_MISMATCH"
	ErrCodeInvalidReceiptSignature  = "ERR_INVALID_RECEIPT_SIGNATURE"
	ErrCodeOutputMerkleMismatch     = "ERR_OUTPUT_MERKLE_MISMATCH"
	ErrCodePrivacyBoundaryViolation = "ERR_PRIVACY_BOUNDARY_VIOLATION"
	ErrCodeCapacityConservation     = "ERR_CAPACITY_CONSERVATION"
	ErrCodeConstitutionalViolation  = "ERR_CONSTITUTIONAL_VIOLATION"
	ErrCodeMissingProviderNode      = "ERR_MISSING_PROVIDER_NODE"
)

// Sentinel errors used by runtime components.
var (
	ErrPrivacyBoundaryViolation = errors.New(ErrCodePrivacyBoundaryViolation)
	ErrCapacityExhausted        = errors.New("ERR_CAPACITY_EXHAUSTED")
	ErrStaleHeartbeatEpoch      = errors.New(ErrCodeStaleHeartbeatEpoch)
	ErrKeyMismatch              = errors.New(ErrCodeKeyMismatch)
	ErrNoHealthyNodes           = errors.New("ERR_NO_HEALTHY_NODES")
	ErrConstitutionalViolation  = errors.New(ErrCodeConstitutionalViolation)
)

// NodeAdvertisement is a permissionless RFC 8032 Ed25519 signed worker capability record.
type NodeAdvertisement struct {
	SchemaVersion       string          `json:"schema_version"`
	NodeID              string          `json:"node_id"`
	PublicKeyHex        string          `json:"public_key_hex"`
	HardwareProfile     HardwareProfile `json:"hardware_profile"`
	ModelID             string          `json:"model_id"`
	ExecutionRole       ExecutionRole   `json:"execution_role"`
	LayerStart          uint32          `json:"layer_start"`
	LayerEnd            uint32          `json:"layer_end"`
	TotalLayers         uint32          `json:"total_layers"`
	VRAMTotalMiB        uint64          `json:"vram_total_mib"`
	VRAMReservedBaseMiB uint64          `json:"vram_reserved_base_mib"`
	KVSlotsTotal        uint32          `json:"kv_slots_total"`
	PrefillTPS          uint32          `json:"prefill_tps"`
	DecodeTPS           uint32          `json:"decode_tps"`
	WANRTTUs            uint64          `json:"wan_rtt_us"`
	BandwidthKbps       uint64          `json:"bandwidth_kbps"`
	PrivacyTier         PrivacyTier     `json:"privacy_tier"`
	TEEAttestationSHA   string          `json:"tee_attestation_sha256"`
	HeartbeatEpoch      uint64          `json:"heartbeat_epoch"`
	TimestampUnixS      uint64          `json:"timestamp_unix_s"`
	SignatureHex        string          `json:"signature_hex"`
}

// CapacityEvent records an atomic VRAM + KV-cache reservation or release.
type CapacityEvent struct {
	Seq           uint64 `json:"seq"`
	Action        string `json:"action"` // "RESERVE" or "RELEASE"
	ReservationID string `json:"reservation_id"`
	NodeID        string `json:"node_id"`
	RequestID     string `json:"request_id"`
	VRAMMiB       uint64 `json:"vram_mib"`
	KVSlots       uint32 `json:"kv_slots"`
	Reason        string `json:"reason"`
}

// InferenceRequest represents a single grounded inference request.
type InferenceRequest struct {
	RequestID          string             `json:"request_id"`
	ModelID            string             `json:"model_id"`
	PromptText         string             `json:"prompt_text"`
	PromptSHA256       string             `json:"prompt_sha256"`
	PromptPrefixSHA256 string             `json:"prompt_prefix_sha256"`
	PromptTokens       uint32             `json:"prompt_tokens"`
	MaxOutputTokens    uint32             `json:"max_output_tokens"`
	PrivacyRequirement PrivacyRequirement `json:"privacy_requirement"`
	ArrivalUs          uint64             `json:"arrival_us"`
	SourcePaper        string             `json:"source_paper"`
}

// DeliveryReceipt is the cryptographically signed delivery & accounting proof.
type DeliveryReceipt struct {
	SchemaVersion           string             `json:"schema_version"`
	ReceiptID               string             `json:"receipt_id"`
	RequestID               string             `json:"request_id"`
	TopologyMode            TopologyMode       `json:"topology_mode"`
	ModelID                 string             `json:"model_id"`
	PromptSHA256            string             `json:"prompt_sha256"`
	PromptPrefixSHA256      string             `json:"prompt_prefix_sha256"`
	PromptTokens            uint32             `json:"prompt_tokens"`
	OutputTokens            uint32             `json:"output_tokens"`
	OutputMerkleRoot        string             `json:"output_merkle_root"`
	PrivacyRequirement      PrivacyRequirement `json:"privacy_requirement"`
	EffectivePrivacyTier    PrivacyTier        `json:"effective_privacy_tier"`
	RouteNodeIDs            []string           `json:"route_node_ids"`
	PrimaryProviderID       string             `json:"primary_provider_id"`
	ProviderPublicKeyHex    string             `json:"provider_public_key_hex"`
	PrefillNodeID           string             `json:"prefill_node_id"`
	DecodeNodeIDs           []string           `json:"decode_node_ids"`
	KVSlotsReserved         uint32             `json:"kv_slots_reserved"`
	VRAMReservedMiB         uint64             `json:"vram_reserved_mib"`
	NetworkBytesTransferred uint64             `json:"network_bytes_transferred"`
	TTFTUs                  uint64             `json:"ttft_us"`
	TPOTUs                  uint64             `json:"tpot_us"`
	TotalLatencyUs          uint64             `json:"total_latency_us"`
	RecoveryLatencyUs       uint64             `json:"recovery_latency_us"`
	FailoverAttempts        uint32             `json:"failover_attempts"`
	FailedNodeIDs           []string           `json:"failed_node_ids"`
	BatchSizeEffective      uint32             `json:"batch_size_effective"`
	BatchUtilizationBps     uint32             `json:"batch_utilization_bps"`
	Status                  DeliveryStatus     `json:"status"`
	ProvesScientificTruth   bool               `json:"proves_scientific_truth"`
	AuthorizesTreasurySpend bool               `json:"authorizes_treasury_spend"`
	SignatureHex            string             `json:"signature_hex"`
}

// ParityCase packages an end-to-end verifiable case for Go <-> Python parity.
type ParityCase struct {
	CaseID                string              `json:"case_id"`
	Description           string              `json:"description"`
	Nodes                 []NodeAdvertisement `json:"nodes"`
	Receipt               DeliveryReceipt     `json:"receipt"`
	OutputChunks          []string            `json:"output_chunks"`
	CapacityLedger        []CapacityEvent     `json:"capacity_ledger"`
	ExpectedValid         bool                `json:"expected_valid"`
	ExpectedErrorCode     string              `json:"expected_error_code"`
	ExpectedVerdictDigest string              `json:"expected_verdict_digest"`
}

// ParitySuite holds all canonical parity test cases and the root audit digest.
type ParitySuite struct {
	SchemaVersion   string       `json:"schema_version"`
	SpecVersion     string       `json:"spec_version"`
	CorpusRootSHA   string       `json:"corpus_root_sha256"`
	Seed            uint64       `json:"seed"`
	Cases           []ParityCase `json:"cases"`
	AuditMerkleRoot string       `json:"audit_merkle_root"`
}

// VerificationResult captures deterministic verification output for one ParityCase.
type VerificationResult struct {
	CaseID              string `json:"case_id"`
	Valid               bool   `json:"valid"`
	ErrorCode           string `json:"error_code"`
	Detail              string `json:"detail"`
	SignatureValid      bool   `json:"signature_valid"`
	PrivacyCompliant    bool   `json:"privacy_compliant"`
	CapacityConserved   bool   `json:"capacity_conserved"`
	ConstitutionalValid bool   `json:"constitutional_valid"`
	VerdictDigest       string `json:"verdict_digest"`
}

// DeriveNodeKey deterministically derives an Ed25519 keypair for a node from seed + nodeID.
func DeriveNodeKey(seed uint64, nodeID string) (ed25519.PublicKey, ed25519.PrivateKey) {
	h := sha256.New()
	h.Write([]byte(DomainKeyDerive))
	var sb [8]byte
	binary.BigEndian.PutUint64(sb[:], seed)
	h.Write(sb[:])
	h.Write([]byte(nodeID))
	sum := h.Sum(nil)
	priv := ed25519.NewKeyFromSeed(sum[:ed25519.SeedSize])
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv
}

// DeriveTEEAttestation computes a deterministic mock TEE quote SHA-256 for attested nodes.
func DeriveTEEAttestation(seed uint64, nodeID string, hw HardwareProfile) string {
	h := sha256.New()
	h.Write([]byte(DomainTEEQuote))
	var sb [8]byte
	binary.BigEndian.PutUint64(sb[:], seed)
	h.Write(sb[:])
	h.Write([]byte(nodeID))
	h.Write([]byte{0})
	h.Write([]byte(hw))
	return hex.EncodeToString(h.Sum(nil))
}

func appendLPString(buf []byte, s string) []byte {
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(s)))
	buf = append(buf, lb[:]...)
	return append(buf, s...)
}

func appendLPStringSlice(buf []byte, xs []string) []byte {
	var cb [4]byte
	binary.BigEndian.PutUint32(cb[:], uint32(len(xs)))
	buf = append(buf, cb[:]...)
	for _, s := range xs {
		buf = appendLPString(buf, s)
	}
	return buf
}

func appendU32(buf []byte, v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return append(buf, b[:]...)
}

func appendU64(buf []byte, v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return append(buf, b[:]...)
}

func appendBool(buf []byte, v bool) []byte {
	if v {
		return append(buf, 1)
	}
	return append(buf, 0)
}

// CanonicalNodeAdvertisementBytes produces the exact byte payload signed by Ed25519.
func CanonicalNodeAdvertisementBytes(a NodeAdvertisement) []byte {
	buf := make([]byte, 0, 256)
	buf = append(buf, []byte(DomainNodeAdv)...)
	buf = appendLPString(buf, a.SchemaVersion)
	buf = appendLPString(buf, a.NodeID)
	buf = appendLPString(buf, a.PublicKeyHex)
	buf = appendLPString(buf, string(a.HardwareProfile))
	buf = appendLPString(buf, a.ModelID)
	buf = appendLPString(buf, string(a.ExecutionRole))
	buf = appendU32(buf, a.LayerStart)
	buf = appendU32(buf, a.LayerEnd)
	buf = appendU32(buf, a.TotalLayers)
	buf = appendU64(buf, a.VRAMTotalMiB)
	buf = appendU64(buf, a.VRAMReservedBaseMiB)
	buf = appendU32(buf, a.KVSlotsTotal)
	buf = appendU32(buf, a.PrefillTPS)
	buf = appendU32(buf, a.DecodeTPS)
	buf = appendU64(buf, a.WANRTTUs)
	buf = appendU64(buf, a.BandwidthKbps)
	buf = appendLPString(buf, string(a.PrivacyTier))
	buf = appendLPString(buf, a.TEEAttestationSHA)
	buf = appendU64(buf, a.HeartbeatEpoch)
	buf = appendU64(buf, a.TimestampUnixS)
	return buf
}

// SignNodeAdvertisement signs a NodeAdvertisement with the node's Ed25519 private key.
func SignNodeAdvertisement(a *NodeAdvertisement, priv ed25519.PrivateKey) {
	pub := priv.Public().(ed25519.PublicKey)
	a.SchemaVersion = SchemaVersion
	a.PublicKeyHex = hex.EncodeToString(pub)
	msg := CanonicalNodeAdvertisementBytes(*a)
	sig := ed25519.Sign(priv, msg)
	a.SignatureHex = hex.EncodeToString(sig)
}

// VerifyNodeAdvertisementSignature verifies the RFC 8032 Ed25519 signature of a NodeAdvertisement.
func VerifyNodeAdvertisementSignature(a NodeAdvertisement) bool {
	pub, err := hex.DecodeString(a.PublicKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(a.SignatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	msg := CanonicalNodeAdvertisementBytes(a)
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// CanonicalDeliveryReceiptBytes produces the exact byte payload signed by the provider.
func CanonicalDeliveryReceiptBytes(r DeliveryReceipt) []byte {
	buf := make([]byte, 0, 512)
	buf = append(buf, []byte(DomainReceipt)...)
	buf = appendLPString(buf, r.SchemaVersion)
	buf = appendLPString(buf, r.ReceiptID)
	buf = appendLPString(buf, r.RequestID)
	buf = appendLPString(buf, string(r.TopologyMode))
	buf = appendLPString(buf, r.ModelID)
	buf = appendLPString(buf, r.PromptSHA256)
	buf = appendLPString(buf, r.PromptPrefixSHA256)
	buf = appendU32(buf, r.PromptTokens)
	buf = appendU32(buf, r.OutputTokens)
	buf = appendLPString(buf, r.OutputMerkleRoot)
	buf = appendLPString(buf, string(r.PrivacyRequirement))
	buf = appendLPString(buf, string(r.EffectivePrivacyTier))
	buf = appendLPStringSlice(buf, r.RouteNodeIDs)
	buf = appendLPString(buf, r.PrimaryProviderID)
	buf = appendLPString(buf, r.ProviderPublicKeyHex)
	buf = appendLPString(buf, r.PrefillNodeID)
	buf = appendLPStringSlice(buf, r.DecodeNodeIDs)
	buf = appendU32(buf, r.KVSlotsReserved)
	buf = appendU64(buf, r.VRAMReservedMiB)
	buf = appendU64(buf, r.NetworkBytesTransferred)
	buf = appendU64(buf, r.TTFTUs)
	buf = appendU64(buf, r.TPOTUs)
	buf = appendU64(buf, r.TotalLatencyUs)
	buf = appendU64(buf, r.RecoveryLatencyUs)
	buf = appendU32(buf, r.FailoverAttempts)
	buf = appendLPStringSlice(buf, r.FailedNodeIDs)
	buf = appendU32(buf, r.BatchSizeEffective)
	buf = appendU32(buf, r.BatchUtilizationBps)
	buf = appendLPString(buf, string(r.Status))
	buf = appendBool(buf, r.ProvesScientificTruth)
	buf = appendBool(buf, r.AuthorizesTreasurySpend)
	return buf
}

// SignDeliveryReceipt signs a DeliveryReceipt with the primary provider's Ed25519 private key.
func SignDeliveryReceipt(r *DeliveryReceipt, priv ed25519.PrivateKey) {
	pub := priv.Public().(ed25519.PublicKey)
	r.SchemaVersion = SchemaVersion
	r.ProviderPublicKeyHex = hex.EncodeToString(pub)
	msg := CanonicalDeliveryReceiptBytes(*r)
	sig := ed25519.Sign(priv, msg)
	r.SignatureHex = hex.EncodeToString(sig)
}

// VerifyDeliveryReceiptSignature verifies the provider Ed25519 signature of a DeliveryReceipt.
func VerifyDeliveryReceiptSignature(r DeliveryReceipt) bool {
	pub, err := hex.DecodeString(r.ProviderPublicKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(r.SignatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	msg := CanonicalDeliveryReceiptBytes(r)
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// ComputeOutputMerkleRoot computes the SHA-256 binary Merkle root over ordered output token chunks.
func ComputeOutputMerkleRoot(chunks []string) string {
	if len(chunks) == 0 {
		sum := sha256.Sum256([]byte(DomainEmptyMerkle))
		return hex.EncodeToString(sum[:])
	}
	leaves := make([][32]byte, len(chunks))
	for i, ch := range chunks {
		h := sha256.New()
		h.Write([]byte{0x00})
		var ib [4]byte
		binary.BigEndian.PutUint32(ib[:], uint32(i))
		h.Write(ib[:])
		h.Write([]byte(ch))
		copy(leaves[i][:], h.Sum(nil))
	}
	root := reduceMerkle(leaves)
	return hex.EncodeToString(root[:])
}

// ComputeMerkleRootFromHexDigests builds a binary SHA-256 Merkle root from 32-byte hex digests.
func ComputeMerkleRootFromHexDigests(digests []string) (string, error) {
	if len(digests) == 0 {
		sum := sha256.Sum256([]byte(DomainEmptyMerkle))
		return hex.EncodeToString(sum[:]), nil
	}
	nodes := make([][32]byte, len(digests))
	for i, d := range digests {
		raw, err := hex.DecodeString(d)
		if err != nil || len(raw) != 32 {
			return "", fmt.Errorf("invalid digest at index %d", i)
		}
		copy(nodes[i][:], raw)
	}
	root := reduceMerkle(nodes)
	return hex.EncodeToString(root[:]), nil
}

func reduceMerkle(level [][32]byte) [32]byte {
	cur := make([][32]byte, len(level))
	copy(cur, level)
	for len(cur) > 1 {
		nextLen := (len(cur) + 1) / 2
		next := make([][32]byte, nextLen)
		for i := 0; i < len(cur); i += 2 {
			left := cur[i]
			right := left
			if i+1 < len(cur) {
				right = cur[i+1]
			}
			h := sha256.New()
			h.Write([]byte{0x01})
			h.Write(left[:])
			h.Write(right[:])
			copy(next[i/2][:], h.Sum(nil))
		}
		cur = next
	}
	return cur[0]
}

// ComputeVerdictDigest produces a deterministic 32-byte hex digest of a VerificationResult.
func ComputeVerdictDigest(res VerificationResult, outputMerkleRoot string) string {
	buf := make([]byte, 0, 160)
	buf = append(buf, []byte(DomainVerdict)...)
	buf = appendLPString(buf, res.CaseID)
	buf = appendBool(buf, res.Valid)
	buf = appendLPString(buf, res.ErrorCode)
	buf = appendBool(buf, res.SignatureValid)
	buf = appendBool(buf, res.PrivacyCompliant)
	buf = appendBool(buf, res.CapacityConserved)
	buf = appendBool(buf, res.ConstitutionalValid)
	buf = appendLPString(buf, outputMerkleRoot)
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

// IsValidHardwareProfile checks whether a hardware profile is in the v1 enum.
func IsValidHardwareProfile(p HardwareProfile) bool {
	switch p {
	case HWProfileH100, HWProfileRTX4090, HWProfileMacM4Max, HWProfileConsumer12:
		return true
	default:
		return false
	}
}

// IsValidExecutionRole checks whether an execution role is in the v1 enum.
func IsValidExecutionRole(r ExecutionRole) bool {
	switch r {
	case RoleWholeModel, RolePrefill, RoleDecode, RolePipelineStage:
		return true
	default:
		return false
	}
}

// IsValidPrivacyTier checks whether a privacy tier is in the v1 enum.
func IsValidPrivacyTier(t PrivacyTier) bool {
	switch t {
	case PrivacyTEEAttested, PrivacyLocalPrivate, PrivacyPublicRelay:
		return true
	default:
		return false
	}
}

// IsValidTopologyMode checks whether a topology mode is in the v1 enum.
func IsValidTopologyMode(m TopologyMode) bool {
	switch m {
	case TopologyCentralizedBaseline, TopologyDynamoReplica, TopologyPetalsPipeline, TopologyStrictTEE:
		return true
	default:
		return false
	}
}

// PrivacyTierSatisfies returns true iff nodeTier is permitted under req.
func PrivacyTierSatisfies(req PrivacyRequirement, nodeTier PrivacyTier) bool {
	if req == PrivacyReqPublicOK {
		return IsValidPrivacyTier(nodeTier)
	}
	if req == PrivacyReqStrict {
		return nodeTier == PrivacyTEEAttested || nodeTier == PrivacyLocalPrivate
	}
	return false
}

// EffectiveTierForRoute returns the weakest (least confidential) privacy tier touched on a route.
func EffectiveTierForRoute(tiers []PrivacyTier) PrivacyTier {
	if len(tiers) == 0 {
		return PrivacyPublicRelay
	}
	rank := func(t PrivacyTier) int {
		switch t {
		case PrivacyTEEAttested:
			return 3
		case PrivacyLocalPrivate:
			return 2
		default:
			return 1
		}
	}
	minTier := tiers[0]
	for _, t := range tiers[1:] {
		if rank(t) < rank(minTier) {
			minTier = t
		}
	}
	return minTier
}

// DeterministicOutputChunks generates deterministic token chunks for a request.
func DeterministicOutputChunks(promptSHA string, modelID string, count uint32) []string {
	chunks := make([]string, count)
	for i := uint32(0); i < count; i++ {
		h := sha256.New()
		h.Write([]byte(DomainTokenDerive))
		h.Write([]byte(promptSHA))
		h.Write([]byte{0})
		h.Write([]byte(modelID))
		var ib [4]byte
		binary.BigEndian.PutUint32(ib[:], i)
		h.Write(ib[:])
		sum := h.Sum(nil)
		chunks[i] = fmt.Sprintf("tok_%04d_%s", i, hex.EncodeToString(sum[:4]))
	}
	return chunks
}

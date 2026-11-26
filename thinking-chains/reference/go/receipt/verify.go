// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation and Contributors

package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var (
	hex64Re  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex128Re = regexp.MustCompile(`^[0-9a-f]{128}$`)
	idRe     = regexp.MustCompile(`^[A-Za-z0-9._:/-]{2,128}$`)
)

var forbiddenCoTKeyTokens = []string{
	"private_cot",
	"chain_of_thought",
	"internal_cot",
	"hidden_reasoning",
	"raw_thinking",
	"private_scratchpad",
	"thought_tokens",
	"internal_monologue",
	"reasoning_trace_private",
}

var forbiddenPrivateURIPrefixes = []string{
	"private://",
	"cot://",
	"internal-cot://",
	"hidden-cot://",
}

var (
	allowedTaskTypes = map[string]bool{
		"math_verification":   true,
		"code_synthesis":      true,
		"corpus_retrieval":    true,
		"benchmark_eval":      true,
		"governance_advisory": true,
	}
	allowedInferenceTiers = map[string]bool{
		"tier1_deterministic_int8": true,
		"tier2_quorum":             true,
		"tier2_attested_tee":       true,
		"tier2_zkml":               true,
	}
	allowedEvidenceModes = map[string]bool{
		"deterministic_recomputation": true,
		"quorum_signatures":           true,
		"tee_attestation":             true,
		"zkml_proof":                  true,
	}
	allowedEvidenceKinds = map[string]bool{
		"execution_trace_digest":  true,
		"intermediate_artifact":   true,
		"public_rationale_digest": true,
		"benchmark_log_digest":    true,
		"prior_receipt_ref":       true,
		"tee_quote_digest":        true,
	}
	allowedCheckTypes = map[string]bool{
		"deterministic_replay": true,
		"unit_test_suite":      true,
		"hash_match":           true,
		"schema_validation":    true,
		"metric_threshold":     true,
		"differential_parity":  true,
	}
	allowedResultStatuses = map[string]bool{
		"completed": true,
		"failed":    true,
		"contested": true,
		"abstained": true,
	}
	allowedProposedActionScopes = map[string]bool{
		"research_artifact":       true,
		"advisory_recommendation": true,
		"benchmark_report":        true,
		"model_delta_proposal":    true,
	}
	allowedVerifierRoles = map[string]bool{
		"independent_verifier":  true,
		"quorum_validator":      true,
		"hardware_tee_verifier": true,
		"human_reviewer":        true,
	}
	allowedVerdicts = map[string]bool{
		"VALID":     true,
		"REJECT":    true,
		"CONTESTED": true,
	}
)

var (
	topLevelKeys = []string{
		"schema_version", "job_id", "nonce", "objective", "execution",
		"inputs", "authorized_tools", "public_evidence", "checks",
		"result", "provenance", "settlement", "attestations",
	}
	objectiveKeys = []string{
		"task_type", "summary", "objective_hash", "output_space_id",
		"governance_level", "recursion_depth", "max_recursion_depth",
	}
	executionKeys = []string{
		"executor_id", "model_id", "model_version", "model_spec_hash",
		"execution_profile_id", "inference_tier", "evidence_mode",
		"public_trace_only", "hardware_class",
	}
	inputKeys = []string{
		"artifact_id", "role", "uri", "media_type", "byte_length", "sha256",
	}
	toolKeys = []string{
		"seq", "tool_name", "tool_version", "deterministic",
		"args_sha256", "output_sha256", "wall_time_ms", "exit_code",
	}
	evidenceKeys = []string{
		"evidence_id", "kind", "uri", "byte_length", "sha256", "public_only",
	}
	checkKeys = []string{
		"check_id", "check_type", "passed", "metric_name",
		"metric_bps", "threshold_bps", "verifier_cmd_sha256", "log_sha256",
	}
	resultKeys = []string{
		"status", "canonical_output_sha256", "output_byte_length",
		"finite_verdict", "quality_score_bps", "dissent_bps", "proposed_action_scope",
	}
	provenanceKeys = []string{
		"hash_algorithm", "domain_separator", "inputs_root", "tools_root",
		"evidence_root", "checks_root", "result_digest", "provenance_root",
	}
	settlementKeys = []string{
		"chain_id", "escrow_ref", "intent_id", "payer", "fee_units",
		"subsidy_eligible", "settled_at_height", "settled_at_unix",
		"treasury_spend_authorized", "voting_rules_modified",
	}
	attestationKeys = []string{
		"verifier_id", "verifier_role", "algorithm", "public_key_hex",
		"verdict", "attested_receipt_hash", "attested_at_unix", "signature_hex",
	}
)

// LoadPolicy loads and strictly parses a PolicyBundle JSON file.
func LoadPolicy(path string) (*PolicyBundle, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, newError("ERR_INVALID_JSON", "failed to read policy file: %v", err)
	}
	if _, err := ParseStrictJSON(raw); err != nil {
		return nil, err
	}
	var bundle PolicyBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return nil, newError("ERR_SCHEMA_VIOLATION", "invalid policy structure: %v", err)
	}
	if bundle.AuthorizedProfiles == nil || bundle.TrustedVerifiers == nil {
		return nil, newError("ERR_SCHEMA_VIOLATION", "policy must define authorized_profiles and trusted_verifiers")
	}
	return &bundle, nil
}

func scanPrivateCoT(node any, path string) error {
	switch v := node.(type) {
	case map[string]any:
		for k, child := range v {
			kl := strings.ToLower(k)
			for _, tok := range forbiddenCoTKeyTokens {
				if strings.Contains(kl, tok) {
					return newError("ERR_PRIVATE_COT_FORBIDDEN", "forbidden private chain-of-thought key %q at %s", k, path)
				}
			}
			if err := scanPrivateCoT(child, path+"."+k); err != nil {
				return err
			}
		}
	case []any:
		for i, item := range v {
			if err := scanPrivateCoT(item, path+"["+strconv.Itoa(i)+"]"); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkExactKeys(node any, expected []string, ctx string) (map[string]any, error) {
	obj, ok := node.(map[string]any)
	if !ok {
		return nil, newError("ERR_SCHEMA_VIOLATION", "%s must be a JSON object", ctx)
	}
	expSet := make(map[string]bool, len(expected))
	for _, k := range expected {
		expSet[k] = true
		if _, exists := obj[k]; !exists {
			return nil, newError("ERR_SCHEMA_VIOLATION", "%s missing required key %q", ctx, k)
		}
	}
	for k := range obj {
		if !expSet[k] {
			return nil, newError("ERR_SCHEMA_VIOLATION", "%s contains unknown key %q", ctx, k)
		}
	}
	return obj, nil
}

func checkString(val any, ctx string) (string, error) {
	s, ok := val.(string)
	if !ok {
		return "", newError("ERR_SCHEMA_VIOLATION", "%s must be a string", ctx)
	}
	return s, nil
}

func checkHex64(val any, ctx string) (string, error) {
	s, err := checkString(val, ctx)
	if err != nil || !hex64Re.MatchString(s) {
		return "", newError("ERR_SCHEMA_VIOLATION", "%s must be 64 lowercase hex chars", ctx)
	}
	return s, nil
}

func checkHex128(val any, ctx string) (string, error) {
	s, err := checkString(val, ctx)
	if err != nil || !hex128Re.MatchString(s) {
		return "", newError("ERR_SCHEMA_VIOLATION", "%s must be 128 lowercase hex chars", ctx)
	}
	return s, nil
}

func checkID(val any, ctx string) (string, error) {
	s, err := checkString(val, ctx)
	if err != nil || !idRe.MatchString(s) {
		return "", newError("ERR_SCHEMA_VIOLATION", "%s must be a valid identifier", ctx)
	}
	return s, nil
}

func checkNonEmptyStr(val any, ctx string, maxLen int) (string, error) {
	s, err := checkString(val, ctx)
	if err != nil || len(s) == 0 || len(s) > maxLen {
		return "", newError("ERR_SCHEMA_VIOLATION", "%s must be a non-empty string of length <= %d", ctx, maxLen)
	}
	return s, nil
}

func checkBool(val any, ctx string) (bool, error) {
	b, ok := val.(bool)
	if !ok {
		return false, newError("ERR_SCHEMA_VIOLATION", "%s must be a boolean", ctx)
	}
	return b, nil
}

func checkInt64(val any, ctx string) (int64, error) {
	n, ok := val.(int64)
	if !ok {
		return 0, newError("ERR_SCHEMA_VIOLATION", "%s must be an integer", ctx)
	}
	return n, nil
}

func checkIntRange(val any, ctx string, lo int64, hasHi bool, hi int64) (int64, error) {
	n, err := checkInt64(val, ctx)
	if err != nil {
		return 0, err
	}
	if n < lo || (hasHi && n > hi) {
		return 0, newError("ERR_SCHEMA_VIOLATION", "%s out of allowed range", ctx)
	}
	return n, nil
}

func canonicalLeaves(items []any) ([][]byte, error) {
	leaves := make([][]byte, len(items))
	for i, item := range items {
		b, err := CanonicalJSON(item)
		if err != nil {
			return nil, err
		}
		leaves[i] = b
	}
	return leaves, nil
}

// ComputeProvenance deterministically recomputes all section Merkle roots and the provenance root.
func ComputeProvenance(rec map[string]any) (*ProvenanceCommitment, error) {
	inputsArr, ok := rec["inputs"].([]any)
	if !ok {
		return nil, newError("ERR_SCHEMA_VIOLATION", "inputs must be an array")
	}
	toolsArr, ok := rec["authorized_tools"].([]any)
	if !ok {
		return nil, newError("ERR_SCHEMA_VIOLATION", "authorized_tools must be an array")
	}
	evArr, ok := rec["public_evidence"].([]any)
	if !ok {
		return nil, newError("ERR_SCHEMA_VIOLATION", "public_evidence must be an array")
	}
	checksArr, ok := rec["checks"].([]any)
	if !ok {
		return nil, newError("ERR_SCHEMA_VIOLATION", "checks must be an array")
	}

	inputLeaves, err := canonicalLeaves(inputsArr)
	if err != nil {
		return nil, err
	}
	toolLeaves, err := canonicalLeaves(toolsArr)
	if err != nil {
		return nil, err
	}
	evLeaves, err := canonicalLeaves(evArr)
	if err != nil {
		return nil, err
	}
	checkLeaves, err := canonicalLeaves(checksArr)
	if err != nil {
		return nil, err
	}

	inputsRoot := MerkleRoot("inputs", inputLeaves)
	toolsRoot := MerkleRoot("tools", toolLeaves)
	evidenceRoot := MerkleRoot("evidence", evLeaves)
	checksRoot := MerkleRoot("checks", checkLeaves)

	resCanon, err := CanonicalJSON(rec["result"])
	if err != nil {
		return nil, err
	}
	rh := sha256.New()
	rh.Write([]byte(ResultDomainPrefix))
	rh.Write(resCanon)
	var resultDigest [32]byte
	copy(resultDigest[:], rh.Sum(nil))

	provLeaves := [][]byte{
		inputsRoot[:],
		toolsRoot[:],
		evidenceRoot[:],
		checksRoot[:],
		resultDigest[:],
	}
	provRoot := MerkleRoot("provenance", provLeaves)

	return &ProvenanceCommitment{
		HashAlgorithm:   "sha256",
		DomainSeparator: SchemaVersion,
		InputsRoot:      hex.EncodeToString(inputsRoot[:]),
		ToolsRoot:       hex.EncodeToString(toolsRoot[:]),
		EvidenceRoot:    hex.EncodeToString(evidenceRoot[:]),
		ChecksRoot:      hex.EncodeToString(checksRoot[:]),
		ResultDigest:    hex.EncodeToString(resultDigest[:]),
		ProvenanceRoot:  hex.EncodeToString(provRoot[:]),
	}, nil
}

// CanonicalReceiptHash computes the domain-separated SHA-256 hash over the unsigned receipt payload.
func CanonicalReceiptHash(rec map[string]any) (string, error) {
	unsigned := make(map[string]any, len(rec))
	for k, v := range rec {
		if k != "attestations" {
			unsigned[k] = v
		}
	}
	canon, err := CanonicalJSON(unsigned)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(ReceiptDomainPrefix))
	h.Write(canon)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// AttestationMessage constructs the exact domain-separated RFC 8032 signing preimage.
func AttestationMessage(receiptHashHex, verifierID, verifierRole, verdict string, attestedAtUnix int64) []byte {
	var buf bytes.Buffer
	buf.WriteString(AttestationDomainPrefix)
	buf.WriteString(receiptHashHex)
	buf.WriteByte(0x00)
	buf.WriteString(verifierID)
	buf.WriteByte(0x00)
	buf.WriteString(verifierRole)
	buf.WriteByte(0x00)
	buf.WriteString(verdict)
	buf.WriteByte(0x00)
	buf.WriteString(strconv.FormatInt(attestedAtUnix, 10))
	return buf.Bytes()
}

// VerifyReceiptBytes strictly parses raw JSON and performs complete independent verification.
func VerifyReceiptBytes(raw []byte, policy *PolicyBundle) (*VerificationResult, error) {
	parsed, err := ParseStrictJSON(raw)
	if err != nil {
		return nil, err
	}
	return VerifyReceipt(parsed, policy)
}

// VerifyReceipt runs all schema, privacy, constitutional, policy, provenance, and Ed25519 checks.
func VerifyReceipt(parsed any, policy *PolicyBundle) (*VerificationResult, error) {
	if policy == nil {
		return nil, newError("ERR_SCHEMA_VIOLATION", "policy bundle is required")
	}

	// 1. Recursive private-CoT key scan before schema validation.
	if err := scanPrivateCoT(parsed, "$"); err != nil {
		return nil, err
	}

	// 2. Top-level exact key check.
	rec, err := checkExactKeys(parsed, topLevelKeys, "receipt")
	if err != nil {
		return nil, err
	}
	sv, err := checkString(rec["schema_version"], "schema_version")
	if err != nil || sv != SchemaVersion {
		return nil, newError("ERR_SCHEMA_VIOLATION", "unsupported schema_version: %v", rec["schema_version"])
	}
	jobID, err := checkID(rec["job_id"], "job_id")
	if err != nil {
		return nil, err
	}
	if _, err := checkHex64(rec["nonce"], "nonce"); err != nil {
		return nil, err
	}

	// 3. Objective validation.
	obj, err := checkExactKeys(rec["objective"], objectiveKeys, "objective")
	if err != nil {
		return nil, err
	}
	taskType, err := checkString(obj["task_type"], "objective.task_type")
	if err != nil || !allowedTaskTypes[taskType] {
		return nil, newError("ERR_SCHEMA_VIOLATION", "invalid task_type: %v", obj["task_type"])
	}
	if _, err := checkNonEmptyStr(obj["summary"], "objective.summary", 512); err != nil {
		return nil, err
	}
	if _, err := checkHex64(obj["objective_hash"], "objective.objective_hash"); err != nil {
		return nil, err
	}
	if _, err := checkID(obj["output_space_id"], "objective.output_space_id"); err != nil {
		return nil, err
	}
	if _, err := checkIntRange(obj["governance_level"], "objective.governance_level", 0, true, 5); err != nil {
		return nil, err
	}
	recDepth, err := checkIntRange(obj["recursion_depth"], "objective.recursion_depth", 0, false, 0)
	if err != nil {
		return nil, err
	}
	maxRecDepth, err := checkIntRange(obj["max_recursion_depth"], "objective.max_recursion_depth", 0, false, 0)
	if err != nil {
		return nil, err
	}
	if recDepth > maxRecDepth {
		return nil, newError("ERR_RECURSION_BUDGET_EXCEEDED", "recursion_depth (%d) exceeds max_recursion_depth (%d)", recDepth, maxRecDepth)
	}

	// 4. Execution validation & public-trace-only boundary.
	exe, err := checkExactKeys(rec["execution"], executionKeys, "execution")
	if err != nil {
		return nil, err
	}
	executorID, err := checkID(exe["executor_id"], "execution.executor_id")
	if err != nil {
		return nil, err
	}
	modelID, err := checkID(exe["model_id"], "execution.model_id")
	if err != nil {
		return nil, err
	}
	if _, err := checkID(exe["model_version"], "execution.model_version"); err != nil {
		return nil, err
	}
	modelSpecHash, err := checkHex64(exe["model_spec_hash"], "execution.model_spec_hash")
	if err != nil {
		return nil, err
	}
	profileID, err := checkID(exe["execution_profile_id"], "execution.execution_profile_id")
	if err != nil {
		return nil, err
	}
	inferenceTier, err := checkString(exe["inference_tier"], "execution.inference_tier")
	if err != nil || !allowedInferenceTiers[inferenceTier] {
		return nil, newError("ERR_SCHEMA_VIOLATION", "invalid inference_tier: %v", exe["inference_tier"])
	}
	evidenceMode, err := checkString(exe["evidence_mode"], "execution.evidence_mode")
	if err != nil || !allowedEvidenceModes[evidenceMode] {
		return nil, newError("ERR_SCHEMA_VIOLATION", "invalid evidence_mode: %v", exe["evidence_mode"])
	}
	publicTraceOnly, err := checkBool(exe["public_trace_only"], "execution.public_trace_only")
	if err != nil {
		return nil, err
	}
	if !publicTraceOnly {
		return nil, newError("ERR_PRIVATE_COT_FORBIDDEN", "execution.public_trace_only must be true")
	}
	if _, err := checkID(exe["hardware_class"], "execution.hardware_class"); err != nil {
		return nil, err
	}

	// 5. Inputs validation.
	inputs, ok := rec["inputs"].([]any)
	if !ok || len(inputs) == 0 {
		return nil, newError("ERR_SCHEMA_VIOLATION", "inputs must be a non-empty array")
	}
	for i, item := range inputs {
		ctx := "inputs[" + strconv.Itoa(i) + "]"
		inp, err := checkExactKeys(item, inputKeys, ctx)
		if err != nil {
			return nil, err
		}
		if _, err := checkID(inp["artifact_id"], ctx+".artifact_id"); err != nil {
			return nil, err
		}
		if _, err := checkID(inp["role"], ctx+".role"); err != nil {
			return nil, err
		}
		if _, err := checkNonEmptyStr(inp["uri"], ctx+".uri", 512); err != nil {
			return nil, err
		}
		if _, err := checkNonEmptyStr(inp["media_type"], ctx+".media_type", 128); err != nil {
			return nil, err
		}
		if _, err := checkIntRange(inp["byte_length"], ctx+".byte_length", 0, false, 0); err != nil {
			return nil, err
		}
		if _, err := checkHex64(inp["sha256"], ctx+".sha256"); err != nil {
			return nil, err
		}
	}

	// 6. Authorized tools validation.
	tools, ok := rec["authorized_tools"].([]any)
	if !ok {
		return nil, newError("ERR_SCHEMA_VIOLATION", "authorized_tools must be an array")
	}
	toolNames := make([]string, len(tools))
	for i, item := range tools {
		ctx := "authorized_tools[" + strconv.Itoa(i) + "]"
		tl, err := checkExactKeys(item, toolKeys, ctx)
		if err != nil {
			return nil, err
		}
		seq, err := checkIntRange(tl["seq"], ctx+".seq", 0, false, 0)
		if err != nil {
			return nil, err
		}
		if seq != int64(i) {
			return nil, newError("ERR_SCHEMA_VIOLATION", "%s.seq must equal %d, got %d", ctx, i, seq)
		}
		tName, err := checkID(tl["tool_name"], ctx+".tool_name")
		if err != nil {
			return nil, err
		}
		toolNames[i] = tName
		if _, err := checkID(tl["tool_version"], ctx+".tool_version"); err != nil {
			return nil, err
		}
		if _, err := checkBool(tl["deterministic"], ctx+".deterministic"); err != nil {
			return nil, err
		}
		if _, err := checkHex64(tl["args_sha256"], ctx+".args_sha256"); err != nil {
			return nil, err
		}
		if _, err := checkHex64(tl["output_sha256"], ctx+".output_sha256"); err != nil {
			return nil, err
		}
		if _, err := checkIntRange(tl["wall_time_ms"], ctx+".wall_time_ms", 0, false, 0); err != nil {
			return nil, err
		}
		if _, err := checkInt64(tl["exit_code"], ctx+".exit_code"); err != nil {
			return nil, err
		}
	}

	// 7. Public evidence validation & private-CoT URI/flag guard.
	evidence, ok := rec["public_evidence"].([]any)
	if !ok || len(evidence) == 0 {
		return nil, newError("ERR_SCHEMA_VIOLATION", "public_evidence must be a non-empty array")
	}
	for i, item := range evidence {
		ctx := "public_evidence[" + strconv.Itoa(i) + "]"
		ev, err := checkExactKeys(item, evidenceKeys, ctx)
		if err != nil {
			return nil, err
		}
		if _, err := checkID(ev["evidence_id"], ctx+".evidence_id"); err != nil {
			return nil, err
		}
		kind, err := checkString(ev["kind"], ctx+".kind")
		if err != nil || !allowedEvidenceKinds[kind] {
			return nil, newError("ERR_SCHEMA_VIOLATION", "invalid %s.kind: %v", ctx, ev["kind"])
		}
		uri, err := checkNonEmptyStr(ev["uri"], ctx+".uri", 512)
		if err != nil {
			return nil, err
		}
		uriLower := strings.ToLower(uri)
		for _, pfx := range forbiddenPrivateURIPrefixes {
			if strings.HasPrefix(uriLower, pfx) {
				return nil, newError("ERR_PRIVATE_COT_FORBIDDEN", "%s.uri references forbidden private CoT URI %q", ctx, uri)
			}
		}
		if strings.Contains(uriLower, "private_cot") || strings.Contains(uriLower, "internal_cot") {
			return nil, newError("ERR_PRIVATE_COT_FORBIDDEN", "%s.uri references private CoT path %q", ctx, uri)
		}
		if _, err := checkIntRange(ev["byte_length"], ctx+".byte_length", 0, false, 0); err != nil {
			return nil, err
		}
		if _, err := checkHex64(ev["sha256"], ctx+".sha256"); err != nil {
			return nil, err
		}
		pubOnly, err := checkBool(ev["public_only"], ctx+".public_only")
		if err != nil {
			return nil, err
		}
		if !pubOnly {
			return nil, newError("ERR_PRIVATE_COT_FORBIDDEN", "%s.public_only must be true", ctx)
		}
	}

	// 8. Checks validation.
	checks, ok := rec["checks"].([]any)
	if !ok || len(checks) == 0 {
		return nil, newError("ERR_SCHEMA_VIOLATION", "checks must be a non-empty array")
	}
	type parsedCheck struct {
		checkID      string
		passed       bool
		metricBPS    int64
		thresholdBPS int64
	}
	parsedChecks := make([]parsedCheck, len(checks))
	for i, item := range checks {
		ctx := "checks[" + strconv.Itoa(i) + "]"
		chk, err := checkExactKeys(item, checkKeys, ctx)
		if err != nil {
			return nil, err
		}
		cID, err := checkID(chk["check_id"], ctx+".check_id")
		if err != nil {
			return nil, err
		}
		cType, err := checkString(chk["check_type"], ctx+".check_type")
		if err != nil || !allowedCheckTypes[cType] {
			return nil, newError("ERR_SCHEMA_VIOLATION", "invalid %s.check_type: %v", ctx, chk["check_type"])
		}
		passed, err := checkBool(chk["passed"], ctx+".passed")
		if err != nil {
			return nil, err
		}
		if _, err := checkID(chk["metric_name"], ctx+".metric_name"); err != nil {
			return nil, err
		}
		mBPS, err := checkIntRange(chk["metric_bps"], ctx+".metric_bps", 0, true, 10000)
		if err != nil {
			return nil, err
		}
		tBPS, err := checkIntRange(chk["threshold_bps"], ctx+".threshold_bps", 0, true, 10000)
		if err != nil {
			return nil, err
		}
		if _, err := checkHex64(chk["verifier_cmd_sha256"], ctx+".verifier_cmd_sha256"); err != nil {
			return nil, err
		}
		if _, err := checkHex64(chk["log_sha256"], ctx+".log_sha256"); err != nil {
			return nil, err
		}
		parsedChecks[i] = parsedCheck{
			checkID:      cID,
			passed:       passed,
			metricBPS:    mBPS,
			thresholdBPS: tBPS,
		}
	}

	// 9. Result & Constitutional action-scope guard.
	res, err := checkExactKeys(rec["result"], resultKeys, "result")
	if err != nil {
		return nil, err
	}
	resStatus, err := checkString(res["status"], "result.status")
	if err != nil || !allowedResultStatuses[resStatus] {
		return nil, newError("ERR_SCHEMA_VIOLATION", "invalid result.status: %v", res["status"])
	}
	if _, err := checkHex64(res["canonical_output_sha256"], "result.canonical_output_sha256"); err != nil {
		return nil, err
	}
	outputByteLen, err := checkIntRange(res["output_byte_length"], "result.output_byte_length", 0, false, 0)
	if err != nil {
		return nil, err
	}
	if _, err := checkID(res["finite_verdict"], "result.finite_verdict"); err != nil {
		return nil, err
	}
	if _, err := checkIntRange(res["quality_score_bps"], "result.quality_score_bps", 0, true, 10000); err != nil {
		return nil, err
	}
	if _, err := checkIntRange(res["dissent_bps"], "result.dissent_bps", 0, true, 10000); err != nil {
		return nil, err
	}
	scope, err := checkString(res["proposed_action_scope"], "result.proposed_action_scope")
	if err != nil || !allowedProposedActionScopes[scope] {
		return nil, newError("ERR_CONSTITUTIONAL_AUTHORITY_ESCALATION", "disallowed result.proposed_action_scope: %v", res["proposed_action_scope"])
	}

	// 10. Settlement & Constitutional guards.
	sett, err := checkExactKeys(rec["settlement"], settlementKeys, "settlement")
	if err != nil {
		return nil, err
	}
	if _, err := checkID(sett["chain_id"], "settlement.chain_id"); err != nil {
		return nil, err
	}
	if _, err := checkNonEmptyStr(sett["escrow_ref"], "settlement.escrow_ref", 256); err != nil {
		return nil, err
	}
	if _, err := checkHex64(sett["intent_id"], "settlement.intent_id"); err != nil {
		return nil, err
	}
	if _, err := checkID(sett["payer"], "settlement.payer"); err != nil {
		return nil, err
	}
	if _, err := checkIntRange(sett["fee_units"], "settlement.fee_units", 0, false, 0); err != nil {
		return nil, err
	}
	subsidyEligible, err := checkBool(sett["subsidy_eligible"], "settlement.subsidy_eligible")
	if err != nil {
		return nil, err
	}
	if _, err := checkIntRange(sett["settled_at_height"], "settlement.settled_at_height", 0, false, 0); err != nil {
		return nil, err
	}
	if _, err := checkIntRange(sett["settled_at_unix"], "settlement.settled_at_unix", 1, false, 0); err != nil {
		return nil, err
	}
	treasuryAuth, err := checkBool(sett["treasury_spend_authorized"], "settlement.treasury_spend_authorized")
	if err != nil {
		return nil, err
	}
	if treasuryAuth {
		return nil, newError("ERR_CONSTITUTIONAL_TREASURY_SPEND", "AI execution receipts may not authorize treasury spending")
	}
	votingMod, err := checkBool(sett["voting_rules_modified"], "settlement.voting_rules_modified")
	if err != nil {
		return nil, err
	}
	if votingMod {
		return nil, newError("ERR_CONSTITUTIONAL_VOTING_RULES", "AI execution receipts may not modify voting rules")
	}
	if subsidyEligible && evidenceMode == "quorum_signatures" {
		return nil, newError("ERR_SUBSIDY_REQUIRES_PROVABLE_WORK", "subsidy_eligible=true forbidden for bare quorum_signatures")
	}

	// 11. Authorized Execution Profile & Tool Allowlist Guard.
	prof, exists := policy.AuthorizedProfiles[profileID]
	if !exists {
		return nil, newError("ERR_UNAUTHORIZED_PROFILE", "execution_profile_id %q is not in authorized_profiles", profileID)
	}
	if !slices.Contains(prof.AllowedModels, modelID) {
		return nil, newError("ERR_UNAUTHORIZED_MODEL_OR_TIER", "model_id %q not allowed by profile %q", modelID, profileID)
	}
	if !slices.Contains(prof.AllowedModelSpecHashes, modelSpecHash) {
		return nil, newError("ERR_UNAUTHORIZED_MODEL_OR_TIER", "model_spec_hash %q not allowed by profile %q", modelSpecHash, profileID)
	}
	if !slices.Contains(prof.AllowedTiers, inferenceTier) {
		return nil, newError("ERR_UNAUTHORIZED_MODEL_OR_TIER", "inference_tier %q not allowed by profile %q", inferenceTier, profileID)
	}
	if !slices.Contains(prof.AllowedEvidenceModes, evidenceMode) {
		return nil, newError("ERR_UNAUTHORIZED_MODEL_OR_TIER", "evidence_mode %q not allowed by profile %q", evidenceMode, profileID)
	}
	if maxRecDepth > prof.MaxRecursionDepth {
		return nil, newError("ERR_RECURSION_BUDGET_EXCEEDED", "objective.max_recursion_depth (%d) exceeds profile limit (%d)", maxRecDepth, prof.MaxRecursionDepth)
	}
	if outputByteLen > prof.MaxOutputBytes {
		return nil, newError("ERR_OUTPUT_TOO_LARGE", "result.output_byte_length (%d) exceeds profile limit (%d)", outputByteLen, prof.MaxOutputBytes)
	}
	for i, tName := range toolNames {
		if !slices.Contains(prof.AllowedTools, tName) {
			return nil, newError("ERR_UNAUTHORIZED_TOOL", "authorized_tools[%d].tool_name %q not allowed by profile %q", i, tName, profileID)
		}
	}

	// 12. Check consistency guard for completed jobs.
	if resStatus == "completed" {
		for i, chk := range parsedChecks {
			if !chk.passed || chk.metricBPS < chk.thresholdBPS {
				return nil, newError("ERR_FAILED_CHECK_IN_COMPLETED_JOB", "completed receipt has failing check checks[%d] (%s)", i, chk.checkID)
			}
		}
	}

	// 13. Provenance schema & Merkle root reconstruction.
	prov, err := checkExactKeys(rec["provenance"], provenanceKeys, "provenance")
	if err != nil {
		return nil, err
	}
	if prov["hash_algorithm"] != "sha256" || prov["domain_separator"] != SchemaVersion {
		return nil, newError("ERR_PROVENANCE_MISMATCH", "provenance hash_algorithm or domain_separator mismatch")
	}
	committedInputsRoot, err := checkHex64(prov["inputs_root"], "provenance.inputs_root")
	if err != nil {
		return nil, err
	}
	committedToolsRoot, err := checkHex64(prov["tools_root"], "provenance.tools_root")
	if err != nil {
		return nil, err
	}
	committedEvidenceRoot, err := checkHex64(prov["evidence_root"], "provenance.evidence_root")
	if err != nil {
		return nil, err
	}
	committedChecksRoot, err := checkHex64(prov["checks_root"], "provenance.checks_root")
	if err != nil {
		return nil, err
	}
	committedResultDigest, err := checkHex64(prov["result_digest"], "provenance.result_digest")
	if err != nil {
		return nil, err
	}
	committedProvRoot, err := checkHex64(prov["provenance_root"], "provenance.provenance_root")
	if err != nil {
		return nil, err
	}

	recomputed, err := ComputeProvenance(rec)
	if err != nil {
		return nil, err
	}
	if committedInputsRoot != recomputed.InputsRoot ||
		committedToolsRoot != recomputed.ToolsRoot ||
		committedEvidenceRoot != recomputed.EvidenceRoot ||
		committedChecksRoot != recomputed.ChecksRoot ||
		committedResultDigest != recomputed.ResultDigest ||
		committedProvRoot != recomputed.ProvenanceRoot {
		return nil, newError("ERR_PROVENANCE_MISMATCH", "recomputed provenance roots do not match committed provenance")
	}

	// 14. Canonical receipt hash computation.
	receiptHash, err := CanonicalReceiptHash(rec)
	if err != nil {
		return nil, err
	}

	// 15. Independent Verifier Attestations (Ed25519 + no self-attestation).
	atts, ok := rec["attestations"].([]any)
	if !ok || len(atts) == 0 {
		return nil, newError("ERR_INSUFFICIENT_ATTESTATIONS", "attestations must be non-empty")
	}
	seenVerifiers := make(map[string]bool, len(atts))
	validCount := 0
	for i, item := range atts {
		ctx := "attestations[" + strconv.Itoa(i) + "]"
		att, err := checkExactKeys(item, attestationKeys, ctx)
		if err != nil {
			return nil, err
		}
		vID, err := checkID(att["verifier_id"], ctx+".verifier_id")
		if err != nil {
			return nil, err
		}
		if vID == executorID {
			return nil, newError("ERR_SELF_ATTESTATION_FORBIDDEN", "executor %q cannot self-attest its own receipt", executorID)
		}
		if seenVerifiers[vID] {
			return nil, newError("ERR_DUPLICATE_VERIFIER", "duplicate verifier_id %q in attestations", vID)
		}
		seenVerifiers[vID] = true

		vEntry, trusted := policy.TrustedVerifiers[vID]
		if !trusted {
			return nil, newError("ERR_UNTRUSTED_VERIFIER", "verifier_id %q not in trusted_verifiers", vID)
		}
		vRole, err := checkString(att["verifier_role"], ctx+".verifier_role")
		if err != nil || !allowedVerifierRoles[vRole] || !slices.Contains(vEntry.AllowedRoles, vRole) {
			return nil, newError("ERR_UNTRUSTED_VERIFIER", "verifier_role %q not permitted for %q", vRole, vID)
		}
		alg, err := checkString(att["algorithm"], ctx+".algorithm")
		if err != nil || alg != "ed25519" {
			return nil, newError("ERR_SCHEMA_VIOLATION", "%s.algorithm must be ed25519", ctx)
		}
		pubHex, err := checkHex64(att["public_key_hex"], ctx+".public_key_hex")
		if err != nil {
			return nil, err
		}
		if pubHex != vEntry.PublicKeyHex {
			return nil, newError("ERR_UNTRUSTED_VERIFIER", "public_key_hex for %q does not match trusted registry", vID)
		}
		verdict, err := checkString(att["verdict"], ctx+".verdict")
		if err != nil || !allowedVerdicts[verdict] {
			return nil, newError("ERR_SCHEMA_VIOLATION", "invalid %s.verdict: %v", ctx, att["verdict"])
		}
		attHash, err := checkHex64(att["attested_receipt_hash"], ctx+".attested_receipt_hash")
		if err != nil {
			return nil, err
		}
		if attHash != receiptHash {
			return nil, newError("ERR_ATTESTATION_HASH_MISMATCH", "%s.attested_receipt_hash does not match canonical_receipt_hash", ctx)
		}
		attTS, err := checkIntRange(att["attested_at_unix"], ctx+".attested_at_unix", 1, false, 0)
		if err != nil {
			return nil, err
		}
		sigHex, err := checkHex128(att["signature_hex"], ctx+".signature_hex")
		if err != nil {
			return nil, err
		}

		pubBytes, err := hex.DecodeString(pubHex)
		if err != nil {
			return nil, newError("ERR_SCHEMA_VIOLATION", "invalid public key hex")
		}
		sigBytes, err := hex.DecodeString(sigHex)
		if err != nil {
			return nil, newError("ERR_SCHEMA_VIOLATION", "invalid signature hex")
		}
		msg := AttestationMessage(receiptHash, vID, vRole, verdict, attTS)
		if !ed25519.Verify(ed25519.PublicKey(pubBytes), msg, sigBytes) {
			return nil, newError("ERR_INVALID_SIGNATURE", "invalid Ed25519 signature for verifier %q", vID)
		}
		if verdict == "VALID" {
			validCount++
		}
	}

	if int64(validCount) < prof.MinVerifiers {
		return nil, newError("ERR_INSUFFICIENT_ATTESTATIONS", "receipt has %d valid attestations, profile requires >= %d", validCount, prof.MinVerifiers)
	}

	return &VerificationResult{
		JobID:                 jobID,
		CanonicalReceiptHash:  receiptHash,
		ProvenanceRoot:        recomputed.ProvenanceRoot,
		ValidAttestationCount: validCount,
	}, nil
}

// VerifyBatch verifies a slice of parsed receipts with global replay protection
// across job_id, nonce, and settlement.intent_id.
func VerifyBatch(receipts []any, policy *PolicyBundle) ([]VerificationResult, error) {
	seenJobs := make(map[string]bool, len(receipts))
	seenNonces := make(map[string]bool, len(receipts))
	seenIntents := make(map[string]bool, len(receipts))
	results := make([]VerificationResult, 0, len(receipts))

	for _, item := range receipts {
		res, err := VerifyReceipt(item, policy)
		if err != nil {
			return nil, err
		}
		rec := item.(map[string]any)
		nonce := rec["nonce"].(string)
		intentID := rec["settlement"].(map[string]any)["intent_id"].(string)

		if seenJobs[res.JobID] {
			return nil, newError("ERR_REPLAY_DETECTED", "duplicate job_id %q", res.JobID)
		}
		if seenNonces[nonce] {
			return nil, newError("ERR_REPLAY_DETECTED", "duplicate nonce %q", nonce)
		}
		if seenIntents[intentID] {
			return nil, newError("ERR_REPLAY_DETECTED", "duplicate intent_id %q", intentID)
		}
		seenJobs[res.JobID] = true
		seenNonces[nonce] = true
		seenIntents[intentID] = true
		results = append(results, *res)
	}
	return results, nil
}

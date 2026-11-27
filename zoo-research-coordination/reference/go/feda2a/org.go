// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package feda2a

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// MemoryRecord is an org-internal memory entry tagged with its isolation tier.
type MemoryRecord struct {
	ID      string
	Tier    string // public_artifact, shared_exchange, private_memory, restricted_pii, raw_reasoning_trace
	Content string
}

// CredentialStore isolates an organization's internal credentials in memory.
// Plaintext values are NEVER exported on AgentCards or A2A wire messages.
type CredentialStore struct {
	OrgID   string
	Secrets map[string]string // handle -> synthetic internal credential value
}

func (cs *CredentialStore) VaultRoot() string {
	keys := make([]string, 0, len(cs.Secrets))
	for k := range cs.Secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	leaves := make([]string, 0, len(keys))
	for _, k := range keys {
		leaves = append(leaves, SHA256Hex([]byte(cs.OrgID+":"+k+":"+cs.Secrets[k])))
	}
	return MerkleRootRFC6962(leaves)
}

// MemoryVault isolates an organization's tiered memory records.
type MemoryVault struct {
	OrgID   string
	Records map[string]MemoryRecord
}

func (mv *MemoryVault) TierRoot(tiers ...string) (string, int64) {
	allowed := map[string]bool{}
	for _, t := range tiers {
		allowed[t] = true
	}
	ids := make([]string, 0, len(mv.Records))
	for id, r := range mv.Records {
		if allowed[r.Tier] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	leaves := make([]string, 0, len(ids))
	for _, id := range ids {
		r := mv.Records[id]
		leaves = append(leaves, SHA256Hex([]byte(mv.OrgID+":"+r.ID+":"+r.Tier+":"+r.Content)))
	}
	return MerkleRootRFC6962(leaves), int64(len(ids))
}

// ScanBoundaryProbes inspects raw wire bytes against a set of boundary probes
// (credentials, private memory canaries, private memory IDs, and raw reasoning traces)
// across raw UTF-8, case-folded, base64, and lowercase hex encodings.
func ScanBoundaryProbes(payload []byte, probes []BoundaryProbeSpec) (credLeakBytes, memLeakBytes, traceLeakBytes int64, firstCode, firstClass string) {
	rawStr := string(payload)
	lowerStr := strings.ToLower(rawStr)

	checkToken := func(tok string) (leaked int64, encoded bool) {
		if tok == "" {
			return 0, false
		}
		if strings.Contains(rawStr, tok) || strings.Contains(lowerStr, strings.ToLower(tok)) {
			return int64(len(tok)), false
		}
		b64 := base64.StdEncoding.EncodeToString([]byte(tok))
		if strings.Contains(rawStr, b64) {
			return int64(len(b64)), true
		}
		hx := hex.EncodeToString([]byte(tok))
		if strings.Contains(lowerStr, hx) {
			return int64(len(hx)), true
		}
		return 0, false
	}

	for _, p := range probes {
		for _, tok := range p.CredentialProbes {
			if n, enc := checkToken(tok); n > 0 {
				credLeakBytes += n
				if firstCode == "" {
					if enc {
						firstCode = CodeEncodedSecretLeak
						firstClass = "encoded_secret"
					} else {
						firstCode = CodeCredentialLeakDetected
						firstClass = "credential"
					}
				}
			}
		}
		for _, tok := range p.PrivateMemoryProbes {
			if n, enc := checkToken(tok); n > 0 {
				memLeakBytes += n
				if firstCode == "" {
					if enc {
						firstCode = CodeEncodedSecretLeak
						firstClass = "encoded_secret"
					} else {
						firstCode = CodePrivateMemoryLeak
						firstClass = "private_memory"
					}
				}
			}
		}
		for _, refID := range p.PrivateMemoryRefIDs {
			if n, _ := checkToken(refID); n > 0 {
				memLeakBytes += n
				if firstCode == "" {
					firstCode = CodePrivateMemoryRefForbidden
					firstClass = "private_memory"
				}
			}
		}
		for _, tok := range p.RawTraceProbes {
			if n, enc := checkToken(tok); n > 0 {
				traceLeakBytes += n
				if firstCode == "" {
					if enc {
						firstCode = CodeEncodedSecretLeak
						firstClass = "encoded_secret"
					} else {
						firstCode = CodeRawTraceLeak
						firstClass = "raw_reasoning_trace"
					}
				}
			}
		}
	}
	return credLeakBytes, memLeakBytes, traceLeakBytes, firstCode, firstClass
}

// OrgDeployment represents one independently administered organization running
// its own live HTTP A2A server, isolated credentials, isolated memory vault,
// Ed25519 keys, nonce replay cache, and fail-closed Egress Boundary Firewall.
type OrgDeployment struct {
	OrgID       string
	Name        string
	Description string
	LogicalURL  string
	Seed        int64

	GatewayKey  KeyPair
	ReviewerKey KeyPair
	CouncilKey  KeyPair
	AIAgentKey  KeyPair
	HMACSecret  []byte

	Policy      OrgGovernancePolicy
	Credentials CredentialStore
	Memory      MemoryVault
	AgentCard   AgentCard

	mu            sync.Mutex
	clockSec      int64
	peerCards     map[string]AgentCard
	seenNonces    map[string]int64
	tasks         map[string]TaskResultReceipt
	taskRequester map[string]string
	egressBlocks  []EgressBlockEvent
	wireFrames    []WireFrame
	frameCounter  int64

	listener net.Listener
	server   *http.Server
	baseURL  string
	client   *http.Client
}

// NewOrgDeployment initializes an isolated OrgDeployment with its own keys,
// synthetic internal credentials, private memory vault, and signed AgentCard.
func NewOrgDeployment(seed int64, orgID, name, description, logicalURL string, creds map[string]string, records []MemoryRecord) *OrgDeployment {
	gw := DeriveKeyPair(seed, orgID, orgID+"-gateway", RoleOrgGateway)
	rev := DeriveKeyPair(seed, orgID, orgID+"-reviewer", RoleHumanReviewer)
	council := DeriveKeyPair(seed, orgID, orgID+"-council", RoleCouncilMember)
	ai := DeriveKeyPair(seed, orgID, orgID+"-ai-agent", RoleAIAgent)

	policy := OrgGovernancePolicy{
		OrgID:         orgID,
		PolicyVersion: "1.0.0",
		AllowedSkills: []string{
			SkillZHLCompare,
			SkillZHLCorrelate,
			SkillReproAudit,
		},
		AllowedLicenses: []string{
			"Apache-2.0",
			"MIT",
			"CC-BY-4.0",
			"CC0-1.0",
		},
		AllowedExchangeTiers: []string{
			TierPublicArtifact,
			TierSharedExchange,
		},
		DeniedScopes: []string{
			ScopeTreasurySpend,
			ScopeGovernanceRuleChg,
			ScopeCredentialRead,
			ScopePrivateMemoryDump,
		},
		AIAgentCanRedefineVoting: false,
		AIAgentCanAuthorizeSpend: false,
		AIAgentCanSelfCertify:    false,
		Principals: []Principal{
			gw.Principal,
			rev.Principal,
			council.Principal,
			ai.Principal,
		},
	}
	policy.PolicyHash = ComputeOrgPolicyHash(policy)

	credStore := CredentialStore{
		OrgID:   orgID,
		Secrets: make(map[string]string, len(creds)),
	}
	for k, v := range creds {
		credStore.Secrets[k] = v
	}

	memVault := MemoryVault{
		OrgID:   orgID,
		Records: make(map[string]MemoryRecord, len(records)),
	}
	for _, r := range records {
		memVault.Records[r.ID] = r
	}

	privRoot, privCount := memVault.TierRoot(TierPrivateMemory, TierRestrictedPII)
	traceRoot, traceCount := memVault.TierRoot(TierRawReasoningTrace)

	card := AgentCard{
		SchemaVersion:    SchemaVersion,
		ProtocolVersion:  A2AProtocolVer,
		OrgID:            orgID,
		Name:             name,
		Description:      description,
		LogicalURL:       logicalURL,
		GatewayPrincipal: gw.Principal,
		Capabilities: A2ACapabilities{
			Streaming:              true,
			PushNotifications:      false,
			StateTransitionHistory: true,
		},
		Skills: []A2ASkill{
			{
				ID:              SkillZHLCompare,
				Name:            "ZooCoord ZHL COMPARE",
				Description:     "Deterministic fixed-point two-group scientific hypothesis comparison.",
				AllowedTiers:    []string{TierPublicArtifact, TierSharedExchange},
				Deterministic:   true,
				MaxPayloadBytes: 262144,
			},
			{
				ID:              SkillZHLCorrelate,
				Name:            "ZooCoord ZHL CORRELATE",
				Description:     "Deterministic fixed-point paired Pearson correlation analysis.",
				AllowedTiers:    []string{TierPublicArtifact, TierSharedExchange},
				Deterministic:   true,
				MaxPayloadBytes: 262144,
			},
			{
				ID:              SkillReproAudit,
				Name:            "ZooCoord Reproducibility Audit",
				Description:     "Independent deterministic verification of committed ZHL results.",
				AllowedTiers:    []string{TierPublicArtifact, TierSharedExchange},
				Deterministic:   true,
				MaxPayloadBytes: 262144,
			},
		},
		PolicyDigest: policy.PolicyHash,
		BoundaryCommitment: BoundaryCommitment{
			OrgID:                  orgID,
			CredentialCount:        int64(len(credStore.Secrets)),
			CredentialVaultRoot:    credStore.VaultRoot(),
			PrivateMemoryCount:     privCount,
			PrivateMemoryVaultRoot: privRoot,
			RawTraceCount:          traceCount,
			RawTraceVaultRoot:      traceRoot,
			EgressFirewallEnforced: true,
		},
	}
	card.CardHash = ComputeAgentCardHash(card)
	card.OrgSignatureHex = SignCanonical(gw.Private, DomainAgentCard, AgentCardSigningPayload(card))

	return &OrgDeployment{
		OrgID:         orgID,
		Name:          name,
		Description:   description,
		LogicalURL:    logicalURL,
		Seed:          seed,
		GatewayKey:    gw,
		ReviewerKey:   rev,
		CouncilKey:    council,
		AIAgentKey:    ai,
		HMACSecret:    DeriveInternalHMACSecret(seed, orgID),
		Policy:        policy,
		Credentials:   credStore,
		Memory:        memVault,
		AgentCard:     card,
		clockSec:      BaseEpochSec,
		peerCards:     make(map[string]AgentCard),
		seenNonces:    make(map[string]int64),
		tasks:         make(map[string]TaskResultReceipt),
		taskRequester: make(map[string]string),
		client:        &http.Client{Timeout: 10 * time.Second},
	}
}

// BoundaryProbes exports this deployment's synthetic probes ONLY for test/benchmark
// auditing so an external verifier can confirm 0 leaked bytes across captured wire frames.
func (o *OrgDeployment) BoundaryProbes() BoundaryProbeSpec {
	credKeys := make([]string, 0, len(o.Credentials.Secrets))
	for k := range o.Credentials.Secrets {
		credKeys = append(credKeys, k)
	}
	sort.Strings(credKeys)
	credProbes := make([]string, 0, len(credKeys))
	for _, k := range credKeys {
		credProbes = append(credProbes, o.Credentials.Secrets[k])
	}

	recIDs := make([]string, 0, len(o.Memory.Records))
	for id := range o.Memory.Records {
		recIDs = append(recIDs, id)
	}
	sort.Strings(recIDs)

	var privProbes, privRefIDs, traceProbes []string
	for _, id := range recIDs {
		r := o.Memory.Records[id]
		switch r.Tier {
		case TierPrivateMemory, TierRestrictedPII:
			privProbes = append(privProbes, r.Content)
			privRefIDs = append(privRefIDs, r.ID)
		case TierRawReasoningTrace:
			traceProbes = append(traceProbes, r.Content)
			privRefIDs = append(privRefIDs, r.ID)
		}
	}
	return BoundaryProbeSpec{
		OrgID:               o.OrgID,
		CredentialProbes:    nonNilStrings(credProbes),
		PrivateMemoryProbes: nonNilStrings(privProbes),
		PrivateMemoryRefIDs: nonNilStrings(privRefIDs),
		RawTraceProbes:      nonNilStrings(traceProbes),
	}
}

// SetClock sets the deployment's deterministic logical clock (thread-safe).
func (o *OrgDeployment) SetClock(ts int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.clockSec = ts
}

// Now returns the deployment's current logical timestamp (thread-safe).
func (o *OrgDeployment) Now() int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.clockSec
}

// Start launches an independent live HTTP/1.1 server bound to loopback 127.0.0.1:0.
func (o *OrgDeployment) Start() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/agent.json", o.handleAgentCard)
	mux.HandleFunc("/a2a/rpc", o.handleJSONRPC)
	mux.HandleFunc("/a2a/passthrough", o.handlePassthroughBench)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	o.listener = ln
	o.server = srv
	o.baseURL = "http://" + ln.Addr().String()
	go func() {
		_ = srv.Serve(ln)
	}()
	return nil
}

// BaseURL returns the live loopback URL for this deployment's HTTP server.
func (o *OrgDeployment) BaseURL() string {
	return o.baseURL
}

// Stop gracefully shuts down this deployment's HTTP server.
func (o *OrgDeployment) Stop() {
	if o.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = o.server.Shutdown(ctx)
	}
	if o.client != nil {
		o.client.CloseIdleConnections()
	}
}

// WireFrames returns a snapshot of all HTTP wire frames recorded by this deployment's client.
func (o *OrgDeployment) WireFrames() []WireFrame {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]WireFrame, len(o.wireFrames))
	copy(out, o.wireFrames)
	return out
}

// EgressBlocks returns all recorded fail-closed Egress Boundary Firewall events.
func (o *OrgDeployment) EgressBlocks() []EgressBlockEvent {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]EgressBlockEvent, len(o.egressBlocks))
	copy(out, o.egressBlocks)
	return out
}

// inspectEgress runs the fail-closed Egress Boundary Firewall over raw outgoing bytes.
// If any credential, private memory canary, or raw trace is detected, it records a signed
// EgressBlockEvent and returns the sanitized block event (never leaking plaintext).
func (o *OrgDeployment) inspectEgress(taskID string, draftBytes []byte) *EgressBlockEvent {
	probes := []BoundaryProbeSpec{o.BoundaryProbes()}
	credN, memN, traceN, code, cls := ScanBoundaryProbes(draftBytes, probes)
	if credN == 0 && memN == 0 && traceN == 0 {
		return nil
	}
	reasonCode := CodeEgressMemoryBlocked
	if credN > 0 || code == CodeEncodedSecretLeak {
		reasonCode = CodeEgressCredentialBlocked
	}
	o.mu.Lock()
	ts := o.clockSec
	eventID := fmt.Sprintf("egress-block-%s-%d", o.OrgID, len(o.egressBlocks)+1)
	ev := EgressBlockEvent{
		EventID:       eventID,
		OrgID:         o.OrgID,
		TaskID:        taskID,
		Timestamp:     ts,
		ReasonCode:    reasonCode,
		BlockedClass:  cls,
		BlockedDigest: SHA256Hex(draftBytes),
		BytesBlocked:  int64(len(draftBytes)),
		WireBytesSent: 0,
	}
	ev.EventSigHex = SignCanonical(o.GatewayKey.Private, DomainEgressBlock, EgressBlockSigningPayload(ev))
	o.egressBlocks = append(o.egressBlocks, ev)
	o.mu.Unlock()
	return &ev
}

func (o *OrgDeployment) writeGuardedJSON(w http.ResponseWriter, status int, taskID string, resp any) {
	raw, err := CanonicalJSON(resp)
	if err != nil {
		http.Error(w, `{"error":"marshal_failed"}`, http.StatusInternalServerError)
		return
	}
	if block := o.inspectEgress(taskID, raw); block != nil {
		// Fail-closed: NEVER transmit the blocked bytes. Return a sanitized rejection receipt.
		receipt := o.signRejectedReceipt(taskID, "", block.ReasonCode, block)
		sanitized := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      taskID,
			Result:  receipt,
		}
		safeRaw, _ := CanonicalJSON(sanitized)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write(safeRaw)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func (o *OrgDeployment) handleAgentCard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	o.writeGuardedJSON(w, http.StatusOK, "agent-card", o.AgentCard)
}

// handlePassthroughBench is an unverified raw HTTP JSON-RPC echo/compute endpoint
// used ONLY in the honest negative regime benchmark to quantify the exact latency
// and throughput cost of full federated security boundaries vs unverified passthrough.
func (o *OrgDeployment) handlePassthroughBench(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	var req struct {
		JSONRPC string `json:"jsonrpc"`
		ID      string `json:"id"`
		Method  string `json:"method"`
		Params  struct {
			TaskID     string               `json:"task_id"`
			Commitment ExperimentCommitment `json:"commitment"`
		} `json:"params"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	res, err := RunDeterministicZHL(req.Params.TaskID, req.Params.Commitment)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out, _ := json.Marshal(JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  res,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

func (o *OrgDeployment) handleJSONRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read failed", http.StatusBadRequest)
		return
	}
	var rpcReq struct {
		JSONRPC string            `json:"jsonrpc"`
		ID      string            `json:"id"`
		Method  string            `json:"method"`
		Params  SignedA2AEnvelope `json:"params"`
	}
	if err := json.Unmarshal(rawBody, &rpcReq); err != nil || rpcReq.JSONRPC != "2.0" {
		o.writeGuardedJSON(w, http.StatusBadRequest, "invalid-rpc", JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      rpcReq.ID,
			Error:   &JSONRPCError{Code: -32600, Message: "invalid JSON-RPC 2.0 request"},
		})
		return
	}
	env := rpcReq.Params

	switch rpcReq.Method {
	case "tasks/send":
		receipt, httpStatus := o.processTaskSend(env)
		o.writeGuardedJSON(w, httpStatus, env.Payload.TaskID, JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      rpcReq.ID,
			Result:  receipt,
		})
	case "tasks/sendSubscribe":
		o.processTaskSendSSE(w, rpcReq.ID, env)
	case "tasks/get":
		receipt, httpStatus := o.processTaskGet(env)
		o.writeGuardedJSON(w, httpStatus, env.Payload.TaskID, JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      rpcReq.ID,
			Result:  receipt,
		})
	case "tasks/cancel":
		receipt, httpStatus := o.processTaskCancel(env)
		o.writeGuardedJSON(w, httpStatus, env.Payload.TaskID, JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      rpcReq.ID,
			Result:  receipt,
		})
	default:
		o.writeGuardedJSON(w, http.StatusBadRequest, env.Payload.TaskID, JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      rpcReq.ID,
			Error:   &JSONRPCError{Code: -32601, Message: "unsupported A2A method"},
		})
	}
}

func (o *OrgDeployment) validateEnvelopeIngress(env SignedA2AEnvelope, consumeNonce bool) string {
	o.mu.Lock()
	peerCard, hasPeer := o.peerCards[env.SenderOrgID]
	now := o.clockSec
	_, nonceSeen := o.seenNonces[env.SenderOrgID+":"+env.TaskNonce]
	o.mu.Unlock()

	if !hasPeer {
		return CodeSpoofedOrgIdentity
	}
	if env.AudienceOrgID != o.OrgID {
		return CodeAudienceMismatch
	}
	if env.IssuedAt > now || now > env.ExpiresAt {
		return CodeEnvelopeExpired
	}
	if consumeNonce && nonceSeen {
		return CodeNonceReplay
	}
	if env.SignerID != peerCard.GatewayPrincipal.ID {
		return CodeSpoofedOrgIdentity
	}
	if env.EnvelopeHash != ComputeEnvelopeHash(env) {
		return CodeEnvelopeSigInvalid
	}
	if !VerifyCanonical(peerCard.GatewayPrincipal.PublicKeyHex, env.OrgSigHex, DomainEnvelope, EnvelopeSigningPayload(env)) {
		return CodeEnvelopeSigInvalid
	}

	// Scope & constitutional enforcement
	if env.Method == "tasks/send" || env.Method == "tasks/sendSubscribe" {
		for _, denied := range o.Policy.DeniedScopes {
			if env.Scope == denied || env.Payload.SkillID == denied {
				if env.Payload.ActorRole == RoleAIAgent {
					if denied == ScopeTreasurySpend {
						return CodeAITreasuryForbidden
					}
					if denied == ScopeGovernanceRuleChg {
						return CodeAIVotingRuleForbidden
					}
				}
				return CodeScopeEscalation
			}
		}
		if !containsString(o.Policy.AllowedSkills, env.Scope) || !containsString(o.Policy.AllowedSkills, env.Payload.SkillID) {
			return CodeScopeEscalation
		}
		if env.Payload.ActorRole == RoleAIAgent && env.Payload.SelfCertified {
			return CodeAISelfCertifyForbidden
		}
		if !containsString(o.Policy.AllowedExchangeTiers, env.Payload.Commitment.InputTier) {
			return CodePrivateMemoryRefForbidden
		}
		// Reject any private memory references smuggled in input_record_refs.
		for _, ref := range env.Payload.Commitment.InputRecordRefs {
			lowerRef := strings.ToLower(ref)
			if strings.Contains(lowerRef, "priv") || strings.Contains(lowerRef, "pii") || strings.Contains(lowerRef, "trace") {
				return CodePrivateMemoryRefForbidden
			}
			if rec, ok := o.Memory.Records[ref]; ok && !containsString(o.Policy.AllowedExchangeTiers, rec.Tier) {
				return CodePrivateMemoryRefForbidden
			}
		}
		// License review gate on every attached dataset/artifact.
		if len(env.Payload.Licenses) == 0 {
			return CodeLicenseUnreviewed
		}
		for _, lic := range env.Payload.Licenses {
			if !lic.LicenseReviewed || !containsString(o.Policy.AllowedLicenses, lic.LicenseID) {
				return CodeLicenseUnreviewed
			}
		}
	}

	if consumeNonce {
		o.mu.Lock()
		o.seenNonces[env.SenderOrgID+":"+env.TaskNonce] = now
		o.mu.Unlock()
	}
	return CodeOK
}

func (o *OrgDeployment) signRejectedReceipt(taskID, requesterOrgID, code string, block *EgressBlockEvent) TaskResultReceipt {
	ts := o.Now()
	rec := TaskResultReceipt{
		ReceiptID:         fmt.Sprintf("rcpt-%s-%s", o.OrgID, taskID),
		TaskID:            taskID,
		ExecutorOrgID:     o.OrgID,
		RequesterOrgID:    requesterOrgID,
		SignerID:          o.GatewayKey.Principal.ID,
		State:             TaskStateRejected,
		ErrorCode:         code,
		CompletedAt:       ts,
		Transitions:       []StateTransition{{State: TaskStateRejected, Timestamp: ts, Note: code}},
		EgressBlock:       block,
		EgressAuditPassed: true,
	}
	rec.ReceiptHash = ComputeReceiptHash(rec)
	rec.ExecutorSigHex = SignCanonical(o.GatewayKey.Private, DomainTaskReceipt, ReceiptSigningPayload(rec))
	return rec
}

func (o *OrgDeployment) processTaskSend(env SignedA2AEnvelope) (TaskResultReceipt, int) {
	if code := o.validateEnvelopeIngress(env, true); code != CodeOK {
		return o.signRejectedReceipt(env.Payload.TaskID, env.SenderOrgID, code, nil), http.StatusForbidden
	}

	ts := o.Now()
	// Mint an internal-only ephemeral HMAC capability token for local sandbox execution
	// (never exported over the wire).
	capToken := MintInternalCapabilityToken(o.HMACSecret, o.OrgID, env.Payload.TaskID, env.Scope, env.ExpiresAt)
	if !VerifyInternalCapabilityToken(o.HMACSecret, o.OrgID, env.Payload.TaskID, env.Scope, env.ExpiresAt, capToken) {
		return o.signRejectedReceipt(env.Payload.TaskID, env.SenderOrgID, CodeScopeEscalation, nil), http.StatusForbidden
	}

	// Deferred task lifecycle (used to exercise live tasks/cancel).
	if env.Payload.DeferCompletion {
		rec := TaskResultReceipt{
			ReceiptID:      fmt.Sprintf("rcpt-%s-%s", o.OrgID, env.Payload.TaskID),
			TaskID:         env.Payload.TaskID,
			ExecutorOrgID:  o.OrgID,
			RequesterOrgID: env.SenderOrgID,
			SignerID:       o.GatewayKey.Principal.ID,
			State:          TaskStateSubmitted,
			ErrorCode:      CodeOK,
			CompletedAt:    ts,
			Transitions: []StateTransition{
				{State: TaskStateSubmitted, Timestamp: ts, Note: "queued for federated execution"},
			},
			EgressAuditPassed: true,
		}
		rec.ReceiptHash = ComputeReceiptHash(rec)
		rec.ExecutorSigHex = SignCanonical(o.GatewayKey.Private, DomainTaskReceipt, ReceiptSigningPayload(rec))
		o.mu.Lock()
		o.tasks[env.Payload.TaskID] = rec
		o.taskRequester[env.Payload.TaskID] = env.SenderOrgID
		o.mu.Unlock()
		return rec, http.StatusOK
	}

	// Run deterministic scientific computation on committed public/shared inputs.
	sciRes, err := RunDeterministicZHL(env.Payload.TaskID, env.Payload.Commitment)
	if err != nil {
		return o.signRejectedReceipt(env.Payload.TaskID, env.SenderOrgID, CodeTaskStateInvalid, nil), http.StatusBadRequest
	}

	// Simulate an adversarial prompt-injection inside an untrusted worker attempting to
	// smuggle internal credentials or private memory into the outgoing artifact:
	// the live Egress Boundary Firewall intercepts the draft payload BEFORE any byte hits the wire!
	lowerNote := strings.ToLower(env.Payload.PromptNote)
	if strings.Contains(lowerNote, "exfiltrate") || strings.Contains(lowerNote, "dump_credentials") || strings.Contains(lowerNote, "ignore previous instructions") {
		leakedDraft := sciRes
		credKeys := make([]string, 0, len(o.Credentials.Secrets))
		for k := range o.Credentials.Secrets {
			credKeys = append(credKeys, k)
		}
		sort.Strings(credKeys)
		var firstCred, firstMem string
		if len(credKeys) > 0 {
			firstCred = o.Credentials.Secrets[credKeys[0]]
		}
		memIDs := make([]string, 0, len(o.Memory.Records))
		for id, r := range o.Memory.Records {
			if r.Tier == TierPrivateMemory || r.Tier == TierRestrictedPII {
				memIDs = append(memIDs, id)
			}
		}
		sort.Strings(memIDs)
		if len(memIDs) > 0 {
			firstMem = o.Memory.Records[memIDs[0]].Content
		}
		leakedDraft.SummaryNote = fmt.Sprintf("EXFIL_ATTEMPT cred=%s mem=%s", firstCred, firstMem)
		draftBytes, _ := CanonicalJSON(leakedDraft)
		if block := o.inspectEgress(env.Payload.TaskID, draftBytes); block != nil {
			rej := o.signRejectedReceipt(env.Payload.TaskID, env.SenderOrgID, block.ReasonCode, block)
			o.mu.Lock()
			o.tasks[env.Payload.TaskID] = rej
			o.taskRequester[env.Payload.TaskID] = env.SenderOrgID
			o.mu.Unlock()
			return rej, http.StatusForbidden
		}
	}

	rec := TaskResultReceipt{
		ReceiptID:      fmt.Sprintf("rcpt-%s-%s", o.OrgID, env.Payload.TaskID),
		TaskID:         env.Payload.TaskID,
		ExecutorOrgID:  o.OrgID,
		RequesterOrgID: env.SenderOrgID,
		SignerID:       o.GatewayKey.Principal.ID,
		State:          TaskStateCompleted,
		ErrorCode:      CodeOK,
		CompletedAt:    ts + 2,
		Transitions: []StateTransition{
			{State: TaskStateSubmitted, Timestamp: ts, Note: "envelope verified"},
			{State: TaskStateWorking, Timestamp: ts + 1, Note: "deterministic ZHL compute"},
			{State: TaskStateCompleted, Timestamp: ts + 2, Note: "egress boundary audit passed"},
		},
		Result:            &sciRes,
		EgressAuditPassed: true,
	}
	rec.ReceiptHash = ComputeReceiptHash(rec)
	rec.ExecutorSigHex = SignCanonical(o.GatewayKey.Private, DomainTaskReceipt, ReceiptSigningPayload(rec))

	o.mu.Lock()
	o.tasks[env.Payload.TaskID] = rec
	o.taskRequester[env.Payload.TaskID] = env.SenderOrgID
	o.mu.Unlock()
	return rec, http.StatusOK
}

func (o *OrgDeployment) processTaskSendSSE(w http.ResponseWriter, rpcID string, env SignedA2AEnvelope) {
	receipt, status := o.processTaskSend(env)
	if status != http.StatusOK {
		o.writeGuardedJSON(w, status, env.Payload.TaskID, JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      rpcID,
			Result:  receipt,
		})
		return
	}

	flusher, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	// Emit A2A TaskStatusUpdateEvent frames + final TaskArtifactUpdateEvent frame,
	// guarding every single SSE frame through the Egress Boundary Firewall.
	for _, tr := range receipt.Transitions {
		evPayload, _ := CanonicalJSON(map[string]any{
			"id":        rpcID,
			"jsonrpc":   "2.0",
			"state":     tr.State,
			"task_id":   receipt.TaskID,
			"timestamp": tr.Timestamp,
		})
		if o.inspectEgress(receipt.TaskID, evPayload) != nil {
			return
		}
		_, _ = fmt.Fprintf(w, "event: status\ndata: %s\n\n", string(evPayload))
		if flusher != nil {
			flusher.Flush()
		}
	}
	finalPayload, _ := CanonicalJSON(JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      rpcID,
		Result:  receipt,
	})
	if o.inspectEgress(receipt.TaskID, finalPayload) != nil {
		return
	}
	_, _ = fmt.Fprintf(w, "event: artifact\ndata: %s\n\n", string(finalPayload))
	if flusher != nil {
		flusher.Flush()
	}
}

func (o *OrgDeployment) processTaskGet(env SignedA2AEnvelope) (TaskResultReceipt, int) {
	if code := o.validateEnvelopeIngress(env, true); code != CodeOK {
		return o.signRejectedReceipt(env.Payload.TaskID, env.SenderOrgID, code, nil), http.StatusForbidden
	}
	o.mu.Lock()
	rec, ok := o.tasks[env.Payload.TaskID]
	owner := o.taskRequester[env.Payload.TaskID]
	o.mu.Unlock()
	if !ok || owner != env.SenderOrgID {
		return o.signRejectedReceipt(env.Payload.TaskID, env.SenderOrgID, CodeTaskStateInvalid, nil), http.StatusNotFound
	}
	return rec, http.StatusOK
}

func (o *OrgDeployment) processTaskCancel(env SignedA2AEnvelope) (TaskResultReceipt, int) {
	if code := o.validateEnvelopeIngress(env, true); code != CodeOK {
		return o.signRejectedReceipt(env.Payload.TaskID, env.SenderOrgID, code, nil), http.StatusForbidden
	}
	o.mu.Lock()
	rec, ok := o.tasks[env.Payload.TaskID]
	owner := o.taskRequester[env.Payload.TaskID]
	ts := o.clockSec
	if !ok || owner != env.SenderOrgID || (rec.State != TaskStateSubmitted && rec.State != TaskStateWorking) {
		o.mu.Unlock()
		return o.signRejectedReceipt(env.Payload.TaskID, env.SenderOrgID, CodeTaskStateInvalid, nil), http.StatusConflict
	}
	rec.State = TaskStateCanceled
	rec.CompletedAt = ts
	rec.Transitions = append(rec.Transitions, StateTransition{
		State:     TaskStateCanceled,
		Timestamp: ts,
		Note:      "canceled by originating organization",
	})
	rec.ReceiptHash = ComputeReceiptHash(rec)
	rec.ExecutorSigHex = SignCanonical(o.GatewayKey.Private, DomainTaskReceipt, ReceiptSigningPayload(rec))
	o.tasks[env.Payload.TaskID] = rec
	o.mu.Unlock()
	return rec, http.StatusOK
}

// --- Client-side live HTTP methods with automatic WireFrame recording ---

func (o *OrgDeployment) recordWireFrame(stage, toOrgID, method, path, contentType string, status int, reqBody, respBody []byte) WireFrame {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.frameCounter++
	wf := WireFrame{
		FrameID:        fmt.Sprintf("wf-%s-%02d", o.OrgID, o.frameCounter),
		Stage:          stage,
		FromOrgID:      o.OrgID,
		ToOrgID:        toOrgID,
		HTTPMethod:     method,
		Path:           path,
		ContentType:    contentType,
		HTTPStatus:     int64(status),
		RequestBody:    string(reqBody),
		ResponseBody:   string(respBody),
		RequestSHA256:  SHA256Hex(reqBody),
		ResponseSHA256: SHA256Hex(respBody),
		RequestBytes:   int64(len(reqBody)),
		ResponseBytes:  int64(len(respBody)),
	}
	o.wireFrames = append(o.wireFrames, wf)
	return wf
}

// DiscoverPeer fetches GET /.well-known/agent.json from a live peer HTTP server,
// verifies its Ed25519 signature, registers it locally, and records the WireFrame.
func (o *OrgDeployment) DiscoverPeer(stage, peerBaseURL, peerOrgID string) (AgentCard, WireFrame, error) {
	resp, err := o.client.Get(peerBaseURL + "/.well-known/agent.json")
	if err != nil {
		return AgentCard{}, WireFrame{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return AgentCard{}, WireFrame{}, err
	}
	wf := o.recordWireFrame(stage, peerOrgID, http.MethodGet, "/.well-known/agent.json",
		resp.Header.Get("Content-Type"), resp.StatusCode, nil, body)

	var card AgentCard
	if err := json.Unmarshal(body, &card); err != nil {
		return AgentCard{}, wf, err
	}
	if card.CardHash != ComputeAgentCardHash(card) ||
		!VerifyCanonical(card.GatewayPrincipal.PublicKeyHex, card.OrgSignatureHex, DomainAgentCard, AgentCardSigningPayload(card)) {
		return AgentCard{}, wf, fmt.Errorf("invalid peer AgentCard signature for %s", peerOrgID)
	}
	o.mu.Lock()
	o.peerCards[card.OrgID] = card
	o.mu.Unlock()
	return card, wf, nil
}

// SignEnvelope builds and signs a canonical SignedA2AEnvelope from this organization.
func (o *OrgDeployment) SignEnvelope(envelopeID, method, audienceOrgID, scope, nonce string, issuedAt, expiresAt int64, payload TaskPayload) SignedA2AEnvelope {
	payload.Commitment.CommitmentHash = ComputeCommitmentHash(payload.Commitment)
	env := SignedA2AEnvelope{
		EnvelopeID:    envelopeID,
		Method:        method,
		SenderOrgID:   o.OrgID,
		AudienceOrgID: audienceOrgID,
		SignerID:      o.GatewayKey.Principal.ID,
		Scope:         scope,
		TaskNonce:     nonce,
		IssuedAt:      issuedAt,
		ExpiresAt:     expiresAt,
		Payload:       payload,
	}
	env.EnvelopeHash = ComputeEnvelopeHash(env)
	env.OrgSigHex = SignCanonical(o.GatewayKey.Private, DomainEnvelope, EnvelopeSigningPayload(env))
	return env
}

// CallRPC sends a live HTTP POST /a2a/rpc JSON-RPC 2.0 request to a peer deployment.
func (o *OrgDeployment) CallRPC(stage, peerBaseURL string, env SignedA2AEnvelope) (TaskResultReceipt, WireFrame, int, error) {
	reqObj := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      env.EnvelopeID,
		Method:  env.Method,
		Params:  env,
	}
	reqBytes, err := CanonicalJSON(reqObj)
	if err != nil {
		return TaskResultReceipt{}, WireFrame{}, 0, err
	}
	// Outbound client egress firewall check BEFORE touching the socket!
	if block := o.inspectEgress(env.Payload.TaskID, reqBytes); block != nil {
		return TaskResultReceipt{}, WireFrame{}, http.StatusForbidden, fmt.Errorf("outbound egress blocked: %s", block.ReasonCode)
	}

	resp, err := o.client.Post(peerBaseURL+"/a2a/rpc", "application/json", bytes.NewReader(reqBytes))
	if err != nil {
		return TaskResultReceipt{}, WireFrame{}, 0, err
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return TaskResultReceipt{}, WireFrame{}, resp.StatusCode, err
	}
	wf := o.recordWireFrame(stage, env.AudienceOrgID, http.MethodPost, "/a2a/rpc",
		resp.Header.Get("Content-Type"), resp.StatusCode, reqBytes, respBytes)

	var rpcResp struct {
		JSONRPC string            `json:"jsonrpc"`
		ID      string            `json:"id"`
		Result  TaskResultReceipt `json:"result"`
		Error   *JSONRPCError     `json:"error"`
	}
	if err := json.Unmarshal(respBytes, &rpcResp); err != nil {
		return TaskResultReceipt{}, wf, resp.StatusCode, err
	}
	if rpcResp.Error != nil {
		return TaskResultReceipt{}, wf, resp.StatusCode, fmt.Errorf("rpc error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	return rpcResp.Result, wf, resp.StatusCode, nil
}

// CallRPCSSE sends a live HTTP POST /a2a/rpc with method "tasks/sendSubscribe"
// and consumes the live Server-Sent Events stream from the peer deployment.
func (o *OrgDeployment) CallRPCSSE(stage, peerBaseURL string, env SignedA2AEnvelope) (TaskResultReceipt, []string, WireFrame, int, error) {
	reqObj := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      env.EnvelopeID,
		Method:  "tasks/sendSubscribe",
		Params:  env,
	}
	reqBytes, err := CanonicalJSON(reqObj)
	if err != nil {
		return TaskResultReceipt{}, nil, WireFrame{}, 0, err
	}
	if block := o.inspectEgress(env.Payload.TaskID, reqBytes); block != nil {
		return TaskResultReceipt{}, nil, WireFrame{}, http.StatusForbidden, fmt.Errorf("outbound egress blocked: %s", block.ReasonCode)
	}

	resp, err := o.client.Post(peerBaseURL+"/a2a/rpc", "application/json", bytes.NewReader(reqBytes))
	if err != nil {
		return TaskResultReceipt{}, nil, WireFrame{}, 0, err
	}
	defer resp.Body.Close()

	var fullStream bytes.Buffer
	var events []string
	var finalReceipt TaskResultReceipt
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var currentEvent string
	for scanner.Scan() {
		line := scanner.Text()
		fullStream.WriteString(line)
		fullStream.WriteByte('\n')
		if strings.HasPrefix(line, "event: ") {
			currentEvent = strings.TrimPrefix(line, "event: ")
		} else if strings.HasPrefix(line, "data: ") {
			dataStr := strings.TrimPrefix(line, "data: ")
			events = append(events, currentEvent+":"+dataStr)
			if currentEvent == "artifact" {
				var rpcResp struct {
					Result TaskResultReceipt `json:"result"`
				}
				if err := json.Unmarshal([]byte(dataStr), &rpcResp); err == nil {
					finalReceipt = rpcResp.Result
				}
			}
		}
	}
	wf := o.recordWireFrame(stage, env.AudienceOrgID, http.MethodPost, "/a2a/rpc",
		resp.Header.Get("Content-Type"), resp.StatusCode, reqBytes, fullStream.Bytes())
	return finalReceipt, events, wf, resp.StatusCode, nil
}

// CreateAIAdvisory builds a non-binding AI_AGENT advisory recommendation.
func (o *OrgDeployment) CreateAIAdvisory(advisoryID, taskID, recommendation string, estimatedValueBps int64, conflicts []string) AdvisoryAssessment {
	adv := AdvisoryAssessment{
		AdvisoryID:        advisoryID,
		OrgID:             o.OrgID,
		AgentID:           o.AIAgentKey.Principal.ID,
		TaskID:            taskID,
		Binding:           false,
		Recommendation:    recommendation,
		EstimatedValueBps: estimatedValueBps,
		ConflictFlags:     nonNilStrings(conflicts),
	}
	adv.SignatureHex = SignCanonical(o.AIAgentKey.Private, DomainAdvisory, AdvisorySigningPayload(adv))
	return adv
}

// RecomputeAndAccept independently recomputes a peer's scientific result and
// signs an authoritative HUMAN_REVIEWER ExperimentAcceptance.
func (o *OrgDeployment) RecomputeAndAccept(acceptanceID string, env SignedA2AEnvelope, receipt TaskResultReceipt, advisoryID string, acceptedAt int64) (ExperimentAcceptance, error) {
	if receipt.Result == nil {
		return ExperimentAcceptance{}, fmt.Errorf("missing scientific result")
	}
	recomputed, err := RunDeterministicZHL(env.Payload.TaskID, env.Payload.Commitment)
	if err != nil {
		return ExperimentAcceptance{}, err
	}
	if recomputed.ResultHash != receipt.Result.ResultHash {
		return ExperimentAcceptance{}, fmt.Errorf("scientific recomputation mismatch: got %s want %s", receipt.Result.ResultHash, recomputed.ResultHash)
	}
	acc := ExperimentAcceptance{
		AcceptanceID:   acceptanceID,
		OrgID:          o.OrgID,
		TaskID:         env.Payload.TaskID,
		ReceiptHash:    receipt.ReceiptHash,
		RecomputedHash: recomputed.ResultHash,
		ReviewerID:     o.ReviewerKey.Principal.ID,
		ReviewerRole:   o.ReviewerKey.Principal.Role,
		AcceptedAt:     acceptedAt,
		AdvisoryRefID:  advisoryID,
	}
	acc.AcceptanceSigHex = SignCanonical(o.ReviewerKey.Private, DomainAcceptance, AcceptanceSigningPayload(acc))
	return acc, nil
}

func containsString(list []string, target string) bool {
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}

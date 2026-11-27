// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package settlement

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// RPCErrorResponse is returned by test-network HTTP endpoints when a protocol invariant rejects a request.
type RPCErrorResponse struct {
	OK        bool      `json:"ok"`
	ErrorCode ErrorCode `json:"error_code"`
	Message   string    `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeProtoError(w http.ResponseWriter, err error) {
	code := ErrorCodeOf(err)
	status := http.StatusBadRequest
	switch code {
	case ErrAppIssuanceForbidden, ErrAIIssuanceForbidden, ErrAIPolicyMutationForbid, ErrUnauthorizedTreasury, ErrUnauthorizedValidator, ErrSelfVerificationForbid:
		status = http.StatusForbidden
	case ErrDoubleClaim:
		status = http.StatusConflict
	}
	writeJSON(w, status, RPCErrorResponse{
		OK:        false,
		ErrorCode: code,
		Message:   err.Error(),
	})
}

// LoopbackTestNet hosts three isolated loopback HTTP/JSON-RPC nodes:
// Layer 1 (ValidatorCommittee), Layer 2 (SettlementEngine), and Layer 3 (FinalityTreasuryGate).
type LoopbackTestNet struct {
	ValidatorURL  string
	SettlementURL string
	FinalityURL   string

	ValidatorSrv  *http.Server
	SettlementSrv *http.Server
	FinalitySrv   *http.Server

	Committee  *ValidatorCommittee
	Settlement *SettlementEngine
	Finality   *FinalityTreasuryGate

	client *http.Client
}

// StartLoopbackTestNet launches three independent HTTP servers on 127.0.0.1 ephemeral ports.
func StartLoopbackTestNet(committee *ValidatorCommittee, engine *SettlementEngine, gate *FinalityTreasuryGate) (*LoopbackTestNet, error) {
	valMux := http.NewServeMux()
	valMux.HandleFunc("/v1/jobs/admit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var job AdmittedJob
		if err := json.NewDecoder(r.Body).Decode(&job); err != nil {
			writeProtoError(w, newProtoErr(ErrInvalidSchema, "bad json: %v", err))
			return
		}
		if err := committee.AdmitJob(job); err != nil {
			writeProtoError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "job_id": job.JobID})
	})
	valMux.HandleFunc("/v1/jobs/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			JobID string     `json:"job_id"`
			Work  WorkResult `json:"work"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeProtoError(w, newProtoErr(ErrInvalidSchema, "bad json: %v", err))
			return
		}
		atts, err := committee.VerifyAndAttest(req.JobID, req.Work)
		if err != nil {
			writeProtoError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "attestations": atts})
	})

	settleMux := http.NewServeMux()
	settleMux.HandleFunc("/v1/receipts/settle", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			CallerID     string           `json:"caller_id"`
			CallerRole   Role             `json:"caller_role"`
			Job          AdmittedJob      `json:"job"`
			Work         WorkResult       `json:"work"`
			Attestations []EASAttestation `json:"attestations"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeProtoError(w, newProtoErr(ErrInvalidSchema, "bad json: %v", err))
			return
		}
		receipt, err := engine.IssueReceipt(req.CallerID, req.CallerRole, req.Job, req.Work, req.Attestations)
		if err != nil {
			writeProtoError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "receipt": receipt})
	})
	settleMux.HandleFunc("/v1/epochs/seal", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Epoch uint64 `json:"epoch"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeProtoError(w, newProtoErr(ErrInvalidSchema, "bad json: %v", err))
			return
		}
		comm, proofs, err := engine.SealEpoch(req.Epoch)
		if err != nil {
			writeProtoError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "commitment": comm, "proofs": proofs})
	})
	settleMux.HandleFunc("/v1/receipts/read", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		rid := r.URL.Query().Get("receipt_id")
		rec, ok := engine.ReadReceipt(rid)
		if !ok {
			writeJSON(w, http.StatusNotFound, RPCErrorResponse{OK: false, ErrorCode: ErrInvalidSchema, Message: "receipt not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "receipt": rec})
	})

	finMux := http.NewServeMux()
	finMux.HandleFunc("/v1/epochs/commit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var comm EpochCommitment
		if err := json.NewDecoder(r.Body).Decode(&comm); err != nil {
			writeProtoError(w, newProtoErr(ErrInvalidSchema, "bad json: %v", err))
			return
		}
		if err := gate.RegisterEpochCommitment(comm); err != nil {
			writeProtoError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	finMux.HandleFunc("/v1/rewards/authorize", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			AuthorityID   string            `json:"authority_id"`
			AuthorityRole Role              `json:"authority_role"`
			CurrentEpoch  uint64            `json:"current_epoch"`
			Job           AdmittedJob       `json:"job"`
			Work          WorkResult        `json:"work"`
			Attestations  []EASAttestation  `json:"attestations"`
			Receipt       UsefulWorkReceipt `json:"receipt"`
			Proof         []MerkleProofStep `json:"proof"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeProtoError(w, newProtoErr(ErrInvalidSchema, "bad json: %v", err))
			return
		}
		auth, err := gate.AuthorizeReward(req.AuthorityID, req.AuthorityRole, req.CurrentEpoch, req.Job, req.Work, req.Attestations, req.Receipt, req.Proof)
		if err != nil {
			writeProtoError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "authorization": auth})
	})
	finMux.HandleFunc("/v1/policy/update", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var attempt PolicyMutationAttempt
		if err := json.NewDecoder(r.Body).Decode(&attempt); err != nil {
			writeProtoError(w, newProtoErr(ErrInvalidSchema, "bad json: %v", err))
			return
		}
		if err := gate.UpdatePolicy(attempt); err != nil {
			writeProtoError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	finMux.HandleFunc("/v1/ledger/balances", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "balance_sheet": gate.BalanceSheetSnapshot()})
	})

	startNode := func(mux *http.ServeMux) (string, *http.Server, error) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return "", nil, err
		}
		srv := &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			_ = srv.Serve(ln)
		}()
		return "http://" + ln.Addr().String(), srv, nil
	}

	valURL, valSrv, err := startNode(valMux)
	if err != nil {
		return nil, err
	}
	settleURL, settleSrv, err := startNode(settleMux)
	if err != nil {
		_ = valSrv.Close()
		return nil, err
	}
	finURL, finSrv, err := startNode(finMux)
	if err != nil {
		_ = valSrv.Close()
		_ = settleSrv.Close()
		return nil, err
	}

	return &LoopbackTestNet{
		ValidatorURL:  valURL,
		SettlementURL: settleURL,
		FinalityURL:   finURL,
		ValidatorSrv:  valSrv,
		SettlementSrv: settleSrv,
		FinalitySrv:   finSrv,
		Committee:     committee,
		Settlement:    engine,
		Finality:      gate,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        128,
				MaxIdleConnsPerHost: 128,
				IdleConnTimeout:     30 * time.Second,
			},
		},
	}, nil
}

// Close shuts down all three loopback HTTP nodes cleanly.
func (tn *LoopbackTestNet) Close() {
	if tn.ValidatorSrv != nil {
		_ = tn.ValidatorSrv.Close()
	}
	if tn.SettlementSrv != nil {
		_ = tn.SettlementSrv.Close()
	}
	if tn.FinalitySrv != nil {
		_ = tn.FinalitySrv.Close()
	}
	if tn.client != nil {
		tn.client.CloseIdleConnections()
	}
}

func (tn *LoopbackTestNet) postJSON(endpoint string, body any, dst any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := tn.client.Post(endpoint, "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var er RPCErrorResponse
		if json.Unmarshal(data, &er) == nil && er.ErrorCode != "" {
			return &ProtocolError{Code: er.ErrorCode, Message: er.Message}
		}
		return fmt.Errorf("http %d from %s: %s", resp.StatusCode, endpoint, string(data))
	}
	if dst != nil {
		return json.Unmarshal(data, dst)
	}
	return nil
}

// HTTPAdmitJob submits an AdmittedJob to Layer 1 Validator Node over loopback HTTP.
func (tn *LoopbackTestNet) HTTPAdmitJob(job AdmittedJob) error {
	return tn.postJSON(tn.ValidatorURL+"/v1/jobs/admit", job, nil)
}

// HTTPVerifyAndAttest requests independent verification & EAS attestations from Layer 1 over loopback HTTP.
func (tn *LoopbackTestNet) HTTPVerifyAndAttest(jobID string, work WorkResult) ([]EASAttestation, error) {
	var resp struct {
		OK           bool             `json:"ok"`
		Attestations []EASAttestation `json:"attestations"`
	}
	err := tn.postJSON(tn.ValidatorURL+"/v1/jobs/verify", map[string]any{
		"job_id": jobID,
		"work":   work,
	}, &resp)
	return resp.Attestations, err
}

// HTTPIssueReceipt sends quorum attestations to Layer 2 Settlement Node over loopback HTTP.
func (tn *LoopbackTestNet) HTTPIssueReceipt(callerID string, callerRole Role, job AdmittedJob, work WorkResult, atts []EASAttestation) (UsefulWorkReceipt, error) {
	var resp struct {
		OK      bool              `json:"ok"`
		Receipt UsefulWorkReceipt `json:"receipt"`
	}
	err := tn.postJSON(tn.SettlementURL+"/v1/receipts/settle", map[string]any{
		"caller_id":    callerID,
		"caller_role":  callerRole,
		"job":          job,
		"work":         work,
		"attestations": atts,
	}, &resp)
	return resp.Receipt, err
}

// HTTPSealEpoch seals an epoch on Layer 2 over loopback HTTP.
func (tn *LoopbackTestNet) HTTPSealEpoch(epoch uint64) (EpochCommitment, map[string][]MerkleProofStep, error) {
	var resp struct {
		OK         bool                         `json:"ok"`
		Commitment EpochCommitment              `json:"commitment"`
		Proofs     map[string][]MerkleProofStep `json:"proofs"`
	}
	err := tn.postJSON(tn.SettlementURL+"/v1/epochs/seal", map[string]any{"epoch": epoch}, &resp)
	return resp.Commitment, resp.Proofs, err
}

// HTTPReadReceipt performs a read-only consumer query against Layer 2 over loopback HTTP.
func (tn *LoopbackTestNet) HTTPReadReceipt(receiptID string) (UsefulWorkReceipt, error) {
	endpoint := tn.SettlementURL + "/v1/receipts/read?receipt_id=" + url.QueryEscape(receiptID)
	resp, err := tn.client.Get(endpoint)
	if err != nil {
		return UsefulWorkReceipt{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return UsefulWorkReceipt{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return UsefulWorkReceipt{}, fmt.Errorf("http %d: %s", resp.StatusCode, string(data))
	}
	var out struct {
		OK      bool              `json:"ok"`
		Receipt UsefulWorkReceipt `json:"receipt"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return UsefulWorkReceipt{}, err
	}
	return out.Receipt, nil
}

// HTTPRegisterEpochCommitment registers a sealed Layer 2 epoch root on Layer 3 over loopback HTTP.
func (tn *LoopbackTestNet) HTTPRegisterEpochCommitment(comm EpochCommitment) error {
	return tn.postJSON(tn.FinalityURL+"/v1/epochs/commit", comm, nil)
}

// HTTPAuthorizeReward requests Layer 3 finality-gated treasury authorization over loopback HTTP.
func (tn *LoopbackTestNet) HTTPAuthorizeReward(authorityID string, authorityRole Role, currentEpoch uint64, job AdmittedJob, work WorkResult, atts []EASAttestation, receipt UsefulWorkReceipt, proof []MerkleProofStep) (RewardAuthorization, error) {
	var resp struct {
		OK            bool                `json:"ok"`
		Authorization RewardAuthorization `json:"authorization"`
	}
	err := tn.postJSON(tn.FinalityURL+"/v1/rewards/authorize", map[string]any{
		"authority_id":   authorityID,
		"authority_role": authorityRole,
		"current_epoch":  currentEpoch,
		"job":            job,
		"work":           work,
		"attestations":   atts,
		"receipt":        receipt,
		"proof":          proof,
	}, &resp)
	return resp.Authorization, err
}

// HTTPUpdatePolicy attempts a Layer 3 governance policy mutation over loopback HTTP.
func (tn *LoopbackTestNet) HTTPUpdatePolicy(attempt PolicyMutationAttempt) error {
	return tn.postJSON(tn.FinalityURL+"/v1/policy/update", attempt, nil)
}

// HTTPGetBalances reads the Layer 3 BalanceSheet over loopback HTTP.
func (tn *LoopbackTestNet) HTTPGetBalances() (BalanceSheet, error) {
	resp, err := tn.client.Get(tn.FinalityURL + "/v1/ledger/balances")
	if err != nil {
		return BalanceSheet{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return BalanceSheet{}, err
	}
	var out struct {
		OK           bool         `json:"ok"`
		BalanceSheet BalanceSheet `json:"balance_sheet"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return BalanceSheet{}, err
	}
	return out.BalanceSheet, nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation & Open ResearchDAO Contributors.

package daoos

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

const (
	domainGenesis   = "researchdao-os.v1:genesis:"
	domainEnvelope  = "researchdao-os.v1:envelope:"
	domainEvent     = "researchdao-os.v1:event:"
	domainState     = "researchdao-os.v1:state:"
	domainMerkleEmp = "researchdao-os.v1:merkle:empty"
	domainMerkleLf  = "researchdao-os.v1:merkle:leaf:"
	domainMerkleNd  = "researchdao-os.v1:merkle:node:"
)

// CanonicalJSON encodes an arbitrary Go value (struct, map, slice, primitives) into
// deterministic, compact, sorted-key UTF-8 JSON without HTML escaping.
// Floats are explicitly forbidden in consensus objects to guarantee cross-language bit identity.
func CanonicalJSON(v any) ([]byte, error) {
	// Round-trip through encoding/json with UseNumber to normalize structs/maps uniformly.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("canonical json marshal: %w", err)
	}
	dec := json.NewDecoder(&buf)
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("canonical json decode: %w", err)
	}
	var out bytes.Buffer
	if err := writeCanonical(&out, generic); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func writeCanonical(out *bytes.Buffer, v any) error {
	switch val := v.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if val {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case json.Number:
		s := val.String()
		// Reject floating point numbers in consensus state.
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			u, uerr := strconv.ParseUint(s, 10, 64)
			if uerr != nil {
				return fmt.Errorf("non-integer number %q forbidden in canonical json", s)
			}
			out.WriteString(strconv.FormatUint(u, 10))
			return nil
		}
		out.WriteString(strconv.FormatInt(i, 10))
	case string:
		writeJSONString(out, val)
	case []any:
		out.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeCanonical(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			writeJSONString(out, k)
			out.WriteByte(':')
			if err := writeCanonical(out, val[k]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical json type %T", v)
	}
	return nil
}

// writeJSONString performs minimal RFC 8259 string escaping without HTML escaping,
// matching Python's json.dumps(..., ensure_ascii=False).
func writeJSONString(out *bytes.Buffer, s string) {
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
}

// HashGenesis returns the deterministic domain-separated SHA-256 hex digest of a Genesis object.
func HashGenesis(g Genesis) (string, error) {
	norm := normalizeGenesis(g)
	raw, err := CanonicalJSON(norm)
	if err != nil {
		return "", err
	}
	return domainSHA256Hex(domainGenesis, raw), nil
}

// SigningBytes constructs the domain-separated message signed by Ed25519 for an Envelope.
func SigningBytes(env Envelope) ([]byte, error) {
	unsigned := map[string]any{
		"spec_version":    env.SpecVersion,
		"seq":             env.Seq,
		"prev_event_hash": env.PrevEventHash,
		"timestamp":       env.Timestamp,
		"actor_id":        env.ActorID,
		"nonce":           env.Nonce,
		"type":            string(env.Type),
		"payload":         env.Payload,
	}
	raw, err := CanonicalJSON(unsigned)
	if err != nil {
		return nil, err
	}
	msg := make([]byte, 0, len(domainEnvelope)+len(raw))
	msg = append(msg, domainEnvelope...)
	msg = append(msg, raw...)
	return msg, nil
}

// HashEnvelope returns the deterministic SHA-256 hex digest of a signed Envelope.
func HashEnvelope(env Envelope) (string, error) {
	full := map[string]any{
		"spec_version":    env.SpecVersion,
		"seq":             env.Seq,
		"prev_event_hash": env.PrevEventHash,
		"timestamp":       env.Timestamp,
		"actor_id":        env.ActorID,
		"nonce":           env.Nonce,
		"type":            string(env.Type),
		"payload":         env.Payload,
		"signature_hex":   env.SignatureHex,
	}
	raw, err := CanonicalJSON(full)
	if err != nil {
		return "", err
	}
	return domainSHA256Hex(domainEvent, raw), nil
}

// StateRootHash computes the deterministic SHA-256 commitment over the complete normalized OS state.
func StateRootHash(st *State) (string, error) {
	view := canonicalStateView(st)
	raw, err := CanonicalJSON(view)
	if err != nil {
		return "", err
	}
	return domainSHA256Hex(domainState, raw), nil
}

// AuditMerkleRoot computes a binary SHA-256 Merkle root over the ordered event hashes.
func AuditMerkleRoot(eventHashes []string) (string, error) {
	if len(eventHashes) == 0 {
		sum := sha256.Sum256([]byte(domainMerkleEmp))
		return hex.EncodeToString(sum[:]), nil
	}
	level := make([][32]byte, len(eventHashes))
	for i, hHex := range eventHashes {
		b, err := hex.DecodeString(hHex)
		if err != nil || len(b) != 32 {
			return "", fmt.Errorf("invalid event hash at index %d", i)
		}
		h := sha256.New()
		h.Write([]byte(domainMerkleLf))
		h.Write(b)
		copy(level[i][:], h.Sum(nil))
	}
	for len(level) > 1 {
		nextLen := (len(level) + 1) / 2
		next := make([][32]byte, nextLen)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			h := sha256.New()
			h.Write([]byte(domainMerkleNd))
			h.Write(left[:])
			h.Write(right[:])
			copy(next[i/2][:], h.Sum(nil))
		}
		level = next
	}
	return hex.EncodeToString(level[0][:]), nil
}

func domainSHA256Hex(domain string, payload []byte) string {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

func normalizeGenesis(g Genesis) map[string]any {
	actors := make([]Actor, len(g.Actors))
	copy(actors, g.Actors)
	sort.Slice(actors, func(i, j int) bool { return actors[i].ID < actors[j].ID })
	actorViews := make([]any, len(actors))
	for i, a := range actors {
		roles := make([]string, len(a.Roles))
		for j, r := range a.Roles {
			roles[j] = string(r)
		}
		sort.Strings(roles)
		affs := make([]string, len(a.Affiliations))
		copy(affs, a.Affiliations)
		sort.Strings(affs)
		actorViews[i] = map[string]any{
			"id":              a.ID,
			"pubkey_hex":      a.PubKeyHex,
			"kind":            string(a.Kind),
			"roles":           roles,
			"affiliations":    affs,
			"reputation":      a.Reputation,
			"active":          a.Active,
			"effective_until": a.EffectiveUntil,
			"revoked_at":      a.RevokedAt,
			"last_nonce":      a.LastNonce,
		}
	}
	return map[string]any{
		"spec_version":             g.SpecVersion,
		"chain_id":                 g.ChainID,
		"created_at":               g.CreatedAt,
		"initial_treasury_balance": g.InitialTreasuryBalance,
		"config":                   configView(g.Config),
		"actors":                   actorViews,
	}
}

func configView(c GovernanceConfig) map[string]any {
	return map[string]any{
		"min_peer_reviews":           c.MinPeerReviews,
		"min_review_score_bps":       c.MinReviewScoreBps,
		"milestone_quorum":           c.MilestoneQuorum,
		"treasury_quorum":            c.TreasuryQuorum,
		"emergency_pause_quorum":     c.EmergencyPauseQuorum,
		"meta_governance_quorum":     c.MetaGovernanceQuorum,
		"timelock_seconds":           c.TimelockSeconds,
		"epoch_duration_seconds":     c.EpochDurationSeconds,
		"epoch_spend_cap_bps":        c.EpochSpendCapBps,
		"max_emergency_duration_sec": c.MaxEmergencyDurationSec,
		"holdback_bps":               c.HoldbackBps,
	}
}

func canonicalStateView(st *State) map[string]any {
	// Actors sorted by ID
	actorIDs := make([]string, 0, len(st.Actors))
	for id := range st.Actors {
		actorIDs = append(actorIDs, id)
	}
	sort.Strings(actorIDs)
	actorsView := make([]any, 0, len(actorIDs))
	for _, id := range actorIDs {
		a := st.Actors[id]
		roles := make([]string, len(a.Roles))
		for i, r := range a.Roles {
			roles[i] = string(r)
		}
		sort.Strings(roles)
		affs := make([]string, len(a.Affiliations))
		copy(affs, a.Affiliations)
		sort.Strings(affs)
		actorsView = append(actorsView, map[string]any{
			"id":              a.ID,
			"pubkey_hex":      a.PubKeyHex,
			"kind":            string(a.Kind),
			"roles":           roles,
			"affiliations":    affs,
			"reputation":      a.Reputation,
			"active":          a.Active,
			"effective_until": a.EffectiveUntil,
			"revoked_at":      a.RevokedAt,
			"last_nonce":      a.LastNonce,
		})
	}

	// Proposals sorted by ID
	propIDs := make([]string, 0, len(st.Proposals))
	for id := range st.Proposals {
		propIDs = append(propIDs, id)
	}
	sort.Strings(propIDs)
	proposalsView := make([]any, 0, len(propIDs))
	for _, id := range propIDs {
		p := st.Proposals[id]
		coi := sortedStringsCopy(p.DeclaredCOIActors)

		advs := make([]AdvisoryNote, len(p.Advisories))
		copy(advs, p.Advisories)
		sort.Slice(advs, func(i, j int) bool { return advs[i].Seq < advs[j].Seq })
		advsView := make([]any, len(advs))
		for i, n := range advs {
			advsView[i] = map[string]any{
				"seq":             n.Seq,
				"advisor_id":      n.AdvisorID,
				"timestamp":       n.Timestamp,
				"advisory_only":   n.AdvisoryOnly,
				"analysis_hash":   n.AnalysisHash,
				"summary":         n.Summary,
				"conflict_flags":  sortedStringsCopy(n.ConflictFlags),
				"estimated_value": n.EstimatedValue,
			}
		}

		revs := make([]PeerReview, len(p.Reviews))
		copy(revs, p.Reviews)
		sort.Slice(revs, func(i, j int) bool { return revs[i].ReviewerID < revs[j].ReviewerID })
		revsView := make([]any, len(revs))
		for i, r := range revs {
			revsView[i] = map[string]any{
				"reviewer_id":  r.ReviewerID,
				"timestamp":    r.Timestamp,
				"score_bps":    r.ScoreBps,
				"report_hash":  r.ReportHash,
				"recommend":    r.Recommend,
				"coi_declared": r.COIDeclared,
			}
		}

		msApps := make([]MilestoneApproval, len(p.MilestoneApprovals))
		copy(msApps, p.MilestoneApprovals)
		sort.Slice(msApps, func(i, j int) bool { return msApps[i].ApproverID < msApps[j].ApproverID })
		msView := make([]any, len(msApps))
		for i, m := range msApps {
			msView[i] = map[string]any{
				"approver_id":   m.ApproverID,
				"timestamp":     m.Timestamp,
				"evidence_hash": m.EvidenceHash,
				"notes_hash":    m.NotesHash,
			}
		}

		var fundingView any = nil
		if p.Funding != nil {
			fundingView = map[string]any{
				"amount":               p.Funding.Amount,
				"initial_tranche":      p.Funding.InitialTranche,
				"holdback_tranche":     p.Funding.HoldbackTranche,
				"queued_at":            p.Funding.QueuedAt,
				"timelock_ready_at":    p.Funding.TimelockReadyAt,
				"authorized_at":        p.Funding.AuthorizedAt,
				"steward_signers":      sortedStringsCopy(p.Funding.StewardSigners),
				"initial_tranche_id":   p.Funding.InitialTrancheID,
				"holdback_tranche_id":  p.Funding.HoldbackTrancheID,
				"initial_disbursed":    p.Funding.InitialDisbursed,
				"holdback_disbursed":   p.Funding.HoldbackDisbursed,
				"holdback_clawed_back": p.Funding.HoldbackClawedBack,
			}
		}

		var vetoView any = nil
		if p.Veto != nil {
			vetoView = map[string]any{
				"guardian_id":   p.Veto.GuardianID,
				"timestamp":     p.Veto.Timestamp,
				"justification": p.Veto.Justification,
			}
		}

		var accView any = nil
		if p.Acceptance != nil {
			accView = map[string]any{
				"verifier_id":         p.Acceptance.VerifierID,
				"timestamp":           p.Acceptance.Timestamp,
				"bound_evidence_hash": p.Acceptance.BoundEvidenceHash,
				"repro_check_hash":    p.Acceptance.ReproCheckHash,
				"verdict":             p.Acceptance.Verdict,
			}
		}

		proposalsView = append(proposalsView, map[string]any{
			"id":                      p.ID,
			"title":                   p.Title,
			"category":                string(p.Category),
			"proposer_id":             p.ProposerID,
			"plan_hash":               p.PlanHash,
			"source_paper":            p.SourcePaper,
			"requested_amount":        p.RequestedAmount,
			"declared_coi_actors":     coi,
			"status":                  string(p.Status),
			"submitted_at":            p.SubmittedAt,
			"advisories":              advsView,
			"reviews":                 revsView,
			"review_mean_score_bps":   p.ReviewMeanScoreBps,
			"milestone_index":         p.MilestoneIndex,
			"milestone_evidence_hash": p.MilestoneEvidenceHash,
			"milestone_approvals":     msView,
			"funding":                 fundingView,
			"veto":                    vetoView,
			"acceptance":              accView,
		})
	}

	// Treasury view
	epochSpent := make(map[string]any, len(st.Treasury.EpochSpent))
	for k, v := range st.Treasury.EpochSpent {
		epochSpent[k] = v
	}
	tranches := make([]string, 0, len(st.Treasury.DisbursedTranches))
	for k, v := range st.Treasury.DisbursedTranches {
		if v {
			tranches = append(tranches, k)
		}
	}
	sort.Strings(tranches)

	// Emergency pause view
	pendingPauses := make(map[string]any, len(st.EmergencyPause.PendingPauses))
	for k, v := range st.EmergencyPause.PendingPauses {
		pendingPauses[k] = sortedStringsCopy(v)
	}
	pendingReasons := make(map[string]any, len(st.EmergencyPause.PendingReasons))
	for k, v := range st.EmergencyPause.PendingReasons {
		pendingReasons[k] = v
	}
	pendingDurs := make(map[string]any, len(st.EmergencyPause.PendingDurs))
	for k, v := range st.EmergencyPause.PendingDurs {
		pendingDurs[k] = v
	}
	pendingLifts := make(map[string]any, len(st.EmergencyPause.PendingLifts))
	for k, v := range st.EmergencyPause.PendingLifts {
		pendingLifts[k] = sortedStringsCopy(v)
	}

	// Pending rule changes sorted by ChangeID
	rcIDs := make([]string, 0, len(st.PendingRuleChanges))
	for id := range st.PendingRuleChanges {
		rcIDs = append(rcIDs, id)
	}
	sort.Strings(rcIDs)
	rcView := make([]any, 0, len(rcIDs))
	for _, id := range rcIDs {
		rc := st.PendingRuleChanges[id]
		rcView = append(rcView, map[string]any{
			"change_id":   rc.ChangeID,
			"parameter":   rc.Parameter,
			"new_value":   rc.NewValue,
			"signers":     sortedStringsCopy(rc.Signers),
			"executed":    rc.Executed,
			"executed_at": rc.ExecutedAt,
			"proposed_at": rc.ProposedAt,
		})
	}

	return map[string]any{
		"spec_version":   st.SpecVersion,
		"chain_id":       st.ChainID,
		"genesis_hash":   st.GenesisHash,
		"seq":            st.Seq,
		"last_timestamp": st.LastTimestamp,
		"last_event_hash": st.LastEventHash,
		"config":         configView(st.Config),
		"treasury": map[string]any{
			"balance":            st.Treasury.Balance,
			"escrowed_total":     st.Treasury.EscrowedTotal,
			"total_disbursed":    st.Treasury.TotalDisbursed,
			"epoch_spent":        epochSpent,
			"disbursed_tranches": tranches,
		},
		"emergency_pause": map[string]any{
			"active":           st.EmergencyPause.Active,
			"action_id":        st.EmergencyPause.ActionID,
			"reason":           st.EmergencyPause.Reason,
			"activated_at":     st.EmergencyPause.ActivatedAt,
			"expires_at":       st.EmergencyPause.ExpiresAt,
			"signers":          sortedStringsCopy(st.EmergencyPause.Signers),
			"pending_pauses":   pendingPauses,
			"pending_reasons":  pendingReasons,
			"pending_durs":     pendingDurs,
			"pending_lifts":    pendingLifts,
			"last_review_hash": st.EmergencyPause.LastReviewHash,
		},
		"actors":               actorsView,
		"proposals":            proposalsView,
		"pending_rule_changes": rcView,
	}
}

func sortedStringsCopy(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	cp := make([]string, len(in))
	copy(cp, in)
	sort.Strings(cp)
	return cp
}

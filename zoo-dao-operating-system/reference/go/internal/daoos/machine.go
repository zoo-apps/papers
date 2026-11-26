// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation & Open ResearchDAO Contributors.

package daoos

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Machine executes the deterministic ResearchDAO Operating System state machine.
type Machine struct {
	mu          sync.RWMutex
	genesis     Genesis
	state       State
	eventHashes []string
	wal         *WAL
}

// NewMachine initializes a ResearchDAO OS state machine from an immutable Genesis configuration.
func NewMachine(g Genesis) (*Machine, error) {
	if err := validateGenesis(g); err != nil {
		return nil, err
	}
	if g.SpecVersion == "" {
		g.SpecVersion = SpecVersion
	}
	genHash, err := HashGenesis(g)
	if err != nil {
		return nil, err
	}

	actors := make(map[string]*Actor, len(g.Actors))
	for _, a := range g.Actors {
		cp := cloneActor(&a)
		actors[cp.ID] = cp
	}

	st := State{
		SpecVersion:   SpecVersion,
		ChainID:       g.ChainID,
		GenesisHash:   genHash,
		Seq:           0,
		LastTimestamp: g.CreatedAt,
		LastEventHash: GenesisPrevHash,
		Config:        g.Config,
		Treasury: TreasuryState{
			Balance:           g.InitialTreasuryBalance,
			EscrowedTotal:     0,
			TotalDisbursed:    0,
			EpochSpent:        map[string]int64{},
			DisbursedTranches: map[string]bool{},
		},
		EmergencyPause: EmergencyPauseState{
			Active:         false,
			Signers:        []string{},
			PendingPauses:  map[string][]string{},
			PendingReasons: map[string]string{},
			PendingDurs:    map[string]int64{},
			PendingLifts:   map[string][]string{},
		},
		Actors:             actors,
		Proposals:          map[string]*Proposal{},
		PendingRuleChanges: map[string]*PendingRuleChange{},
	}

	return &Machine{
		genesis:     g,
		state:       st,
		eventHashes: []string{},
	}, nil
}

// AttachWAL binds a crash-safe disk WAL to this Machine so every committed envelope is fsynced.
func (m *Machine) AttachWAL(w *WAL) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.wal = w
}

// Genesis returns a copy of the Genesis configuration.
func (m *Machine) Genesis() Genesis {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.genesis
}

// NextSeq returns the next expected sequence number.
func (m *Machine) NextSeq() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.Seq + 1
}

// LastEventHash returns the current tip event hash.
func (m *Machine) LastEventHash() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.LastEventHash
}

// ActorNextNonce returns the next required nonce for actorID.
func (m *Machine) ActorNextNonce(actorID string) (uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.state.Actors[actorID]
	if !ok {
		return 0, NewTransitionError(ErrUnknownActor, actorID)
	}
	return a.LastNonce + 1, nil
}

// Roots returns the deterministic (state_root_hash, audit_merkle_root) commitments.
func (m *Machine) Roots() (stateRoot string, auditRoot string, err error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sr, err := StateRootHash(&m.state)
	if err != nil {
		return "", "", err
	}
	ar, err := AuditMerkleRoot(m.eventHashes)
	if err != nil {
		return "", "", err
	}
	return sr, ar, nil
}

// SnapshotState returns a deep copy of the current State.
func (m *Machine) SnapshotState() State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return deepCopyState(&m.state)
}

// CreateCheckpoint captures a verified durable Checkpoint at the current sequence.
func (m *Machine) CreateCheckpoint() (Checkpoint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sr, err := StateRootHash(&m.state)
	if err != nil {
		return Checkpoint{}, err
	}
	ar, err := AuditMerkleRoot(m.eventHashes)
	if err != nil {
		return Checkpoint{}, err
	}
	hashesCopy := make([]string, len(m.eventHashes))
	copy(hashesCopy, m.eventHashes)
	return Checkpoint{
		SpecVersion:     SpecVersion,
		GenesisHash:     m.state.GenesisHash,
		Seq:             m.state.Seq,
		LastEventHash:   m.state.LastEventHash,
		StateRootHash:   sr,
		AuditMerkleRoot: ar,
		EventHashes:     hashesCopy,
		State:           deepCopyState(&m.state),
	}, nil
}

// Apply validates, authorizes, optionally fsyncs to WAL, and atomically applies a signed Envelope.
// On any error, the in-memory state and WAL remain completely unmodified.
func (m *Machine) Apply(env Envelope) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applyLocked(env, true)
}

func (m *Machine) applyLocked(env Envelope, persist bool) (string, error) {
	// Stage transition against a deep copy for strict atomicity on any validation or disk failure.
	// Wait: for high-throughput benchmarks we validate first before mutating m.state directly,
	// avoiding O(|proposals|) deep copies per event while maintaining zero partial mutations.
	if env.SpecVersion != SpecVersion {
		return "", NewTransitionError(ErrInvalidPayload, fmt.Sprintf("unsupported spec_version %q", env.SpecVersion))
	}
	if env.Seq != m.state.Seq+1 {
		return "", NewTransitionError(ErrInvalidSequence, fmt.Sprintf("expected seq %d, got %d", m.state.Seq+1, env.Seq))
	}
	if env.PrevEventHash != m.state.LastEventHash {
		return "", NewTransitionError(ErrChainBroken, fmt.Sprintf("expected prev_event_hash %s, got %s", m.state.LastEventHash, env.PrevEventHash))
	}
	if env.Timestamp < m.state.LastTimestamp {
		return "", NewTransitionError(ErrTimestampRegression, fmt.Sprintf("timestamp %d < last_timestamp %d", env.Timestamp, m.state.LastTimestamp))
	}

	actor, ok := m.state.Actors[env.ActorID]
	if !ok {
		return "", NewTransitionError(ErrUnknownActor, fmt.Sprintf("unknown actor %q", env.ActorID))
	}
	if !actor.Active {
		return "", NewTransitionError(ErrActorRevoked, fmt.Sprintf("actor %q is revoked", env.ActorID))
	}
	if actor.EffectiveUntil > 0 && env.Timestamp > actor.EffectiveUntil {
		return "", NewTransitionError(ErrActorExpired, fmt.Sprintf("actor %q key expired at %d", env.ActorID, actor.EffectiveUntil))
	}
	if env.Nonce != actor.LastNonce+1 {
		return "", NewTransitionError(ErrNonceReplay, fmt.Sprintf("actor %q expected nonce %d, got %d", env.ActorID, actor.LastNonce+1, env.Nonce))
	}
	if err := VerifyEnvelopeSignature(env, actor.PubKeyHex); err != nil {
		return "", err
	}

	// Strict Constitutional Separation: AI agents may ONLY emit non-binding AdvisoryRecorded notes.
	if actor.Kind == ActorKindAIAgent {
		if err := enforceAIConstitution(env.Type); err != nil {
			return "", err
		}
	}

	// Validate transition and obtain commit closure (pure validation, no mutations until commit()).
	commitFn, err := m.prepareTransitionLocked(actor, env)
	if err != nil {
		return "", err
	}

	eventHash, err := HashEnvelope(env)
	if err != nil {
		return "", NewTransitionError(ErrInvalidPayload, err.Error())
	}

	if persist && m.wal != nil {
		if err := m.wal.AppendEnvelope(env); err != nil {
			return "", fmt.Errorf("wal append failed: %w", err)
		}
	}

	// Commit state mutations atomically in memory.
	commitFn()
	actor.LastNonce = env.Nonce
	m.state.Seq = env.Seq
	m.state.LastTimestamp = env.Timestamp
	m.state.LastEventHash = eventHash
	m.eventHashes = append(m.eventHashes, eventHash)
	return eventHash, nil
}

func enforceAIConstitution(evType EventType) error {
	switch evType {
	case EventAdvisoryRecorded:
		return nil
	case EventFundingQueued, EventFundingCosigned, EventFundingAuthorized:
		return NewTransitionError(ErrAITreasuryForbidden, "AI agents cannot queue, cosign, or authorize treasury disbursements")
	case EventGovernanceRuleAmended:
		return NewTransitionError(ErrAIRuleChangeForbidden, "AI agents cannot redefine governance or voting rules")
	case EventPeerReviewRecorded, EventMilestoneApproved, EventIndependentAcceptanceRecorded:
		return NewTransitionError(ErrAIValidationForbidden, "AI agents cannot cast peer reviews, approve milestones, or declare experiments valid")
	default:
		return NewTransitionError(ErrAIGovernanceForbidden, fmt.Sprintf("AI agents are constitutionally barred from %s", evType))
	}
}

func (m *Machine) isPausedLocked(ts int64) bool {
	return m.state.EmergencyPause.Active && ts <= m.state.EmergencyPause.ExpiresAt
}

func (m *Machine) prepareTransitionLocked(actor *Actor, env Envelope) (func(), error) {
	switch env.Type {
	case EventProposalSubmitted:
		return m.prepareProposalSubmitted(actor, env)
	case EventAdvisoryRecorded:
		return m.prepareAdvisoryRecorded(actor, env)
	case EventPeerReviewRecorded:
		return m.preparePeerReviewRecorded(actor, env)
	case EventMilestoneApproved:
		return m.prepareMilestoneApproved(actor, env)
	case EventFundingQueued:
		return m.prepareFundingQueued(actor, env)
	case EventFundingCosigned:
		return m.prepareFundingCosigned(actor, env)
	case EventFundingAuthorized:
		return m.prepareFundingAuthorized(actor, env)
	case EventBoardVetoRecorded:
		return m.prepareBoardVetoRecorded(actor, env)
	case EventIndependentAcceptanceRecorded:
		return m.prepareIndependentAcceptance(actor, env)
	case EventEmergencyPauseSigned:
		return m.prepareEmergencyPauseSigned(actor, env)
	case EventEmergencyPauseLifted:
		return m.prepareEmergencyPauseLifted(actor, env)
	case EventGovernanceRuleAmended:
		return m.prepareGovernanceRuleAmended(actor, env)
	case EventActorRevoked:
		return m.prepareActorRevoked(actor, env)
	default:
		return nil, NewTransitionError(ErrInvalidPayload, fmt.Sprintf("unknown event type %q", env.Type))
	}
}

func (m *Machine) prepareProposalSubmitted(actor *Actor, env Envelope) (func(), error) {
	if !actor.HasRole(RoleResearcher) {
		return nil, NewTransitionError(ErrUnauthorizedRole, "requires RESEARCHER role")
	}
	propID, err := reqString(env.Payload, "proposal_id")
	if err != nil {
		return nil, err
	}
	if _, exists := m.state.Proposals[propID]; exists {
		return nil, NewTransitionError(ErrDuplicateProposal, fmt.Sprintf("proposal %q already exists", propID))
	}
	title, err := reqString(env.Payload, "title")
	if err != nil {
		return nil, err
	}
	catStr, err := reqString(env.Payload, "category")
	if err != nil {
		return nil, err
	}
	cat := ProposalCategory(catStr)
	if !isValidCategory(cat) {
		return nil, NewTransitionError(ErrInvalidPayload, fmt.Sprintf("invalid category %q", catStr))
	}
	planHash, err := reqHash(env.Payload, "plan_hash")
	if err != nil {
		return nil, err
	}
	sourcePaper, err := reqString(env.Payload, "source_paper")
	if err != nil {
		return nil, err
	}
	reqAmt, err := reqInt64(env.Payload, "requested_amount")
	if err != nil || reqAmt <= 0 {
		return nil, NewTransitionError(ErrInvalidPayload, "requested_amount must be positive integer")
	}
	coiActors, err := optStringSlice(env.Payload, "declared_coi_actors")
	if err != nil {
		return nil, err
	}

	return func() {
		m.state.Proposals[propID] = &Proposal{
			ID:                 propID,
			Title:              title,
			Category:           cat,
			ProposerID:         actor.ID,
			PlanHash:           planHash,
			SourcePaper:        sourcePaper,
			RequestedAmount:    reqAmt,
			DeclaredCOIActors:  sortedStringsCopy(coiActors),
			Status:             StatusSubmitted,
			SubmittedAt:        env.Timestamp,
			Advisories:         []AdvisoryNote{},
			Reviews:            []PeerReview{},
			MilestoneApprovals: []MilestoneApproval{},
		}
	}, nil
}

func (m *Machine) prepareAdvisoryRecorded(actor *Actor, env Envelope) (func(), error) {
	if !actor.HasRole(RoleAIAdvisor) {
		return nil, NewTransitionError(ErrUnauthorizedRole, "requires AI_ADVISOR role")
	}
	propID, err := reqString(env.Payload, "proposal_id")
	if err != nil {
		return nil, err
	}
	p, ok := m.state.Proposals[propID]
	if !ok {
		return nil, NewTransitionError(ErrProposalNotFound, propID)
	}
	advOnly, err := reqBool(env.Payload, "advisory_only")
	if err != nil || !advOnly {
		return nil, NewTransitionError(ErrInvalidPayload, "advisory_only must be explicitly true")
	}
	analysisHash, err := reqHash(env.Payload, "analysis_hash")
	if err != nil {
		return nil, err
	}
	summary, err := reqString(env.Payload, "summary")
	if err != nil {
		return nil, err
	}
	flags, err := optStringSlice(env.Payload, "conflict_flags")
	if err != nil {
		return nil, err
	}
	estVal, err := reqInt64(env.Payload, "estimated_value")
	if err != nil || estVal < 0 {
		return nil, NewTransitionError(ErrInvalidPayload, "estimated_value must be non-negative integer")
	}

	return func() {
		// Strictly non-binding: never alters proposal Status, config, or treasury.
		p.Advisories = append(p.Advisories, AdvisoryNote{
			Seq:            env.Seq,
			AdvisorID:      actor.ID,
			Timestamp:      env.Timestamp,
			AdvisoryOnly:   true,
			AnalysisHash:   analysisHash,
			Summary:        summary,
			ConflictFlags:  sortedStringsCopy(flags),
			EstimatedValue: estVal,
		})
	}, nil
}

func (m *Machine) preparePeerReviewRecorded(actor *Actor, env Envelope) (func(), error) {
	if !actor.HasRole(RolePeerReviewer) {
		return nil, NewTransitionError(ErrUnauthorizedRole, "requires PEER_REVIEWER role")
	}
	propID, err := reqString(env.Payload, "proposal_id")
	if err != nil {
		return nil, err
	}
	p, ok := m.state.Proposals[propID]
	if !ok {
		return nil, NewTransitionError(ErrProposalNotFound, propID)
	}
	if p.Status != StatusSubmitted && p.Status != StatusUnderReview {
		return nil, NewTransitionError(ErrInvalidTransition, fmt.Sprintf("proposal %q in state %s cannot accept peer reviews", propID, p.Status))
	}
	if actor.ID == p.ProposerID {
		return nil, NewTransitionError(ErrSelfReviewForbidden, "proposer cannot peer-review own proposal")
	}
	if hasCOI(actor, m.state.Actors[p.ProposerID], p.DeclaredCOIActors) {
		return nil, NewTransitionError(ErrCOIConflict, fmt.Sprintf("reviewer %q has conflict of interest with proposer %q", actor.ID, p.ProposerID))
	}
	for _, r := range p.Reviews {
		if r.ReviewerID == actor.ID {
			return nil, NewTransitionError(ErrDuplicateReview, fmt.Sprintf("reviewer %q already reviewed %q", actor.ID, propID))
		}
	}
	scoreBps, err := reqInt64(env.Payload, "score_bps")
	if err != nil || scoreBps < 0 || scoreBps > 10000 {
		return nil, NewTransitionError(ErrInvalidPayload, "score_bps must be integer in [0, 10000]")
	}
	reportHash, err := reqHash(env.Payload, "report_hash")
	if err != nil {
		return nil, err
	}
	recommend, err := reqBool(env.Payload, "recommend")
	if err != nil {
		return nil, err
	}
	coiDeclared, err := reqBool(env.Payload, "coi_declared")
	if err != nil {
		return nil, err
	}
	if coiDeclared {
		return nil, NewTransitionError(ErrCOIConflict, "reviewer declared COI and must recuse")
	}

	return func() {
		p.Reviews = append(p.Reviews, PeerReview{
			ReviewerID:  actor.ID,
			Timestamp:   env.Timestamp,
			ScoreBps:    scoreBps,
			ReportHash:  reportHash,
			Recommend:   recommend,
			COIDeclared: false,
		})
		sort.Slice(p.Reviews, func(i, j int) bool { return p.Reviews[i].ReviewerID < p.Reviews[j].ReviewerID })
		var sum int64
		for _, r := range p.Reviews {
			sum += r.ScoreBps
		}
		cnt := int64(len(p.Reviews))
		p.ReviewMeanScoreBps = sum / cnt
		if len(p.Reviews) >= m.state.Config.MinPeerReviews {
			if sum >= m.state.Config.MinReviewScoreBps*cnt {
				p.Status = StatusPeerReviewed
			} else {
				p.Status = StatusReviewRejected
			}
		} else {
			p.Status = StatusUnderReview
		}
	}, nil
}

func (m *Machine) prepareMilestoneApproved(actor *Actor, env Envelope) (func(), error) {
	if !actor.HasRole(RoleMilestoneCommittee) {
		return nil, NewTransitionError(ErrUnauthorizedRole, "requires MILESTONE_COMMITTEE role")
	}
	propID, err := reqString(env.Payload, "proposal_id")
	if err != nil {
		return nil, err
	}
	p, ok := m.state.Proposals[propID]
	if !ok {
		return nil, NewTransitionError(ErrProposalNotFound, propID)
	}
	if p.Status != StatusPeerReviewed {
		return nil, NewTransitionError(ErrInvalidTransition, fmt.Sprintf("proposal %q in state %s cannot approve milestone", propID, p.Status))
	}
	if actor.ID == p.ProposerID {
		return nil, NewTransitionError(ErrSelfApprovalForbidden, "proposer cannot approve own milestone")
	}
	if hasCOI(actor, m.state.Actors[p.ProposerID], p.DeclaredCOIActors) {
		return nil, NewTransitionError(ErrCOIConflict, fmt.Sprintf("committee member %q has COI with proposer %q", actor.ID, p.ProposerID))
	}
	for _, a := range p.MilestoneApprovals {
		if a.ApproverID == actor.ID {
			return nil, NewTransitionError(ErrDuplicateApproval, fmt.Sprintf("approver %q already approved milestone", actor.ID))
		}
	}
	msIdx, err := reqInt64(env.Payload, "milestone_index")
	if err != nil || msIdx < 1 {
		return nil, NewTransitionError(ErrInvalidPayload, "milestone_index must be >= 1")
	}
	evHash, err := reqHash(env.Payload, "evidence_hash")
	if err != nil {
		return nil, err
	}
	if evHash == p.PlanHash {
		return nil, NewTransitionError(ErrEvidenceMismatch, "milestone evidence_hash cannot reuse proposal plan_hash")
	}
	if p.MilestoneEvidenceHash != "" && p.MilestoneEvidenceHash != evHash {
		return nil, NewTransitionError(ErrEvidenceMismatch, "milestone evidence_hash conflicts with prior committee approval")
	}
	notesHash, err := reqHash(env.Payload, "notes_hash")
	if err != nil {
		return nil, err
	}

	return func() {
		p.MilestoneIndex = msIdx
		p.MilestoneEvidenceHash = evHash
		p.MilestoneApprovals = append(p.MilestoneApprovals, MilestoneApproval{
			ApproverID:   actor.ID,
			Timestamp:    env.Timestamp,
			EvidenceHash: evHash,
			NotesHash:    notesHash,
		})
		sort.Slice(p.MilestoneApprovals, func(i, j int) bool { return p.MilestoneApprovals[i].ApproverID < p.MilestoneApprovals[j].ApproverID })
		if len(p.MilestoneApprovals) >= m.state.Config.MilestoneQuorum {
			p.Status = StatusMilestoneApproved
		}
	}, nil
}

func (m *Machine) prepareFundingQueued(actor *Actor, env Envelope) (func(), error) {
	if !actor.HasRole(RoleTreasurySteward) {
		return nil, NewTransitionError(ErrUnauthorizedRole, "requires TREASURY_STEWARD role")
	}
	if m.isPausedLocked(env.Timestamp) {
		return nil, NewTransitionError(ErrSystemPaused, "funding queue blocked during active emergency pause")
	}
	propID, err := reqString(env.Payload, "proposal_id")
	if err != nil {
		return nil, err
	}
	p, ok := m.state.Proposals[propID]
	if !ok {
		return nil, NewTransitionError(ErrProposalNotFound, propID)
	}
	if p.Status == StatusVetoed {
		return nil, NewTransitionError(ErrProposalVetoed, "proposal was vetoed by board guardian")
	}
	if p.Status != StatusMilestoneApproved {
		return nil, NewTransitionError(ErrInvalidTransition, fmt.Sprintf("proposal %q in state %s cannot queue funding", propID, p.Status))
	}
	amount, err := reqInt64(env.Payload, "amount")
	if err != nil || amount <= 0 {
		return nil, NewTransitionError(ErrInvalidPayload, "amount must be positive integer")
	}
	if amount > p.RequestedAmount {
		return nil, NewTransitionError(ErrBudgetCapExceeded, "funding amount exceeds proposal requested_amount")
	}
	if err := m.checkTreasuryCapLocked(amount, env.Timestamp); err != nil {
		return nil, err
	}

	holdback := (amount * m.state.Config.HoldbackBps) / 10000
	initial := amount - holdback

	return func() {
		p.Funding = &FundingRecord{
			Amount:            amount,
			InitialTranche:    initial,
			HoldbackTranche:   holdback,
			QueuedAt:          env.Timestamp,
			TimelockReadyAt:   env.Timestamp + m.state.Config.TimelockSeconds,
			AuthorizedAt:      0,
			StewardSigners:    []string{actor.ID},
			InitialTrancheID:  propID + ":initial",
			HoldbackTrancheID: propID + ":holdback",
		}
		p.Status = StatusFundingQueued
	}, nil
}

func (m *Machine) prepareFundingCosigned(actor *Actor, env Envelope) (func(), error) {
	if !actor.HasRole(RoleTreasurySteward) {
		return nil, NewTransitionError(ErrUnauthorizedRole, "requires TREASURY_STEWARD role")
	}
	if m.isPausedLocked(env.Timestamp) {
		return nil, NewTransitionError(ErrSystemPaused, "funding cosign blocked during active emergency pause")
	}
	propID, err := reqString(env.Payload, "proposal_id")
	if err != nil {
		return nil, err
	}
	p, ok := m.state.Proposals[propID]
	if !ok {
		return nil, NewTransitionError(ErrProposalNotFound, propID)
	}
	if p.Status == StatusVetoed {
		return nil, NewTransitionError(ErrProposalVetoed, "proposal was vetoed by board guardian")
	}
	if p.Status != StatusFundingQueued || p.Funding == nil {
		return nil, NewTransitionError(ErrInvalidTransition, fmt.Sprintf("proposal %q is not in FUNDING_QUEUED state", propID))
	}
	for _, s := range p.Funding.StewardSigners {
		if s == actor.ID {
			return nil, NewTransitionError(ErrDuplicateApproval, fmt.Sprintf("steward %q already cosigned %q", actor.ID, propID))
		}
	}

	return func() {
		p.Funding.StewardSigners = append(p.Funding.StewardSigners, actor.ID)
		sort.Strings(p.Funding.StewardSigners)
	}, nil
}

func (m *Machine) prepareFundingAuthorized(actor *Actor, env Envelope) (func(), error) {
	if !actor.HasRole(RoleTreasurySteward) {
		return nil, NewTransitionError(ErrUnauthorizedRole, "requires TREASURY_STEWARD role")
	}
	if m.isPausedLocked(env.Timestamp) {
		return nil, NewTransitionError(ErrSystemPaused, "funding authorization blocked during active emergency pause")
	}
	propID, err := reqString(env.Payload, "proposal_id")
	if err != nil {
		return nil, err
	}
	p, ok := m.state.Proposals[propID]
	if !ok {
		return nil, NewTransitionError(ErrProposalNotFound, propID)
	}
	if p.Status == StatusVetoed {
		return nil, NewTransitionError(ErrProposalVetoed, "proposal was vetoed by board guardian")
	}
	if p.Funding != nil && (p.Funding.InitialDisbursed || m.state.Treasury.DisbursedTranches[p.Funding.InitialTrancheID]) {
		return nil, NewTransitionError(ErrTrancheAlreadyDisbursed, fmt.Sprintf("initial tranche %q already disbursed", p.Funding.InitialTrancheID))
	}
	if p.Status != StatusFundingQueued || p.Funding == nil {
		return nil, NewTransitionError(ErrInvalidTransition, fmt.Sprintf("proposal %q in state %s cannot authorize funding", propID, p.Status))
	}
	// Count active, unexpired stewards in StewardSigners (revoked/expired cosigners do not count).
	activeSigners := map[string]bool{}
	for _, sid := range p.Funding.StewardSigners {
		sa, exists := m.state.Actors[sid]
		if exists && sa.Active && (sa.EffectiveUntil == 0 || env.Timestamp <= sa.EffectiveUntil) {
			activeSigners[sid] = true
		}
	}
	if len(activeSigners) < m.state.Config.TreasuryQuorum {
		return nil, NewTransitionError(ErrQuorumNotMet, fmt.Sprintf("treasury steward quorum requires %d active signers, have %d", m.state.Config.TreasuryQuorum, len(activeSigners)))
	}
	if env.Timestamp < p.Funding.TimelockReadyAt {
		return nil, NewTransitionError(ErrTimelockNotElapsed, fmt.Sprintf("timelock ready at %d, current timestamp %d", p.Funding.TimelockReadyAt, env.Timestamp))
	}
	if err := m.checkTreasuryCapLocked(p.Funding.Amount, env.Timestamp); err != nil {
		return nil, err
	}

	epochKey := strconv.FormatInt(env.Timestamp/m.state.Config.EpochDurationSeconds, 10)
	return func() {
		m.state.Treasury.Balance -= p.Funding.Amount
		m.state.Treasury.EscrowedTotal += p.Funding.HoldbackTranche
		m.state.Treasury.TotalDisbursed += p.Funding.InitialTranche
		m.state.Treasury.EpochSpent[epochKey] += p.Funding.Amount
		m.state.Treasury.DisbursedTranches[p.Funding.InitialTrancheID] = true
		p.Funding.InitialDisbursed = true
		p.Funding.AuthorizedAt = env.Timestamp
		p.Status = StatusFundingAuthorized
	}, nil
}

func (m *Machine) prepareBoardVetoRecorded(actor *Actor, env Envelope) (func(), error) {
	if !actor.HasRole(RoleBoardGuardian) {
		return nil, NewTransitionError(ErrUnauthorizedRole, "requires BOARD_GUARDIAN role")
	}
	propID, err := reqString(env.Payload, "proposal_id")
	if err != nil {
		return nil, err
	}
	p, ok := m.state.Proposals[propID]
	if !ok {
		return nil, NewTransitionError(ErrProposalNotFound, propID)
	}
	if p.Status != StatusFundingQueued {
		return nil, NewTransitionError(ErrInvalidTransition, "board veto is narrowly restricted to FUNDING_QUEUED state (ZIP-0017 Theorem 8.2)")
	}
	just, err := reqString(env.Payload, "justification")
	if err != nil || strings.TrimSpace(just) == "" {
		return nil, NewTransitionError(ErrInvalidPayload, "board veto requires non-empty legal/mission justification")
	}

	return func() {
		p.Veto = &BoardVetoRecord{
			GuardianID:    actor.ID,
			Timestamp:     env.Timestamp,
			Justification: just,
		}
		p.Status = StatusVetoed
	}, nil
}

func (m *Machine) prepareIndependentAcceptance(actor *Actor, env Envelope) (func(), error) {
	if !actor.HasRole(RoleIndependentVerifier) {
		return nil, NewTransitionError(ErrUnauthorizedRole, "requires INDEPENDENT_VERIFIER role")
	}
	if m.isPausedLocked(env.Timestamp) {
		return nil, NewTransitionError(ErrSystemPaused, "acceptance holdback release blocked during active emergency pause")
	}
	propID, err := reqString(env.Payload, "proposal_id")
	if err != nil {
		return nil, err
	}
	p, ok := m.state.Proposals[propID]
	if !ok {
		return nil, NewTransitionError(ErrProposalNotFound, propID)
	}
	if p.Acceptance != nil || (p.Funding != nil && (p.Funding.HoldbackDisbursed || m.state.Treasury.DisbursedTranches[p.Funding.HoldbackTrancheID])) {
		return nil, NewTransitionError(ErrTrancheAlreadyDisbursed, fmt.Sprintf("holdback tranche for %q already settled", propID))
	}
	if p.Status != StatusFundingAuthorized || p.Funding == nil {
		return nil, NewTransitionError(ErrInvalidTransition, fmt.Sprintf("proposal %q in state %s cannot record independent acceptance", propID, p.Status))
	}
	// Strict independence: verifier cannot be proposer, peer reviewer, or milestone approver.
	if actor.ID == p.ProposerID {
		return nil, NewTransitionError(ErrVerifierNotIndependent, "proposer cannot independently accept own proposal")
	}
	for _, r := range p.Reviews {
		if r.ReviewerID == actor.ID {
			return nil, NewTransitionError(ErrVerifierNotIndependent, "peer reviewer cannot act as independent final verifier")
		}
	}
	for _, ma := range p.MilestoneApprovals {
		if ma.ApproverID == actor.ID {
			return nil, NewTransitionError(ErrVerifierNotIndependent, "milestone approver cannot act as independent final verifier")
		}
	}
	if hasCOI(actor, m.state.Actors[p.ProposerID], p.DeclaredCOIActors) {
		return nil, NewTransitionError(ErrCOIConflict, "independent verifier has COI with proposer")
	}

	boundEv, err := reqHash(env.Payload, "bound_evidence_hash")
	if err != nil {
		return nil, err
	}
	if boundEv != p.MilestoneEvidenceHash {
		return nil, NewTransitionError(ErrEvidenceMismatch, "bound_evidence_hash does not match approved milestone_evidence_hash")
	}
	reproHash, err := reqHash(env.Payload, "repro_check_hash")
	if err != nil {
		return nil, err
	}
	if reproHash == p.PlanHash || reproHash == p.MilestoneEvidenceHash {
		return nil, NewTransitionError(ErrEvidenceMismatch, "repro_check_hash must be a distinct independent verification artifact")
	}
	verdict, err := reqString(env.Payload, "verdict")
	if err != nil || (verdict != "ACCEPTED" && verdict != "FAILED_REPRO") {
		return nil, NewTransitionError(ErrInvalidPayload, "verdict must be ACCEPTED or FAILED_REPRO")
	}

	return func() {
		p.Acceptance = &AcceptanceRecord{
			VerifierID:        actor.ID,
			Timestamp:         env.Timestamp,
			BoundEvidenceHash: boundEv,
			ReproCheckHash:    reproHash,
			Verdict:           verdict,
		}
		if verdict == "ACCEPTED" {
			m.state.Treasury.EscrowedTotal -= p.Funding.HoldbackTranche
			m.state.Treasury.TotalDisbursed += p.Funding.HoldbackTranche
			m.state.Treasury.DisbursedTranches[p.Funding.HoldbackTrancheID] = true
			p.Funding.HoldbackDisbursed = true
			p.Status = StatusAccepted
		} else {
			m.state.Treasury.EscrowedTotal -= p.Funding.HoldbackTranche
			m.state.Treasury.Balance += p.Funding.HoldbackTranche
			p.Funding.HoldbackClawedBack = true
			p.Status = StatusAcceptanceFailed
		}
	}, nil
}

func (m *Machine) prepareEmergencyPauseSigned(actor *Actor, env Envelope) (func(), error) {
	if !actor.HasRole(RoleEmergencyCouncil) {
		return nil, NewTransitionError(ErrUnauthorizedRole, "requires EMERGENCY_COUNCIL role")
	}
	actionID, err := reqString(env.Payload, "action_id")
	if err != nil {
		return nil, err
	}
	reason, err := reqString(env.Payload, "reason")
	if err != nil || strings.TrimSpace(reason) == "" {
		return nil, NewTransitionError(ErrInvalidPayload, "emergency pause requires non-empty reason")
	}
	dur, err := reqInt64(env.Payload, "duration_seconds")
	if err != nil || dur <= 0 || dur > m.state.Config.MaxEmergencyDurationSec {
		return nil, NewTransitionError(ErrInvalidPayload, fmt.Sprintf("duration_seconds must be in (0, %d] (ZIP-0027 72h cap)", m.state.Config.MaxEmergencyDurationSec))
	}
	existing := m.state.EmergencyPause.PendingPauses[actionID]
	for _, s := range existing {
		if s == actor.ID {
			return nil, NewTransitionError(ErrDuplicateApproval, fmt.Sprintf("council member %q already signed pause %q", actor.ID, actionID))
		}
	}
	if prevDur, ok := m.state.EmergencyPause.PendingDurs[actionID]; ok && prevDur != dur {
		return nil, NewTransitionError(ErrInvalidPayload, "duration_seconds mismatch for pending pause action")
	}

	return func() {
		signers := append([]string{}, m.state.EmergencyPause.PendingPauses[actionID]...)
		signers = append(signers, actor.ID)
		sort.Strings(signers)
		m.state.EmergencyPause.PendingPauses[actionID] = signers
		m.state.EmergencyPause.PendingReasons[actionID] = reason
		m.state.EmergencyPause.PendingDurs[actionID] = dur
		if len(signers) >= m.state.Config.EmergencyPauseQuorum {
			m.state.EmergencyPause.Active = true
			m.state.EmergencyPause.ActionID = actionID
			m.state.EmergencyPause.Reason = reason
			m.state.EmergencyPause.ActivatedAt = env.Timestamp
			m.state.EmergencyPause.ExpiresAt = env.Timestamp + dur
			m.state.EmergencyPause.Signers = sortedStringsCopy(signers)
		}
	}, nil
}

func (m *Machine) prepareEmergencyPauseLifted(actor *Actor, env Envelope) (func(), error) {
	if !actor.HasRole(RoleEmergencyCouncil) && !actor.HasRole(RoleMetaGovernor) {
		return nil, NewTransitionError(ErrUnauthorizedRole, "requires EMERGENCY_COUNCIL or META_GOVERNOR role")
	}
	if !m.isPausedLocked(env.Timestamp) {
		return nil, NewTransitionError(ErrInvalidTransition, "no active emergency pause to lift")
	}
	actionID, err := reqString(env.Payload, "action_id")
	if err != nil {
		return nil, err
	}
	if actionID != m.state.EmergencyPause.ActionID {
		return nil, NewTransitionError(ErrInvalidPayload, "action_id does not match active emergency pause")
	}
	reviewHash, err := reqHash(env.Payload, "post_review_hash")
	if err != nil {
		return nil, err
	}
	for _, s := range m.state.EmergencyPause.PendingLifts[actionID] {
		if s == actor.ID {
			return nil, NewTransitionError(ErrDuplicateApproval, "actor already signed lift for this emergency")
		}
	}

	return func() {
		lifts := append([]string{}, m.state.EmergencyPause.PendingLifts[actionID]...)
		lifts = append(lifts, actor.ID)
		sort.Strings(lifts)
		m.state.EmergencyPause.PendingLifts[actionID] = lifts
		if len(lifts) >= m.state.Config.EmergencyPauseQuorum {
			m.state.EmergencyPause.Active = false
			m.state.EmergencyPause.LastReviewHash = reviewHash
		}
	}, nil
}

func (m *Machine) prepareGovernanceRuleAmended(actor *Actor, env Envelope) (func(), error) {
	if !actor.HasRole(RoleMetaGovernor) {
		return nil, NewTransitionError(ErrUnauthorizedRole, "requires META_GOVERNOR role")
	}
	changeID, err := reqString(env.Payload, "change_id")
	if err != nil {
		return nil, err
	}
	param, err := reqString(env.Payload, "parameter")
	if err != nil {
		return nil, err
	}
	newVal, err := reqInt64(env.Payload, "new_value")
	if err != nil {
		return nil, err
	}
	if err := validateRuleParameter(param, newVal); err != nil {
		return nil, err
	}
	if existing, ok := m.state.PendingRuleChanges[changeID]; ok {
		if existing.Executed {
			return nil, NewTransitionError(ErrInvalidTransition, "rule change already executed")
		}
		if existing.Parameter != param || existing.NewValue != newVal {
			return nil, NewTransitionError(ErrInvalidPayload, "rule change parameter/value mismatch")
		}
		for _, s := range existing.Signers {
			if s == actor.ID {
				return nil, NewTransitionError(ErrDuplicateApproval, "meta-governor already signed rule change")
			}
		}
	}

	return func() {
		rc, ok := m.state.PendingRuleChanges[changeID]
		if !ok {
			rc = &PendingRuleChange{
				ChangeID:   changeID,
				Parameter:  param,
				NewValue:   newVal,
				Signers:    []string{},
				ProposedAt: env.Timestamp,
			}
			m.state.PendingRuleChanges[changeID] = rc
		}
		rc.Signers = append(rc.Signers, actor.ID)
		sort.Strings(rc.Signers)
		if len(rc.Signers) >= m.state.Config.MetaGovernanceQuorum {
			applyRuleParameter(&m.state.Config, param, newVal)
			rc.Executed = true
			rc.ExecutedAt = env.Timestamp
		}
	}, nil
}

func (m *Machine) prepareActorRevoked(actor *Actor, env Envelope) (func(), error) {
	if !actor.HasRole(RoleEmergencyCouncil) && !actor.HasRole(RoleMetaGovernor) {
		return nil, NewTransitionError(ErrUnauthorizedRole, "requires EMERGENCY_COUNCIL or META_GOVERNOR role")
	}
	targetID, err := reqString(env.Payload, "target_actor_id")
	if err != nil {
		return nil, err
	}
	reason, err := reqString(env.Payload, "reason")
	if err != nil || strings.TrimSpace(reason) == "" {
		return nil, NewTransitionError(ErrInvalidPayload, "revocation requires non-empty reason")
	}
	target, ok := m.state.Actors[targetID]
	if !ok {
		return nil, NewTransitionError(ErrUnknownActor, targetID)
	}
	if !target.Active {
		return nil, NewTransitionError(ErrActorRevoked, "target actor already revoked")
	}

	return func() {
		target.Active = false
		target.RevokedAt = env.Timestamp
	}, nil
}

func (m *Machine) checkTreasuryCapLocked(amount int64, ts int64) error {
	if amount > m.state.Treasury.Balance {
		return NewTransitionError(ErrBudgetCapExceeded, fmt.Sprintf("requested %d exceeds available treasury balance %d", amount, m.state.Treasury.Balance))
	}
	epochKey := strconv.FormatInt(ts/m.state.Config.EpochDurationSeconds, 10)
	epochCap := (m.state.Treasury.Balance * m.state.Config.EpochSpendCapBps) / 10000
	if m.state.Treasury.EpochSpent[epochKey]+amount > epochCap {
		return NewTransitionError(ErrBudgetCapExceeded, fmt.Sprintf("epoch spend %d + %d exceeds epoch cap %d", m.state.Treasury.EpochSpent[epochKey], amount, epochCap))
	}
	return nil
}

func validateGenesis(g Genesis) error {
	if g.ChainID == "" {
		return NewTransitionError(ErrInvalidPayload, "genesis chain_id required")
	}
	if g.InitialTreasuryBalance <= 0 {
		return NewTransitionError(ErrInvalidPayload, "initial_treasury_balance must be positive")
	}
	c := g.Config
	if c.MinPeerReviews < 1 || c.MinReviewScoreBps < 0 || c.MinReviewScoreBps > 10000 ||
		c.MilestoneQuorum < 1 || c.TreasuryQuorum < 1 || c.EmergencyPauseQuorum < 1 ||
		c.MetaGovernanceQuorum < 1 || c.TimelockSeconds < 0 || c.EpochDurationSeconds <= 0 ||
		c.EpochSpendCapBps <= 0 || c.EpochSpendCapBps > 10000 ||
		c.MaxEmergencyDurationSec <= 0 || c.MaxEmergencyDurationSec > MaxEmergencyDurationSeconds ||
		c.HoldbackBps < 0 || c.HoldbackBps > 5000 {
		return NewTransitionError(ErrInvalidPayload, "invalid genesis governance config")
	}
	seen := map[string]bool{}
	for _, a := range g.Actors {
		if a.ID == "" || seen[a.ID] {
			return NewTransitionError(ErrInvalidPayload, fmt.Sprintf("invalid or duplicate actor id %q", a.ID))
		}
		seen[a.ID] = true
		if len(a.PubKeyHex) != 64 {
			return NewTransitionError(ErrInvalidPayload, fmt.Sprintf("invalid pubkey_hex for actor %q", a.ID))
		}
		if a.Kind != ActorKindHuman && a.Kind != ActorKindAIAgent {
			return NewTransitionError(ErrInvalidPayload, fmt.Sprintf("invalid actor kind %q", a.Kind))
		}
		if a.Kind == ActorKindAIAgent {
			for _, r := range a.Roles {
				if r != RoleAIAdvisor {
					return NewTransitionError(ErrAIGovernanceForbidden, fmt.Sprintf("AI_AGENT %q cannot hold authority role %s", a.ID, r))
				}
			}
		}
	}
	return nil
}

func validateRuleParameter(param string, val int64) error {
	switch param {
	case "min_peer_reviews", "milestone_quorum", "treasury_quorum", "emergency_pause_quorum", "meta_governance_quorum":
		if val < 1 || val > 21 {
			return NewTransitionError(ErrInvalidPayload, "quorum parameter out of safe range [1, 21]")
		}
	case "min_review_score_bps":
		if val < 1000 || val > 10000 {
			return NewTransitionError(ErrInvalidPayload, "min_review_score_bps out of range [1000, 10000]")
		}
	case "timelock_seconds":
		if val < 0 || val > 30*24*3600 {
			return NewTransitionError(ErrInvalidPayload, "timelock_seconds out of range")
		}
	case "epoch_spend_cap_bps":
		if val < 100 || val > 5000 {
			return NewTransitionError(ErrInvalidPayload, "epoch_spend_cap_bps out of safe range [100, 5000]")
		}
	case "holdback_bps":
		if val < 0 || val > 5000 {
			return NewTransitionError(ErrInvalidPayload, "holdback_bps out of safe range [0, 5000]")
		}
	default:
		return NewTransitionError(ErrInvalidPayload, fmt.Sprintf("unknown rule parameter %q", param))
	}
	return nil
}

func applyRuleParameter(c *GovernanceConfig, param string, val int64) {
	switch param {
	case "min_peer_reviews":
		c.MinPeerReviews = int(val)
	case "min_review_score_bps":
		c.MinReviewScoreBps = val
	case "milestone_quorum":
		c.MilestoneQuorum = int(val)
	case "treasury_quorum":
		c.TreasuryQuorum = int(val)
	case "emergency_pause_quorum":
		c.EmergencyPauseQuorum = int(val)
	case "meta_governance_quorum":
		c.MetaGovernanceQuorum = int(val)
	case "timelock_seconds":
		c.TimelockSeconds = val
	case "epoch_spend_cap_bps":
		c.EpochSpendCapBps = val
	case "holdback_bps":
		c.HoldbackBps = val
	}
}

func isValidCategory(cat ProposalCategory) bool {
	switch cat {
	case CategoryConservationResearch, CategoryOpenSourceDev, CategoryCitizenScience, CategoryEducation, CategoryEmergencyConservation:
		return true
	default:
		return false
	}
}

func hasCOI(actor *Actor, proposer *Actor, declaredCOI []string) bool {
	for _, cid := range declaredCOI {
		if cid == actor.ID {
			return true
		}
	}
	if proposer == nil {
		return false
	}
	for _, aAff := range actor.Affiliations {
		for _, pAff := range proposer.Affiliations {
			if aAff != "" && strings.EqualFold(aAff, pAff) {
				return true
			}
		}
	}
	return false
}

func reqString(m map[string]any, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", NewTransitionError(ErrInvalidPayload, fmt.Sprintf("missing field %q", key))
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", NewTransitionError(ErrInvalidPayload, fmt.Sprintf("field %q must be non-empty string", key))
	}
	return s, nil
}

func reqHash(m map[string]any, key string) (string, error) {
	s, err := reqString(m, key)
	if err != nil {
		return "", err
	}
	if !IsValidSHA256Hex(s) {
		return "", NewTransitionError(ErrInvalidPayload, fmt.Sprintf("field %q must be 64-char lowercase hex sha256", key))
	}
	return s, nil
}

func reqBool(m map[string]any, key string) (bool, error) {
	v, ok := m[key]
	if !ok {
		return false, NewTransitionError(ErrInvalidPayload, fmt.Sprintf("missing field %q", key))
	}
	b, ok := v.(bool)
	if !ok {
		return false, NewTransitionError(ErrInvalidPayload, fmt.Sprintf("field %q must be bool", key))
	}
	return b, nil
}

func reqInt64(m map[string]any, key string) (int64, error) {
	v, ok := m[key]
	if !ok {
		return 0, NewTransitionError(ErrInvalidPayload, fmt.Sprintf("missing field %q", key))
	}
	switch n := v.(type) {
	case int:
		return int64(n), nil
	case int64:
		return n, nil
	case uint64:
		return int64(n), nil
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, NewTransitionError(ErrInvalidPayload, fmt.Sprintf("field %q must be integer", key))
		}
		return i, nil
	case float64:
		if float64(int64(n)) != n {
			return 0, NewTransitionError(ErrInvalidPayload, fmt.Sprintf("field %q must be integer", key))
		}
		return int64(n), nil
	default:
		return 0, NewTransitionError(ErrInvalidPayload, fmt.Sprintf("field %q must be integer", key))
	}
}

func optStringSlice(m map[string]any, key string) ([]string, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return []string{}, nil
	}
	switch s := v.(type) {
	case []string:
		return sortedStringsCopy(s), nil
	case []any:
		out := make([]string, len(s))
		for i, item := range s {
			str, ok := item.(string)
			if !ok {
				return nil, NewTransitionError(ErrInvalidPayload, fmt.Sprintf("field %q must be string array", key))
			}
			out[i] = str
		}
		sort.Strings(out)
		return out, nil
	default:
		return nil, NewTransitionError(ErrInvalidPayload, fmt.Sprintf("field %q must be string array", key))
	}
}

func cloneActor(a *Actor) *Actor {
	roles := make([]Role, len(a.Roles))
	copy(roles, a.Roles)
	affs := make([]string, len(a.Affiliations))
	copy(affs, a.Affiliations)
	return &Actor{
		ID:             a.ID,
		PubKeyHex:      a.PubKeyHex,
		Kind:           a.Kind,
		Roles:          roles,
		Affiliations:   affs,
		Reputation:     a.Reputation,
		Active:         a.Active,
		EffectiveUntil: a.EffectiveUntil,
		RevokedAt:      a.RevokedAt,
		LastNonce:      a.LastNonce,
	}
}

func deepCopyState(st *State) State {
	raw, _ := json.Marshal(st)
	var cp State
	_ = json.Unmarshal(raw, &cp)
	if cp.Treasury.EpochSpent == nil {
		cp.Treasury.EpochSpent = map[string]int64{}
	}
	if cp.Treasury.DisbursedTranches == nil {
		cp.Treasury.DisbursedTranches = map[string]bool{}
	}
	if cp.EmergencyPause.PendingPauses == nil {
		cp.EmergencyPause.PendingPauses = map[string][]string{}
	}
	if cp.EmergencyPause.PendingReasons == nil {
		cp.EmergencyPause.PendingReasons = map[string]string{}
	}
	if cp.EmergencyPause.PendingDurs == nil {
		cp.EmergencyPause.PendingDurs = map[string]int64{}
	}
	if cp.EmergencyPause.PendingLifts == nil {
		cp.EmergencyPause.PendingLifts = map[string][]string{}
	}
	if cp.Actors == nil {
		cp.Actors = map[string]*Actor{}
	}
	if cp.Proposals == nil {
		cp.Proposals = map[string]*Proposal{}
	}
	if cp.PendingRuleChanges == nil {
		cp.PendingRuleChanges = map[string]*PendingRuleChange{}
	}
	return cp
}

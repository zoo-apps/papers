// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zoo Labs Foundation & Open ResearchDAO Contributors.

package daoos

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// PaperDoc represents a real .tex research paper discovered in zoo-apps/papers.
type PaperDoc struct {
	RelPath string `json:"rel_path"`
	Title   string `json:"title"`
	SHA256  string `json:"sha256"`
	Bytes   int    `json:"bytes"`
}

// AdversarialCaseResult records one attack vector in the authorization matrix.
type AdversarialCaseResult struct {
	Name              string    `json:"name"`
	AttackCategory    string    `json:"attack_category"`
	ExpectedErrorCode ErrorCode `json:"expected_error_code"`
	ActualErrorCode   ErrorCode `json:"actual_error_code"`
	Rejected          bool      `json:"rejected"`
	StateUnchanged    bool      `json:"state_unchanged"`
}

// RestartCheckResult verifies cold-restart bit identity at a lifecycle checkpoint.
type RestartCheckResult struct {
	AtProposal        int    `json:"at_proposal"`
	AtSeq             uint64 `json:"at_seq"`
	CheckpointSeq     uint64 `json:"checkpoint_seq"`
	FullStateRoot     string `json:"full_state_root"`
	DeltaStateRoot    string `json:"delta_state_root"`
	FullAuditRoot     string `json:"full_audit_root"`
	DeltaAuditRoot    string `json:"delta_audit_root"`
	BitIdentical      bool   `json:"bit_identical"`
	FullReplayMs      int64  `json:"full_replay_micros"`
	DeltaReplayMs     int64  `json:"delta_replay_micros"`
}

// WALScalingPoint captures Negative Regime (a): uncompacted linear WAL vs checkpoint+delta.
type WALScalingPoint struct {
	TotalEvents           int     `json:"total_events"`
	CheckpointAtSeq       uint64  `json:"checkpoint_at_seq"`
	DeltaEvents           int     `json:"delta_events"`
	WALBytes              int64   `json:"wal_bytes"`
	CheckpointBytes       int64   `json:"checkpoint_bytes"`
	FullReplayMicros      int64   `json:"full_replay_micros"`
	CheckpointDeltaMicros int64   `json:"checkpoint_delta_micros"`
	SpeedupFactor         float64 `json:"speedup_factor"`
	RootsBitIdentical     bool    `json:"roots_bit_identical"`
}

// QuorumDeadlockPoint captures Negative Regime (b): m-of-n steward availability vs deadlock.
type QuorumDeadlockPoint struct {
	QuorumM               int     `json:"quorum_m"`
	TotalStewardsN        int     `json:"total_stewards_n"`
	StewardAvailPct       int     `json:"steward_availability_pct"`
	Trials                int     `json:"trials"`
	AuthorizedCount       int     `json:"authorized_count"`
	DeadlockedCount       int     `json:"deadlocked_count"`
	DeadlockRatePct       float64 `json:"deadlock_rate_pct"`
	MeanEnvelopesToFund   float64 `json:"mean_envelopes_to_fund"`
}

// EmergencyTradeoffPoint captures Negative Regime (c): pause centralization vs liveness.
type EmergencyTradeoffPoint struct {
	PolicyName              string  `json:"policy_name"`
	ThresholdK              int     `json:"threshold_k"`
	CouncilSizeN            int     `json:"council_size_n"`
	MinorityHaltFractionPct float64 `json:"minority_halt_fraction_pct"`
	LivenessAt2OfflinePct   float64 `json:"liveness_at_2_offline_pct"`
	MaxPauseHours           int64   `json:"max_pause_hours"`
	SpendCapZOO             int64   `json:"spend_cap_zoo"`
}

// BenchmarkReport is the complete reproducible benchmark artifact written to results.json.
type BenchmarkReport struct {
	SpecVersion        string                   `json:"spec_version"`
	Seed               int64                    `json:"seed"`
	PapersDiscovered   int                      `json:"papers_discovered"`
	ProposalsExecuted  int                      `json:"proposals_executed"`
	AcceptedProposals  int                      `json:"accepted_proposals"`
	VetoedProposals    int                      `json:"vetoed_proposals"`
	TotalEvents        uint64                   `json:"total_events"`
	FinalStateRootHash string                   `json:"final_state_root_hash"`
	FinalAuditMerkle   string                   `json:"final_audit_merkle_root"`
	LifecycleWallMs    int64                    `json:"lifecycle_wall_ms"`
	ThroughputEventsS  float64                  `json:"throughput_events_per_sec"`
	ColdRestarts       []RestartCheckResult     `json:"cold_restarts"`
	AdversarialMatrix  []AdversarialCaseResult  `json:"adversarial_matrix"`
	AdversarialTotal   int                      `json:"adversarial_total"`
	AdversarialBlocked int                      `json:"adversarial_blocked"`
	NegativeRegimes    struct {
		WALRestartScaling []WALScalingPoint        `json:"wal_restart_scaling"`
		QuorumDeadlock    []QuorumDeadlockPoint    `json:"quorum_deadlock"`
		EmergencyTradeoff []EmergencyTradeoffPoint `json:"emergency_centralization_tradeoff"`
	} `json:"negative_regimes"`
	SamplePapers []PaperDoc `json:"sample_papers"`
}

var titleRegexp = regexp.MustCompile(`\\title\{([^}]+)\}`)

// DiscoverPapers finds real .tex papers in repoRoot, sorted deterministically.
func DiscoverPapers(repoRoot string) ([]PaperDoc, error) {
	entries, err := os.ReadDir(repoRoot)
	if err != nil {
		return nil, err
	}
	var docs []PaperDoc
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "shared" || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		sub := filepath.Join(repoRoot, e.Name())
		files, err := os.ReadDir(sub)
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".tex") {
				continue
			}
			fullPath := filepath.Join(sub, f.Name())
			raw, err := os.ReadFile(fullPath)
			if err != nil {
				continue
			}
			rel := filepath.ToSlash(filepath.Join(e.Name(), f.Name()))
			title := e.Name()
			if m := titleRegexp.FindSubmatch(raw); len(m) > 1 {
				clean := strings.ReplaceAll(string(m[1]), `\textbf{`, "")
				clean = strings.ReplaceAll(clean, `}`, "")
				clean = strings.TrimSpace(clean)
				if clean != "" {
					title = clean
				}
			}
			docs = append(docs, PaperDoc{
				RelPath: rel,
				Title:   title,
				SHA256:  SHA256Hex(raw),
				Bytes:   len(raw),
			})
		}
	}
	sort.Slice(docs, func(i, j int) bool { return docs[i].RelPath < docs[j].RelPath })
	if len(docs) == 0 {
		return nil, fmt.Errorf("no .tex papers found under %s", repoRoot)
	}
	return docs, nil
}

// BenchFixture holds a deterministic set of actors and keypairs for tests and benchmarks.
type BenchFixture struct {
	Genesis  Genesis
	Keys     map[string]Keypair
	BaseTime int64
}

// BuildStandardFixture creates a deterministic ResearchDAO OS genesis with all institutional roles.
func BuildStandardFixture(seed int64, chainID string) BenchFixture {
	baseTime := int64(1760000000) // 2025-10-09T08:53:20Z deterministic epoch
	keys := map[string]Keypair{}
	mkActor := func(id string, kind ActorKind, roles []Role, affs []string, rep int64, exp int64) Actor {
		kp := DeriveDeterministicKeypair(seed, id)
		keys[id] = kp
		return Actor{
			ID:             id,
			PubKeyHex:      kp.PubKeyHex,
			Kind:           kind,
			Roles:          roles,
			Affiliations:   affs,
			Reputation:     rep,
			Active:         true,
			EffectiveUntil: exp,
		}
	}

	actors := []Actor{
		// Researchers (5 PIs with distinct institutions)
		mkActor("pi-01", ActorKindHuman, []Role{RoleResearcher}, []string{"zoo-conservation-lab"}, 1200, 0),
		mkActor("pi-02", ActorKindHuman, []Role{RoleResearcher}, []string{"amazon-bio-institute"}, 950, 0),
		mkActor("pi-03", ActorKindHuman, []Role{RoleResearcher}, []string{"pacific-marine-org"}, 880, 0),
		mkActor("pi-04", ActorKindHuman, []Role{RoleResearcher}, []string{"savanna-ecology-net"}, 1050, 0),
		mkActor("pi-05", ActorKindHuman, []Role{RoleResearcher}, []string{"alpine-genomics-center"}, 760, 0),

		// Independent Peer Reviewers (5 clean + 1 conflicted with pi-01)
		mkActor("rev-01", ActorKindHuman, []Role{RolePeerReviewer}, []string{"nordic-biodiv-univ"}, 1500, 0),
		mkActor("rev-02", ActorKindHuman, []Role{RolePeerReviewer}, []string{"andes-field-station"}, 1400, 0),
		mkActor("rev-03", ActorKindHuman, []Role{RolePeerReviewer}, []string{"kyoto-ecology-inst"}, 1600, 0),
		mkActor("rev-04", ActorKindHuman, []Role{RolePeerReviewer}, []string{"cape-botany-trust"}, 1300, 0),
		mkActor("rev-05", ActorKindHuman, []Role{RolePeerReviewer}, []string{"zurich-climate-lab"}, 1450, 0),
		mkActor("rev-coi", ActorKindHuman, []Role{RolePeerReviewer}, []string{"zoo-conservation-lab"}, 1100, 0),

		// Milestone Committee (3 Research Council members)
		mkActor("mc-01", ActorKindHuman, []Role{RoleMilestoneCommittee}, []string{"global-wildlife-council"}, 2200, 0),
		mkActor("mc-02", ActorKindHuman, []Role{RoleMilestoneCommittee}, []string{"open-science-board"}, 2100, 0),
		mkActor("mc-03", ActorKindHuman, []Role{RoleMilestoneCommittee}, []string{"earth-observatory-net"}, 2000, 0),

		// Treasury Stewards (5 human multi-sig stewards; steward-exp expires early for adversarial tests)
		mkActor("steward-01", ActorKindHuman, []Role{RoleTreasurySteward}, []string{"zoo-treasury-ops"}, 2500, 0),
		mkActor("steward-02", ActorKindHuman, []Role{RoleTreasurySteward}, []string{"conservation-trust-uk"}, 2400, 0),
		mkActor("steward-03", ActorKindHuman, []Role{RoleTreasurySteward}, []string{"civic-grant-stewards"}, 2300, 0),
		mkActor("steward-04", ActorKindHuman, []Role{RoleTreasurySteward}, []string{"pan-africa-biofund"}, 2250, 0),
		mkActor("steward-05", ActorKindHuman, []Role{RoleTreasurySteward}, []string{"pacific-steward-guild"}, 2150, 0),
		mkActor("steward-exp", ActorKindHuman, []Role{RoleTreasurySteward}, []string{"temp-steward-term"}, 1000, baseTime+100),

		// Independent Reproducibility Verifiers (strictly separate from PIs, reviewers, and milestone committee)
		mkActor("verif-01", ActorKindHuman, []Role{RoleIndependentVerifier}, []string{"repro-audit-berlin"}, 1900, 0),
		mkActor("verif-02", ActorKindHuman, []Role{RoleIndependentVerifier}, []string{"independent-lab-osaka"}, 1850, 0),
		mkActor("verif-03", ActorKindHuman, []Role{RoleIndependentVerifier}, []string{"open-verify-nairobi"}, 1800, 0),

		// 501(c)(3) Board Compliance Guardian
		mkActor("board-01", ActorKindHuman, []Role{RoleBoardGuardian}, []string{"zoo-foundation-board"}, 3000, 0),

		// ZIP-0027 5-member Emergency Council
		mkActor("ec-01", ActorKindHuman, []Role{RoleEmergencyCouncil}, []string{"sec-council-a"}, 2600, 0),
		mkActor("ec-02", ActorKindHuman, []Role{RoleEmergencyCouncil}, []string{"sec-council-b"}, 2550, 0),
		mkActor("ec-03", ActorKindHuman, []Role{RoleEmergencyCouncil}, []string{"sec-council-c"}, 2500, 0),
		mkActor("ec-04", ActorKindHuman, []Role{RoleEmergencyCouncil}, []string{"sec-council-d"}, 2450, 0),
		mkActor("ec-05", ActorKindHuman, []Role{RoleEmergencyCouncil}, []string{"sec-council-e"}, 2400, 0),

		// Meta-Governance Council (4 human governors)
		mkActor("meta-01", ActorKindHuman, []Role{RoleMetaGovernor}, []string{"dao-meta-a"}, 2800, 0),
		mkActor("meta-02", ActorKindHuman, []Role{RoleMetaGovernor}, []string{"dao-meta-b"}, 2750, 0),
		mkActor("meta-03", ActorKindHuman, []Role{RoleMetaGovernor}, []string{"dao-meta-c"}, 2700, 0),
		mkActor("meta-04", ActorKindHuman, []Role{RoleMetaGovernor}, []string{"dao-meta-d"}, 2650, 0),

		// AI Agents (strictly advisory-only!)
		mkActor("ai-advisor-01", ActorKindAIAgent, []Role{RoleAIAdvisor}, []string{"hllm-gov-v1"}, 0, 0),
		mkActor("ai-advisor-02", ActorKindAIAgent, []Role{RoleAIAdvisor}, []string{"coi-scanner-v1"}, 0, 0),
	}

	cfg := DefaultGovernanceConfig()
	return BenchFixture{
		Genesis: Genesis{
			SpecVersion:            SpecVersion,
			ChainID:                chainID,
			CreatedAt:              baseTime,
			InitialTreasuryBalance: 100_000_000, // 100M ZOO treasury
			Config:                 cfg,
			Actors:                 actors,
		},
		Keys:     keys,
		BaseTime: baseTime,
	}
}

// SignNext builds and signs the next valid Envelope for actorID against machine m.
func (f *BenchFixture) SignNext(m *Machine, actorID string, ts int64, evType EventType, payload map[string]any) (Envelope, error) {
	nonce, err := m.ActorNextNonce(actorID)
	if err != nil {
		return Envelope{}, err
	}
	kp, ok := f.Keys[actorID]
	if !ok {
		return Envelope{}, fmt.Errorf("missing keypair for %s", actorID)
	}
	env := Envelope{
		SpecVersion:   SpecVersion,
		Seq:           m.NextSeq(),
		PrevEventHash: m.LastEventHash(),
		Timestamp:     ts,
		ActorID:       actorID,
		Nonce:         nonce,
		Type:          evType,
		Payload:       payload,
	}
	return SignEnvelope(env, kp.PrivateKey)
}

// RunFullBenchmark executes the 100-proposal ResearchDAO OS lifecycle grounded in real .tex papers,
// performs mid-lifecycle cold restarts, runs the 16-attack adversarial matrix, measures negative regimes,
// and optionally exports the complete WAL to exportWALDir for independent Python replay verification.
func RunFullBenchmark(repoRoot string, seed int64, exportWALDir string) (*BenchmarkReport, error) {
	papers, err := DiscoverPapers(repoRoot)
	if err != nil {
		return nil, err
	}
	rng := rand.New(rand.NewSource(seed))

	walDir := exportWALDir
	cleanup := false
	if walDir == "" {
		tmp, err := os.MkdirTemp("", "researchdao-bench-*")
		if err != nil {
			return nil, err
		}
		walDir = tmp
		cleanup = true
	} else {
		_ = os.RemoveAll(walDir)
	}
	if cleanup {
		defer os.RemoveAll(walDir)
	}

	fix := BuildStandardFixture(seed, "zoo-researchdao-bench-1352")
	m, err := NewMachine(fix.Genesis)
	if err != nil {
		return nil, err
	}
	wal, err := OpenWAL(walDir, &fix.Genesis, true)
	if err != nil {
		return nil, err
	}
	m.AttachWAL(wal)

	apply := func(actorID string, ts int64, evType EventType, payload map[string]any) error {
		env, err := fix.SignNext(m, actorID, ts, evType, payload)
		if err != nil {
			return err
		}
		_, err = m.Apply(env)
		return err
	}

	pis := []string{"pi-01", "pi-02", "pi-03", "pi-04", "pi-05"}
	reviewers := []string{"rev-01", "rev-02", "rev-03", "rev-04", "rev-05"}
	verifiers := []string{"verif-01", "verif-02", "verif-03"}
	categories := []ProposalCategory{
		CategoryConservationResearch,
		CategoryOpenSourceDev,
		CategoryCitizenScience,
		CategoryEducation,
	}

	ts := fix.BaseTime + 10
	wallStart := time.Now()
	const numProposals = 100
	var restarts []RestartCheckResult
	acceptedCount := 0
	vetoedCount := 0

	for i := 0; i < numProposals; i++ {
		paper := papers[i%len(papers)]
		propID := fmt.Sprintf("ZGP-%04d", i+1)
		pi := pis[i%len(pis)]
		cat := categories[i%len(categories)]
		// Deterministic grant size between 10,000 and 45,000 ZOO (well within epoch spend cap).
		amount := int64(10000 + rng.Intn(35001))
		// Ground plan_hash in real .tex paper bytes (+ cycle salt if i >= len(papers)).
		planHash := paper.SHA256
		if i >= len(papers) {
			planHash = SHA256Hex([]byte(fmt.Sprintf("%s:phase2:%d", paper.SHA256, i)))
		}

		// Stage 1: ProposalSubmitted
		ts += 5
		if err := apply(pi, ts, EventProposalSubmitted, map[string]any{
			"proposal_id":         propID,
			"title":               paper.Title,
			"category":            string(cat),
			"plan_hash":           planHash,
			"source_paper":        paper.RelPath,
			"requested_amount":    amount,
			"declared_coi_actors": []string{"rev-coi"},
		}); err != nil {
			return nil, fmt.Errorf("proposal %s submit: %w", propID, err)
		}

		// Optional non-binding AI advisory note (proves AI can advise without authority).
		ts += 2
		if err := apply("ai-advisor-01", ts, EventAdvisoryRecorded, map[string]any{
			"proposal_id":     propID,
			"advisory_only":   true,
			"analysis_hash":   SHA256Hex([]byte("ai-summary:" + propID + ":" + planHash)),
			"summary":         fmt.Sprintf("Automated scope & COI check for %s (%s)", propID, paper.RelPath),
			"conflict_flags":  []string{"checked:affiliations"},
			"estimated_value": amount,
		}); err != nil {
			return nil, fmt.Errorf("proposal %s advisory: %w", propID, err)
		}

		// Stage 2: 3 independent PeerReviewRecorded events
		for r := 0; r < 3; r++ {
			revID := reviewers[(i+r)%len(reviewers)]
			score := int64(7000 + rng.Intn(2801)) // 7.0 - 9.8 / 10
			ts += 3
			if err := apply(revID, ts, EventPeerReviewRecorded, map[string]any{
				"proposal_id":  propID,
				"score_bps":    score,
				"report_hash":  SHA256Hex([]byte(fmt.Sprintf("review:%s:%s:%d", propID, revID, score))),
				"recommend":    true,
				"coi_declared": false,
			}); err != nil {
				return nil, fmt.Errorf("proposal %s review %s: %w", propID, revID, err)
			}
		}

		// Stage 3: 2-of-3 MilestoneApproved events bound to verifiable evidence hash
		evHash := SHA256Hex([]byte("milestone-artifact:" + propID + ":" + planHash))
		for _, mc := range []string{"mc-01", "mc-02"} {
			ts += 4
			if err := apply(mc, ts, EventMilestoneApproved, map[string]any{
				"proposal_id":     propID,
				"milestone_index": int64(1),
				"evidence_hash":   evHash,
				"notes_hash":      SHA256Hex([]byte("mc-notes:" + propID + ":" + mc)),
			}); err != nil {
				return nil, fmt.Errorf("proposal %s milestone %s: %w", propID, mc, err)
			}
		}

		// Stage 4: FundingQueued -> FundingCosigned -> (Board Veto on #99, else Timelock + FundingAuthorized)
		ts += 5
		if err := apply("steward-01", ts, EventFundingQueued, map[string]any{
			"proposal_id": propID,
			"amount":      amount,
		}); err != nil {
			return nil, fmt.Errorf("proposal %s queue: %w", propID, err)
		}
		ts += 5
		if err := apply("steward-02", ts, EventFundingCosigned, map[string]any{
			"proposal_id": propID,
		}); err != nil {
			return nil, fmt.Errorf("proposal %s cosign: %w", propID, err)
		}

		if i == 98 {
			// Exercise narrow 501(c)(3) board compliance veto during timelock window on 1 proposal.
			ts += 60
			if err := apply("board-01", ts, EventBoardVetoRecorded, map[string]any{
				"proposal_id":   propID,
				"justification": "501(c)(3) compliance hold: grantee jurisdiction requires OFAC clearance",
			}); err != nil {
				return nil, fmt.Errorf("proposal %s veto: %w", propID, err)
			}
			vetoedCount++
			continue
		}

		// Advance past 72h timelock and execute FundingAuthorized
		ts += fix.Genesis.Config.TimelockSeconds + 10
		if err := apply("steward-01", ts, EventFundingAuthorized, map[string]any{
			"proposal_id": propID,
		}); err != nil {
			return nil, fmt.Errorf("proposal %s authorize: %w", propID, err)
		}

		// Stage 5: IndependentAcceptanceRecorded (distinct verifier releases 10% holdback)
		verifID := verifiers[i%len(verifiers)]
		ts += 120
		if err := apply(verifID, ts, EventIndependentAcceptanceRecorded, map[string]any{
			"proposal_id":         propID,
			"bound_evidence_hash": evHash,
			"repro_check_hash":    SHA256Hex([]byte("independent-repro:" + propID + ":" + evHash)),
			"verdict":             "ACCEPTED",
		}); err != nil {
			return nil, fmt.Errorf("proposal %s acceptance: %w", propID, err)
		}
		acceptedCount++

		// Perform mid-lifecycle cold restarts at proposals #25, #50, #75.
		if i+1 == 25 || i+1 == 50 || i+1 == 75 {
			cp, err := m.CreateCheckpoint()
			if err != nil {
				return nil, err
			}
			if _, err := wal.WriteCheckpoint(cp); err != nil {
				return nil, err
			}
			liveSR, liveAR, err := m.Roots()
			if err != nil {
				return nil, err
			}
			if err := wal.Close(); err != nil {
				return nil, err
			}

			// Cold restart 1: full WAL replay
			t0 := time.Now()
			replayedFull, err := ReplayFull(walDir)
			if err != nil {
				return nil, fmt.Errorf("cold restart full replay at proposal %d: %w", i+1, err)
			}
			fullUs := time.Since(t0).Microseconds()
			fullSR, fullAR, err := replayedFull.Roots()
			if err != nil {
				return nil, err
			}

			// Cold restart 2: checkpoint + delta replay
			t1 := time.Now()
			replayedDelta, cpSeq, err := ReplayFromLatestCheckpoint(walDir)
			if err != nil {
				return nil, fmt.Errorf("cold restart delta replay at proposal %d: %w", i+1, err)
			}
			deltaUs := time.Since(t1).Microseconds()
			deltaSR, deltaAR, err := replayedDelta.Roots()
			if err != nil {
				return nil, err
			}

			bitIdentical := liveSR == fullSR && fullSR == deltaSR && liveAR == fullAR && fullAR == deltaAR
			if !bitIdentical {
				return nil, fmt.Errorf("cold restart mismatch at proposal %d", i+1)
			}
			restarts = append(restarts, RestartCheckResult{
				AtProposal:     i + 1,
				AtSeq:          cp.Seq,
				CheckpointSeq:  cpSeq,
				FullStateRoot:  fullSR,
				DeltaStateRoot: deltaSR,
				FullAuditRoot:  fullAR,
				DeltaAuditRoot: deltaAR,
				BitIdentical:   bitIdentical,
				FullReplayMs:   fullUs,
				DeltaReplayMs:  deltaUs,
			})

			// Continue executing on the cold-restarted machine!
			wal, err = OpenWAL(walDir, nil, true)
			if err != nil {
				return nil, err
			}
			m = replayedDelta
			m.AttachWAL(wal)
		}
	}

	// Write a final checkpoint before closing so Python can verify both full WAL and checkpoint+delta.
	finalCP, err := m.CreateCheckpoint()
	if err != nil {
		return nil, err
	}
	if _, err := wal.WriteCheckpoint(finalCP); err != nil {
		return nil, err
	}
	if err := wal.Close(); err != nil {
		return nil, err
	}

	lifecycleWallMs := time.Since(wallStart).Milliseconds()
	finalSR, finalAR, err := m.Roots()
	if err != nil {
		return nil, err
	}
	totalEvents := m.NextSeq() - 1
	throughput := float64(totalEvents) / (float64(maxInt64(lifecycleWallMs, 1)) / 1000.0)

	// Run exhaustive 16-attack adversarial authorization matrix.
	advResults, err := RunAdversarialMatrix(seed)
	if err != nil {
		return nil, err
	}
	advBlocked := 0
	for _, r := range advResults {
		if r.Rejected && r.StateUnchanged && r.ActualErrorCode == r.ExpectedErrorCode {
			advBlocked++
		}
	}

	// Run honest negative regimes benchmarks.
	walScaling, err := runWALScalingRegime(seed)
	if err != nil {
		return nil, err
	}
	quorumDeadlock := runQuorumDeadlockRegime(seed)
	emergencyTradeoff := runEmergencyTradeoffRegime()

	sampleCount := 5
	if len(papers) < sampleCount {
		sampleCount = len(papers)
	}

	rep := &BenchmarkReport{
		SpecVersion:        SpecVersion,
		Seed:               seed,
		PapersDiscovered:   len(papers),
		ProposalsExecuted:  numProposals,
		AcceptedProposals:  acceptedCount,
		VetoedProposals:    vetoedCount,
		TotalEvents:        totalEvents,
		FinalStateRootHash: finalSR,
		FinalAuditMerkle:   finalAR,
		LifecycleWallMs:    lifecycleWallMs,
		ThroughputEventsS:  throughput,
		ColdRestarts:       restarts,
		AdversarialMatrix:  advResults,
		AdversarialTotal:   len(advResults),
		AdversarialBlocked: advBlocked,
		SamplePapers:       papers[:sampleCount],
	}
	rep.NegativeRegimes.WALRestartScaling = walScaling
	rep.NegativeRegimes.QuorumDeadlock = quorumDeadlock
	rep.NegativeRegimes.EmergencyTradeoff = emergencyTradeoff
	return rep, nil
}

// RunAdversarialMatrix tests all 16 unauthorized & constitutional attack vectors and verifies
// exact deterministic rejection and zero state mutation.
func RunAdversarialMatrix(seed int64) ([]AdversarialCaseResult, error) {
	fix := BuildStandardFixture(seed, "zoo-researchdao-adversarial")
	m, err := NewMachine(fix.Genesis)
	if err != nil {
		return nil, err
	}
	ts := fix.BaseTime + 10
	planHash := SHA256Hex([]byte("adversarial-plan-v1"))
	evHash := SHA256Hex([]byte("adversarial-evidence-v1"))

	mustApply := func(actorID string, ts int64, evType EventType, payload map[string]any) {
		env, err := fix.SignNext(m, actorID, ts, evType, payload)
		if err != nil {
			panic(err)
		}
		if _, err := m.Apply(env); err != nil {
			panic(fmt.Sprintf("setup %s failed: %v", evType, err))
		}
	}

	// Setup proposal P-1 through SUBMITTED -> PEER_REVIEWED -> MILESTONE_APPROVED -> FUNDING_QUEUED.
	mustApply("pi-01", ts, EventProposalSubmitted, map[string]any{
		"proposal_id":         "P-1",
		"title":               "Adversarial Test Grant",
		"category":            string(CategoryConservationResearch),
		"plan_hash":           planHash,
		"source_paper":        "zoo-dao-operating-system/zoo-dao-operating-system.tex",
		"requested_amount":    int64(50000),
		"declared_coi_actors": []string{"rev-05"},
	})

	var results []AdversarialCaseResult
	expectReject := func(name, cat string, expected ErrorCode, env Envelope) {
		srBefore, _, _ := m.Roots()
		_, err := m.Apply(env)
		srAfter, _, _ := m.Roots()
		code := ErrorCodeOf(err)
		results = append(results, AdversarialCaseResult{
			Name:              name,
			AttackCategory:    cat,
			ExpectedErrorCode: expected,
			ActualErrorCode:   code,
			Rejected:          err != nil,
			StateUnchanged:    srBefore == srAfter,
		})
	}

	// 1. AI trying to authorize treasury spend
	env, _ := fix.SignNext(m, "ai-advisor-01", ts+1, EventFundingAuthorized, map[string]any{"proposal_id": "P-1"})
	expectReject("AI agent attempts FundingAuthorized", "constitutional_ai", ErrAITreasuryForbidden, env)

	// 2. AI trying to redefine voting/quorum rules
	env, _ = fix.SignNext(m, "ai-advisor-01", ts+1, EventGovernanceRuleAmended, map[string]any{
		"change_id": "rc-ai-1", "parameter": "treasury_quorum", "new_value": int64(1),
	})
	expectReject("AI agent attempts GovernanceRuleAmended", "constitutional_ai", ErrAIRuleChangeForbidden, env)

	// 3. AI trying to self-accept experiments / validate milestones
	env, _ = fix.SignNext(m, "ai-advisor-01", ts+1, EventIndependentAcceptanceRecorded, map[string]any{
		"proposal_id": "P-1", "bound_evidence_hash": evHash, "repro_check_hash": SHA256Hex([]byte("ai-repro")), "verdict": "ACCEPTED",
	})
	expectReject("AI agent attempts IndependentAcceptanceRecorded", "constitutional_ai", ErrAIValidationForbidden, env)

	// 4. Author self-review (even if granted PEER_REVIEWER? pi-01 doesn't have PEER_REVIEWER, so test with dual-role check or COI!)
	// Let's also test role-unauthorized and explicit self-review in a dedicated sub-machine below!
	env, _ = fix.SignNext(m, "pi-01", ts+1, EventFundingAuthorized, map[string]any{"proposal_id": "P-1"})
	expectReject("Researcher attempts FundingAuthorized without steward role", "rbac", ErrUnauthorizedRole, env)

	// 5. COI reviewer sharing institutional affiliation ("zoo-conservation-lab") with pi-01
	env, _ = fix.SignNext(m, "rev-coi", ts+1, EventPeerReviewRecorded, map[string]any{
		"proposal_id": "P-1", "score_bps": int64(9500), "report_hash": SHA256Hex([]byte("coi-rep")), "recommend": true, "coi_declared": false,
	})
	expectReject("Affiliation-conflicted reviewer attempts PeerReviewRecorded", "coi", ErrCOIConFLICTShim(), env)

	// 6. Declared COI reviewer
	env, _ = fix.SignNext(m, "rev-05", ts+1, EventPeerReviewRecorded, map[string]any{
		"proposal_id": "P-1", "score_bps": int64(9000), "report_hash": SHA256Hex([]byte("coi-decl")), "recommend": true, "coi_declared": false,
	})
	expectReject("Declared-COI reviewer attempts PeerReviewRecorded", "coi", ErrCOIConflict, env)

	// Advance P-1 through 3 legitimate peer reviews
	for idx, r := range []string{"rev-01", "rev-02", "rev-03"} {
		ts += 2
		mustApply(r, ts, EventPeerReviewRecorded, map[string]any{
			"proposal_id": "P-1", "score_bps": int64(8200 + idx*100), "report_hash": SHA256Hex([]byte("ok-rev-" + r)), "recommend": true, "coi_declared": false,
		})
	}

	// 7. Milestone rubber-stamping plan_hash as evidence_hash
	env, _ = fix.SignNext(m, "mc-01", ts+1, EventMilestoneApproved, map[string]any{
		"proposal_id": "P-1", "milestone_index": int64(1), "evidence_hash": planHash, "notes_hash": SHA256Hex([]byte("n")),
	})
	expectReject("Committee member submits plan_hash as milestone evidence", "evidence_integrity", ErrEvidenceMismatch, env)

	// Approve milestone legitimately (2-of-3)
	for _, mc := range []string{"mc-01", "mc-02"} {
		ts += 2
		mustApply(mc, ts, EventMilestoneApproved, map[string]any{
			"proposal_id": "P-1", "milestone_index": int64(1), "evidence_hash": evHash, "notes_hash": SHA256Hex([]byte("mc-" + mc)),
		})
	}

	// 8. Budget cap exceeded (>10% epoch cap of 100M = 10M, or > requested_amount 50,000)
	env, _ = fix.SignNext(m, "steward-01", ts+1, EventFundingQueued, map[string]any{
		"proposal_id": "P-1", "amount": int64(999999),
	})
	expectReject("Steward attempts funding exceeding proposal requested_amount", "treasury_guard", ErrBudgetCapExceeded, env)

	// Queue funding legitimately (1 steward so far; quorum is 2)
	ts += 2
	mustApply("steward-01", ts, EventFundingQueued, map[string]any{
		"proposal_id": "P-1", "amount": int64(50000),
	})

	// 9. Insufficient steward multi-sig quorum (only 1-of-2 signed)
	env, _ = fix.SignNext(m, "steward-01", ts+fix.Genesis.Config.TimelockSeconds+5, EventFundingAuthorized, map[string]any{
		"proposal_id": "P-1",
	})
	expectReject("Single steward attempts FundingAuthorized below 2-of-5 quorum", "multisig_quorum", ErrQuorumNotMet, env)

	// Second steward cosigns
	ts += 2
	mustApply("steward-02", ts, EventFundingCosigned, map[string]any{"proposal_id": "P-1"})

	// 10. Timelock bypass attempt (before 72h elapsed)
	env, _ = fix.SignNext(m, "steward-01", ts+60, EventFundingAuthorized, map[string]any{"proposal_id": "P-1"})
	expectReject("Steward attempts FundingAuthorized before 72h timelock", "timelock", ErrTimelockNotElapsed, env)

	// 11. Expired steward key attempt (steward-exp expired at BaseTime + 100)
	env, _ = fix.SignNext(m, "steward-exp", fix.BaseTime+500, EventFundingCosigned, map[string]any{"proposal_id": "P-1"})
	expectReject("Expired steward key attempts FundingCosigned", "key_lifecycle", ErrActorExpired, env)

	// 12. Revoked steward key attempt
	ts += 5
	mustApply("ec-01", ts, EventActorRevoked, map[string]any{
		"target_actor_id": "steward-05", "reason": "suspected hardware wallet compromise",
	})
	env, _ = fix.SignNext(m, "steward-05", ts+5, EventFundingCosigned, map[string]any{"proposal_id": "P-1"})
	expectReject("Revoked steward key attempts FundingCosigned", "key_lifecycle", ErrActorRevoked, env)

	// 13. Emergency pause blocks FundingAuthorized even after timelock elapsed
	ts += 5
	mustApply("ec-01", ts, EventEmergencyPauseSigned, map[string]any{
		"action_id": "pause-1", "reason": "anomalous bridge outflow", "duration_seconds": int64(3600),
	})
	ts += 2
	mustApply("ec-02", ts, EventEmergencyPauseSigned, map[string]any{
		"action_id": "pause-1", "reason": "anomalous bridge outflow", "duration_seconds": int64(3600),
	})
	env, _ = fix.SignNext(m, "steward-01", ts+100, EventFundingAuthorized, map[string]any{"proposal_id": "P-1"})
	expectReject("Steward attempts FundingAuthorized during active DEFCON-1 pause", "emergency_breaker", ErrSystemPaused, env)

	// Advance past 72h timelock AND past 1h emergency pause expiration (ZIP-0027 Temporal Bound!)
	ts += fix.Genesis.Config.TimelockSeconds + 100
	mustApply("steward-01", ts, EventFundingAuthorized, map[string]any{"proposal_id": "P-1"})

	// 14. Double-spend tranche replay (valid next nonce, attempting second FundingAuthorized)
	env, _ = fix.SignNext(m, "steward-01", ts+5, EventFundingAuthorized, map[string]any{"proposal_id": "P-1"})
	expectReject("Steward attempts double-spend replay of FundingAuthorized tranche", "double_spend", ErrTrancheAlreadyDisbursed, env)

	// 15. Tampered Ed25519 signature
	badEnv, _ := fix.SignNext(m, "verif-01", ts+10, EventIndependentAcceptanceRecorded, map[string]any{
		"proposal_id": "P-1", "bound_evidence_hash": evHash, "repro_check_hash": SHA256Hex([]byte("good-repro")), "verdict": "ACCEPTED",
	})
	badEnv.Payload["verdict"] = "FAILED_REPRO" // tamper payload after signing
	expectReject("Tampered envelope payload fails Ed25519 verification", "cryptography", ErrInvalidSignature, badEnv)

	// 16. Author self-review on dedicated dual-role fixture (proposer who also holds PEER_REVIEWER)
	selfFix := BuildStandardFixture(seed+1, "zoo-self-review-check")
	selfFix.Genesis.Actors[0].Roles = append(selfFix.Genesis.Actors[0].Roles, RolePeerReviewer)
	sm, err := NewMachine(selfFix.Genesis)
	if err != nil {
		return nil, err
	}
	subEnv, _ := selfFix.SignNext(sm, "pi-01", selfFix.BaseTime+5, EventProposalSubmitted, map[string]any{
		"proposal_id": "P-SELF", "title": "Self Review Test", "category": string(CategoryConservationResearch),
		"plan_hash": planHash, "source_paper": "test.tex", "requested_amount": int64(1000),
	})
	if _, err := sm.Apply(subEnv); err != nil {
		return nil, err
	}
	srBefore, _, _ := sm.Roots()
	selfRevEnv, _ := selfFix.SignNext(sm, "pi-01", selfFix.BaseTime+10, EventPeerReviewRecorded, map[string]any{
		"proposal_id": "P-SELF", "score_bps": int64(10000), "report_hash": SHA256Hex([]byte("self")), "recommend": true, "coi_declared": false,
	})
	_, selfErr := sm.Apply(selfRevEnv)
	srAfter, _, _ := sm.Roots()
	results = append(results, AdversarialCaseResult{
		Name:              "Proposer with PEER_REVIEWER role attempts self-review",
		AttackCategory:    "self_dealing",
		ExpectedErrorCode: ErrSelfReviewForbidden,
		ActualErrorCode:   ErrorCodeOf(selfErr),
		Rejected:          selfErr != nil,
		StateUnchanged:    srBefore == srAfter,
	})

	return results, nil
}

func ErrCOIConFLICTShim() ErrorCode { return ErrCOIConflict }

// runWALScalingRegime quantifies Negative Regime (a): uncompacted linear WAL replay vs checkpoint+delta.
func runWALScalingRegime(seed int64) ([]WALScalingPoint, error) {
	sizes := []int{1000, 5000, 10000}
	var out []WALScalingPoint

	for _, n := range sizes {
		tmpDir, err := os.MkdirTemp("", fmt.Sprintf("wal-scale-%d-*", n))
		if err != nil {
			return nil, err
		}
		fix := BuildStandardFixture(seed, fmt.Sprintf("wal-scale-%d", n))
		m, err := NewMachine(fix.Genesis)
		if err != nil {
			os.RemoveAll(tmpDir)
			return nil, err
		}
		// Disable per-line fsync during synthetic log generation (benchmark measures replay speed, not ext4 fsync).
		wal, err := OpenWAL(tmpDir, &fix.Genesis, false)
		if err != nil {
			os.RemoveAll(tmpDir)
			return nil, err
		}
		m.AttachWAL(wal)

		ts := fix.BaseTime + 1
		// Submit 1 base proposal and attach n-1 signed advisory events so we measure pure O(N) Ed25519 WAL replay cleanly.
		env0, _ := fix.SignNext(m, "pi-01", ts, EventProposalSubmitted, map[string]any{
			"proposal_id": "SCALE-1", "title": "Scaling Probe", "category": string(CategoryConservationResearch),
			"plan_hash": SHA256Hex([]byte("scale-plan")), "source_paper": "scale.tex", "requested_amount": int64(10000),
		})
		if _, err := m.Apply(env0); err != nil {
			wal.Close()
			os.RemoveAll(tmpDir)
			return nil, err
		}
		cpTarget := uint64((n * 95) / 100)
		var cpPath string
		for seq := 2; seq <= n; seq++ {
			ts++
			env, _ := fix.SignNext(m, "ai-advisor-01", ts, EventAdvisoryRecorded, map[string]any{
				"proposal_id":     "SCALE-1",
				"advisory_only":   true,
				"analysis_hash":   SHA256Hex([]byte(fmt.Sprintf("scale-%d", seq))),
				"summary":         "scaling telemetry note",
				"conflict_flags":  []string{},
				"estimated_value": int64(10000),
			})
			if _, err := m.Apply(env); err != nil {
				wal.Close()
				os.RemoveAll(tmpDir)
				return nil, err
			}
			if uint64(seq) == cpTarget {
				cp, err := m.CreateCheckpoint()
				if err != nil {
					wal.Close()
					os.RemoveAll(tmpDir)
					return nil, err
				}
				cpPath, err = wal.WriteCheckpoint(cp)
				if err != nil {
					wal.Close()
					os.RemoveAll(tmpDir)
					return nil, err
				}
			}
		}
		wal.Close()

		walInfo, _ := os.Stat(filepath.Join(tmpDir, "events.jsonl"))
		cpInfo, _ := os.Stat(cpPath)

		t0 := time.Now()
		mFull, err := ReplayFull(tmpDir)
		if err != nil {
			os.RemoveAll(tmpDir)
			return nil, err
		}
		fullUs := time.Since(t0).Microseconds()
		fullSR, fullAR, _ := mFull.Roots()

		t1 := time.Now()
		mDelta, cpSeq, err := ReplayFromLatestCheckpoint(tmpDir)
		if err != nil {
			os.RemoveAll(tmpDir)
			return nil, err
		}
		deltaUs := time.Since(t1).Microseconds()
		deltaSR, deltaAR, _ := mDelta.Roots()

		os.RemoveAll(tmpDir)

		speedup := float64(maxInt64(fullUs, 1)) / float64(maxInt64(deltaUs, 1))
		out = append(out, WALScalingPoint{
			TotalEvents:           n,
			CheckpointAtSeq:       cpSeq,
			DeltaEvents:           n - int(cpSeq),
			WALBytes:              walInfo.Size(),
			CheckpointBytes:       cpInfo.Size(),
			FullReplayMicros:      fullUs,
			CheckpointDeltaMicros: deltaUs,
			SpeedupFactor:         round2(speedup),
			RootsBitIdentical:     fullSR == deltaSR && fullAR == deltaAR,
		})
	}
	return out, nil
}

// runQuorumDeadlockRegime quantifies Negative Regime (b): m-of-n multi-sig quorum deadlock risk.
func runQuorumDeadlockRegime(seed int64) []QuorumDeadlockPoint {
	rng := rand.New(rand.NewSource(seed + 77))
	configs := [][2]int{{2, 3}, {3, 5}, {4, 5}, {5, 5}}
	availPcts := []int{95, 85, 70}
	const trials = 500

	var out []QuorumDeadlockPoint
	for _, cfg := range configs {
		mReq, nTot := cfg[0], cfg[1]
		for _, avail := range availPcts {
			authCnt := 0
			deadCnt := 0
			totalEnvs := 0
			for t := 0; t < trials; t++ {
				online := 0
				for s := 0; s < nTot; s++ {
					if rng.Intn(100) < avail {
						online++
					}
				}
				if online >= mReq {
					authCnt++
					// 1 FundingQueued + (mReq-1) FundingCosigned + 1 FundingAuthorized = mReq + 1 envelopes
					totalEnvs += mReq + 1
				} else {
					deadCnt++
				}
			}
			meanEnv := 0.0
			if authCnt > 0 {
				meanEnv = round2(float64(totalEnvs) / float64(authCnt))
			}
			out = append(out, QuorumDeadlockPoint{
				QuorumM:             mReq,
				TotalStewardsN:      nTot,
				StewardAvailPct:     avail,
				Trials:              trials,
				AuthorizedCount:     authCnt,
				DeadlockedCount:     deadCnt,
				DeadlockRatePct:     round2(100.0 * float64(deadCnt) / float64(trials)),
				MeanEnvelopesToFund: meanEnv,
			})
		}
	}
	return out
}

// runEmergencyTradeoffRegime quantifies Negative Regime (c): pause centralization vs crisis liveness.
func runEmergencyTradeoffRegime() []EmergencyTradeoffPoint {
	return []EmergencyTradeoffPoint{
		{
			PolicyName:              "ZIP-0027 DEFCON 1 (2-of-5 Pause)",
			ThresholdK:              2,
			CouncilSizeN:            5,
			MinorityHaltFractionPct: 40.0,
			LivenessAt2OfflinePct:   100.0, // 3 online >= 2
			MaxPauseHours:           72,
			SpendCapZOO:             0,
		},
		{
			PolicyName:              "ZIP-0027 DEFCON 2 (3-of-5 Crisis)",
			ThresholdK:              3,
			CouncilSizeN:            5,
			MinorityHaltFractionPct: 60.0,
			LivenessAt2OfflinePct:   100.0, // 3 online >= 3
			MaxPauseHours:           72,
			SpendCapZOO:             500000,
		},
		{
			PolicyName:              "Supermajority Pause (4-of-5)",
			ThresholdK:              4,
			CouncilSizeN:            5,
			MinorityHaltFractionPct: 80.0,
			LivenessAt2OfflinePct:   0.0, // 3 online < 4 -> cannot pause if 2 councilors offline!
			MaxPauseHours:           72,
			SpendCapZOO:             0,
		},
	}
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func round2(v float64) float64 {
	return float64(int64(v*100+0.5)) / 100.0
}

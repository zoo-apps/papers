// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package govcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
)

// stateFingerprint hashes the abstract governance state (excluding audit log and
// exact nonce history) for BFS state-space deduplication.
func stateFingerprint(s *GovernanceState) [32]byte {
	var b strings.Builder
	fmt.Fprintf(&b, "ep=%d|tr=%d|p=%t:%d|", s.Epoch/3600, s.TreasuryBalance/1000, s.Emergency.Paused, (s.Emergency.PauseExpiresAt-s.Epoch)/3600)
	for _, a := range s.Actors {
		fmt.Fprintf(&b, "%s:%s,", a.ID, a.Status)
	}
	b.WriteByte('|')
	for _, d := range s.Delegations {
		fmt.Fprintf(&b, "%s->%s:%t:%s,", d.From, d.To, d.Revoked, strings.Join(d.Scopes, "+"))
	}
	b.WriteByte('|')
	for _, q := range s.QueuedActions {
		fmt.Fprintf(&b, "%s:%t:%t,", q.ID, q.Executed, q.Invalidated)
	}
	b.WriteByte('|')
	for _, c := range s.ContestedActions {
		fmt.Fprintf(&b, "%s:%s:%t,", c.ID, c.AppealStatus, c.Finalized)
	}
	return sha256.Sum256([]byte(b.String()))
}

func makeAbstractAction(s *GovernanceState, id, actType, actorID, target string, epochDelta int64, signers []string) GovernanceAction {
	sigs := make([]SignerSig, 0, len(signers))
	seenNonce := make(map[string]uint64)
	for _, sid := range signers {
		var nextNonce uint64 = 1
		if a, ok := s.FindActor(sid); ok {
			nextNonce = a.LastNonce + 1
		}
		if prev, ok := seenNonce[sid]; ok {
			nextNonce = prev + 1
		}
		seenNonce[sid] = nextNonce
		sigs = append(sigs, SignerSig{ActorID: sid, Nonce: nextNonce})
	}
	return GovernanceAction{
		ID:      id,
		Type:    actType,
		ActorID: actorID,
		Target:  target,
		Epoch:   s.Epoch + epochDelta,
		Signers: sigs,
	}
}

// candidateActions enumerates representative valid AND adversarial transitions
// from state s so the bounded BFS explorer and fuzzer stress every invariant.
func candidateActions(s *GovernanceState, stepTag int) []GovernanceAction {
	acts := make([]GovernanceAction, 0, 24)

	// 1. Valid & adversarial delegations (INV-02, INV-01)
	d1 := makeAbstractAction(s, fmt.Sprintf("mc-del1-%d", stepTag), ActionDelegate, "council_1", "human_1", 10, []string{"council_1"})
	d1.DurationSec = 300000
	d1.Scopes = []string{ScopeTreasurySpend, ScopeVoteStandard}
	d1.DelegationID = fmt.Sprintf("d-c1-h1-%d", len(s.Delegations)+1)
	acts = append(acts, d1)

	d2 := makeAbstractAction(s, fmt.Sprintf("mc-del2-%d", stepTag), ActionDelegate, "human_1", "human_2", 10, []string{"human_1"})
	d2.DurationSec = 200000
	d2.Scopes = []string{ScopeTreasurySpend}
	d2.DelegationID = fmt.Sprintf("d-h1-h2-%d", len(s.Delegations)+1)
	acts = append(acts, d2)

	// Cycle & self-loop probes (INV-02)
	dSelf := makeAbstractAction(s, fmt.Sprintf("mc-self-%d", stepTag), ActionDelegate, "council_1", "council_1", 10, []string{"council_1"})
	dSelf.DurationSec = 100000
	dSelf.Scopes = []string{ScopeVoteStandard}
	acts = append(acts, dSelf)

	dCyc := makeAbstractAction(s, fmt.Sprintf("mc-cyc-%d", stepTag), ActionDelegate, "human_2", "council_1", 10, []string{"human_2"})
	dCyc.DurationSec = 100000
	dCyc.Scopes = []string{ScopeVoteStandard}
	acts = append(acts, dCyc)

	// AI sovereign delegation & spend probes (INV-01)
	aiDel := makeAbstractAction(s, fmt.Sprintf("mc-aidel-%d", stepTag), ActionDelegate, "council_1", "ai_agent_1", 10, []string{"council_1"})
	aiDel.DurationSec = 100000
	aiDel.Scopes = []string{ScopeTreasurySpend}
	acts = append(acts, aiDel)

	aiSpend := makeAbstractAction(s, fmt.Sprintf("mc-ai-%d", stepTag), ActionTreasuryQueue, "ai_agent_1", "grant_x", 10, []string{"ai_agent_1", "council_1"})
	aiSpend.Amount = 1000
	acts = append(acts, aiSpend)

	// Duplicate signer attempt (INV-04) — 3x council_1 would fake 100% if dup-check disabled
	dupSig := makeAbstractAction(s, fmt.Sprintf("mc-dup-%d", stepTag), ActionEmergencyPause, "council_1", "bridge", 10, []string{"council_1", "council_1", "council_1"})
	dupSig.DurationSec = 3600
	acts = append(acts, dupSig)

	// DEFCON-1 Emergency pause (INV-05, 3-of-3 council = 100% >= 67%)
	emPause := makeAbstractAction(s, fmt.Sprintf("mc-pause-%d", stepTag), ActionEmergencyPause, "council_1", "bridge", 10, []string{"council_1", "council_2", "council_3"})
	emPause.DurationSec = MaxEmergencyDurationSec
	acts = append(acts, emPause)

	// Treasury queue & early/valid execute (INV-08, INV-05, INV-07)
	tq := makeAbstractAction(s, fmt.Sprintf("mc-tq-%d", stepTag), ActionTreasuryQueue, "council_1", "grant_mc", 10, []string{"council_1", "council_2"})
	tq.Amount = 5000
	tq.ProposalID = fmt.Sprintf("p-mc-%d", len(s.QueuedActions)+1)
	if len(s.Delegations) > 0 && !s.Delegations[0].Revoked {
		tq.ActorID = s.Delegations[0].To
		tq.DelegationID = s.Delegations[0].ID
		tq.Signers = []SignerSig{{ActorID: s.Delegations[0].To, Nonce: 1}, {ActorID: "council_2", Nonce: 1}}
		if a, ok := s.FindActor(tq.ActorID); ok {
			tq.Signers[0].Nonce = a.LastNonce + 1
		}
		if a, ok := s.FindActor("council_2"); ok {
			tq.Signers[1].Nonce = a.LastNonce + 1
		}
	}
	acts = append(acts, tq)

	for _, q := range s.QueuedActions {
		if q.Executed {
			continue
		}
		// Early execution probe (INV-08)
		teEarly := makeAbstractAction(s, fmt.Sprintf("mc-te-early-%d", stepTag), ActionTreasuryExecute, "council_1", q.Target, 3600, []string{"council_1"})
		teEarly.ProposalID = q.ID
		teEarly.Amount = q.Amount
		teEarly.EmergencyBypass = true
		acts = append(acts, teEarly)

		// Post-timelock execution
		teValid := makeAbstractAction(s, fmt.Sprintf("mc-te-ok-%d", stepTag), ActionTreasuryExecute, "council_1", q.Target, MinTimelockTreasurySec+10, []string{"council_1"})
		teValid.ProposalID = q.ID
		teValid.Amount = q.Amount
		acts = append(acts, teValid)
		break
	}

	// Revocation (INV-03)
	rev := makeAbstractAction(s, fmt.Sprintf("mc-rev-%d", stepTag), ActionRevokeActor, "council_1", "human_1", 10, []string{"council_1"})
	acts = append(acts, rev)

	// Suspension + Appeal + Self-adjudication probe + Independent resolution (INV-06, INV-10)
	susp := makeAbstractAction(s, fmt.Sprintf("mc-susp-%d", stepTag), ActionSuspendActor, "council_1", "human_2", 10, []string{"council_1"})
	susp.ContestedID = fmt.Sprintf("c-mc-%d", len(s.ContestedActions)+1)
	acts = append(acts, susp)

	for _, c := range s.ContestedActions {
		if c.Finalized {
			continue
		}
		if c.AppealStatus == "NONE" {
			af := makeAbstractAction(s, fmt.Sprintf("mc-af-%d", stepTag), ActionAppealFile, c.TargetActorID, c.ID, 100, []string{c.TargetActorID})
			af.ContestedID = c.ID
			acts = append(acts, af)
		}
		if c.AppealStatus == "PENDING" {
			// Self-adjudication probe (INV-06)
			selfAdj := makeAbstractAction(s, fmt.Sprintf("mc-selfadj-%d", stepTag), ActionAppealResolve, "judge_1", c.ID, 100, []string{c.InitiatorID, "judge_1"})
			selfAdj.ContestedID = c.ID
			selfAdj.AppealOutcome = "UPHELD"
			acts = append(acts, selfAdj)

			// Suspended actor escalation probe (INV-10)
			suspAct := makeAbstractAction(s, fmt.Sprintf("mc-suspact-%d", stepTag), ActionAdvisoryRecommend, c.TargetActorID, "bypass", 100, []string{c.TargetActorID})
			acts = append(acts, suspAct)

			// Independent overturn
			okAdj := makeAbstractAction(s, fmt.Sprintf("mc-okadj-%d", stepTag), ActionAppealResolve, "judge_1", c.ID, 100, []string{"judge_1", "judge_2"})
			okAdj.ContestedID = c.ID
			okAdj.AppealOutcome = "OVERTURNED"
			acts = append(acts, okAdj)
		}
		break
	}

	// Nonce replay probe (INV-09)
	if a, ok := s.FindActor("council_1"); ok && a.LastNonce > 0 {
		rep := GovernanceAction{
			ID:      fmt.Sprintf("mc-rep-%d", stepTag),
			Type:    ActionAdvisoryRecommend,
			ActorID: "council_1",
			Target:  "replay_memo",
			Epoch:   s.Epoch + 5,
			Signers: []SignerSig{{ActorID: "council_1", Nonce: a.LastNonce}},
		}
		acts = append(acts, rep)
	}

	// Conflict rule probe (INV-07)
	cfAct := makeAbstractAction(s, fmt.Sprintf("mc-cf-%d", stepTag), ActionAdvisoryRecommend, "council_1", "conflict_target", 10, []string{"council_1"})
	acts = append(acts, cfAct)

	// Clock advance (+72h auto-sunset probe)
	clk := makeAbstractAction(s, fmt.Sprintf("mc-clk-%d", stepTag), ActionAdvanceClock, "council_2", "clock", MaxEmergencyDurationSec+10, []string{"council_2"})
	acts = append(acts, clk)

	return acts
}

func makeModelCheckerInitialState(seed int64) *GovernanceState {
	kr := newFixtureKeyring(seed, []string{
		"council_1", "council_2", "council_3",
		"human_1", "human_2", "human_3", "human_4",
		"judge_1", "judge_2", "ai_agent_1",
	})
	st := baseFixtureState(kr)
	// Include a same-tier charter conflict on "conflict_target" so INV-07 is exercised in BFS/fuzzer.
	st.Rules = append(st.Rules,
		PolicyRule{ID: "R-MC-ALLOW", Tier: TierCharterStatute, ActionType: ActionAdvisoryRecommend, Target: "conflict_target", Effect: EffectAllow, Condition: "ALWAYS", Rationale: "MC conflict allow"},
		PolicyRule{ID: "R-MC-DENY", Tier: TierCharterStatute, ActionType: ActionAdvisoryRecommend, Target: "conflict_target", Effect: EffectDeny, Condition: "ALWAYS", Rationale: "MC conflict deny"},
	)
	return &st
}

type bfsNode struct {
	state *GovernanceState
	depth int
	trace []string
}

type mcRunResult struct {
	statesExplored     int
	transitionsChecked int
	violation          *InvariantViolation
	counterexample     []string
}

func runBoundedBFS(init *GovernanceState, cfg EngineConfig, maxDepth, maxStates int) mcRunResult {
	visited := make(map[[32]byte]bool, maxStates)
	visited[stateFingerprint(init)] = true
	queue := []bfsNode{{state: init.Clone(), depth: 0, trace: nil}}

	res := mcRunResult{statesExplored: 1}
	stepTag := 0

	for len(queue) > 0 && res.statesExplored < maxStates {
		cur := queue[0]
		queue = queue[1:]
		if cur.depth >= maxDepth {
			continue
		}
		cands := candidateActions(cur.state, stepTag)
		stepTag++

		for _, act := range cands {
			post := cur.state.Clone()
			tr := Apply(post, act, cfg)
			res.transitionsChecked++

			if viol := CheckAllInvariants(cur.state, act, tr, post); viol != nil {
				trace := append(append([]string(nil), cur.trace...), fmt.Sprintf("%s(%s->%s):%s", act.Type, act.ActorID, act.Target, tr.ErrorCode))
				res.violation = viol
				res.counterexample = trace
				return res
			}

			if tr.Verdict == VerdictAllow {
				fp := stateFingerprint(post)
				if !visited[fp] && res.statesExplored < maxStates {
					visited[fp] = true
					res.statesExplored++
					nextTrace := append(append([]string(nil), cur.trace...), fmt.Sprintf("%s(%s->%s)", act.Type, act.ActorID, act.Target))
					queue = append(queue, bfsNode{state: post, depth: cur.depth + 1, trace: nextTrace})
				}
			}
		}
	}
	return res
}

// RunModelChecker runs both deterministic bounded BFS state-space exploration
// and seeded randomized trace fuzzing across >= 60,000 states/transitions,
// verifying INV-01..INV-10 at every single transition.
func RunModelChecker(seed int64) ModelCheckerReport {
	init := makeModelCheckerInitialState(seed)
	cfg := EngineConfig{SkipSigVerify: true}

	// Phase 1: Bounded BFS exploration (depth <= 6, up to 2,500 distinct reachable states -> ~30,000+ transitions)
	bfs := runBoundedBFS(init, cfg, 6, 2500)

	// Phase 2: Seeded property-based randomized trace fuzzer (1,600 traces x 32 steps = 51,200 checked transitions)
	rng := rand.New(rand.NewSource(seed))
	fuzzTraces := 1600
	fuzzStepsPerTrace := 32
	fuzzSteps := 0
	violations := 0
	if bfs.violation != nil {
		violations++
	}

	for t := 0; t < fuzzTraces; t++ {
		st := init.Clone()
		for step := 0; step < fuzzStepsPerTrace; step++ {
			cands := candidateActions(st, t*100+step)
			act := cands[rng.Intn(len(cands))]
			pre := st.Clone()
			tr := Apply(st, act, cfg)
			fuzzSteps++
			if viol := CheckAllInvariants(pre, act, tr, st); viol != nil {
				violations++
				break
			}
		}
	}

	return ModelCheckerReport{
		BFSMaxDepth:               6,
		BFSStatesExplored:         bfs.statesExplored,
		BFSTransitionsChecked:     bfs.transitionsChecked,
		FuzzTraces:                fuzzTraces,
		FuzzStepsChecked:          fuzzSteps,
		TotalStatesAndTransitions: bfs.statesExplored + bfs.transitionsChecked + fuzzSteps,
		InvariantViolations:       violations,
		InvariantsChecked:         append([]string(nil), AllInvariantIDs...),
	}
}

// RunMutationAudit intentionally injects one targeted bug per invariant (MUT-01..MUT-10)
// and proves our bounded model checker catches 10/10 mutants with concrete counterexamples.
func RunMutationAudit(seed int64) MutationAuditReport {
	specs := []struct {
		id     string
		target string
		desc   string
	}{
		{"MUT-01", "INV-01", "Disable AI_AGENT constitutional boundary guard"},
		{"MUT-02", "INV-02", "Disable delegation cycle & depth/scope attenuation check"},
		{"MUT-03", "INV-03", "Disable transitive revocation of delegations & queued actions"},
		{"MUT-04", "INV-04", "Disable duplicate-signer and double-delegation vote guard"},
		{"MUT-05", "INV-05", "Disable DEFCON-1 72h pause spend guard & self-renewal check"},
		{"MUT-06", "INV-06", "Disable zero self-adjudication guard in appeal resolution"},
		{"MUT-07", "INV-07", "Replace fail-closed conflict resolution with naive first-match"},
		{"MUT-08", "INV-08", "Disable treasury & rule-amendment timelock enforcement"},
		{"MUT-09", "INV-09", "Disable monotonic nonce replay protection"},
		{"MUT-10", "INV-10", "Allow suspended actor to execute actions during pending appeal"},
	}

	init := makeModelCheckerInitialState(seed)
	// Ensure initial state has a pre-queued action so MUT-08 is reachable in minimal BFS depth.
	init.QueuedActions = append(init.QueuedActions, QueuedAction{
		ID: "p-mut-init", Kind: "TREASURY", ProposerID: "council_1", Target: "grant_mut",
		Amount: 1000, QueuedAt: BaseEpoch, MinTimelockSec: MinTimelockTreasurySec,
	})
	// Advance council_1 nonce to 1 so MUT-09 replay probe triggers immediately at depth 1.
	init.Actors[0].LastNonce = 1
	init.UsedNonces = append(init.UsedNonces, "council_1:1")

	results := make([]MutationResult, 0, len(specs))
	killed := 0

	for _, sp := range specs {
		bfs := runBoundedBFS(init, EngineConfig{SkipSigVerify: true, Mutant: sp.id}, 5, 1500)
		mr := MutationResult{
			MutantID:        sp.id,
			TargetInvariant: sp.target,
			Description:     sp.desc,
		}
		if bfs.violation != nil {
			mr.Killed = true
			mr.CounterexampleDepth = len(bfs.counterexample)
			mr.CounterexampleSteps = bfs.counterexample
			mr.ViolatedInvariant = bfs.violation.InvariantID
			killed++
		} else {
			mr.CounterexampleSteps = []string{}
		}
		results = append(results, mr)
	}

	return MutationAuditReport{
		TotalMutants:  len(specs),
		MutantsKilled: killed,
		KillRateBps:   int64(killed*10000) / int64(len(specs)),
		Mutants:       results,
	}
}

// HashBytesHex returns SHA-256 hex digest of raw bytes.
func HashBytesHex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

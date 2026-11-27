// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package govcheck

import (
	"fmt"
	"math/rand"
)

// RunNegativeRegimes executes the 3 explicit honest negative regimes documented
// in BENCHMARK.md and SPEC.md.
func RunNegativeRegimes(seed int64) NegativeRegimesReport {
	return NegativeRegimesReport{
		FirstMatchMasksRuleConflict: runNegFirstMatchMasksRuleConflict(seed),
		FailClosedLivenessDeadlock:  runNegFailClosedLivenessDeadlock(seed),
		BoundedMCDepthHorizon:       runNegBoundedMCDepthHorizon(),
	}
}

// Negative Regime 1: First-Match Precedence Bug vs Fail-Closed Conflict Detection.
// Evaluates 200 trials with conflicting same-tier CHARTER_STATUTE rules under
// randomized rule registration orderings. A naive first-match evaluator silently
// allows unauthorized spends whenever the ALLOW rule appears first (~50%),
// whereas INV-07 fail-closed conflict resolution blocks 100% and emits a ConflictWitness.
func runNegFirstMatchMasksRuleConflict(seed int64) NegFirstMatchReport {
	rng := rand.New(rand.NewSource(seed + 101))
	const trials = 200
	kr := newFixtureKeyring(seed, []string{"council_1", "council_2", "council_3", "human_1", "human_2", "human_3", "human_4", "judge_1", "judge_2", "ai_agent_1"})

	naiveAllows := 0
	failClosedBlocked := 0
	witnesses := 0

	for i := 0; i < trials; i++ {
		st := baseFixtureState(kr)
		allowRule := PolicyRule{
			ID:         fmt.Sprintf("R-CH-ALLOW-%03d", i),
			Tier:       TierCharterStatute,
			ActionType: ActionTreasuryExecute,
			Target:     "conflict_grant",
			Effect:     EffectAllow,
			Condition:  "ALWAYS",
			Rationale:  "Permissive charter clause",
		}
		denyRule := PolicyRule{
			ID:         fmt.Sprintf("R-CH-DENY-%03d", i),
			Tier:       TierCharterStatute,
			ActionType: ActionTreasuryExecute,
			Target:     "conflict_grant",
			Effect:     EffectDeny,
			Condition:  "ALWAYS",
			Rationale:  "Contradictory charter freeze clause",
		}
		if rng.Intn(2) == 0 {
			st.Rules = []PolicyRule{allowRule, denyRule}
		} else {
			st.Rules = []PolicyRule{denyRule, allowRule}
		}
		act := GovernanceAction{
			ID:      fmt.Sprintf("neg1-act-%03d", i),
			Type:    ActionTreasuryExecute,
			ActorID: "council_1",
			Target:  "conflict_grant",
			Epoch:   BaseEpoch + MinTimelockTreasurySec + 10,
			Amount:  50000,
		}
		naive := EvaluateNaiveFirstMatch(&st, act)
		if naive.Allowed {
			naiveAllows++
		}
		strict := EvaluatePolicyHierarchy(&st, act)
		if !strict.Allowed && strict.ErrorCode == CodeDenyRuleConflict {
			failClosedBlocked++
		}
		if strict.ConflictWitness != nil {
			witnesses++
		}
	}

	return NegFirstMatchReport{
		Trials:                     trials,
		NaiveFirstMatchUnsafeAllow: naiveAllows,
		NaiveUnsafeAllowBps:        int64(naiveAllows*10000) / trials,
		FailClosedBlocked:          failClosedBlocked,
		FailClosedBlockBps:         int64(failClosedBlocked*10000) / trials,
		ConflictWitnessesEmitted:   witnesses,
	}
}

// Negative Regime 2: Fail-Closed Liveness Deadlock Under Ambiguous Rules / Emergency Freeze.
// Demonstrates the honest safety-vs-liveness trade-off: when 100 urgent valid
// conservation-grant operations arrive during (a) an unresolved same-tier charter
// conflict or (b) an active 72h DEFCON-1 emergency freeze, constitutional fail-closed
// semantics preserve 100% safety (0 violations) at the cost of 0% execution liveness
// until human resolution or 72h mandatory auto-sunset.
func runNegFailClosedLivenessDeadlock(seed int64) NegLivenessDeadlockReport {
	const ops = 100
	kr := newFixtureKeyring(seed, []string{"council_1", "council_2", "council_3", "human_1", "human_2", "human_3", "human_4", "judge_1", "judge_2", "ai_agent_1"})

	// Regime 2a: unresolved charter conflict.
	stConflict := baseFixtureState(kr)
	stConflict.Rules = append(stConflict.Rules, PolicyRule{
		ID:         "R-CHARTER-FREEZE-DEADLOCK",
		Tier:       TierCharterStatute,
		ActionType: ActionTreasuryExecute,
		Target:     "urgent_habitat_grant",
		Effect:     EffectDeny,
		Condition:  "ALWAYS",
		Rationale:  "Ambiguous conflicting statute",
	})
	execConflict := 0
	safetyViolations := 0

	for i := 0; i < ops; i++ {
		pid := fmt.Sprintf("urgent-c-%d", i)
		stConflict.QueuedActions = append(stConflict.QueuedActions, QueuedAction{
			ID: pid, Kind: "TREASURY", ProposerID: "council_1", Target: "urgent_habitat_grant",
			Amount: 1000, QueuedAt: BaseEpoch, MinTimelockSec: MinTimelockTreasurySec,
		})
		act := makeAbstractAction(&stConflict, fmt.Sprintf("neg2a-%d", i), ActionTreasuryExecute, "council_1", "urgent_habitat_grant", MinTimelockTreasurySec+int64(i)+10, []string{"council_1"})
		act.ProposalID = pid
		act.Amount = 1000
		pre := stConflict.Clone()
		res := Apply(&stConflict, act, EngineConfig{SkipSigVerify: true})
		if CheckAllInvariants(pre, act, res, &stConflict) != nil {
			safetyViolations++
		}
		if res.Verdict == VerdictAllow {
			execConflict++
		}
	}

	// Regime 2b: active 72h DEFCON-1 freeze.
	stPaused := baseFixtureState(kr)
	stPaused.Emergency = EmergencyState{
		Paused:         true,
		PauseStartedAt: BaseEpoch,
		PauseExpiresAt: BaseEpoch + MaxEmergencyDurationSec,
		LastTriggerers: []string{"council_1", "council_2"},
	}
	execPaused := 0

	for i := 0; i < ops; i++ {
		pid := fmt.Sprintf("urgent-p-%d", i)
		stPaused.QueuedActions = append(stPaused.QueuedActions, QueuedAction{
			ID: pid, Kind: "TREASURY", ProposerID: "council_1", Target: "urgent_habitat_grant",
			Amount: 1000, QueuedAt: BaseEpoch - MinTimelockTreasurySec - 10, MinTimelockSec: MinTimelockTreasurySec,
		})
		// Arrives inside the 72h freeze window (offset 60s..6060s < 259200s).
		act := makeAbstractAction(&stPaused, fmt.Sprintf("neg2b-%d", i), ActionTreasuryExecute, "council_1", "urgent_habitat_grant", 60+int64(i)*60, []string{"council_1"})
		act.ProposalID = pid
		act.Amount = 1000
		pre := stPaused.Clone()
		res := Apply(&stPaused, act, EngineConfig{SkipSigVerify: true})
		if CheckAllInvariants(pre, act, res, &stPaused) != nil {
			safetyViolations++
		}
		if res.Verdict == VerdictAllow {
			execPaused++
		}
	}

	return NegLivenessDeadlockReport{
		UrgentValidOps:               ops,
		ExecutedUnderCharterConflict: execConflict,
		ExecutedUnderDefcon1Pause:    execPaused,
		LivenessUnderConflictBps:     int64(execConflict*10000) / ops,
		LivenessUnderPauseBps:        int64(execPaused*10000) / ops,
		SafetyViolations:             safetyViolations,
		AutoSunsetRecoverySec:        MaxEmergencyDurationSec,
	}
}

// Negative Regime 3: Bounded Model-Checking State-Space Horizon Limit.
// Constructs an explicit multi-step governance state machine with a planted
// depth-8 delegation + appeal + cooldown interaction vulnerability. Proves that
// shallow bounded model checking (max_depth = 2, 4, 6) reports 0 violations
// (horizon blind spot), while depth >= 8 discovers the 8-step counterexample —
// empirically grounding why unbounded safety proofs require Lean 4 / TLA+.
type horizonState struct {
	delegated      bool
	queued         bool
	suspended      bool
	appealFiled    bool
	appealOverturn bool
	pauseStarted   bool
	pauseExpired   bool
	cooldownReset  bool
	exploitReached bool
}

func horizonBFS(maxDepth int) DepthProbe {
	type node struct {
		st    horizonState
		depth int
		steps int
	}
	init := horizonState{}
	visited := map[horizonState]bool{init: true}
	queue := []node{{st: init, depth: 0, steps: 0}}
	explored := 1

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.st.exploitReached {
			return DepthProbe{
				MaxDepth:          maxDepth,
				StatesExplored:    explored,
				BugDetected:       true,
				CounterexampleLen: cur.steps,
			}
		}
		if cur.depth >= maxDepth {
			continue
		}

		// Branch across deterministic governance transitions + distractor actions.
		nexts := make([]horizonState, 0, 8)

		// Step 1: Delegate scope
		if !cur.st.delegated {
			n := cur.st
			n.delegated = true
			nexts = append(nexts, n)
		}
		// Step 2: Queue proposal via delegation
		if cur.st.delegated && !cur.st.queued {
			n := cur.st
			n.queued = true
			nexts = append(nexts, n)
		}
		// Step 3: Suspend delegator
		if cur.st.queued && !cur.st.suspended {
			n := cur.st
			n.suspended = true
			nexts = append(nexts, n)
		}
		// Step 4: File appeal
		if cur.st.suspended && !cur.st.appealFiled {
			n := cur.st
			n.appealFiled = true
			nexts = append(nexts, n)
		}
		// Step 5: Appeal overturned (restores actor)
		if cur.st.appealFiled && !cur.st.appealOverturn {
			n := cur.st
			n.appealOverturn = true
			nexts = append(nexts, n)
		}
		// Step 6: Trigger DEFCON-1 emergency pause
		if cur.st.appealOverturn && !cur.st.pauseStarted {
			n := cur.st
			n.pauseStarted = true
			nexts = append(nexts, n)
		}
		// Step 7: Advance clock past 72h auto-sunset (planted bug: mistakenly resets cooldown ONLY when appealOverturn && queued)
		if cur.st.pauseStarted && !cur.st.pauseExpired && cur.st.appealOverturn && cur.st.queued {
			n := cur.st
			n.pauseExpired = true
			n.cooldownReset = true
			nexts = append(nexts, n)
		}
		// Step 8: Exploit cooldown reset to self-renew pause without 24h cooldown!
		if cur.st.pauseExpired && cur.st.cooldownReset && !cur.st.exploitReached {
			n := cur.st
			n.exploitReached = true
			nexts = append(nexts, n)
		}
		// Add benign branching (independent toggles) so state space is realistic.
		if !cur.st.pauseStarted {
			n := cur.st
			n.pauseStarted = true
			nexts = append(nexts, n)
		}
		if cur.st.pauseStarted && !cur.st.pauseExpired {
			n := cur.st
			n.pauseExpired = true
			nexts = append(nexts, n)
		}

		for _, nxt := range nexts {
			if !visited[nxt] {
				visited[nxt] = true
				explored++
				queue = append(queue, node{st: nxt, depth: cur.depth + 1, steps: cur.steps + 1})
			}
		}
	}

	return DepthProbe{
		MaxDepth:          maxDepth,
		StatesExplored:    explored,
		BugDetected:       false,
		CounterexampleLen: 0,
	}
}

func runNegBoundedMCDepthHorizon() NegDepthHorizonReport {
	depths := []int{2, 4, 6, 8, 10}
	probes := make([]DepthProbe, 0, len(depths))
	for _, d := range depths {
		probes = append(probes, horizonBFS(d))
	}
	return NegDepthHorizonReport{
		PlantedBugMinDepth:     8,
		UnboundedProofRequired: true,
		DepthProbes:            probes,
	}
}

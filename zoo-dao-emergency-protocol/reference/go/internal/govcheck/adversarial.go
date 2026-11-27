// Copyright 2026 Zoo Labs Foundation.
// Licensed under the Apache License, Version 2.0.

package govcheck

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
)

const BaseEpoch int64 = 1700000000

type fixtureActors struct {
	keys map[string]ed25519.PrivateKey
	pubs map[string]string
}

func newFixtureKeyring(seed int64, ids []string) *fixtureActors {
	fa := &fixtureActors{
		keys: make(map[string]ed25519.PrivateKey, len(ids)),
		pubs: make(map[string]string, len(ids)),
	}
	for _, id := range ids {
		pub, priv := DeterministicKeyPair(seed, id)
		fa.keys[id] = priv
		fa.pubs[id] = hex.EncodeToString(pub)
	}
	return fa
}

func (fa *fixtureActors) sign(act GovernanceAction, signerNonces map[string]uint64, order []string) GovernanceAction {
	sigs := make([]SignerSig, 0, len(order))
	for _, id := range order {
		s, err := SignAction(act, id, signerNonces[id], fa.keys[id])
		if err != nil {
			panic(err)
		}
		sigs = append(sigs, s)
	}
	act.Signers = sigs
	return act
}

func baseFixtureState(kr *fixtureActors) GovernanceState {
	actors := []Actor{
		{
			ID:           "council_1",
			Role:         RoleCouncilMember,
			PubKeyHex:    kr.pubs["council_1"],
			VotingWeight: 20,
			Status:       StatusActive,
			BaseScopes:   []string{ScopeVoteStandard, ScopeTreasurySpend, ScopeRuleAmend, ScopeEmergencyPause, ScopeRevokeMember, ScopeExperimentValidate, ScopeAdvisoryRecommend},
		},
		{
			ID:           "council_2",
			Role:         RoleCouncilMember,
			PubKeyHex:    kr.pubs["council_2"],
			VotingWeight: 20,
			Status:       StatusActive,
			BaseScopes:   []string{ScopeVoteStandard, ScopeTreasurySpend, ScopeRuleAmend, ScopeEmergencyPause, ScopeRevokeMember, ScopeExperimentValidate, ScopeAdvisoryRecommend},
		},
		{
			ID:           "council_3",
			Role:         RoleCouncilMember,
			PubKeyHex:    kr.pubs["council_3"],
			VotingWeight: 20,
			Status:       StatusActive,
			BaseScopes:   []string{ScopeVoteStandard, ScopeTreasurySpend, ScopeRuleAmend, ScopeEmergencyPause, ScopeRevokeMember, ScopeExperimentValidate, ScopeAdvisoryRecommend},
		},
		{
			ID:           "human_1",
			Role:         RoleHumanMember,
			PubKeyHex:    kr.pubs["human_1"],
			VotingWeight: 10,
			Status:       StatusActive,
			BaseScopes:   []string{ScopeVoteStandard, ScopeTreasurySpend, ScopeAdvisoryRecommend},
		},
		{
			ID:           "human_2",
			Role:         RoleHumanMember,
			PubKeyHex:    kr.pubs["human_2"],
			VotingWeight: 10,
			Status:       StatusActive,
			BaseScopes:   []string{ScopeVoteStandard, ScopeAdvisoryRecommend},
		},
		{
			ID:           "human_3",
			Role:         RoleHumanMember,
			PubKeyHex:    kr.pubs["human_3"],
			VotingWeight: 5,
			Status:       StatusActive,
			BaseScopes:   []string{ScopeVoteStandard},
		},
		{
			ID:           "human_4",
			Role:         RoleHumanMember,
			PubKeyHex:    kr.pubs["human_4"],
			VotingWeight: 5,
			Status:       StatusActive,
			BaseScopes:   []string{ScopeVoteStandard},
		},
		{
			ID:           "judge_1",
			Role:         RoleAppealJudge,
			PubKeyHex:    kr.pubs["judge_1"],
			VotingWeight: 5,
			Status:       StatusActive,
			BaseScopes:   []string{ScopeVoteStandard, ScopeAppealAdjudicate},
		},
		{
			ID:           "judge_2",
			Role:         RoleAppealJudge,
			PubKeyHex:    kr.pubs["judge_2"],
			VotingWeight: 5,
			Status:       StatusActive,
			BaseScopes:   []string{ScopeVoteStandard, ScopeAppealAdjudicate},
		},
		{
			ID:           "ai_agent_1",
			Role:         RoleAIAgent,
			PubKeyHex:    kr.pubs["ai_agent_1"],
			VotingWeight: 0,
			Status:       StatusActive,
			BaseScopes:   []string{ScopeAdvisoryRecommend, ScopeFlagConflict, ScopeEstimateValue, ScopePreparePlan},
		},
	}

	rules := []PolicyRule{
		{
			ID:         "R-CONST-AI-01",
			Tier:       TierConstitutional,
			ActionType: ActionTreasuryExecute,
			Target:     "*",
			Effect:     EffectDeny,
			Condition:  "ACTOR_IS_AI",
			Rationale:  "INV-01: AI agents cannot authorize treasury spending",
		},
		{
			ID:         "R-EMERG-PAUSE-01",
			Tier:       TierEmergencySafety,
			ActionType: ActionTreasuryExecute,
			Target:     "*",
			Effect:     EffectDeny,
			Condition:  "WHEN_PAUSED",
			Rationale:  "INV-05: ZIP-0027 DEFCON-1 spend cap is 0 ZOO while paused",
		},
		{
			ID:         "R-CHARTER-TREASURY-01",
			Tier:       TierCharterStatute,
			ActionType: ActionTreasuryExecute,
			Target:     "*",
			Effect:     EffectAllow,
			Condition:  "ALWAYS",
			Rationale:  "Charter allows standard timelocked treasury execution",
		},
	}

	return GovernanceState{
		Epoch:               BaseEpoch,
		TreasuryBalance:     10_000_000,
		GenesisActiveWeight: 100,
		Actors:              actors,
		Delegations:         []Delegation{},
		Rules:               rules,
		QueuedActions:       []QueuedAction{},
		ContestedActions:    []ContestedAction{},
		Emergency:           EmergencyState{},
		UsedNonces:          []string{},
	}
}

// RunCase executes an AdversarialCase sequentially against its InitialState,
// returning the final transition result and ensuring every intermediate setup
// step succeeds while the terminal action produces the tested verdict.
func RunCase(c *AdversarialCase, cfg EngineConfig) {
	st := c.InitialState.Clone()
	var last TransitionResult
	for _, act := range c.Actions {
		last = Apply(st, act, cfg)
	}
	c.ActualVerdict = last.Verdict
	c.ActualErrorCode = last.ErrorCode
	c.ConflictWitness = last.ConflictWitness
	c.Passed = (c.ActualVerdict == c.ExpectedVerdict && c.ActualErrorCode == c.ExpectedErrorCode)
	dig, err := CaseDigest(*c)
	if err != nil {
		panic(err)
	}
	c.CaseDigest = dig
}

// BuildAdversarialSuite constructs and executes all 46 deterministic,
// Ed25519-signed adversarial and golden governance cases (INV-01..INV-10).
func BuildAdversarialSuite(seed int64) AdversarialSuiteReport {
	actorIDs := []string{
		"council_1", "council_2", "council_3",
		"human_1", "human_2", "human_3", "human_4",
		"judge_1", "judge_2", "ai_agent_1",
	}
	kr := newFixtureKeyring(seed, actorIDs)

	cases := make([]AdversarialCase, 0, 46)
	addCase := func(id, inv, desc string, init GovernanceState, acts []GovernanceAction, expV Verdict, expCode string) {
		c := AdversarialCase{
			CaseID:            id,
			InvariantID:       inv,
			Description:       desc,
			InitialState:      init,
			Actions:           acts,
			ExpectedVerdict:   expV,
			ExpectedErrorCode: expCode,
		}
		RunCase(&c, EngineConfig{SkipSigVerify: false})
		cases = append(cases, c)
	}

	// ==================== GROUP A: INV-01 AI Constitutional Boundary (6 cases) ====================
	{
		st := baseFixtureState(kr)
		st.QueuedActions = append(st.QueuedActions, QueuedAction{
			ID: "p-ai-1", Kind: "TREASURY", ProposerID: "council_1", Target: "grant_alpha",
			Amount: 1000, QueuedAt: BaseEpoch, MinTimelockSec: MinTimelockTreasurySec,
		})
		a := kr.sign(GovernanceAction{
			ID: "act-ai-01", Type: ActionTreasuryExecute, ActorID: "ai_agent_1",
			Target: "grant_alpha", Epoch: BaseEpoch + MinTimelockTreasurySec + 10, ProposalID: "p-ai-1", Amount: 1000,
		}, map[string]uint64{"ai_agent_1": 1}, []string{"ai_agent_1"})
		addCase("adv_01_ai_treasury_spend_direct", "INV-01",
			"AI_AGENT attempts to execute treasury transfer directly",
			st, []GovernanceAction{a}, VerdictDeny, CodeAIConstitutionalViolation)
	}
	{
		st := baseFixtureState(kr)
		a := kr.sign(GovernanceAction{
			ID: "act-ai-02", Type: ActionRuleAmendQueue, ActorID: "ai_agent_1", Target: "quorum_rule",
			Epoch: BaseEpoch + 10, ProposalID: "amend-ai-1",
			NewRule: &PolicyRule{ID: "R-AI-HACK", Tier: TierCharterStatute, ActionType: "*", Target: "*", Effect: EffectAllow, Condition: "ALWAYS", Rationale: "ai rule"},
		}, map[string]uint64{"ai_agent_1": 1, "council_1": 1, "council_2": 1, "council_3": 1, "human_1": 1, "human_2": 1},
			[]string{"ai_agent_1", "council_1", "council_2", "council_3", "human_1", "human_2"})
		addCase("adv_02_ai_mutate_voting_rules", "INV-01",
			"AI_AGENT attempts to queue voting/quorum rule amendment",
			st, []GovernanceAction{a}, VerdictDeny, CodeAIConstitutionalViolation)
	}
	{
		st := baseFixtureState(kr)
		a := kr.sign(GovernanceAction{
			ID: "act-ai-03", Type: ActionEmergencyPause, ActorID: "council_1", Target: "bridge",
			Epoch: BaseEpoch + 10, DurationSec: 3600,
		}, map[string]uint64{"council_1": 1, "council_2": 1, "ai_agent_1": 1},
			[]string{"council_1", "council_2", "ai_agent_1"})
		addCase("adv_03_ai_approve_emergency_pause", "INV-01",
			"AI_AGENT co-signs DEFCON-1 emergency pause authorization",
			st, []GovernanceAction{a}, VerdictDeny, CodeAIConstitutionalViolation)
	}
	{
		st := baseFixtureState(kr)
		a := kr.sign(GovernanceAction{
			ID: "act-ai-04", Type: ActionExperimentValidate, ActorID: "ai_agent_1", Target: "exp-1352",
			Epoch: BaseEpoch + 10, ExperimentAuthorID: "ai_agent_1",
		}, map[string]uint64{"ai_agent_1": 1}, []string{"ai_agent_1"})
		addCase("adv_04_ai_self_validate_experiment", "INV-01",
			"AI_AGENT attempts to declare its own experimental claim valid",
			st, []GovernanceAction{a}, VerdictDeny, CodeAIConstitutionalViolation)
	}
	{
		st := baseFixtureState(kr)
		a := kr.sign(GovernanceAction{
			ID: "act-ai-05", Type: ActionDelegate, ActorID: "council_1", Target: "ai_agent_1",
			Epoch: BaseEpoch + 10, DurationSec: 3600, Scopes: []string{ScopeTreasurySpend},
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		addCase("adv_05_ai_delegated_sovereign_escalation", "INV-01",
			"Human council member attempts to delegate sovereign TREASURY_SPEND scope to AI_AGENT",
			st, []GovernanceAction{a}, VerdictDeny, CodeAIConstitutionalViolation)
	}
	{
		st := baseFixtureState(kr)
		a := kr.sign(GovernanceAction{
			ID: "act-ai-06", Type: ActionAdvisoryRecommend, ActorID: "ai_agent_1", Target: "proposal-review-42",
			Epoch: BaseEpoch + 10,
		}, map[string]uint64{"ai_agent_1": 1}, []string{"ai_agent_1"})
		addCase("ok_06_ai_advisory_recommendation", "INV-01",
			"AI_AGENT legitimately submits non-binding advisory recommendation and conflict flag",
			st, []GovernanceAction{a}, VerdictAllow, CodeOK)
	}

	// ==================== GROUP B: INV-02 Acyclic Bounded Delegation (6 cases) ====================
	{
		st := baseFixtureState(kr)
		a := kr.sign(GovernanceAction{
			ID: "act-del-07", Type: ActionDelegate, ActorID: "council_1", Target: "council_1",
			Epoch: BaseEpoch + 10, DurationSec: 3600, Scopes: []string{ScopeVoteStandard},
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		addCase("adv_07_delegation_self_loop", "INV-02",
			"Actor attempts self-delegation loop (council_1 -> council_1)",
			st, []GovernanceAction{a}, VerdictDeny, CodeDelegationCycle)
	}
	{
		st := baseFixtureState(kr)
		a1 := kr.sign(GovernanceAction{
			ID: "act-del-08a", Type: ActionDelegate, ActorID: "council_1", Target: "human_1",
			Epoch: BaseEpoch + 10, DurationSec: 7200, Scopes: []string{ScopeVoteStandard}, DelegationID: "d-c1-h1",
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		a2 := kr.sign(GovernanceAction{
			ID: "act-del-08b", Type: ActionDelegate, ActorID: "human_1", Target: "human_2",
			Epoch: BaseEpoch + 20, DurationSec: 3600, Scopes: []string{ScopeVoteStandard}, DelegationID: "d-h1-h2",
		}, map[string]uint64{"human_1": 1}, []string{"human_1"})
		a3 := kr.sign(GovernanceAction{
			ID: "act-del-08c", Type: ActionDelegate, ActorID: "human_2", Target: "council_1",
			Epoch: BaseEpoch + 30, DurationSec: 1800, Scopes: []string{ScopeVoteStandard}, DelegationID: "d-h2-c1",
		}, map[string]uint64{"human_2": 1}, []string{"human_2"})
		addCase("adv_08_delegation_cycle_3hop", "INV-02",
			"3-hop delegation cycle A -> B -> C -> A rejected",
			st, []GovernanceAction{a1, a2, a3}, VerdictDeny, CodeDelegationCycle)
	}
	{
		st := baseFixtureState(kr)
		a1 := kr.sign(GovernanceAction{
			ID: "act-del-09a", Type: ActionDelegate, ActorID: "council_1", Target: "human_1",
			Epoch: BaseEpoch + 10, DurationSec: 7200, Scopes: []string{ScopeVoteStandard}, DelegationID: "d-1",
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		a2 := kr.sign(GovernanceAction{
			ID: "act-del-09b", Type: ActionDelegate, ActorID: "human_1", Target: "human_2",
			Epoch: BaseEpoch + 20, DurationSec: 6000, Scopes: []string{ScopeVoteStandard}, DelegationID: "d-2",
		}, map[string]uint64{"human_1": 1}, []string{"human_1"})
		a3 := kr.sign(GovernanceAction{
			ID: "act-del-09c", Type: ActionDelegate, ActorID: "human_2", Target: "human_3",
			Epoch: BaseEpoch + 30, DurationSec: 5000, Scopes: []string{ScopeVoteStandard}, DelegationID: "d-3",
		}, map[string]uint64{"human_2": 1}, []string{"human_2"})
		a4 := kr.sign(GovernanceAction{
			ID: "act-del-09d", Type: ActionDelegate, ActorID: "human_3", Target: "human_4",
			Epoch: BaseEpoch + 40, DurationSec: 4000, Scopes: []string{ScopeVoteStandard}, DelegationID: "d-4",
		}, map[string]uint64{"human_3": 1}, []string{"human_3"})
		addCase("adv_09_delegation_depth_exceeds_3", "INV-02",
			"4-hop delegation chain exceeds max_depth=3 ceiling",
			st, []GovernanceAction{a1, a2, a3, a4}, VerdictDeny, CodeDelegationDepthExceeded)
	}
	{
		st := baseFixtureState(kr)
		a := kr.sign(GovernanceAction{
			ID: "act-del-10", Type: ActionDelegate, ActorID: "human_2", Target: "human_3",
			Epoch: BaseEpoch + 10, DurationSec: 3600, Scopes: []string{ScopeTreasurySpend},
		}, map[string]uint64{"human_2": 1}, []string{"human_2"})
		addCase("adv_10_delegation_scope_escalation", "INV-02",
			"Actor holding only VOTE_STANDARD attempts to delegate TREASURY_SPEND",
			st, []GovernanceAction{a}, VerdictDeny, CodeDelegationScopeEscalation)
	}
	{
		st := baseFixtureState(kr)
		a1 := kr.sign(GovernanceAction{
			ID: "act-del-11a", Type: ActionDelegate, ActorID: "council_1", Target: "human_2",
			Epoch: BaseEpoch + 10, DurationSec: 3600, Scopes: []string{ScopeTreasurySpend}, DelegationID: "d-exp-1",
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		a2 := kr.sign(GovernanceAction{
			ID: "act-del-11b", Type: ActionDelegate, ActorID: "human_2", Target: "human_3",
			Epoch: BaseEpoch + 20, DurationSec: 7200, Scopes: []string{ScopeTreasurySpend}, DelegationID: "d-exp-2",
		}, map[string]uint64{"human_2": 1}, []string{"human_2"})
		addCase("adv_11_delegation_expiry_escalation", "INV-02",
			"Sub-delegation attempts longer expiry than parent delegation authority",
			st, []GovernanceAction{a1, a2}, VerdictDeny, CodeDelegationExpiryEscalation)
	}
	{
		st := baseFixtureState(kr)
		a1 := kr.sign(GovernanceAction{
			ID: "act-del-12a", Type: ActionDelegate, ActorID: "council_1", Target: "human_2",
			Epoch: BaseEpoch + 10, DurationSec: 7200, Scopes: []string{ScopeVoteStandard, ScopeTreasurySpend}, DelegationID: "d-ok-1",
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		a2 := kr.sign(GovernanceAction{
			ID: "act-del-12b", Type: ActionDelegate, ActorID: "human_2", Target: "human_3",
			Epoch: BaseEpoch + 20, DurationSec: 3600, Scopes: []string{ScopeTreasurySpend}, DelegationID: "d-ok-2",
		}, map[string]uint64{"human_2": 1}, []string{"human_2"})
		addCase("ok_12_delegation_valid_attenuated_chain", "INV-02",
			"Valid depth-2 delegation with strictly attenuated scope and shorter expiry",
			st, []GovernanceAction{a1, a2}, VerdictAllow, CodeOK)
	}

	// ==================== GROUP C: INV-03 Immediate Transitive Revocation (4 cases) ====================
	{
		st := baseFixtureState(kr)
		a1 := kr.sign(GovernanceAction{
			ID: "act-rev-13a", Type: ActionRevokeActor, ActorID: "council_1", Target: "human_1",
			Epoch: BaseEpoch + 10,
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		a2 := kr.sign(GovernanceAction{
			ID: "act-rev-13b", Type: ActionAdvisoryRecommend, ActorID: "human_1", Target: "memo",
			Epoch: BaseEpoch + 20,
		}, map[string]uint64{"human_1": 1}, []string{"human_1"})
		addCase("adv_13_post_revocation_direct_action", "INV-03",
			"Revoked actor attempts action at t >= t_revoke",
			st, []GovernanceAction{a1, a2}, VerdictDeny, CodeActorRevoked)
	}
	{
		st := baseFixtureState(kr)
		a1 := kr.sign(GovernanceAction{
			ID: "act-rev-14a", Type: ActionDelegate, ActorID: "human_1", Target: "human_2",
			Epoch: BaseEpoch + 10, DurationSec: 7200, Scopes: []string{ScopeTreasurySpend}, DelegationID: "d-r1",
		}, map[string]uint64{"human_1": 1}, []string{"human_1"})
		a2 := kr.sign(GovernanceAction{
			ID: "act-rev-14b", Type: ActionDelegate, ActorID: "human_2", Target: "human_3",
			Epoch: BaseEpoch + 20, DurationSec: 3600, Scopes: []string{ScopeTreasurySpend}, DelegationID: "d-r2",
		}, map[string]uint64{"human_2": 1}, []string{"human_2"})
		a3 := kr.sign(GovernanceAction{
			ID: "act-rev-14c", Type: ActionRevokeActor, ActorID: "council_1", Target: "human_1",
			Epoch: BaseEpoch + 30,
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		a4 := kr.sign(GovernanceAction{
			ID: "act-rev-14d", Type: ActionTreasuryQueue, ActorID: "human_3", Target: "grant_1",
			Epoch: BaseEpoch + 40, Amount: 1000, DelegationID: "d-r2", ProposalID: "p-r14",
		}, map[string]uint64{"human_3": 1, "council_2": 1}, []string{"human_3", "council_2"})
		addCase("adv_14_transitive_subdelegation_revoked", "INV-03",
			"Revoking root delegator transitively revokes 2-hop sub-delegation d-r2",
			st, []GovernanceAction{a1, a2, a3, a4}, VerdictDeny, CodeDelegationRevoked)
	}
	{
		st := baseFixtureState(kr)
		a1 := kr.sign(GovernanceAction{
			ID: "act-rev-15a", Type: ActionDelegate, ActorID: "human_1", Target: "human_2",
			Epoch: BaseEpoch + 10, DurationSec: 200000, Scopes: []string{ScopeTreasurySpend}, DelegationID: "d-q15",
		}, map[string]uint64{"human_1": 1}, []string{"human_1"})
		a2 := kr.sign(GovernanceAction{
			ID: "act-rev-15b", Type: ActionTreasuryQueue, ActorID: "human_2", Target: "grant_15",
			Epoch: BaseEpoch + 20, Amount: 5000, DelegationID: "d-q15", ProposalID: "p-q15",
		}, map[string]uint64{"human_2": 1, "council_2": 1}, []string{"human_2", "council_2"})
		a3 := kr.sign(GovernanceAction{
			ID: "act-rev-15c", Type: ActionRevokeActor, ActorID: "council_1", Target: "human_1",
			Epoch: BaseEpoch + 30,
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		a4 := kr.sign(GovernanceAction{
			ID: "act-rev-15d", Type: ActionTreasuryExecute, ActorID: "human_2", Target: "grant_15",
			Epoch: BaseEpoch + 20 + MinTimelockTreasurySec + 10, ProposalID: "p-q15", Amount: 5000,
		}, map[string]uint64{"human_2": 2}, []string{"human_2"})
		addCase("adv_15_queued_action_invalidated_by_revocation", "INV-03",
			"Pending queued treasury spend is immediately invalidated when delegator is revoked",
			st, []GovernanceAction{a1, a2, a3, a4}, VerdictDeny, CodeProposerAuthorityRevoked)
	}
	{
		st := baseFixtureState(kr)
		a1 := kr.sign(GovernanceAction{
			ID: "act-rev-16a", Type: ActionDelegate, ActorID: "council_1", Target: "human_2",
			Epoch: BaseEpoch + 10, DurationSec: 7200, Scopes: []string{ScopeTreasurySpend}, DelegationID: "d-edge-16",
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		a2 := kr.sign(GovernanceAction{
			ID: "act-rev-16b", Type: ActionRevokeDelegation, ActorID: "council_1", Target: "human_2",
			Epoch: BaseEpoch + 20, DelegationID: "d-edge-16",
		}, map[string]uint64{"council_1": 2}, []string{"council_1"})
		a3 := kr.sign(GovernanceAction{
			ID: "act-rev-16c", Type: ActionTreasuryQueue, ActorID: "human_2", Target: "grant_16",
			Epoch: BaseEpoch + 30, Amount: 1000, DelegationID: "d-edge-16", ProposalID: "p-16",
		}, map[string]uint64{"human_2": 1, "council_2": 1}, []string{"human_2", "council_2"})
		addCase("adv_16_delegation_edge_revoked_replay", "INV-03",
			"Revoked delegation edge cannot be replayed by delegatee",
			st, []GovernanceAction{a1, a2, a3}, VerdictDeny, CodeDelegationRevoked)
	}

	// ==================== GROUP D: INV-04 Quorum & Supermajority Monotonicity (6 cases) ====================
	{
		st := baseFixtureState(kr)
		a := GovernanceAction{
			ID: "act-q-17", Type: ActionEmergencyPause, ActorID: "council_1", Target: "bridge",
			Epoch: BaseEpoch + 10, DurationSec: 3600,
		}
		s1, _ := SignAction(a, "council_1", 1, kr.keys["council_1"])
		s2, _ := SignAction(a, "council_1", 2, kr.keys["council_1"])
		a.Signers = []SignerSig{s1, s2}
		addCase("adv_17_duplicate_signer_inflation", "INV-04",
			"Single council member signs twice to counterfeit 2-of-3 supermajority",
			st, []GovernanceAction{a}, VerdictDeny, CodeDuplicateSigner)
	}
	{
		st := baseFixtureState(kr)
		a1 := kr.sign(GovernanceAction{
			ID: "act-q-18a", Type: ActionDelegate, ActorID: "human_1", Target: "human_2",
			Epoch: BaseEpoch + 10, DurationSec: 7200, Scopes: []string{ScopeVoteStandard}, DelegationID: "d-vote-18",
		}, map[string]uint64{"human_1": 1}, []string{"human_1"})
		a2 := kr.sign(GovernanceAction{
			ID: "act-q-18b", Type: ActionTreasuryQueue, ActorID: "council_1", Target: "grant_18",
			Epoch: BaseEpoch + 20, Amount: 1000, ProposalID: "p-18",
		}, map[string]uint64{"council_1": 1, "human_1": 2, "human_2": 1}, []string{"council_1", "human_1", "human_2"})
		addCase("adv_18_double_vote_via_split_delegation", "INV-04",
			"Delegator and delegatee both sign same vote attempting double counting",
			st, []GovernanceAction{a1, a2}, VerdictDeny, CodeDoubleVoteDelegation)
	}
	{
		st := baseFixtureState(kr)
		a1 := kr.sign(GovernanceAction{
			ID: "act-q-19a", Type: ActionRevokeActor, ActorID: "council_1", Target: "council_2",
			Epoch: BaseEpoch + 10,
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		// human_1 has weight 10 out of active 80 (12.5% < 15% quorum); tries adding revoked council_2 (weight 20).
		a2 := kr.sign(GovernanceAction{
			ID: "act-q-19b", Type: ActionTreasuryQueue, ActorID: "human_1", Target: "grant_19",
			Epoch: BaseEpoch + 20, Amount: 1000, ProposalID: "p-19",
		}, map[string]uint64{"human_1": 1, "council_2": 1}, []string{"human_1", "council_2"})
		addCase("adv_19_revoked_member_vote_excluded", "INV-04",
			"Revoked member weight is excluded from quorum numerator",
			st, []GovernanceAction{a1, a2}, VerdictDeny, CodeQuorumNotMet)
	}
	{
		st := baseFixtureState(kr)
		// 60 weight self-suspends (council_1=20, council_2=20, council_3=20 -> active drops to 40 < 50 floor).
		s1 := kr.sign(GovernanceAction{ID: "ss-1", Type: ActionSelfSuspend, ActorID: "council_1", Target: "council_1", Epoch: BaseEpoch + 10}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		s2 := kr.sign(GovernanceAction{ID: "ss-2", Type: ActionSelfSuspend, ActorID: "council_2", Target: "council_2", Epoch: BaseEpoch + 11}, map[string]uint64{"council_2": 1}, []string{"council_2"})
		s3 := kr.sign(GovernanceAction{ID: "ss-3", Type: ActionSelfSuspend, ActorID: "council_3", Target: "council_3", Epoch: BaseEpoch + 12}, map[string]uint64{"council_3": 1}, []string{"council_3"})
		a4 := kr.sign(GovernanceAction{
			ID: "act-q-20", Type: ActionRuleAmendQueue, ActorID: "human_1", Target: "rule_capture",
			Epoch: BaseEpoch + 20, ProposalID: "amend-20",
			NewRule: &PolicyRule{ID: "R-CABAL", Tier: TierCharterStatute, ActionType: "*", Target: "*", Effect: EffectAllow, Condition: "ALWAYS", Rationale: "capture"},
		}, map[string]uint64{"human_1": 1, "human_2": 1, "human_3": 1, "human_4": 1}, []string{"human_1", "human_2", "human_3", "human_4"})
		addCase("adv_20_quorum_shrinking_mass_self_suspension", "INV-04",
			"Mass self-suspension shrinks active weight below 50% constitutional quorum floor",
			st, []GovernanceAction{s1, s2, s3, a4}, VerdictDeny, CodeQuorumFloorBreached)
	}
	{
		st := baseFixtureState(kr)
		// Weight = 20+20+20+10 = 70% (< 75% required for meta-governance).
		a := kr.sign(GovernanceAction{
			ID: "act-q-21", Type: ActionRuleAmendQueue, ActorID: "council_1", Target: "rule_21",
			Epoch: BaseEpoch + 10, ProposalID: "amend-21",
			NewRule: &PolicyRule{ID: "R-NEW-21", Tier: TierCharterStatute, ActionType: "*", Target: "*", Effect: EffectAllow, Condition: "ALWAYS", Rationale: "test"},
		}, map[string]uint64{"council_1": 1, "council_2": 1, "council_3": 1, "human_1": 1},
			[]string{"council_1", "council_2", "council_3", "human_1"})
		addCase("adv_21_meta_gov_below_75_supermajority", "INV-04",
			"Meta-governance rule amendment at 70% (< 75% supermajority) rejected",
			st, []GovernanceAction{a}, VerdictDeny, CodeSupermajorityNotMet)
	}
	{
		st := baseFixtureState(kr)
		// Weight = 20+20+20+10+10 = 80% (>= 75%).
		a := kr.sign(GovernanceAction{
			ID: "act-q-22", Type: ActionRuleAmendQueue, ActorID: "council_1", Target: "rule_22",
			Epoch: BaseEpoch + 10, ProposalID: "amend-22",
			NewRule: &PolicyRule{ID: "R-NEW-22", Tier: TierCharterStatute, ActionType: ActionAdvisoryRecommend, Target: "*", Effect: EffectAllow, Condition: "ALWAYS", Rationale: "valid"},
		}, map[string]uint64{"council_1": 1, "council_2": 1, "council_3": 1, "human_1": 1, "human_2": 1},
			[]string{"council_1", "council_2", "council_3", "human_1", "human_2"})
		addCase("ok_22_meta_gov_75_supermajority_valid", "INV-04",
			"Meta-governance rule amendment with 80% distinct human supermajority queues validly",
			st, []GovernanceAction{a}, VerdictAllow, CodeOK)
	}

	// ==================== GROUP E: INV-05 Bounded Emergency Suspension (6 cases) ====================
	{
		st := baseFixtureState(kr)
		a := kr.sign(GovernanceAction{
			ID: "act-em-23", Type: ActionEmergencyPause, ActorID: "council_1", Target: "bridge",
			Epoch: BaseEpoch + 10, DurationSec: 96 * 3600,
		}, map[string]uint64{"council_1": 1, "council_2": 1}, []string{"council_1", "council_2"})
		addCase("adv_23_defcon1_duration_exceeds_72h", "INV-05",
			"DEFCON-1 pause requesting 96h exceeds ZIP-0027 72h maximum duration",
			st, []GovernanceAction{a}, VerdictDeny, CodeEmergencyDurationExceeded)
	}
	{
		st := baseFixtureState(kr)
		a := kr.sign(GovernanceAction{
			ID: "act-em-24", Type: ActionEmergencyPause, ActorID: "council_1", Target: "bridge",
			Epoch: BaseEpoch + 10, DurationSec: 3600,
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		addCase("adv_24_defcon1_insufficient_supermajority", "INV-05",
			"Single council member (33%) cannot trigger DEFCON-1 pause (requires >=67%)",
			st, []GovernanceAction{a}, VerdictDeny, CodeSupermajorityNotMet)
	}
	{
		st := baseFixtureState(kr)
		st.QueuedActions = append(st.QueuedActions, QueuedAction{
			ID: "p-em-25", Kind: "TREASURY", ProposerID: "council_1", Target: "grant_25",
			Amount: 50000, QueuedAt: BaseEpoch - MinTimelockTreasurySec - 10, MinTimelockSec: MinTimelockTreasurySec,
		})
		a1 := kr.sign(GovernanceAction{
			ID: "act-em-25a", Type: ActionEmergencyPause, ActorID: "council_1", Target: "bridge",
			Epoch: BaseEpoch + 10, DurationSec: MaxEmergencyDurationSec,
		}, map[string]uint64{"council_1": 1, "council_2": 1, "council_3": 1}, []string{"council_1", "council_2", "council_3"})
		a2 := kr.sign(GovernanceAction{
			ID: "act-em-25b", Type: ActionTreasuryExecute, ActorID: "council_1", Target: "grant_25",
			Epoch: BaseEpoch + 100, ProposalID: "p-em-25", Amount: 50000,
		}, map[string]uint64{"council_1": 2}, []string{"council_1"})
		addCase("adv_25_defcon1_treasury_drain_while_paused", "INV-05",
			"Treasury execution blocked during active DEFCON-1 pause (0 ZOO spend cap)",
			st, []GovernanceAction{a1, a2}, VerdictDeny, CodePolicyDeny)
	}
	{
		st := baseFixtureState(kr)
		a1 := kr.sign(GovernanceAction{
			ID: "act-em-26a", Type: ActionEmergencyPause, ActorID: "council_1", Target: "bridge",
			Epoch: BaseEpoch + 10, DurationSec: MaxEmergencyDurationSec,
		}, map[string]uint64{"council_1": 1, "council_2": 1, "council_3": 1}, []string{"council_1", "council_2", "council_3"})
		a2 := kr.sign(GovernanceAction{
			ID: "act-em-26b", Type: ActionRuleAmendQueue, ActorID: "council_1", Target: "constitution",
			Epoch: BaseEpoch + 100, ProposalID: "amend-26",
			NewRule: &PolicyRule{ID: "R-PAUSED", Tier: TierCharterStatute, ActionType: "*", Target: "*", Effect: EffectAllow, Condition: "ALWAYS", Rationale: "bypass"},
		}, map[string]uint64{"council_1": 2, "council_2": 2, "council_3": 2, "human_1": 1, "human_2": 1},
			[]string{"council_1", "council_2", "council_3", "human_1", "human_2"})
		addCase("adv_26_defcon1_rule_edit_while_paused", "INV-05",
			"Constitutional/charter rule edit forbidden while DEFCON-1 pause is active",
			st, []GovernanceAction{a1, a2}, VerdictDeny, CodePausedActionForbidden)
	}
	{
		st := baseFixtureState(kr)
		a1 := kr.sign(GovernanceAction{
			ID: "act-em-27a", Type: ActionEmergencyPause, ActorID: "council_1", Target: "bridge",
			Epoch: BaseEpoch + 10, DurationSec: MaxEmergencyDurationSec,
		}, map[string]uint64{"council_1": 1, "council_2": 1, "council_3": 1}, []string{"council_1", "council_2", "council_3"})
		a2 := kr.sign(GovernanceAction{
			ID: "act-em-27b", Type: ActionEmergencyRenew, ActorID: "council_1", Target: "bridge",
			Epoch: BaseEpoch + 10 + MaxEmergencyDurationSec + RenewalCooldownSec + 10, DurationSec: MaxEmergencyDurationSec,
		}, map[string]uint64{"council_1": 2, "council_2": 2, "council_3": 2}, []string{"council_1", "council_2", "council_3"})
		addCase("adv_27_defcon1_infinite_self_renewal_loop", "INV-05",
			"Original council trigger set cannot self-renew DEFCON-1 without independent human supermajority",
			st, []GovernanceAction{a1, a2}, VerdictDeny, CodeEmergencySelfRenewal)
	}
	{
		st := baseFixtureState(kr)
		st.QueuedActions = append(st.QueuedActions, QueuedAction{
			ID: "p-em-28", Kind: "TREASURY", ProposerID: "council_1", Target: "grant_28",
			Amount: 1000, QueuedAt: BaseEpoch, MinTimelockSec: MinTimelockTreasurySec,
		})
		a1 := kr.sign(GovernanceAction{
			ID: "act-em-28a", Type: ActionEmergencyPause, ActorID: "council_1", Target: "bridge",
			Epoch: BaseEpoch + 10, DurationSec: MaxEmergencyDurationSec,
		}, map[string]uint64{"council_1": 1, "council_2": 1, "council_3": 1}, []string{"council_1", "council_2", "council_3"})
		a2 := kr.sign(GovernanceAction{
			ID: "act-em-28b", Type: ActionTreasuryExecute, ActorID: "council_1", Target: "grant_28",
			Epoch: BaseEpoch + 10 + MaxEmergencyDurationSec + 1, ProposalID: "p-em-28", Amount: 1000,
		}, map[string]uint64{"council_1": 2}, []string{"council_1"})
		addCase("ok_28_defcon1_auto_sunset_and_valid_resume", "INV-05",
			"After 72h auto-sunset, valid timelocked treasury execution resumes cleanly",
			st, []GovernanceAction{a1, a2}, VerdictAllow, CodeOK)
	}

	// ==================== GROUP F: INV-06 Appeal & Due-Process Determinism (5 cases) ====================
	{
		st := baseFixtureState(kr)
		a1 := kr.sign(GovernanceAction{
			ID: "act-ap-29a", Type: ActionSuspendActor, ActorID: "council_1", Target: "human_1",
			Epoch: BaseEpoch + 10, ContestedID: "cont-29",
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		a2 := kr.sign(GovernanceAction{
			ID: "act-ap-29b", Type: ActionFinalizeContested, ActorID: "council_1", Target: "human_1",
			Epoch: BaseEpoch + 10 + 3600, ContestedID: "cont-29",
		}, map[string]uint64{"council_1": 2}, []string{"council_1"})
		addCase("adv_29_premature_finalize_during_appeal_window", "INV-06",
			"Irreversible finalization blocked while 48h appeal window is open",
			st, []GovernanceAction{a1, a2}, VerdictDeny, CodeAppealWindowOpen)
	}
	{
		st := baseFixtureState(kr)
		a1 := kr.sign(GovernanceAction{
			ID: "act-ap-30a", Type: ActionSuspendActor, ActorID: "council_1", Target: "human_1",
			Epoch: BaseEpoch + 10, ContestedID: "cont-30",
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		a2 := kr.sign(GovernanceAction{
			ID: "act-ap-30b", Type: ActionAppealFile, ActorID: "human_1", Target: "cont-30",
			Epoch: BaseEpoch + 100, ContestedID: "cont-30",
		}, map[string]uint64{"human_1": 1}, []string{"human_1"})
		a3 := kr.sign(GovernanceAction{
			ID: "act-ap-30c", Type: ActionFinalizeContested, ActorID: "council_1", Target: "human_1",
			Epoch: BaseEpoch + 10 + AppealWindowSec + 100, ContestedID: "cont-30",
		}, map[string]uint64{"council_1": 2}, []string{"council_1"})
		addCase("adv_30_finalize_frozen_pending_appeal", "INV-06",
			"Pending appeal freezes irreversible finalization even after appeal window passes",
			st, []GovernanceAction{a1, a2, a3}, VerdictDeny, CodeAppealFreezeActive)
	}
	{
		st := baseFixtureState(kr)
		a1 := kr.sign(GovernanceAction{
			ID: "act-ap-31a", Type: ActionSuspendActor, ActorID: "council_1", Target: "human_1",
			Epoch: BaseEpoch + 10, ContestedID: "cont-31",
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		a2 := kr.sign(GovernanceAction{
			ID: "act-ap-31b", Type: ActionAppealFile, ActorID: "human_1", Target: "cont-31",
			Epoch: BaseEpoch + 100, ContestedID: "cont-31",
		}, map[string]uint64{"human_1": 1}, []string{"human_1"})
		a3 := kr.sign(GovernanceAction{
			ID: "act-ap-31c", Type: ActionAppealResolve, ActorID: "judge_1", Target: "cont-31",
			Epoch: BaseEpoch + 200, ContestedID: "cont-31", AppealOutcome: "UPHELD",
		}, map[string]uint64{"council_1": 2, "judge_1": 1}, []string{"council_1", "judge_1"})
		addCase("adv_31_self_adjudication_by_initiator", "INV-06",
			"Original suspension initiator barred from judging the resulting appeal",
			st, []GovernanceAction{a1, a2, a3}, VerdictDeny, CodeSelfAdjudication)
	}
	{
		st := baseFixtureState(kr)
		a1 := kr.sign(GovernanceAction{
			ID: "act-ap-32a", Type: ActionSuspendActor, ActorID: "council_1", Target: "judge_1",
			Epoch: BaseEpoch + 10, ContestedID: "cont-32",
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		a2 := kr.sign(GovernanceAction{
			ID: "act-ap-32b", Type: ActionAppealFile, ActorID: "judge_1", Target: "cont-32",
			Epoch: BaseEpoch + 100, ContestedID: "cont-32",
		}, map[string]uint64{"judge_1": 1}, []string{"judge_1"})
		a3 := kr.sign(GovernanceAction{
			ID: "act-ap-32c", Type: ActionAppealResolve, ActorID: "judge_2", Target: "cont-32",
			Epoch: BaseEpoch + 200, ContestedID: "cont-32", AppealOutcome: "OVERTURNED",
		}, map[string]uint64{"judge_1": 2, "judge_2": 1}, []string{"judge_1", "judge_2"})
		addCase("adv_32_self_adjudication_by_appellant", "INV-06",
			"Suspended appellant barred from adjudicating their own appeal",
			st, []GovernanceAction{a1, a2, a3}, VerdictDeny, CodeSelfAdjudication)
	}
	{
		st := baseFixtureState(kr)
		a1 := kr.sign(GovernanceAction{
			ID: "act-ap-33a", Type: ActionSuspendActor, ActorID: "council_1", Target: "human_1",
			Epoch: BaseEpoch + 10, ContestedID: "cont-33",
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		a2 := kr.sign(GovernanceAction{
			ID: "act-ap-33b", Type: ActionAppealFile, ActorID: "human_1", Target: "cont-33",
			Epoch: BaseEpoch + 100, ContestedID: "cont-33",
		}, map[string]uint64{"human_1": 1}, []string{"human_1"})
		a3 := kr.sign(GovernanceAction{
			ID: "act-ap-33c", Type: ActionAppealResolve, ActorID: "judge_1", Target: "cont-33",
			Epoch: BaseEpoch + 200, ContestedID: "cont-33", AppealOutcome: "OVERTURNED",
		}, map[string]uint64{"judge_1": 1, "judge_2": 1}, []string{"judge_1", "judge_2"})
		addCase("ok_33_independent_appeal_overturns_suspension", "INV-06",
			"Two independent appeal judges legitimately overturn contested suspension",
			st, []GovernanceAction{a1, a2, a3}, VerdictAllow, CodeOK)
	}

	// ==================== GROUP G: INV-07 Rule-Precedence & Conflict Resolution (5 cases) ====================
	{
		st := baseFixtureState(kr)
		st.Rules = append(st.Rules, PolicyRule{
			ID: "R-CHARTER-TREASURY-DENY-34", Tier: TierCharterStatute, ActionType: ActionTreasuryExecute,
			Target: "grant_clash", Effect: EffectDeny, Condition: "ALWAYS", Rationale: "Conflicting charter freeze",
		})
		st.QueuedActions = append(st.QueuedActions, QueuedAction{
			ID: "p-34", Kind: "TREASURY", ProposerID: "council_1", Target: "grant_clash",
			Amount: 1000, QueuedAt: BaseEpoch, MinTimelockSec: MinTimelockTreasurySec,
		})
		a := kr.sign(GovernanceAction{
			ID: "act-cf-34", Type: ActionTreasuryExecute, ActorID: "council_1", Target: "grant_clash",
			Epoch: BaseEpoch + MinTimelockTreasurySec + 10, ProposalID: "p-34", Amount: 1000,
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		addCase("adv_34_same_tier_charter_allow_deny_conflict", "INV-07",
			"Same-tier CHARTER_STATUTE ALLOW and DENY clash fails closed with ConflictWitness",
			st, []GovernanceAction{a}, VerdictDeny, CodeDenyRuleConflict)
	}
	{
		st := baseFixtureState(kr)
		st.Rules = append(st.Rules,
			PolicyRule{ID: "R-EMERG-ALLOW-35", Tier: TierEmergencySafety, ActionType: ActionAdvisoryRecommend, Target: "crisis_alert", Effect: EffectAllow, Condition: "ALWAYS", Rationale: "Allow alert"},
			PolicyRule{ID: "R-EMERG-DENY-35", Tier: TierEmergencySafety, ActionType: ActionAdvisoryRecommend, Target: "crisis_alert", Effect: EffectDeny, Condition: "ALWAYS", Rationale: "Suppress alert"},
		)
		a := kr.sign(GovernanceAction{
			ID: "act-cf-35", Type: ActionAdvisoryRecommend, ActorID: "council_1", Target: "crisis_alert",
			Epoch: BaseEpoch + 10,
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		addCase("adv_35_same_tier_emergency_safety_conflict", "INV-07",
			"Same-tier EMERGENCY_SAFETY conflict fails closed with ConflictWitness",
			st, []GovernanceAction{a}, VerdictDeny, CodeDenyRuleConflict)
	}
	{
		st := baseFixtureState(kr)
		st.Rules = append(st.Rules,
			PolicyRule{ID: "R-CONST-DENY-36", Tier: TierConstitutional, ActionType: ActionTreasuryExecute, Target: "restricted_vault", Effect: EffectDeny, Condition: "ALWAYS", Rationale: "Constitutional vault lock"},
			PolicyRule{ID: "R-CHARTER-ALLOW-36", Tier: TierCharterStatute, ActionType: ActionTreasuryExecute, Target: "restricted_vault", Effect: EffectAllow, Condition: "ALWAYS", Rationale: "Lower charter override attempt"},
		)
		st.QueuedActions = append(st.QueuedActions, QueuedAction{
			ID: "p-36", Kind: "TREASURY", ProposerID: "council_1", Target: "restricted_vault",
			Amount: 1000, QueuedAt: BaseEpoch, MinTimelockSec: MinTimelockTreasurySec,
		})
		a := kr.sign(GovernanceAction{
			ID: "act-cf-36", Type: ActionTreasuryExecute, ActorID: "council_1", Target: "restricted_vault",
			Epoch: BaseEpoch + MinTimelockTreasurySec + 10, ProposalID: "p-36", Amount: 1000,
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		addCase("adv_36_charter_cannot_override_constitutional_deny", "INV-07",
			"Lower-tier CHARTER_STATUTE ALLOW cannot override CONSTITUTIONAL DENY",
			st, []GovernanceAction{a}, VerdictDeny, CodeConstitutionalOverrideBlocked)
	}
	{
		st := baseFixtureState(kr)
		st.Rules = append(st.Rules,
			PolicyRule{ID: "R-EMERG-DENY-37", Tier: TierEmergencySafety, ActionType: ActionAdvisoryRecommend, Target: "oracle_feed", Effect: EffectDeny, Condition: "ALWAYS", Rationale: "Safety hold"},
			PolicyRule{ID: "R-ADV-ALLOW-37", Tier: TierAdvisoryPolicy, ActionType: ActionAdvisoryRecommend, Target: "oracle_feed", Effect: EffectAllow, Condition: "ALWAYS", Rationale: "Advisory allow"},
		)
		a := kr.sign(GovernanceAction{
			ID: "act-cf-37", Type: ActionAdvisoryRecommend, ActorID: "council_1", Target: "oracle_feed",
			Epoch: BaseEpoch + 10,
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		addCase("adv_37_advisory_cannot_override_emergency_safety", "INV-07",
			"ADVISORY_POLICY ALLOW cannot override EMERGENCY_SAFETY DENY",
			st, []GovernanceAction{a}, VerdictDeny, CodePolicyDeny)
	}
	{
		st := baseFixtureState(kr)
		st.Rules = append(st.Rules,
			PolicyRule{ID: "R-CONST-ALLOW-38", Tier: TierConstitutional, ActionType: ActionAdvisoryRecommend, Target: "audit_report", Effect: EffectAllow, Condition: "ALWAYS", Rationale: "Constitutional transparency mandate"},
			PolicyRule{ID: "R-ADV-DENY-38", Tier: TierAdvisoryPolicy, ActionType: ActionAdvisoryRecommend, Target: "audit_report", Effect: EffectDeny, Condition: "ALWAYS", Rationale: "Advisory suppression"},
		)
		a := kr.sign(GovernanceAction{
			ID: "act-cf-38", Type: ActionAdvisoryRecommend, ActorID: "council_1", Target: "audit_report",
			Epoch: BaseEpoch + 10,
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		addCase("ok_38_higher_tier_constitutional_allow_overrides_advisory_deny", "INV-07",
			"CONSTITUTIONAL ALLOW cleanly supersedes lower-tier ADVISORY_POLICY DENY",
			st, []GovernanceAction{a}, VerdictAllow, CodeOK)
	}

	// ==================== GROUP H: INV-08 Timelock Non-Bypassability (3 cases) ====================
	{
		st := baseFixtureState(kr)
		st.QueuedActions = append(st.QueuedActions, QueuedAction{
			ID: "p-tl-39", Kind: "TREASURY", ProposerID: "council_1", Target: "grant_39",
			Amount: 1000, QueuedAt: BaseEpoch, MinTimelockSec: MinTimelockTreasurySec,
		})
		a := kr.sign(GovernanceAction{
			ID: "act-tl-39", Type: ActionTreasuryExecute, ActorID: "council_1", Target: "grant_39",
			Epoch: BaseEpoch + 12*3600, ProposalID: "p-tl-39", Amount: 1000,
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		addCase("adv_39_treasury_timelock_early_execute", "INV-08",
			"Treasury execution at 12h (< 24h min_timelock) rejected",
			st, []GovernanceAction{a}, VerdictDeny, CodeTimelockNotElapsed)
	}
	{
		st := baseFixtureState(kr)
		st.QueuedActions = append(st.QueuedActions, QueuedAction{
			ID: "p-tl-40", Kind: "TREASURY", ProposerID: "council_1", Target: "grant_40",
			Amount: 1000, QueuedAt: BaseEpoch, MinTimelockSec: MinTimelockTreasurySec,
		})
		a := kr.sign(GovernanceAction{
			ID: "act-tl-40", Type: ActionTreasuryExecute, ActorID: "council_1", Target: "grant_40",
			Epoch: BaseEpoch + 3600, ProposalID: "p-tl-40", Amount: 1000, EmergencyBypass: true,
		}, map[string]uint64{"council_1": 1, "council_2": 1, "council_3": 1}, []string{"council_1", "council_2", "council_3"})
		addCase("adv_40_treasury_timelock_emergency_bypass_claim", "INV-08",
			"Emergency bypass flag cannot circumvent 24h treasury timelock",
			st, []GovernanceAction{a}, VerdictDeny, CodeTimelockNotElapsed)
	}
	{
		st := baseFixtureState(kr)
		st.QueuedActions = append(st.QueuedActions, QueuedAction{
			ID: "amend-41", Kind: "RULE_AMEND", ProposerID: "council_1", Target: "rule_41",
			QueuedAt: BaseEpoch, MinTimelockSec: MinTimelockRuleAmendSec,
			NewRule: &PolicyRule{ID: "R-TL-41", Tier: TierCharterStatute, ActionType: "*", Target: "*", Effect: EffectAllow, Condition: "ALWAYS", Rationale: "early"},
		})
		a := kr.sign(GovernanceAction{
			ID: "act-tl-41", Type: ActionRuleAmendExecute, ActorID: "council_1", Target: "rule_41",
			Epoch: BaseEpoch + 24*3600, ProposalID: "amend-41",
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		addCase("adv_41_rule_amend_timelock_early_execute", "INV-08",
			"Rule amendment execution at 24h (< 48h min_timelock) rejected",
			st, []GovernanceAction{a}, VerdictDeny, CodeTimelockNotElapsed)
	}

	// ==================== GROUP I: INV-09 Cryptographic Provenance & Replay Defense (3 cases) ====================
	{
		st := baseFixtureState(kr)
		a := kr.sign(GovernanceAction{
			ID: "act-sig-42", Type: ActionAdvisoryRecommend, ActorID: "council_1", Target: "memo",
			Epoch: BaseEpoch + 10,
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		// Flip last hex char of Ed25519 signature.
		sigHex := a.Signers[0].SignatureHex
		if sigHex[len(sigHex)-1] == '0' {
			sigHex = sigHex[:len(sigHex)-1] + "1"
		} else {
			sigHex = sigHex[:len(sigHex)-1] + "0"
		}
		a.Signers[0].SignatureHex = sigHex
		addCase("adv_42_invalid_ed25519_signature", "INV-09",
			"Tampered RFC 8032 Ed25519 signature byte rejected",
			st, []GovernanceAction{a}, VerdictDeny, CodeInvalidSignature)
	}
	{
		st := baseFixtureState(kr)
		a1 := kr.sign(GovernanceAction{
			ID: "act-rep-43a", Type: ActionAdvisoryRecommend, ActorID: "council_1", Target: "memo-1",
			Epoch: BaseEpoch + 10,
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		a2 := kr.sign(GovernanceAction{
			ID: "act-rep-43b", Type: ActionAdvisoryRecommend, ActorID: "council_1", Target: "memo-2",
			Epoch: BaseEpoch + 20,
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		addCase("adv_43_nonce_replay_attack", "INV-09",
			"Reused actor nonce rejected as replay attack",
			st, []GovernanceAction{a1, a2}, VerdictDeny, CodeReplayNonce)
	}
	{
		st := baseFixtureState(kr)
		a := kr.sign(GovernanceAction{
			ID: "act-ep-44", Type: ActionAdvisoryRecommend, ActorID: "council_1", Target: "memo-past",
			Epoch: BaseEpoch - 10,
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		addCase("adv_44_epoch_regression_attack", "INV-09",
			"Action carrying backwards epoch (< state.epoch) rejected",
			st, []GovernanceAction{a}, VerdictDeny, CodeEpochRegression)
	}

	// ==================== GROUP J: INV-10 Concurrent Interleaving Non-Escalation (2 cases) ====================
	{
		st := baseFixtureState(kr)
		st.QueuedActions = append(st.QueuedActions, QueuedAction{
			ID: "p-int-45", Kind: "TREASURY", ProposerID: "human_1", Target: "grant_45",
			Amount: 1000, QueuedAt: BaseEpoch - MinTimelockTreasurySec - 10, MinTimelockSec: MinTimelockTreasurySec,
		})
		a1 := kr.sign(GovernanceAction{
			ID: "act-int-45a", Type: ActionSuspendActor, ActorID: "council_1", Target: "human_1",
			Epoch: BaseEpoch + 10, ContestedID: "cont-45",
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		a2 := kr.sign(GovernanceAction{
			ID: "act-int-45b", Type: ActionAppealFile, ActorID: "human_1", Target: "cont-45",
			Epoch: BaseEpoch + 20, ContestedID: "cont-45",
		}, map[string]uint64{"human_1": 1}, []string{"human_1"})
		a3 := kr.sign(GovernanceAction{
			ID: "act-int-45c", Type: ActionTreasuryExecute, ActorID: "human_1", Target: "grant_45",
			Epoch: BaseEpoch + 30, ProposalID: "p-int-45", Amount: 1000,
		}, map[string]uint64{"human_1": 2}, []string{"human_1"})
		addCase("adv_45_suspended_actor_exploits_pending_appeal_window", "INV-10",
			"Suspended actor with pending appeal cannot execute treasury spend during appeal freeze",
			st, []GovernanceAction{a1, a2, a3}, VerdictDeny, CodeActorSuspended)
	}
	{
		st := baseFixtureState(kr)
		a1 := kr.sign(GovernanceAction{
			ID: "act-int-46a", Type: ActionDelegate, ActorID: "human_1", Target: "human_2",
			Epoch: BaseEpoch + 10, DurationSec: 500000, Scopes: []string{ScopeTreasurySpend}, DelegationID: "d-46",
		}, map[string]uint64{"human_1": 1}, []string{"human_1"})
		a2 := kr.sign(GovernanceAction{
			ID: "act-int-46b", Type: ActionTreasuryQueue, ActorID: "human_2", Target: "grant_46",
			Epoch: BaseEpoch + 20, Amount: 2000, DelegationID: "d-46", ProposalID: "p-46",
		}, map[string]uint64{"human_2": 1, "council_2": 1}, []string{"human_2", "council_2"})
		a3 := kr.sign(GovernanceAction{
			ID: "act-int-46c", Type: ActionEmergencyPause, ActorID: "council_1", Target: "bridge",
			Epoch: BaseEpoch + 30, DurationSec: MaxEmergencyDurationSec,
		}, map[string]uint64{"council_1": 1, "council_2": 2, "council_3": 1}, []string{"council_1", "council_2", "council_3"})
		a4 := kr.sign(GovernanceAction{
			ID: "act-int-46d", Type: ActionSuspendActor, ActorID: "council_1", Target: "human_1",
			Epoch: BaseEpoch + 40, ContestedID: "cont-46",
		}, map[string]uint64{"council_1": 2}, []string{"council_1"})
		a5 := kr.sign(GovernanceAction{
			ID: "act-int-46e", Type: ActionFinalizeContested, ActorID: "council_1", Target: "human_1",
			Epoch: BaseEpoch + 40 + AppealWindowSec + 10, ContestedID: "cont-46",
		}, map[string]uint64{"council_1": 3}, []string{"council_1"})
		// After DEFCON-1 auto-sunsets AND human_1's suspension finalized into revocation, human_2 tries to execute p-46.
		a6 := kr.sign(GovernanceAction{
			ID: "act-int-46f", Type: ActionTreasuryExecute, ActorID: "human_2", Target: "grant_46",
			Epoch: BaseEpoch + 30 + MaxEmergencyDurationSec + 100, ProposalID: "p-46", Amount: 2000,
		}, map[string]uint64{"human_2": 2}, []string{"human_2"})
		addCase("adv_46_concurrent_revocation_during_appeal_and_defcon", "INV-10",
			"Interleaved DEFCON-1 sunset + finalized suspension revocation invalidates delegatee's queued treasury spend",
			st, []GovernanceAction{a1, a2, a3, a4, a5, a6}, VerdictDeny, CodeProposerAuthorityRevoked)
	}
	{
		// Fuzzer-discovered concurrent interleaving regression (INV-02 + INV-10):
		// human_1 -> human_2 -> council_1; suspend human_2 (dormant edges); council_1 tries to delegate -> human_1
		// so that overturning human_2's suspension would resurrect a 3-hop cycle!
		st := baseFixtureState(kr)
		a1 := kr.sign(GovernanceAction{
			ID: "act-int-47a", Type: ActionDelegate, ActorID: "human_1", Target: "human_2",
			Epoch: BaseEpoch + 10, DurationSec: 200000, Scopes: []string{ScopeVoteStandard}, DelegationID: "d-47a",
		}, map[string]uint64{"human_1": 1}, []string{"human_1"})
		a2 := kr.sign(GovernanceAction{
			ID: "act-int-47b", Type: ActionDelegate, ActorID: "human_2", Target: "council_1",
			Epoch: BaseEpoch + 20, DurationSec: 100000, Scopes: []string{ScopeVoteStandard}, DelegationID: "d-47b",
		}, map[string]uint64{"human_2": 1}, []string{"human_2"})
		a3 := kr.sign(GovernanceAction{
			ID: "act-int-47c", Type: ActionSuspendActor, ActorID: "council_1", Target: "human_2",
			Epoch: BaseEpoch + 30, ContestedID: "cont-47",
		}, map[string]uint64{"council_1": 1}, []string{"council_1"})
		a4 := kr.sign(GovernanceAction{
			ID: "act-int-47d", Type: ActionDelegate, ActorID: "council_1", Target: "human_1",
			Epoch: BaseEpoch + 40, DurationSec: 100000, Scopes: []string{ScopeVoteStandard}, DelegationID: "d-47c",
		}, map[string]uint64{"council_1": 2}, []string{"council_1"})
		addCase("adv_47_dormant_suspension_cycle_resurrection", "INV-10",
			"Fuzzer-discovered attack: delegating across dormant suspended-actor edges to resurrect a cycle on appeal overturn rejected",
			st, []GovernanceAction{a1, a2, a3, a4}, VerdictDeny, CodeDelegationCycle)
	}

	report := AdversarialSuiteReport{
		TotalCases: len(cases),
		Cases:      cases,
	}
	for _, c := range cases {
		if c.ExpectedVerdict == VerdictDeny {
			report.AdversarialDenyCases++
		} else {
			report.PositiveAllowCases++
		}
		if c.Passed {
			report.Passed++
		} else {
			report.Failed++
		}
	}
	if report.TotalCases != 47 {
		panic(fmt.Sprintf("expected 47 adversarial cases, got %d", report.TotalCases))
	}
	return report
}

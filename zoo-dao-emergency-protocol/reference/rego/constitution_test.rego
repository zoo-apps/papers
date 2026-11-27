# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.
#
# OPA Rego v1 Unit Test Suite for constitutional-gov.v1.
# Run with: opa test rego/ -v

package govcheck.constitution_test

import rego.v1
import data.govcheck.constitution
import data.govcheck.conflict

base_state := {
	"epoch": 1700000000,
	"treasury_balance": 10000000,
	"genesis_active_weight": 100,
	"actors": [
		{"id": "alice", "role": "COUNCIL_MEMBER", "voting_weight": 25, "status": "ACTIVE", "last_nonce": 0, "base_scopes": ["VOTE_STANDARD", "TREASURY_SPEND", "RULE_AMEND", "EMERGENCY_PAUSE"]},
		{"id": "bob", "role": "COUNCIL_MEMBER", "voting_weight": 25, "status": "ACTIVE", "last_nonce": 0, "base_scopes": ["VOTE_STANDARD", "TREASURY_SPEND", "RULE_AMEND", "EMERGENCY_PAUSE"]},
		{"id": "carol", "role": "COUNCIL_MEMBER", "voting_weight": 25, "status": "ACTIVE", "last_nonce": 0, "base_scopes": ["VOTE_STANDARD", "TREASURY_SPEND", "RULE_AMEND", "EMERGENCY_PAUSE"]},
		{"id": "judge1", "role": "APPEAL_JUDGE", "voting_weight": 25, "status": "ACTIVE", "last_nonce": 0, "base_scopes": ["VOTE_STANDARD", "APPEAL_ADJUDICATE"]},
		{"id": "ai_bot", "role": "AI_AGENT", "voting_weight": 0, "status": "ACTIVE", "last_nonce": 0, "base_scopes": ["ADVISORY_RECOMMEND", "FLAG_CONFLICT"]},
	],
	"delegations": [],
	"rules": [
		{"id": "R-CONST-01", "tier": "CONSTITUTIONAL", "action_type": "TREASURY_EXECUTE", "target": "*", "effect": "DENY", "condition": "ACTOR_IS_AI", "rationale": "INV-01"},
		{"id": "R-CHARTER-01", "tier": "CHARTER_STATUTE", "action_type": "TREASURY_EXECUTE", "target": "*", "effect": "ALLOW", "condition": "ALWAYS", "rationale": "Standard treasury"},
	],
	"queued_actions": [
		{"id": "prop-1", "queued_at": 1700000000},
	],
	"contested_actions": [
		{"id": "cont-1", "initiator_id": "alice", "target_actor_id": "bob", "appeal_deadline": 1700172800, "appeal_status": "PENDING"},
	],
	"emergency": {
		"paused": false,
		"pause_started_at": 0,
		"pause_expires_at": 0,
		"unreviewed_count": 0,
	},
}

test_inv01_ai_cannot_spend_treasury if {
	res := constitution.decision with input as {
		"state": base_state,
		"action": {
			"id": "a1",
			"type": "TREASURY_EXECUTE",
			"actor_id": "ai_bot",
			"target": "grant_pool",
			"epoch": 1700100000,
			"proposal_id": "prop-1",
			"amount": 1000,
			"delegation_id": "",
			"signers": [{"actor_id": "ai_bot", "nonce": 1}],
		},
	}
	res.verdict == "DENY"
	"ERR_AI_CONSTITUTIONAL_VIOLATION" in res.violations
}

test_inv02_delegation_cycle_blocked if {
	st := object.union(base_state, {
		"delegations": [
			{"id": "d1", "from": "alice", "to": "bob", "scopes": ["VOTE_STANDARD"], "expires_at": 1700500000, "revoked": false},
			{"id": "d2", "from": "bob", "to": "carol", "scopes": ["VOTE_STANDARD"], "expires_at": 1700500000, "revoked": false},
		],
	})
	res := constitution.decision with input as {
		"state": st,
		"action": {
			"id": "a2",
			"type": "DELEGATE",
			"actor_id": "carol",
			"target": "alice",
			"epoch": 1700000100,
			"duration_sec": 3600,
			"scopes": ["VOTE_STANDARD"],
			"delegation_id": "",
			"signers": [{"actor_id": "carol", "nonce": 1}],
		},
	}
	res.verdict == "DENY"
	"ERR_DELEGATION_CYCLE" in res.violations
}

test_inv05_defcon1_blocks_treasury_and_caps_72h if {
	paused_state := object.union(base_state, {
		"emergency": {"paused": true, "pause_started_at": 1700000000, "pause_expires_at": 1700259200, "unreviewed_count": 0},
	})
	res := constitution.decision with input as {
		"state": paused_state,
		"action": {
			"id": "a3",
			"type": "TREASURY_EXECUTE",
			"actor_id": "alice",
			"target": "grant_pool",
			"epoch": 1700100000,
			"proposal_id": "prop-1",
			"amount": 1000,
			"delegation_id": "",
			"signers": [{"actor_id": "alice", "nonce": 1}],
		},
	}
	res.verdict == "DENY"
	"ERR_PAUSED_ACTION_FORBIDDEN" in res.violations
}

test_inv06_self_adjudication_blocked if {
	res := constitution.decision with input as {
		"state": base_state,
		"action": {
			"id": "a4",
			"type": "APPEAL_RESOLVE",
			"actor_id": "alice",
			"target": "cont-1",
			"contested_id": "cont-1",
			"epoch": 1700010000,
			"delegation_id": "",
			"signers": [{"actor_id": "alice", "nonce": 1}, {"actor_id": "judge1", "nonce": 1}],
		},
	}
	res.verdict == "DENY"
	"ERR_SELF_ADJUDICATION" in res.violations
}

test_inv07_same_tier_conflict_fails_closed if {
	conflict_state := object.union(base_state, {
		"rules": [
			{"id": "R-CHARTER-ALLOW", "tier": "CHARTER_STATUTE", "action_type": "TREASURY_EXECUTE", "target": "grant_pool", "effect": "ALLOW", "condition": "ALWAYS", "rationale": "Allow grant"},
			{"id": "R-CHARTER-DENY", "tier": "CHARTER_STATUTE", "action_type": "TREASURY_EXECUTE", "target": "grant_pool", "effect": "DENY", "condition": "ALWAYS", "rationale": "Freeze grant"},
		],
	})
	res := constitution.decision with input as {
		"state": conflict_state,
		"action": {
			"id": "a5",
			"type": "TREASURY_EXECUTE",
			"actor_id": "alice",
			"target": "grant_pool",
			"epoch": 1700100000,
			"proposal_id": "prop-1",
			"amount": 1000,
			"delegation_id": "",
			"signers": [{"actor_id": "alice", "nonce": 1}],
		},
	}
	res.verdict == "DENY"
	"ERR_DENY_RULE_CONFLICT" in res.violations
	witness := conflict.conflict_witness with input as {
		"state": conflict_state,
		"action": {
			"id": "a5",
			"type": "TREASURY_EXECUTE",
			"actor_id": "alice",
			"target": "grant_pool",
			"epoch": 1700100000,
			"proposal_id": "prop-1",
			"amount": 1000,
			"delegation_id": "",
			"signers": [{"actor_id": "alice", "nonce": 1}],
		},
	}
	witness.resolution == "DENY_RULE_CONFLICT"
}

test_inv08_timelock_non_bypassable if {
	res := constitution.decision with input as {
		"state": base_state,
		"action": {
			"id": "a6",
			"type": "TREASURY_EXECUTE",
			"actor_id": "alice",
			"target": "grant_pool",
			"epoch": 1700043200,
			"proposal_id": "prop-1",
			"amount": 1000,
			"emergency_bypass": true,
			"delegation_id": "",
			"signers": [{"actor_id": "alice", "nonce": 1}],
		},
	}
	res.verdict == "DENY"
	"ERR_TIMELOCK_NOT_ELAPSED" in res.violations
}

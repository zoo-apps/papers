# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.
#
# Constitutional Governance Policy Bundle (constitutional-gov.v1, v1.0.0)
# Module: constitution.rego — Master policy aggregating INV-01 through INV-10.

package govcheck.constitution

import rego.v1
import data.govcheck.conflict
import data.govcheck.delegation
import data.govcheck.emergency

default allow := false

min_timelock_treasury_sec := 86400
min_timelock_rule_amend_sec := 172800
quorum_floor_bps := 5000
supermajority_emergency_bps := 6700
supermajority_meta_gov_bps := 7500

ai_forbidden_actions := {
	"TREASURY_QUEUE",
	"TREASURY_EXECUTE",
	"RULE_AMEND_QUEUE",
	"RULE_AMEND_EXECUTE",
	"EMERGENCY_PAUSE",
	"EMERGENCY_RENEW",
	"EXPERIMENT_VALIDATE",
	"APPEAL_RESOLVE",
	"REVOKE_ACTOR",
}

actor_by_id[a.id] := a if {
	some a in input.state.actors
}

# INV-01: AI Constitutional Boundary.
violations contains "ERR_AI_CONSTITUTIONAL_VIOLATION" if {
	actor := actor_by_id[input.action.actor_id]
	actor.role == "AI_AGENT"
	input.action.type in ai_forbidden_actions
}

violations contains "ERR_AI_CONSTITUTIONAL_VIOLATION" if {
	some sig in input.action.signers
	actor := actor_by_id[sig.actor_id]
	actor.role == "AI_AGENT"
	input.action.type in ai_forbidden_actions
}

# INV-03 & INV-10: Revoked or suspended actors cannot execute sovereign actions.
violations contains "ERR_ACTOR_REVOKED" if {
	actor := actor_by_id[input.action.actor_id]
	actor.status == "REVOKED"
}

violations contains "ERR_ACTOR_SUSPENDED" if {
	actor := actor_by_id[input.action.actor_id]
	actor.status == "SUSPENDED"
	input.action.type != "APPEAL_FILE"
}

# INV-04: Duplicate signer detection & quorum floor / supermajority checks.
signer_ids := [s.actor_id | some s in input.action.signers]
unique_signer_ids := {s.actor_id | some s in input.action.signers}

violations contains "ERR_DUPLICATE_SIGNER" if {
	count(signer_ids) != count(unique_signer_ids)
}

active_human_weight := sum([a.voting_weight |
	some a in input.state.actors
	a.status == "ACTIVE"
	a.role != "AI_AGENT"
])

signed_active_weight := sum([actor_by_id[id].voting_weight |
	some id in unique_signer_ids
	actor_by_id[id].status == "ACTIVE"
	actor_by_id[id].role != "AI_AGENT"
])

quorum_floor_weight := (input.state.genesis_active_weight * quorum_floor_bps) / 10000

violations contains "ERR_QUORUM_FLOOR_BREACHED" if {
	input.action.type in {"TREASURY_QUEUE", "RULE_AMEND_QUEUE"}
	active_human_weight < quorum_floor_weight
}

violations contains "ERR_SUPERMAJORITY_NOT_MET" if {
	input.action.type == "RULE_AMEND_QUEUE"
	active_human_weight >= quorum_floor_weight
	active_human_weight > 0
	((signed_active_weight * 10000) / active_human_weight) < supermajority_meta_gov_bps
}

# INV-06: Appeal due-process freeze & zero self-adjudication.
violations contains "ERR_APPEAL_WINDOW_OPEN" if {
	input.action.type == "FINALIZE_CONTESTED"
	some c in input.state.contested_actions
	c.id == input.action.contested_id
	input.action.epoch < c.appeal_deadline
}

violations contains "ERR_APPEAL_FREEZE_ACTIVE" if {
	input.action.type == "FINALIZE_CONTESTED"
	some c in input.state.contested_actions
	c.id == input.action.contested_id
	c.appeal_status == "PENDING"
}

violations contains "ERR_SELF_ADJUDICATION" if {
	input.action.type == "APPEAL_RESOLVE"
	some c in input.state.contested_actions
	c.id == input.action.contested_id
	some s in input.action.signers
	s.actor_id in {c.initiator_id, c.target_actor_id}
}

# INV-08: Timelock non-bypassability.
violations contains "ERR_TIMELOCK_NOT_ELAPSED" if {
	input.action.type == "TREASURY_EXECUTE"
	some q in input.state.queued_actions
	q.id == input.action.proposal_id
	input.action.epoch < (q.queued_at + min_timelock_treasury_sec)
}

violations contains "ERR_TIMELOCK_NOT_ELAPSED" if {
	input.action.type == "RULE_AMEND_EXECUTE"
	some q in input.state.queued_actions
	q.id == input.action.proposal_id
	input.action.epoch < (q.queued_at + min_timelock_rule_amend_sec)
}

# INV-09: Monotonic epoch & nonce replay defense (Ed25519 signature check runs in verifier).
violations contains "ERR_EPOCH_REGRESSION" if {
	input.action.epoch < input.state.epoch
}

violations contains "ERR_REPLAY_NONCE" if {
	some s in input.action.signers
	actor := actor_by_id[s.actor_id]
	s.nonce <= actor.last_nonce
}

# Aggregate all module violations.
all_violations := ((violations | delegation.violations) | emergency.violations) | conflict.violations

allow if {
	count(all_violations) == 0
}

decision := {
	"verdict": "ALLOW",
	"violations": [],
} if {
	allow
} else := {
	"verdict": "DENY",
	"violations": sort([v | some v in all_violations]),
	"conflict_witness": object.get(conflict, "conflict_witness", null),
}

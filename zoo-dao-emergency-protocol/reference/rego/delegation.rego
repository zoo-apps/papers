# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.
#
# Constitutional Governance Policy Bundle (constitutional-gov.v1, v1.0.0)
# Module: delegation.rego — INV-02 (Acyclic Bounded Delegation & Scope Attenuation)
# and INV-03 (Immediate Transitive Revocation).

package govcheck.delegation

import rego.v1

max_delegation_depth := 3

sovereign_scopes := {
	"TREASURY_SPEND",
	"RULE_AMEND",
	"EMERGENCY_PAUSE",
	"EMERGENCY_SPEND",
	"EXPERIMENT_VALIDATE",
	"APPEAL_ADJUDICATE",
	"REVOKE_MEMBER",
}

actor_by_id[a.id] := a if {
	some a in input.state.actors
}

# Active (non-revoked, non-expired, both endpoints ACTIVE) delegation edges.
active_edges contains d if {
	some d in input.state.delegations
	d.revoked == false
	d.expires_at > input.action.epoch
	actor_by_id[d.from].status == "ACTIVE"
	actor_by_id[d.to].status == "ACTIVE"
}

# Non-revoked, non-expired edges including SUSPENDED actors so overturning a
# temporary suspension via INV-06 appeal cannot resurrect a delegation cycle.
non_revoked_edges contains d if {
	some d in input.state.delegations
	d.revoked == false
	d.expires_at > input.action.epoch
	actor_by_id[d.from].status != "REVOKED"
	actor_by_id[d.to].status != "REVOKED"
}

# Build directed adjacency map for reachability / cycle detection.
edge_graph[u] := neighbors if {
	some u, _ in actor_by_id
	neighbors := {d.to | some d in non_revoked_edges; d.from == u}
}

# INV-02: Detect self-delegation or cycle if proposed DELEGATE edge (from -> to)
# makes delegator reachable from delegatee.
proposed_creates_cycle if {
	input.action.type == "DELEGATE"
	input.action.actor_id == input.action.target
}

proposed_creates_cycle if {
	input.action.type == "DELEGATE"
	reachable := graph.reachable(edge_graph, {input.action.target})
	input.action.actor_id in reachable
}

# Compute incoming chain depth up to max_delegation_depth + 1 (bounded 4-hop check).
has_depth_1(node) if {
	some d1 in active_edges
	d1.to == node
}

has_depth_2(node) if {
	some d1 in active_edges
	d1.to == node
	has_depth_1(d1.from)
}

has_depth_3(node) if {
	some d1 in active_edges
	d1.to == node
	has_depth_2(d1.from)
}

# Adding edge actor_id -> target would exceed max_delegation_depth (3) if actor_id
# already sits at depth >= 3.
proposed_exceeds_depth if {
	input.action.type == "DELEGATE"
	has_depth_3(input.action.actor_id)
}

# Effective scopes of an actor: base_scopes union active non-revoked incoming delegation scopes.
effective_scopes(actor_id) := base | inherited if {
	actor := actor_by_id[actor_id]
	actor.status == "ACTIVE"
	base := {s | some s in actor.base_scopes}
	inherited := {s |
		some d in active_edges
		d.to == actor_id
		some s in d.scopes
	}
}

# INV-02: Scope attenuation check — delegator cannot grant scopes it does not hold.
proposed_escalates_scope if {
	input.action.type == "DELEGATE"
	held := effective_scopes(input.action.actor_id)
	some req in input.action.scopes
	not (req in held)
}

# INV-02: Expiry monotonicity — if delegator relies on delegated scope (not base_scopes),
# expiry cannot exceed the authorizing parent delegation's expires_at.
proposed_escalates_expiry if {
	input.action.type == "DELEGATE"
	actor := actor_by_id[input.action.actor_id]
	base := {s | some s in actor.base_scopes}
	req_expires := input.action.epoch + input.action.duration_sec
	some req in input.action.scopes
	not (req in base)
	parent_expiries := [d.expires_at |
		some d in active_edges
		d.to == input.action.actor_id
		req in d.scopes
	]
	count(parent_expiries) > 0
	req_expires > max(parent_expiries)
}

# INV-01 boundary on delegation: never delegate sovereign scopes to AI_AGENT.
proposed_ai_sovereign_delegation if {
	input.action.type == "DELEGATE"
	target := actor_by_id[input.action.target]
	target.role == "AI_AGENT"
	some s in input.action.scopes
	s in sovereign_scopes
}

# INV-03: Referenced delegation must not be revoked or derived from a revoked ancestor.
referenced_delegation_revoked if {
	input.action.delegation_id != ""
	some d in input.state.delegations
	d.id == input.action.delegation_id
	d.revoked == true
}

referenced_delegation_revoked if {
	input.action.delegation_id != ""
	some d in input.state.delegations
	d.id == input.action.delegation_id
	actor_by_id[d.from].status == "REVOKED"
}

violations contains "ERR_AI_CONSTITUTIONAL_VIOLATION" if {
	proposed_ai_sovereign_delegation
}

violations contains "ERR_DELEGATION_CYCLE" if {
	proposed_creates_cycle
}

violations contains "ERR_DELEGATION_DEPTH_EXCEEDED" if {
	proposed_exceeds_depth
}

violations contains "ERR_DELEGATION_SCOPE_ESCALATION" if {
	proposed_escalates_scope
}

violations contains "ERR_DELEGATION_EXPIRY_ESCALATION" if {
	proposed_escalates_expiry
}

violations contains "ERR_DELEGATION_REVOKED" if {
	referenced_delegation_revoked
}

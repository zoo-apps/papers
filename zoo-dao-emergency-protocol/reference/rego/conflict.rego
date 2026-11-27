# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.
#
# Constitutional Governance Policy Bundle (constitutional-gov.v1, v1.0.0)
# Module: conflict.rego — INV-07 Deterministic Rule-Precedence Hierarchy
# and Fail-Closed Conflict Resolution.

package govcheck.conflict

import rego.v1

# Strict 4-tier constitutional precedence hierarchy:
# CONSTITUTIONAL (4) > EMERGENCY_SAFETY (3) > CHARTER_STATUTE (2) > ADVISORY_POLICY (1)
tier_rank := {
	"CONSTITUTIONAL": 4,
	"EMERGENCY_SAFETY": 3,
	"CHARTER_STATUTE": 2,
	"ADVISORY_POLICY": 1,
}

# Evaluate whether a policy rule condition holds under the current input state.
condition_holds(rule) if {
	rule.condition == "ALWAYS"
}

condition_holds(rule) if {
	rule.condition == "WHEN_PAUSED"
	input.state.emergency.paused == true
	input.action.epoch < input.state.emergency.pause_expires_at
}

condition_holds(rule) if {
	rule.condition == "ACTOR_IS_AI"
	some a in input.state.actors
	a.id == input.action.actor_id
	a.role == "AI_AGENT"
}

condition_holds(rule) if {
	rule.condition == "AMOUNT_GT_CAP"
	cap := (input.state.treasury_balance * 500) / 10000
	input.action.amount > cap
}

condition_holds(rule) if {
	rule.condition == "NO_TIMELOCK"
	input.action.emergency_bypass == true
}

condition_holds(rule) if {
	rule.condition == "UNREVIEWED_EMERGENCY"
	input.state.emergency.unreviewed_count > 0
}

rule_matches(rule) if {
	rule.action_type == input.action.type
	rule.target == input.action.target
	condition_holds(rule)
}

rule_matches(rule) if {
	rule.action_type == input.action.type
	rule.target == "*"
	condition_holds(rule)
}

rule_matches(rule) if {
	rule.action_type == "*"
	rule.target == input.action.target
	condition_holds(rule)
}

rule_matches(rule) if {
	rule.action_type == "*"
	rule.target == "*"
	condition_holds(rule)
}

matching_rules contains rule if {
	some rule in input.state.rules
	rule_matches(rule)
}

matching_ranks contains rank if {
	some rule in matching_rules
	rank := tier_rank[rule.tier]
}

highest_rank := max(matching_ranks) if {
	count(matching_ranks) > 0
}

highest_tier_rules contains rule if {
	some rule in matching_rules
	tier_rank[rule.tier] == highest_rank
}

highest_tier_allows contains rule.id if {
	some rule in highest_tier_rules
	rule.effect == "ALLOW"
}

highest_tier_denies contains rule.id if {
	some rule in highest_tier_rules
	rule.effect == "DENY"
}

highest_tier_name := name if {
	some name, r in tier_rank
	r == highest_rank
}

# INV-07: Same-tier contradictory ALLOW and DENY rules MUST fail closed.
has_same_tier_conflict if {
	count(highest_tier_allows) > 0
	count(highest_tier_denies) > 0
}

conflict_witness := {
	"tier": highest_tier_name,
	"allow_rule_ids": sort([id | some id in highest_tier_allows]),
	"deny_rule_ids": sort([id | some id in highest_tier_denies]),
	"action_id": input.action.id,
	"action_type": input.action.type,
	"target": input.action.target,
	"epoch": input.action.epoch,
	"resolution": "DENY_RULE_CONFLICT",
} if {
	has_same_tier_conflict
}

# Detect lower-tier ALLOW trying to override a CONSTITUTIONAL DENY.
constitutional_override_attempted if {
	not has_same_tier_conflict
	highest_tier_name == "CONSTITUTIONAL"
	count(highest_tier_denies) > 0
	some lower in matching_rules
	tier_rank[lower.tier] < 4
	lower.effect == "ALLOW"
}

violations contains "ERR_DENY_RULE_CONFLICT" if {
	has_same_tier_conflict
}

violations contains "ERR_CONSTITUTIONAL_OVERRIDE_BLOCKED" if {
	constitutional_override_attempted
}

violations contains "ERR_POLICY_DENY" if {
	not has_same_tier_conflict
	not constitutional_override_attempted
	count(highest_tier_denies) > 0
}

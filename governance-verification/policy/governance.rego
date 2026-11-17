# Copyright 2024 Zoo Apps
# Licensed under the Apache License, Version 2.0
package zoo.governance

import future.keywords.if
import future.keywords.in

default allow = false

# --- Invariants ---

# 1. Quorum Invariant: A proposal cannot pass without meeting the threshold
quorum_met(proposal) if {
    total_votes := count(proposal.votes)
    total_votes >= proposal.quorum_threshold
}

# 2. Emergency Suspension Invariant: Normal operations must cease if emergency is active
# Reference: Zoo emergency-governance paper
is_suspended if {
    data.emergency_state.active == true
}

# 3. AI Agent Constraint: Agents may recommend but NOT redefine rules or authorize spending
# As per HIP-1352 requirements
action_authorized if {
    input.actor.type == "human"
    input.actor.role in ["admin", "voter"]
}

action_authorized if {
    input.actor.type == "ai_agent"
    input.action.type in ["recommend", "flag_conflict", "estimate_value"]
}

# --- Governance Rules ---

# Allow voting only if not suspended and actor is authorized
allow if {
    not is_suspended
    input.action.type == "vote"
    action_authorized
    input.proposal.status == "active"
}

# Emergency Suspension can only be triggered by authorized emergency-committee
allow if {
    input.action.type == "trigger_emergency"
    input.actor.role == "emergency_committee"
}

# Revocation: A delegation can be revoked at any time by the delegator
allow if {
    input.action.type == "revoke_delegation"
    input.actor.id == input.delegation.owner_id
}

# Conflict Resolution: If two rules conflict, the emergency suspension takes precedence
conflicting_rules if {
    is_suspended
    input.action.type == "execute_proposal"
    # Conflict: Proposal execution attempted during suspension
}

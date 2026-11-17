package zoo.governance_test

import data.zoo.governance

# Test Quorum Logic
test_quorum_met {
    governance.quorum_met({"votes": [1, 2, 3], "quorum_threshold": 2})
}

test_quorum_not_met {
    not governance.quorum_met({"votes": [1], "quorum_threshold": 2})
}

# Adversarial Test: AI Agent attempting to authorize treasury spending (Should Fail)
test_ai_unauthorized_spending {
    not governance.allow with input as {
        "actor": {"type": "ai_agent", "role": "optimizer"},
        "action": {"type": "authorize_treasury_spending"},
        "proposal": {"status": "active"}
    }
}

# Adversarial Test: Voting during Emergency Suspension (Should Fail)
test_no_voting_during_suspension {
    not governance.allow with input as {
        "actor": {"type": "human", "role": "voter"},
        "action": {"type": "vote"},
        "proposal": {"status": "active"}
    } with data.emergency_state as {"active": true}
}

# Test Revocation Rights
test_revocation_by_owner {
    governance.allow with input as {
        "actor": {"id": "user123"},
        "action": {"type": "revoke_delegation"},
        "delegation": {"owner_id": "user123"}
    }
}

# Adversarial Test: Rule Conflict (Emergency vs Execution)
test_conflict_detection {
    governance.conflicting_rules with input as {
        "action": {"type": "execute_proposal"}
    } with data.emergency_state as {"active": true}
}

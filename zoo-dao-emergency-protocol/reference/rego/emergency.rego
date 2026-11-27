# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.
#
# Constitutional Governance Policy Bundle (constitutional-gov.v1, v1.0.0)
# Module: emergency.rego — INV-05 Bounded Emergency Suspension & Mandatory Auto-Sunset
# (ZIP-0027 DEFCON-1 safety invariants).

package govcheck.emergency

import rego.v1

max_emergency_duration_sec := 259200
renewal_cooldown_sec := 86400

# Pause is active iff paused == true AND epoch < pause_expires_at (mandatory auto-sunset).
is_effectively_paused if {
	input.state.emergency.paused == true
	input.action.epoch < input.state.emergency.pause_expires_at
}

# Actions forbidden while DEFCON-1 emergency pause is active (spend cap = 0 ZOO, no rule edits).
paused_forbidden_actions := {
	"TREASURY_QUEUE",
	"TREASURY_EXECUTE",
	"RULE_AMEND_QUEUE",
	"RULE_AMEND_EXECUTE",
}

violations contains "ERR_PAUSED_ACTION_FORBIDDEN" if {
	is_effectively_paused
	input.action.type in paused_forbidden_actions
}

violations contains "ERR_EMERGENCY_DURATION_EXCEEDED" if {
	input.action.type in {"EMERGENCY_PAUSE", "EMERGENCY_RENEW"}
	input.action.duration_sec > max_emergency_duration_sec
}

violations contains "ERR_EMERGENCY_SELF_RENEWAL" if {
	input.action.type in {"EMERGENCY_PAUSE", "EMERGENCY_RENEW"}
	is_effectively_paused
}

violations contains "ERR_EMERGENCY_COOLDOWN_ACTIVE" if {
	input.action.type == "EMERGENCY_RENEW"
	not is_effectively_paused
	input.state.emergency.pause_expires_at > 0
	input.action.epoch < (input.state.emergency.pause_expires_at + renewal_cooldown_sec)
}

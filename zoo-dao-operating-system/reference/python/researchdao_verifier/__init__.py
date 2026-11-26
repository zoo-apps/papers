# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation & Open ResearchDAO Contributors.

"""Independent pure-stdlib Python 3.12 verifier for Open ResearchDAO OS v1."""

from .verifier import (
    SPEC_VERSION,
    GENESIS_PREV_HASH,
    MAX_EMERGENCY_DURATION_SECONDS,
    TransitionError,
    VerifierMachine,
    replay_full,
    replay_from_checkpoint_file,
    replay_from_latest_checkpoint,
)

__all__ = [
    "SPEC_VERSION",
    "GENESIS_PREV_HASH",
    "MAX_EMERGENCY_DURATION_SECONDS",
    "TransitionError",
    "VerifierMachine",
    "replay_full",
    "replay_from_checkpoint_file",
    "replay_from_latest_checkpoint",
]

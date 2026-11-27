# SPDX-License-Identifier: Apache-2.0
"""Clean-room pure-Python stdlib verifier for attribution-rep.v1 (HIP-1352)."""

from .verifier import (
    SCHEMA_VERSION,
    SPEC_VERSION,
    default_policy,
    verify_suite,
)

__all__ = [
    "SCHEMA_VERSION",
    "SPEC_VERSION",
    "default_policy",
    "verify_suite",
]

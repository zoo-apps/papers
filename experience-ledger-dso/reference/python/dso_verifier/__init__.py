# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation
"""Independent zero-dependency Python 3.12 audit verifier for dso-aggregation.v1."""

from .canonical import (
    FIXED_SCALE,
    SCHEMA_VERSION,
    canonical_cell_leaf_hash,
    canonical_contribution_bytes,
    compute_merkle_root,
    to_micro,
)
from .ed25519 import verify_ed25519
from .verifier import (
    aggregate_round,
    gini_coefficient,
    jains_fairness_index,
    verify_audit_trace,
    verify_contribution,
    verify_results_report,
)

__all__ = [
    "FIXED_SCALE",
    "SCHEMA_VERSION",
    "aggregate_round",
    "canonical_cell_leaf_hash",
    "canonical_contribution_bytes",
    "compute_merkle_root",
    "gini_coefficient",
    "jains_fairness_index",
    "to_micro",
    "verify_audit_trace",
    "verify_contribution",
    "verify_ed25519",
    "verify_results_report",
]

# Copyright 2026 Zoo Labs Foundation & Hanzo Industries.
# SPDX-License-Identifier: Apache-2.0
"""Independent pure-Python stdlib verifier for Proof-of-AI (poai-transcript.v1)."""

from .ed25519 import verify as ed25519_verify
from .field import FIELD_MODULUS, exact_int_gemm, matvec_int8_mod_p, matvec_int64_mod_p, mod_p
from .verifier import (
    KERNEL_PROFILE,
    SCHEMA_VERSION,
    SPEC_VERSION,
    audit_receipt_leaf,
    compute_audit_merkle_root,
    verify_parity_suite,
    verify_transcript,
)

__all__ = [
    "FIELD_MODULUS",
    "KERNEL_PROFILE",
    "SCHEMA_VERSION",
    "SPEC_VERSION",
    "audit_receipt_leaf",
    "compute_audit_merkle_root",
    "ed25519_verify",
    "exact_int_gemm",
    "matvec_int8_mod_p",
    "matvec_int64_mod_p",
    "mod_p",
    "verify_parity_suite",
    "verify_transcript",
]

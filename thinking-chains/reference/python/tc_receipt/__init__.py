# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation and Contributors

"""Zero-dependency Python reference implementation for Thinking Chains canonical receipts."""

from .canonical import (
    CanonicalError,
    canonical_json,
    parse_strict_json,
)
from .ed25519 import (
    ed25519_public_key_from_seed,
    ed25519_sign,
    ed25519_verify,
)
from .merkle import (
    InclusionProof,
    build_inclusion_proof,
    merkle_root,
    verify_inclusion_proof,
)
from .verify import (
    SCHEMA_VERSION,
    VerificationError,
    VerificationResult,
    attestation_message,
    canonical_receipt_hash,
    compute_provenance,
    load_policy,
    verify_batch,
    verify_receipt,
    verify_receipt_bytes,
)

__all__ = [
    "SCHEMA_VERSION",
    "CanonicalError",
    "InclusionProof",
    "VerificationError",
    "VerificationResult",
    "attestation_message",
    "build_inclusion_proof",
    "canonical_json",
    "canonical_receipt_hash",
    "compute_provenance",
    "ed25519_public_key_from_seed",
    "ed25519_sign",
    "ed25519_verify",
    "load_policy",
    "merkle_root",
    "parse_strict_json",
    "verify_batch",
    "verify_inclusion_proof",
    "verify_receipt",
    "verify_receipt_bytes",
]

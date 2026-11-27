# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Independent zero-dependency Python 3.12 verifier for inference-net.v1 (zoo-apps/papers#12)."""

from .canonical import (
    SCHEMA_VERSION,
    SPEC_VERSION,
    canonical_delivery_receipt_bytes,
    canonical_node_advertisement_bytes,
    compute_merkle_root_from_hex_digests,
    compute_output_merkle_root,
    compute_verdict_digest,
)
from .ed25519 import verify_ed25519
from .verifier import (
    VerificationResult,
    verify_capacity_conservation,
    verify_node_advertisement,
    verify_parity_case,
    verify_parity_suite,
)

__all__ = [
    "SCHEMA_VERSION",
    "SPEC_VERSION",
    "VerificationResult",
    "canonical_delivery_receipt_bytes",
    "canonical_node_advertisement_bytes",
    "compute_merkle_root_from_hex_digests",
    "compute_output_merkle_root",
    "compute_verdict_digest",
    "verify_capacity_conservation",
    "verify_ed25519",
    "verify_node_advertisement",
    "verify_parity_case",
    "verify_parity_suite",
]

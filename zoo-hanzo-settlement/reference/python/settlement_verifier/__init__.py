# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""Pure Python 3.12 stdlib verifier for settlement-receipt.v1 (zoo-apps/papers#15)."""

from .ed25519 import verify_ed25519_hex
from .merkle import (
    compute_merkle_root,
    compute_receipt_merkle_leaf,
    empty_merkle_root,
    verify_merkle_proof,
)
from .verifier import (
    PROTOCOL_ID,
    SCHEMA_VERSION,
    canonical_eas_schema_uid,
    verify_trace_bundle,
)

__all__ = [
    "PROTOCOL_ID",
    "SCHEMA_VERSION",
    "canonical_eas_schema_uid",
    "compute_merkle_root",
    "compute_receipt_merkle_leaf",
    "empty_merkle_root",
    "verify_ed25519_hex",
    "verify_merkle_proof",
    "verify_trace_bundle",
]

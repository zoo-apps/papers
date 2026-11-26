# SPDX-License-Identifier: Apache-2.0
"""Independent pure-Python reference replayer and verifier for zoo-experience-ledger/v1."""

from .canonical import (
    EMPTY_MERKLE_DOMAIN,
    SCHEMA_VERSION,
    SIGNING_DOMAIN_EVENT,
    canonical_json,
    compute_event_id,
    compute_policy_sha256,
    compute_state_root_hash,
    sha256_hex,
    sign_event,
    signing_message,
)
from .ed25519 import ed25519_public_key_from_seed, ed25519_sign, ed25519_verify
from .merkle import (
    compute_active_merkle_root,
    generate_merkle_proof,
    verify_merkle_proof,
)
from .replay import create_checkpoint, replay, replay_from_checkpoint, validate_policy
from .vfs import LocalVFSStore, validate_storage_uri

__all__ = [
    "SCHEMA_VERSION",
    "SIGNING_DOMAIN_EVENT",
    "EMPTY_MERKLE_DOMAIN",
    "canonical_json",
    "sha256_hex",
    "compute_policy_sha256",
    "compute_event_id",
    "signing_message",
    "sign_event",
    "compute_state_root_hash",
    "ed25519_public_key_from_seed",
    "ed25519_sign",
    "ed25519_verify",
    "compute_active_merkle_root",
    "generate_merkle_proof",
    "verify_merkle_proof",
    "LocalVFSStore",
    "validate_storage_uri",
    "validate_policy",
    "replay",
    "create_checkpoint",
    "replay_from_checkpoint",
]

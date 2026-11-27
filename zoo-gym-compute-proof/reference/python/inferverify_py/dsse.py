# Copyright 2026 Zoo Labs Foundation / Hanzo Industries.
# Licensed under the Apache License, Version 2.0.
"""in-toto DSSE v1 PAE verification and transparency-log leaf digest."""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from . import ed25519

DSSE_PAYLOAD_TYPE_INTOTO = "application/vnd.in-toto+json"

ERR_NONE = "OK"
ERR_INVALID_ENVELOPE = "ERR_INVALID_ENVELOPE"
ERR_INVALID_PAYLOAD_TYPE = "ERR_INVALID_PAYLOAD_TYPE"
ERR_INVALID_DSSE_SIG = "ERR_INVALID_DSSE_SIG"


def key_id_from_pubkey_hex(pub_hex: str) -> str | None:
    try:
        raw = bytes.fromhex(pub_hex)
    except ValueError:
        return None
    if len(raw) != 32:
        return None
    return hashlib.sha256(raw).digest()[:8].hex()


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    header = f"DSSEv1 {len(payload_type)} {payload_type} {len(payload)} ".encode(
        "utf-8"
    )
    return header + payload


def decode_payload_only(env: dict[str, Any]) -> tuple[bytes | None, str]:
    payload_b64 = env.get("payload", "")
    if not isinstance(payload_b64, str) or not payload_b64:
        return None, ERR_INVALID_ENVELOPE
    try:
        raw = base64.b64decode(payload_b64, validate=True)
    except Exception:
        return None, ERR_INVALID_ENVELOPE
    return raw, ERR_NONE


def verify_dsse_signature(
    env: dict[str, Any], pub_hex: str
) -> tuple[bytes | None, bytes | None, str]:
    if env.get("payloadType") != DSSE_PAYLOAD_TYPE_INTOTO:
        return None, None, ERR_INVALID_PAYLOAD_TYPE
    sigs = env.get("signatures")
    if not isinstance(sigs, list) or len(sigs) == 0:
        return None, None, ERR_INVALID_ENVELOPE
    payload_bytes, err = decode_payload_only(env)
    if err != ERR_NONE or payload_bytes is None:
        return None, None, err

    expected_key_id = key_id_from_pubkey_hex(pub_hex)
    if expected_key_id is None:
        return None, None, ERR_INVALID_DSSE_SIG
    pub_bytes = bytes.fromhex(pub_hex)

    sig_entry = sigs[0]
    if not isinstance(sig_entry, dict) or sig_entry.get("keyid") != expected_key_id:
        return None, None, ERR_INVALID_DSSE_SIG
    try:
        sig_bytes = base64.b64decode(sig_entry.get("sig", ""), validate=True)
    except Exception:
        return None, None, ERR_INVALID_DSSE_SIG
    if len(sig_bytes) != 64:
        return None, None, ERR_INVALID_DSSE_SIG

    pae = dsse_pae(env["payloadType"], payload_bytes)
    if not ed25519.verify(pub_bytes, pae, sig_bytes):
        return None, None, ERR_INVALID_DSSE_SIG
    return payload_bytes, sig_bytes, ERR_NONE


def compute_tlog_leaf_entry_digest(
    job_id: str, payload_bytes: bytes, sig_bytes: bytes, epoch: int
) -> str:
    p_hex = hashlib.sha256(payload_bytes).hexdigest()
    s_hex = hashlib.sha256(sig_bytes).hexdigest()
    canonical = f"inference-verify.v1:tlog-leaf:{job_id}:{p_hex}:{s_hex}:{epoch}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

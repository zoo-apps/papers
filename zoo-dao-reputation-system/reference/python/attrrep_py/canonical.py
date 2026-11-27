# SPDX-License-Identifier: Apache-2.0
"""Bit-identical canonical JSON, SHA-256, EAS AttestationUID, Ed25519 & Merkle root."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List

from . import ed25519

DOMAIN_CANONICAL_TEXT = b"zoo.attrrep.v1.canonical\x00"
DOMAIN_SHINGLE = b"zoo.attrrep.v1.shingle\x00"
DOMAIN_WINNOW_DIGEST = b"zoo.attrrep.v1.winnow\x00"
DOMAIN_CONTRIB_SIG = b"zoo.attrrep.v1.contrib.sig\x00"
DOMAIN_EAS_UID = b"zoo.attrrep.v1.eas.uid\x00"
DOMAIN_EAS_SIG = b"zoo.attrrep.v1.eas.sig\x00"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def domain_sha256_hex(domain: bytes, data: bytes) -> str:
    return hashlib.sha256(domain + data).hexdigest()


def canonical_json(obj: Any) -> bytes:
    """Compact UTF-8 JSON with sorted keys and no HTML escaping (matches Go CanonicalJSON)."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def contribution_sign_message(c: Dict[str, Any]) -> bytes:
    parents = sorted(c.get("parents") or [])
    payload = {
        "author_id": c["author_id"],
        "base_value_micro": int(c["base_value_micro"]),
        "canonical_digest": c["canonical_digest"],
        "category": c["category"],
        "claimed_novelty_bps": int(c["claimed_novelty_bps"]),
        "contribution_id": c["contribution_id"],
        "epoch": int(c["epoch"]),
        "fingerprint_digest": c["fingerprint_digest"],
        "ledger_seq": int(c["ledger_seq"]),
        "parents": parents,
        "raw_sha256": c["raw_sha256"],
        "timestamp": int(c["timestamp"]),
    }
    return DOMAIN_CONTRIB_SIG + canonical_json(payload)


def verify_contribution_signature(c: Dict[str, Any], pub_hex: str) -> bool:
    try:
        pub = bytes.fromhex(pub_hex)
        sig = bytes.fromhex(c.get("signature_hex", ""))
    except ValueError:
        return False
    msg = contribution_sign_message(c)
    return ed25519.verify(pub, msg, sig)


def compute_attestation_uid(a: Dict[str, Any]) -> str:
    payload = {
        "attester": a["attester"],
        "data_digest": a["data_digest"],
        "epoch": int(a["epoch"]),
        "expiration_time": int(a["expiration_time"]),
        "nonce": int(a["nonce"]),
        "recipient": a["recipient"],
        "ref_uid": a["ref_uid"],
        "revocable": bool(a["revocable"]),
        "schema_uid": a["schema_uid"],
        "time": int(a["time"]),
        "weight_bps": int(a["weight_bps"]),
    }
    return "0x" + domain_sha256_hex(DOMAIN_EAS_UID, canonical_json(payload))


def attestation_sign_message(a: Dict[str, Any]) -> bytes:
    payload = {
        "attester": a["attester"],
        "epoch": int(a["epoch"]),
        "nonce": int(a["nonce"]),
        "recipient": a["recipient"],
        "ref_uid": a["ref_uid"],
        "schema_uid": a["schema_uid"],
        "uid": a["uid"],
        "weight_bps": int(a["weight_bps"]),
    }
    return DOMAIN_EAS_SIG + canonical_json(payload)


def verify_attestation_signature(a: Dict[str, Any], pub_hex: str) -> bool:
    try:
        pub = bytes.fromhex(pub_hex)
        sig = bytes.fromhex(a.get("signature_hex", ""))
    except ValueError:
        return False
    msg = attestation_sign_message(a)
    return ed25519.verify(pub, msg, sig)


def merkle_root(leaves: List[bytes]) -> str:
    """RFC 6962-style domain-separated binary SHA-256 Merkle root (matches Go MerkleRoot)."""
    if not leaves:
        return hashlib.sha256(b"").hexdigest()
    level = [hashlib.sha256(b"\x00" + leaf).digest() for leaf in leaves]
    while len(level) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(level), 2):
            if i + 1 == len(level):
                nxt.append(level[i])
            else:
                nxt.append(hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest())
        level = nxt
    return level[0].hex()

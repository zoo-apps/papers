# Copyright 2026 Zoo Labs Foundation & Hanzo Industries.
# SPDX-License-Identifier: Apache-2.0
"""Independent pure-Python stdlib verifier for poai-transcript.v1."""

from __future__ import annotations

import hashlib
import struct
from typing import Any, Sequence

from .ed25519 import verify as ed25519_verify
from .field import FIELD_MODULUS, MAX_DIMENSION, matvec_int8_mod_p, matvec_int64_mod_p
from .matrix import (
    activation_trace_root,
    int8_matrix_merkle_root,
    int8_matrix_sha256,
    int64_matrix_merkle_root,
    int64_matrix_sha256,
    merkle_root,
    vec_sha256,
)

SCHEMA_VERSION = "poai-transcript.v1"
SPEC_VERSION = "1.0.0"
KERNEL_PROFILE = "int8-whole-k-i32-fp2147483647.v1"
SIGNATURE_ALGORITHM = "Ed25519-RFC8032"

CHALLENGE_MODE_BINARY = "binary_01"
CHALLENGE_MODE_FIELD = "field_fp"

CHALLENGE_SOURCE_EXTERNAL = "external_verifier_nonce"
CHALLENGE_SOURCE_FIAT_SHAMIR = "fiat_shamir"

VERDICT_COMPUTE_VERIFIED = "COMPUTE_VERIFIED"
VERDICT_COMPUTE_CORRUPTED = "COMPUTE_CORRUPTED"
VERDICT_INVALID_TRANSCRIPT = "INVALID_TRANSCRIPT"
VERDICT_POLICY_REJECTED = "POLICY_REJECTED"

ERR_BAD_SCHEMA_VERSION = "ERR_BAD_SCHEMA_VERSION"
ERR_BAD_KERNEL_PROFILE = "ERR_BAD_KERNEL_PROFILE"
ERR_BAD_MODULUS = "ERR_BAD_MODULUS"
ERR_BAD_DIMENSIONS = "ERR_BAD_DIMENSIONS"
ERR_BAD_CHALLENGE_MODE = "ERR_BAD_CHALLENGE_MODE"
ERR_BAD_CHALLENGE_SOURCE = "ERR_BAD_CHALLENGE_SOURCE"
ERR_COMMITMENT_MISMATCH_A = "ERR_COMMITMENT_MISMATCH_A"
ERR_COMMITMENT_MISMATCH_B = "ERR_COMMITMENT_MISMATCH_B"
ERR_COMMITMENT_MISMATCH_C = "ERR_COMMITMENT_MISMATCH_C"
ERR_TRACE_ROOT_MISMATCH = "ERR_TRACE_ROOT_MISMATCH"
ERR_HEADER_DIGEST_MISMATCH = "ERR_HEADER_DIGEST_MISMATCH"
ERR_TRANSCRIPT_ID_MISMATCH = "ERR_TRANSCRIPT_ID_MISMATCH"
ERR_INVALID_SIGNATURE = "ERR_INVALID_SIGNATURE"
ERR_CHALLENGE_SEED_MISMATCH = "ERR_CHALLENGE_SEED_MISMATCH"
ERR_FREIVALDS_MISMATCH = "ERR_FREIVALDS_MISMATCH"
ERR_WEAK_FIAT_SHAMIR_GRINDING_RISK = "ERR_WEAK_FIAT_SHAMIR_GRINDING_RISK"
ERR_FORBIDDEN_GOVERNANCE_ACTION = "ERR_FORBIDDEN_GOVERNANCE_ACTION"
ERR_FORBIDDEN_SEMANTIC_CLAIM = "ERR_FORBIDDEN_SEMANTIC_CLAIM"

DOMAIN_HEADER = b"poai:v1:header:"
DOMAIN_CHALLENGE_EXTERNAL = b"poai:v1:challenge:external:"
DOMAIN_CHALLENGE_FIAT_SHAMIR = b"poai:v1:challenge:fiat-shamir:"
DOMAIN_ROUND = b"poai:v1:round:"
DOMAIN_RECEIPT = b"poai:v1:receipt:"

FORBIDDEN_GOVERNANCE_ACTIONS = frozenset(
    {"redefine_voting_rules", "authorize_treasury", "self_declare_valid"}
)


def _lp(s: str) -> bytes:
    raw = s.encode("utf-8")
    return struct.pack("<I", len(raw)) + raw


def _hex32(val: str, field_name: str) -> bytes:
    try:
        raw = bytes.fromhex(val)
    except ValueError as exc:
        raise ValueError(f"invalid hex for {field_name}") from exc
    if len(raw) != 32:
        raise ValueError(f"expected 32-byte hex for {field_name}")
    return raw


def has_weak_fiat_shamir_risk(source: str, mode: str, k: int) -> bool:
    if source != CHALLENGE_SOURCE_FIAT_SHAMIR:
        return False
    if mode == CHALLENGE_MODE_BINARY:
        return k < 40
    if mode == CHALLENGE_MODE_FIELD:
        return k < 2
    return True


def canonical_header_bytes(schema_version: str, spec_version: str, header: dict[str, Any]) -> bytes:
    """Canonical binary serialization matching Go poai.CanonicalHeaderBytes byte-for-byte."""
    dims = header["dims"]
    commitments = header["commitments"]

    parts = [
        DOMAIN_HEADER,
        _lp(schema_version),
        _lp(spec_version),
        _lp(header["job_id"]),
        struct.pack("<Q", int(header["policy_epoch"])),
        _lp(header["kernel_profile"]),
        _lp(header["model_id"]),
        struct.pack("<I", int(header["layer_index"])),
        struct.pack("<III", int(dims["m"]), int(dims["d"]), int(dims["n"])),
        struct.pack("<Q", int(header["field_modulus"])),
        _lp(header["challenge_mode"]),
        _lp(header["challenge_source"]),
        struct.pack("<I", int(header["challenge_rounds_k"])),
        _lp(header.get("verifier_nonce_hex", "")),
        _lp(header.get("prover_salt_hex", "")),
        _hex32(commitments["matrix_a_root"], "matrix_a_root"),
        _hex32(commitments["matrix_b_root"], "matrix_b_root"),
        _hex32(commitments["matrix_c_root"], "matrix_c_root"),
        _hex32(commitments["matrix_a_sha256"], "matrix_a_sha256"),
        _hex32(commitments["matrix_b_sha256"], "matrix_b_sha256"),
        _hex32(commitments["matrix_c_sha256"], "matrix_c_sha256"),
        _hex32(commitments["activation_trace_root"], "activation_trace_root"),
        _hex32(commitments["corpus_manifest_sha256"], "corpus_manifest_sha256"),
        _hex32(header["provider_pubkey_hex"], "provider_pubkey_hex"),
    ]

    sem = header.get("semantic_metadata")
    if sem is None:
        parts.append(b"\x00")
    else:
        parts.append(b"\x01")
        parts.append(_lp(sem.get("claimed_model_purpose", "")))
        parts.append(_lp(sem.get("claimed_truth_statement", "")))
        parts.append(b"\x01" if sem.get("weights_attested", False) else b"\x00")
        parts.append(b"\x01" if sem.get("nonlinearities_verified", False) else b"\x00")
        parts.append(_lp(sem.get("requested_governance_action", "")))

    return b"".join(parts)


def compute_header_digest(schema_version: str, spec_version: str, header: dict[str, Any]) -> bytes:
    return hashlib.sha256(canonical_header_bytes(schema_version, spec_version, header)).digest()


def derive_challenge_seed(
    source: str,
    header_digest: bytes,
    verifier_nonce_hex: str,
    prover_salt_hex: str,
) -> bytes:
    if source == CHALLENGE_SOURCE_EXTERNAL:
        nonce = bytes.fromhex(verifier_nonce_hex)
        if len(nonce) != 32:
            raise ValueError("external_verifier_nonce requires 32-byte hex verifier_nonce_hex")
        return hashlib.sha256(DOMAIN_CHALLENGE_EXTERNAL + header_digest + nonce).digest()
    if source == CHALLENGE_SOURCE_FIAT_SHAMIR:
        salt = bytes.fromhex(prover_salt_hex)
        if len(salt) not in (0, 16):
            raise ValueError("fiat_shamir requires empty or 16-byte hex prover_salt_hex")
        return hashlib.sha256(DOMAIN_CHALLENGE_FIAT_SHAMIR + header_digest + salt).digest()
    raise ValueError(f"unsupported challenge source: {source!r}")


def derive_challenge_vector(mode: str, challenge_seed: bytes, round_idx: int, n: int) -> list[int]:
    if n <= 0:
        raise ValueError(f"invalid vector length {n}")
    round_seed = hashlib.sha256(DOMAIN_ROUND + challenge_seed + struct.pack("<I", round_idx)).digest()

    if mode == CHALLENGE_MODE_BINARY:
        out = [0] * n
        block = b""
        block_idx = -1
        for j in range(n):
            byte_pos = j >> 3
            need_block = byte_pos >> 5
            if need_block != block_idx:
                block_idx = need_block
                block = hashlib.sha256(round_seed + struct.pack("<I", block_idx)).digest()
            b = block[byte_pos & 31]
            out[j] = (b >> (j & 7)) & 1
        return out

    if mode == CHALLENGE_MODE_FIELD:
        out = []
        block_idx = 0
        words: tuple[int, ...] = ()
        word_pos = 8
        while len(out) < n:
            if word_pos >= 8:
                block = hashlib.sha256(round_seed + struct.pack("<I", block_idx)).digest()
                words = struct.unpack("<8I", block)
                block_idx += 1
                word_pos = 0
            v = words[word_pos] & 0x7FFFFFFF
            word_pos += 1
            if v == 0x7FFFFFFF:
                continue
            out.append(v)
        return out

    raise ValueError(f"unsupported challenge mode: {mode!r}")


def verify_transcript(
    tx: dict[str, Any],
    a_data: Sequence[int],
    b_data: Sequence[int],
    c_data: Sequence[int],
) -> dict[str, Any]:
    """Independently verify a poai-transcript.v1 document against matrices (A, B, C)."""
    err_set: set[str] = set()
    receipt: dict[str, Any] = {
        "transcript_id": tx.get("transcript_id", "") if isinstance(tx, dict) else "",
        "header_digest_hex": "",
        "challenge_seed_hex": "",
        "rounds_executed": 0,
        "first_failing_round": -1,
        "round_digests": [],
        "constitutional_boundary": {
            "compute_verdict": VERDICT_INVALID_TRANSCRIPT,
            "proves_matrix_product_only": True,
            "proves_full_model_inference": False,
            "proves_scientific_truth": False,
            "proves_weight_provenance": False,
            "grinding_risk_warning": False,
            "error_codes": [],
        },
    }

    if not isinstance(tx, dict):
        err_set.add(ERR_BAD_SCHEMA_VERSION)
        receipt["constitutional_boundary"]["error_codes"] = sorted(err_set)
        return receipt

    header = tx.get("header", {})
    sig_block = tx.get("signature", {})
    ch_tx = tx.get("challenge_transcript", {})
    cb_in = tx.get("constitutional_boundary", {})

    receipt["header_digest_hex"] = sig_block.get("header_digest_hex", "")
    receipt["challenge_seed_hex"] = ch_tx.get("challenge_seed_hex", "")

    # 1. Constitutional pre-gate (non-bypassable).
    policy_violation = False
    sem = header.get("semantic_metadata")
    if isinstance(sem, dict) and sem.get("requested_governance_action") in FORBIDDEN_GOVERNANCE_ACTIONS:
        err_set.add(ERR_FORBIDDEN_GOVERNANCE_ACTION)
        policy_violation = True
    if (
        cb_in.get("proves_full_model_inference", False)
        or cb_in.get("proves_scientific_truth", False)
        or cb_in.get("proves_weight_provenance", False)
        or not cb_in.get("proves_matrix_product_only", False)
    ):
        err_set.add(ERR_FORBIDDEN_SEMANTIC_CLAIM)
        policy_violation = True

    # 2. Structural & protocol version checks.
    structural_error = False
    if tx.get("schema_version") != SCHEMA_VERSION or tx.get("spec_version") != SPEC_VERSION:
        err_set.add(ERR_BAD_SCHEMA_VERSION)
        structural_error = True
    if header.get("kernel_profile") != KERNEL_PROFILE:
        err_set.add(ERR_BAD_KERNEL_PROFILE)
        structural_error = True
    if header.get("field_modulus") != FIELD_MODULUS:
        err_set.add(ERR_BAD_MODULUS)
        structural_error = True
    mode = header.get("challenge_mode", "")
    if mode not in (CHALLENGE_MODE_BINARY, CHALLENGE_MODE_FIELD):
        err_set.add(ERR_BAD_CHALLENGE_MODE)
        structural_error = True
    source = header.get("challenge_source", "")
    if source not in (CHALLENGE_SOURCE_EXTERNAL, CHALLENGE_SOURCE_FIAT_SHAMIR):
        err_set.add(ERR_BAD_CHALLENGE_SOURCE)
        structural_error = True
    k_rounds = int(header.get("challenge_rounds_k", 0))
    if k_rounds < 1 or k_rounds > 256:
        err_set.add(ERR_BAD_DIMENSIONS)
        structural_error = True

    dims = header.get("dims", {})
    m = int(dims.get("m", 0))
    d = int(dims.get("d", 0))
    n = int(dims.get("n", 0))
    if (
        m <= 0
        or d <= 0
        or n <= 0
        or m > MAX_DIMENSION
        or d > MAX_DIMENSION
        or n > MAX_DIMENSION
        or len(a_data) != m * d
        or len(b_data) != d * n
        or len(c_data) != m * n
    ):
        err_set.add(ERR_BAD_DIMENSIONS)
        structural_error = True

    if has_weak_fiat_shamir_risk(source, mode, k_rounds):
        receipt["constitutional_boundary"]["grinding_risk_warning"] = True
        err_set.add(ERR_WEAK_FIAT_SHAMIR_GRINDING_RISK)

    # 3. Canonical commitments & activation trace root.
    if not structural_error:
        commitments = header.get("commitments", {})
        a_root = int8_matrix_merkle_root(a_data, m, d, b"A")
        b_root = int8_matrix_merkle_root(b_data, d, n, b"B")
        c_root = int64_matrix_merkle_root(c_data, m, n, b"C")
        a_sha = int8_matrix_sha256(a_data, m, d, b"A")
        b_sha = int8_matrix_sha256(b_data, d, n, b"B")
        c_sha = int64_matrix_sha256(c_data, m, n, b"C")
        trace_root = activation_trace_root(a_root, b_root, c_root)

        if a_root.hex() != commitments.get("matrix_a_root") or a_sha.hex() != commitments.get("matrix_a_sha256"):
            err_set.add(ERR_COMMITMENT_MISMATCH_A)
            structural_error = True
        if b_root.hex() != commitments.get("matrix_b_root") or b_sha.hex() != commitments.get("matrix_b_sha256"):
            err_set.add(ERR_COMMITMENT_MISMATCH_B)
            structural_error = True
        if c_root.hex() != commitments.get("matrix_c_root") or c_sha.hex() != commitments.get("matrix_c_sha256"):
            err_set.add(ERR_COMMITMENT_MISMATCH_C)
            structural_error = True
        if trace_root.hex() != commitments.get("activation_trace_root"):
            err_set.add(ERR_TRACE_ROOT_MISMATCH)
            structural_error = True

    # 4. Canonical header digest, transcript ID, and pure-Python RFC 8032 Ed25519 signature.
    header_digest: bytes | None = None
    try:
        header_digest = compute_header_digest(tx.get("schema_version", ""), tx.get("spec_version", ""), header)
    except Exception:
        err_set.add(ERR_HEADER_DIGEST_MISMATCH)
        structural_error = True
    else:
        digest_hex = header_digest.hex()
        receipt["header_digest_hex"] = digest_hex
        if digest_hex != sig_block.get("header_digest_hex"):
            err_set.add(ERR_HEADER_DIGEST_MISMATCH)
            structural_error = True
        if digest_hex != tx.get("transcript_id"):
            err_set.add(ERR_TRANSCRIPT_ID_MISMATCH)
            structural_error = True
        try:
            pub_bytes = bytes.fromhex(header.get("provider_pubkey_hex", ""))
            sig_bytes = bytes.fromhex(sig_block.get("signature_hex", ""))
            sig_ok = (
                sig_block.get("algorithm") == SIGNATURE_ALGORITHM
                and len(pub_bytes) == 32
                and len(sig_bytes) == 64
                and ed25519_verify(pub_bytes, header_digest, sig_bytes)
            )
        except ValueError:
            sig_ok = False
        if not sig_ok:
            err_set.add(ERR_INVALID_SIGNATURE)
            structural_error = True

    # 5. Challenge seed derivation.
    ch_seed: bytes | None = None
    if header_digest is not None:
        try:
            ch_seed = derive_challenge_seed(
                source,
                header_digest,
                header.get("verifier_nonce_hex", ""),
                header.get("prover_salt_hex", ""),
            )
        except Exception:
            err_set.add(ERR_CHALLENGE_SEED_MISMATCH)
            structural_error = True
        else:
            ch_seed_hex = ch_seed.hex()
            receipt["challenge_seed_hex"] = ch_seed_hex
            if ch_tx.get("challenge_seed_hex") and ch_seed_hex != ch_tx.get("challenge_seed_hex"):
                err_set.add(ERR_CHALLENGE_SEED_MISMATCH)
                structural_error = True
    else:
        err_set.add(ERR_CHALLENGE_SEED_MISMATCH)
        structural_error = True

    if policy_violation:
        receipt["constitutional_boundary"]["compute_verdict"] = VERDICT_POLICY_REJECTED
        receipt["constitutional_boundary"]["error_codes"] = sorted(err_set)
        return receipt

    if structural_error or ch_seed is None:
        receipt["constitutional_boundary"]["compute_verdict"] = VERDICT_INVALID_TRANSCRIPT
        receipt["constitutional_boundary"]["error_codes"] = sorted(err_set)
        return receipt

    # 6. Execute all k Freivalds rounds deterministically.
    all_matched = True
    first_fail = -1
    digests: list[dict[str, Any]] = []
    for t in range(k_rounds):
        r = derive_challenge_vector(mode, ch_seed, t, n)
        br = matvec_int8_mod_p(b_data, d, n, r)
        abr = matvec_int8_mod_p(a_data, m, d, br)
        cr = matvec_int64_mod_p(c_data, m, n, r)
        matched = abr == cr
        if not matched:
            all_matched = False
            if first_fail == -1:
                first_fail = t
        digests.append(
            {
                "round": t,
                "r_sha256": vec_sha256(r).hex(),
                "abr_sha256": vec_sha256(abr).hex(),
                "cr_sha256": vec_sha256(cr).hex(),
                "matched": matched,
            }
        )

    receipt["rounds_executed"] = len(digests)
    receipt["first_failing_round"] = first_fail
    receipt["round_digests"] = digests

    if not all_matched:
        err_set.add(ERR_FREIVALDS_MISMATCH)
        receipt["constitutional_boundary"]["compute_verdict"] = VERDICT_COMPUTE_CORRUPTED
    else:
        receipt["constitutional_boundary"]["compute_verdict"] = VERDICT_COMPUTE_VERIFIED

    receipt["constitutional_boundary"]["error_codes"] = sorted(err_set)
    return receipt


def audit_receipt_leaf(receipt: dict[str, Any]) -> bytes:
    cb = receipt["constitutional_boundary"]
    payload = (
        f"{receipt['transcript_id']}|{cb['compute_verdict']}|"
        f"{','.join(cb['error_codes'])}|{receipt['header_digest_hex']}|"
        f"{receipt['challenge_seed_hex']}|{receipt['first_failing_round']}"
    ).encode("utf-8")
    return hashlib.sha256(DOMAIN_RECEIPT + payload).digest()


def compute_audit_merkle_root(receipts: Sequence[dict[str, Any]]) -> str:
    return merkle_root([audit_receipt_leaf(r) for r in receipts]).hex()


def verify_parity_suite(suite: dict[str, Any]) -> tuple[bool, str, list[str]]:
    """Verify all cases in parity-suite.v1.json and compare bit-for-bit against Go expected receipts."""
    receipts: list[dict[str, Any]] = []
    mismatches: list[str] = []

    for tc in suite["cases"]:
        got = verify_transcript(tc["transcript"], tc["matrix_a"], tc["matrix_b"], tc["matrix_c"])
        receipts.append(got)
        if got != tc["expected_receipt"]:
            mismatches.append(
                f"{tc['case_id']}: got={got['constitutional_boundary']} want={tc['expected_receipt']['constitutional_boundary']}"
            )

    got_root = compute_audit_merkle_root(receipts)
    if got_root != suite["audit_merkle_root"]:
        mismatches.append(f"audit_merkle_root: got={got_root} want={suite['audit_merkle_root']}")

    return len(mismatches) == 0, got_root, mismatches

# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

"""Independent pure Python 3.12 stdlib verifier for settlement-receipt.v1."""

from __future__ import annotations

import re
from typing import Any

from .ed25519 import verify_ed25519_hex
from .merkle import (
    compute_merkle_root,
    compute_receipt_merkle_leaf,
    sha256_hex,
    verify_merkle_proof,
)

SCHEMA_VERSION = "1.0.0"
PROTOCOL_ID = "settlement-receipt.v1"
BPS_DENOMINATOR = 10_000
EAS_SCHEMA_STRING = (
    "settlement-receipt.v1|bytes32 job_id,bytes32 work_hash,address provider_id,"
    "uint64 epoch,uint64 tokens_processed,uint64 compute_units,int64 consumed_micro_zoo"
)

VALID_ROLES = {
    "PAYER",
    "PROVIDER",
    "VALIDATOR",
    "SETTLEMENT_NODE",
    "GOVERNANCE_TREASURY",
    "APPLICATION",
    "AI_AGENT",
}
VALID_TIERS = {"small", "medium", "large", "frontier"}

ERR_NONE = ""
ERR_INVALID_SCHEMA = "ERR_INVALID_SCHEMA"
ERR_BUDGET_OVERFLOW = "ERR_BUDGET_OVERFLOW"
ERR_SELF_VERIFICATION_FORBIDDEN = "ERR_SELF_VERIFICATION_FORBIDDEN"
ERR_UNAUTHORIZED_VALIDATOR = "ERR_UNAUTHORIZED_VALIDATOR"
ERR_INVALID_ATTESTATION_UID = "ERR_INVALID_ATTESTATION_UID"
ERR_INVALID_SIGNATURE = "ERR_INVALID_SIGNATURE"
ERR_DUPLICATE_VALIDATOR = "ERR_DUPLICATE_VALIDATOR"
ERR_INSUFFICIENT_QUORUM = "ERR_INSUFFICIENT_QUORUM"
ERR_ATTESTATION_MISMATCH = "ERR_ATTESTATION_MISMATCH"
ERR_DOUBLE_CLAIM = "ERR_DOUBLE_CLAIM"
ERR_INVALID_RECEIPT_ID = "ERR_INVALID_RECEIPT_ID"
ERR_INVALID_NULLIFIER = "ERR_INVALID_NULLIFIER"
ERR_ACCOUNTING_MISMATCH = "ERR_ACCOUNTING_MISMATCH"
ERR_INVALID_MERKLE_PROOF = "ERR_INVALID_MERKLE_PROOF"
ERR_UNFINALIZED_EPOCH = "ERR_UNFINALIZED_EPOCH"
ERR_EPOCH_EXPIRED = "ERR_EPOCH_EXPIRED"
ERR_APP_ISSUANCE_FORBIDDEN = "ERR_APP_ISSUANCE_FORBIDDEN"
ERR_AI_ISSUANCE_FORBIDDEN = "ERR_AI_ISSUANCE_FORBIDDEN"
ERR_AI_POLICY_MUTATION_FORBIDDEN = "ERR_AI_POLICY_MUTATION_FORBIDDEN"
ERR_UNAUTHORIZED_TREASURY = "ERR_UNAUTHORIZED_TREASURY"
ERR_TREASURY_CAP_EXCEEDED = "ERR_TREASURY_CAP_EXCEEDED"
ERR_KEY_ROLE_CONFLICT = "ERR_KEY_ROLE_CONFLICT"

_RE_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_RE_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _valid_id(s: Any) -> bool:
    return isinstance(s, str) and bool(_RE_ID.match(s))


def _valid_hex64(s: Any) -> bool:
    return isinstance(s, str) and bool(_RE_HEX64.match(s))


def canonical_eas_schema_uid() -> str:
    return sha256_hex("eas-schema:v1|" + EAS_SCHEMA_STRING)


def compute_ref_uid(job_id: str) -> str:
    return sha256_hex(f"job:v1|{job_id}")


def compute_work_hash(
    job_id: str,
    corpus_paper_sha256: str,
    work_spec_hash: str,
    output_digest: str,
    tokens_processed: int,
    compute_units: int,
) -> str:
    return sha256_hex(
        f"work:v1|{job_id}|{corpus_paper_sha256}|{work_spec_hash}|{output_digest}|{tokens_processed}|{compute_units}"
    )


def compute_attestation_uid(
    schema_uid: str,
    ref_uid: str,
    recipient: str,
    attester: str,
    work_hash: str,
    epoch: int,
    nonce: int,
) -> str:
    return sha256_hex(
        f"eas-attestation:v1|{schema_uid}|{ref_uid}|{recipient}|{attester}|{work_hash}|{epoch}|{nonce}"
    )


def validator_signature_message(att: dict[str, Any]) -> str:
    return (
        f"eas-sig:v1|{att['attestation_uid']}|{att['job_id']}|{att['recipient']}|{att['attester']}|"
        f"{att['work_hash']}|{att['epoch']}|{att['nonce']}|{att['consumed_micro_zoo']}|"
        f"{att['tokens_processed']}|{att['compute_units']}"
    )


def compute_receipt_id(
    job_id: str,
    provider_id: str,
    payer_id: str,
    work_hash: str,
    epoch: int,
    max_budget: int,
    consumed: int,
    conservation_bps: int,
    protocol_bps: int,
    attestation_uids: list[str],
) -> str:
    sorted_uids = ",".join(sorted(attestation_uids))
    return sha256_hex(
        f"receipt:v1|{job_id}|{provider_id}|{payer_id}|{work_hash}|{epoch}|"
        f"{max_budget}|{consumed}|{conservation_bps}|{protocol_bps}|{sorted_uids}"
    )


def compute_receipt_nullifier(job_id: str, receipt_id: str, work_hash: str) -> str:
    return sha256_hex(f"nullifier:v1|{job_id}|{receipt_id}|{work_hash}")


def compute_reward_auth_id(auth: dict[str, Any]) -> str:
    return sha256_hex(
        f"reward-auth:v1|{auth['receipt_id']}|{auth['nullifier']}|{auth['job_id']}|{auth['provider_id']}|"
        f"{auth['receipt_epoch']}|{auth['finalized_epoch']}|{auth['provider_share_micro_zoo']}|"
        f"{auth['conservation_share_micro_zoo']}|{auth['protocol_fee_micro_zoo']}|"
        f"{auth['refund_micro_zoo']}|{auth['epoch_merkle_root']}"
    )


def treasury_signature_message(auth: dict[str, Any]) -> str:
    return (
        f"treasury-auth:v1|{auth['auth_id']}|{auth['authority_id']}|"
        f"{auth['authority_role']}|{auth['finalized_epoch']}"
    )


def compute_exact_split(
    max_budget: int, consumed: int, conservation_bps: int, protocol_bps: int
) -> tuple[tuple[int, int, int, int] | None, str]:
    if not all(_is_int(x) for x in (max_budget, consumed, conservation_bps, protocol_bps)):
        return None, ERR_INVALID_SCHEMA
    if max_budget <= 0 or consumed <= 0:
        return None, ERR_INVALID_SCHEMA
    if conservation_bps < 0 or protocol_bps < 0 or conservation_bps + protocol_bps > BPS_DENOMINATOR:
        return None, ERR_INVALID_SCHEMA
    if consumed > max_budget:
        return None, ERR_BUDGET_OVERFLOW
    conservation_share = (consumed * conservation_bps) // BPS_DENOMINATOR
    protocol_fee = (consumed * protocol_bps) // BPS_DENOMINATOR
    provider_share = consumed - conservation_share - protocol_fee
    refund = max_budget - consumed
    return (provider_share, conservation_share, protocol_fee, refund), ERR_NONE


def validate_principal_key_separation(
    principals: list[dict[str, Any]]
) -> tuple[dict[str, dict[str, Any]] | None, str]:
    by_id: dict[str, dict[str, Any]] = {}
    by_pub: dict[str, dict[str, Any]] = {}
    for p in principals:
        pid = p.get("id")
        role = p.get("role")
        pub = p.get("public_key_hex")
        if not _valid_id(pid) or role not in VALID_ROLES or not _valid_hex64(pub):
            return None, ERR_INVALID_SCHEMA
        if pid in by_id or pub in by_pub:
            return None, ERR_KEY_ROLE_CONFLICT
        by_id[pid] = p
        by_pub[pub] = p
    return by_id, ERR_NONE


def validate_job(job: dict[str, Any], principals: dict[str, dict[str, Any]]) -> str:
    if not all(
        _valid_id(job.get(k))
        for k in ("job_id", "payer_id", "provider_id", "corpus_paper_id")
    ):
        return ERR_INVALID_SCHEMA
    if not _valid_hex64(job.get("corpus_paper_sha256")) or not _valid_hex64(job.get("work_spec_hash")):
        return ERR_INVALID_SCHEMA
    epoch = job.get("epoch")
    max_budget = job.get("max_budget_micro_zoo")
    cons_bps = job.get("conservation_bps")
    proto_bps = job.get("protocol_bps")
    if not all(_is_int(x) for x in (epoch, max_budget, cons_bps, proto_bps)):
        return ERR_INVALID_SCHEMA
    if epoch <= 0 or max_budget <= 0:
        return ERR_INVALID_SCHEMA
    if cons_bps < 0 or proto_bps < 0 or cons_bps + proto_bps > BPS_DENOMINATOR:
        return ERR_INVALID_SCHEMA
    if job.get("model_tier") not in VALID_TIERS:
        return ERR_INVALID_SCHEMA
    payer = principals.get(job["payer_id"])
    if payer is None or payer["role"] != "PAYER":
        return ERR_INVALID_SCHEMA
    prov = principals.get(job["provider_id"])
    if prov is None or prov["role"] != "PROVIDER":
        return ERR_INVALID_SCHEMA
    return ERR_NONE


def validate_work_result(job: dict[str, Any], work: dict[str, Any]) -> str:
    if work.get("job_id") != job["job_id"] or work.get("provider_id") != job["provider_id"]:
        return ERR_INVALID_SCHEMA
    if not _valid_hex64(work.get("output_digest")) or not _valid_hex64(work.get("work_hash")):
        return ERR_INVALID_SCHEMA
    tokens = work.get("tokens_processed")
    cu = work.get("compute_units")
    consumed = work.get("consumed_micro_zoo")
    if not all(_is_int(x) for x in (tokens, cu, consumed)):
        return ERR_INVALID_SCHEMA
    if tokens <= 0 or cu <= 0 or consumed <= 0:
        return ERR_INVALID_SCHEMA
    if consumed > job["max_budget_micro_zoo"]:
        return ERR_BUDGET_OVERFLOW
    want_wh = compute_work_hash(
        job["job_id"],
        job["corpus_paper_sha256"],
        job["work_spec_hash"],
        work["output_digest"],
        tokens,
        cu,
    )
    if work["work_hash"] != want_wh:
        return ERR_INVALID_ATTESTATION_UID
    return ERR_NONE


def validate_quorum_attestations(
    job: dict[str, Any],
    work: dict[str, Any],
    attestations: list[dict[str, Any]],
    principals: dict[str, dict[str, Any]],
    policy: dict[str, Any],
) -> str:
    err = validate_job(job, principals)
    if err:
        return err
    err = validate_work_result(job, work)
    if err:
        return err
    if not attestations:
        return ERR_INSUFFICIENT_QUORUM

    want_schema_uid = canonical_eas_schema_uid()
    want_ref_uid = compute_ref_uid(job["job_id"])
    seen_validators: set[str] = set()

    for att in attestations:
        if att.get("schema_uid") != want_schema_uid:
            return ERR_INVALID_SCHEMA
        if att.get("ref_uid") != want_ref_uid:
            return ERR_INVALID_ATTESTATION_UID

        attester = att.get("attester")
        recipient = att.get("recipient")
        if attester == job["provider_id"] or attester == recipient:
            return ERR_SELF_VERIFICATION_FORBIDDEN

        att_p = principals.get(attester)
        if att_p is None:
            return ERR_UNAUTHORIZED_VALIDATOR
        if att_p["role"] == "APPLICATION":
            return ERR_APP_ISSUANCE_FORBIDDEN
        if att_p["role"] == "AI_AGENT":
            return ERR_AI_ISSUANCE_FORBIDDEN
        if att_p["role"] != "VALIDATOR":
            return ERR_UNAUTHORIZED_VALIDATOR

        prov_p = principals.get(job["provider_id"])
        if prov_p is not None and prov_p["public_key_hex"] == att_p["public_key_hex"]:
            return ERR_SELF_VERIFICATION_FORBIDDEN

        if attester in seen_validators:
            return ERR_DUPLICATE_VALIDATOR
        seen_validators.add(attester)

        if (
            att.get("job_id") != job["job_id"]
            or recipient != job["provider_id"]
            or att.get("work_hash") != work["work_hash"]
            or att.get("epoch") != job["epoch"]
            or att.get("consumed_micro_zoo") != work["consumed_micro_zoo"]
            or att.get("tokens_processed") != work["tokens_processed"]
            or att.get("compute_units") != work["compute_units"]
        ):
            return ERR_ATTESTATION_MISMATCH

        want_uid = compute_attestation_uid(
            att["schema_uid"],
            att["ref_uid"],
            att["recipient"],
            att["attester"],
            att["work_hash"],
            att["epoch"],
            att["nonce"],
        )
        if att.get("attestation_uid") != want_uid:
            return ERR_INVALID_ATTESTATION_UID

        if not verify_ed25519_hex(att_p["public_key_hex"], validator_signature_message(att), att.get("signature_hex", "")):
            return ERR_INVALID_SIGNATURE

    if len(seen_validators) < policy["validator_quorum"]:
        return ERR_INSUFFICIENT_QUORUM
    return ERR_NONE


def verify_receipt_issuer_role(receipt: dict[str, Any], principals: dict[str, dict[str, Any]]) -> str:
    issuer_role = receipt.get("issuer_role")
    issuer_id = receipt.get("issuer_id")
    if issuer_role == "APPLICATION":
        return ERR_APP_ISSUANCE_FORBIDDEN
    if issuer_role == "AI_AGENT":
        return ERR_AI_ISSUANCE_FORBIDDEN
    p = principals.get(issuer_id)
    if p is None:
        return ERR_INVALID_SCHEMA
    if p["role"] == "APPLICATION":
        return ERR_APP_ISSUANCE_FORBIDDEN
    if p["role"] == "AI_AGENT":
        return ERR_AI_ISSUANCE_FORBIDDEN
    if p["role"] != "SETTLEMENT_NODE" or issuer_role != "SETTLEMENT_NODE":
        return ERR_UNAUTHORIZED_TREASURY
    return ERR_NONE


def validate_receipt_integrity(
    job: dict[str, Any],
    work: dict[str, Any],
    attestations: list[dict[str, Any]],
    receipt: dict[str, Any],
    principals: dict[str, dict[str, Any]],
) -> str:
    err = verify_receipt_issuer_role(receipt, principals)
    if err:
        return err

    if (
        receipt.get("job_id") != job["job_id"]
        or receipt.get("payer_id") != job["payer_id"]
        or receipt.get("provider_id") != job["provider_id"]
        or receipt.get("work_hash") != work["work_hash"]
        or receipt.get("epoch") != job["epoch"]
        or receipt.get("max_budget_micro_zoo") != job["max_budget_micro_zoo"]
        or receipt.get("consumed_micro_zoo") != work["consumed_micro_zoo"]
        or receipt.get("conservation_bps") != job["conservation_bps"]
        or receipt.get("protocol_bps") != job["protocol_bps"]
    ):
        return ERR_INVALID_SCHEMA

    split, err = compute_exact_split(
        job["max_budget_micro_zoo"],
        work["consumed_micro_zoo"],
        job["conservation_bps"],
        job["protocol_bps"],
    )
    if err or split is None:
        return err
    prov_s, cons_s, proto_s, refund_s = split
    if (
        receipt.get("provider_share_micro_zoo") != prov_s
        or receipt.get("conservation_share_micro_zoo") != cons_s
        or receipt.get("protocol_fee_micro_zoo") != proto_s
        or receipt.get("refund_micro_zoo") != refund_s
    ):
        return ERR_ACCOUNTING_MISMATCH
    if (
        receipt["provider_share_micro_zoo"]
        + receipt["conservation_share_micro_zoo"]
        + receipt["protocol_fee_micro_zoo"]
        != receipt["consumed_micro_zoo"]
        or receipt["consumed_micro_zoo"] + receipt["refund_micro_zoo"]
        != receipt["max_budget_micro_zoo"]
    ):
        return ERR_ACCOUNTING_MISMATCH

    att_uids = sorted(a["attestation_uid"] for a in attestations)
    got_uids = sorted(receipt.get("attestation_uids", []))
    if got_uids != att_uids:
        return ERR_INVALID_RECEIPT_ID

    want_rid = compute_receipt_id(
        receipt["job_id"],
        receipt["provider_id"],
        receipt["payer_id"],
        receipt["work_hash"],
        receipt["epoch"],
        receipt["max_budget_micro_zoo"],
        receipt["consumed_micro_zoo"],
        receipt["conservation_bps"],
        receipt["protocol_bps"],
        att_uids,
    )
    if receipt.get("receipt_id") != want_rid:
        return ERR_INVALID_RECEIPT_ID
    want_null = compute_receipt_nullifier(receipt["job_id"], receipt["receipt_id"], receipt["work_hash"])
    if receipt.get("nullifier") != want_null:
        return ERR_INVALID_NULLIFIER
    return ERR_NONE


def validate_policy_mutation(attempt: dict[str, Any], principals: dict[str, dict[str, Any]]) -> str:
    actor_role = attempt.get("actor_role")
    actor_id = attempt.get("actor_id")
    if actor_role in ("AI_AGENT", "APPLICATION"):
        return ERR_AI_POLICY_MUTATION_FORBIDDEN
    p = principals.get(actor_id)
    if p is None:
        return ERR_UNAUTHORIZED_TREASURY
    if p["role"] in ("AI_AGENT", "APPLICATION"):
        return ERR_AI_POLICY_MUTATION_FORBIDDEN
    if p["role"] != "GOVERNANCE_TREASURY" or actor_role != "GOVERNANCE_TREASURY":
        return ERR_UNAUTHORIZED_TREASURY
    return ERR_NONE


def verify_authorization_authority_role(
    auth: dict[str, Any], principals: dict[str, dict[str, Any]]
) -> tuple[dict[str, Any] | None, str]:
    role = auth.get("authority_role")
    aid = auth.get("authority_id")
    if role == "APPLICATION":
        return None, ERR_APP_ISSUANCE_FORBIDDEN
    if role == "AI_AGENT":
        return None, ERR_AI_ISSUANCE_FORBIDDEN
    p = principals.get(aid)
    if p is None:
        return None, ERR_UNAUTHORIZED_TREASURY
    if p["role"] == "APPLICATION":
        return None, ERR_APP_ISSUANCE_FORBIDDEN
    if p["role"] == "AI_AGENT":
        return None, ERR_AI_ISSUANCE_FORBIDDEN
    if p["role"] != "GOVERNANCE_TREASURY" or role != "GOVERNANCE_TREASURY":
        return None, ERR_UNAUTHORIZED_TREASURY
    return p, ERR_NONE


def compute_audit_case_leaf(
    case_id: str,
    stage: str,
    verdict: str,
    error_code: str,
    receipt_id: str,
    nullifier: str,
    provider_share: int,
    conservation_share: int,
    protocol_fee: int,
    refund: int,
) -> str:
    return sha256_hex(
        f"audit-leaf:v1|{case_id}|{stage}|{verdict}|{error_code}|{receipt_id}|{nullifier}|"
        f"{provider_share}|{conservation_share}|{protocol_fee}|{refund}"
    )


def compute_audit_balance_sheet_leaf(bs: dict[str, Any]) -> str:
    prov = bs["provider_balances_micro_zoo"]
    pairs = ",".join(f"{k}:{prov[k]}" for k in sorted(prov.keys()))
    return sha256_hex(
        f"balance-sheet:v1|escrow={bs['total_finalized_escrow_micro_zoo']}|"
        f"authorized={bs['total_authorized_payout_micro_zoo']}|"
        f"provider={bs['total_provider_payout_micro_zoo']}|"
        f"conservation={bs['conservation_fund_micro_zoo']}|"
        f"protocol={bs['protocol_fee_pool_micro_zoo']}|"
        f"refund={bs['total_payer_refunds_micro_zoo']}|{pairs}"
    )


def check_balance_sheet_conservation(bs: dict[str, Any]) -> bool:
    prov_vals = bs["provider_balances_micro_zoo"].values()
    ep_vals = bs["epoch_authorized_micro_zoo"].values()
    if any(v < 0 for v in prov_vals) or any(v < 0 for v in ep_vals):
        return False
    prov_sum = sum(prov_vals)
    ep_sum = sum(ep_vals)
    ok = (
        prov_sum == bs["total_provider_payout_micro_zoo"]
        and bs["total_provider_payout_micro_zoo"]
        + bs["conservation_fund_micro_zoo"]
        + bs["protocol_fee_pool_micro_zoo"]
        == bs["total_authorized_payout_micro_zoo"]
        and bs["total_authorized_payout_micro_zoo"] + bs["total_payer_refunds_micro_zoo"]
        == bs["total_finalized_escrow_micro_zoo"]
        and ep_sum == bs["total_authorized_payout_micro_zoo"]
    )
    bs["conservation_exact"] = ok
    return ok


def verify_trace_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    """Independently verify a full settlement-receipt.v1 trace bundle."""
    if bundle.get("schema_version") != SCHEMA_VERSION or bundle.get("protocol") != PROTOCOL_ID:
        raise ValueError(f"unsupported schema/protocol: {bundle.get('schema_version')} / {bundle.get('protocol')}")
    if bundle.get("eas_schema_uid") != canonical_eas_schema_uid():
        raise ValueError("eas_schema_uid mismatch")

    principals, err = validate_principal_key_separation(bundle["principals"])
    if err or principals is None:
        raise ValueError(f"invalid principals: {err}")

    policy = bundle["policy"]
    commitments: dict[int, dict[str, Any]] = {
        c["epoch"]: c for c in bundle.get("epoch_commitments", [])
    }

    settled_nullifiers: set[str] = set()
    settled_jobs: set[str] = set()
    authorized_nullifiers: set[str] = set()
    authorized_jobs: set[str] = set()

    bs: dict[str, Any] = {
        "total_finalized_escrow_micro_zoo": 0,
        "total_authorized_payout_micro_zoo": 0,
        "total_provider_payout_micro_zoo": 0,
        "conservation_fund_micro_zoo": 0,
        "protocol_fee_pool_micro_zoo": 0,
        "total_payer_refunds_micro_zoo": 0,
        "authorized_receipt_count": 0,
        "provider_balances_micro_zoo": {},
        "epoch_authorized_micro_zoo": {},
        "conservation_exact": True,
    }

    verdicts: list[dict[str, Any]] = []
    audit_leaves: list[str] = []
    accepted = 0
    rejected = 0
    matched = 0

    for tc in bundle["cases"]:
        stage = tc["stage"]
        err_code = ERR_NONE
        receipt_id = ""
        nullifier = ""
        prov_share = 0
        cons_share = 0
        proto_fee = 0
        refund = 0

        if stage == "KEY_AUDIT":
            _, err_code = validate_principal_key_separation(tc.get("override_principals", []))

        elif stage == "POLICY_MUTATION":
            pm = tc.get("policy_mutation")
            if pm is None:
                err_code = ERR_INVALID_SCHEMA
            else:
                err_code = validate_policy_mutation(pm, principals)

        elif stage == "VERIFY":
            job = tc.get("job")
            work = tc.get("work_result")
            if job is None or work is None:
                err_code = ERR_INVALID_SCHEMA
            else:
                err_code = validate_quorum_attestations(
                    job, work, tc.get("attestations", []), principals, policy
                )

        elif stage == "ISSUE_RECEIPT":
            job = tc.get("job")
            work = tc.get("work_result")
            rec = tc.get("receipt")
            if job is None or work is None or rec is None:
                err_code = ERR_INVALID_SCHEMA
            else:
                receipt_id = rec.get("receipt_id", "")
                nullifier = rec.get("nullifier", "")
                err_code = verify_receipt_issuer_role(rec, principals)
                if not err_code:
                    err_code = validate_quorum_attestations(
                        job, work, tc.get("attestations", []), principals, policy
                    )
                if not err_code:
                    err_code = validate_receipt_integrity(
                        job, work, tc.get("attestations", []), rec, principals
                    )
                if not err_code:
                    if rec["nullifier"] in settled_nullifiers or rec["job_id"] in settled_jobs:
                        err_code = ERR_DOUBLE_CLAIM
                if not err_code:
                    settled_nullifiers.add(rec["nullifier"])
                    settled_jobs.add(rec["job_id"])
                    prov_share = rec["provider_share_micro_zoo"]
                    cons_share = rec["conservation_share_micro_zoo"]
                    proto_fee = rec["protocol_fee_micro_zoo"]
                    refund = rec["refund_micro_zoo"]

        elif stage == "AUTHORIZE_REWARD":
            job = tc.get("job")
            work = tc.get("work_result")
            rec = tc.get("receipt")
            auth = tc.get("authorization")
            if job is None or work is None or rec is None or auth is None:
                err_code = ERR_INVALID_SCHEMA
            else:
                receipt_id = rec.get("receipt_id", "")
                nullifier = rec.get("nullifier", "")
                auth_p, err_code = verify_authorization_authority_role(auth, principals)
                if not err_code:
                    err_code = validate_quorum_attestations(
                        job, work, tc.get("attestations", []), principals, policy
                    )
                if not err_code:
                    err_code = validate_receipt_integrity(
                        job, work, tc.get("attestations", []), rec, principals
                    )
                if not err_code:
                    if (
                        auth.get("receipt_id") != rec["receipt_id"]
                        or auth.get("nullifier") != rec["nullifier"]
                        or auth.get("job_id") != rec["job_id"]
                        or auth.get("provider_id") != rec["provider_id"]
                        or auth.get("receipt_epoch") != rec["epoch"]
                    ):
                        err_code = ERR_INVALID_SCHEMA
                if not err_code:
                    if (
                        auth.get("provider_share_micro_zoo") != rec["provider_share_micro_zoo"]
                        or auth.get("conservation_share_micro_zoo") != rec["conservation_share_micro_zoo"]
                        or auth.get("protocol_fee_micro_zoo") != rec["protocol_fee_micro_zoo"]
                        or auth.get("refund_micro_zoo") != rec["refund_micro_zoo"]
                    ):
                        err_code = ERR_ACCOUNTING_MISMATCH
                if not err_code:
                    if auth["finalized_epoch"] < rec["epoch"] + policy["finality_delay_epochs"]:
                        err_code = ERR_UNFINALIZED_EPOCH
                    elif auth["finalized_epoch"] > rec["epoch"] + policy["claim_window_epochs"]:
                        err_code = ERR_EPOCH_EXPIRED
                if not err_code:
                    comm = commitments.get(rec["epoch"])
                    if comm is None or auth.get("epoch_merkle_root") != comm["receipts_merkle_root"]:
                        err_code = ERR_INVALID_MERKLE_PROOF
                    else:
                        leaf = compute_receipt_merkle_leaf(
                            rec["receipt_id"], rec["nullifier"], rec["consumed_micro_zoo"]
                        )
                        if not verify_merkle_proof(
                            leaf, auth.get("merkle_proof", []), comm["receipts_merkle_root"]
                        ):
                            err_code = ERR_INVALID_MERKLE_PROOF
                if not err_code:
                    if auth.get("auth_id") != compute_reward_auth_id(auth):
                        err_code = ERR_INVALID_SCHEMA
                    elif auth_p is None or not verify_ed25519_hex(
                        auth_p["public_key_hex"],
                        treasury_signature_message(auth),
                        auth.get("treasury_sig_hex", ""),
                    ):
                        err_code = ERR_INVALID_SIGNATURE
                if not err_code:
                    if rec["nullifier"] in authorized_nullifiers or rec["job_id"] in authorized_jobs:
                        err_code = ERR_DOUBLE_CLAIM
                if not err_code:
                    cap = tc.get("override_epoch_treasury_cap_micro_zoo") or policy["epoch_treasury_cap_micro_zoo"]
                    ep_key = str(rec["epoch"])
                    cur_spent = bs["epoch_authorized_micro_zoo"].get(ep_key, 0)
                    if cur_spent + rec["consumed_micro_zoo"] > cap:
                        err_code = ERR_TREASURY_CAP_EXCEEDED
                if not err_code:
                    settled_nullifiers.add(rec["nullifier"])
                    settled_jobs.add(rec["job_id"])
                    authorized_nullifiers.add(rec["nullifier"])
                    authorized_jobs.add(rec["job_id"])

                    bs["total_finalized_escrow_micro_zoo"] += rec["max_budget_micro_zoo"]
                    bs["total_authorized_payout_micro_zoo"] += rec["consumed_micro_zoo"]
                    bs["total_provider_payout_micro_zoo"] += rec["provider_share_micro_zoo"]
                    bs["conservation_fund_micro_zoo"] += rec["conservation_share_micro_zoo"]
                    bs["protocol_fee_pool_micro_zoo"] += rec["protocol_fee_micro_zoo"]
                    bs["total_payer_refunds_micro_zoo"] += rec["refund_micro_zoo"]
                    bs["authorized_receipt_count"] += 1
                    pid = rec["provider_id"]
                    bs["provider_balances_micro_zoo"][pid] = (
                        bs["provider_balances_micro_zoo"].get(pid, 0) + rec["provider_share_micro_zoo"]
                    )
                    ep_key = str(rec["epoch"])
                    bs["epoch_authorized_micro_zoo"][ep_key] = (
                        bs["epoch_authorized_micro_zoo"].get(ep_key, 0) + rec["consumed_micro_zoo"]
                    )

                    prov_share = rec["provider_share_micro_zoo"]
                    cons_share = rec["conservation_share_micro_zoo"]
                    proto_fee = rec["protocol_fee_micro_zoo"]
                    refund = rec["refund_micro_zoo"]
        else:
            err_code = ERR_INVALID_SCHEMA

        verdict = "REJECT" if err_code else "ACCEPT"
        if verdict == "ACCEPT":
            accepted += 1
        else:
            rejected += 1
        exp_v = tc["expected_verdict"]
        exp_e = tc["expected_error"]
        is_match = verdict == exp_v and err_code == exp_e
        if is_match:
            matched += 1

        verdicts.append(
            {
                "case_id": tc["case_id"],
                "category": tc["category"],
                "stage": stage,
                "verdict": verdict,
                "error_code": err_code,
                "expected_verdict": exp_v,
                "expected_error": exp_e,
                "matched_expectation": is_match,
                "receipt_id": receipt_id,
                "nullifier": nullifier,
                "provider_share_micro_zoo": prov_share,
                "conservation_share_micro_zoo": cons_share,
                "protocol_fee_micro_zoo": proto_fee,
                "refund_micro_zoo": refund,
            }
        )
        audit_leaves.append(
            compute_audit_case_leaf(
                tc["case_id"],
                stage,
                verdict,
                err_code,
                receipt_id,
                nullifier,
                prov_share,
                cons_share,
                proto_fee,
                refund,
            )
        )

    conservation_exact = check_balance_sheet_conservation(bs)
    audit_leaves.append(compute_audit_balance_sheet_leaf(bs))
    audit_root = compute_merkle_root(audit_leaves)
    exp_root = bundle.get("expected_audit_merkle_root", "")

    return {
        "verifier": "python-stdlib-3.12",
        "schema_version": bundle["schema_version"],
        "protocol": bundle["protocol"],
        "total_cases": len(bundle["cases"]),
        "accepted_cases": accepted,
        "rejected_cases": rejected,
        "matched_count": matched,
        "all_matched": matched == len(bundle["cases"]),
        "conservation_exact": conservation_exact,
        "balance_sheet": bs,
        "audit_merkle_root": audit_root,
        "expected_audit_merkle_root": exp_root,
        "audit_root_matched": (not exp_root) or (audit_root == exp_root),
        "case_verdicts": verdicts,
    }

# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.

"""Pure-Python 3 verifier for federated-a2a.v1 mirroring Go verifier bit-for-bit."""

import base64
from typing import Any, Dict, List, Optional, Tuple

from .canonical import canonical_json, domain_message, hash_canonical, merkle_root_rfc6962, sha256_hex
from .compute import compute_scientific_result_hash, run_deterministic_zhl
from .ed25519 import verify_ed25519

SCHEMA_VERSION = "federated-a2a.v1"
SPEC_VERSION = "1.0.0"

DOMAIN_AGENT_CARD = "federated-a2a.v1:agent_card"
DOMAIN_ORG_POLICY = "federated-a2a.v1:org_policy"
DOMAIN_ENVELOPE = "federated-a2a.v1:envelope"
DOMAIN_TASK_RECEIPT = "federated-a2a.v1:task_receipt"
DOMAIN_EGRESS_BLOCK = "federated-a2a.v1:egress_block"
DOMAIN_GOVERNANCE_ACTION = "federated-a2a.v1:governance_action"
DOMAIN_ADVISORY = "federated-a2a.v1:advisory"
DOMAIN_ACCEPTANCE = "federated-a2a.v1:acceptance"
DOMAIN_WIRE_FRAME = "federated-a2a.v1:wire_frame"
DOMAIN_AUDIT_LEAF = "federated-a2a.v1:audit_leaf"

ROLE_ORG_GATEWAY = "ORG_GATEWAY"
ROLE_HUMAN_REVIEWER = "HUMAN_REVIEWER"
ROLE_COUNCIL_MEMBER = "COUNCIL_MEMBER"
ROLE_AI_AGENT = "AI_AGENT"

SCOPE_TREASURY_SPEND = "treasury_spend"
SCOPE_GOVERNANCE_RULE_CHG = "governance_rule_change"

CODE_OK = "OK"
CODE_CREDENTIAL_LEAK_DETECTED = "ERR_CREDENTIAL_LEAK_DETECTED"
CODE_PRIVATE_MEMORY_LEAK = "ERR_PRIVATE_MEMORY_LEAK"
CODE_RAW_TRACE_LEAK = "ERR_RAW_TRACE_LEAK"
CODE_PRIVATE_MEMORY_REF_FORBIDDEN = "ERR_PRIVATE_MEMORY_REF_FORBIDDEN"
CODE_ENCODED_SECRET_LEAK = "ERR_ENCODED_SECRET_LEAK"
CODE_AGENT_CARD_SIG_INVALID = "ERR_AGENT_CARD_SIG_INVALID"
CODE_AGENT_CARD_CRED_LEAK = "ERR_AGENT_CARD_CRED_LEAK"
CODE_ENVELOPE_SIG_INVALID = "ERR_ENVELOPE_SIG_INVALID"
CODE_SPOOFED_ORG_IDENTITY = "ERR_SPOOFED_ORG_IDENTITY"
CODE_AUDIENCE_MISMATCH = "ERR_AUDIENCE_MISMATCH"
CODE_ENVELOPE_EXPIRED = "ERR_ENVELOPE_EXPIRED"
CODE_NONCE_REPLAY = "ERR_NONCE_REPLAY"
CODE_SCOPE_ESCALATION = "ERR_SCOPE_ESCALATION"
CODE_AI_VOTING_RULE_FORBIDDEN = "ERR_AI_VOTING_RULE_FORBIDDEN"
CODE_AI_TREASURY_FORBIDDEN = "ERR_AI_TREASURY_FORBIDDEN"
CODE_AI_SELF_CERTIFY_FORBIDDEN = "ERR_AI_SELF_CERTIFY_FORBIDDEN"
CODE_RESULT_RECOMPUTE_MISMATCH = "ERR_RESULT_RECOMPUTE_MISMATCH"
CODE_LICENSE_UNREVIEWED = "ERR_LICENSE_UNREVIEWED"
CODE_RECEIPT_SIG_INVALID = "ERR_RECEIPT_SIG_INVALID"
CODE_TASK_STATE_INVALID = "ERR_TASK_STATE_INVALID"


def verify_canonical(pub_hex: str, sig_hex: str, domain: str, payload: Any) -> bool:
    try:
        pub = bytes.fromhex(pub_hex)
        sig = bytes.fromhex(sig_hex)
    except ValueError:
        return False
    if len(pub) != 32 or len(sig) != 64:
        return False
    msg = domain_message(domain, payload)
    return verify_ed25519(pub, msg, sig)


def compute_org_policy_hash(p: Dict[str, Any]) -> str:
    return hash_canonical(
        DOMAIN_ORG_POLICY,
        {
            "ai_agent_can_authorize_spend": p["ai_agent_can_authorize_spend"],
            "ai_agent_can_redefine_voting": p["ai_agent_can_redefine_voting"],
            "ai_agent_can_self_certify": p["ai_agent_can_self_certify"],
            "allowed_exchange_tiers": p.get("allowed_exchange_tiers") or [],
            "allowed_licenses": p.get("allowed_licenses") or [],
            "allowed_skills": p.get("allowed_skills") or [],
            "denied_scopes": p.get("denied_scopes") or [],
            "org_id": p["org_id"],
            "policy_version": p["policy_version"],
            "principals": p.get("principals") or [],
        },
    )


def agent_card_signing_payload(c: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "boundary_commitment": c["boundary_commitment"],
        "capabilities": c["capabilities"],
        "description": c["description"],
        "gateway_principal": c["gateway_principal"],
        "logical_url": c["logical_url"],
        "name": c["name"],
        "org_id": c["org_id"],
        "policy_digest": c["policy_digest"],
        "protocol_version": c["protocol_version"],
        "schema_version": c["schema_version"],
        "skills": c.get("skills") or [],
    }


def compute_agent_card_hash(c: Dict[str, Any]) -> str:
    return hash_canonical(DOMAIN_AGENT_CARD, agent_card_signing_payload(c))


def envelope_signing_payload(e: Dict[str, Any]) -> Dict[str, Any]:
    p = e["payload"]
    return {
        "audience_org_id": e["audience_org_id"],
        "envelope_id": e["envelope_id"],
        "expires_at": e["expires_at"],
        "issued_at": e["issued_at"],
        "method": e["method"],
        "payload": {
            "actor_id": p["actor_id"],
            "actor_role": p["actor_role"],
            "commitment": p["commitment"],
            "defer_completion": p["defer_completion"],
            "licenses": p.get("licenses") or [],
            "prompt_note": p["prompt_note"],
            "self_certified": p["self_certified"],
            "skill_id": p["skill_id"],
            "task_id": p["task_id"],
        },
        "scope": e["scope"],
        "sender_org_id": e["sender_org_id"],
        "signer_id": e["signer_id"],
        "task_nonce": e["task_nonce"],
    }


def compute_envelope_hash(e: Dict[str, Any]) -> str:
    return hash_canonical(DOMAIN_ENVELOPE, envelope_signing_payload(e))


def egress_block_signing_payload(ev: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "blocked_class": ev["blocked_class"],
        "blocked_digest": ev["blocked_digest"],
        "bytes_blocked": ev["bytes_blocked"],
        "event_id": ev["event_id"],
        "org_id": ev["org_id"],
        "reason_code": ev["reason_code"],
        "task_id": ev["task_id"],
        "timestamp": ev["timestamp"],
        "wire_bytes_sent": ev["wire_bytes_sent"],
    }


def receipt_signing_payload(r: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "completed_at": r["completed_at"],
        "egress_audit_passed": r["egress_audit_passed"],
        "egress_block": r.get("egress_block"),
        "error_code": r["error_code"],
        "executor_org_id": r["executor_org_id"],
        "receipt_id": r["receipt_id"],
        "requester_org_id": r["requester_org_id"],
        "result": r.get("result"),
        "signer_id": r["signer_id"],
        "state": r["state"],
        "task_id": r["task_id"],
        "transitions": r.get("transitions") or [],
    }


def compute_receipt_hash(r: Dict[str, Any]) -> str:
    return hash_canonical(DOMAIN_TASK_RECEIPT, receipt_signing_payload(r))


def advisory_signing_payload(a: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "advisory_id": a["advisory_id"],
        "agent_id": a["agent_id"],
        "binding": a["binding"],
        "conflict_flags": a.get("conflict_flags") or [],
        "estimated_value_bps": a["estimated_value_bps"],
        "org_id": a["org_id"],
        "recommendation": a["recommendation"],
        "task_id": a["task_id"],
    }


def acceptance_signing_payload(a: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "acceptance_id": a["acceptance_id"],
        "accepted_at": a["accepted_at"],
        "advisory_ref_id": a["advisory_ref_id"],
        "org_id": a["org_id"],
        "receipt_hash": a["receipt_hash"],
        "recomputed_hash": a["recomputed_hash"],
        "reviewer_id": a["reviewer_id"],
        "reviewer_role": a["reviewer_role"],
        "task_id": a["task_id"],
    }


def governance_action_signing_payload(g: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "action_id": g["action_id"],
        "action_type": g["action_type"],
        "amount_micro": g["amount_micro"],
        "org_id": g["org_id"],
        "proposer_id": g["proposer_id"],
        "proposer_role": g["proposer_role"],
        "summary": g["summary"],
    }


def scan_boundary_probes(payload: bytes, probes: List[Dict[str, Any]]) -> Tuple[int, int, int, str, str]:
    raw_str = payload.decode("utf-8", errors="replace")
    lower_str = raw_str.lower()

    def check_token(tok: str) -> Tuple[int, bool]:
        if not tok:
            return 0, False
        if tok in raw_str or tok.lower() in lower_str:
            return len(tok), False
        b64 = base64.b64encode(tok.encode("utf-8")).decode("ascii")
        if b64 in raw_str:
            return len(b64), True
        hx = tok.encode("utf-8").hex()
        if hx in lower_str:
            return len(hx), True
        return 0, False

    cred_bytes = 0
    mem_bytes = 0
    trace_bytes = 0
    first_code = ""
    first_class = ""

    for p in probes:
        for tok in p.get("credential_probes") or []:
            n, enc = check_token(tok)
            if n > 0:
                cred_bytes += n
                if not first_code:
                    first_code = CODE_ENCODED_SECRET_LEAK if enc else CODE_CREDENTIAL_LEAK_DETECTED
                    first_class = "encoded_secret" if enc else "credential"
        for tok in p.get("private_memory_probes") or []:
            n, enc = check_token(tok)
            if n > 0:
                mem_bytes += n
                if not first_code:
                    first_code = CODE_ENCODED_SECRET_LEAK if enc else CODE_PRIVATE_MEMORY_LEAK
                    first_class = "encoded_secret" if enc else "private_memory"
        for ref_id in p.get("private_memory_ref_ids") or []:
            n, _ = check_token(ref_id)
            if n > 0:
                mem_bytes += n
                if not first_code:
                    first_code = CODE_PRIVATE_MEMORY_REF_FORBIDDEN
                    first_class = "private_memory"
        for tok in p.get("raw_trace_probes") or []:
            n, enc = check_token(tok)
            if n > 0:
                trace_bytes += n
                if not first_code:
                    first_code = CODE_ENCODED_SECRET_LEAK if enc else CODE_RAW_TRACE_LEAK
                    first_class = "encoded_secret" if enc else "raw_reasoning_trace"

    return cred_bytes, mem_bytes, trace_bytes, first_code, first_class


def _find_principal(policy: Dict[str, Any], principal_id: str) -> Optional[Dict[str, Any]]:
    for pr in policy.get("principals") or []:
        if pr["id"] == principal_id:
            return pr
    return None


def verify_agent_card(
    card: Dict[str, Any],
    policies: Dict[str, Dict[str, Any]],
    probes: List[Dict[str, Any]],
) -> Tuple[bool, str]:
    raw = canonical_json(card)
    cred_n, mem_n, trace_n, first_code, _ = scan_boundary_probes(raw, probes)
    if cred_n > 0:
        return False, CODE_AGENT_CARD_CRED_LEAK
    if mem_n > 0 or trace_n > 0:
        return False, first_code
    pol = policies.get(card["org_id"])
    if pol is None:
        return False, CODE_AGENT_CARD_SIG_INVALID
    if pol["policy_hash"] != compute_org_policy_hash(pol) or card["policy_digest"] != pol["policy_hash"]:
        return False, CODE_AGENT_CARD_SIG_INVALID
    gw = card["gateway_principal"]
    pr = _find_principal(pol, gw["id"])
    if pr is None or pr["role"] != ROLE_ORG_GATEWAY or pr["public_key_hex"] != gw["public_key_hex"]:
        return False, CODE_AGENT_CARD_SIG_INVALID
    if card["card_hash"] != compute_agent_card_hash(card):
        return False, CODE_AGENT_CARD_SIG_INVALID
    if not verify_canonical(gw["public_key_hex"], card["org_signature_hex"], DOMAIN_AGENT_CARD, agent_card_signing_payload(card)):
        return False, CODE_AGENT_CARD_SIG_INVALID
    return True, CODE_OK


def verify_envelope(
    env: Dict[str, Any],
    receiver_org_id: str,
    verified_at: int,
    prior_nonces: List[str],
    cards: Dict[str, Dict[str, Any]],
    policies: Dict[str, Dict[str, Any]],
    probes: List[Dict[str, Any]],
) -> Tuple[bool, str]:
    method = env["method"]
    payload = env["payload"]
    if method in ("tasks/send", "tasks/sendSubscribe"):
        recv_pol = policies.get(receiver_org_id)
        if recv_pol is not None and payload["commitment"]["input_tier"] not in (recv_pol.get("allowed_exchange_tiers") or []):
            return False, CODE_PRIVATE_MEMORY_REF_FORBIDDEN
        for ref in payload["commitment"].get("input_record_refs") or []:
            lower_ref = ref.lower()
            if "priv" in lower_ref or "pii" in lower_ref or "trace" in lower_ref:
                return False, CODE_PRIVATE_MEMORY_REF_FORBIDDEN
            for p in probes:
                if ref in (p.get("private_memory_ref_ids") or []):
                    return False, CODE_PRIVATE_MEMORY_REF_FORBIDDEN

    raw = canonical_json(env)
    cred_n, mem_n, trace_n, first_code, _ = scan_boundary_probes(raw, probes)
    if cred_n > 0 or mem_n > 0 or trace_n > 0:
        return False, first_code

    sender_card = cards.get(env["sender_org_id"])
    if sender_card is None or env["signer_id"] != sender_card["gateway_principal"]["id"]:
        return False, CODE_SPOOFED_ORG_IDENTITY
    if env["envelope_hash"] != compute_envelope_hash(env):
        return False, CODE_ENVELOPE_SIG_INVALID
    sig_payload = envelope_signing_payload(env)
    if not verify_canonical(sender_card["gateway_principal"]["public_key_hex"], env["org_sig_hex"], DOMAIN_ENVELOPE, sig_payload):
        for org_id, other_card in cards.items():
            if org_id != env["sender_org_id"] and verify_canonical(
                other_card["gateway_principal"]["public_key_hex"], env["org_sig_hex"], DOMAIN_ENVELOPE, sig_payload
            ):
                return False, CODE_SPOOFED_ORG_IDENTITY
        return False, CODE_ENVELOPE_SIG_INVALID

    if env["audience_org_id"] != receiver_org_id:
        return False, CODE_AUDIENCE_MISMATCH
    if env["issued_at"] > verified_at or verified_at > env["expires_at"]:
        return False, CODE_ENVELOPE_EXPIRED
    if env["task_nonce"] in prior_nonces:
        return False, CODE_NONCE_REPLAY

    if method in ("tasks/send", "tasks/sendSubscribe"):
        recv_pol = policies.get(receiver_org_id)
        if recv_pol is None:
            return False, CODE_AUDIENCE_MISMATCH
        for denied in recv_pol.get("denied_scopes") or []:
            if env["scope"] == denied or payload["skill_id"] == denied:
                if payload["actor_role"] == ROLE_AI_AGENT:
                    if denied == SCOPE_TREASURY_SPEND:
                        return False, CODE_AI_TREASURY_FORBIDDEN
                    if denied == SCOPE_GOVERNANCE_RULE_CHG:
                        return False, CODE_AI_VOTING_RULE_FORBIDDEN
                return False, CODE_SCOPE_ESCALATION
        allowed_skills = recv_pol.get("allowed_skills") or []
        if env["scope"] not in allowed_skills or payload["skill_id"] not in allowed_skills:
            return False, CODE_SCOPE_ESCALATION
        if payload["actor_role"] == ROLE_AI_AGENT and payload["self_certified"]:
            return False, CODE_AI_SELF_CERTIFY_FORBIDDEN
        licenses = payload.get("licenses") or []
        if not licenses:
            return False, CODE_LICENSE_UNREVIEWED
        allowed_lic = recv_pol.get("allowed_licenses") or []
        for lic in licenses:
            if not lic["license_reviewed"] or lic["license_id"] not in allowed_lic:
                return False, CODE_LICENSE_UNREVIEWED

    return True, CODE_OK


def verify_receipt(
    env: Optional[Dict[str, Any]],
    receipt: Dict[str, Any],
    acceptance: Optional[Dict[str, Any]],
    cards: Dict[str, Dict[str, Any]],
    policies: Dict[str, Dict[str, Any]],
    probes: List[Dict[str, Any]],
) -> Tuple[bool, str, bool]:
    raw = canonical_json(receipt)
    cred_n, mem_n, trace_n, first_code, _ = scan_boundary_probes(raw, probes)
    if cred_n > 0 or mem_n > 0 or trace_n > 0:
        return False, first_code, False

    exec_card = cards.get(receipt["executor_org_id"])
    if exec_card is None or receipt["signer_id"] != exec_card["gateway_principal"]["id"]:
        return False, CODE_RECEIPT_SIG_INVALID, False
    if receipt["receipt_hash"] != compute_receipt_hash(receipt):
        return False, CODE_RECEIPT_SIG_INVALID, False
    if not verify_canonical(
        exec_card["gateway_principal"]["public_key_hex"],
        receipt["executor_sig_hex"],
        DOMAIN_TASK_RECEIPT,
        receipt_signing_payload(receipt),
    ):
        return False, CODE_RECEIPT_SIG_INVALID, False

    egress_block = receipt.get("egress_block")
    if egress_block is not None:
        if egress_block["wire_bytes_sent"] != 0:
            return False, CODE_CREDENTIAL_LEAK_DETECTED, False
        if not verify_canonical(
            exec_card["gateway_principal"]["public_key_hex"],
            egress_block["event_sig_hex"],
            DOMAIN_EGRESS_BLOCK,
            egress_block_signing_payload(egress_block),
        ):
            return False, CODE_RECEIPT_SIG_INVALID, False

    recompute_ok = False
    res = receipt.get("result")
    if res is not None and env is not None:
        try:
            expected = run_deterministic_zhl(env["payload"]["task_id"], env["payload"]["commitment"])
        except Exception:
            return False, CODE_RESULT_RECOMPUTE_MISMATCH, False
        if (
            res["result_hash"] != compute_scientific_result_hash(res)
            or res["result_hash"] != expected["result_hash"]
            or res["mean_a_micro"] != expected["mean_a_micro"]
            or res["mean_b_micro"] != expected["mean_b_micro"]
            or res["effect_size_micro"] != expected["effect_size_micro"]
            or res["stat_micro"] != expected["stat_micro"]
            or res["significant"] != expected["significant"]
        ):
            return False, CODE_RESULT_RECOMPUTE_MISMATCH, False
        recompute_ok = True

    if acceptance is not None:
        if acceptance["reviewer_role"] == ROLE_AI_AGENT:
            return False, CODE_AI_SELF_CERTIFY_FORBIDDEN, recompute_ok
        pol = policies.get(acceptance["org_id"])
        if pol is None:
            return False, CODE_AI_SELF_CERTIFY_FORBIDDEN, recompute_ok
        pr = _find_principal(pol, acceptance["reviewer_id"])
        if pr is None or pr["role"] not in (ROLE_HUMAN_REVIEWER, ROLE_COUNCIL_MEMBER):
            return False, CODE_AI_SELF_CERTIFY_FORBIDDEN, recompute_ok
        if not verify_canonical(
            pr["public_key_hex"],
            acceptance["acceptance_sig_hex"],
            DOMAIN_ACCEPTANCE,
            acceptance_signing_payload(acceptance),
        ):
            return False, CODE_RECEIPT_SIG_INVALID, recompute_ok
        if acceptance["receipt_hash"] != receipt["receipt_hash"]:
            return False, CODE_RECEIPT_SIG_INVALID, recompute_ok
        if res is not None and acceptance["recomputed_hash"] != res["result_hash"]:
            return False, CODE_RESULT_RECOMPUTE_MISMATCH, recompute_ok

    return True, CODE_OK, recompute_ok


def verify_governance_action(action: Dict[str, Any], policies: Dict[str, Dict[str, Any]]) -> Tuple[bool, str]:
    if action["proposer_role"] == ROLE_AI_AGENT:
        if action["action_type"] == "voting_rule_change":
            return False, CODE_AI_VOTING_RULE_FORBIDDEN
        if action["action_type"] == "treasury_spend":
            return False, CODE_AI_TREASURY_FORBIDDEN
        return False, CODE_SCOPE_ESCALATION
    pol = policies.get(action["org_id"])
    if pol is None:
        return False, CODE_SCOPE_ESCALATION
    pr = _find_principal(pol, action["proposer_id"])
    if pr is None or pr["role"] != ROLE_COUNCIL_MEMBER:
        return False, CODE_SCOPE_ESCALATION
    if not verify_canonical(
        pr["public_key_hex"],
        action["signature_hex"],
        DOMAIN_GOVERNANCE_ACTION,
        governance_action_signing_payload(action),
    ):
        return False, CODE_ENVELOPE_SIG_INVALID
    return True, CODE_OK


def verify_advisory(adv: Dict[str, Any], policies: Dict[str, Dict[str, Any]]) -> Tuple[bool, str]:
    if adv["binding"]:
        return False, CODE_AI_SELF_CERTIFY_FORBIDDEN
    pol = policies.get(adv["org_id"])
    if pol is None:
        return False, CODE_SPOOFED_ORG_IDENTITY
    pr = _find_principal(pol, adv["agent_id"])
    if pr is None or pr["role"] != ROLE_AI_AGENT:
        return False, CODE_SPOOFED_ORG_IDENTITY
    if not verify_canonical(
        pr["public_key_hex"],
        adv["signature_hex"],
        DOMAIN_ADVISORY,
        advisory_signing_payload(adv),
    ):
        return False, CODE_ENVELOPE_SIG_INVALID
    return True, CODE_OK


def compute_wire_transcript_root(frames: List[Dict[str, Any]]) -> str:
    leaves = [
        hash_canonical(
            DOMAIN_WIRE_FRAME,
            {
                "content_type": f["content_type"],
                "frame_id": f["frame_id"],
                "from_org_id": f["from_org_id"],
                "http_method": f["http_method"],
                "http_status": f["http_status"],
                "path": f["path"],
                "request_bytes": f["request_bytes"],
                "request_sha256": f["request_sha256"],
                "response_bytes": f["response_bytes"],
                "response_sha256": f["response_sha256"],
                "stage": f["stage"],
                "to_org_id": f["to_org_id"],
            },
        )
        for f in frames
    ]
    return merkle_root_rfc6962(leaves)


def verify_wire_transcript(frames: List[Dict[str, Any]], probes: List[Dict[str, Any]]) -> Dict[str, Any]:
    total_bytes = 0
    cred_bytes = 0
    mem_bytes = 0
    trace_bytes = 0
    all_hashes_ok = True

    for f in frames:
        req_b = f["request_body"].encode("utf-8")
        resp_b = f["response_body"].encode("utf-8")
        total_bytes += len(req_b) + len(resp_b)
        if (
            len(req_b) != f["request_bytes"]
            or len(resp_b) != f["response_bytes"]
            or sha256_hex(req_b) != f["request_sha256"]
            or sha256_hex(resp_b) != f["response_sha256"]
        ):
            all_hashes_ok = False
        c1, m1, t1, _, _ = scan_boundary_probes(req_b, probes)
        c2, m2, t2, _, _ = scan_boundary_probes(resp_b, probes)
        cred_bytes += c1 + c2
        mem_bytes += m1 + m2
        trace_bytes += t1 + t2

    return {
        "total_frames": len(frames),
        "total_wire_bytes": total_bytes,
        "credential_leak_bytes": cred_bytes,
        "private_memory_leak_bytes": mem_bytes,
        "raw_trace_leak_bytes": trace_bytes,
        "wire_transcript_root": compute_wire_transcript_root(frames),
        "all_frame_hashes_valid": all_hashes_ok,
        "zero_boundary_leakage": cred_bytes == 0 and mem_bytes == 0 and trace_bytes == 0,
    }


def compute_audit_merkle_root(
    wire: Dict[str, Any],
    stages: List[Dict[str, Any]],
    adv: List[Dict[str, Any]],
) -> str:
    leaves: List[str] = [
        hash_canonical(
            DOMAIN_AUDIT_LEAF,
            {
                "all_frame_hashes_valid": wire["all_frame_hashes_valid"],
                "credential_leak_bytes": wire["credential_leak_bytes"],
                "kind": "wire_audit",
                "private_memory_leak_bytes": wire["private_memory_leak_bytes"],
                "raw_trace_leak_bytes": wire["raw_trace_leak_bytes"],
                "total_frames": wire["total_frames"],
                "total_wire_bytes": wire["total_wire_bytes"],
                "wire_transcript_root": wire["wire_transcript_root"],
                "zero_boundary_leakage": wire["zero_boundary_leakage"],
            },
        )
    ]
    for s in stages:
        leaves.append(
            hash_canonical(
                DOMAIN_AUDIT_LEAF,
                {
                    "code": s["code"],
                    "credential_leak_bytes": s["credential_leak_bytes"],
                    "kind": "stage",
                    "private_memory_leak_bytes": s["private_memory_leak_bytes"],
                    "raw_trace_leak_bytes": s["raw_trace_leak_bytes"],
                    "recompute_verified": s["recompute_verified"],
                    "stage": s["stage"],
                    "task_state": s["task_state"],
                    "valid": s["valid"],
                    "wire_frames_checked": s["wire_frames_checked"],
                },
            )
        )
    for c in sorted(adv, key=lambda x: x["case_id"]):
        leaves.append(
            hash_canonical(
                DOMAIN_AUDIT_LEAF,
                {
                    "actual_code": c["actual_code"],
                    "actual_valid": c["actual_valid"],
                    "case_id": c["case_id"],
                    "category": c["category"],
                    "expected_code": c["expected_code"],
                    "expected_valid": c["expected_valid"],
                    "kind": "adversarial",
                    "matched": c["matched"],
                },
            )
        )
    return merkle_root_rfc6962(leaves)


def verify_suite(suite: Dict[str, Any]) -> Dict[str, Any]:
    policies = {p["org_id"]: p for p in suite.get("org_policies") or []}
    cards = {c["org_id"]: c for c in suite.get("agent_cards") or []}
    probes = suite.get("boundary_probes") or []
    frames = suite.get("wire_transcript") or []
    frames_by_id = {f["frame_id"]: f for f in frames}

    wire_audit = verify_wire_transcript(frames, probes)

    all_cards_ok = len(suite.get("agent_cards") or []) >= 2
    card_code = CODE_OK
    for card in suite.get("agent_cards") or []:
        ok, code = verify_agent_card(card, policies, probes)
        if not ok:
            all_cards_ok = False
            card_code = code
            break

    stage_outcomes: List[Dict[str, Any]] = []
    all_stages_valid = all_cards_ok and wire_audit["all_frame_hashes_valid"] and wire_audit["zero_boundary_leakage"]
    seen_nonces_by_org: Dict[str, List[str]] = {}

    for st in suite.get("live_stages") or []:
        st_cred = 0
        st_mem = 0
        st_trace = 0
        checked_frames = 0
        for fid in st.get("wire_frame_ids") or []:
            wf = frames_by_id.get(fid)
            if wf is None:
                continue
            checked_frames += 1
            c1, m1, t1, _, _ = scan_boundary_probes(wf["request_body"].encode("utf-8"), probes)
            c2, m2, t2, _, _ = scan_boundary_probes(wf["response_body"].encode("utf-8"), probes)
            st_cred += c1 + c2
            st_mem += m1 + m2
            st_trace += t1 + t2

        stage_valid = True
        stage_code = CODE_OK
        task_state = st["expected_state"]
        recompute_ok = False

        if st_cred > 0 or st_mem > 0 or st_trace > 0:
            stage_valid = False
            stage_code = CODE_CREDENTIAL_LEAK_DETECTED

        if stage_valid and st["stage"] == "1_discover_agent_cards":
            if not all_cards_ok:
                stage_valid = False
                stage_code = card_code

        env = st.get("envelope")
        if stage_valid and env is not None:
            recv_org = env["audience_org_id"]
            prior = seen_nonces_by_org.get(recv_org, [])
            ok, code = verify_envelope(env, recv_org, st["verified_at"], prior, cards, policies, probes)
            if not ok:
                stage_valid = False
                stage_code = code
            else:
                seen_nonces_by_org.setdefault(recv_org, []).append(env["task_nonce"])

        adv = st.get("advisory")
        if stage_valid and adv is not None:
            ok, code = verify_advisory(adv, policies)
            if not ok:
                stage_valid = False
                stage_code = code

        rcpt = st.get("receipt")
        if stage_valid and rcpt is not None:
            task_state = rcpt["state"]
            ok, code, rec_ok = verify_receipt(env, rcpt, st.get("acceptance"), cards, policies, probes)
            recompute_ok = rec_ok
            if not ok:
                stage_valid = False
                stage_code = code
            elif rcpt["state"] != st["expected_state"] or rcpt["error_code"] != st["expected_error_code"]:
                stage_valid = False
                stage_code = CODE_TASK_STATE_INVALID

        if stage_valid and st["stage"] == "7_wire_transcript_boundary_audit":
            if not wire_audit["all_frame_hashes_valid"] or not wire_audit["zero_boundary_leakage"]:
                stage_valid = False
                stage_code = CODE_CREDENTIAL_LEAK_DETECTED

        if not stage_valid:
            all_stages_valid = False

        stage_outcomes.append(
            {
                "stage": st["stage"],
                "valid": stage_valid,
                "code": stage_code,
                "task_state": task_state,
                "wire_frames_checked": checked_frames,
                "credential_leak_bytes": st_cred,
                "private_memory_leak_bytes": st_mem,
                "raw_trace_leak_bytes": st_trace,
                "recompute_verified": recompute_ok,
            }
        )

    adv_results: List[Dict[str, Any]] = []
    all_adv_pass = True
    attacks_detected = 0
    attacks_total = 0
    positive_pass = 0

    for tc in suite.get("adversarial_cases") or []:
        target = tc["target"]
        actual_valid = False
        actual_code = CODE_TASK_STATE_INVALID
        if target == "agent_card" and tc.get("agent_card") is not None:
            actual_valid, actual_code = verify_agent_card(tc["agent_card"], policies, probes)
        elif target == "envelope" and tc.get("envelope") is not None:
            actual_valid, actual_code = verify_envelope(
                tc["envelope"],
                tc.get("receiver_org_id", ""),
                tc["verified_at"],
                tc.get("prior_nonces") or [],
                cards,
                policies,
                probes,
            )
        elif target == "receipt" and tc.get("receipt") is not None:
            actual_valid, actual_code, _ = verify_receipt(
                tc.get("envelope"),
                tc["receipt"],
                tc.get("acceptance"),
                cards,
                policies,
                probes,
            )
        elif target == "governance" and tc.get("governance_action") is not None:
            actual_valid, actual_code = verify_governance_action(tc["governance_action"], policies)
        elif target == "advisory" and tc.get("advisory") is not None:
            actual_valid, actual_code = verify_advisory(tc["advisory"], policies)

        matched = (actual_valid == tc["expected_valid"]) and (actual_code == tc["expected_code"])
        if not matched:
            all_adv_pass = False
        if not tc["expected_valid"]:
            attacks_total += 1
            if matched:
                attacks_detected += 1
        elif matched:
            positive_pass += 1

        adv_results.append(
            {
                "case_id": tc["case_id"],
                "category": tc["category"],
                "expected_valid": tc["expected_valid"],
                "actual_valid": actual_valid,
                "expected_code": tc["expected_code"],
                "actual_code": actual_code,
                "matched": matched,
            }
        )

    audit_root = compute_audit_merkle_root(wire_audit, stage_outcomes, adv_results)

    return {
        "schema_version": SCHEMA_VERSION,
        "spec_version": SPEC_VERSION,
        "seed": suite["seed"],
        "all_stages_valid": all_stages_valid,
        "all_adversarial_pass": all_adv_pass,
        "attacks_detected": attacks_detected,
        "attacks_total": attacks_total,
        "positive_cases_pass": positive_pass,
        "wire_audit": wire_audit,
        "stage_outcomes": stage_outcomes,
        "adversarial_results": adv_results,
        "audit_merkle_root": audit_root,
    }

# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.

"""100% offline fail-closed verifier mirroring Go agentid/verifier.go bit-for-bit."""

import hmac
from typing import Any, Dict, List, Optional, Tuple

from .bitstring import bitstring_is_revoked, decode_bitstring
from .canonical import (
    decode_base64url,
    domain_message,
    hash_canonical,
    merkle_root_rfc6962,
    public_key_from_did_key,
)
from .ed25519 import verify_ed25519

SCHEMA_VERSION = "agent-identity-delegation.v1"
SPEC_VERSION = "1.0.0"

DOMAIN_DID_DOC = "zoo.agentid.v1.diddoc"
DOMAIN_KEY_ROTATION = "zoo.agentid.v1.keyrot"
DOMAIN_VC = "zoo.agentid.v1.vc"
DOMAIN_STATUS_LIST = "zoo.agentid.v1.statuslist"
DOMAIN_REV_SNAPSHOT = "zoo.agentid.v1.revsnapshot"
DOMAIN_HOLDER_PROOF = "zoo.agentid.v1.holderproof"
DOMAIN_AUDIT_LEAF = "zoo.agentid.v1.auditleaf"

PRINCIPAL_HUMAN_COUNCIL = "HUMAN_COUNCIL"
PRINCIPAL_ORG_CONTROLLER = "ORG_CONTROLLER"
PRINCIPAL_AI_AGENT = "AI_AGENT"
PRINCIPAL_EPHEMERAL_SESSION = "EPHEMERAL_SESSION"

HOLDER_PROOF_MAX_PAST_SKEW = 300
HOLDER_PROOF_MAX_FUTURE_SKEW = 30

RESERVED_GOVERNANCE_SCOPES = {
    "governance:vote_rules",
    "treasury:authorize",
    "experiment:certify",
}

ERR_DID_INVALID_FORMAT = "ERR_DID_INVALID_FORMAT"
ERR_DID_KEY_BINDING_MISMATCH = "ERR_DID_KEY_BINDING_MISMATCH"
ERR_DID_SIGNATURE_INVALID = "ERR_DID_SIGNATURE_INVALID"
ERR_DID_NOT_FOUND = "ERR_DID_NOT_FOUND"
ERR_KEY_NOT_FOUND = "ERR_KEY_NOT_FOUND"
ERR_KEY_ROTATION_INVALID = "ERR_KEY_ROTATION_INVALID"
ERR_CHAIN_EMPTY = "ERR_CHAIN_EMPTY"
ERR_UNTRUSTED_ROOT = "ERR_UNTRUSTED_ROOT"
ERR_CHAIN_LINK_BROKEN = "ERR_CHAIN_LINK_BROKEN"
ERR_PARENT_DIGEST_MISMATCH = "ERR_PARENT_DIGEST_MISMATCH"
ERR_CYCLIC_DELEGATION = "ERR_CYCLIC_DELEGATION"
ERR_VC_SIGNATURE_INVALID = "ERR_VC_SIGNATURE_INVALID"
ERR_DEPTH_OVERFLOW = "ERR_DEPTH_OVERFLOW"
ERR_SCOPE_ESCALATION = "ERR_SCOPE_ESCALATION"
ERR_RESOURCE_ESCALATION = "ERR_RESOURCE_ESCALATION"
ERR_CONSTRAINT_ESCALATION = "ERR_CONSTRAINT_ESCALATION"
ERR_TTL_EXTENSION = "ERR_TTL_EXTENSION"
ERR_VC_EXPIRED = "ERR_VC_EXPIRED"
ERR_VC_NOT_YET_VALID = "ERR_VC_NOT_YET_VALID"
ERR_AUDIENCE_MISMATCH = "ERR_AUDIENCE_MISMATCH"
ERR_CONSTITUTIONAL_AI_GOV_FORBIDDEN = "ERR_CONSTITUTIONAL_AI_GOVERNANCE_FORBIDDEN"
ERR_STATUS_LIST_MISSING = "ERR_STATUS_LIST_MISSING"
ERR_STATUS_LIST_SIGNATURE_INVALID = "ERR_STATUS_LIST_SIGNATURE_INVALID"
ERR_STATUS_LIST_STALE = "ERR_STATUS_LIST_STALE"
ERR_STATUS_LIST_DIGEST_MISMATCH = "ERR_STATUS_LIST_DIGEST_MISMATCH"
ERR_STATUS_LIST_INDEX_OUT_OF_BOUNDS = "ERR_STATUS_LIST_INDEX_OUT_OF_BOUNDS"
ERR_REVOCATION_SNAPSHOT_SIGNATURE = "ERR_REVOCATION_SNAPSHOT_SIGNATURE_INVALID"
ERR_REVOCATION_SNAPSHOT_STALE = "ERR_REVOCATION_SNAPSHOT_STALE"
ERR_REVOCATION_SNAPSHOT_MERKLE_MISMATCH = "ERR_REVOCATION_SNAPSHOT_MERKLE_MISMATCH"
ERR_VC_REVOKED_BITSTRING = "ERR_VC_REVOKED_BITSTRING"
ERR_CASCADE_PARENT_REVOKED = "ERR_CASCADE_PARENT_REVOKED"
ERR_KEY_REVOKED_BEFORE_CUTOFF = "ERR_KEY_REVOKED_BEFORE_CUTOFF"
ERR_KEY_COMPROMISED_REVOKED = "ERR_KEY_COMPROMISED_REVOKED"
ERR_HOLDER_PROOF_MISSING = "ERR_HOLDER_PROOF_MISSING"
ERR_HOLDER_DID_MISMATCH = "ERR_HOLDER_DID_MISMATCH"
ERR_HOLDER_BINDING_MISMATCH = "ERR_HOLDER_BINDING_MISMATCH"
ERR_HOLDER_SIGNATURE_INVALID = "ERR_HOLDER_SIGNATURE_INVALID"
ERR_HOLDER_PROOF_STALE = "ERR_HOLDER_PROOF_STALE"
ERR_NONCE_REPLAY = "ERR_NONCE_REPLAY"
ERR_ACTION_SCOPE_DENIED = "ERR_ACTION_SCOPE_DENIED"
ERR_ACTION_RESOURCE_DENIED = "ERR_ACTION_RESOURCE_DENIED"


def _verify_domain(pub_b64: str, domain: str, payload: Any, sig_b64: str) -> bool:
    try:
        pub = decode_base64url(pub_b64)
        sig = decode_base64url(sig_b64)
    except Exception:
        return False
    if len(pub) != 32 or len(sig) != 64:
        return False
    msg = domain_message(domain, payload)
    return verify_ed25519(pub, msg, sig)


def _unsigned_did_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    proof = doc.get("proof") or {}
    m: Dict[str, Any] = {
        "@context": list(doc.get("@context") or []),
        "id": doc.get("id", ""),
        "principal_type": doc.get("principal_type", ""),
        "controller": doc.get("controller", ""),
        "genesis_key_id": doc.get("genesis_key_id", ""),
        "genesis_public_key_b64": doc.get("genesis_public_key_b64", ""),
        "active_key_id": doc.get("active_key_id", ""),
        "verification_methods": list(doc.get("verification_methods") or []),
        "key_rotations": list(doc.get("key_rotations") or []),
        "portable_export": bool(doc.get("portable_export", False)),
        "proof_meta": {
            "type": proof.get("type", ""),
            "cryptosuite": proof.get("cryptosuite", ""),
            "verification_method": proof.get("verification_method", ""),
            "created": proof.get("created", 0),
        },
    }
    if doc.get("agent_nft_binding") is not None:
        m["agent_nft_binding"] = doc["agent_nft_binding"]
    return m


def _unsigned_key_rotation(rot: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "did": rot.get("did", ""),
        "from_key_id": rot.get("from_key_id", ""),
        "to_key_id": rot.get("to_key_id", ""),
        "new_public_key_b64": rot.get("new_public_key_b64", ""),
        "rotated_at": rot.get("rotated_at", 0),
        "reason": rot.get("reason", ""),
        "controller_key_id": rot.get("controller_key_id", ""),
    }


def _unsigned_vc(vc: Dict[str, Any]) -> Dict[str, Any]:
    subj = vc.get("credential_subject") or {}
    proof = vc.get("proof") or {}
    return {
        "@context": list(vc.get("@context") or []),
        "id": vc.get("id", ""),
        "type": list(vc.get("type") or []),
        "issuer": vc.get("issuer", ""),
        "issuer_key_id": vc.get("issuer_key_id", ""),
        "valid_from": vc.get("valid_from", 0),
        "valid_until": vc.get("valid_until", 0),
        "credential_status": vc.get("credential_status") or {},
        "credential_subject": {
            "id": subj.get("id", ""),
            "subject_principal_type": subj.get("subject_principal_type", ""),
            "delegation_depth": subj.get("delegation_depth", 0),
            "max_sub_depth": subj.get("max_sub_depth", 0),
            "parent_vc_id": subj.get("parent_vc_id", ""),
            "parent_vc_digest": subj.get("parent_vc_digest", ""),
            "audience": subj.get("audience", ""),
            "scopes": list(subj.get("scopes") or []),
            "allowed_resources": list(subj.get("allowed_resources") or []),
            "constraints": subj.get("constraints") or {},
            "nonce": subj.get("nonce", ""),
        },
        "proof_meta": {
            "type": proof.get("type", ""),
            "cryptosuite": proof.get("cryptosuite", ""),
            "verification_method": proof.get("verification_method", ""),
            "created": proof.get("created", 0),
        },
    }


def _unsigned_status_list(sl: Dict[str, Any]) -> Dict[str, Any]:
    proof = sl.get("proof") or {}
    return {
        "@context": list(sl.get("@context") or []),
        "id": sl.get("id", ""),
        "type": list(sl.get("type") or []),
        "issuer": sl.get("issuer", ""),
        "issuer_key_id": sl.get("issuer_key_id", ""),
        "valid_from": sl.get("valid_from", 0),
        "valid_until": sl.get("valid_until", 0),
        "credential_subject": sl.get("credential_subject") or {},
        "proof_meta": {
            "type": proof.get("type", ""),
            "cryptosuite": proof.get("cryptosuite", ""),
            "verification_method": proof.get("verification_method", ""),
            "created": proof.get("created", 0),
        },
    }


def _unsigned_revocation_snapshot(snap: Dict[str, Any]) -> Dict[str, Any]:
    proof = snap.get("proof") or {}
    return {
        "snapshot_id": snap.get("snapshot_id", ""),
        "issuer": snap.get("issuer", ""),
        "issuer_key_id": snap.get("issuer_key_id", ""),
        "issued_at": snap.get("issued_at", 0),
        "valid_until": snap.get("valid_until", 0),
        "status_list_digests": list(snap.get("status_list_digests") or []),
        "key_revocations": list(snap.get("key_revocations") or []),
        "revoked_vc_ids": list(snap.get("revoked_vc_ids") or []),
        "crl_merkle_root": snap.get("crl_merkle_root", ""),
        "proof_meta": {
            "type": proof.get("type", ""),
            "cryptosuite": proof.get("cryptosuite", ""),
            "verification_method": proof.get("verification_method", ""),
            "created": proof.get("created", 0),
        },
    }


def _unsigned_holder_proof(hp: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "holder_did": hp.get("holder_did", ""),
        "holder_key_id": hp.get("holder_key_id", ""),
        "delegation_chain_digest": hp.get("delegation_chain_digest", ""),
        "challenge_nonce": hp.get("challenge_nonce", ""),
        "audience": hp.get("audience", ""),
        "action_verb": hp.get("action_verb", ""),
        "resource_uri": hp.get("resource_uri", ""),
        "timestamp": hp.get("timestamp", 0),
    }


def compute_vc_digest(vc: Dict[str, Any]) -> str:
    return hash_canonical(
        DOMAIN_VC,
        {
            "unsigned": _unsigned_vc(vc),
            "signature_b64": (vc.get("proof") or {}).get("signature_b64", ""),
        },
    )


def compute_status_list_digest(sl: Dict[str, Any]) -> str:
    return hash_canonical(
        DOMAIN_STATUS_LIST,
        {
            "unsigned": _unsigned_status_list(sl),
            "signature_b64": (sl.get("proof") or {}).get("signature_b64", ""),
        },
    )


def compute_delegation_chain_digest(chain: List[Dict[str, Any]]) -> str:
    return hash_canonical(DOMAIN_VC + ".chain", [compute_vc_digest(vc) for vc in chain])


def compute_crl_merkle_root(revoked_vc_ids: List[str], key_revs: List[Dict[str, Any]]) -> str:
    leaves: List[str] = [f"vc:{vc_id}" for vc_id in revoked_vc_ids]
    for kr in key_revs:
        rev_all = "true" if kr.get("revoke_all", False) else "false"
        leaves.append(f"key:{kr.get('did', '')}|{kr.get('key_id', '')}|{kr.get('revoked_before', 0)}|{rev_all}")
    leaves.sort()
    return merkle_root_rfc6962(leaves)


def _validate_did_structure(doc: Dict[str, Any]) -> Tuple[str, str]:
    did = doc.get("id", "")
    if not (did.startswith("did:zoo:") or did.startswith("did:key:z")):
        return ERR_DID_INVALID_FORMAT, f"unsupported DID format: {did}"
    if (
        not doc.get("portable_export")
        or not doc.get("genesis_key_id")
        or not doc.get("genesis_public_key_b64")
        or not doc.get("active_key_id")
    ):
        return ERR_DID_INVALID_FORMAT, f"DID {did} missing required portable export fields"
    try:
        gen_pub = decode_base64url(doc["genesis_public_key_b64"])
    except Exception:
        return ERR_DID_INVALID_FORMAT, f"DID {did} has invalid genesis_public_key_b64"
    if len(gen_pub) != 32:
        return ERR_DID_INVALID_FORMAT, f"DID {did} has invalid genesis_public_key_b64 length"
    if did.startswith("did:key:z"):
        try:
            derived_pub = public_key_from_did_key(did)
        except Exception as exc:
            return ERR_DID_INVALID_FORMAT, f"invalid did:key {did}: {exc}"
        if not hmac.compare_digest(gen_pub, derived_pub):
            return ERR_DID_KEY_BINDING_MISMATCH, f"did:key {did} public key does not match multicodec identifier"
    return "", ""


def _verify_unrotated_did(doc: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], str, str]:
    did = doc["id"]
    if doc["active_key_id"] != doc["genesis_key_id"]:
        return None, ERR_KEY_ROTATION_INVALID, f"DID {did} active_key_id != genesis_key_id without rotation proofs"
    vms = doc.get("verification_methods") or []
    if len(vms) != 1:
        return None, ERR_KEY_ROTATION_INVALID, f"unrotated DID {did} must have exactly 1 verification method"
    vm = vms[0]
    if vm.get("id") != doc["genesis_key_id"] or vm.get("public_key_b64") != doc["genesis_public_key_b64"]:
        return None, ERR_DID_KEY_BINDING_MISMATCH, f"DID {did} genesis verification method mismatch"
    proof = doc.get("proof") or {}
    if proof.get("verification_method") != doc["active_key_id"]:
        return None, ERR_DID_SIGNATURE_INVALID, f"DID {did} proof verification_method must equal active_key_id"
    if not _verify_domain(vm["public_key_b64"], DOMAIN_DID_DOC, _unsigned_did_doc(doc), proof.get("signature_b64", "")):
        return None, ERR_DID_SIGNATURE_INVALID, f"DID {did} self-signature invalid"
    return {
        "doc": doc,
        "authorized_keys": {vm["id"]: vm},
        "active_key": vm,
        "verified_rot_cnt": 0,
        "signature_checks": 1,
    }, "", ""


def _verify_rotated_did(
    doc: Dict[str, Any], controller_vd: Optional[Dict[str, Any]]
) -> Tuple[Optional[Dict[str, Any]], str, str]:
    did = doc["id"]
    vms = doc.get("verification_methods") or []
    vm_by_id = {vm["id"]: vm for vm in vms}
    gen_vm = vm_by_id.get(doc["genesis_key_id"])
    if gen_vm is None or gen_vm.get("public_key_b64") != doc["genesis_public_key_b64"]:
        return None, ERR_DID_KEY_BINDING_MISMATCH, f"DID {did} missing matching genesis verification method"

    authorized = {gen_vm["id"]: gen_vm}
    cur_key_id = gen_vm["id"]
    cur_pub_b64 = gen_vm["public_key_b64"]
    sig_checks = 0
    rotations = doc.get("key_rotations") or []

    for rot in rotations:
        if rot.get("did") != did or rot.get("from_key_id") != cur_key_id:
            return None, ERR_KEY_ROTATION_INVALID, f"DID {did} rotation link broken"
        next_vm = vm_by_id.get(rot.get("to_key_id", ""))
        if next_vm is None or next_vm.get("public_key_b64") != rot.get("new_public_key_b64"):
            return None, ERR_KEY_ROTATION_INVALID, f"DID {did} rotation target key missing or mismatched"
        sig_checks += 1
        if not _verify_domain(cur_pub_b64, DOMAIN_KEY_ROTATION, _unsigned_key_rotation(rot), rot.get("outgoing_sig_b64", "")):
            return None, ERR_KEY_ROTATION_INVALID, f"DID {did} rotation outgoing signature invalid"
        ctrl_key_id = rot.get("controller_key_id", "")
        if controller_vd is not None:
            cvm = controller_vd["authorized_keys"].get(ctrl_key_id)
        else:
            cvm = authorized.get(ctrl_key_id)
        if cvm is None:
            return None, ERR_KEY_ROTATION_INVALID, f"DID {did} rotation controller key {ctrl_key_id} not authorized"
        sig_checks += 1
        if not _verify_domain(
            cvm["public_key_b64"], DOMAIN_KEY_ROTATION, _unsigned_key_rotation(rot), rot.get("controller_sig_b64", "")
        ):
            return None, ERR_KEY_ROTATION_INVALID, f"DID {did} rotation controller co-signature invalid"
        authorized[next_vm["id"]] = next_vm
        cur_key_id = next_vm["id"]
        cur_pub_b64 = next_vm["public_key_b64"]

    if cur_key_id != doc["active_key_id"]:
        return None, ERR_KEY_ROTATION_INVALID, f"DID {did} active_key_id != final rotated key"
    if len(authorized) != len(vms):
        return None, ERR_KEY_ROTATION_INVALID, f"DID {did} contains unauthorized verification methods"
    proof = doc.get("proof") or {}
    if proof.get("verification_method") != doc["active_key_id"]:
        return None, ERR_DID_SIGNATURE_INVALID, f"DID {did} proof verification_method != active_key_id"
    sig_checks += 1
    if not _verify_domain(cur_pub_b64, DOMAIN_DID_DOC, _unsigned_did_doc(doc), proof.get("signature_b64", "")):
        return None, ERR_DID_SIGNATURE_INVALID, f"DID {did} active-key self-signature invalid"

    return {
        "doc": doc,
        "authorized_keys": authorized,
        "active_key": authorized[cur_key_id],
        "verified_rot_cnt": len(rotations),
        "signature_checks": sig_checks,
    }, "", ""


def prepare_epoch(ctx: Dict[str, Any], eval_time: int) -> Tuple[Optional[Dict[str, Any]], str, str]:
    """Verify all portable DID documents, key rotations, RevocationSnapshot, and BitstringStatusLists offline."""
    trusted_roots = set(ctx.get("trusted_root_dids") or [])
    docs = list(ctx.get("did_documents") or [])

    verified_dids: Dict[str, Dict[str, Any]] = {}
    total_rotations = 0
    total_sig_checks = 0

    for doc in docs:
        err_code, err_msg = _validate_did_structure(doc)
        if err_code:
            return None, err_code, err_msg
        if not (doc.get("key_rotations") or []):
            vd, err_code, err_msg = _verify_unrotated_did(doc)
            if err_code:
                return None, err_code, err_msg
            assert vd is not None
            verified_dids[doc["id"]] = vd
            total_sig_checks += vd["signature_checks"]

    pending = [doc for doc in docs if (doc.get("key_rotations") or [])]
    for _ in range(len(docs) + 1):
        if not pending:
            break
        next_pending = []
        progressed = False
        for doc in pending:
            ctrl = doc.get("controller", "")
            if ctrl == doc["id"]:
                vd, err_code, err_msg = _verify_rotated_did(doc, None)
                if err_code:
                    return None, err_code, err_msg
                assert vd is not None
                verified_dids[doc["id"]] = vd
                total_rotations += vd["verified_rot_cnt"]
                total_sig_checks += vd["signature_checks"]
                progressed = True
                continue
            ctrl_vd = verified_dids.get(ctrl)
            if ctrl_vd is None:
                next_pending.append(doc)
                continue
            vd, err_code, err_msg = _verify_rotated_did(doc, ctrl_vd)
            if err_code:
                return None, err_code, err_msg
            assert vd is not None
            verified_dids[doc["id"]] = vd
            total_rotations += vd["verified_rot_cnt"]
            total_sig_checks += vd["signature_checks"]
            progressed = True
        pending = next_pending
        if not progressed and pending:
            return None, ERR_KEY_ROTATION_INVALID, f"unresolved controller {pending[0].get('controller')} for rotated DID"

    snap = ctx.get("revocation_snapshot") or {}
    snap_issuer_did = snap.get("issuer", "")
    if snap_issuer_did not in trusted_roots:
        return None, ERR_UNTRUSTED_ROOT, f"revocation snapshot issuer {snap_issuer_did} is not trusted"
    snap_issuer = verified_dids.get(snap_issuer_did)
    if snap_issuer is None:
        return None, ERR_DID_NOT_FOUND, f"revocation snapshot issuer DID {snap_issuer_did} not found"
    snap_key_id = snap.get("issuer_key_id", "")
    snap_key = snap_issuer["authorized_keys"].get(snap_key_id)
    if snap_key is None or (snap.get("proof") or {}).get("verification_method") != snap_key_id:
        return None, ERR_KEY_NOT_FOUND, f"revocation snapshot key {snap_key_id} not authorized"
    total_sig_checks += 1
    if not _verify_domain(
        snap_key["public_key_b64"],
        DOMAIN_REV_SNAPSHOT,
        _unsigned_revocation_snapshot(snap),
        (snap.get("proof") or {}).get("signature_b64", ""),
    ):
        return None, ERR_REVOCATION_SNAPSHOT_SIGNATURE, "revocation snapshot signature verification failed"
    if eval_time < snap.get("issued_at", 0) or eval_time > snap.get("valid_until", 0):
        return None, ERR_REVOCATION_SNAPSHOT_STALE, "revocation snapshot stale"
    expected_crl = compute_crl_merkle_root(
        list(snap.get("revoked_vc_ids") or []),
        list(snap.get("key_revocations") or []),
    )
    if snap.get("crl_merkle_root", "") != expected_crl:
        return None, ERR_REVOCATION_SNAPSHOT_MERKLE_MISMATCH, "crl_merkle_root mismatch"

    pinned_digests = {
        pin["status_list_id"]: pin["digest_sha256"] for pin in (snap.get("status_list_digests") or [])
    }

    status_bytes: Dict[str, bytes] = {}
    status_bit_lens: Dict[str, int] = {}
    for sl in ctx.get("status_lists") or []:
        sl_issuer_did = sl.get("issuer", "")
        if sl_issuer_did not in trusted_roots:
            return None, ERR_UNTRUSTED_ROOT, f"status list issuer {sl_issuer_did} is not trusted"
        sl_issuer = verified_dids.get(sl_issuer_did)
        if sl_issuer is None:
            return None, ERR_DID_NOT_FOUND, f"status list issuer DID {sl_issuer_did} not found"
        sl_key_id = sl.get("issuer_key_id", "")
        sl_key = sl_issuer["authorized_keys"].get(sl_key_id)
        if sl_key is None or (sl.get("proof") or {}).get("verification_method") != sl_key_id:
            return None, ERR_KEY_NOT_FOUND, f"status list key {sl_key_id} not authorized"
        total_sig_checks += 1
        if not _verify_domain(
            sl_key["public_key_b64"],
            DOMAIN_STATUS_LIST,
            _unsigned_status_list(sl),
            (sl.get("proof") or {}).get("signature_b64", ""),
        ):
            return None, ERR_STATUS_LIST_SIGNATURE_INVALID, f"status list {sl.get('id')} signature invalid"
        if eval_time < sl.get("valid_from", 0) or eval_time > sl.get("valid_until", 0):
            return None, ERR_STATUS_LIST_STALE, f"status list {sl.get('id')} stale"
        if sl["id"] in pinned_digests and compute_status_list_digest(sl) != pinned_digests[sl["id"]]:
            return None, ERR_STATUS_LIST_DIGEST_MISMATCH, f"status list {sl['id']} digest mismatch"
        subj = sl.get("credential_subject") or {}
        try:
            raw_bits = decode_bitstring(
                subj.get("encoded_list", ""),
                subj.get("encoding", ""),
                int(subj.get("bit_length", 0)),
            )
        except Exception as exc:
            return None, ERR_STATUS_LIST_SIGNATURE_INVALID, f"failed to decode bitstring: {exc}"
        status_bytes[sl["id"]] = raw_bits
        status_bit_lens[sl["id"]] = int(subj["bit_length"])

    return {
        "dids": verified_dids,
        "status_list_bytes": status_bytes,
        "status_list_bit_lens": status_bit_lens,
        "revoked_vc_set": set(snap.get("revoked_vc_ids") or []),
        "key_revocations": list(snap.get("key_revocations") or []),
        "trusted_roots": trusted_roots,
        "verified_did_count": len(verified_dids),
        "verified_rotations": total_rotations,
        "epoch_sig_checks": total_sig_checks,
    }, "", ""


def _check_key_revocation(
    revs: List[Dict[str, Any]], did: str, key_id: str, signed_at: int, valid_from: int
) -> Tuple[str, str]:
    for kr in revs:
        if kr.get("did") == did and kr.get("key_id") == key_id:
            if kr.get("revoke_all", False):
                return ERR_KEY_COMPROMISED_REVOKED, f"key {key_id} of {did} is globally revoked"
            rev_before = int(kr.get("revoked_before", 0))
            if rev_before > 0 and (signed_at < rev_before or valid_from < rev_before):
                return ERR_KEY_REVOKED_BEFORE_CUTOFF, f"key {key_id} predates revoked_before={rev_before}"
    return "", ""


def _is_ai_principal(pt: str) -> bool:
    return pt in (PRINCIPAL_AI_AGENT, PRINCIPAL_EPHEMERAL_SESSION)


def _is_safe_resource_uri(res: str) -> bool:
    if not res or ".." in res or "*" in res:
        return False
    return res.startswith("zoo://")


def _is_resource_within(child: str, parent: str) -> bool:
    if child == parent:
        return True
    if parent.endswith("/"):
        return child.startswith(parent)
    return child.startswith(parent + "/")


def _is_resource_contained(child: str, parents: List[str]) -> bool:
    return any(_is_resource_within(child, p) for p in parents)


def verify_presentation(ctx: Dict[str, Any], pres: Dict[str, Any]) -> Dict[str, Any]:
    """Perform 100% offline verification of an ActionPresentation (cold-snapshot mode)."""
    epoch, err_code, err_msg = prepare_epoch(ctx, int(pres.get("eval_time", 0)))
    if err_code:
        return {
            "valid": False,
            "error_code": err_code,
            "error_detail": err_msg,
            "chain_depth": 0,
            "leaf_did": "",
            "leaf_principal_type": "",
            "root_did": "",
            "delegation_chain_digest": "",
            "effective_scopes": [],
            "verified_did_count": 0,
            "verified_rotations": 0,
            "signature_checks": 0,
        }
    assert epoch is not None
    res = verify_presentation_with_epoch(epoch, ctx, pres)
    res["signature_checks"] += epoch["epoch_sig_checks"]
    return res


def verify_presentation_with_epoch(
    epoch: Dict[str, Any], ctx: Dict[str, Any], pres: Dict[str, Any]
) -> Dict[str, Any]:
    """Verify a delegation chain and holder-bound action presentation against a pre-verified epoch."""
    chain = list(pres.get("delegation_chain") or [])

    def fail(code: str, detail: str, sigs: int) -> Dict[str, Any]:
        return {
            "valid": False,
            "error_code": code,
            "error_detail": detail,
            "chain_depth": len(chain),
            "leaf_did": "",
            "leaf_principal_type": "",
            "root_did": "",
            "delegation_chain_digest": "",
            "effective_scopes": [],
            "verified_did_count": epoch["verified_did_count"],
            "verified_rotations": epoch["verified_rotations"],
            "signature_checks": sigs,
        }

    sig_checks = 0
    chain_digest = compute_delegation_chain_digest(chain)
    eval_time = int(pres.get("eval_time", 0))

    expected_holder_did = ""
    leaf_principal_type = ""
    root_did = ""
    effective_scopes: List[str] = []
    effective_resources: List[str] = []

    if len(chain) == 0:
        if not ctx.get("allow_root_direct_actions", False):
            return fail(ERR_CHAIN_EMPTY, "delegation chain is empty", sig_checks)
        hp = pres.get("holder_proof")
        if hp is None:
            return fail(ERR_HOLDER_PROOF_MISSING, "holder proof required for direct root action", sig_checks)
        if hp.get("holder_did") not in epoch["trusted_roots"]:
            return fail(ERR_UNTRUSTED_ROOT, "direct root action holder is not a trusted root", sig_checks)
        root_vd = epoch["dids"].get(hp["holder_did"])
        if root_vd is None or root_vd["doc"].get("principal_type") != PRINCIPAL_HUMAN_COUNCIL:
            return fail(ERR_UNTRUSTED_ROOT, "direct root action requires HUMAN_COUNCIL principal", sig_checks)
        expected_holder_did = root_vd["doc"]["id"]
        leaf_principal_type = root_vd["doc"]["principal_type"]
        root_did = root_vd["doc"]["id"]
        effective_scopes = [pres.get("action_verb", "")]
    else:
        seen_dids = set()
        prev_vc: Optional[Dict[str, Any]] = None
        prev_digest = ""

        for i, vc in enumerate(chain):
            subj = vc.get("credential_subject") or {}
            vc_issuer = vc.get("issuer", "")
            subj_id = subj.get("id", "")

            if i == 0:
                if vc_issuer not in epoch["trusted_roots"]:
                    return fail(ERR_UNTRUSTED_ROOT, f"root issuer {vc_issuer} is not trusted", sig_checks)
                if int(subj.get("delegation_depth", -1)) != 0:
                    return fail(ERR_DEPTH_OVERFLOW, "root VC must have delegation_depth 0", sig_checks)
                if subj.get("parent_vc_id", "") != "" or subj.get("parent_vc_digest", "") != "":
                    return fail(ERR_CHAIN_LINK_BROKEN, "root VC must have empty parent link", sig_checks)
                root_did = vc_issuer
                seen_dids.add(vc_issuer)
            else:
                assert prev_vc is not None
                if vc_issuer != (prev_vc.get("credential_subject") or {}).get("id", ""):
                    return fail(ERR_CHAIN_LINK_BROKEN, f"hop {i} issuer mismatch", sig_checks)
                if subj.get("parent_vc_id", "") != prev_vc.get("id", ""):
                    return fail(ERR_CHAIN_LINK_BROKEN, f"hop {i} parent_vc_id mismatch", sig_checks)
                if subj.get("parent_vc_digest", "") != prev_digest:
                    return fail(ERR_PARENT_DIGEST_MISMATCH, f"hop {i} parent_vc_digest mismatch", sig_checks)

            if subj_id in seen_dids:
                return fail(ERR_CYCLIC_DELEGATION, f"cyclic delegation detected for DID {subj_id}", sig_checks)
            seen_dids.add(subj_id)

            issuer_vd = epoch["dids"].get(vc_issuer)
            if issuer_vd is None:
                return fail(ERR_DID_NOT_FOUND, f"issuer DID {vc_issuer} not found", sig_checks)
            issuer_key_id = vc.get("issuer_key_id", "")
            issuer_key = issuer_vd["authorized_keys"].get(issuer_key_id)
            proof = vc.get("proof") or {}
            if issuer_key is None or proof.get("verification_method") != issuer_key_id:
                return fail(ERR_KEY_NOT_FOUND, f"issuer key {issuer_key_id} not authorized", sig_checks)
            sig_checks += 1
            if not _verify_domain(
                issuer_key["public_key_b64"], DOMAIN_VC, _unsigned_vc(vc), proof.get("signature_b64", "")
            ):
                return fail(ERR_VC_SIGNATURE_INVALID, f"VC {vc.get('id')} Ed25519 signature invalid", sig_checks)

            err_code, err_msg = _check_key_revocation(
                epoch["key_revocations"],
                vc_issuer,
                issuer_key_id,
                int(proof.get("created", 0)),
                int(vc.get("valid_from", 0)),
            )
            if err_code:
                return fail(err_code, err_msg, sig_checks)

            subj_vd = epoch["dids"].get(subj_id)
            if subj_vd is None:
                return fail(ERR_DID_NOT_FOUND, f"subject DID {subj_id} not found", sig_checks)
            if subj.get("subject_principal_type") != subj_vd["doc"].get("principal_type"):
                return fail(ERR_DID_KEY_BINDING_MISMATCH, "subject principal_type mismatch", sig_checks)

            scopes = list(subj.get("scopes") or [])
            if _is_ai_principal(subj_vd["doc"]["principal_type"]):
                for sc in scopes:
                    if sc in RESERVED_GOVERNANCE_SCOPES:
                        return fail(
                            ERR_CONSTITUTIONAL_AI_GOV_FORBIDDEN,
                            f"AI principal {subj_id} cannot hold reserved human-governance scope {sc}",
                            sig_checks,
                        )

            if not scopes or any("*" in sc for sc in scopes):
                return fail(ERR_SCOPE_ESCALATION, "empty or wildcard scope forbidden", sig_checks)
            resources = list(subj.get("allowed_resources") or [])
            if not resources or any(not _is_safe_resource_uri(r) for r in resources):
                return fail(ERR_RESOURCE_ESCALATION, "empty or unsafe resource pattern forbidden", sig_checks)

            if i > 0:
                assert prev_vc is not None
                p_subj = prev_vc["credential_subject"]
                p_max_sub = int(p_subj.get("max_sub_depth", 0))
                c_depth = int(subj.get("delegation_depth", -1))
                c_max_sub = int(subj.get("max_sub_depth", -1))
                if p_max_sub < 1 or c_depth != int(p_subj["delegation_depth"]) + 1 or c_max_sub < 0 or c_max_sub > p_max_sub - 1:
                    return fail(ERR_DEPTH_OVERFLOW, f"hop {i} depth/max_sub_depth overflow", sig_checks)
                if int(vc["valid_from"]) < int(prev_vc["valid_from"]) or int(vc["valid_until"]) > int(prev_vc["valid_until"]):
                    return fail(ERR_TTL_EXTENSION, f"hop {i} TTL exceeds parent", sig_checks)
                p_scopes = set(p_subj.get("scopes") or [])
                if not all(sc in p_scopes for sc in scopes):
                    return fail(ERR_SCOPE_ESCALATION, f"hop {i} scopes escalate beyond parent", sig_checks)
                p_resources = list(p_subj.get("allowed_resources") or [])
                if not all(_is_resource_contained(r, p_resources) for r in resources):
                    return fail(ERR_RESOURCE_ESCALATION, f"hop {i} resources escape parent bounds", sig_checks)
                c_con = subj.get("constraints") or {}
                p_con = p_subj.get("constraints") or {}
                if (
                    int(c_con.get("max_calls_per_hour", 0)) <= 0
                    or int(c_con.get("max_calls_per_hour", 0)) > int(p_con.get("max_calls_per_hour", 0))
                    or int(c_con.get("max_budget_usd_cents", -1)) < 0
                    or int(c_con.get("max_budget_usd_cents", 0)) > int(p_con.get("max_budget_usd_cents", 0))
                    or (bool(p_con.get("require_holder_proof", False)) and not bool(c_con.get("require_holder_proof", False)))
                ):
                    return fail(ERR_CONSTRAINT_ESCALATION, f"hop {i} constraints exceed parent bounds", sig_checks)
                p_aud = p_subj.get("audience", "")
                if p_aud and p_aud != "any" and subj.get("audience", "") != p_aud:
                    return fail(ERR_AUDIENCE_MISMATCH, f"hop {i} audience mismatch", sig_checks)

            v_from = int(vc.get("valid_from", 0))
            v_until = int(vc.get("valid_until", 0))
            if v_from >= v_until:
                return fail(ERR_VC_EXPIRED, "invalid validity interval", sig_checks)
            if eval_time < v_from:
                return fail(ERR_VC_NOT_YET_VALID, f"VC {vc.get('id')} not yet valid", sig_checks)
            if eval_time > v_until:
                return fail(ERR_VC_EXPIRED, f"VC {vc.get('id')} expired", sig_checks)

            cs = vc.get("credential_status") or {}
            sl_id = cs.get("status_list_credential", "")
            raw_bits = epoch["status_list_bytes"].get(sl_id)
            if raw_bits is None:
                return fail(ERR_STATUS_LIST_MISSING, f"status list {sl_id} not provided", sig_checks)
            bit_len = epoch["status_list_bit_lens"][sl_id]
            try:
                rev_bit = bitstring_is_revoked(raw_bits, bit_len, int(cs.get("status_list_index", -1)))
            except IndexError:
                return fail(ERR_STATUS_LIST_INDEX_OUT_OF_BOUNDS, "status list index out of bounds", sig_checks)
            if rev_bit or vc.get("id") in epoch["revoked_vc_set"]:
                if i < len(chain) - 1:
                    return fail(ERR_CASCADE_PARENT_REVOKED, f"upstream intermediate VC {vc.get('id')} revoked", sig_checks)
                return fail(ERR_VC_REVOKED_BITSTRING, f"leaf VC {vc.get('id')} revoked", sig_checks)

            prev_vc = vc
            prev_digest = compute_vc_digest(vc)

        leaf = chain[-1]
        leaf_subj = leaf["credential_subject"]
        expected_holder_did = leaf_subj["id"]
        leaf_principal_type = leaf_subj["subject_principal_type"]
        effective_scopes = sorted(leaf_subj.get("scopes") or [])
        effective_resources = list(leaf_subj.get("allowed_resources") or [])
        leaf_aud = leaf_subj.get("audience", "")
        if leaf_aud and leaf_aud != "any" and leaf_aud != pres.get("audience", ""):
            return fail(ERR_AUDIENCE_MISMATCH, "leaf VC audience mismatch", sig_checks)

    expected_aud = ctx.get("expected_audience", "")
    if expected_aud and pres.get("audience", "") != expected_aud:
        return fail(ERR_AUDIENCE_MISMATCH, "presentation audience mismatch", sig_checks)
    nonce = pres.get("challenge_nonce", "")
    if not nonce or nonce in (ctx.get("used_nonces") or []):
        return fail(ERR_NONCE_REPLAY, "challenge_nonce empty or already consumed", sig_checks)
    hp = pres.get("holder_proof")
    if hp is None:
        return fail(ERR_HOLDER_PROOF_MISSING, "holder_proof is required", sig_checks)
    if hp.get("holder_did") != expected_holder_did:
        return fail(ERR_HOLDER_DID_MISMATCH, "holder_did != leaf delegate", sig_checks)
    if (
        hp.get("delegation_chain_digest") != chain_digest
        or hp.get("challenge_nonce") != nonce
        or hp.get("audience") != pres.get("audience")
        or hp.get("action_verb") != pres.get("action_verb")
        or hp.get("resource_uri") != pres.get("resource_uri")
    ):
        return fail(ERR_HOLDER_BINDING_MISMATCH, "holder_proof signed fields do not match presentation", sig_checks)
    hp_ts = int(hp.get("timestamp", 0))
    if hp_ts < eval_time - HOLDER_PROOF_MAX_PAST_SKEW or hp_ts > eval_time + HOLDER_PROOF_MAX_FUTURE_SKEW:
        return fail(ERR_HOLDER_PROOF_STALE, "holder_proof timestamp outside freshness window", sig_checks)

    holder_vd = epoch["dids"].get(hp["holder_did"])
    if holder_vd is None:
        return fail(ERR_DID_NOT_FOUND, "holder DID not found", sig_checks)
    holder_key_id = hp.get("holder_key_id", "")
    holder_key = holder_vd["authorized_keys"].get(holder_key_id)
    if holder_key is None:
        return fail(ERR_KEY_NOT_FOUND, "holder key not authorized", sig_checks)
    err_code, err_msg = _check_key_revocation(
        epoch["key_revocations"], hp["holder_did"], holder_key_id, hp_ts, hp_ts
    )
    if err_code:
        return fail(err_code, err_msg, sig_checks)
    sig_checks += 1
    if not _verify_domain(
        holder_key["public_key_b64"], DOMAIN_HOLDER_PROOF, _unsigned_holder_proof(hp), hp.get("signature_b64", "")
    ):
        return fail(ERR_HOLDER_SIGNATURE_INVALID, "holder_proof Ed25519 signature invalid", sig_checks)

    action_verb = pres.get("action_verb", "")
    resource_uri = pres.get("resource_uri", "")
    if _is_ai_principal(holder_vd["doc"]["principal_type"]) and action_verb in RESERVED_GOVERNANCE_SCOPES:
        return fail(ERR_CONSTITUTIONAL_AI_GOV_FORBIDDEN, "AI principal cannot exercise reserved governance action", sig_checks)

    if len(chain) > 0:
        if action_verb not in effective_scopes:
            return fail(ERR_ACTION_SCOPE_DENIED, "action not in leaf effective scopes", sig_checks)
        if not _is_safe_resource_uri(resource_uri) or not _is_resource_contained(resource_uri, effective_resources):
            return fail(ERR_ACTION_RESOURCE_DENIED, "resource outside leaf allowed_resources", sig_checks)

    return {
        "valid": True,
        "error_code": "",
        "error_detail": "",
        "chain_depth": len(chain),
        "leaf_did": expected_holder_did,
        "leaf_principal_type": leaf_principal_type,
        "root_did": root_did,
        "delegation_chain_digest": chain_digest,
        "effective_scopes": effective_scopes,
        "verified_did_count": epoch["verified_did_count"],
        "verified_rotations": epoch["verified_rotations"],
        "signature_checks": sig_checks,
    }


def verify_suite(suite: Dict[str, Any]) -> Dict[str, Any]:
    """Verify all positive lifecycle stages and threat-model cases offline, producing Go-identical JSON."""
    stages = list(suite.get("stages") or [])
    stage_reports: List[Dict[str, Any]] = []
    passed_stages = 0
    audit_leaves: List[str] = []

    for st in stages:
        res = verify_presentation(st["context"], st["presentation"])
        if res["valid"]:
            passed_stages += 1
        sr = {
            "stage_id": st["stage_id"],
            "name": st["name"],
            "valid": res["valid"],
            "error_code": res["error_code"],
            "chain_depth": res["chain_depth"],
            "delegation_chain_digest": res["delegation_chain_digest"],
            "verified_rotations": res["verified_rotations"],
            "signature_checks": res["signature_checks"],
        }
        stage_reports.append(sr)
        audit_leaves.append(
            hash_canonical(
                DOMAIN_AUDIT_LEAF,
                {
                    "kind": "stage",
                    "id": sr["stage_id"],
                    "valid": sr["valid"],
                    "error_code": sr["error_code"],
                    "chain_depth": sr["chain_depth"],
                    "digest": sr["delegation_chain_digest"],
                },
            )
        )

    threats = list(suite.get("threat_cases") or [])
    threat_reports: List[Dict[str, Any]] = []
    attacks_total = 0
    attacks_caught = 0
    pos_controls = 0
    pos_controls_ok = 0
    all_threat_pass = True

    for tc in threats:
        res = verify_presentation(tc["context"], tc["presentation"])
        expect_valid = bool(tc["expect_valid"])
        expected_error = tc.get("expected_error", "")
        passed = res["valid"] == expect_valid
        if not expect_valid and expected_error and res["error_code"] != expected_error:
            passed = False
        if not expect_valid:
            attacks_total += 1
            if passed:
                attacks_caught += 1
        else:
            pos_controls += 1
            if passed:
                pos_controls_ok += 1
        if not passed:
            all_threat_pass = False
        tr = {
            "case_id": tc["case_id"],
            "category": tc["category"],
            "name": tc["name"],
            "expect_valid": expect_valid,
            "actual_valid": res["valid"],
            "expected_error": expected_error,
            "actual_error": res["error_code"],
            "pass": passed,
        }
        threat_reports.append(tr)
        audit_leaves.append(
            hash_canonical(
                DOMAIN_AUDIT_LEAF,
                {
                    "kind": "threat",
                    "id": tr["case_id"],
                    "expect_valid": tr["expect_valid"],
                    "actual_valid": tr["actual_valid"],
                    "expected_error": tr["expected_error"],
                    "actual_error": tr["actual_error"],
                    "pass": tr["pass"],
                },
            )
        )

    return {
        "schema_version": suite.get("schema_version", SCHEMA_VERSION),
        "spec_version": suite.get("spec_version", SPEC_VERSION),
        "seed": int(suite.get("seed", 0)),
        "total_stages": len(stages),
        "passed_stages": passed_stages,
        "all_stages_valid": passed_stages == len(stages),
        "total_threat_cases": len(threats),
        "attacks_total": attacks_total,
        "attacks_caught": attacks_caught,
        "positive_controls": pos_controls,
        "positive_controls_ok": pos_controls_ok,
        "all_threat_pass": all_threat_pass,
        "stage_reports": stage_reports,
        "threat_reports": threat_reports,
        "audit_merkle_root": merkle_root_rfc6962(audit_leaves),
    }

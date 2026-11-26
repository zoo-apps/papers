# SPDX-License-Identifier: Apache-2.0
"""Deterministic domain-separated SHA-256 canonical hashing and Merkle tree."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping, Sequence

DOMAIN_CORPUS = "zoo.qfsim.v1.corpus\n"
DOMAIN_LEAF = "zoo.qfsim.v1.leaf\n"
DOMAIN_GOVERNANCE = "zoo.qfsim.v1.governance\n"
DOMAIN_NODE = "zoo.qfsim.v1.node\n"
DOMAIN_ROOT = "zoo.qfsim.v1.root\n"


def _sha256_hex(domain: str, payload: str) -> str:
    h = hashlib.sha256()
    h.update(domain.encode("utf-8"))
    h.update(payload.encode("utf-8"))
    return h.hexdigest()


def _bool_tok(val: bool) -> str:
    return "1" if val else "0"


def hash_corpus(proposals: Sequence[Mapping[str, Any]]) -> str:
    ordered = sorted(proposals, key=lambda p: p["id"])
    lines = []
    for p in ordered:
        lines.append(
            f"{p['id']}|{p['paper_dir']}|{p['tex_sha256']}|{p['category']}|"
            f"{p['archetype']}|{int(p['merit_bps'])}|{_bool_tok(bool(p['is_attacker_target']))}|"
            f"{_bool_tok(bool(p['is_newcomer_grant']))}|{_bool_tok(bool(p['is_lab_grant']))}\n"
        )
    return _sha256_hex(DOMAIN_CORPUS, "".join(lines))


def hash_evaluation(ev: Mapping[str, Any]) -> str:
    allocs = sorted(ev["allocations"], key=lambda a: a["project_id"])
    m = ev["metrics"]
    g = ev["governance_gate"]
    parts = [
        f"scenario={ev['scenario_id']}\n",
        f"mechanism={ev['mechanism_id']}\n",
        f"pool={int(ev['matching_pool_micro_zoo'])}\n",
        (
            f"conserved={_bool_tok(bool(m['pool_conserved']))}|"
            f"matched={int(m['total_matched_micro_zoo'])}|"
            f"unalloc={int(m['unallocated_pool_micro_zoo'])}|"
            f"att_match={int(m['attacker_match_micro_zoo'])}|"
            f"extract={int(m['pool_extraction_bps'])}|"
            f"droi={int(m['direct_cost_roi_bps'])}|"
            f"nroi={int(m['net_attack_roi_bps'])}|"
            f"welfare={int(m['merit_welfare_bps'])}|"
            f"grass={int(m['grassroots_share_bps'])}|"
            f"minor={int(m['minority_share_bps'])}|"
            f"gini={int(m['honest_gini_bps'])}|"
            f"lab={int(m['lab_share_bps'])}|"
            f"newc={int(m['newcomer_share_bps'])}|"
            f"whale={int(m['whale_niche_share_bps'])}\n"
        ),
        (
            f"gate={g['plan_status']}|{int(g['required_human_quorum'])}|"
            f"{int(g['treasury_committee_size'])}|{int(g['min_steward_zoo_rep'])}|"
            f"{int(g['human_signatures_collected'])}|"
            f"{_bool_tok(bool(g['ai_rule_mutation_blocked']))}|"
            f"{_bool_tok(bool(g['ai_treasury_auth_blocked']))}|"
            f"{_bool_tok(bool(g['ai_self_validation_blocked']))}\n"
        ),
    ]
    for a in allocs:
        parts.append(
            f"alloc={a['project_id']}:{int(a['direct_micro_zoo'])}:"
            f"{int(a['match_micro_zoo'])}:{int(a['total_micro_zoo'])}:"
            f"{int(a['unique_donors'])}:{int(a['match_share_bps'])}\n"
        )
    return _sha256_hex(DOMAIN_LEAF, "".join(parts))


def hash_governance_checks(checks: Sequence[Mapping[str, Any]]) -> str:
    ordered = sorted(checks, key=lambda c: c["check_id"])
    lines = []
    for c in ordered:
        lines.append(
            f"{c['check_id']}|{c['actor_id']}|{c['actor_role']}|"
            f"{int(c['actor_zoo_rep'])}|{c['action']}|"
            f"{_bool_tok(bool(c['allowed']))}|{c['reason_code']}|{int(c['human_signers'])}\n"
        )
    return _sha256_hex(DOMAIN_GOVERNANCE, "".join(lines))


def compute_merkle_root(hashes: Sequence[str]) -> str:
    if not hashes:
        return _sha256_hex(DOMAIN_NODE, "")
    level = list(hashes)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level = []
        for i in range(0, len(level), 2):
            next_level.append(_sha256_hex(DOMAIN_NODE, f"{level[i]}\n{level[i + 1]}"))
        level = next_level
    return level[0]


def compute_audit_merkle_root(
    corpus_hash: str, eval_merkle_root: str, governance_hash: str
) -> str:
    return _sha256_hex(
        DOMAIN_ROOT, f"{corpus_hash}\n{eval_merkle_root}\n{governance_hash}"
    )

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation
"""Canonical JSON encoding, micro-unit conversion, and Merkle hashing matching Go bit-for-bit."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

SCHEMA_VERSION = "dso-aggregation.v1"
FIXED_SCALE = 1_000_000
FEATURE_DIM = 64


def to_micro(v: float) -> int:
    """Match Go's math.Round(v * 1_000_000) (round half away from zero)."""
    if math.isnan(v) or math.isinf(v):
        return 0
    scaled = v * FIXED_SCALE
    if scaled >= 0:
        return int(math.floor(scaled + 0.5))
    return int(math.ceil(scaled - 0.5))


def from_micro(m: int) -> float:
    return float(m) / float(FIXED_SCALE)


def _json_str(s: str) -> str:
    return json.dumps(s, ensure_ascii=False, separators=(",", ":"))


def canonical_experience_bytes(exp: dict[str, Any]) -> bytes:
    payload = (
        f'{{"confidence_micro":{int(exp["confidence_micro"])}'
        f',"domain":{_json_str(exp["domain"])}'
        f',"id":{_json_str(exp["id"])}'
        f',"op":{_json_str(exp["op"])}'
        f',"paper_path":{_json_str(exp["paper_path"])}'
        f',"paper_sha256":{_json_str(exp["paper_sha256"])}'
        f',"text":{_json_str(exp["text"])}}}'
    )
    return payload.encode("utf-8")


def canonical_contribution_bytes(body: dict[str, Any]) -> bytes:
    deltas = ",".join(str(int(x)) for x in body["delta_micro"])
    exp_str = canonical_experience_bytes(body["experience"]).decode("utf-8")
    payload = (
        f'{{"delta_micro":[{deltas}]'
        f',"domain":{_json_str(body["domain"])}'
        f',"experience":{exp_str}'
        f',"node_id":{_json_str(body["node_id"])}'
        f',"public_key_hex":{_json_str(body["public_key_hex"])}'
        f',"round":{int(body["round"])}'
        f',"schema_version":{_json_str(body["schema_version"])}}}'
    )
    return payload.encode("utf-8")


def canonical_cell_leaf_hash(cell: dict[str, Any]) -> str:
    payload = (
        f'{{"adversarial_admission_rate_micro":{to_micro(cell["adversarial_admission_rate"])}'
        f',"adversarial_weight_share_micro":{to_micro(cell["adversarial_weight_share"])}'
        f',"adversary_fraction_micro":{to_micro(cell["adversary_fraction"])}'
        f',"aggregator":{_json_str(cell["aggregator"])}'
        f',"attack_degradation_delta_micro":{to_micro(cell["attack_degradation_delta"])}'
        f',"attribution_gini_micro":{to_micro(cell["attribution_gini"])}'
        f',"fairness_ratio_micro":{to_micro(cell["fairness_ratio"])}'
        f',"final_weights_digest_sha256":{_json_str(cell["final_weights_digest_sha256"])}'
        f',"global_test_accuracy_micro":{to_micro(cell["global_test_accuracy"])}'
        f',"global_test_loss_micro":{to_micro(cell["global_test_loss"])}'
        f',"jains_fairness_index_micro":{to_micro(cell["jains_fairness_index"])}'
        f',"majority_honest_acceptance_rate_micro":{to_micro(cell["majority_honest_acceptance_rate"])}'
        f',"majority_test_accuracy_micro":{to_micro(cell["majority_test_accuracy"])}'
        f',"minority_honest_acceptance_rate_micro":{to_micro(cell["minority_honest_acceptance_rate"])}'
        f',"minority_test_accuracy_micro":{to_micro(cell["minority_test_accuracy"])}'
        f',"num_nodes":{int(cell["num_nodes"])}'
        f',"num_rounds":{int(cell["num_rounds"])}'
        f',"payload_bytes_per_round":{int(cell["payload_bytes_per_round"])}'
        f',"scenario":{_json_str(cell["scenario"])}}}'
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_merkle_root(hex_digests: list[str]) -> str:
    if not hex_digests:
        return hashlib.sha256(b"dso-empty-merkle").hexdigest()
    level: list[bytes] = []
    for hd in hex_digests:
        try:
            raw = bytes.fromhex(hd)
        except ValueError:
            raw = hd.encode("utf-8")
        level.append(hashlib.sha256(b"\x00" + raw).digest())
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(hashlib.sha256(b"\x01" + left + right).digest())
        level = nxt
    return level[0].hex()

# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.

"""Exact fixed-point BitDelta, DeltaSoup merge, and evaluation engine in pure Python."""

from typing import Any, Dict, List, Optional, Tuple

from .canonical import div_trunc

MICRO_SCALE = 1_000_000
BPS_SCALE = 10_000
DEFAULT_MARGIN_MICRO = 1_000_000


def compress_bitdelta(base_weights: List[int], fine_weights: List[int]) -> Tuple[str, int]:
    """Compress delta = fine - base into packed 1-bit LSB-first signs and optimal L1 scale."""
    dim = len(base_weights)
    num_bytes = (dim + 7) // 8
    packed = bytearray(num_bytes)
    sum_abs = 0
    for i in range(dim):
        diff = fine_weights[i] - base_weights[i]
        if diff >= 0:
            packed[i // 8] |= 1 << (i % 8)
            sum_abs += diff
        else:
            sum_abs += -diff
    scale_micro = div_trunc(sum_abs, dim) if dim > 0 else 0
    return packed.hex(), scale_micro


def unpack_bitdelta(dim: int, sign_bits_hex: str, scale_micro: int) -> List[int]:
    """Unpack LSB-first packed sign bits and scale into signed micro-unit delta vector."""
    raw = bytes.fromhex(sign_bits_hex)
    expected_bytes = (dim + 7) // 8
    if len(raw) != expected_bytes:
        raise ValueError(f"sign_bits length {len(raw)} != expected {expected_bytes}")
    out = [0] * dim
    for i in range(dim):
        if raw[i // 8] & (1 << (i % 8)):
            out[i] = scale_micro
        else:
            out[i] = -scale_micro
    return out


def apply_bitdelta(base_weights: List[int], delta: Dict[str, Any]) -> List[int]:
    """Reconstruct W_hat = W_base + gamma * S."""
    dim = int(delta["dim"])
    if len(base_weights) != dim:
        raise ValueError(f"base weight dim {len(base_weights)} != delta dim {dim}")
    d_vec = unpack_bitdelta(dim, str(delta["sign_bits_hex"]), int(delta["scale_micro"]))
    return [base_weights[i] + d_vec[i] for i in range(dim)]


def merge_cross_fork_weights(
    base_weights: List[int],
    local_delta: Optional[Dict[str, Any]],
    remote_delta: Dict[str, Any],
    step_bps: int,
) -> List[int]:
    """Compute W_merged = W_base + delta_local + (step_bps / 10000) * delta_remote."""
    out = list(base_weights)
    if local_delta is not None:
        lv = unpack_bitdelta(
            int(local_delta["dim"]),
            str(local_delta["sign_bits_hex"]),
            int(local_delta["scale_micro"]),
        )
        for i in range(len(out)):
            out[i] += lv[i]
    rv = unpack_bitdelta(
        int(remote_delta["dim"]),
        str(remote_delta["sign_bits_hex"]),
        int(remote_delta["scale_micro"]),
    )
    for i in range(len(out)):
        out[i] += div_trunc(rv[i] * step_bps, BPS_SCALE)
    return out


def predict_logits(
    weights: List[int], num_classes: int, num_features: int, features: List[int]
) -> List[int]:
    logits = [0] * num_classes
    for c in range(num_classes):
        acc = 0
        row = c * num_features
        for f in range(num_features):
            acc += weights[row + f] * features[f]
        logits[c] = div_trunc(acc, MICRO_SCALE)
    return logits


def argmax(logits: List[int]) -> int:
    best_idx = 0
    best_val = logits[0]
    for i in range(1, len(logits)):
        if logits[i] > best_val:
            best_val = logits[i]
            best_idx = i
    return best_idx


def evaluate_model(weights: List[int], ds: Dict[str, Any]) -> Dict[str, int]:
    """Exact deterministic fixed-point evaluation matching Go EvaluateModel bit-for-bit."""
    num_classes = int(ds["num_classes"])
    num_features = int(ds["num_features"])
    samples = ds["samples"]
    safety_probes = ds["safety_probes"]

    correct = 0
    total_loss = 0
    n = len(samples)
    for s in samples:
        logits = predict_logits(weights, num_classes, num_features, s["features_micro"])
        label = int(s["label"])
        if argmax(logits) == label:
            correct += 1
        true_logit = logits[label]
        for c in range(num_classes):
            if c == label:
                continue
            gap = DEFAULT_MARGIN_MICRO - (true_logit - logits[c])
            if gap > 0:
                total_loss += gap

    safe_correct = 0
    n_safe = len(safety_probes)
    for s in safety_probes:
        logits = predict_logits(weights, num_classes, num_features, s["features_micro"])
        if argmax(logits) == int(s["label"]):
            safe_correct += 1

    acc_bps = div_trunc(correct * BPS_SCALE, n) if n > 0 else 0
    mean_loss = div_trunc(total_loss, n) if n > 0 else 0
    safety_bps = div_trunc(safe_correct * BPS_SCALE, n_safe) if n_safe > 0 else 0
    return {
        "accuracy_bps": acc_bps,
        "mean_loss_micro": mean_loss,
        "safety_bps": safety_bps,
        "num_samples": n,
    }

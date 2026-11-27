# Copyright 2026 Zoo Labs Foundation / Hanzo Industries.
# Licensed under the Apache License, Version 2.0.
"""Bit-identical pure-Python quantized integer MLP token-scoring engine."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

MODEL_VOCAB_SIZE = 512
MODEL_DIM_IN = 32
MODEL_DIM_HID = 64
MODEL_DIM_OUT = 16
PROMPT_LEN = 16


@dataclass(frozen=True)
class InferenceOutput:
    input_digest: str
    logits: list[int]
    logits_digest: str
    top_token: int
    output_digest: str


def _derive_tensor(
    corpus_root_hex: str,
    model_id: str,
    tensor_name: str,
    count: int,
    min_val: int,
    span: int,
) -> list[int]:
    out: list[int] = []
    prefix = f"{corpus_root_hex}|{model_id}|{tensor_name}|".encode("utf-8")
    block = 0
    while len(out) < count:
        digest = hashlib.sha256(prefix + struct.pack("<I", block)).digest()
        for b in digest:
            if len(out) >= count:
                break
            out.append((b % span) + min_val)
        block += 1
    return out


def _pack_i64_le(vals: list[int]) -> bytes:
    return struct.pack(f"<{len(vals)}q", *vals)


def compute_input_digest(tokens: list[int], decode_steps: int) -> str:
    h = hashlib.sha256()
    h.update(b"inference-verify.v1:input:")
    h.update(struct.pack("<II", decode_steps & 0xFFFFFFFF, len(tokens) & 0xFFFFFFFF))
    for tok in tokens:
        h.update(struct.pack("<I", tok & 0xFFFFFFFF))
    return h.hexdigest()


def compute_logits_digest(logits: list[int]) -> str:
    h = hashlib.sha256()
    h.update(b"inference-verify.v1:logits:")
    h.update(_pack_i64_le(logits))
    return h.hexdigest()


def compute_output_digest(
    job_id: str,
    model_digest: str,
    input_digest: str,
    logits_digest: str,
    top_token: int,
) -> str:
    h = hashlib.sha256()
    h.update(
        f"inference-verify.v1:output:{job_id}:{model_digest}:{input_digest}:{logits_digest}:".encode(
            "utf-8"
        )
    )
    h.update(struct.pack("<I", top_token & 0xFFFFFFFF))
    return h.hexdigest()


def _clip(v: int, lo: int, hi: int) -> int:
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v


def _argmax(vals: list[int]) -> int:
    best_idx = 0
    best_val = vals[0]
    for i in range(1, len(vals)):
        if vals[i] > best_val:
            best_val = vals[i]
            best_idx = i
    return best_idx


class QuantizedMLP:
    """Exact integer MLP matching Go inferverify.QuantizedMLP bit-for-bit."""

    def __init__(self, corpus_root_hex: str, model_id: str) -> None:
        self.model_id = model_id
        self.corpus_root_sha256 = corpus_root_hex
        self.embed = _derive_tensor(
            corpus_root_hex, model_id, "embed", MODEL_VOCAB_SIZE * MODEL_DIM_IN, -127, 255
        )
        self.w1 = _derive_tensor(
            corpus_root_hex, model_id, "w1", MODEL_DIM_HID * MODEL_DIM_IN, -64, 128
        )
        self.b1 = _derive_tensor(
            corpus_root_hex, model_id, "b1", MODEL_DIM_HID, -128, 256
        )
        self.w2 = _derive_tensor(
            corpus_root_hex, model_id, "w2", MODEL_DIM_HID * MODEL_DIM_HID, -64, 128
        )
        self.b2 = _derive_tensor(
            corpus_root_hex, model_id, "b2", MODEL_DIM_HID, -128, 256
        )
        self.w3 = _derive_tensor(
            corpus_root_hex, model_id, "w3", MODEL_DIM_OUT * MODEL_DIM_HID, -64, 128
        )
        self.b3 = _derive_tensor(
            corpus_root_hex, model_id, "b3", MODEL_DIM_OUT, -128, 256
        )
        self.model_digest = self._compute_model_digest()

    def _compute_model_digest(self) -> str:
        h = hashlib.sha256()
        h.update(
            f"inference-verify.v1:model:{self.model_id}:{self.corpus_root_sha256}:".encode(
                "utf-8"
            )
        )
        for arr in (self.embed, self.w1, self.b1, self.w2, self.b2, self.w3, self.b3):
            h.update(_pack_i64_le(arr))
        return h.hexdigest()

    def forward_honest(
        self, job_id: str, tokens: list[int], decode_steps: int
    ) -> InferenceOutput:
        if decode_steps < 1:
            decode_steps = 1
        input_digest = compute_input_digest(tokens, decode_steps)

        x = [0] * MODEL_DIM_IN
        embed = self.embed
        for pos, tok in enumerate(tokens):
            tid = tok % MODEL_VOCAB_SIZE
            base = tid * MODEL_DIM_IN
            weight = 1 + (pos % 3)
            for d in range(MODEL_DIM_IN):
                x[d] += embed[base + d] * weight
        x = [_clip(v, -127, 127) for v in x]

        w1, b1 = self.w1, self.b1
        w2, b2 = self.w2, self.b2
        w3, b3 = self.w3, self.b3
        h1 = [0] * MODEL_DIM_HID
        h2 = [0] * MODEL_DIM_HID
        logits = [0] * MODEL_DIM_OUT

        for step in range(decode_steps):
            for j in range(MODEL_DIM_HID):
                row = j * MODEL_DIM_IN
                acc = b1[j]
                for i in range(MODEL_DIM_IN):
                    acc += w1[row + i] * x[i]
                h1[j] = 0 if acc <= 0 else (acc >> 7)

            for k in range(MODEL_DIM_HID):
                row = k * MODEL_DIM_HID
                acc = b2[k]
                for j in range(MODEL_DIM_HID):
                    acc += w2[row + j] * h1[j]
                h2[k] = 0 if acc <= 0 else (acc >> 7)

            for c in range(MODEL_DIM_OUT):
                row = c * MODEL_DIM_HID
                acc = b3[c]
                for k in range(MODEL_DIM_HID):
                    acc += w3[row + k] * h2[k]
                logits[c] = acc

            if step + 1 < decode_steps:
                best = _argmax(logits)
                next_tok = (best * 31 + step * 7) % MODEL_VOCAB_SIZE
                base = next_tok * MODEL_DIM_IN
                for d in range(MODEL_DIM_IN):
                    # Exact arithmetic right shift matching Go int64 >> 1
                    x[d] = _clip((x[d] + embed[base + d]) >> 1, -127, 127)

        top_token = _argmax(logits)
        logits_digest = compute_logits_digest(logits)
        out_digest = compute_output_digest(
            job_id, self.model_digest, input_digest, logits_digest, top_token
        )
        return InferenceOutput(
            input_digest=input_digest,
            logits=logits,
            logits_digest=logits_digest,
            top_token=top_token,
            output_digest=out_digest,
        )

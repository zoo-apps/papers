# SPDX-License-Identifier: Apache-2.0
"""Bit-identical LaTeX/scientific text normalizer and k-shingle Winnowing fingerprint."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import List

from .canonical import DOMAIN_CANONICAL_TEXT, DOMAIN_SHINGLE, DOMAIN_WINNOW_DIGEST, domain_sha256_hex, sha256_hex

SHINGLE_SIZE = 4
WINNOW_WINDOW = 3
BPS_SCALE = 10_000

STRIPPED_ARG_COMMANDS = frozenset({
    "label",
    "ref",
    "eqref",
    "cite",
    "citep",
    "citet",
    "usepackage",
    "documentclass",
    "bibliographystyle",
    "bibliography",
    "vspace",
    "hspace",
    "begin",
    "end",
})


def _is_ascii_letter(b: int) -> bool:
    return (65 <= b <= 90) or (97 <= b <= 122)


def _skip_spaces(data: bytes, i: int) -> int:
    n = len(data)
    while i < n and data[i] in (32, 9, 13, 10):
        i += 1
    return i


def _skip_balanced(data: bytes, i: int, open_ch: int, close_ch: int) -> int:
    n = len(data)
    if i >= n or data[i] != open_ch:
        return i
    depth = 0
    while i < n:
        ch = data[i]
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return i


def normalize_scientific_text(raw: str) -> List[str]:
    """Byte-exact mirror of Go NormalizeScientificText."""
    raw_bytes = raw.encode("utf-8")
    n_raw = len(raw_bytes)

    # Step 1: Strip unescaped '%' line comments.
    no_comments = bytearray()
    in_comment = False
    for i in range(n_raw):
        ch = raw_bytes[i]
        if in_comment:
            if ch == 10:  # '\n'
                in_comment = False
                no_comments.append(10)
            continue
        if ch == 37:  # '%'
            bs = 0
            j = i - 1
            while j >= 0 and raw_bytes[j] == 92:  # '\\'
                bs += 1
                j -= 1
            if bs % 2 == 0:
                in_comment = True
                continue
        no_comments.append(ch)

    s = bytes(no_comments)
    n = len(s)

    # Step 2: Strip LaTeX commands (and arguments for metadata commands).
    cleaned = bytearray()
    i = 0
    while i < n:
        if s[i] == 92 and i + 1 < n and _is_ascii_letter(s[i + 1]):
            start = i + 1
            j = start
            while j < n and _is_ascii_letter(s[j]):
                j += 1
            cmd = s[start:j].decode("ascii")
            if j < n and s[j] == 42:  # '*'
                j += 1
            if cmd in STRIPPED_ARG_COMMANDS:
                j = _skip_spaces(s, j)
                if j < n and s[j] == 91:  # '['
                    j = _skip_balanced(s, j, 91, 93)
                    j = _skip_spaces(s, j)
                if j < n and s[j] == 123:  # '{'
                    j = _skip_balanced(s, j, 123, 125)
            cleaned.append(32)
            i = j
            continue
        cleaned.append(s[i])
        i += 1

    # Step 3: Extract lowercase ASCII alphanumeric tokens.
    tokens: List[str] = []
    cur = bytearray()
    for ch in cleaned:
        if 65 <= ch <= 90:
            cur.append(ch + 32)
        elif (97 <= ch <= 122) or (48 <= ch <= 57):
            cur.append(ch)
        else:
            if cur:
                tokens.append(cur.decode("ascii"))
                cur.clear()
    if cur:
        tokens.append(cur.decode("ascii"))
    return tokens


@dataclass
class ArtifactFingerprints:
    raw_sha256: str
    canonical_digest: str
    winnow_fingerprint: List[str]
    fingerprint_digest: str
    token_count: int


def _hash_shingle(shingle: str) -> int:
    digest = hashlib.sha256(DOMAIN_SHINGLE + shingle.encode("utf-8")).digest()
    return struct.unpack(">Q", digest[:8])[0]


def compute_fingerprints(raw: str) -> ArtifactFingerprints:
    raw_bytes = raw.encode("utf-8")
    raw_digest = sha256_hex(raw_bytes)
    tokens = normalize_scientific_text(raw)
    canonical_joined = " ".join(tokens)
    canonical_digest = domain_sha256_hex(DOMAIN_CANONICAL_TEXT, canonical_joined.encode("utf-8"))

    if not tokens:
        shingle_hashes = [_hash_shingle("")]
    elif len(tokens) < SHINGLE_SIZE:
        shingle_hashes = [_hash_shingle(canonical_joined)]
    else:
        shingle_hashes = [
            _hash_shingle(" ".join(tokens[i : i + SHINGLE_SIZE]))
            for i in range(len(tokens) - SHINGLE_SIZE + 1)
        ]

    selected = set()
    if len(shingle_hashes) <= WINNOW_WINDOW:
        min_val = shingle_hashes[0]
        for h in shingle_hashes[1:]:
            if h <= min_val:
                min_val = h
        selected.add(min_val)
    else:
        for i in range(len(shingle_hashes) - WINNOW_WINDOW + 1):
            min_val = shingle_hashes[i]
            for j in range(i + 1, i + WINNOW_WINDOW):
                if shingle_hashes[j] <= min_val:
                    min_val = shingle_hashes[j]
            selected.add(min_val)

    vals = sorted(selected)
    fp_hex = [f"{v:016x}" for v in vals]
    buf = b"".join(struct.pack(">Q", v) for v in vals)
    fp_digest = domain_sha256_hex(DOMAIN_WINNOW_DIGEST, buf)

    return ArtifactFingerprints(
        raw_sha256=raw_digest,
        canonical_digest=canonical_digest,
        winnow_fingerprint=fp_hex,
        fingerprint_digest=fp_digest,
        token_count=len(tokens),
    )


def _sorted_intersection_count(a: List[str], b: List[str]) -> int:
    i = 0
    j = 0
    count = 0
    na = len(a)
    nb = len(b)
    while i < na and j < nb:
        if a[i] == b[j]:
            count += 1
            i += 1
            j += 1
        elif a[i] < b[j]:
            i += 1
        else:
            j += 1
    return count


def containment_bps(a: List[str], b: List[str]) -> int:
    if not a:
        return 0
    inter = _sorted_intersection_count(a, b)
    return (inter * BPS_SCALE) // len(a)


def jaccard_bps(a: List[str], b: List[str]) -> int:
    if not a and not b:
        return BPS_SCALE
    inter = _sorted_intersection_count(a, b)
    union = len(a) + len(b) - inter
    if union == 0:
        return 0
    return (inter * BPS_SCALE) // union

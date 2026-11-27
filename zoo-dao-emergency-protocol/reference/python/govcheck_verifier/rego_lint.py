# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.

"""Zero-dependency OPA Rego v1 structural/syntax validator and bundle hasher."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, List, Tuple


REQUIRED_REGO_FILES = [
    "conflict.rego",
    "constitution.rego",
    "constitution_test.rego",
    "delegation.rego",
    "emergency.rego",
]


def _strip_comments_and_strings(text: str) -> str:
    """Remove line comments and string literals to verify delimiter balance."""
    out: List[str] = []
    i = 0
    n = len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            i += 1
            continue
        if ch == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue
        out.append(ch)
        i += 1
    if in_str:
        raise ValueError("unterminated string literal in rego file")
    return "".join(out)


def _check_balanced(text: str, filename: str) -> None:
    cleaned = _strip_comments_and_strings(text)
    pairs = {"{": "}", "[": "]", "(": ")"}
    closers = set(pairs.values())
    stack: List[str] = []
    for ch in cleaned:
        if ch in pairs:
            stack.append(pairs[ch])
        elif ch in closers:
            if not stack or stack[-1] != ch:
                raise ValueError(f"{filename}: unmatched closing delimiter {ch!r}")
            stack.pop()
    if stack:
        raise ValueError(f"{filename}: unclosed delimiters remaining: {stack}")


def validate_rego_bundle(rego_dir: Path) -> Tuple[List[str], str, Dict[str, int]]:
    """Validate all Rego v1 files and compute the canonical bundle SHA-256."""
    files = sorted(p.name for p in rego_dir.iterdir() if p.is_file() and p.suffix == ".rego")
    for req in REQUIRED_REGO_FILES:
        if req not in files:
            raise ValueError(f"missing required rego file: {req}")

    h = hashlib.sha256()
    stats: Dict[str, int] = {}
    for fname in files:
        raw = (rego_dir / fname).read_bytes()
        text = raw.decode("utf-8")
        if "import rego.v1" not in text:
            raise ValueError(f"{fname}: missing 'import rego.v1'")
        if "package govcheck." not in text:
            raise ValueError(f"{fname}: missing 'package govcheck.*' declaration")
        _check_balanced(text, fname)
        if fname == "constitution_test.rego":
            test_count = sum(1 for line in text.splitlines() if line.strip().startswith("test_"))
            if test_count < 6:
                raise ValueError(f"{fname}: expected >= 6 rego unit tests, found {test_count}")
            stats["rego_unit_tests"] = test_count
        stats[fname] = len(text.splitlines())
        h.update(fname.encode("utf-8"))
        h.update(b"\x00")
        h.update(raw)
        h.update(b"\x00")

    return files, h.hexdigest(), stats

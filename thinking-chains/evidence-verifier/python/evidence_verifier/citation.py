# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation

"""Deterministic citation_check verifier (1:1 parity with Go verifier)."""

from __future__ import annotations

import math
import os
import re
from typing import Any

from .types import (
    REASON_HUMAN_REVIEW_REQUIRED,
    REASON_INVALID_SHA256_FORMAT,
    REASON_INVALID_SOURCE_PATH,
    REASON_MISSING_CITATION_FIELDS,
    REASON_MISSING_PAYLOAD,
    REASON_NUMERIC_MISMATCH,
    REASON_OK_CITATION,
    REASON_PARAPHRASE_HUMAN_REVIEW,
    REASON_POLARITY_REVERSAL,
    REASON_QUOTE_NOT_FOUND,
    REASON_QUOTE_NUMERIC_ALTERATION,
    REASON_QUOTE_POLARITY_ALT,
    REASON_SECTION_NOT_FOUND,
    REASON_SOURCE_NOT_FOUND,
    REASON_SOURCE_SHA256_MISMATCH,
    VERDICT_INCONCLUSIVE,
    VERDICT_REFUTED,
    VERDICT_UNSUPPORTED,
    VERDICT_VERIFIED,
    format_canonical_float,
    is_valid_hex_sha256,
    make_result,
    sha256_hex,
)

_RE_TEX_FORMAT_CMD = re.compile(r"\\(textbf|emph|textit|textsc|texttt|text|mathrm|mathbf)\{([^{}]*)\}")
_TEX_MACRO_PAIRS = [
    (r"\PoAI{}", "PoAI"),
    (r"\PoAI", "PoAI"),
    (r"\PoT{}", "PoT"),
    (r"\PoT", "PoT"),
    (r"\Quasar{}", "Quasar"),
    (r"\Quasar", "Quasar"),
    (r"\LLM{}", "LLM"),
    (r"\LLM", "LLM"),
    (r"\DAO{}", "DAO"),
    (r"\DAO", "DAO"),
    (r"\ZOO{}", "ZOO"),
    (r"\ZOO", "ZOO"),
    (r"\Zoo{}", "Zoo"),
    (r"\Zoo", "Zoo"),
    (r"\TPS{}", "TPS"),
    (r"\TPS", "TPS"),
    (r"\EVM{}", "EVM"),
    (r"\EVM", "EVM"),
    (r"\IPFS{}", "IPFS"),
    (r"\IPFS", "IPFS"),
    (r"\REP{}", "REP"),
    (r"\REP", "REP"),
    (r"\Lux{}", "Lux"),
    (r"\Lux", "Lux"),
    (r"\noindent", " "),
    (r"\medskip", " "),
    (r"\bigskip", " "),
    (r"\smallskip", " "),
    (r"\geq", ">="),
    (r"\leq", "<="),
    (r"\ge", ">="),
    (r"\le", "<="),
    (r"\times", "x"),
    (r"\approx", "~"),
    (r"\sim", "~"),
    (r"\%", "%"),
    (r"\,", ""),
    (r"\!", ""),
    (r"\;", " "),
    ("~", " "),
    ("---", " - "),
    ("--", "-"),
]
_RE_WHITESPACE = re.compile(r"\s+")
_RE_SECTION_HEADER = re.compile(
    r"\\(?:sub)*section\*?\{([^}]*)\}|\\begin\{(abstract)\}|\\begin\{(?:theorem|lemma|principle|definition|proposition)\}\[([^\]]*)\]",
    re.IGNORECASE,
)
_RE_WORD_TOKEN = re.compile(r"[a-z0-9]+")
_RE_NUMBER_LITERAL = re.compile(
    r"(\d+\^\{?\d+\}?|\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?)(k|m|b|gb|pb|ms|%)?",
    re.IGNORECASE,
)
_NEGATION_TRIGGERS = (
    "never ",
    " not ",
    "cannot ",
    "does not ",
    "may not ",
    "no premine",
    "no coin ",
    "without ",
    "neither ",
    "none ",
)


def normalize_latex(raw: str) -> str:
    cleaned: list[str] = []
    for line in raw.split("\n"):
        idx = -1
        for i, ch in enumerate(line):
            if ch == "%" and (i == 0 or line[i - 1] != "\\"):
                idx = i
                break
        if idx >= 0:
            line = line[:idx]
        cleaned.append(line)
    s = " ".join(cleaned)
    for old, new in _TEX_MACRO_PAIRS:
        s = s.replace(old, new)
    for _ in range(4):
        nxt = _RE_TEX_FORMAT_CMD.sub(r"\2", s)
        if nxt == s:
            break
        s = nxt
    for old, new in (("$", ""), ("{", ""), ("}", ""), ("``", '"'), ("''", '"'), ("\\", " ")):
        s = s.replace(old, new)
    s = s.lower()
    return _RE_WHITESPACE.sub(" ", s).strip()


def extract_scoped_section(raw: str, section_hint: str) -> tuple[str, bool]:
    hint = section_hint.strip().lower()
    if not hint:
        return raw, True
    matches = list(_RE_SECTION_HEADER.finditer(raw))
    norm_hint = normalize_latex(hint)
    for idx, m in enumerate(matches):
        title = m.group(1) or m.group(2) or m.group(3) or ""
        norm_title = normalize_latex(title)
        if norm_hint in norm_title or norm_title == norm_hint:
            start = m.start()
            end = len(raw)
            if title.lower() == "abstract":
                end_idx = raw.find(r"\end{abstract}", start)
                if end_idx >= 0:
                    end = end_idx + len(r"\end{abstract}")
            elif idx + 1 < len(matches):
                for j in range(idx + 1, len(matches)):
                    hdr = raw[matches[j].start() : matches[j].end()].lower()
                    if (
                        hdr.startswith(r"\section")
                        or hdr.startswith(r"\begin{theorem")
                        or hdr.startswith(r"\begin{lemma")
                        or hdr.startswith(r"\begin{principle")
                    ):
                        end = matches[j].start()
                        break
            return raw[start:end], True
    return "", False


def extract_numbers(norm: str) -> list[float]:
    out: list[float] = []
    for m in _RE_NUMBER_LITERAL.finditer(norm):
        num_str = m.group(1).replace(",", "")
        suffix = (m.group(2) or "").lower()
        base: float | None = None
        if "^" in num_str:
            parts = num_str.split("^", 1)
            try:
                base = math.pow(float(parts[0]), float(parts[1]))
            except (ValueError, OverflowError):
                base = None
        else:
            try:
                base = float(num_str)
            except ValueError:
                base = None
        if base is None or math.isnan(base) or math.isinf(base):
            continue
        out.append(base)
        if suffix == "k":
            out.append(base * 1e3)
        elif suffix == "m":
            out.append(base * 1e6)
        elif suffix == "b":
            out.append(base * 1e9)
        elif suffix == "ms":
            out.append(base / 1e3)
    return out


def _number_matches_any(target: float, candidates: list[float]) -> bool:
    for c in candidates:
        diff = abs(target - c)
        tol = max(1e-9, 1e-5 * max(abs(target), abs(c)))
        if diff <= tol:
            return True
    return False


def _has_negation(norm: str) -> bool:
    padded = f" {norm} "
    return any(trig in padded for trig in _NEGATION_TRIGGERS)


def _is_non_sentence_dot(s: str, i: int) -> bool:
    if (
        0 < i < len(s) - 1
        and s[i] == "."
        and "0" <= s[i - 1] <= "9"
        and "0" <= s[i + 1] <= "9"
    ):
        return True
    if i >= 2 and s[i - 2 : i + 1] == "vs." and (i == 2 or s[i - 3] in (" ", "(")):
        return True
    if i >= 3 and s[i - 3 : i + 1] in ("e.g.", "i.e."):
        return True
    return False


def _extract_enclosing_clause(norm_text: str, match_idx: int, match_len: int) -> str:
    start = match_idx
    while start > 0:
        ch = norm_text[start - 1]
        if (ch == "." and not _is_non_sentence_dot(norm_text, start - 1)) or ch in ";\n":
            break
        if start >= 3 and norm_text[start - 3 : start] == " - ":
            break
        start -= 1
    end = match_idx + match_len
    while end < len(norm_text):
        ch = norm_text[end]
        if (ch == "." and not _is_non_sentence_dot(norm_text, end)) or ch in ";\n":
            end += 1
            break
        if end + 3 <= len(norm_text) and norm_text[end : end + 3] == " - ":
            break
        end += 1
    return norm_text[start:end].strip()


def _split_sentences(norm_text: str) -> list[str]:
    out: list[str] = []
    start = 0
    for i, ch in enumerate(norm_text):
        if (ch == "." and not _is_non_sentence_dot(norm_text, i)) or ch in ";\n":
            seg = norm_text[start:i].strip()
            if seg:
                out.append(seg)
            start = i + 1
    if start < len(norm_text):
        seg = norm_text[start:].strip()
        if seg:
            out.append(seg)
    return out


def _content_tokens(norm: str) -> set[str]:
    res: set[str] = set()
    for tok in _RE_WORD_TOKEN.findall(norm):
        if len(tok) < 3 or tok.isdigit():
            continue
        res.add(tok)
    return res


def _best_sentence_overlap(norm_scoped: str, norm_quote: str) -> tuple[float, str]:
    q_toks = _content_tokens(norm_quote)
    if not q_toks:
        return 0.0, ""
    best_score = 0.0
    best_sent = ""
    for sent in _split_sentences(norm_scoped):
        s_toks = _content_tokens(sent)
        if not s_toks:
            continue
        overlap = sum(1 for t in q_toks if t in s_toks)
        score = overlap / len(q_toks)
        if score > best_score:
            best_score = score
            best_sent = sent
    return best_score, best_sent


def verify_citation(corpus_root: str, claim: dict[str, Any]) -> dict[str, Any]:
    c = claim.get("citation")
    if not isinstance(c, dict):
        return make_result(claim, VERDICT_UNSUPPORTED, REASON_MISSING_PAYLOAD, "citation payload missing")
    review_scope = c.get("review_scope", "")
    if review_scope in ("external_domain", "subjective_judgment"):
        return make_result(
            claim,
            VERDICT_INCONCLUSIVE,
            REASON_HUMAN_REVIEW_REQUIRED,
            "claim requires external domain or subjective human review",
        )
    source_path = c.get("source_path", "")
    expected_sha = c.get("expected_sha256", "")
    quoted_span = c.get("quoted_span", "")
    if not source_path.strip() or not expected_sha.strip() or not quoted_span.strip():
        return make_result(
            claim,
            VERDICT_UNSUPPORTED,
            REASON_MISSING_CITATION_FIELDS,
            "citation missing source_path, expected_sha256, or quoted_span",
        )
    cleaned = os.path.normpath(source_path)
    if os.path.isabs(source_path) or cleaned.startswith("..") or ".." in source_path:
        return make_result(
            claim,
            VERDICT_UNSUPPORTED,
            REASON_INVALID_SOURCE_PATH,
            "citation source_path escapes corpus root",
        )
    full_path = os.path.join(corpus_root, cleaned)
    try:
        with open(full_path, "rb") as f:
            raw_bytes = f.read()
    except OSError:
        return make_result(
            claim,
            VERDICT_UNSUPPORTED,
            REASON_SOURCE_NOT_FOUND,
            f"pinned source not found: {source_path}",
        )
    actual_sha = sha256_hex(raw_bytes)
    if not is_valid_hex_sha256(expected_sha):
        return make_result(
            claim,
            VERDICT_UNSUPPORTED,
            REASON_INVALID_SHA256_FORMAT,
            "expected_sha256 is not a valid 64-char lowercase hex digest",
            "",
            actual_sha,
        )
    if actual_sha != expected_sha:
        return make_result(
            claim,
            VERDICT_REFUTED,
            REASON_SOURCE_SHA256_MISMATCH,
            "source file SHA-256 does not match pinned expected_sha256",
            "",
            actual_sha,
        )
    raw_text = raw_bytes.decode("utf-8", errors="replace")
    section_hint = c.get("section_hint", "")
    scoped_raw, found_sec = extract_scoped_section(raw_text, section_hint)
    if not found_sec:
        return make_result(
            claim,
            VERDICT_REFUTED,
            REASON_SECTION_NOT_FOUND,
            f"section hint not found: {section_hint}",
            "",
            actual_sha,
        )
    norm_scoped = normalize_latex(scoped_raw)
    norm_quote = normalize_latex(quoted_span)
    if not norm_quote:
        return make_result(
            claim,
            VERDICT_UNSUPPORTED,
            REASON_MISSING_CITATION_FIELDS,
            "quoted_span normalized to empty string",
            "",
            actual_sha,
        )

    idx = norm_scoped.find(norm_quote)
    if idx >= 0:
        win_start = max(0, idx - 380)
        win_end = min(len(norm_scoped), idx + len(norm_quote) + 380)
        ctx_nums = extract_numbers(norm_scoped[win_start:win_end])
        for claimed_num in c.get("claimed_numbers") or []:
            cnum = float(claimed_num)
            if not _number_matches_any(cnum, ctx_nums):
                fnum = format_canonical_float(cnum)
                return make_result(
                    claim,
                    VERDICT_REFUTED,
                    REASON_NUMERIC_MISMATCH,
                    f"claimed number {fnum} absent from matched context window",
                    fnum,
                    actual_sha,
                )
        sentence = _extract_enclosing_clause(norm_scoped, idx, len(norm_quote))
        sent_neg = _has_negation(sentence)
        quote_neg = _has_negation(norm_quote)
        claimed_polarity = c.get("claimed_polarity", "")
        if claimed_polarity == "positive" and sent_neg and not quote_neg:
            return make_result(
                claim,
                VERDICT_REFUTED,
                REASON_POLARITY_REVERSAL,
                "enclosing sentence negates positive claim",
                "",
                actual_sha,
            )
        if claimed_polarity == "negative" and not sent_neg:
            return make_result(
                claim,
                VERDICT_REFUTED,
                REASON_POLARITY_REVERSAL,
                "enclosing sentence lacks negation for negative claim",
                "",
                actual_sha,
            )
        return make_result(
            claim,
            VERDICT_VERIFIED,
            REASON_OK_CITATION,
            "pinned SHA-256, section, span, numeric, and polarity checks passed",
            "matched",
            actual_sha,
        )

    best_score, best_sent = _best_sentence_overlap(norm_scoped, norm_quote)
    if best_score >= 0.70:
        quote_nums = extract_numbers(norm_quote)
        sent_nums = extract_numbers(best_sent)
        if quote_nums:
            for qn in quote_nums:
                if not _number_matches_any(qn, sent_nums):
                    fnum = format_canonical_float(qn)
                    return make_result(
                        claim,
                        VERDICT_REFUTED,
                        REASON_QUOTE_NUMERIC_ALTERATION,
                        f"quoted span alters number {fnum} relative to source sentence",
                        fnum,
                        actual_sha,
                    )
        if _has_negation(norm_quote) != _has_negation(best_sent):
            return make_result(
                claim,
                VERDICT_REFUTED,
                REASON_QUOTE_POLARITY_ALT,
                "quoted span flips negation polarity relative to source sentence",
                "",
                actual_sha,
            )
    if not c.get("require_exact_span", False) and best_score >= 0.45:
        quote_nums = extract_numbers(norm_quote)
        sent_nums = extract_numbers(best_sent)
        if all(_number_matches_any(qn, sent_nums) for qn in quote_nums):
            fscore = format_canonical_float(best_score)
            return make_result(
                claim,
                VERDICT_INCONCLUSIVE,
                REASON_PARAPHRASE_HUMAN_REVIEW,
                f"paraphrase overlap {fscore} requires human or NLI review",
                fscore,
                actual_sha,
            )
    return make_result(
        claim,
        VERDICT_UNSUPPORTED,
        REASON_QUOTE_NOT_FOUND,
        "quoted span not found verbatim in pinned source section",
        format_canonical_float(best_score),
        actual_sha,
    )

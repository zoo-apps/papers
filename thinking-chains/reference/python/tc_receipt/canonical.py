# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zoo Labs Foundation and Contributors

"""Strict integer-only JSON parser and RFC 8785 canonical JSON encoder."""

from __future__ import annotations

import json
from typing import Any

INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1


class CanonicalError(Exception):
    """Raised when input JSON violates strict canonicalization rules."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _reject_float(token: str) -> Any:
    raise CanonicalError(
        "ERR_FLOAT_FORBIDDEN",
        f"floating-point or exponent literal not permitted in canonical receipts: {token!r}",
    )


def _reject_constant(token: str) -> Any:
    raise CanonicalError(
        "ERR_FLOAT_FORBIDDEN",
        f"non-standard JSON numeric constant not permitted: {token!r}",
    )


def _parse_int64(token: str) -> int:
    val = int(token)
    if val < INT64_MIN or val > INT64_MAX:
        raise CanonicalError(
            "ERR_SCHEMA_VIOLATION",
            f"integer {token} out of signed 64-bit range",
        )
    return val


def _strict_object_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise CanonicalError(
                "ERR_DUPLICATE_KEY",
                f"duplicate JSON object key detected: {k!r}",
            )
        out[k] = v
    return out


def parse_strict_json(raw: bytes | str) -> Any:
    """Parse UTF-8 JSON while rejecting duplicate keys, floats, NaN/Infinity, and int64 overflow."""
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CanonicalError("ERR_INVALID_JSON", f"invalid UTF-8: {exc}") from exc
    else:
        text = raw

    if text.startswith("\ufeff"):
        raise CanonicalError("ERR_INVALID_JSON", "UTF-8 BOM is forbidden")

    try:
        return json.loads(
            text,
            object_pairs_hook=_strict_object_pairs_hook,
            parse_float=_reject_float,
            parse_int=_parse_int64,
            parse_constant=_reject_constant,
        )
    except CanonicalError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise CanonicalError("ERR_INVALID_JSON", f"malformed JSON: {exc}") from exc


def _escape_json_string(s: str) -> str:
    """RFC 8785 §3.2.2.2 string escaping (no HTML escaping, raw UTF-8 for >= 0x80)."""
    out: list[str] = ['"']
    for ch in s:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif code == 0x08:
            out.append("\\b")
        elif code == 0x0C:
            out.append("\\f")
        elif code == 0x0A:
            out.append("\\n")
        elif code == 0x0D:
            out.append("\\r")
        elif code == 0x09:
            out.append("\\t")
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _encode_value(val: Any) -> str:
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        if val < INT64_MIN or val > INT64_MAX:
            raise CanonicalError("ERR_SCHEMA_VIOLATION", f"integer out of int64 range: {val}")
        return str(val)
    if isinstance(val, float):
        raise CanonicalError("ERR_FLOAT_FORBIDDEN", f"float value not permitted: {val!r}")
    if isinstance(val, str):
        return _escape_json_string(val)
    if val is None:
        return "null"
    if isinstance(val, list):
        return "[" + ",".join(_encode_value(item) for item in val) + "]"
    if isinstance(val, dict):
        # Sort keys strictly by UTF-8 byte order (identical to UTF-16 order for ASCII keys).
        sorted_keys = sorted(val.keys(), key=lambda k: k.encode("utf-8"))
        parts = [f"{_escape_json_string(k)}:{_encode_value(val[k])}" for k in sorted_keys]
        return "{" + ",".join(parts) + "}"
    raise CanonicalError("ERR_SCHEMA_VIOLATION", f"unsupported value type: {type(val).__name__}")


def canonical_json(value: Any) -> bytes:
    """Encode value as RFC 8785 integer-only canonical JSON UTF-8 bytes."""
    return _encode_value(value).encode("utf-8")

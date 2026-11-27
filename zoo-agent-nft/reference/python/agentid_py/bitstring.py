# Copyright 2026 Zoo Labs Foundation.
# Licensed under the Apache License, Version 2.0.

"""W3C Bitstring Status List v1.0 decoding and MSB-first revocation lookup (stdlib only)."""

import gzip
import io

from .canonical import decode_base64url

ENCODING_GZIP_BASE64URL = "gzip_base64url"
ENCODING_RAW_BASE64URL = "raw_base64url"


def decode_bitstring(encoded: str, encoding: str, expected_bit_length: int) -> bytes:
    """Decode an encoded W3C BitstringStatusList to raw bytes with zip-bomb bound."""
    if expected_bit_length <= 0 or expected_bit_length % 8 != 0:
        raise ValueError("invalid expected bit length")
    expected_bytes = expected_bit_length // 8
    data = decode_base64url(encoded)
    if encoding == ENCODING_RAW_BASE64URL:
        raw = data
    elif encoding == ENCODING_GZIP_BASE64URL:
        with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as zr:
            raw = zr.read(expected_bytes + 1)
    else:
        raise ValueError(f"unsupported bitstring encoding: {encoding}")
    if len(raw) != expected_bytes:
        raise ValueError(f"decoded bitstring byte length {len(raw)} != expected {expected_bytes}")
    return raw


def bitstring_is_revoked(raw: bytes, bit_length: int, idx: int) -> bool:
    """Check revocation bit at idx (MSB-first per W3C Bitstring Status List v1.0)."""
    if idx < 0 or idx >= bit_length or len(raw) * 8 < bit_length:
        raise IndexError("status list index out of bounds")
    byte_idx = idx // 8
    bit_mask = 1 << (7 - (idx % 8))
    return (raw[byte_idx] & bit_mask) != 0

# SPDX-License-Identifier: Apache-2.0
"""Content-addressed VFS / S3 object store adapter (no second storage stack)."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .canonical import sha256_hex


def _is_lower_hex64(s: str) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def validate_storage_uri(uri: str, digest: str) -> bool:
    """Validate that uri is a canonical vfs:// or s3:// content-addressed pointer for digest."""
    if not isinstance(uri, str) or not _is_lower_hex64(digest):
        return False
    if uri == f"vfs://sha256/{digest}":
        return True
    if uri.startswith("s3://"):
        rest = uri[len("s3://") :]
        slash = rest.find("/")
        if slash < 3 or slash > 63:
            return False
        bucket = rest[:slash]
        if not all(("a" <= c <= "z") or ("0" <= c <= "9") or c in ".-" for c in bucket):
            return False
        key = rest[slash + 1 :]
        return key == f"sha256/{digest[:2]}/{digest}"
    return False


@dataclass(frozen=True)
class ObjectPutResult:
    sha256: str
    uri: str
    size_bytes: int
    deduplicated: bool


class LocalVFSStore:
    """Content-addressed local VFS adapter using S3-compatible sharded keys sha256/<p>/<hex>."""

    def __init__(self, root_dir: str | Path, s3_bucket: str = "") -> None:
        self.root = Path(root_dir)
        self.s3_bucket = s3_bucket
        (self.root / "sha256").mkdir(parents=True, exist_ok=True)
        self.total_writes = 0
        self.dedup_hits = 0
        self.logical_bytes = 0
        self.stored_bytes = 0

    def uri_for(self, digest: str) -> str:
        if self.s3_bucket and len(digest) == 64:
            return f"s3://{self.s3_bucket}/sha256/{digest[:2]}/{digest}"
        return f"vfs://sha256/{digest}"

    def _obj_path(self, digest: str) -> Path:
        if not _is_lower_hex64(digest):
            raise ValueError(f"invalid sha256 hex: {digest!r}")
        return self.root / "sha256" / digest[:2] / digest

    def put(self, data: bytes) -> ObjectPutResult:
        digest = sha256_hex(data)
        path = self._obj_path(digest)
        self.total_writes += 1
        self.logical_bytes += len(data)
        if path.exists():
            self.dedup_hits += 1
            return ObjectPutResult(digest, self.uri_for(digest), len(data), True)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.replace(tmp, path)
        except Exception:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        self.stored_bytes += len(data)
        return ObjectPutResult(digest, self.uri_for(digest), len(data), False)

    def get(self, digest: str) -> bytes:
        path = self._obj_path(digest)
        data = path.read_bytes()
        got = sha256_hex(data)
        if got != digest:
            raise ValueError(f"vfs integrity mismatch: expected {digest}, got {got}")
        return data

    def exists(self, digest: str) -> bool:
        return self._obj_path(digest).exists()

    def stats(self) -> dict[str, int]:
        return {
            "total_writes": self.total_writes,
            "dedup_hits": self.dedup_hits,
            "logical_bytes": self.logical_bytes,
            "stored_bytes": self.stored_bytes,
        }

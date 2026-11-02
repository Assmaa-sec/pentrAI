"""Local-only ZIP object store for development and integration tests."""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
from collections.abc import AsyncIterable


class LocalObjectStore:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def path_for(self, key: str) -> Path:
        parts = PurePosixPath(key).parts
        if not parts or any(part in {"", ".", ".."} for part in parts) or "\\" in key or ":" in key:
            raise ValueError("invalid object key")
        if PurePosixPath(key).is_absolute():
            raise ValueError("object key must be relative")
        # A flat digest path also stays below Windows MAX_PATH in deep checkouts.
        return self.root / f"{hashlib.sha256(key.encode('utf-8')).hexdigest()}.zip"

    async def write_stream(self, key: str, chunks: AsyncIterable[bytes], max_bytes: int) -> int:
        path = self.path_for(key)
        total = 0
        created = False
        try:
            with path.open("xb") as output:
                created = True
                async for chunk in chunks:
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError("upload exceeds declared size")
                    output.write(chunk)
            if total != max_bytes:
                raise ValueError("upload size differs from declared size")
        except Exception:
            if created:
                path.unlink(missing_ok=True)
            raise
        return total

    def read_chunks(self, key: str):
        with self.path_for(key).open("rb") as source:
            while chunk := source.read(1024 * 1024):
                yield chunk

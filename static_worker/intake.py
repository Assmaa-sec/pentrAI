"""Bounded ZIP metadata inspection for untrusted source archives."""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath


class IntakeRejected(ValueError):
    pass


@dataclass(frozen=True)
class IntakeLimits:
    max_archive_bytes: int = 50 * 1024 * 1024
    max_members: int = 5000
    max_expanded_bytes: int = 250 * 1024 * 1024
    max_member_bytes: int = 25 * 1024 * 1024
    max_compression_ratio: int = 100
    max_depth: int = 16


@dataclass(frozen=True)
class FileEntry:
    path: str
    size: int
    crc32: int


@dataclass(frozen=True)
class SourceInventory:
    archive_sha256: str
    manifest_sha256: str
    files: tuple[FileEntry, ...]
    total_expanded_bytes: int


def _safe_path(name: str, max_depth: int) -> str:
    if not name or "\x00" in name or "\\" in name or name.startswith("/") or PureWindowsPath(name).drive:
        raise IntakeRejected("archive member path is unsafe")
    parts = (name[:-1] if name.endswith("/") else name).split("/")
    reserved = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
    if not parts or any(
        part in {".", "..", ""}
        or ":" in part
        or part.rstrip(" .") != part
        or part.split(".", 1)[0].casefold() in reserved
        for part in parts
    ):
        raise IntakeRejected("archive member path is unsafe")
    if len(parts) > max_depth:
        raise IntakeRejected("archive member path exceeds depth limit")
    return "/".join(parts)


def inspect_archive(path: Path, limits: IntakeLimits) -> SourceInventory:
    """Reject unsafe ZIP members before any caller extracts source content."""
    if path.stat().st_size > limits.max_archive_bytes:
        raise IntakeRejected("archive size limit exceeded")
    archive_bytes = path.read_bytes()
    archive_digest = hashlib.sha256(archive_bytes)

    entries: list[FileEntry] = []
    seen: set[str] = set()
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            members = archive.infolist()
            if len(members) > limits.max_members:
                raise IntakeRejected("archive member count limit exceeded")
            for info in members:
                normalized = _safe_path(info.filename, limits.max_depth)
                folded = normalized.casefold()
                if folded in seen:
                    raise IntakeRejected("duplicate normalized archive member name")
                seen.add(folded)
                kind = stat.S_IFMT(info.external_attr >> 16) if info.create_system == 3 else 0
                if kind == stat.S_IFLNK:
                    raise IntakeRejected("archive links are not allowed")
                if kind not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise IntakeRejected("special archive member is not allowed")
                if info.flag_bits & 0x1:
                    raise IntakeRejected("encrypted archive member is not allowed")
                if info.is_dir():
                    if info.file_size:
                        raise IntakeRejected("directory member has content")
                    continue
                if kind == stat.S_IFDIR:
                    raise IntakeRejected("directory member has content")
                if info.file_size > limits.max_member_bytes:
                    raise IntakeRejected("member expanded size limit exceeded")
                total += info.file_size
                if total > limits.max_expanded_bytes:
                    raise IntakeRejected("archive expanded size limit exceeded")
                if info.file_size / max(info.compress_size, 1) > limits.max_compression_ratio:
                    raise IntakeRejected("archive compression ratio limit exceeded")
                entries.append(FileEntry(normalized, info.file_size, info.CRC))
    except zipfile.BadZipFile as exc:
        raise IntakeRejected("invalid ZIP archive") from exc
    canonical = json.dumps(
        [entry.__dict__ for entry in sorted(entries, key=lambda entry: entry.path)],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return SourceInventory(
        archive_sha256=archive_digest.hexdigest(),
        manifest_sha256=hashlib.sha256(canonical).hexdigest(),
        files=tuple(entries),
        total_expanded_bytes=total,
    )


def extract_archive(path: Path, workspace: Path, limits: IntakeLimits) -> Path:
    """Extract a validated snapshot into a new job-owned source directory."""
    inventory = inspect_archive(path, limits)
    archive_bytes = path.read_bytes()
    if hashlib.sha256(archive_bytes).hexdigest() != inventory.archive_sha256:
        raise IntakeRejected("archive changed during intake")
    workspace_root = workspace.resolve(strict=True)
    if not workspace_root.is_dir():
        raise ValueError("workspace must be a directory")
    destination = workspace_root / "source"
    destination.mkdir(exist_ok=False)
    try:
        total = 0
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            expected = {entry.path: entry for entry in inventory.files}
            for info in archive.infolist():
                if info.is_dir():
                    continue
                normalized = _safe_path(info.filename, limits.max_depth)
                entry = expected[normalized]
                target = destination.joinpath(*PurePosixPath(normalized).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with archive.open(info) as source, target.open("xb") as output:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        written += len(chunk)
                        total += len(chunk)
                        if written > entry.size or total > limits.max_expanded_bytes:
                            raise IntakeRejected("archive expanded size limit exceeded")
                        output.write(chunk)
                if written != entry.size:
                    raise IntakeRejected("archive member size changed")
    except Exception:
        # Only this newly created directory is removed, after checking its
        # resolved absolute path remains directly under the intended workspace.
        if destination.resolve() == workspace_root / "source":
            shutil.rmtree(destination)
        raise
    return destination

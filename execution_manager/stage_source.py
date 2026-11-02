"""Isolated source ZIP staging; never builds or runs the uploaded application."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

import httpx

from static_worker.intake import IntakeLimits, IntakeRejected, SourceInventory, extract_archive, inspect_archive


def stage_source(
    archive: Path, workspace: Path, expected_sha256: str, expected_bytes: int,
    *, limits: IntakeLimits | None = None,
) -> tuple[Path, SourceInventory]:
    """Verify immutable archive bytes and extract only inside a job-owned volume.

    The artifact broker places the archive on a read-only input mount. This
    function runs inside the isolated stager, before the agent gets a read-only
    view of the resulting source volume.
    """
    limits = limits or IntakeLimits()
    if (len(expected_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in expected_sha256)
            or not 0 < expected_bytes <= limits.max_archive_bytes):
        raise ValueError("invalid source artifact claim")
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size != expected_bytes:
        raise IntakeRejected("staged archive size or type changed")
    digest = hashlib.sha256()
    with archive.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected_sha256:
        raise IntakeRejected("staged archive digest changed")
    if workspace.is_symlink() or not workspace.is_dir():
        raise ValueError("job source workspace is unavailable")
    inventory = inspect_archive(archive, limits)
    if inventory.archive_sha256 != expected_sha256:
        raise IntakeRejected("staged archive digest changed")
    source_root = extract_archive(archive, workspace, limits)
    return source_root, inventory


def fetch_and_stage_source(
    broker: str, artifact_id: str, token_path: Path, scratch: Path,
    workspace: Path, expected_sha256: str, expected_bytes: int,
) -> tuple[Path, SourceInventory]:
    limits = IntakeLimits()
    if (not 0 < expected_bytes <= limits.max_archive_bytes
            or len(expected_sha256) != 64
            or any(ch not in "0123456789abcdef" for ch in expected_sha256)):
        raise ValueError("invalid source artifact claim")
    parsed = urlsplit(broker)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.port is None
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
            or parsed.username or parsed.password):
        raise ValueError("source broker must be private HTTPS")
    address = ipaddress.ip_address(parsed.hostname)
    if not address.is_private or address.is_loopback or address.is_link_local:
        raise ValueError("source broker must be private HTTPS")
    try:
        canonical_id = str(UUID(artifact_id))
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid source artifact id") from exc
    if canonical_id != artifact_id or not scratch.is_dir() or scratch.is_symlink():
        raise ValueError("invalid source staging workspace")
    token = token_path.read_text(encoding="utf-8").strip()
    if not token or len(token) > 4096:
        raise ValueError("source broker token is missing")
    archive = scratch / "source.zip"
    if archive.exists():
        raise ValueError("source staging scratch is not empty")
    url = broker.rstrip("/") + f"/internal/artifacts/{artifact_id}"
    created = False
    try:
        digest = hashlib.sha256()
        size = 0
        with httpx.Client(timeout=60, follow_redirects=False, trust_env=False) as client:
            with client.stream("GET", url, headers={"Authorization": f"Bearer {token}"}) as response:
                if response.status_code != 200:
                    raise IntakeRejected("source broker did not return the artifact")
                response.raise_for_status()
                with archive.open("xb") as output:
                    created = True
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > expected_bytes:
                            raise IntakeRejected("source broker returned too many bytes")
                        digest.update(chunk)
                        output.write(chunk)
        if size != expected_bytes or digest.hexdigest() != expected_sha256:
            raise IntakeRejected("source broker bytes differ from finalized artifact")
        return stage_source(archive, workspace, expected_sha256, expected_bytes)
    finally:
        if created:
            archive.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Stage a verified source ZIP inside the runner")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--archive", type=Path)
    source.add_argument("--broker")
    parser.add_argument("--artifact-id")
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--scratch", type=Path)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--bytes", type=int, required=True)
    args = parser.parse_args()
    if args.broker:
        if not args.artifact_id or args.token_file is None or args.scratch is None:
            parser.error("broker staging requires artifact id, token file, and scratch")
        source_root, inventory = fetch_and_stage_source(
            args.broker, args.artifact_id, args.token_file, args.scratch,
            args.workspace, args.sha256, args.bytes)
    else:
        source_root, inventory = stage_source(args.archive, args.workspace, args.sha256, args.bytes)
    print(f"staged {len(inventory.files)} files at {source_root}", flush=True)


if __name__ == "__main__":
    main()

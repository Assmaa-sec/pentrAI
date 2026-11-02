"""Grant-bound source download for an isolated staging job."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from .grants import GrantError, verify_grant
from .models import RunnerLease, Scan, ScanGrant, ScanState, SourceArtifact


class SourceBrokerRejected(PermissionError):
    pass


def authorize_source_download(
    session: Session, artifact_id: str, token: str, signing_key: bytes,
    *, now: datetime | None = None,
) -> SourceArtifact:
    now = now or datetime.now(timezone.utc)
    if not token or len(token) > 4096:
        raise SourceBrokerRejected("runner grant is required")
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    record = session.scalar(select(ScanGrant).where(ScanGrant.token_digest == digest))
    scan = session.get(Scan, record.scan_id) if record else None
    if (scan is None or scan.state is not ScanState.QUEUED
            or scan.execution_backend != "hexstrike"):
        raise SourceBrokerRejected("queued scan is required")
    try:
        claims = verify_grant(session, token, signing_key, scan.source_digest, now=now)
    except GrantError as exc:
        raise SourceBrokerRejected("valid runner grant is required") from exc
    if (claims.record.id != record.id or claims.scan_id != scan.id
            or not scan.source_artifact_id or scan.source_artifact_id != artifact_id):
        raise SourceBrokerRejected("source artifact is outside the runner grant")
    lease = session.scalar(select(RunnerLease).where(
        RunnerLease.scan_id == scan.id, RunnerLease.scan_grant_id == record.id,
        RunnerLease.cleaned_at.is_(None),
    ))
    if (lease is None or (lease.expires_at.replace(tzinfo=timezone.utc)
                          if lease.expires_at.tzinfo is None else lease.expires_at) <= now):
        raise SourceBrokerRejected("live runner lease is required")
    artifact = session.scalar(select(SourceArtifact).where(
        SourceArtifact.id == artifact_id,
        SourceArtifact.organization_id == scan.organization_id,
        SourceArtifact.project_id == scan.project_id,
    ))
    if (artifact is None or artifact.sha256 != scan.source_digest
            or artifact.content_type != "application/zip"
            or not 0 < artifact.size_bytes <= 50 * 1024 * 1024):
        raise SourceBrokerRejected("finalized source artifact is required")
    return artifact

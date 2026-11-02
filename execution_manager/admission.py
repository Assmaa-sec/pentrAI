"""Bind an authorized customer scan to one native HexStrike runner lease.

The caller owns the transaction and must provision the isolated workload and
arrange cleanup. This module does not launch customer code or tools.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from control_plane.events import append_visible_event
from control_plane.grants import ScanGrantClaims, issue_grant, recover_grant_token, verify_grant
from control_plane.models import AuditEvent, RunnerLease, Scan, ScanGrant, ScanState, SourceArtifact
from control_plane.organization_authorization import active_authorization
from .job_agent import JobScope
from .leases import create_lease


@dataclass(frozen=True)
class PreparedRunnerJob:
    lease: RunnerLease
    claims: ScanGrantClaims
    scope: JobScope
    artifact_id: str | None
    artifact_bytes: int | None
    grant_token: str = field(repr=False)


def _artifact_for_scan(session: Session, scan: Scan) -> SourceArtifact | None:
    artifact = session.scalar(select(SourceArtifact).where(
        SourceArtifact.id == scan.source_artifact_id,
        SourceArtifact.organization_id == scan.organization_id,
        SourceArtifact.project_id == scan.project_id,
    )) if scan.source_artifact_id else None
    if scan.source_artifact_id and (
        artifact is None or artifact.sha256 != scan.source_digest
        or artifact.content_type != "application/zip"
        or not 0 < artifact.size_bytes <= 50 * 1024 * 1024
    ):
        raise ValueError("finalized source artifact binding changed")
    return artifact


def _prepared(scan: Scan, lease: RunnerLease, claims: ScanGrantClaims,
              artifact: SourceArtifact | None, token: str, now: datetime) -> PreparedRunnerJob:
    expiry = (lease.expires_at.replace(tzinfo=timezone.utc)
              if lease.expires_at.tzinfo is None else lease.expires_at)
    scope = JobScope.from_dict({
        "scan_id": scan.id,
        "organization_id": scan.organization_id,
        "lease_id": lease.id,
        "source_digest": scan.source_digest,
        "scope_digest": scan.scope_digest,
        "source_present": artifact is not None,
        "target_url": scan.target_url,
        "scope_note": scan.scope_note,
        "profile": scan.profile,
        "expires_at": expiry.isoformat(),
    }, now=now)
    return PreparedRunnerJob(lease, claims, scope,
                             artifact.id if artifact else None,
                             artifact.size_bytes if artifact else None, token)


def prepare_runner_job(
    session: Session, organization_id: str, scan_id: str, signing_key: bytes,
    *, dynamic_scans_enabled: bool = False,
    now: datetime | None = None,
    ttl: timedelta = timedelta(minutes=15),
) -> PreparedRunnerJob:
    """Stage a queue transition and matching grant/lease in one transaction.

    The caller must commit or roll back the complete transaction. A dispatcher
    must still provision credentials and isolated resources, and must arrange
    idempotent cleanup for any failure after commit.
    """
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None or not timedelta(0) < ttl <= timedelta(hours=1):
        raise ValueError("invalid runner admission lifetime")
    scan = session.scalar(select(Scan).where(
        Scan.id == scan_id, Scan.organization_id == organization_id,
    ).with_for_update())
    if (scan is None or scan.state is not ScanState.AUTHORIZED
            or scan.execution_backend not in {"hexstrike", "hexstrike_local"}):
        raise ValueError("authorized scan is required for runner admission")
    if scan.dynamic_authorized != bool(scan.target_url):
        raise ValueError("scan target authorization changed")
    if scan.target_url and not dynamic_scans_enabled:
        raise ValueError("URL scan release gate is closed")
    if not scan.source_artifact_id and not scan.target_url:
        raise ValueError("scan has no assessment target")
    if scan.authorization_id is not None:
        authority = active_authorization(session, organization_id,
                                         source=bool(scan.source_artifact_id), url=bool(scan.target_url), now=now)
        if authority.id != scan.authorization_id:
            raise ValueError("scan organization authority changed")
    artifact = _artifact_for_scan(session, scan)
    live_grant = session.scalar(select(ScanGrant.id).where(
        ScanGrant.scan_id == scan.id,
        ScanGrant.organization_id == organization_id,
        ScanGrant.revoked_at.is_(None),
        ScanGrant.expires_at > now,
    ))
    if live_grant is not None:
        raise ValueError("scan already has a live runner grant")
    scan.state = ScanState.QUEUED
    token = issue_grant(session, scan, signing_key, ttl, now=now)
    claims = verify_grant(session, token, signing_key, scan.source_digest, now=now)
    lease = create_lease(session, claims, ttl, now=now)
    prepared = _prepared(scan, lease, claims, artifact, token, now)
    session.add(AuditEvent(
        organization_id=organization_id, scan_id=scan.id,
        actor_id="execution-manager", action="runner.admitted",
        payload={"lease_id": lease.id, "source": artifact is not None,
                 "url": bool(scan.target_url), "profile": scan.profile},
    ))
    append_visible_event(session, scan.id, organization_id, "status", "Assessment queued")
    session.flush()
    return prepared


def resume_runner_job(
    session: Session, organization_id: str, lease_id: str, signing_key: bytes,
    *, dynamic_scans_enabled: bool = False, now: datetime | None = None,
) -> PreparedRunnerJob:
    """Recover a committed queued job after a dispatcher process restart."""
    now = now or datetime.now(timezone.utc)
    lease = session.scalar(select(RunnerLease).where(
        RunnerLease.id == lease_id, RunnerLease.organization_id == organization_id,
        RunnerLease.cleaned_at.is_(None),
    ))
    scan = session.scalar(select(Scan).where(
        Scan.id == lease.scan_id, Scan.organization_id == organization_id,
    )) if lease else None
    if (scan is None or scan.state is not ScanState.QUEUED
            or scan.execution_backend not in {"hexstrike", "hexstrike_local"}):
        raise ValueError("live queued runner job not found")
    if scan.target_url and not dynamic_scans_enabled:
        raise ValueError("URL scan release gate is closed")
    if scan.authorization_id is not None:
        authority = active_authorization(session, organization_id,
                                         source=bool(scan.source_artifact_id), url=bool(scan.target_url), now=now)
        if authority.id != scan.authorization_id:
            raise ValueError("scan organization authority changed")
    token = recover_grant_token(session, lease.scan_grant_id, signing_key, now=now)
    claims = verify_grant(session, token, signing_key, scan.source_digest, now=now)
    if claims.record.id != lease.scan_grant_id or claims.scan_id != scan.id:
        raise ValueError("runner grant and lease changed")
    artifact = _artifact_for_scan(session, scan)
    return _prepared(scan, lease, claims, artifact, token, now)

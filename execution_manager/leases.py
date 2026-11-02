"""Durable, fail-closed runner lease lifecycle.

Cloud adapters must make namespace deletion and artifact-token revocation
idempotent. This module records intent and cleanup, but does not provision a
runner or enable dynamic execution.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable, Protocol

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from control_plane.grants import ScanGrantClaims
from control_plane.events import append_visible_event
from control_plane.models import AuditEvent, RunnerLease, Scan, ScanGrant, ScanReport, ScanState, WebTargetProof, new_uuid, utcnow
from control_plane.web_targets import normalize_target_url, WebTargetRejected
from control_plane.credits import release_scan_credits


class NamespaceClient(Protocol):
    def delete_namespace(self, namespace: str) -> None: ...


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def create_lease(
    session: Session, claims: ScanGrantClaims, ttl: timedelta, *, now: datetime | None = None,
) -> RunnerLease:
    """Record a unique lease for a queued scan under a verified grant."""
    now = now or utcnow()
    if not timedelta(0) < ttl <= timedelta(hours=1):
        raise ValueError("runner lease lifetime must be at most one hour")
    scan = session.scalar(select(Scan).where(
        Scan.id == claims.scan_id, Scan.organization_id == claims.organization_id,
    ).with_for_update())
    grant = session.get(ScanGrant, claims.record.id)
    if (scan is None or scan.state is not ScanState.QUEUED or grant is None
            or grant.scan_id != scan.id or grant.organization_id != scan.organization_id
            or grant.revoked_at is not None or _aware(grant.expires_at) <= now
            or scan.source_digest != claims.source_digest or scan.project_id != claims.project_id
            or scan.target_url != claims.target_url
            or scan.web_target_proof_id != claims.web_target_proof_id
            or scan.scope_digest != claims.scope_digest or scan.profile != claims.profile
            or scan.dynamic_authorized != claims.dynamic_authorized):
        raise ValueError("queued scan and live grant are required for a runner lease")
    if scan.target_url:
        try:
            _, origin = normalize_target_url(scan.target_url)
        except WebTargetRejected as exc:
            raise ValueError("verified web target proof is required for a runner lease") from exc
        proof = session.get(WebTargetProof, scan.web_target_proof_id)
        if (proof is None or proof.organization_id != scan.organization_id
                or proof.project_id != scan.project_id or proof.origin != origin
                or proof.verified_at is None or proof.verified_until is None
                or _aware(proof.verified_until) <= now):
            raise ValueError("verified web target proof is required for a runner lease")
    if session.scalar(select(RunnerLease.id).where(
        RunnerLease.scan_id == scan.id, RunnerLease.cleaned_at.is_(None),
    )) is not None:
        raise ValueError("scan already has an active runner lease")
    lease_id = new_uuid()
    lease = RunnerLease(
        id=lease_id, organization_id=scan.organization_id, scan_id=scan.id,
        scan_grant_id=grant.id, namespace=f"scan-{lease_id.replace('-', '')}",
        service_account="scan-runner", expires_at=min(now + ttl, _aware(grant.expires_at)),
        heartbeat_at=now,
    )
    session.add(lease)
    session.add(AuditEvent(
        organization_id=scan.organization_id, scan_id=scan.id,
        actor_id="execution-manager", action="runner.lease_created",
        payload={"lease_id": lease.id},
    ))
    session.flush()
    return lease


def reap_expired_leases(
    session: Session,
    cluster: NamespaceClient,
    revoke_artifact_grant: Callable[[RunnerLease], None],
    *,
    now: datetime | None = None,
    limit: int = 100,
    execution_backend: str | None = None,
) -> int:
    """Retry cleanup until namespace deletion and token revocation both succeed.

    The caller commits after this function returns. If the process crashes before
    commit, the next pass repeats the idempotent external operations.
    """
    now = now or utcnow()
    if not 1 <= limit <= 1000:
        raise ValueError("lease reaper limit must be between 1 and 1000")
    query = select(RunnerLease).join(Scan, Scan.id == RunnerLease.scan_id).where(
        or_(RunnerLease.expires_at <= now,
            Scan.state.in_((ScanState.CLEANUP, ScanState.CANCELLED))),
        RunnerLease.cleaned_at.is_(None),
    )
    if execution_backend is not None:
        query = query.where(Scan.execution_backend == execution_backend)
    leases = session.scalars(query.order_by(RunnerLease.expires_at).limit(limit)
                             .with_for_update(skip_locked=True)).all()
    cleaned = 0
    for lease in leases:
        lease.cleanup_attempts += 1
        errors: list[str] = []
        try:
            cluster.delete_namespace(lease.namespace)
        except Exception as exc:  # retry on the next reaper pass
            errors.append(f"namespace:{type(exc).__name__}")
        if lease.artifact_grant_revoked_at is None:
            try:
                revoke_artifact_grant(lease)
                lease.artifact_grant_revoked_at = now
            except Exception as exc:  # retry on the next reaper pass
                errors.append(f"artifact_grant:{type(exc).__name__}")
        grant = session.get(ScanGrant, lease.scan_grant_id)
        if grant is None:
            errors.append("scan_grant:missing")
        elif grant.revoked_at is None:
            grant.revoked_at = now
        lease.cleanup_error = ",".join(errors)[:200] if errors else None
        if not errors:
            lease.cleaned_at = now
            cleaned += 1
            scan = session.get(Scan, lease.scan_id)
            if scan is not None and scan.state is ScanState.CANCELLED:
                release_scan_credits(session, scan)
            if scan is not None and scan.state is ScanState.CLEANUP:
                report = session.scalar(select(ScanReport.id).where(ScanReport.scan_id == scan.id))
                scan.state = ScanState.COMPLETED if report is not None else ScanState.FAILED
                if report is None:
                    release_scan_credits(session, scan)
                append_visible_event(session, scan.id, scan.organization_id, "status",
                                     "Assessment completed" if report is not None
                                     else "Assessment could not be completed")
            elif scan is not None and scan.state not in (
                ScanState.COMPLETED, ScanState.FAILED, ScanState.CANCELLED,
            ):
                scan.state = ScanState.FAILED
                release_scan_credits(session, scan)
                append_visible_event(session, scan.id, scan.organization_id, "status",
                                     "Assessment could not be completed")
        session.add(AuditEvent(
            organization_id=lease.organization_id, scan_id=lease.scan_id,
            actor_id="execution-manager",
            action="runner.lease_cleaned" if not errors else "runner.cleanup_retry",
            payload={"lease_id": lease.id, "attempt": lease.cleanup_attempts,
                     "error_class": lease.cleanup_error},
        ))
    session.flush()
    return cleaned

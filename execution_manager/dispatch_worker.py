"""Durable admission and launch loop for native HexStrike runner Jobs."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Callable
from uuid import uuid4

from sqlalchemy import or_, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from control_plane.events import append_visible_event
from control_plane.models import AuditEvent, RunnerLease, Scan, ScanGrant, ScanState
from control_plane.runner_readiness import publish_worker_heartbeat
from .admission import prepare_runner_job, resume_runner_job
from .dispatch import ClusterClient, launch_prepared_job
from .preflight import ClusterFacts, preflight_failures
from .staging_workload import SourceBrokerEnvironment
from .workload import RunnerEnvironment


_WORKER_ID = str(uuid4())


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def dispatch_tick(
    engine: Engine, signing_key: bytes,
    cluster_for_namespace: Callable[[str], ClusterClient],
    runner: RunnerEnvironment, broker: SourceBrokerEnvironment | None,
    facts: ClusterFacts, *, containment_verified: bool = False,
    dynamic_scans_enabled: bool = False,
    now: datetime | None = None,
) -> bool:
    """Claim one customer scan, resume or admit it, and launch exactly one Job.

    A short renewable database claim excludes competing workers. If a process
    stops, another can recover the signed grant after the claim expires.
    The cluster must independently enforce containment; the default is closed.
    """
    if not containment_verified or preflight_failures(facts):
        raise ValueError("execution cluster containment is not verified")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("dispatch time must include timezone")
    owner = str(uuid4())
    url_filter = () if dynamic_scans_enabled else (Scan.target_url.is_(None),)
    with Session(engine) as session:
        with session.begin():
            publish_worker_heartbeat(
                session, _WORKER_ID, facts, runner, broker,
                containment_verified=containment_verified,
                url_enabled=dynamic_scans_enabled, now=now,
            )
    with Session(engine) as session:
        with session.begin():
            lease = session.scalar(select(RunnerLease).join(
                Scan, Scan.id == RunnerLease.scan_id,
            ).where(
                Scan.state == ScanState.QUEUED,
                Scan.execution_backend == "hexstrike",
                RunnerLease.cleaned_at.is_(None),
                RunnerLease.launched_at.is_(None),
                RunnerLease.expires_at > now,
                RunnerLease.dispatch_attempts < 3,
                or_(RunnerLease.dispatch_claim_until.is_(None),
                    RunnerLease.dispatch_claim_until <= now),
                *url_filter,
            ).order_by(RunnerLease.created_at).limit(1).with_for_update(skip_locked=True))
            if lease is None:
                scan = session.scalar(select(Scan).where(
                    Scan.state == ScanState.AUTHORIZED,
                    Scan.execution_backend == "hexstrike",
                    *url_filter,
                ).order_by(Scan.created_at).limit(1).with_for_update(skip_locked=True))
                if scan is None:
                    return False
                prepared = prepare_runner_job(
                    session, scan.organization_id, scan.id, signing_key,
                    dynamic_scans_enabled=dynamic_scans_enabled, now=now)
                lease = prepared.lease
            lease.dispatch_owner = owner
            lease.dispatch_claim_until = min(now + timedelta(minutes=3),
                                             _aware(lease.expires_at))
            lease.dispatch_attempts += 1
            lease_id, organization_id, namespace = (
                lease.id, lease.organization_id, lease.namespace)

    def heartbeat() -> None:
        current = datetime.now(timezone.utc)
        with Session(engine) as session:
            with session.begin():
                active = session.scalar(select(RunnerLease).where(
                    RunnerLease.id == lease_id,
                ).with_for_update())
                scan = session.get(Scan, active.scan_id) if active is not None else None
                grant = session.get(ScanGrant, active.scan_grant_id) if active is not None else None
                if (active is None or active.dispatch_owner != owner
                        or active.cleaned_at is not None or active.launched_at is not None
                        or _aware(active.expires_at) <= current
                        or scan is None or scan.state is not ScanState.QUEUED
                        or scan.execution_backend != "hexstrike"
                        or grant is None or grant.revoked_at is not None
                        or _aware(grant.expires_at) <= current):
                    raise RuntimeError("runner dispatch claim was lost")
                active.dispatch_claim_until = min(current + timedelta(minutes=3),
                                                  _aware(active.expires_at))
                publish_worker_heartbeat(
                    session, _WORKER_ID, facts, runner, broker,
                    containment_verified=containment_verified,
                    url_enabled=dynamic_scans_enabled, now=current,
                )

    try:
        with Session(engine) as session:
            prepared = resume_runner_job(
                session, organization_id, lease_id, signing_key,
                dynamic_scans_enabled=dynamic_scans_enabled)
        cluster = cluster_for_namespace(namespace)
        launch_prepared_job(
            prepared, cluster, runner, broker, signing_key, facts,
            containment_verified=True, dynamic_scans_enabled=dynamic_scans_enabled,
            heartbeat=heartbeat,
        )
        with Session(engine) as session:
            with session.begin():
                active = session.scalar(select(RunnerLease).where(
                    RunnerLease.id == lease_id,
                ).with_for_update())
                if active is None or active.dispatch_owner != owner:
                    raise RuntimeError("runner dispatch claim was lost")
                active.launched_at = datetime.now(timezone.utc)
                active.dispatch_owner = None
                active.dispatch_claim_until = None
                session.add(AuditEvent(
                    organization_id=organization_id, scan_id=active.scan_id,
                    actor_id="execution-manager", action="runner.launched",
                    payload={"lease_id": lease_id},
                ))
                append_visible_event(session, active.scan_id, organization_id,
                                     "status", "Assessment running")
    except Exception:
        with Session(engine) as session:
            with session.begin():
                active = session.scalar(select(RunnerLease).where(
                    RunnerLease.id == lease_id,
                ).with_for_update())
                if active is not None and active.dispatch_owner == owner:
                    active.dispatch_owner = None
                    active.dispatch_claim_until = None
                    if active.dispatch_attempts >= 3:
                        scan = session.get(Scan, active.scan_id)
                        if scan is not None and scan.state is ScanState.QUEUED:
                            scan.state = ScanState.CLEANUP
                            append_visible_event(session, scan.id, organization_id,
                                                 "warning", "Assessment could not be started")
                    session.add(AuditEvent(
                        organization_id=organization_id, scan_id=active.scan_id,
                        actor_id="execution-manager", action="runner.dispatch_retry",
                        payload={"lease_id": lease_id,
                                 "attempt": active.dispatch_attempts},
                    ))
        raise
    return True

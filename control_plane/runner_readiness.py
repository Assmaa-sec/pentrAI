"""Admit native scans only while a verified dispatcher is actively polling."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from execution_manager.preflight import ClusterFacts, preflight_failures
from execution_manager.staging_workload import SourceBrokerEnvironment
from execution_manager.workload import RunnerEnvironment

from .models import NativeRunnerWorker


def publish_worker_heartbeat(
    session: Session, worker_id: str, facts: ClusterFacts,
    runner: RunnerEnvironment, broker: SourceBrokerEnvironment | None, *,
    containment_verified: bool = False, url_enabled: bool = False,
    now: datetime | None = None,
) -> None:
    """Publish only after the service has verified its execution dependencies."""
    now = now or datetime.now(timezone.utc)
    if (str(UUID(worker_id)) != worker_id or now.tzinfo is None
            or not containment_verified or preflight_failures(facts)
            or not isinstance(runner, RunnerEnvironment)
            or not isinstance(broker, SourceBrokerEnvironment)):
        raise ValueError("native runner is not ready")
    session.execute(delete(NativeRunnerWorker).where(
        NativeRunnerWorker.heartbeat_at < now - timedelta(hours=1)))
    status = session.get(NativeRunnerWorker, worker_id)
    if status is None:
        status = NativeRunnerWorker(id=worker_id, heartbeat_at=now,
                                    source_ready=True, url_ready=url_enabled)
        session.add(status)
    else:
        status.heartbeat_at = now
        status.source_ready = True
        status.url_ready = url_enabled
    session.flush()


def runner_available(session: Session, *, url: bool = False,
                     now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("readiness time must include timezone")
    cutoff = now - timedelta(seconds=30)
    return session.scalar(select(NativeRunnerWorker.id).where(
        NativeRunnerWorker.heartbeat_at >= cutoff,
        NativeRunnerWorker.url_ready.is_(True) if url
        else NativeRunnerWorker.source_ready.is_(True),
    ).limit(1)) is not None

"""Development Docker worker heartbeat, separate from production ACK readiness."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import LocalHexStrikeWorker


def publish_local_heartbeat(session: Session, worker_id: str, *,
                            now: datetime | None = None) -> None:
    now = now or datetime.now(timezone.utc)
    if str(UUID(worker_id)) != worker_id or now.tzinfo is None:
        raise ValueError("invalid local worker heartbeat")
    worker = session.get(LocalHexStrikeWorker, worker_id)
    if worker is None:
        session.add(LocalHexStrikeWorker(id=worker_id, heartbeat_at=now))
    else:
        worker.heartbeat_at = now
    session.flush()


def local_worker_available(session: Session, *, now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("readiness time must include timezone")
    return session.scalar(select(LocalHexStrikeWorker.id).where(
        LocalHexStrikeWorker.heartbeat_at >= now - timedelta(seconds=30)
    ).limit(1)) is not None

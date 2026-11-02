"""Transactional outbox dispatcher primitives.

The caller holds the transaction while delivering and marks the event delivered
only after the downstream receiver acknowledges its idempotent event ID.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from .models import OutboxEvent, utcnow


@dataclass(frozen=True)
class DispatchMessage:
    """Queue envelope containing identifiers only, never customer data."""

    event_id: str
    kind: str
    organization_id: str
    scan_id: str | None


def claim_outbox(session: Session, limit: int = 100) -> list[OutboxEvent]:
    if not 1 <= limit <= 1000:
        raise ValueError("outbox claim limit must be between 1 and 1000")
    events = list(
        session.scalars(
            select(OutboxEvent)
            .where(OutboxEvent.delivered_at.is_(None))
            .order_by(OutboxEvent.created_at, OutboxEvent.id)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
    )
    for event in events:
        event.attempts += 1
    session.flush()
    return events


def mark_delivered(session: Session, event_id: str) -> None:
    event = session.get(OutboxEvent, event_id)
    if event is None:
        raise LookupError("outbox event not found")
    event.delivered_at = utcnow()
    session.flush()


def dispatch_once(engine: Engine, deliver: Callable[[DispatchMessage], None]) -> bool:
    """Deliver one pending event, committing its acknowledgement atomically.

    The receiver must deduplicate by event_id: a process can fail after delivery
    but before the database commit. A failed delivery rolls the transaction back
    and leaves the event available for retry.
    """
    with Session(engine) as session:
        with session.begin():
            claimed = claim_outbox(session, limit=1)
            if not claimed:
                return False
            event = claimed[0]
            deliver(DispatchMessage(event.id, event.kind, event.organization_id, event.scan_id))
            mark_delivered(session, event.id)
    return True

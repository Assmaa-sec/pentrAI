"""Persist redacted visible scan events before any SSE publication."""

from __future__ import annotations

import re

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import OutboxEvent, Scan, ScanEvent


_ASSIGNMENT = re.compile(r"(?i)\b(token|password|passwd|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+")
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]+")
_VISIBLE_KINDS = frozenset({"intake", "scanner", "analysis", "validation", "report", "status", "warning"})


def _safe_summary(value: str) -> str:
    cleaned = " ".join(value.split())[:2000]
    cleaned = _ASSIGNMENT.sub(r"\1=[REDACTED]", cleaned)
    cleaned = _AWS_KEY.sub("[REDACTED]", cleaned)
    cleaned = _BEARER.sub("Bearer [REDACTED]", cleaned)
    return cleaned[:500]


def append_visible_event(
    session: Session,
    scan_id: str,
    organization_id: str,
    kind: str,
    summary: str,
) -> ScanEvent:
    if kind not in _VISIBLE_KINDS:
        raise ValueError("unknown visible event kind")
    scan = session.scalar(
        select(Scan).where(Scan.id == scan_id, Scan.organization_id == organization_id).with_for_update()
    )
    if scan is None:
        raise LookupError("scan not found")
    last_sequence = session.scalar(select(func.max(ScanEvent.sequence)).where(ScanEvent.scan_id == scan_id)) or 0
    event = ScanEvent(
        organization_id=organization_id,
        scan_id=scan_id,
        sequence=last_sequence + 1,
        kind=kind,
        summary=_safe_summary(summary),
    )
    session.add(event)
    session.flush()
    session.add(
        OutboxEvent(
            organization_id=organization_id,
            scan_id=scan_id,
            kind="scan.visible_event",
            payload={"event_id": event.id, "sequence": event.sequence},
        )
    )
    session.flush()
    return event

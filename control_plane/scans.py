"""Transactional scan transitions and organization boundary."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditEvent, IdempotencyRecord, Membership, OutboxEvent, Scan, ScanState


class ScanNotFound(LookupError):
    pass


class InvalidTransition(ValueError):
    pass


class NotAuthorized(PermissionError):
    pass


_NEXT: dict[ScanState, frozenset[ScanState]] = {
    ScanState.DRAFT: frozenset({ScanState.UPLOADED}),
    ScanState.UPLOADED: frozenset({ScanState.AUTHORIZED}),
    ScanState.AUTHORIZED: frozenset({ScanState.QUEUED}),
    ScanState.QUEUED: frozenset({ScanState.INTAKE, ScanState.CLEANUP}),
    ScanState.INTAKE: frozenset({ScanState.STATIC, ScanState.CLEANUP}),
    ScanState.STATIC: frozenset({ScanState.DYNAMIC_ELIGIBLE, ScanState.REPORTING, ScanState.CLEANUP}),
    ScanState.DYNAMIC_ELIGIBLE: frozenset({ScanState.VALIDATING, ScanState.REPORTING, ScanState.CLEANUP}),
    ScanState.VALIDATING: frozenset({ScanState.REPORTING, ScanState.CLEANUP}),
    ScanState.REPORTING: frozenset({ScanState.CLEANUP}),
    ScanState.CLEANUP: frozenset({ScanState.COMPLETED, ScanState.FAILED, ScanState.CANCELLED}),
    ScanState.COMPLETED: frozenset(),
    ScanState.FAILED: frozenset(),
    ScanState.CANCELLED: frozenset(),
}


@dataclass(frozen=True)
class TransitionResult:
    scan_id: str
    state: ScanState
    audit_event_id: str


def transition_scan(
    session: Session,
    scan_id: str,
    organization_id: str,
    actor_id: str,
    to_state: ScanState,
    key: str,
    *,
    release_dynamic_enabled: bool = False,
) -> TransitionResult:
    """Stage a transition, audit, and outbox event in the caller's transaction."""
    if not key or len(key) > 200:
        raise ValueError("a bounded idempotency key is required")
    scan = session.scalar(
        select(Scan)
        .where(Scan.id == scan_id, Scan.organization_id == organization_id)
        .with_for_update()
    )
    if scan is None:
        raise ScanNotFound(scan_id)
    membership = session.scalar(
        select(Membership).where(
            Membership.organization_id == organization_id,
            Membership.user_id == actor_id,
        )
    )
    if membership is None or membership.role not in {"owner", "security_engineer"}:
        raise NotAuthorized("actor cannot transition this scan")
    prior = session.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.organization_id == organization_id,
            IdempotencyRecord.key == key,
        )
    )
    if prior is not None:
        if prior.scan_id != scan_id or prior.target_state != to_state:
            raise ValueError("idempotency key was used for another transition")
        return TransitionResult(scan_id, to_state, prior.audit_event_id)
    if to_state not in _NEXT[scan.state]:
        raise InvalidTransition(f"{scan.state.value} cannot enter {to_state.value}")
    if to_state is ScanState.VALIDATING:
        if not scan.dynamic_authorized:
            raise NotAuthorized("dynamic validation requires scan authorization")
        if not release_dynamic_enabled:
            raise NotAuthorized("dynamic validation release gate is closed")

    from_state = scan.state
    scan.state = to_state
    audit = AuditEvent(
        organization_id=organization_id,
        scan_id=scan_id,
        actor_id=actor_id,
        action="scan.transition",
        payload={"from": from_state.value, "to": to_state.value},
    )
    session.add(audit)
    session.flush()
    session.add_all(
        [
            OutboxEvent(
                organization_id=organization_id,
                scan_id=scan_id,
                kind="scan.transition",
                payload={"scan_id": scan_id, "state": to_state.value, "audit_event_id": audit.id},
            ),
            IdempotencyRecord(
                organization_id=organization_id,
                scan_id=scan_id,
                key=key,
                target_state=to_state,
                audit_event_id=audit.id,
            ),
        ]
    )
    session.flush()
    return TransitionResult(scan_id, to_state, audit.id)

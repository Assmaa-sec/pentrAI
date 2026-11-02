"""Owner-approved organization assessment authority, separate from scan scope."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .events import append_visible_event
from .models import (AuditEvent, Organization, OrganizationAssessmentAuthorization,
                     Scan, ScanGrant, ScanState, utcnow)
from .credits import release_scan_credits


TERMS_VERSION = "2026-10"


class OrganizationAuthorizationRejected(ValueError):
    pass


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def active_authorization(session: Session, organization_id: str, *,
                         source: bool, url: bool,
                         now: datetime | None = None) -> OrganizationAssessmentAuthorization:
    now = now or utcnow()
    authorization = session.scalar(select(OrganizationAssessmentAuthorization).where(
        OrganizationAssessmentAuthorization.organization_id == organization_id,
        OrganizationAssessmentAuthorization.revoked_at.is_(None),
    ).order_by(OrganizationAssessmentAuthorization.approved_at.desc()).limit(1))
    if (authorization is None or _aware(authorization.expires_at) <= now
            or authorization.terms_version != TERMS_VERSION
            or (source and not authorization.source_allowed)
            or (url and not authorization.url_allowed)):
        raise OrganizationAuthorizationRejected("active organization assessment authorization is required")
    return authorization


def approve_authorization(session: Session, organization_id: str, actor_id: str, *,
                          scope_statement: str, source_allowed: bool, url_allowed: bool,
                          valid_days: int, accept_terms: bool) -> OrganizationAssessmentAuthorization:
    statement = scope_statement.strip()
    if (accept_terms is not True or not 20 <= len(statement) <= 2000 or not (source_allowed or url_allowed)
            or type(valid_days) is not int or not 1 <= valid_days <= 365):
        raise OrganizationAuthorizationRejected("bounded assessment authority and scope are required")
    org = session.scalar(select(Organization).where(
        Organization.id == organization_id).with_for_update())
    if org is None:
        raise OrganizationAuthorizationRejected("organization not found")
    now = utcnow()
    for previous in session.scalars(select(OrganizationAssessmentAuthorization).where(
        OrganizationAssessmentAuthorization.organization_id == organization_id,
        OrganizationAssessmentAuthorization.revoked_at.is_(None))).all():
        revoke_authorization(session, organization_id, actor_id, previous.id)
    record = OrganizationAssessmentAuthorization(
        organization_id=organization_id, approved_by=actor_id,
        scope_statement=statement, terms_version=TERMS_VERSION,
        source_allowed=source_allowed, url_allowed=url_allowed,
        approved_at=now, expires_at=now + timedelta(days=valid_days))
    session.add(record)
    session.flush()
    session.add(AuditEvent(organization_id=organization_id, actor_id=actor_id,
                           action="organization.authorization_approved",
                           payload={"authorization_id": record.id, "source_allowed": source_allowed,
                                    "url_allowed": url_allowed, "expires_at": record.expires_at.isoformat()}))
    return record


def revoke_authorization(session: Session, organization_id: str, actor_id: str,
                         authorization_id: str) -> None:
    session.scalar(select(Organization).where(Organization.id == organization_id).with_for_update())
    record = session.scalar(select(OrganizationAssessmentAuthorization).where(
        OrganizationAssessmentAuthorization.id == authorization_id,
        OrganizationAssessmentAuthorization.organization_id == organization_id).with_for_update())
    if record is None:
        raise OrganizationAuthorizationRejected("assessment authorization not found")
    if record.revoked_at is not None:
        return
    now = utcnow()
    record.revoked_at = now
    scans = session.scalars(select(Scan).where(
        Scan.authorization_id == record.id,
        Scan.state.in_((ScanState.AUTHORIZED, ScanState.QUEUED))).with_for_update()).all()
    for scan in scans:
        queued = scan.state is ScanState.QUEUED
        scan.state = ScanState.CANCELLED
        if not queued:
            release_scan_credits(session, scan)
        for grant in session.scalars(select(ScanGrant).where(
            ScanGrant.scan_id == scan.id, ScanGrant.revoked_at.is_(None))).all():
            grant.revoked_at = now
        append_visible_event(session, scan.id, organization_id, "warning",
                             "Assessment authorization was revoked")
    session.add(AuditEvent(organization_id=organization_id, actor_id=actor_id,
                           action="organization.authorization_revoked",
                           payload={"authorization_id": record.id, "cancelled_scans": len(scans)}))

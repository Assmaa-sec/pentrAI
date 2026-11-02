"""Authorized scan creation with immutable source and execution routing."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .events import append_visible_event
from .models import (
    AuditEvent, IdempotencyRecord, Membership, OutboxEvent,
    Project, Scan, ScanState, SourceArtifact, WebTargetProof,
)
from .web_targets import normalize_target_url, WebTargetRejected, _aware
from .organization_authorization import active_authorization, OrganizationAuthorizationRejected
from .credits import CreditRejected, reserve_scan_credits
from .model_catalog import model_options


class CreateScanRejected(ValueError):
    pass


def create_scan(
    session: Session,
    organization_id: str,
    project_id: str,
    actor_id: str,
    source_artifact_id: str | None,
    *,
    scope_note: str,
    profile: str,
    authorized: bool,
    idempotency_key: str,
    target_url: str | None = None,
    web_target_proof_id: str | None = None,
    execution_backend: str = "hexstrike",
    model_id: str = "managed",
) -> Scan:
    if execution_backend not in {"hexstrike", "hexstrike_local", "local_static"}:
        raise CreateScanRejected("unknown scan execution backend")
    if target_url and execution_backend != "hexstrike":
        raise CreateScanRejected("website scans require native HexStrike execution")
    if (execution_backend == "local_static" and not authorized) or not scope_note.strip() or len(scope_note) > 2000:
        raise CreateScanRejected("assessment authorization and bounded scope are required")
    if profile not in {"quick", "standard", "deep"}:
        raise CreateScanRejected("unknown scan profile")
    option = model_options().get(model_id) if execution_backend != "local_static" else None
    if execution_backend != "local_static" and option is None:
        raise CreateScanRejected("unknown model option")
    if not idempotency_key or len(idempotency_key) > 200:
        raise CreateScanRejected("bounded idempotency key required")
    membership = session.scalar(
        select(Membership).where(
            Membership.organization_id == organization_id,
            Membership.user_id == actor_id,
        )
    )
    project = session.scalar(select(Project).where(Project.id == project_id, Project.organization_id == organization_id))
    artifact = session.scalar(select(SourceArtifact).where(
        SourceArtifact.id == source_artifact_id,
        SourceArtifact.organization_id == organization_id,
        SourceArtifact.project_id == project_id,
    )) if source_artifact_id else None
    if membership is None or membership.role not in {"owner", "security_engineer"} or project is None:
        raise CreateScanRejected("project or authorized member not found")
    if source_artifact_id and artifact is None:
        raise CreateScanRejected("source artifact not found")
    if not artifact and not target_url:
        raise CreateScanRejected("source artifact or verified web target required")
    normalized_url = None
    if target_url:
        try:
            normalized_url, origin = normalize_target_url(target_url)
        except WebTargetRejected as exc:
            raise CreateScanRejected(str(exc)) from exc
        proof = session.scalar(select(WebTargetProof).where(
            WebTargetProof.id == web_target_proof_id,
            WebTargetProof.organization_id == organization_id,
            WebTargetProof.project_id == project_id,
            WebTargetProof.origin == origin,
        )) if web_target_proof_id else None
        now = datetime.now(timezone.utc)
        if (proof is None or proof.verified_at is None or proof.verified_until is None
                or now >= _aware(proof.verified_until)):
            raise CreateScanRejected("current web target proof required")
    elif web_target_proof_id:
        raise CreateScanRejected("web target proof requires a URL")
    prior = session.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.organization_id == organization_id,
            IdempotencyRecord.key == idempotency_key,
        )
    )
    scope_material = scope_note if normalized_url is None else f"{scope_note}\0{normalized_url}\0{web_target_proof_id}"
    scope_digest = hashlib.sha256(scope_material.encode("utf-8")).hexdigest()
    if prior is not None:
        scan = session.get(Scan, prior.scan_id)
        if (
            scan is None
            or scan.project_id != project_id
            or scan.source_artifact_id != source_artifact_id
            or scan.target_url != normalized_url
            or scan.web_target_proof_id != web_target_proof_id
            or scan.scope_digest != scope_digest
            or scan.profile != profile
            or scan.model_id != model_id
            or scan.execution_backend != execution_backend
        ):
            raise CreateScanRejected("idempotency key reused for another scan")
        return scan
    authorization = None
    if execution_backend != "local_static":
        try:
            authorization = active_authorization(session, organization_id,
                                                 source=artifact is not None,
                                                 url=bool(normalized_url))
        except OrganizationAuthorizationRejected as exc:
            raise CreateScanRejected(str(exc)) from exc
    scan = Scan(
        organization_id=organization_id,
        project_id=project_id,
        authorization_id=authorization.id if authorization else None,
        source_artifact_id=source_artifact_id,
        source_digest=artifact.sha256 if artifact else hashlib.sha256(b"").hexdigest(),
        target_url=normalized_url,
        web_target_proof_id=web_target_proof_id,
        scope_digest=scope_digest,
        scope_note=scope_note.strip(),
        profile=profile,
        model_id=model_id,
        prompt_credit_rate=option.prompt_credit_rate if option else 1,
        completion_credit_rate=option.completion_credit_rate if option else 1,
        dynamic_authorized=bool(normalized_url),
        execution_backend=execution_backend,
        state=ScanState.AUTHORIZED,
    )
    session.add(scan)
    session.flush()
    if execution_backend != "local_static":
        try:
            reserve_scan_credits(session, scan)
        except CreditRejected as exc:
            raise CreateScanRejected(str(exc)) from exc
    audit = AuditEvent(
        organization_id=organization_id,
        scan_id=scan.id,
        actor_id=actor_id,
        action="scan.create",
        payload={"source_artifact_id": source_artifact_id, "target_url": normalized_url,
                 "web_target_proof_id": web_target_proof_id, "scope_digest": scope_digest,
                 "profile": profile, "execution_backend": execution_backend,
                 "model_id": model_id,
                 "organization_authorization_id": authorization.id if authorization else None},
    )
    session.add(audit)
    session.flush()
    session.add_all(
        [
            IdempotencyRecord(
                organization_id=organization_id,
                scan_id=scan.id,
                key=idempotency_key,
                target_state=ScanState.AUTHORIZED,
                audit_event_id=audit.id,
            ),
            OutboxEvent(
                organization_id=organization_id,
                scan_id=scan.id,
                kind="scan.create.hexstrike" if execution_backend == "hexstrike" else "scan.create",
                payload={"scan_id": scan.id, "artifact_id": artifact.id if artifact else None,
                         "target_url": normalized_url},
            ),
        ]
    )
    append_visible_event(session, scan.id, organization_id, "status", "Assessment accepted")
    session.flush()
    return scan

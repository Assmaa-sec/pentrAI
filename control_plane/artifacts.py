"""Tenant-scoped upload grants and verified immutable source metadata."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Iterable, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (
    AuditEvent, Membership, OutboxEvent, Project, SourceArtifact,
    UploadGrantRecord, new_uuid, utcnow,
)


class UploadRejected(ValueError):
    pass


class ObjectStore(Protocol):
    def read_chunks(self, key: str) -> Iterable[bytes]: ...


def _require_uploader(session: Session, organization_id: str, project_id: str, actor_id: str) -> None:
    membership = session.scalar(
        select(Membership).where(
            Membership.organization_id == organization_id,
            Membership.user_id == actor_id,
        )
    )
    project = session.scalar(select(Project).where(Project.id == project_id, Project.organization_id == organization_id))
    if membership is None or membership.role not in {"owner", "security_engineer", "developer"} or project is None:
        raise UploadRejected("project not found or upload not authorized")


def create_upload_grant(
    session: Session,
    organization_id: str,
    project_id: str,
    actor_id: str,
    *,
    content_type: str,
    declared_bytes: int,
    idempotency_key: str,
) -> UploadGrantRecord:
    _require_uploader(session, organization_id, project_id, actor_id)
    if content_type != "application/zip" or not 1 <= declared_bytes <= 50 * 1024 * 1024:
        raise UploadRejected("only size-limited ZIP uploads are accepted")
    if not idempotency_key or len(idempotency_key) > 200:
        raise UploadRejected("bounded idempotency key required")
    prior = session.scalar(
        select(UploadGrantRecord).where(
            UploadGrantRecord.organization_id == organization_id,
            UploadGrantRecord.idempotency_key == idempotency_key,
        )
    )
    if prior is not None:
        if prior.project_id != project_id or prior.created_by != actor_id or prior.declared_bytes != declared_bytes:
            raise UploadRejected("idempotency key reused for another upload")
        return prior
    grant_id = new_uuid()
    key = f"organizations/{organization_id}/projects/{project_id}/uploads/{grant_id}.zip"
    grant = UploadGrantRecord(
        id=grant_id,
        organization_id=organization_id,
        project_id=project_id,
        created_by=actor_id,
        object_key=key,
        content_type=content_type,
        declared_bytes=declared_bytes,
        idempotency_key=idempotency_key,
        expires_at=utcnow() + timedelta(minutes=15),
    )
    session.add(grant)
    session.add_all(
        [
            AuditEvent(
                organization_id=organization_id,
                scan_id=None,
                actor_id=actor_id,
                action="upload.grant",
                payload={"grant_id": grant_id, "project_id": project_id},
            ),
            OutboxEvent(
                organization_id=organization_id,
                scan_id=None,
                kind="upload.grant",
                payload={"grant_id": grant_id},
            ),
        ]
    )
    session.flush()
    return grant


def finalize_upload(
    session: Session,
    grant_id: str,
    organization_id: str,
    actor_id: str,
    store: ObjectStore,
    claimed_sha256: str,
    object_key: str,
) -> SourceArtifact:
    grant = session.scalar(
        select(UploadGrantRecord)
        .where(UploadGrantRecord.id == grant_id, UploadGrantRecord.organization_id == organization_id)
        .with_for_update()
    )
    if grant is None:
        raise UploadRejected("upload grant not found")
    _require_uploader(session, organization_id, grant.project_id, actor_id)
    if grant.created_by != actor_id:
        raise UploadRejected("upload grant belongs to another actor")
    if object_key != grant.object_key:
        raise UploadRejected("object key does not match upload grant")
    prior = session.scalar(select(SourceArtifact).where(SourceArtifact.upload_grant_id == grant_id))
    if prior is not None:
        if prior.sha256 != claimed_sha256:
            raise UploadRejected("digest differs from finalized artifact")
        return prior
    expiry = grant.expires_at.replace(tzinfo=timezone.utc) if grant.expires_at.tzinfo is None else grant.expires_at
    if datetime.now(timezone.utc) >= expiry:
        raise UploadRejected("upload grant expired")
    digest = hashlib.sha256()
    size = 0
    try:
        for chunk in store.read_chunks(grant.object_key):
            if not isinstance(chunk, bytes):
                raise UploadRejected("object store returned invalid bytes")
            size += len(chunk)
            if size > grant.declared_bytes or size > 50 * 1024 * 1024:
                raise UploadRejected("uploaded object exceeds declared size")
            digest.update(chunk)
    except (KeyError, FileNotFoundError) as exc:
        raise UploadRejected("uploaded object not found") from exc
    if size != grant.declared_bytes:
        raise UploadRejected("uploaded object size does not match grant")
    if digest.hexdigest() != claimed_sha256:
        raise UploadRejected("uploaded object digest mismatch")
    artifact = SourceArtifact(
        organization_id=organization_id,
        project_id=grant.project_id,
        upload_grant_id=grant.id,
        object_key=grant.object_key,
        sha256=digest.hexdigest(),
        size_bytes=size,
        content_type=grant.content_type,
    )
    grant.finalized_at = utcnow()
    session.add(artifact)
    session.flush()
    session.add_all(
        [
            AuditEvent(
                organization_id=organization_id,
                scan_id=None,
                actor_id=actor_id,
                action="upload.finalize",
                payload={"artifact_id": artifact.id, "grant_id": grant.id},
            ),
            OutboxEvent(
                organization_id=organization_id,
                scan_id=None,
                kind="upload.finalize",
                payload={"artifact_id": artifact.id},
            ),
        ]
    )
    session.flush()
    return artifact

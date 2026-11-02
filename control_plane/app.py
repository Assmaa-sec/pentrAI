"""FastAPI control-plane entry point; no source execution occurs here."""

from __future__ import annotations

import json
import time
import hashlib
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session

from .auth import CurrentActor, OIDCVerifier, current_actor, mint_local_token
from .artifacts import UploadRejected, _require_uploader, create_upload_grant, finalize_upload
from .db import get_session
from .local_store import LocalObjectStore
from .models import AuditEvent, IdempotencyRecord, Membership, Organization, OrganizationCreditAccount, OutboxEvent, Project, ProjectCreateRecord, Scan, ScanCreditReservation, ScanEvent, ScanFinding, ScanGrant, ScanReport, ScanState, UploadGrantRecord, User, WebTargetProof, utcnow
from .scan_creation import CreateScanRejected, create_scan
from .report_exports import render_docx, render_pdf
from .runner_results import RunnerResultRejected, accept_runner_result
from .runner_readiness import runner_available
from .local_hexstrike_readiness import local_worker_available
from .settings import Settings
from .organization_authorization import (OrganizationAuthorizationRejected,
                                         active_authorization, approve_authorization,
                                         revoke_authorization)
from .credits import CreditRejected, release_scan_credits, reserve_scan_credits
from .model_catalog import model_options
from .source_broker import SourceBrokerRejected, authorize_source_download
from .web_targets import WebTargetRejected, start_web_proof, verify_web_proof, _aware


class CreateScanRequest(BaseModel):
    source_artifact_id: str | None = None
    target_url: str | None = Field(default=None, max_length=2048)
    web_target_proof_id: str | None = None
    scope_note: str = Field(min_length=1, max_length=2000)
    profile: str
    model_id: str = "managed"
    authorized: bool = False


class StartWebProofRequest(BaseModel):
    target_url: str = Field(min_length=1, max_length=2048)


class CreateUploadRequest(BaseModel):
    content_type: str
    declared_bytes: int


class FinalizeUploadRequest(BaseModel):
    sha256: str = Field(min_length=64, max_length=64)


class ScanQuestionRequest(BaseModel):
    question: str = Field(min_length=1, max_length=500)


class CreateProjectRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class MemberRoleRequest(BaseModel):
    role: str


class OrganizationAuthorizationRequest(BaseModel):
    scope_statement: str = Field(min_length=20, max_length=2000)
    source_allowed: bool
    url_allowed: bool
    valid_days: int = Field(ge=1, le=365)
    accept_terms: bool


def create_app(settings: Settings) -> FastAPI:
    app = FastAPI(title="PentrAI Control Plane", version="0.1.0", docs_url=None, redoc_url=None)
    app.state.settings = settings
    app.state.engine = create_engine(settings.database_url, pool_pre_ping=True)
    app.state.oidc_verifier = (
        OIDCVerifier(settings.oidc_issuer, settings.oidc_audience, settings.oidc_jwks_url)
        if settings.oidc_issuer and settings.oidc_audience and settings.oidc_jwks_url
        else None
    )
    app.state.local_store = LocalObjectStore(settings.local_artifact_root) if settings.local_artifact_root else None

    def require_local_store() -> LocalObjectStore:
        store = app.state.local_store
        if store is None:
            raise HTTPException(status_code=503, detail="local artifact storage is not configured")
        return store

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/capabilities")
    def capabilities(session: Session = Depends(get_session)) -> dict[str, bool | str]:
        native_source = settings.native_runner_ready and runner_available(session)
        native_url = (settings.dynamic_scans_enabled and settings.native_runner_ready
                      and runner_available(session, url=True))
        return {"source_scans_available": native_source or settings.local_static_enabled or
                (settings.local_hexstrike_enabled and local_worker_available(session)),
                "web_scans_available": native_url,
                "source_mode": "hexstrike" if native_source or settings.local_hexstrike_enabled else "local_static"}

    @app.post("/internal/runner-results")
    async def runner_results(request: Request, session: Session = Depends(get_session)) -> dict[str, str]:
        """Receive a bounded, grant-authenticated result from an isolated runner."""
        authorization = request.headers.get("authorization", "")
        if not authorization.startswith("Bearer ") or len(authorization) > 4200:
            raise HTTPException(status_code=403, detail="runner result rejected")
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 1024 * 1024:
                raise HTTPException(status_code=413, detail="runner result exceeds size limit")
        try:
            payload = json.loads(body)
            report = accept_runner_result(
                session, payload, authorization[7:],
                settings.grant_signing_key.get_secret_value().encode("utf-8"),
                release_dynamic_enabled=settings.dynamic_scans_enabled,
            )
        except (ValueError, TypeError):
            raise HTTPException(status_code=403, detail="runner result rejected") from None
        session.commit()
        return {"report_id": report.id, "sha256": report.sha256}

    @app.get("/internal/artifacts/{artifact_id}")
    def runner_source_artifact(
        artifact_id: str, authorization: str = Header(default=""),
        session: Session = Depends(get_session),
    ) -> StreamingResponse:
        """Broker a finalized ZIP to a separately isolated staging job."""
        if not authorization.startswith("Bearer ") or len(authorization) > 4200:
            raise HTTPException(status_code=403, detail="source download rejected")
        try:
            artifact = authorize_source_download(
                session, artifact_id, authorization[7:],
                settings.grant_signing_key.get_secret_value().encode("utf-8"),
            )
        except SourceBrokerRejected:
            raise HTTPException(status_code=403, detail="source download rejected") from None
        store = require_local_store()
        return StreamingResponse(
            store.read_chunks(artifact.object_key), media_type="application/zip",
            headers={"Cache-Control": "no-store", "Content-Length": str(artifact.size_bytes)},
        )

    @app.post("/v1/local/session")
    def local_session(request: Request, response: Response,
                      session: Session = Depends(get_session)) -> dict[str, str]:
        """Make the explicitly enabled, loopback-only development workspace usable."""
        if not settings.local_dev_auth or request.client is None or request.client.host not in {"127.0.0.1", "::1", "testclient"}:
            raise HTTPException(status_code=404, detail="not found")
        origin = request.headers.get("origin")
        if origin and origin not in {"http://127.0.0.1:5173", "http://localhost:5173"}:
            raise HTTPException(status_code=403, detail="origin not allowed")
        owner = session.scalar(select(User).where(User.oidc_subject == "urn:pentrai:local|local-owner"))
        if owner is None:
            raise HTTPException(status_code=404, detail="workspace not provisioned")
        membership = session.scalar(select(Membership).where(
            Membership.user_id == owner.id, Membership.role == "owner").order_by(Membership.id))
        if membership is None:
            raise HTTPException(status_code=404, detail="workspace not provisioned")
        token = mint_local_token("local-owner", settings.grant_signing_key.get_secret_value().encode(),
                                 int(time.time()) + 3600)
        response.headers["Cache-Control"] = "no-store"
        return {"organization_id": membership.organization_id, "token": token}

    def membership_for(session: Session, organization_id: str, actor: CurrentActor) -> Membership:
        membership = session.scalar(select(Membership).where(
            Membership.organization_id == organization_id, Membership.user_id == actor.user_id))
        if membership is None:
            raise HTTPException(status_code=404, detail="organization not found")
        return membership

    def owner_for(session: Session, organization_id: str, actor: CurrentActor) -> Membership:
        membership = membership_for(session, organization_id, actor)
        if membership.role != "owner":
            raise HTTPException(status_code=403, detail="owner role required")
        return membership

    @app.get("/v1/organizations/{organization_id}/assessment-authorization")
    def get_assessment_authorization(
        organization_id: str, actor: CurrentActor = Depends(current_actor),
        session: Session = Depends(get_session),
    ) -> dict[str, object]:
        membership_for(session, organization_id, actor)
        try:
            record = active_authorization(session, organization_id, source=False, url=False)
        except OrganizationAuthorizationRejected:
            return {"active": False}
        return {"active": True, "id": record.id, "scope_statement": record.scope_statement,
                "source_allowed": record.source_allowed, "url_allowed": record.url_allowed,
                "expires_at": record.expires_at.isoformat(), "terms_version": record.terms_version}

    @app.get("/v1/organizations/{organization_id}/credits")
    def get_credits(organization_id: str, actor: CurrentActor = Depends(current_actor),
                    session: Session = Depends(get_session)) -> dict[str, int]:
        membership_for(session, organization_id, actor)
        account = session.get(OrganizationCreditAccount, organization_id)
        return {"available": account.available if account else 0,
                "reserved": account.reserved if account else 0,
                "spent": account.spent if account else 0}

    @app.get("/v1/organizations/{organization_id}/models")
    def list_model_options(organization_id: str, actor: CurrentActor = Depends(current_actor),
                           session: Session = Depends(get_session)) -> list[dict[str, str | int]]:
        membership_for(session, organization_id, actor)
        return [option.public() for option in model_options().values()]

    @app.put("/v1/organizations/{organization_id}/assessment-authorization")
    def put_assessment_authorization(
        organization_id: str, body: OrganizationAuthorizationRequest,
        actor: CurrentActor = Depends(current_actor), session: Session = Depends(get_session),
    ) -> dict[str, object]:
        owner_for(session, organization_id, actor)
        try:
            record = approve_authorization(
                session, organization_id, actor.user_id,
                scope_statement=body.scope_statement,
                source_allowed=body.source_allowed, url_allowed=body.url_allowed,
                valid_days=body.valid_days, accept_terms=body.accept_terms)
            session.commit()
            return {"id": record.id, "expires_at": record.expires_at.isoformat()}
        except OrganizationAuthorizationRejected as exc:
            session.rollback()
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.delete("/v1/organizations/{organization_id}/assessment-authorization/{authorization_id}", status_code=204)
    def delete_assessment_authorization(
        organization_id: str, authorization_id: str,
        actor: CurrentActor = Depends(current_actor), session: Session = Depends(get_session),
    ) -> Response:
        owner_for(session, organization_id, actor)
        try:
            revoke_authorization(session, organization_id, actor.user_id, authorization_id)
            session.commit()
            return Response(status_code=204)
        except OrganizationAuthorizationRejected as exc:
            session.rollback()
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/v1/organizations/{organization_id}/access")
    def get_access(organization_id: str, actor: CurrentActor = Depends(current_actor),
                   session: Session = Depends(get_session)) -> dict[str, str]:
        membership = membership_for(session, organization_id, actor)
        return {"role": membership.role, "user_id": actor.user_id}

    @app.get("/v1/organizations/{organization_id}/members")
    def list_members(organization_id: str, actor: CurrentActor = Depends(current_actor),
                     session: Session = Depends(get_session)) -> list[dict[str, str]]:
        owner_for(session, organization_id, actor)
        rows = session.execute(select(Membership, User).join(User, Membership.user_id == User.id).where(
            Membership.organization_id == organization_id).order_by(User.oidc_subject)).all()
        return [{"id": membership.id, "user_id": user.id, "identity": user.oidc_subject,
                 "role": membership.role} for membership, user in rows]

    @app.get("/v1/organizations/{organization_id}/audit-events")
    def list_audit_events(organization_id: str, actor: CurrentActor = Depends(current_actor),
                          session: Session = Depends(get_session)) -> list[dict[str, str]]:
        owner_for(session, organization_id, actor)
        events = session.scalars(select(AuditEvent).where(
            AuditEvent.organization_id == organization_id,
        ).order_by(AuditEvent.created_at.desc()).limit(50)).all()
        return [{"id": event.id, "action": event.action,
                 "created_at": event.created_at.isoformat()} for event in events]

    @app.patch("/v1/organizations/{organization_id}/members/{member_id}")
    def update_member(organization_id: str, member_id: str, body: MemberRoleRequest,
                      actor: CurrentActor = Depends(current_actor),
                      session: Session = Depends(get_session)) -> dict[str, str]:
        owner_for(session, organization_id, actor)
        if body.role not in {"owner", "security_engineer", "developer"}:
            raise HTTPException(status_code=400, detail="unsupported role")
        session.scalar(select(Organization).where(Organization.id == organization_id).with_for_update())
        member = session.scalar(select(Membership).where(
            Membership.id == member_id, Membership.organization_id == organization_id))
        if member is None:
            raise HTTPException(status_code=404, detail="member not found")
        if member.role == "owner" and body.role != "owner":
            owner_count = session.scalar(select(func.count()).select_from(Membership).where(
                Membership.organization_id == organization_id, Membership.role == "owner"))
            if owner_count <= 1:
                raise HTTPException(status_code=409, detail="organization needs an owner")
        previous_role = member.role
        if previous_role != body.role:
            member.role = body.role
            session.add(AuditEvent(organization_id=organization_id, actor_id=actor.user_id,
                                   action="member.role_change", payload={"member_id": member_id,
                                   "previous_role": previous_role, "role": body.role}))
            session.commit()
        return {"id": member.id, "user_id": member.user_id, "role": member.role}

    @app.delete("/v1/organizations/{organization_id}/members/{member_id}", status_code=204)
    def remove_member(organization_id: str, member_id: str,
                      actor: CurrentActor = Depends(current_actor),
                      session: Session = Depends(get_session)) -> Response:
        owner_for(session, organization_id, actor)
        session.scalar(select(Organization).where(Organization.id == organization_id).with_for_update())
        member = session.scalar(select(Membership).where(
            Membership.id == member_id, Membership.organization_id == organization_id))
        if member is None:
            raise HTTPException(status_code=404, detail="member not found")
        if member.role == "owner":
            owner_count = session.scalar(select(func.count()).select_from(Membership).where(
                Membership.organization_id == organization_id, Membership.role == "owner"))
            if owner_count <= 1:
                raise HTTPException(status_code=409, detail="organization needs an owner")
        session.add(AuditEvent(organization_id=organization_id, actor_id=actor.user_id,
                               action="member.remove", payload={"member_id": member_id,
                               "user_id": member.user_id, "role": member.role}))
        session.delete(member)
        session.commit()
        return Response(status_code=204)

    @app.get("/v1/organizations/{organization_id}/projects/{project_id}")
    def get_project(
        organization_id: str,
        project_id: str,
        actor: CurrentActor = Depends(current_actor),
        session: Session = Depends(get_session),
    ) -> dict[str, str]:
        membership = session.scalar(
            select(Membership).where(
                Membership.organization_id == organization_id,
                Membership.user_id == actor.user_id,
            )
        )
        project = session.scalar(
            select(Project).where(Project.id == project_id, Project.organization_id == organization_id)
        )
        if membership is None or project is None:
            raise HTTPException(status_code=404, detail="project not found")
        return {"id": project.id, "organization_id": organization_id, "name": project.name}

    @app.get("/v1/organizations/{organization_id}/projects")
    def list_projects(organization_id: str, actor: CurrentActor = Depends(current_actor),
                      session: Session = Depends(get_session)) -> list[dict[str, str]]:
        membership = session.scalar(select(Membership).where(
            Membership.organization_id == organization_id, Membership.user_id == actor.user_id))
        if membership is None:
            raise HTTPException(status_code=404, detail="organization not found")
        projects = session.scalars(select(Project).where(Project.organization_id == organization_id).order_by(Project.name)).all()
        return [{"id": item.id, "name": item.name, "organization_id": organization_id} for item in projects]

    @app.get("/v1/organizations/{organization_id}/workspace-summary")
    def workspace_summary(organization_id: str, actor: CurrentActor = Depends(current_actor),
                          session: Session = Depends(get_session)) -> dict[str, int]:
        membership_for(session, organization_id, actor)
        return {
            "projects": session.scalar(select(func.count(Project.id)).where(Project.organization_id == organization_id)) or 0,
            "assessments": session.scalar(select(func.count(Scan.id)).where(Scan.organization_id == organization_id)) or 0,
            "completed": session.scalar(select(func.count(Scan.id)).where(
                Scan.organization_id == organization_id, Scan.state == ScanState.COMPLETED)) or 0,
            "findings": session.scalar(select(func.count(ScanFinding.id)).where(ScanFinding.organization_id == organization_id)) or 0,
        }

    @app.get("/v1/organizations/{organization_id}/scans")
    def organization_scans(organization_id: str, actor: CurrentActor = Depends(current_actor),
                           session: Session = Depends(get_session)) -> list[dict[str, str]]:
        membership_for(session, organization_id, actor)
        rows = session.execute(select(Scan, Project.name).join(Project, Scan.project_id == Project.id).where(
            Scan.organization_id == organization_id,
        ).order_by(Scan.created_at.desc()).limit(100)).all()
        return [{"id": scan.id, "project_id": scan.project_id, "project_name": project_name,
                 "state": scan.state.value, "profile": scan.profile,
                 "created_at": scan.created_at.isoformat()} for scan, project_name in rows]

    @app.get("/v1/organizations/{organization_id}/findings")
    def organization_findings(organization_id: str, actor: CurrentActor = Depends(current_actor),
                              session: Session = Depends(get_session)) -> list[dict[str, object]]:
        membership_for(session, organization_id, actor)
        rows = session.execute(select(ScanFinding, Scan.project_id, Project.name).join(
            Scan, ScanFinding.scan_id == Scan.id).join(Project, Scan.project_id == Project.id).where(
                ScanFinding.organization_id == organization_id,
        ).order_by(ScanFinding.created_at.desc()).limit(200)).all()
        return [{"id": finding.id, "scan_id": finding.scan_id, "project_id": project_id,
                 "project_name": project_name, "state": finding.state, "source": finding.source,
                 "dependency": finding.dependency, "advisory_id": finding.advisory_id,
                 "source_manifest": finding.source_manifest,
                 "title": finding.title, "severity": finding.severity,
                 "created_at": finding.created_at.isoformat()} for finding, project_id, project_name in rows]

    @app.post("/v1/organizations/{organization_id}/projects", status_code=201)
    def post_project(organization_id: str, body: CreateProjectRequest,
                     idempotency_key: str = Header(alias="Idempotency-Key"),
                     actor: CurrentActor = Depends(current_actor),
                     session: Session = Depends(get_session)) -> dict[str, str]:
        membership = session.scalar(select(Membership).where(
            Membership.organization_id == organization_id, Membership.user_id == actor.user_id))
        if membership is None or membership.role not in {"owner", "security_engineer"}:
            raise HTTPException(status_code=403, detail="project creation not authorized")
        name = body.name.strip()
        if not name or not idempotency_key or len(idempotency_key) > 200:
            raise HTTPException(status_code=400, detail="project name and bounded idempotency key required")
        session.scalar(select(Organization).where(Organization.id == organization_id).with_for_update())
        name_digest = hashlib.sha256(name.encode("utf-8")).hexdigest()
        prior = session.scalar(select(ProjectCreateRecord).where(
            ProjectCreateRecord.organization_id == organization_id,
            ProjectCreateRecord.key == idempotency_key,
        ))
        if prior is not None:
            project = session.get(Project, prior.project_id)
            if (project is None or prior.actor_id != actor.user_id
                    or prior.name_digest != name_digest):
                raise HTTPException(status_code=409, detail="idempotency key reused")
            return {"id": project.id, "name": project.name, "organization_id": organization_id}
        existing = session.scalar(select(Project).where(Project.organization_id == organization_id, Project.name == name))
        if existing is not None:
            raise HTTPException(status_code=409, detail="project name already exists")
        project = Project(organization_id=organization_id, name=name)
        session.add(project)
        session.flush()
        session.add(AuditEvent(organization_id=organization_id, actor_id=actor.user_id,
                               action="project.create", payload={"project_id": project.id}))
        session.add(ProjectCreateRecord(
            organization_id=organization_id, actor_id=actor.user_id,
            project_id=project.id, key=idempotency_key, name_digest=name_digest,
        ))
        session.add(OutboxEvent(
            organization_id=organization_id, kind="project.create",
            payload={"project_id": project.id},
        ))
        session.commit()
        return {"id": project.id, "name": project.name, "organization_id": organization_id}

    @app.get("/v1/organizations/{organization_id}/projects/{project_id}/scans")
    def list_scans(organization_id: str, project_id: str,
                   actor: CurrentActor = Depends(current_actor),
                   session: Session = Depends(get_session)) -> list[dict[str, str]]:
        membership = session.scalar(select(Membership).where(
            Membership.organization_id == organization_id, Membership.user_id == actor.user_id))
        project = session.scalar(select(Project).where(Project.id == project_id, Project.organization_id == organization_id))
        if membership is None or project is None:
            raise HTTPException(status_code=404, detail="project not found")
        scans = session.scalars(select(Scan).where(
            Scan.organization_id == organization_id, Scan.project_id == project_id,
        ).order_by(Scan.created_at.desc()).limit(100)).all()
        return [{"id": item.id, "state": item.state.value, "profile": item.profile,
                 "created_at": item.created_at.isoformat()} for item in scans]

    @app.post("/v1/organizations/{organization_id}/projects/{project_id}/uploads", status_code=201)
    def post_upload_grant(
        organization_id: str,
        project_id: str,
        body: CreateUploadRequest,
        idempotency_key: str = Header(alias="Idempotency-Key"),
        actor: CurrentActor = Depends(current_actor),
        session: Session = Depends(get_session),
    ) -> dict[str, str]:
        require_local_store()
        try:
            grant = create_upload_grant(
                session, organization_id, project_id, actor.user_id,
                content_type=body.content_type, declared_bytes=body.declared_bytes,
                idempotency_key=idempotency_key,
            )
            result = {"id": grant.id, "expires_at": grant.expires_at.isoformat()}
            session.commit()
            return result
        except UploadRejected as exc:
            session.rollback()
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.put("/v1/organizations/{organization_id}/uploads/{grant_id}", status_code=204)
    async def put_upload(
        organization_id: str,
        grant_id: str,
        request: Request,
        actor: CurrentActor = Depends(current_actor),
        session: Session = Depends(get_session),
    ) -> None:
        store = require_local_store()
        grant = session.scalar(
            select(UploadGrantRecord).where(
                UploadGrantRecord.id == grant_id,
                UploadGrantRecord.organization_id == organization_id,
            )
        )
        if grant is None:
            raise HTTPException(status_code=404, detail="upload grant not found")
        try:
            _require_uploader(session, organization_id, grant.project_id, actor.user_id)
        except UploadRejected as exc:
            raise HTTPException(status_code=404, detail="upload grant not found") from exc
        expiry = grant.expires_at.replace(tzinfo=timezone.utc) if grant.expires_at.tzinfo is None else grant.expires_at
        if grant.created_by != actor.user_id or grant.finalized_at is not None or datetime.now(timezone.utc) >= expiry:
            raise HTTPException(status_code=403, detail="upload grant is unavailable")
        if request.headers.get("content-type", "").split(";", 1)[0] != grant.content_type:
            raise HTTPException(status_code=415, detail="content type differs from grant")
        try:
            await store.write_stream(grant.object_key, request.stream(), grant.declared_bytes)
        except FileExistsError as exc:
            raise HTTPException(status_code=409, detail="upload already exists") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/v1/organizations/{organization_id}/uploads/{grant_id}/finalize", status_code=201)
    def post_finalize_upload(
        organization_id: str,
        grant_id: str,
        body: FinalizeUploadRequest,
        actor: CurrentActor = Depends(current_actor),
        session: Session = Depends(get_session),
    ) -> dict[str, str | int]:
        store = require_local_store()
        grant = session.scalar(
            select(UploadGrantRecord).where(
                UploadGrantRecord.id == grant_id,
                UploadGrantRecord.organization_id == organization_id,
            )
        )
        if grant is None:
            raise HTTPException(status_code=404, detail="upload grant not found")
        try:
            artifact = finalize_upload(
                session, grant_id, organization_id, actor.user_id, store,
                body.sha256, grant.object_key,
            )
            result = {"id": artifact.id, "sha256": artifact.sha256, "size_bytes": artifact.size_bytes}
            session.commit()
            return result
        except UploadRejected as exc:
            session.rollback()
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/v1/organizations/{organization_id}/projects/{project_id}/web-target-proofs", status_code=201)
    def post_web_target_proof(
        organization_id: str, project_id: str, request: StartWebProofRequest,
        actor: CurrentActor = Depends(current_actor), session: Session = Depends(get_session),
    ) -> dict[str, str]:
        if (not settings.dynamic_scans_enabled or not settings.native_runner_ready
                or not runner_available(session, url=True)):
            raise HTTPException(status_code=503, detail="website scanning is not available")
        try:
            proof, token = start_web_proof(session, organization_id, project_id,
                                           actor.user_id, request.target_url)
            result = {"id": proof.id, "origin": proof.origin, "token": token,
                      "verification_url": f"{proof.origin}/.well-known/pentrai-verification/{proof.id}",
                      "expires_at": proof.expires_at.isoformat()}
            session.commit()
            return result
        except WebTargetRejected as exc:
            session.rollback()
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/v1/organizations/{organization_id}/projects/{project_id}/web-target-proofs/{proof_id}/verify")
    def post_verify_web_target_proof(
        organization_id: str, project_id: str, proof_id: str,
        actor: CurrentActor = Depends(current_actor), session: Session = Depends(get_session),
    ) -> dict[str, str]:
        if (not settings.dynamic_scans_enabled or not settings.native_runner_ready
                or not runner_available(session, url=True)):
            raise HTTPException(status_code=503, detail="website scanning is not available")
        try:
            proof = verify_web_proof(session, organization_id, project_id, actor.user_id, proof_id)
            result = {"id": proof.id, "origin": proof.origin,
                      "verified_until": proof.verified_until.isoformat()}
            session.commit()
            return result
        except WebTargetRejected as exc:
            session.rollback()
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/v1/organizations/{organization_id}/projects/{project_id}/scans", status_code=201)
    def post_scan(
        organization_id: str,
        project_id: str,
        request: CreateScanRequest,
        idempotency_key: str = Header(alias="Idempotency-Key"),
        actor: CurrentActor = Depends(current_actor),
        session: Session = Depends(get_session),
    ) -> dict[str, str]:
        if request.target_url and (not settings.dynamic_scans_enabled
                                   or not settings.native_runner_ready
                                   or not runner_available(session, url=True)):
            raise HTTPException(status_code=503, detail="website scanning is not available")
        if (not settings.local_static_enabled
                and not (settings.local_hexstrike_enabled and local_worker_available(session))
                and (not settings.native_runner_ready or not runner_available(session))):
            raise HTTPException(status_code=503, detail="assessment execution is not available")
        execution_backend = ("local_static" if settings.local_static_enabled else
                             "hexstrike_local" if settings.local_hexstrike_enabled else "hexstrike")
        try:
            scan = create_scan(
                session, organization_id, project_id, actor.user_id,
                request.source_artifact_id,
                scope_note=request.scope_note, profile=request.profile,
                model_id=request.model_id,
                authorized=request.authorized, idempotency_key=idempotency_key,
                target_url=request.target_url, web_target_proof_id=request.web_target_proof_id,
                execution_backend=execution_backend,
            )
            result = {"id": scan.id, "organization_id": organization_id, "project_id": project_id, "state": scan.state.value}
            session.commit()
            return result
        except CreateScanRejected as exc:
            session.rollback()
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/v1/organizations/{organization_id}/scans/{scan_id}/events")
    def scan_events(
        organization_id: str,
        scan_id: str,
        follow: bool = True,
        last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
        actor: CurrentActor = Depends(current_actor),
        session: Session = Depends(get_session),
    ) -> StreamingResponse:
        membership = session.scalar(
            select(Membership).where(
                Membership.organization_id == organization_id,
                Membership.user_id == actor.user_id,
            )
        )
        scan = session.scalar(select(Scan).where(Scan.id == scan_id, Scan.organization_id == organization_id))
        if membership is None or scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        if last_event_id is not None and (not last_event_id.isdecimal() or len(last_event_id) > 18):
            raise HTTPException(status_code=400, detail="invalid Last-Event-ID")
        cursor = int(last_event_id) if last_event_id else 0

        def stream():
            nonlocal cursor
            last_heartbeat = time.monotonic()
            while True:
                events = session.scalars(
                    select(ScanEvent)
                    .where(
                        ScanEvent.organization_id == organization_id,
                        ScanEvent.scan_id == scan_id,
                        ScanEvent.sequence > cursor,
                    )
                    .order_by(ScanEvent.sequence)
                    .limit(100)
                ).all()
                for event in events:
                    cursor = event.sequence
                    payload = {"kind": event.kind, "summary": event.summary, "sequence": event.sequence}
                    yield f"id: {event.sequence}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
                if not follow:
                    return
                if time.monotonic() - last_heartbeat >= 15:
                    yield ": heartbeat\n\n"
                    last_heartbeat = time.monotonic()
                time.sleep(1)

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    def require_scan_reader(session: Session, organization_id: str, scan_id: str, actor_id: str) -> Scan:
        membership = session.scalar(select(Membership).where(
            Membership.organization_id == organization_id, Membership.user_id == actor_id,
        ))
        scan = session.scalar(select(Scan).where(
            Scan.id == scan_id, Scan.organization_id == organization_id,
        ))
        if membership is None or scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return scan

    @app.get("/v1/organizations/{organization_id}/scans/{scan_id}")
    def get_scan(
        organization_id: str,
        scan_id: str,
        actor: CurrentActor = Depends(current_actor),
        session: Session = Depends(get_session),
    ) -> dict[str, str | bool | int | None]:
        scan = require_scan_reader(session, organization_id, scan_id, actor.user_id)
        reservation = session.get(ScanCreditReservation, scan.id)
        return {
            "id": scan.id, "organization_id": scan.organization_id,
            "project_id": scan.project_id, "profile": scan.profile,
            "model_id": scan.model_id,
            "reserved_credits": reservation.reserved_credits if reservation else 0,
            "charged_credits": (reservation.charged_credits if reservation and
                                (reservation.settled_at or reservation.released_at) else
                                reservation.metered_credits if reservation else 0),
            "state": scan.state.value, "dynamic_authorized": scan.dynamic_authorized,
            "scope_note": scan.scope_note,
            "target_url": scan.target_url,
        }

    @app.post("/v1/organizations/{organization_id}/scans/{scan_id}/cancel")
    def cancel_scan(organization_id: str, scan_id: str,
                    idempotency_key: str = Header(alias="Idempotency-Key"),
                    actor: CurrentActor = Depends(current_actor),
                    session: Session = Depends(get_session)) -> dict[str, str]:
        require_scan_reader(session, organization_id, scan_id, actor.user_id)
        scan = session.scalar(select(Scan).where(
            Scan.id == scan_id, Scan.organization_id == organization_id).with_for_update())
        membership = session.scalar(select(Membership).where(
            Membership.organization_id == organization_id, Membership.user_id == actor.user_id))
        if membership.role not in {"owner", "security_engineer"}:
            raise HTTPException(status_code=403, detail="scan cancellation not authorized")
        if not idempotency_key or len(idempotency_key) > 200:
            raise HTTPException(status_code=400, detail="bounded idempotency key required")
        prior = session.scalar(select(IdempotencyRecord).where(
            IdempotencyRecord.organization_id == organization_id,
            IdempotencyRecord.key == idempotency_key,
        ))
        if prior is not None:
            audit = session.get(AuditEvent, prior.audit_event_id)
            if (prior.scan_id != scan_id or prior.target_state is not ScanState.CANCELLED
                    or audit is None or audit.action != "scan.cancel"):
                raise HTTPException(status_code=409, detail="idempotency key reused")
            return {"id": scan.id, "state": scan.state.value}
        if scan.state is ScanState.CANCELLED:
            return {"id": scan.id, "state": scan.state.value}
        if scan.state not in {ScanState.AUTHORIZED, ScanState.QUEUED}:
            raise HTTPException(status_code=409, detail="scan cannot be cancelled at this stage")
        queued = scan.state is ScanState.QUEUED
        scan.state = ScanState.CANCELLED
        if not queued:
            release_scan_credits(session, scan)
        for grant in session.scalars(select(ScanGrant).where(
            ScanGrant.organization_id == organization_id, ScanGrant.scan_id == scan_id,
            ScanGrant.revoked_at.is_(None))).all():
            grant.revoked_at = utcnow()
        audit = AuditEvent(organization_id=organization_id, scan_id=scan_id,
                           actor_id=actor.user_id, action="scan.cancel", payload={})
        session.add(audit)
        session.flush()
        session.add(IdempotencyRecord(
            organization_id=organization_id, scan_id=scan_id, key=idempotency_key,
            target_state=ScanState.CANCELLED, audit_event_id=audit.id,
        ))
        session.add(OutboxEvent(organization_id=organization_id, scan_id=scan_id,
                                kind="scan.cancel", payload={"scan_id": scan_id}))
        from .events import append_visible_event
        append_visible_event(session, scan_id, organization_id, "status", "Assessment cancelled")
        session.commit()
        return {"id": scan.id, "state": scan.state.value}

    @app.post("/v1/organizations/{organization_id}/scans/{scan_id}/retry", status_code=201)
    def retry_scan(organization_id: str, scan_id: str,
                   idempotency_key: str = Header(alias="Idempotency-Key"),
                   actor: CurrentActor = Depends(current_actor),
                   session: Session = Depends(get_session)) -> dict[str, str]:
        original = require_scan_reader(session, organization_id, scan_id, actor.user_id)
        membership = session.scalar(select(Membership).where(
            Membership.organization_id == organization_id, Membership.user_id == actor.user_id))
        if membership.role not in {"owner", "security_engineer"}:
            raise HTTPException(status_code=403, detail="scan retry not authorized")
        if not idempotency_key or len(idempotency_key) > 200:
            raise HTTPException(status_code=400, detail="bounded idempotency key required")
        prior = session.scalar(select(IdempotencyRecord).where(
            IdempotencyRecord.organization_id == organization_id, IdempotencyRecord.key == idempotency_key))
        if prior is not None:
            new_scan = session.get(Scan, prior.scan_id)
            audit = session.get(AuditEvent, prior.audit_event_id)
            if (new_scan is None or audit is None or audit.action != "scan.retry"
                    or audit.payload.get("previous_scan_id") != scan_id):
                raise HTTPException(status_code=409, detail="idempotency key reused")
            return {"id": new_scan.id, "state": new_scan.state.value}
        if original.state not in {ScanState.FAILED, ScanState.CANCELLED}:
            raise HTTPException(status_code=409, detail="only failed or cancelled scans can be retried")
        if ((original.execution_backend == "hexstrike"
             and (not settings.native_runner_ready or not runner_available(session,
                                                        url=bool(original.target_url))))
                or (original.execution_backend == "local_static" and not settings.local_static_enabled)
                or (original.execution_backend == "hexstrike_local"
                    and (not settings.local_hexstrike_enabled or not local_worker_available(session)))
                or (original.target_url and not settings.dynamic_scans_enabled)):
            raise HTTPException(status_code=503, detail="assessment execution is not available")
        if original.target_url:
            proof = session.get(WebTargetProof, original.web_target_proof_id)
            if (proof is None or proof.organization_id != organization_id
                    or proof.project_id != original.project_id or proof.verified_until is None
                    or utcnow() >= _aware(proof.verified_until)):
                raise HTTPException(status_code=409, detail="web target proof expired; verify the site again")
        if original.execution_backend != "local_static":
            try:
                authority = active_authorization(session, organization_id,
                                                 source=bool(original.source_artifact_id),
                                                 url=bool(original.target_url))
            except OrganizationAuthorizationRejected as exc:
                raise HTTPException(status_code=403, detail=str(exc)) from exc
        else:
            authority = None
        new_scan = Scan(organization_id=organization_id, project_id=original.project_id,
                        authorization_id=authority.id if authority else None,
                        source_artifact_id=original.source_artifact_id, source_digest=original.source_digest,
                        target_url=original.target_url, web_target_proof_id=original.web_target_proof_id,
                        scope_digest=original.scope_digest, scope_note=original.scope_note, profile=original.profile,
                        model_id=original.model_id,
                        prompt_credit_rate=original.prompt_credit_rate,
                        completion_credit_rate=original.completion_credit_rate,
                        dynamic_authorized=original.dynamic_authorized,
                        execution_backend=original.execution_backend, state=ScanState.AUTHORIZED)
        session.add(new_scan)
        session.flush()
        if original.execution_backend != "local_static":
            try:
                reserve_scan_credits(session, new_scan)
            except CreditRejected as exc:
                session.rollback()
                raise HTTPException(status_code=402, detail=str(exc)) from exc
        audit = AuditEvent(organization_id=organization_id, scan_id=new_scan.id, actor_id=actor.user_id,
                           action="scan.retry", payload={"previous_scan_id": scan_id})
        session.add(audit)
        session.flush()
        session.add(IdempotencyRecord(organization_id=organization_id, scan_id=new_scan.id,
                                      key=idempotency_key, target_state=ScanState.AUTHORIZED,
                                      audit_event_id=audit.id))
        session.add(OutboxEvent(organization_id=organization_id, scan_id=new_scan.id,
                                kind="scan.retry.hexstrike" if original.execution_backend == "hexstrike" else "scan.retry",
                                payload={"previous_scan_id": scan_id}))
        from .events import append_visible_event
        append_visible_event(session, new_scan.id, organization_id, "status", "Assessment retry accepted")
        session.commit()
        return {"id": new_scan.id, "state": new_scan.state.value}

    @app.get("/v1/organizations/{organization_id}/scans/{scan_id}/findings")
    def get_findings(
        organization_id: str,
        scan_id: str,
        actor: CurrentActor = Depends(current_actor),
        session: Session = Depends(get_session),
    ) -> list[dict[str, object]]:
        require_scan_reader(session, organization_id, scan_id, actor.user_id)
        findings = session.scalars(select(ScanFinding).where(
            ScanFinding.organization_id == organization_id,
            ScanFinding.scan_id == scan_id,
        ).order_by(ScanFinding.advisory_id, ScanFinding.dependency)).all()
        return [{
            "id": finding.id, "state": finding.state, "source": finding.source,
            "dependency": finding.dependency, "advisory_id": finding.advisory_id,
            "source_manifest": finding.source_manifest,
            "scanner_version": finding.scanner_version,
            "database_version": finding.database_version,
            "scanner_output_sha256": finding.scanner_output_sha256,
            "title": finding.title, "severity": finding.severity,
            "explanation": finding.explanation,
            "evidence_sha256": finding.evidence_sha256 or [],
        } for finding in findings]

    @app.get("/v1/organizations/{organization_id}/scans/{scan_id}/report")
    def get_report(
        organization_id: str,
        scan_id: str,
        actor: CurrentActor = Depends(current_actor),
        session: Session = Depends(get_session),
    ) -> dict[str, str]:
        require_scan_reader(session, organization_id, scan_id, actor.user_id)
        report = session.scalar(select(ScanReport).where(
            ScanReport.organization_id == organization_id, ScanReport.scan_id == scan_id,
        ))
        if report is None:
            raise HTTPException(status_code=404, detail="report not found")
        return {"id": report.id, "sha256": report.sha256, "markdown": report.markdown}

    @app.get("/v1/organizations/{organization_id}/scans/{scan_id}/report.{format}")
    def download_report(organization_id: str, scan_id: str, format: str,
                        actor: CurrentActor = Depends(current_actor),
                        session: Session = Depends(get_session)) -> Response:
        require_scan_reader(session, organization_id, scan_id, actor.user_id)
        report = session.scalar(select(ScanReport).where(
            ScanReport.organization_id == organization_id, ScanReport.scan_id == scan_id))
        if report is None:
            raise HTTPException(status_code=404, detail="report not found")
        if format == "pdf":
            payload = render_pdf(report.markdown)
            media_type = "application/pdf"
        elif format == "docx":
            payload = render_docx(report.markdown)
            media_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        elif format == "md":
            payload = report.markdown.encode("utf-8")
            media_type = "text/markdown; charset=utf-8"
        else:
            raise HTTPException(status_code=404, detail="report format not found")
        return Response(payload, media_type=media_type, headers={
            "Content-Disposition": f'attachment; filename="pentrai-{scan_id}.{format}"',
            "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
        })

    @app.post("/v1/organizations/{organization_id}/scans/{scan_id}/questions")
    def post_scan_question(
        organization_id: str,
        scan_id: str,
        body: ScanQuestionRequest,
        actor: CurrentActor = Depends(current_actor),
        session: Session = Depends(get_session),
    ) -> dict[str, str | int]:
        scan = require_scan_reader(session, organization_id, scan_id, actor.user_id)
        count = session.scalar(select(func.count(ScanFinding.id)).where(
            ScanFinding.organization_id == organization_id, ScanFinding.scan_id == scan_id,
        )) or 0
        report = session.scalar(select(ScanReport).where(
            ScanReport.organization_id == organization_id, ScanReport.scan_id == scan_id,
        ))
        question = body.question.casefold()
        if any(term in question for term in ("status", "progress", "complete", "state")):
            answer = f"The assessment is {scan.state.value}."
        elif any(term in question for term in ("finding", "vulnerab", "issue", "cve")):
            answer = f"The assessment has {count} detected findings. These have not been validated against a running application."
        elif any(term in question for term in ("coverage", "report", "scope")):
            answer = (
                "The assessment report is available and states the supported manifest coverage and limitations."
                if report else "The assessment report is not available yet."
            )
        else:
            answer = "I can answer questions about assessment status, detected finding count, and report availability."
        session.add(AuditEvent(
            organization_id=organization_id, scan_id=scan_id,
            actor_id=actor.user_id, action="scan.question",
            payload={"question_sha256": hashlib.sha256(body.question.encode("utf-8")).hexdigest()},
        ))
        session.commit()
        return {"answer": answer, "finding_count": count}

    return app

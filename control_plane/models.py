"""Organization-scoped control-plane records.

PostgreSQL is the production database. SQLite is used only for focused unit tests.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class ScanState(str, enum.Enum):
    DRAFT = "draft"
    UPLOADED = "uploaded"
    AUTHORIZED = "authorized"
    QUEUED = "queued"
    INTAKE = "intake"
    STATIC = "static"
    DYNAMIC_ELIGIBLE = "dynamic_eligible"
    VALIDATING = "validating"
    REPORTING = "reporting"
    CLEANUP = "cleanup"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    oidc_subject: Mapped[str] = mapped_column(String(500), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("organization_id", "user_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    role: Mapped[str] = mapped_column(String(40), nullable=False)


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class ProjectCreateRecord(Base):
    __tablename__ = "project_create_records"
    __table_args__ = (UniqueConstraint("organization_id", "key"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    key: Mapped[str] = mapped_column(String(200), nullable=False)
    name_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class OrganizationAssessmentAuthorization(Base):
    __tablename__ = "organization_assessment_authorizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True)
    approved_by: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    scope_statement: Mapped[str] = mapped_column(String(2000), nullable=False)
    terms_version: Mapped[str] = mapped_column(String(32), nullable=False)
    source_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    url_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class OrganizationCreditAccount(Base):
    __tablename__ = "organization_credit_accounts"

    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), primary_key=True)
    available: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reserved: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    spent: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class ScanCreditReservation(Base):
    __tablename__ = "scan_credit_reservations"

    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="RESTRICT"), primary_key=True)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True)
    reserved_credits: Mapped[int] = mapped_column(Integer, nullable=False)
    metered_credits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    charged_credits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    authorization_id: Mapped[str | None] = mapped_column(ForeignKey("organization_assessment_authorizations.id", ondelete="RESTRICT"), nullable=True)
    source_artifact_id: Mapped[str | None] = mapped_column(ForeignKey("source_artifacts.id", ondelete="RESTRICT"), nullable=True)
    target_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    web_target_proof_id: Mapped[str | None] = mapped_column(ForeignKey("web_target_proofs.id", ondelete="RESTRICT"), nullable=True)
    source_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    scope_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    scope_note: Mapped[str] = mapped_column(String(2000), default="", nullable=False)
    profile: Mapped[str] = mapped_column(String(32), nullable=False)
    model_id: Mapped[str] = mapped_column(String(40), nullable=False, default="managed", server_default="managed")
    prompt_credit_rate: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")
    completion_credit_rate: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")
    dynamic_authorized: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    execution_backend: Mapped[str] = mapped_column(String(20), default="hexstrike",
                                                    server_default="hexstrike", nullable=False)
    state: Mapped[ScanState] = mapped_column(Enum(ScanState), default=ScanState.DRAFT, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class NativeRunnerWorker(Base):
    __tablename__ = "native_runner_workers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_ready: Mapped[bool] = mapped_column(Boolean, nullable=False)
    url_ready: Mapped[bool] = mapped_column(Boolean, nullable=False)


class LocalHexStrikeWorker(Base):
    __tablename__ = "local_hexstrike_workers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id", ondelete="RESTRICT"), nullable=True, index=True)
    actor_id: Mapped[str] = mapped_column(String(36), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class OutboxEvent(Base):
    __tablename__ = "outbox_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id", ondelete="RESTRICT"), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(100), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class IdempotencyRecord(Base):
    __tablename__ = "idempotency_records"
    __table_args__ = (UniqueConstraint("organization_id", "key"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="RESTRICT"), nullable=False)
    key: Mapped[str] = mapped_column(String(200), nullable=False)
    target_state: Mapped[ScanState] = mapped_column(Enum(ScanState), nullable=False)
    audit_event_id: Mapped[str] = mapped_column(ForeignKey("audit_events.id", ondelete="RESTRICT"), nullable=False)


class ScanGrant(Base):
    __tablename__ = "scan_grants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="RESTRICT"), nullable=False, index=True)
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    issued_at: Mapped[int | None] = mapped_column(Integer, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class RunnerLease(Base):
    __tablename__ = "runner_leases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="RESTRICT"), nullable=False, index=True)
    scan_grant_id: Mapped[str] = mapped_column(ForeignKey("scan_grants.id", ondelete="RESTRICT"), nullable=False)
    namespace: Mapped[str] = mapped_column(String(63), nullable=False, unique=True)
    service_account: Mapped[str] = mapped_column(String(63), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    dispatch_owner: Mapped[str | None] = mapped_column(String(36), nullable=True)
    dispatch_claim_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    dispatch_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    launched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cleaned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    artifact_grant_revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cleanup_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    cleanup_error: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class UploadGrantRecord(Base):
    __tablename__ = "upload_grants"
    __table_args__ = (UniqueConstraint("organization_id", "idempotency_key"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    object_key: Mapped[str] = mapped_column(String(500), nullable=False, unique=True)
    content_type: Mapped[str] = mapped_column(String(100), nullable=False)
    declared_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finalized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class SourceArtifact(Base):
    __tablename__ = "source_artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    upload_grant_id: Mapped[str] = mapped_column(ForeignKey("upload_grants.id", ondelete="RESTRICT"), nullable=False, unique=True)
    object_key: Mapped[str] = mapped_column(String(500), nullable=False, unique=True)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    content_type: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class WebTargetProof(Base):
    __tablename__ = "web_target_proofs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="RESTRICT"), nullable=False)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    origin: Mapped[str] = mapped_column(String(500), nullable=False)
    token_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class ScanEvent(Base):
    __tablename__ = "scan_events"
    __table_args__ = (UniqueConstraint("scan_id", "sequence"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="RESTRICT"), nullable=False, index=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    summary: Mapped[str] = mapped_column(String(500), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class ScanFinding(Base):
    __tablename__ = "scan_findings"
    __table_args__ = (UniqueConstraint("scan_id", "dependency", "advisory_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="RESTRICT"), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    dependency: Mapped[str] = mapped_column(String(500), nullable=False)
    advisory_id: Mapped[str] = mapped_column(String(200), nullable=False)
    source_manifest: Mapped[str] = mapped_column(String(500), nullable=False)
    scanner_version: Mapped[str] = mapped_column(String(100), nullable=False)
    database_version: Mapped[str] = mapped_column(String(100), nullable=False)
    scanner_output_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str | None] = mapped_column(String(200), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_sha256: Mapped[list | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class ScanReport(Base):
    __tablename__ = "scan_reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="RESTRICT"), nullable=False, unique=True)
    markdown: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

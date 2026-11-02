"""One-shot local static worker. Production dispatch and leases remain separate."""

from __future__ import annotations

import argparse
import os
import shutil
import time
import uuid
from datetime import timedelta, datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from static_worker.osv import OfflineOSVScanner
from static_worker.worker import DependencyScanner

from .events import append_visible_event
from .grants import issue_grant
from .local_static_run import run_local_static_scan
from .local_store import LocalObjectStore
from .models import AuditEvent, OutboxEvent, RunnerLease, Scan, ScanGrant, ScanState, utcnow
from .settings import Settings


def reap_stale_scans(engine, workspace_root: Path | None = None,
                     older_than: timedelta = timedelta(minutes=10)) -> int:
    """Fail abandoned queued scans so a user can retry with a fresh job."""
    cutoff = datetime.now(timezone.utc) - older_than
    with Session(engine) as session:
        scans = session.scalars(select(Scan).where(
            Scan.state == ScanState.QUEUED,
            Scan.execution_backend == "local_static",
            Scan.dynamic_authorized.is_(False),
            Scan.updated_at < cutoff,
            ~select(RunnerLease.id).where(
                RunnerLease.scan_id == Scan.id,
                RunnerLease.cleaned_at.is_(None),
            ).exists(),
        ).with_for_update(skip_locked=True)).all()
        for scan in scans:
            scan.state = ScanState.FAILED
            for grant in session.scalars(select(ScanGrant).where(
                ScanGrant.scan_id == scan.id, ScanGrant.organization_id == scan.organization_id,
                ScanGrant.revoked_at.is_(None))).all():
                grant.revoked_at = utcnow()
            session.add(AuditEvent(organization_id=scan.organization_id, scan_id=scan.id,
                                   actor_id="local-static-worker", action="scan.reaped",
                                   payload={"reason": "queued worker exceeded local deadline"}))
            append_visible_event(session, scan.id, scan.organization_id, "warning", "Assessment interrupted. Retry is available")
        stale_ids = [scan.id for scan in scans]
        session.commit()
    if workspace_root is not None:
        root = workspace_root.resolve(strict=True)
        for scan_id in stale_ids:
            for name in (scan_id, f"scanner-{scan_id}"):
                target = (root / name).resolve()
                if target != root and target.is_relative_to(root) and target.is_dir():
                    shutil.rmtree(target)
    return len(stale_ids)


def run_once(
    engine,
    organization_id: str,
    scan_id: str,
    signing_key: bytes,
    store: LocalObjectStore,
    scanner: DependencyScanner,
    workspace_root: Path,
) -> str:
    """Queue and finish an authorized static scan in a separate local process."""
    with Session(engine) as session:
        scan = session.scalar(select(Scan).where(
            Scan.id == scan_id, Scan.organization_id == organization_id,
        ).with_for_update())
        if (scan is None or scan.state is not ScanState.AUTHORIZED
                or scan.execution_backend != "local_static" or scan.dynamic_authorized):
            raise ValueError("authorized static scan not found")
        scan.state = ScanState.QUEUED
        session.add(AuditEvent(
            organization_id=organization_id, scan_id=scan_id, actor_id="local-static-worker",
            action="scan.queue", payload={"profile": scan.profile},
        ))
        session.add(OutboxEvent(
            organization_id=organization_id, scan_id=scan_id, kind="scan.queue",
            payload={"scan_id": scan_id},
        ))
        append_visible_event(session, scan_id, organization_id, "status", "Assessment queued")
        token = issue_grant(session, scan, signing_key, timedelta(minutes=15))
        session.commit()

    try:
        with Session(engine) as session:
            report = run_local_static_scan(
                session, organization_id, scan_id, token, signing_key,
                store, scanner, workspace_root,
            )
            report_id = report.id
            for grant in session.scalars(select(ScanGrant).where(
                ScanGrant.scan_id == scan_id, ScanGrant.organization_id == organization_id,
                ScanGrant.revoked_at.is_(None))).all():
                grant.revoked_at = utcnow()
            session.commit()
        return report_id
    except Exception:
        with Session(engine) as session:
            scan = session.scalar(select(Scan).where(
                Scan.id == scan_id, Scan.organization_id == organization_id,
            ).with_for_update())
            if scan is not None and scan.state is ScanState.QUEUED:
                scan.state = ScanState.CLEANUP
                scan.state = ScanState.FAILED
                for grant in session.scalars(select(ScanGrant).where(
                    ScanGrant.scan_id == scan_id, ScanGrant.organization_id == organization_id,
                    ScanGrant.revoked_at.is_(None))).all():
                    grant.revoked_at = utcnow()
                session.add(AuditEvent(
                    organization_id=organization_id, scan_id=scan_id,
                    actor_id="local-static-worker", action="scan.static_failed",
                    payload={"reason": "static worker failed; see local worker logs"},
                ))
                append_visible_event(session, scan_id, organization_id, "warning", "Assessment could not be completed")
                session.commit()
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Process one authorized static scan locally")
    parser.add_argument("--organization-id")
    parser.add_argument("--scan-id")
    parser.add_argument("--serve", action="store_true", help="poll and process authorized static scans")
    args = parser.parse_args()
    if not args.serve and (not args.organization_id or not args.scan_id):
        parser.error("--organization-id and --scan-id are required for one-shot mode")
    settings = Settings.from_env()
    if not settings.local_static_enabled:
        parser.error("local static execution is disabled")
    if not settings.local_artifact_root:
        parser.error("PENTRAI_LOCAL_ARTIFACT_ROOT is required for the local worker")
    workspace_root = Path(os.getenv("PENTRAI_LOCAL_WORKSPACE_ROOT", ".tmp/local-jobs")).resolve()
    workspace_root.mkdir(parents=True, exist_ok=True)
    engine = create_engine(settings.database_url, pool_pre_ping=True)

    def process(organization_id: str, scan_id: str) -> None:
        scanner_workspace = (workspace_root / f"scanner-{scan_id}").resolve()
        if not scanner_workspace.is_relative_to(workspace_root) or scanner_workspace == workspace_root:
            raise ValueError("invalid scan workspace")
        scanner_workspace.mkdir(exist_ok=False)
        try:
            scanner = OfflineOSVScanner(
                Path(os.environ["PENTRAI_OSV_SCANNER_PATH"]), os.environ["PENTRAI_OSV_SCANNER_SHA256"],
                Path(os.environ["PENTRAI_OSV_DB_ROOT"]), os.environ["PENTRAI_OSV_DB_SHA256"],
                scanner_workspace,
            )
            report_id = run_once(
                engine, organization_id, scan_id,
                settings.grant_signing_key.get_secret_value().encode("utf-8"),
                LocalObjectStore(settings.local_artifact_root), scanner, workspace_root,
            )
            print(f"scan {scan_id}: report {report_id}", flush=True)
        finally:
            shutil.rmtree(scanner_workspace)

    if not args.serve:
        process(args.organization_id, args.scan_id)
        return
    preflight = (workspace_root / f"scanner-preflight-{uuid.uuid4().hex}").resolve()
    if preflight == workspace_root or not preflight.is_relative_to(workspace_root):
        raise ValueError("invalid scanner preflight workspace")
    preflight.mkdir(exist_ok=False)
    try:
        OfflineOSVScanner(
            Path(os.environ["PENTRAI_OSV_SCANNER_PATH"]), os.environ["PENTRAI_OSV_SCANNER_SHA256"],
            Path(os.environ["PENTRAI_OSV_DB_ROOT"]), os.environ["PENTRAI_OSV_DB_SHA256"],
            preflight,
        )
    finally:
        shutil.rmtree(preflight)
    print("Local static worker polling for authorized scans", flush=True)
    while True:
        reap_stale_scans(engine, workspace_root)
        with Session(engine) as session:
            candidate = session.scalar(select(Scan).where(
                Scan.state == ScanState.AUTHORIZED, Scan.dynamic_authorized.is_(False),
                Scan.execution_backend == "local_static",
            ).order_by(Scan.created_at).limit(1))
            target = (candidate.organization_id, candidate.id) if candidate else None
        if target:
            try:
                process(*target)
            except Exception as exc:
                print(f"scan {target[1]} failed: {type(exc).__name__}: {exc}", flush=True)
        else:
            time.sleep(2)


if __name__ == "__main__":
    main()

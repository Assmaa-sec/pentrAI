from __future__ import annotations

import asyncio
import hashlib
import io
import shutil
import unittest
import uuid
import zipfile
from datetime import timedelta
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from control_plane.artifacts import create_upload_grant, finalize_upload
from control_plane.grants import issue_grant, verify_grant
from control_plane.local_static_run import LocalStaticRunRejected, run_local_static_scan
from control_plane.local_store import LocalObjectStore
from control_plane.local_worker import reap_stale_scans, run_once
from control_plane.models import Base, Membership, Organization, Project, Scan, ScanFinding, ScanGrant, ScanReport, ScanState, SourceArtifact, User, utcnow
from execution_manager.admission import prepare_runner_job, resume_runner_job
from execution_manager.dispatch import launch_prepared_job
from execution_manager.leases import create_lease
from execution_manager.preflight import ClusterFacts
from execution_manager.staging_workload import SourceBrokerEnvironment
from execution_manager.workload import RunnerEnvironment
from control_plane.scan_creation import create_scan
from control_plane.scans import transition_scan
from tests.test_static_worker import FakeScanner
from tests.test_offline_osv_adapter import DB_SHA256, SCANNER_SHA256


async def chunks(data: bytes):
    yield data


class LocalStaticRunTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(".tmp/local-static-run") / uuid.uuid4().hex
        self.root.mkdir(parents=True)
        self.store = LocalObjectStore(self.root / "objects")
        self.engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.session = Session(self.engine)
        org = Organization(name="Test org")
        user = User(oidc_subject="issuer|subject")
        self.session.add_all([org, user])
        self.session.flush()
        project = Project(organization_id=org.id, name="Test project")
        self.session.add_all([project, Membership(organization_id=org.id, user_id=user.id, role="owner")])
        self.session.flush()
        self.org_id, self.project_id, self.user_id = org.id, project.id, user.id
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("requirements.txt", "Flask==2.0.3\n")
        source = buffer.getvalue()
        upload = create_upload_grant(
            self.session, org.id, project.id, user.id,
            content_type="application/zip", declared_bytes=len(source), idempotency_key="upload",
        )
        asyncio.run(self.store.write_stream(upload.object_key, chunks(source), len(source)))
        artifact = finalize_upload(
            self.session, upload.id, org.id, user.id, self.store,
            hashlib.sha256(source).hexdigest(), upload.object_key,
        )
        scan = create_scan(
            self.session, org.id, project.id, user.id, artifact.id,
            scope_note="owned fixture", profile="standard", authorized=True,
            idempotency_key="create-scan", execution_backend="local_static",
        )
        transition_scan(self.session, scan.id, org.id, user.id, ScanState.QUEUED, "queue-scan")
        self.scan_id = scan.id
        self.key = b"x" * 32
        self.token = issue_grant(self.session, scan, self.key, timedelta(minutes=5))
        self.session.commit()

    def tearDown(self):
        self.session.close()
        self.engine.dispose()
        shutil.rmtree(self.root)

    def test_queued_scan_persists_findings_report_and_cleans_workspace(self):
        report = run_local_static_scan(
            self.session, self.org_id, self.scan_id, self.token, self.key,
            self.store, FakeScanner(), self.root / "jobs",
        )
        self.session.commit()
        self.assertIn("CVE\\-2024\\-0001", report.markdown)
        self.assertEqual(ScanState.COMPLETED, self.session.get(Scan, self.scan_id).state)
        self.assertEqual(1, len(self.session.scalars(select(ScanFinding)).all()))
        self.assertEqual(1, len(self.session.scalars(select(ScanReport)).all()))
        self.assertFalse((self.root / "jobs" / self.scan_id).exists())

    def test_wrong_tenant_cannot_run(self):
        with self.assertRaises(LocalStaticRunRejected):
            run_local_static_scan(
                self.session, "another-org", self.scan_id, self.token, self.key,
                self.store, FakeScanner(), self.root / "jobs",
            )

    def test_static_reaper_does_not_fail_active_hexstrike_lease(self):
        claims = verify_grant(self.session, self.token, self.key,
                              self.session.get(Scan, self.scan_id).source_digest)
        lease = create_lease(self.session, claims, timedelta(minutes=5))
        scan = self.session.get(Scan, self.scan_id)
        scan.updated_at = utcnow() - timedelta(minutes=20)
        self.session.commit()
        self.assertEqual(0, reap_stale_scans(self.engine, older_than=timedelta(minutes=10)))
        self.session.expire_all()
        self.assertEqual(ScanState.QUEUED, self.session.get(Scan, self.scan_id).state)
        lease.cleaned_at = utcnow()
        self.session.commit()
        self.assertEqual(1, reap_stale_scans(self.engine, older_than=timedelta(minutes=10)))
        self.session.expire_all()
        self.assertEqual(ScanState.FAILED, self.session.get(Scan, self.scan_id).state)

    def test_static_reaper_ignores_native_scan_without_lease(self):
        scan = self.session.get(Scan, self.scan_id)
        scan.execution_backend = "hexstrike"
        scan.updated_at = utcnow() - timedelta(minutes=20)
        self.session.commit()
        self.assertEqual(0, reap_stale_scans(self.engine, older_than=timedelta(minutes=10)))
        self.session.expire_all()
        self.assertEqual(ScanState.QUEUED, self.session.get(Scan, self.scan_id).state)

    def test_native_admission_binds_source_grant_lease_and_scope(self):
        scan = self.session.get(Scan, self.scan_id)
        scan.execution_backend = "hexstrike"
        self.session.scalar(select(ScanGrant).where(ScanGrant.scan_id == scan.id)).revoked_at = utcnow()
        scan.state = ScanState.AUTHORIZED
        self.session.commit()
        prepared = prepare_runner_job(self.session, self.org_id, scan.id, self.key)
        self.session.commit()
        self.assertEqual(ScanState.QUEUED, scan.state)
        self.assertEqual(scan.source_artifact_id, prepared.artifact_id)
        self.assertEqual(scan.source_digest, prepared.scope.source_digest)
        self.assertTrue(prepared.scope.source_present)
        self.assertIsNone(prepared.scope.target_url)
        self.assertEqual(prepared.lease.scan_grant_id, prepared.claims.record.id)
        self.assertNotIn(prepared.grant_token, repr(prepared))
        with self.assertRaisesRegex(ValueError, "authorized scan"):
            prepare_runner_job(self.session, self.org_id, scan.id, self.key)

    def test_committed_native_job_recovers_after_worker_restart(self):
        from control_plane.grants import GrantError

        scan = self.session.get(Scan, self.scan_id)
        scan.execution_backend = "hexstrike"
        self.session.scalar(select(ScanGrant).where(ScanGrant.scan_id == scan.id)).revoked_at = utcnow()
        scan.state = ScanState.AUTHORIZED
        self.session.commit()
        prepared = prepare_runner_job(self.session, self.org_id, scan.id, self.key)
        self.session.commit()
        with Session(self.engine) as restarted:
            recovered = resume_runner_job(restarted, self.org_id, prepared.lease.id,
                                          self.key)
            self.assertEqual(prepared.grant_token, recovered.grant_token)
            self.assertEqual(prepared.scope, recovered.scope)
            with self.assertRaises(GrantError):
                resume_runner_job(restarted, self.org_id, prepared.lease.id,
                                  b"wrong-key" * 4)
            recovered.claims.record.revoked_at = utcnow()
            restarted.commit()
        with Session(self.engine) as restarted:
            with self.assertRaisesRegex(GrantError, "revoked"):
                resume_runner_job(restarted, self.org_id, prepared.lease.id,
                                  self.key)

    def test_native_admission_rejects_changed_artifact_and_closed_url_gate(self):
        scan = self.session.get(Scan, self.scan_id)
        scan.execution_backend = "hexstrike"
        self.session.scalar(select(ScanGrant).where(ScanGrant.scan_id == scan.id)).revoked_at = utcnow()
        scan.state = ScanState.AUTHORIZED
        artifact = self.session.get(SourceArtifact, scan.source_artifact_id)
        artifact.sha256 = "f" * 64
        self.session.commit()
        with self.assertRaisesRegex(ValueError, "artifact binding"):
            prepare_runner_job(self.session, self.org_id, scan.id, self.key)
        self.assertEqual(ScanState.AUTHORIZED, scan.state)
        artifact.sha256 = scan.source_digest
        scan.target_url = "https://example.com/"
        scan.dynamic_authorized = True
        self.session.commit()
        with self.assertRaisesRegex(ValueError, "release gate"):
            prepare_runner_job(self.session, self.org_id, scan.id, self.key)

    def test_dispatch_stages_source_before_native_job(self):
        scan = self.session.get(Scan, self.scan_id)
        scan.execution_backend = "hexstrike"
        self.session.scalar(select(ScanGrant).where(ScanGrant.scan_id == scan.id)).revoked_at = utcnow()
        scan.state = ScanState.AUTHORIZED
        self.session.commit()
        prepared = prepare_runner_job(self.session, self.org_id, scan.id, self.key)
        self.session.commit()

        class Cluster:
            def __init__(self):
                self.steps = []
                self.fail_staging = False
                self.marked = False
                self.native_job = False

            def apply(self, document):
                self.steps.append(("apply", document["metadata"]["name"]))
                if document["metadata"]["name"] == "source-staged":
                    self.marked = True
                if document["metadata"]["name"] == "hexstrike":
                    self.native_job = True

            def runner_job_exists(self, expected):
                self.steps.append(("check", "hexstrike"))
                return self.native_job

            def source_stage_marked(self, lease_id, source_digest):
                self.steps.append(("check", "source-staged"))
                return self.marked

            def wait_job_complete(self, name, *, deadline_seconds, heartbeat=None):
                self.steps.append(("wait", name))
                if heartbeat is not None:
                    heartbeat()
                if self.fail_staging:
                    raise RuntimeError("staging failed")

            def delete_stage_job(self):
                self.steps.append(("delete", "stage-source"))

            def delete_namespace(self, namespace):
                self.steps.append(("delete", namespace))

        facts = ClusterFacts(True, True, frozenset({"runv"}), True, True,
                             "shared-eni", True, True, True, True, True)
        runner = RunnerEnvironment("registry.example/pentrai@sha256:" + "a" * 64,
                                   "10.4.0.2", 443, "10.4.0.3", 443)
        broker = SourceBrokerEnvironment("10.4.0.4", 443, "encrypted-scans")
        cluster = Cluster()
        with self.assertRaisesRegex(ValueError, "containment"):
            launch_prepared_job(prepared, cluster, runner, broker, self.key, facts)
        self.assertEqual([], cluster.steps)
        launch_prepared_job(prepared, cluster, runner, broker, self.key, facts,
                            containment_verified=True)
        steps = cluster.steps
        self.assertEqual(("apply", prepared.lease.namespace), steps[0])
        self.assertLess(steps.index(("apply", "default-deny")),
                        steps.index(("apply", "runner-identity")))
        self.assertLess(steps.index(("apply", "stage-source")),
                        steps.index(("wait", "stage-source")))
        self.assertLess(steps.index(("wait", "stage-source")),
                        steps.index(("apply", "source-staged")))
        self.assertLess(steps.index(("apply", "source-staged")),
                        steps.index(("delete", "stage-source")))
        self.assertLess(steps.index(("delete", "stage-source")),
                        steps.index(("apply", "hexstrike")))
        cluster.steps.clear()
        launch_prepared_job(prepared, cluster, runner, broker, self.key, facts,
                            containment_verified=True)
        self.assertIn(("check", "source-staged"), cluster.steps)
        self.assertNotIn(("apply", "stage-source"), cluster.steps)
        self.assertNotIn(("wait", "stage-source"), cluster.steps)
        self.assertNotIn(("apply", "hexstrike"), cluster.steps)
        failed = Cluster()
        failed.fail_staging = True
        with self.assertRaisesRegex(RuntimeError, "staging failed"):
            launch_prepared_job(prepared, failed, runner, broker, self.key, facts,
                                containment_verified=True)
        self.assertIn(("delete", prepared.lease.namespace), failed.steps)
        self.assertNotIn(("apply", "hexstrike"), failed.steps)

    def test_one_shot_local_worker_queues_and_completes(self):
        self.session.get(Scan, self.scan_id).state = ScanState.AUTHORIZED
        self.session.commit()
        report_id = run_once(
            self.engine, self.org_id, self.scan_id, self.key,
            self.store, FakeScanner(), self.root / "jobs",
        )
        self.session.expire_all()
        self.assertEqual(ScanState.COMPLETED, self.session.get(Scan, self.scan_id).state)
        self.assertEqual(report_id, self.session.scalar(select(ScanReport)).id)

    def test_one_shot_worker_records_failure_and_cleans_workspace(self):
        class BrokenScanner:
            scanner_version = "broken"
            database_version = "fixture"

            def scan(self, sbom):
                raise RuntimeError("scanner crash")

        self.session.get(Scan, self.scan_id).state = ScanState.AUTHORIZED
        self.session.commit()
        with self.assertRaisesRegex(RuntimeError, "scanner crash"):
            run_once(
                self.engine, self.org_id, self.scan_id, self.key,
                self.store, BrokenScanner(), self.root / "jobs",
            )
        self.session.expire_all()
        self.assertEqual(ScanState.FAILED, self.session.get(Scan, self.scan_id).state)
        self.assertFalse((self.root / "jobs" / self.scan_id).exists())
        self.assertIsNone(self.session.scalar(select(ScanReport)))

    @unittest.skipUnless(
        Path(".tmp/osv-scanner.exe").exists() and Path(".tmp/osvdb/osv-scalibr/PyPI/all.zip").exists(),
        "pinned offline OSV fixture assets are not installed",
    )
    def test_one_shot_worker_with_pinned_offline_osv(self):
        from static_worker.osv import OfflineOSVScanner

        self.session.get(Scan, self.scan_id).state = ScanState.AUTHORIZED
        self.session.commit()
        scanner_workspace = self.root / "scanner"
        scanner_workspace.mkdir()
        scanner = OfflineOSVScanner(
            Path(".tmp/osv-scanner.exe"), SCANNER_SHA256,
            Path(".tmp/osvdb"), DB_SHA256, scanner_workspace,
        )
        run_once(
            self.engine, self.org_id, self.scan_id, self.key,
            self.store, scanner, self.root / "jobs",
        )
        self.session.expire_all()
        self.assertEqual(ScanState.COMPLETED, self.session.get(Scan, self.scan_id).state)
        self.assertGreaterEqual(len(self.session.scalars(select(ScanFinding)).all()), 1)


if __name__ == "__main__":
    unittest.main()

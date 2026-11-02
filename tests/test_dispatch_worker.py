from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from control_plane.models import (Base, NativeRunnerWorker, Organization, Project, RunnerLease, Scan, ScanGrant,
                                  ScanState, SourceArtifact, UploadGrantRecord, User)
from control_plane.runner_readiness import runner_available
from execution_manager.dispatch_worker import dispatch_tick
from execution_manager.preflight import ClusterFacts
from execution_manager.service import service_cycle
from execution_manager.staging_workload import SourceBrokerEnvironment
from execution_manager.workload import RunnerEnvironment


class _Cluster:
    def __init__(self, *, fail: bool = False):
        self.fail = fail
        self.steps: list[str] = []
        self.marked = False
        self.running = False

    def apply(self, document):
        name = document["metadata"]["name"]
        self.steps.append(name)
        if name == "source-staged":
            self.marked = True
        if name == "hexstrike":
            self.running = True

    def source_stage_marked(self, lease_id, source_digest):
        return self.marked

    def wait_job_complete(self, name, *, deadline_seconds, heartbeat=None):
        if heartbeat:
            heartbeat()
        if self.fail:
            raise RuntimeError("fixture staging failure")

    def delete_stage_job(self):
        self.steps.append("delete-stage")

    def runner_job_exists(self, expected):
        return self.running

    def delete_namespace(self, namespace):
        self.steps.append("delete-namespace")
        self.marked = False
        self.running = False


class DispatchWorkerTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite+pysqlite://", poolclass=StaticPool,
                                    connect_args={"check_same_thread": False})
        Base.metadata.create_all(self.engine)
        with Session(self.engine) as session:
            org = Organization(name="Dispatch fixture")
            user = User(oidc_subject="issuer|dispatch")
            session.add_all((org, user))
            session.flush()
            project = Project(organization_id=org.id, name="Owned source")
            session.add(project)
            session.flush()
            upload = UploadGrantRecord(
                organization_id=org.id, project_id=project.id, created_by=user.id,
                object_key="fixture.zip", content_type="application/zip",
                declared_bytes=1024, idempotency_key="fixture",
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            )
            session.add(upload)
            session.flush()
            artifact = SourceArtifact(
                organization_id=org.id, project_id=project.id, upload_grant_id=upload.id,
                object_key="fixture.zip", sha256="a" * 64, size_bytes=1024,
                content_type="application/zip",
            )
            session.add(artifact)
            session.flush()
            scan = Scan(organization_id=org.id, project_id=project.id,
                        source_artifact_id=artifact.id, source_digest=artifact.sha256,
                        scope_digest="b" * 64, scope_note="owned fixture",
                        profile="quick", dynamic_authorized=False,
                        state=ScanState.AUTHORIZED)
            session.add(scan)
            session.commit()
            self.scan_id = scan.id
        self.key = b"d" * 32
        self.facts = ClusterFacts(True, True, frozenset({"runv"}), True, True,
                                  "shared-eni", True, True, True, True, True)
        self.runner = RunnerEnvironment("registry.example/pentrai@sha256:" + "a" * 64,
                                        "10.4.0.2", 443, "10.4.0.3", 443)
        self.broker = SourceBrokerEnvironment("10.4.0.4", 443, "encrypted-scans")

    def tearDown(self):
        self.engine.dispose()

    def _tick(self, cluster, *, verified=True):
        return dispatch_tick(self.engine, self.key, lambda namespace: cluster,
                             self.runner, self.broker, self.facts,
                             containment_verified=verified)

    def test_customer_scan_is_claimed_and_launched_once(self):
        cluster = _Cluster()
        with self.assertRaisesRegex(ValueError, "containment"):
            self._tick(cluster, verified=False)
        with Session(self.engine) as session:
            self.assertEqual(ScanState.AUTHORIZED, session.get(Scan, self.scan_id).state)
            self.assertFalse(runner_available(session))
        self.assertTrue(self._tick(cluster))
        with Session(self.engine) as session:
            lease = session.scalar(select(RunnerLease).where(RunnerLease.scan_id == self.scan_id))
            self.assertEqual(ScanState.QUEUED, session.get(Scan, self.scan_id).state)
            self.assertIsNotNone(lease.launched_at)
            self.assertIsNone(lease.dispatch_owner)
            self.assertTrue(runner_available(session))
            self.assertFalse(runner_available(session, url=True))
            self.assertFalse(runner_available(session,
                now=datetime.now(timezone.utc) + timedelta(seconds=31)))
        self.assertIn("hexstrike", cluster.steps)
        self.assertFalse(self._tick(cluster))

    def test_dispatch_ignores_legacy_static_scan(self):
        cluster = _Cluster()
        with Session(self.engine) as session:
            session.get(Scan, self.scan_id).execution_backend = "local_static"
            session.commit()
        self.assertFalse(self._tick(cluster))
        self.assertEqual([], cluster.steps)
        with Session(self.engine) as session:
            self.assertEqual(ScanState.AUTHORIZED, session.get(Scan, self.scan_id).state)

    def test_failed_launch_retries_then_enters_cleanup(self):
        cluster = _Cluster(fail=True)
        for attempt in range(1, 4):
            with self.assertRaisesRegex(RuntimeError, "fixture staging failure"):
                self._tick(cluster)
            with Session(self.engine) as session:
                lease = session.scalar(select(RunnerLease).where(RunnerLease.scan_id == self.scan_id))
                self.assertEqual(attempt, lease.dispatch_attempts)
                self.assertIsNone(lease.dispatch_owner)
                expected = ScanState.CLEANUP if attempt == 3 else ScanState.QUEUED
                self.assertEqual(expected, session.get(Scan, self.scan_id).state)
        self.assertFalse(self._tick(cluster))

    def test_claim_excludes_other_worker_then_recovers_after_expiry(self):
        cluster = _Cluster(fail=True)
        with self.assertRaisesRegex(RuntimeError, "fixture staging failure"):
            self._tick(cluster)
        with Session(self.engine) as session:
            lease = session.scalar(select(RunnerLease).where(RunnerLease.scan_id == self.scan_id))
            lease.dispatch_owner = "crashed-worker"
            lease.dispatch_claim_until = datetime.now(timezone.utc) + timedelta(minutes=1)
            session.commit()
        cluster.fail = False
        self.assertFalse(self._tick(cluster))
        with Session(self.engine) as session:
            lease = session.scalar(select(RunnerLease).where(RunnerLease.scan_id == self.scan_id))
            self.assertEqual(1, lease.dispatch_attempts)
            lease.dispatch_claim_until = datetime.now(timezone.utc) - timedelta(seconds=1)
            session.commit()
        self.assertTrue(self._tick(cluster))
        with Session(self.engine) as session:
            lease = session.scalar(select(RunnerLease).where(RunnerLease.scan_id == self.scan_id))
            self.assertEqual(2, lease.dispatch_attempts)
            self.assertIsNotNone(lease.launched_at)

    def test_cancellation_during_staging_stops_launch_and_cleans_namespace(self):
        cluster = _Cluster()

        def cancel_during_stage(name, *, deadline_seconds, heartbeat=None):
            with Session(self.engine) as session:
                scan = session.get(Scan, self.scan_id)
                scan.state = ScanState.CANCELLED
                for grant in session.scalars(select(ScanGrant).where(
                    ScanGrant.scan_id == self.scan_id)).all():
                    grant.revoked_at = datetime.now(timezone.utc)
                session.commit()
            heartbeat()

        cluster.wait_job_complete = cancel_during_stage
        with self.assertRaisesRegex(RuntimeError, "claim was lost"):
            self._tick(cluster)
        with Session(self.engine) as session:
            lease = session.scalar(select(RunnerLease).where(RunnerLease.scan_id == self.scan_id))
            self.assertEqual(ScanState.CANCELLED, session.get(Scan, self.scan_id).state)
            self.assertIsNone(lease.launched_at)
        self.assertIn("delete-namespace", cluster.steps)
        self.assertNotIn("hexstrike", cluster.steps)

    def test_service_reaps_cancelled_job_before_lease_expiry(self):
        cluster = _Cluster()
        revoked: list[str] = []

        def cycle():
            return service_cycle(
                self.engine, self.key, lambda namespace: cluster,
                self.runner, self.broker, self.facts,
                lambda lease: revoked.append(lease.id), containment_verified=True,
            )

        self.assertEqual((True, 0), cycle())
        with Session(self.engine) as session:
            session.get(Scan, self.scan_id).state = ScanState.CANCELLED
            session.commit()
        self.assertEqual((False, 1), cycle())
        with Session(self.engine) as session:
            lease = session.scalar(select(RunnerLease).where(RunnerLease.scan_id == self.scan_id))
            self.assertIsNotNone(lease.cleaned_at)
            self.assertEqual([lease.id], revoked)
            self.assertEqual(ScanState.CANCELLED, session.get(Scan, self.scan_id).state)
        self.assertIn("delete-namespace", cluster.steps)

    def test_service_reaps_after_final_launch_failure(self):
        cluster = _Cluster(fail=True)
        for _ in range(3):
            with self.assertRaisesRegex(RuntimeError, "fixture staging failure"):
                service_cycle(
                    self.engine, self.key, lambda namespace: cluster,
                    self.runner, self.broker, self.facts, lambda lease: None,
                    containment_verified=True,
                )
        with Session(self.engine) as session:
            lease = session.scalar(select(RunnerLease).where(RunnerLease.scan_id == self.scan_id))
            self.assertIsNotNone(lease.cleaned_at)
            self.assertEqual(ScanState.FAILED, session.get(Scan, self.scan_id).state)

    def test_staging_heartbeat_renews_worker_readiness(self):
        cluster = _Cluster()

        def slow_stage(name, *, deadline_seconds, heartbeat=None):
            with Session(self.engine) as session:
                worker = session.scalar(select(NativeRunnerWorker))
                worker.heartbeat_at = datetime.now(timezone.utc) - timedelta(minutes=1)
                session.commit()
            heartbeat()
            with Session(self.engine) as session:
                self.assertTrue(runner_available(session))

        cluster.wait_job_complete = slow_stage
        self.assertTrue(self._tick(cluster))


if __name__ == "__main__":
    unittest.main()

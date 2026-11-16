"""Setup failures must be visible and must not starve later assessments."""
import os
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from control_plane.credits import grant_credits, reserve_scan_credits
from control_plane.local_hexstrike_worker import fail_before_execution, main
from control_plane.models import (
    Base, LocalHexStrikeWorker, Organization, OrganizationCreditAccount, Project, Scan, ScanEvent, ScanState,
)


class LocalHexStrikeStartFailureTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.addCleanup(self.engine.dispose)
        with Session(self.engine) as session:
            org = Organization(name="Owned test")
            session.add(org)
            session.flush()
            project = Project(organization_id=org.id, name="Source")
            session.add(project)
            session.flush()
            self.org_id = org.id
            grant_credits(session, org.id, 100_000, actor_id="test", reason="fixture")
            scans = [Scan(
                organization_id=org.id, project_id=project.id,
                source_digest="a" * 64, scope_digest="b" * 64,
                profile="quick", dynamic_authorized=False,
                execution_backend="hexstrike_local", state=ScanState.AUTHORIZED,
            ) for _ in range(2)]
            session.add_all(scans)
            session.flush()
            for scan in scans:
                reserve_scan_credits(session, scan)
            self.first, self.second = [scan.id for scan in scans]
            session.commit()

    def test_missing_credential_fails_visibly_and_unblocks_next_scan(self):
        env = {
            "PENTRAI_DATABASE_URL": "sqlite+pysqlite:///:memory:",
            "PENTRAI_GRANT_SIGNING_KEY": "k" * 32,
            "PENTRAI_LOCAL_ARTIFACT_ROOT": ".tmp/test-start-failure",
            "PENTRAI_LOCAL_DEV_AUTH": "true",
            "PENTRAI_LOCAL_HEXSTRIKE_ENABLED": "true",
        }
        with patch.dict(os.environ, env, clear=True), \
             patch("sys.argv", ["worker", "--organization-id", self.org_id,
                                "--scan-id", self.first]), \
             patch("control_plane.local_hexstrike_worker.create_engine", return_value=self.engine), \
             patch("control_plane.local_hexstrike_worker.shutil.which", return_value="docker"), \
             patch("control_plane.local_hexstrike_worker.subprocess.run") as docker, \
             patch("control_plane.local_hexstrike_worker.run_once") as run:
            docker.return_value.returncode = 0
            with patch("sys.stderr"):
                with self.assertRaises(SystemExit) as error:
                    main()
                self.assertEqual(1, error.exception.code)
            run.assert_not_called()
        with Session(self.engine) as session:
            self.assertEqual(ScanState.FAILED, session.get(Scan, self.first).state)
            candidates = session.scalars(select(Scan.id).where(
                Scan.state == ScanState.AUTHORIZED,
                Scan.execution_backend == "hexstrike_local",
            )).all()
            self.assertEqual([self.second], candidates)
            event = session.scalar(select(ScanEvent).where(ScanEvent.scan_id == self.first))
            self.assertIn("configuration", event.summary)
            account = session.get(OrganizationCreditAccount, self.org_id)
            self.assertEqual((80_000, 20_000), (account.available, account.reserved))
        fail_before_execution(self.engine, self.org_id, self.first)
        with Session(self.engine) as session:
            self.assertEqual(1, len(session.scalars(select(ScanEvent)).all()))

    def test_does_not_change_foreign_cancelled_or_claimed_scan(self):
        fail_before_execution(self.engine, "another-organization", self.first)
        for state in (ScanState.CANCELLED, ScanState.QUEUED, ScanState.COMPLETED):
            with Session(self.engine) as session:
                session.get(Scan, self.first).state = state
                session.commit()
            fail_before_execution(self.engine, self.org_id, self.first)
            with Session(self.engine) as session:
                self.assertEqual(state, session.get(Scan, self.first).state)
                self.assertEqual([], session.scalars(select(ScanEvent)).all())

    def test_polling_fails_each_unstartable_scan_without_advertising_readiness(self):
        env = {
            "PENTRAI_DATABASE_URL": "sqlite+pysqlite:///:memory:",
            "PENTRAI_GRANT_SIGNING_KEY": "k" * 32,
            "PENTRAI_LOCAL_ARTIFACT_ROOT": ".tmp/test-start-failure",
            "PENTRAI_LOCAL_DEV_AUTH": "true",
            "PENTRAI_LOCAL_HEXSTRIKE_ENABLED": "true",
        }
        with patch.dict(os.environ, env, clear=True), \
             patch("sys.argv", ["worker", "--serve"]), \
             patch("control_plane.local_hexstrike_worker.create_engine", return_value=self.engine), \
             patch("control_plane.local_hexstrike_worker.time.sleep", side_effect=StopIteration), \
             patch("builtins.print"):
            with self.assertRaises(StopIteration):
                main()
        with Session(self.engine) as session:
            self.assertEqual([ScanState.FAILED, ScanState.FAILED],
                             session.scalars(select(Scan.state)).all())
            self.assertEqual([], session.scalars(select(LocalHexStrikeWorker)).all())
            account = session.get(OrganizationCreditAccount, self.org_id)
            self.assertEqual((100_000, 0), (account.available, account.reserved))

    def test_preflight_checks_do_not_start_or_change_assessments(self):
        env = {
            "PENTRAI_DATABASE_URL": "sqlite+pysqlite:///:memory:",
            "PENTRAI_GRANT_SIGNING_KEY": "k" * 32,
            "PENTRAI_LOCAL_ARTIFACT_ROOT": ".tmp/test-start-failure",
            "PENTRAI_LOCAL_DEV_AUTH": "true",
            "PENTRAI_LOCAL_HEXSTRIKE_ENABLED": "true",
            "PENTRAI_LLM_API_KEY": "owned-test-key",
        }
        with patch.dict(os.environ, env, clear=True), \
             patch("sys.argv", ["worker", "--check"]), \
             patch("control_plane.local_hexstrike_worker.create_engine", return_value=self.engine), \
             patch("control_plane.local_hexstrike_worker.shutil.which", return_value="docker"), \
             patch("control_plane.local_hexstrike_worker.subprocess.run") as docker, \
             patch("control_plane.local_hexstrike_worker.subprocess.Popen") as launch, \
             patch("builtins.print"):
            docker.return_value.returncode = 0
            main()
            launch.assert_not_called()
        with Session(self.engine) as session:
            self.assertEqual([ScanState.AUTHORIZED, ScanState.AUTHORIZED],
                             session.scalars(select(Scan.state)).all())
            self.assertEqual([], session.scalars(select(LocalHexStrikeWorker)).all())


if __name__ == "__main__":
    unittest.main()

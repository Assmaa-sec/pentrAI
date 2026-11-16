"""Tenant-scoped customer progress and delayed/interrupted lifecycle coverage."""
from datetime import timedelta
import unittest

from sqlalchemy import select
from sqlalchemy.orm import Session

from control_plane.assessment_health import FAILURES, HEALTH_WARNINGS
from control_plane.assessment_progress import progress_snapshot, public_event_summary
from control_plane.events import append_visible_event
from control_plane.models import AuditEvent, Scan, ScanEvent, ScanState, utcnow


class AssessmentProgressTests(unittest.TestCase):
    def setUp(self):
        from tests.test_control_plane_api import ControlPlaneApiTests
        self.fixture = ControlPlaneApiTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.engine = self.fixture.engine
        self.path = f"/v1/organizations/{self.fixture.org_id}/scans/{self.fixture.scan_id}"

    def test_progress_comes_from_actual_phase_and_has_timestamps(self):
        with Session(self.engine) as session:
            scan = session.get(Scan, self.fixture.scan_id)
            scan.state = ScanState.QUEUED
            scan.execution_backend = "local_static"
            append_visible_event(session, scan.id, scan.organization_id, "analysis", "Analyzing the uploaded source")
            session.commit()
        response = self.fixture.client.get(self.path)
        self.assertEqual(200, response.status_code)
        progress = response.json()["progress"]
        self.assertEqual("analysis", progress["stage"])
        self.assertEqual("healthy", progress["health"])
        self.assertIn("+00:00", progress["last_activity_at"])
        self.assertNotIn("percent", progress)
        self.assertFalse(progress["report_ready"])
        self.assertEqual(404, self.fixture.client.get(
            self.path.replace(self.fixture.org_id, self.fixture.other_org_id)).status_code)

    def test_heartbeat_does_not_hide_stale_analysis_or_fabricate_completion(self):
        with Session(self.engine) as session:
            scan = session.get(Scan, self.fixture.scan_id)
            scan.state = ScanState.STATIC
            old = append_visible_event(session, scan.id, scan.organization_id, "analysis", "Analyzing the uploaded source")
            old.created_at = utcnow() - timedelta(minutes=3)
            append_visible_event(session, scan.id, scan.organization_id, "status",
                                 "Assessment service is responding. Current step: analyzing source.")
            session.commit()
            progress = progress_snapshot(session, scan)
            self.assertEqual("delayed", progress["health"])
            self.assertEqual("analysis", progress["stage"])
            self.assertNotEqual(progress["last_activity_at"], progress["last_update_at"])
            self.assertEqual(ScanState.STATIC, scan.state)

    def test_terminal_states_override_old_health_warnings(self):
        with Session(self.engine) as session:
            scan = session.get(Scan, self.fixture.scan_id)
            scan.created_at = utcnow() - timedelta(seconds=100)
            append_visible_event(session, scan.id, scan.organization_id, "warning", HEALTH_WARNINGS[3])
            for state in (ScanState.COMPLETED, ScanState.CANCELLED, ScanState.FAILED):
                scan.state = state
                session.flush()
                progress = progress_snapshot(session, scan, now=utcnow() + timedelta(hours=1))
                self.assertEqual(state.value, progress["health"])
                self.assertLess(progress["elapsed_seconds"], 110)

    def test_failure_details_are_customer_safe_but_audit_keeps_reason(self):
        with Session(self.engine) as session:
            scan = session.get(Scan, self.fixture.scan_id)
            scan.state = ScanState.FAILED
            session.add(AuditEvent(organization_id=scan.organization_id, scan_id=scan.id,
                                  actor_id="test", action="scan.start_failed", payload={"reason": "docker"}))
            append_visible_event(session, scan.id, scan.organization_id, "warning", FAILURES["docker"])
            session.commit()
        response = self.fixture.client.get(self.path)
        text = response.json()["progress"]["message"]
        self.assertNotIn("Docker", text)
        self.assertIn("assessment reference", text)
        events = self.fixture.client.get(self.path + "/events?follow=false")
        self.assertNotIn("Docker", events.text)
        self.assertIn("created_at", events.text)
        with Session(self.engine) as session:
            audit = session.scalar(select(AuditEvent).where(AuditEvent.action == "scan.start_failed"))
            self.assertEqual("docker", audit.payload["reason"])

    def test_legacy_diagnostics_never_reach_customers_as_setup_instructions(self):
        for code, text in FAILURES.items():
            for suffix in ("", " Cleanup is in progress."):
                with self.subTest(code=code, suffix=suffix):
                    public = public_event_summary("warning", text + suffix)
                    self.assertNotIn("Docker", public)
                    self.assertNotIn("API key", public)
                    self.assertNotIn("database", public)
        self.assertNotIn("SECRET", public_event_summary("warning", "PRIVATE SECRET infrastructure failure"))

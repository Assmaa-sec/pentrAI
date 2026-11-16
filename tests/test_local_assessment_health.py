"""Orchestration diagnostics; no Docker daemon or live model is used."""
from datetime import timedelta
import asyncio
import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from control_plane.assessment_health import AssessmentFailure, observe_local_health
from control_plane.local_hexstrike_worker import check_local_dependencies, run_once
from control_plane.local_store import LocalObjectStore
from control_plane.models import (
    LocalHexStrikeWorker, OrganizationCreditAccount, RunnerLease, Scan, ScanEvent,
    ScanState, utcnow,
)


class LocalAssessmentHealthTests(unittest.TestCase):
    def setUp(self):
        # Reuse the owned upload/auth fixture, not its opt-in Docker test methods.
        from tests.test_local_hexstrike_docker import LocalHexStrikeDockerTest
        self.fixture = LocalHexStrikeDockerTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.api = self.fixture.api
        self.scan_id = self.fixture._upload_scan()
        self.cleanup = patch("control_plane.local_hexstrike_worker.LocalDockerClient.delete_namespace")
        self.delete = self.cleanup.start()
        self.addCleanup(self.cleanup.stop)

    def run_scan(self, model=None, heartbeat=None):
        return run_once(self.api.engine, self.api.org_id, self.scan_id,
                        self.api.client.app.state.settings,
                        LocalObjectStore(self.api.artifact_dir), model or Mock(), heartbeat=heartbeat)

    def events(self):
        with Session(self.api.engine) as session:
            return session.scalars(select(ScanEvent.summary).where(
                ScanEvent.scan_id == self.scan_id).order_by(ScanEvent.sequence)).all()

    def assert_failed_and_cleaned(self):
        with Session(self.api.engine) as session:
            self.assertEqual(ScanState.FAILED, session.get(Scan, self.scan_id).state)
            lease = session.scalar(select(RunnerLease).where(RunnerLease.scan_id == self.scan_id))
            self.assertIsNotNone(lease.cleaned_at)
            self.assertEqual(0, session.get(OrganizationCreditAccount, self.api.org_id).reserved)

    def test_provider_errors_have_safe_actionable_messages(self):
        for status, expected in ((401, "authentication"), (403, "authentication"),
                                 (429, "quota or rate"), (500, "provider request failed")):
            # Separate scans so completed failure handling is exercised each time.
            with self.subTest(status=status):
                if status != 401:
                    self.fixture.tearDown()
                    self.fixture.setUp()
                    self.api = self.fixture.api
                    self.scan_id = self.fixture._upload_scan()
                request = httpx.Request("POST", "https://provider.invalid/v1/chat/completions")
                error = httpx.HTTPStatusError("SECRET-KEY-DO-NOT-LOG", request=request,
                                              response=httpx.Response(status, request=request))
                model = Mock()
                model.chat_tools.side_effect = error

                def assess(prepared, archive, metered, **kwargs):
                    kwargs["on_stage"]("model")
                    metered.chat_tools([], tools=[{}])

                with patch("control_plane.local_hexstrike_worker._docker_assessment", side_effect=assess):
                    with self.assertRaises(AssessmentFailure):
                        self.run_scan(model)
                self.assert_failed_and_cleaned()
                text = " ".join(self.events())
                self.assertIn(expected, text)
                self.assertNotIn("SECRET-KEY", text)

    def test_missing_source_fails_and_releases_credits(self):
        with patch.object(LocalObjectStore, "read_chunks", side_effect=FileNotFoundError("PRIVATE-PATH")), \
             patch("control_plane.local_hexstrike_worker._docker_assessment") as assess:
            with self.assertRaises(FileNotFoundError):
                self.run_scan()
            assess.assert_not_called()
        self.assert_failed_and_cleaned()
        self.assertIn("uploaded source", " ".join(self.events()))
        self.assertNotIn("PRIVATE-PATH", " ".join(self.events()))

    def test_progress_heartbeat_and_healthy_completion(self):
        heartbeat = Mock()

        def assess(prepared, archive, model, **kwargs):
            kwargs["on_stage"]("tools")
            with patch("control_plane.local_hexstrike_worker.time.monotonic", return_value=10**12):
                self.assertFalse(kwargs["is_cancelled"]())
            model.chat_tools([], tools=[{}])
            return {
                "scan_id": self.scan_id, "organization_id": self.api.org_id,
                "lease_id": prepared.lease.id, "scope_digest": prepared.scope.scope_digest,
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
                "events": [], "findings": [],
            }

        model = Mock()
        model.chat_tools.return_value = SimpleNamespace(usage={"prompt_tokens": 1, "completion_tokens": 1})
        with patch("control_plane.local_hexstrike_worker._docker_assessment", side_effect=assess):
            self.assertTrue(self.run_scan(model, heartbeat=heartbeat))
        heartbeat.assert_called_once()
        text = " ".join(self.events())
        self.assertIn("Checking the uploaded source", text)
        self.assertIn("service is responding", text)
        self.assertIn("Verifying and saving", text)
        with Session(self.api.engine) as session:
            self.assertEqual(ScanState.COMPLETED, session.get(Scan, self.scan_id).state)

    def test_invalid_result_is_explained_without_false_completion(self):
        with patch("control_plane.local_hexstrike_worker._docker_assessment", return_value={}):
            with self.assertRaises(ValueError):
                self.run_scan()
        self.assert_failed_and_cleaned()
        self.assertIn("could not be verified or saved", " ".join(self.events()))

    def test_job_heartbeat_stall_is_detected_even_if_another_worker_is_ready(self):
        def assess(prepared, archive, model, **kwargs):
            with Session(self.api.engine) as session:
                lease = session.get(RunnerLease, prepared.lease.id)
                lease.heartbeat_at = utcnow() - timedelta(minutes=1)
                session.commit()
            with Session(self.api.engine) as session:
                observe_local_health(session, session.get(Scan, self.scan_id))
                session.commit()
            self.assertIn("stopped reporting activity", " ".join(self.events()))
            self.assertFalse(kwargs["is_cancelled"]())
            with Session(self.api.engine) as session:
                lease = session.get(RunnerLease, prepared.lease.id)
                self.assertGreater(lease.heartbeat_at.replace(tzinfo=utcnow().tzinfo),
                                   utcnow() - timedelta(seconds=5))
            raise AssessmentFailure("runner")

        with patch("control_plane.local_hexstrike_worker._docker_assessment", side_effect=assess):
            with self.assertRaises(AssessmentFailure):
                self.run_scan()
        self.assert_failed_and_cleaned()

    def test_expired_authorization_never_launches_assessment(self):
        from control_plane.models import OrganizationAssessmentAuthorization
        with Session(self.api.engine) as session:
            authority = session.scalar(select(OrganizationAssessmentAuthorization).where(
                OrganizationAssessmentAuthorization.organization_id == self.api.org_id))
            authority.expires_at = utcnow() - timedelta(seconds=1)
            session.commit()
        with patch("control_plane.local_hexstrike_worker._docker_assessment") as assess:
            with self.assertRaisesRegex(AssessmentFailure, "authorization"):
                self.run_scan()
            assess.assert_not_called()

    def test_cleanup_failure_is_visible_retriable_and_deduplicated(self):
        self.delete.side_effect = OSError("PRIVATE-DOCKER-DETAIL")
        with patch("control_plane.local_hexstrike_worker._docker_assessment", side_effect=AssessmentFailure("runner")):
            with self.assertRaisesRegex(RuntimeError, "cleanup remains pending"):
                self.run_scan()
        with Session(self.api.engine) as session:
            scan = session.get(Scan, self.scan_id)
            self.assertEqual(ScanState.CLEANUP, scan.state)
            observe_local_health(session, scan)
            observe_local_health(session, scan)
            session.commit()
        text = " ".join(self.events())
        self.assertIn("cleanup could not finish", text)
        self.assertNotIn("PRIVATE-DOCKER-DETAIL", text)
        from control_plane.local_hexstrike_worker import reap_local_leases
        self.delete.side_effect = None
        self.assertEqual(1, reap_local_leases(self.api.engine, "docker"))
        self.assert_failed_and_cleaned()

    def test_api_warns_when_worker_disappears_without_changing_scan_state(self):
        with Session(self.api.engine) as session:
            for worker in session.scalars(select(LocalHexStrikeWorker)).all():
                worker.heartbeat_at = utcnow() - timedelta(minutes=1)
            session.commit()
        path = f"/v1/organizations/{self.api.org_id}/scans/{self.scan_id}/events?follow=false"
        response = self.api.client.get(path)
        self.assertEqual(200, response.status_code)
        self.assertIn("service is not responding", response.text)
        count = len(self.events())
        self.assertEqual(200, self.api.client.get(path).status_code)
        self.assertEqual(count, len(self.events()))
        replay = self.api.client.get(path, headers={"Last-Event-ID": "99999"})
        self.assertEqual("", replay.text)
        with Session(self.api.engine) as session:
            self.assertEqual(ScanState.AUTHORIZED, session.get(Scan, self.scan_id).state)
        denied = self.api.client.get(path.replace(self.api.org_id, self.api.other_org_id))
        self.assertEqual(404, denied.status_code)

    def test_recovered_service_can_report_a_second_outage(self):
        with Session(self.api.engine) as session:
            worker = session.scalar(select(LocalHexStrikeWorker))
            worker_id = worker.id
            worker.heartbeat_at = utcnow() - timedelta(minutes=1)
            session.commit()
        path = f"/v1/organizations/{self.api.org_id}/scans/{self.scan_id}/events?follow=false"
        self.api.client.get(path)
        from control_plane.local_hexstrike_readiness import publish_local_heartbeat
        with Session(self.api.engine) as session:
            publish_local_heartbeat(session, worker_id)
            session.commit()
        self.api.client.get(path)
        self.assertIn("responding again", " ".join(self.events()))
        with Session(self.api.engine) as session:
            session.get(LocalHexStrikeWorker, worker_id).heartbeat_at = utcnow() - timedelta(minutes=1)
            session.commit()
        self.api.client.get(path)
        self.assertEqual(2, sum("service is not responding" in event for event in self.events()))

    def test_late_provider_usage_is_metered_after_cancellation_and_cleanup(self):
        from control_plane.local_hexstrike_worker import reap_local_leases
        model = Mock()

        def provider(*args, **kwargs):
            path = f"/v1/organizations/{self.api.org_id}/scans/{self.scan_id}/cancel"
            response = self.api.client.post(path, headers={"Idempotency-Key": "cancel-inflight-model"})
            self.assertEqual(200, response.status_code, response.text)
            self.assertEqual(1, reap_local_leases(self.api.engine, "docker"))
            return SimpleNamespace(usage={"prompt_tokens": 3, "completion_tokens": 2})

        model.chat_tools.side_effect = provider

        def assess(prepared, archive, metered, **kwargs):
            metered.chat_tools([], tools=[{}])
            self.fail("cancelled scan must not accept a model result")

        with patch("control_plane.local_hexstrike_worker._docker_assessment", side_effect=assess):
            with self.assertRaises(AssessmentFailure):
                self.run_scan(model)
        with Session(self.api.engine) as session:
            self.assertEqual(ScanState.CANCELLED, session.get(Scan, self.scan_id).state)
            account = session.get(OrganizationCreditAccount, self.api.org_id)
            self.assertEqual(0, account.reserved)
            self.assertEqual(5, account.spent)

    def test_open_event_stream_observes_a_later_commit(self):
        from control_plane.auth import CurrentActor
        from control_plane.events import append_visible_event
        route = next(route for route in self.api.client.app.routes
                     if getattr(route, "path", "").endswith("/{scan_id}/events"))

        async def check():
            with Session(self.api.engine) as session:
                last = session.scalar(select(ScanEvent.sequence).where(
                    ScanEvent.scan_id == self.scan_id).order_by(ScanEvent.sequence.desc()).limit(1))
                session.rollback()
                response = route.endpoint(self.api.org_id, self.scan_id, follow=True,
                    last_event_id=str(last or 0), actor=CurrentActor(self.api.user_id), session=session)
                iterator = response.body_iterator
                waiting = asyncio.create_task(anext(iterator))
                try:
                    await asyncio.sleep(0.1)
                    with Session(self.api.engine) as writer:
                        append_visible_event(writer, self.scan_id, self.api.org_id,
                                             "analysis", "Newly committed assessment progress")
                        writer.commit()
                    payload = await asyncio.wait_for(waiting, timeout=5)
                    self.assertIn("Newly committed assessment progress", payload)
                finally:
                    if not waiting.done():
                        waiting.cancel()
                    await iterator.aclose()

        asyncio.run(check())


class DependencyCheckTests(unittest.TestCase):
    def test_no_key_never_checks_docker_or_calls_provider(self):
        with patch.dict(os.environ, {}, clear=True), \
             patch("control_plane.local_hexstrike_worker.subprocess.run") as docker:
            with self.assertRaisesRegex(AssessmentFailure, "API key is missing"):
                check_local_dependencies("docker", "pentrai/hexstrike-runner:local")
            docker.assert_not_called()

    def test_bad_catalog_and_missing_image_are_actionable(self):
        with patch.dict(os.environ, {"PENTRAI_MODEL_OPTIONS_JSON": "invalid"}, clear=True):
            with self.assertRaisesRegex(AssessmentFailure, "configuration is incomplete"):
                check_local_dependencies("docker", "pentrai/hexstrike-runner:local")
        with patch.dict(os.environ, {"PENTRAI_LLM_API_KEY": "SECRET"}, clear=True), \
             patch("control_plane.local_hexstrike_worker.shutil.which", return_value="docker"), \
             patch("control_plane.local_hexstrike_worker.subprocess.run", return_value=SimpleNamespace(returncode=1)):
            with self.assertRaisesRegex(AssessmentFailure, "check Docker"):
                check_local_dependencies("docker", "pentrai/hexstrike-runner:local")

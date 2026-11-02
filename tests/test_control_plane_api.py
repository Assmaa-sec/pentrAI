from __future__ import annotations

import unittest
import hashlib
import shutil
import uuid
from unittest.mock import patch
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from control_plane.models import Base, Membership, NativeRunnerWorker, Organization, Project, Scan, ScanFinding, ScanReport, SourceArtifact, UploadGrantRecord, User, utcnow
from control_plane.settings import Settings
from control_plane.credits import grant_credits


class ControlPlaneApiTests(unittest.TestCase):
    def setUp(self):
        from control_plane.app import create_app
        from control_plane.auth import CurrentActor, current_actor
        from control_plane.db import get_session

        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
        )
        Base.metadata.create_all(self.engine)
        self.artifact_dir = Path(".tmp/local-artifacts-test") / str(uuid.uuid4())
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        with Session(self.engine) as session:
            org = Organization(name="Northstar")
            other_org = Organization(name="Southstar")
            user = User(oidc_subject="test|one")
            session.add_all([org, other_org, user])
            session.flush()
            grant_credits(session, org.id, 1_000_000, actor_id=user.id,
                          reason="owned test allocation")
            session.add(Membership(organization_id=org.id, user_id=user.id, role="owner"))
            project = Project(organization_id=org.id, name="Payments")
            foreign = Project(organization_id=other_org.id, name="Secrets")
            session.add_all([project, foreign])
            session.flush()
            scan = Scan(
                organization_id=org.id, project_id=project.id,
                source_digest="a" * 64, scope_digest="b" * 64,
                profile="standard", dynamic_authorized=False,
            )
            session.add(scan)
            upload = UploadGrantRecord(
                organization_id=org.id, project_id=project.id, created_by=user.id,
                object_key="fixture.zip", content_type="application/zip", declared_bytes=3,
                idempotency_key="seed-upload", expires_at=utcnow(),
            )
            session.add(upload)
            session.flush()
            artifact = SourceArtifact(
                organization_id=org.id, project_id=project.id, upload_grant_id=upload.id,
                object_key=upload.object_key, sha256="c" * 64, size_bytes=3,
                content_type="application/zip",
            )
            session.add(artifact)
            session.commit()
            self.org_id, self.other_org_id = org.id, other_org.id
            self.project_id, self.foreign_id, self.user_id = project.id, foreign.id, user.id
            self.scan_id = scan.id
            self.artifact_id = artifact.id

        app = create_app(Settings(
            database_url="sqlite+pysqlite:///:memory:", grant_signing_key="k" * 32,
            local_artifact_root=str(self.artifact_dir),
            local_dev_auth=True, local_static_enabled=True,
        ))
        app.dependency_overrides[get_session] = self._session
        app.dependency_overrides[current_actor] = lambda: CurrentActor(self.user_id)
        self.client = TestClient(app)

    def _session(self):
        with Session(self.engine) as session:
            yield session

    def tearDown(self):
        self.client.close()
        self.engine.dispose()
        shutil.rmtree(self.artifact_dir)

    def _authorize_org(self):
        response = self.client.put(
            f"/v1/organizations/{self.org_id}/assessment-authorization",
            json={"scope_statement": "Owned source and website assessment for this organization",
                  "source_allowed": True, "url_allowed": True, "valid_days": 30,
                  "accept_terms": True})
        self.assertEqual(200, response.status_code, response.text)
        return response.json()["id"]

    def test_member_reads_own_project(self):
        response = self.client.get(f"/v1/organizations/{self.org_id}/projects/{self.project_id}")
        self.assertEqual(200, response.status_code)
        self.assertEqual("Payments", response.json()["name"])
        scan = self.client.get(f"/v1/organizations/{self.org_id}/scans/{self.scan_id}")
        self.assertEqual(200, scan.status_code)
        self.assertEqual("standard", scan.json()["profile"])
        models = self.client.get(f"/v1/organizations/{self.org_id}/models")
        self.assertEqual(200, models.status_code)
        self.assertEqual("managed", models.json()[0]["id"])
        self.assertNotIn("key_env", models.text)

    def test_member_cannot_read_other_organizations_project(self):
        response = self.client.get(f"/v1/organizations/{self.other_org_id}/projects/{self.foreign_id}")
        self.assertEqual(404, response.status_code)
        scan = self.client.get(f"/v1/organizations/{self.other_org_id}/scans/{self.scan_id}")
        self.assertEqual(404, scan.status_code)
        models = self.client.get(f"/v1/organizations/{self.other_org_id}/models")
        self.assertEqual(404, models.status_code)

    def test_runner_result_authenticates_and_appears_as_pentrai_finding(self):
        from datetime import timedelta
        from control_plane.grants import issue_grant, verify_grant
        from control_plane.models import ScanState
        from execution_manager.leases import create_lease

        key = b"k" * 32
        with Session(self.engine) as session:
            scan = session.get(Scan, self.scan_id)
            scan.state = ScanState.QUEUED
            token = issue_grant(session, scan, key, timedelta(minutes=15))
            claims = verify_grant(session, token, key, scan.source_digest)
            lease = create_lease(session, claims, timedelta(minutes=10))
            lease_id = lease.id
            session.commit()
        event = {"tool": "list_files", "arguments_sha256": "c" * 64,
                 "output_sha256": "d" * 64, "output_chars": 20, "is_error": False}
        payload = {"scan_id": self.scan_id, "organization_id": self.org_id,
                   "lease_id": lease_id, "scope_digest": "b" * 64,
                   "usage": {"prompt_tokens": 9, "completion_tokens": 4},
                   "events": [event], "findings": [{"title": "Example detected issue",
                       "severity": "medium", "explanation": "Model-written explanation of the tool result.",
                       "evidence_sha256": ["d" * 64]}]}
        route = "/internal/runner-results"
        self.assertEqual(403, self.client.post(route, json=payload,
                                                headers={"Authorization": "Bearer invalid"}).status_code)
        response = self.client.post(route, json=payload,
                                    headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(200, response.status_code, response.text)
        self.assertEqual(response.json(), self.client.post(
            route, json=payload, headers={"Authorization": f"Bearer {token}"}).json())
        findings = self.client.get(f"/v1/organizations/{self.org_id}/scans/{self.scan_id}/findings")
        self.assertEqual(200, findings.status_code)
        self.assertEqual("hexstrike", findings.json()[0]["source"])
        self.assertEqual("Model-written explanation of the tool result.",
                         findings.json()[0]["explanation"])

    def test_source_broker_requires_matching_grant_and_live_lease(self):
        from datetime import timedelta
        from zipfile import ZipFile
        from control_plane.grants import issue_grant, verify_grant
        from control_plane.local_store import LocalObjectStore
        from control_plane.models import ScanState
        from execution_manager.leases import create_lease

        store = LocalObjectStore(self.artifact_dir)
        archive_path = store.path_for("fixture.zip")
        with ZipFile(archive_path, "w") as archive:
            archive.writestr("app.py", "PASSWORD = 'fixture-only'\n")
        archive_bytes = archive_path.read_bytes()
        digest = hashlib.sha256(archive_bytes).hexdigest()
        key = b"k" * 32
        with Session(self.engine) as session:
            scan = session.get(Scan, self.scan_id)
            artifact = session.get(SourceArtifact, self.artifact_id)
            artifact.sha256 = digest
            artifact.size_bytes = len(archive_bytes)
            scan.source_digest = digest
            scan.source_artifact_id = artifact.id
            scan.state = ScanState.QUEUED
            token = issue_grant(session, scan, key, timedelta(minutes=15))
            session.commit()
        route = f"/internal/artifacts/{self.artifact_id}"
        self.assertEqual(403, self.client.get(route,
                                              headers={"Authorization": f"Bearer {token}"}).status_code)
        with Session(self.engine) as session:
            fresh_claims = verify_grant(session, token, key, digest)
            create_lease(session, fresh_claims, timedelta(minutes=10))
            session.commit()
        self.assertEqual(403, self.client.get(route,
                                              headers={"Authorization": "Bearer invalid"}).status_code)
        response = self.client.get(route, headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(200, response.status_code, response.text)
        self.assertEqual(archive_bytes, response.content)
        self.assertEqual("no-store", response.headers["cache-control"])

    def test_project_creation_is_idempotent_and_audited_once(self):
        from control_plane.models import AuditEvent, OutboxEvent, Project

        path = f"/v1/organizations/{self.org_id}/projects"
        headers = {"Idempotency-Key": "project-create-1"}
        first = self.client.post(path, json={"name": "New App"}, headers=headers)
        self.assertEqual(201, first.status_code, first.text)
        again = self.client.post(path, json={"name": "New App"}, headers=headers)
        self.assertEqual(first.json(), again.json())
        changed = self.client.post(path, json={"name": "Other App"}, headers=headers)
        self.assertEqual(409, changed.status_code)
        self.assertEqual(422, self.client.post(path, json={"name": "No Key"}).status_code)
        with Session(self.engine) as session:
            self.assertEqual(1, len(session.scalars(select(Project).where(Project.name == "New App")).all()))
            self.assertEqual(1, len(session.scalars(select(AuditEvent).where(
                AuditEvent.action == "project.create")).all()))
            self.assertEqual(1, len(session.scalars(select(OutboxEvent).where(
                OutboxEvent.kind == "project.create")).all()))

    def test_cancel_is_idempotent_and_revokes_grants_once(self):
        from control_plane.models import AuditEvent, OutboxEvent, ScanState

        with Session(self.engine) as session:
            scan = session.get(Scan, self.scan_id)
            scan.state = ScanState.AUTHORIZED
            session.commit()
        path = f"/v1/organizations/{self.org_id}/scans/{self.scan_id}/cancel"
        headers = {"Idempotency-Key": "cancel-1"}
        first = self.client.post(path, headers=headers)
        self.assertEqual(200, first.status_code, first.text)
        again = self.client.post(path, headers=headers)
        self.assertEqual(first.json(), again.json())
        self.assertEqual(422, self.client.post(path).status_code)
        with Session(self.engine) as session:
            self.assertEqual(1, len(session.scalars(select(AuditEvent).where(
                AuditEvent.action == "scan.cancel")).all()))
            self.assertEqual(1, len(session.scalars(select(OutboxEvent).where(
                OutboxEvent.kind == "scan.cancel")).all()))

    def test_sse_replays_only_events_after_last_event_id(self):
        from control_plane.events import append_visible_event

        with Session(self.engine) as session:
            append_visible_event(session, self.scan_id, self.org_id, "intake", "First update")
            append_visible_event(session, self.scan_id, self.org_id, "scanner", "Second update")
            session.commit()
        response = self.client.get(
            f"/v1/organizations/{self.org_id}/scans/{self.scan_id}/events?follow=false",
            headers={"Last-Event-ID": "1"},
        )
        self.assertEqual(200, response.status_code)
        self.assertIn("id: 2", response.text)
        self.assertIn("Second update", response.text)
        self.assertNotIn("First update", response.text)

    def test_sse_denies_foreign_organization(self):
        response = self.client.get(
            f"/v1/organizations/{self.other_org_id}/scans/{self.scan_id}/events?follow=false"
        )
        self.assertEqual(404, response.status_code)

    def test_post_scan_is_idempotent_and_tenant_scoped(self):
        path = f"/v1/organizations/{self.org_id}/projects/{self.project_id}/scans"
        body = {
            "source_artifact_id": self.artifact_id,
            "scope_note": "owned source for static review",
            "profile": "standard",
            "authorized": True,
        }
        headers = {"Idempotency-Key": "api-create-1"}
        first = self.client.post(path, json=body, headers=headers)
        self.assertEqual(201, first.status_code, first.text)
        self.assertEqual("authorized", first.json()["state"])
        again = self.client.post(path, json=body, headers=headers)
        self.assertEqual(first.json(), again.json())
        changed = self.client.post(path, json={**body, "profile": "deep"}, headers=headers)
        self.assertEqual(400, changed.status_code)
        foreign = self.client.post(
            f"/v1/organizations/{self.other_org_id}/projects/{self.foreign_id}/scans",
            json=body, headers={"Idempotency-Key": "api-create-foreign"},
        )
        self.assertEqual(400, foreign.status_code)

    def test_local_hexstrike_requires_live_worker_heartbeat(self):
        from control_plane.local_hexstrike_readiness import publish_local_heartbeat

        settings = self.client.app.state.settings
        settings.local_static_enabled = False
        settings.local_hexstrike_enabled = True
        path = f"/v1/organizations/{self.org_id}/projects/{self.project_id}/scans"
        body = {"source_artifact_id": self.artifact_id, "scope_note": "owned source",
                "profile": "quick", "authorized": True}
        self.assertFalse(self.client.get("/v1/capabilities").json()["source_scans_available"])
        self.assertEqual(503, self.client.post(path, json=body,
                         headers={"Idempotency-Key": "local-no-worker"}).status_code)
        with Session(self.engine) as session:
            publish_local_heartbeat(session, str(uuid.uuid4()))
            session.commit()
        self._authorize_org()
        self.assertTrue(self.client.get("/v1/capabilities").json()["source_scans_available"])
        created = self.client.post(path, json=body,
                                   headers={"Idempotency-Key": "local-live-worker"})
        self.assertEqual(201, created.status_code, created.text)
        with Session(self.engine) as session:
            self.assertEqual("hexstrike_local", session.get(Scan, created.json()["id"]).execution_backend)

    def test_org_authorization_revokes_pending_native_scan(self):
        from control_plane.local_hexstrike_readiness import publish_local_heartbeat
        from control_plane.models import ScanState

        settings = self.client.app.state.settings
        settings.local_static_enabled = False
        settings.local_hexstrike_enabled = True
        with Session(self.engine) as session:
            publish_local_heartbeat(session, str(uuid.uuid4()))
            session.commit()
        path = f"/v1/organizations/{self.org_id}/projects/{self.project_id}/scans"
        body = {"source_artifact_id": self.artifact_id, "scope_note": "owned source",
                "profile": "quick", "authorized": False}
        denied = self.client.post(path, json=body, headers={"Idempotency-Key": "before-org-auth"})
        self.assertEqual(400, denied.status_code)
        authorization_id = self._authorize_org()
        created = self.client.post(path, json=body,
                                   headers={"Idempotency-Key": "after-org-auth"})
        self.assertEqual(201, created.status_code, created.text)
        scan_id = created.json()["id"]
        with Session(self.engine) as session:
            self.assertEqual(authorization_id, session.get(Scan, scan_id).authorization_id)
        revoked = self.client.delete(
            f"/v1/organizations/{self.org_id}/assessment-authorization/{authorization_id}")
        self.assertEqual(204, revoked.status_code, revoked.text)
        with Session(self.engine) as session:
            self.assertEqual(ScanState.CANCELLED, session.get(Scan, scan_id).state)
        retry = self.client.post(f"/v1/organizations/{self.org_id}/scans/{scan_id}/retry",
                                 headers={"Idempotency-Key": "retry-without-org-auth"})
        self.assertEqual(403, retry.status_code)

    def test_native_scan_is_persistently_routed_away_from_local_worker(self):
        from control_plane.local_worker import run_once

        path = f"/v1/organizations/{self.org_id}/projects/{self.project_id}/scans"
        body = {"source_artifact_id": self.artifact_id, "scope_note": "owned source",
                "profile": "standard", "authorized": True}
        settings = self.client.app.state.settings
        settings.local_static_enabled = False
        unavailable = self.client.post(path, json=body,
                                       headers={"Idempotency-Key": "native-unavailable"})
        self.assertEqual(503, unavailable.status_code)
        settings.native_runner_ready = True
        self.assertEqual(503, self.client.post(path, json=body,
                         headers={"Idempotency-Key": "native-no-worker"}).status_code)
        with Session(self.engine) as session:
            session.add(NativeRunnerWorker(id=str(uuid.uuid4()), heartbeat_at=utcnow(),
                                           source_ready=True, url_ready=False))
            session.commit()
        self._authorize_org()
        created = self.client.post(path, json=body,
                                   headers={"Idempotency-Key": "native-ready"})
        self.assertEqual(201, created.status_code, created.text)
        with Session(self.engine) as session:
            scan = session.get(Scan, created.json()["id"])
            self.assertEqual("hexstrike", scan.execution_backend)
        with self.assertRaisesRegex(ValueError, "authorized static scan not found"):
            run_once(self.engine, self.org_id, created.json()["id"], b"k" * 32,
                     None, None, self.artifact_dir)
        with Session(self.engine) as session:
            from control_plane.models import ScanState
            session.get(Scan, created.json()["id"]).state = ScanState.FAILED
            session.commit()
        retried = self.client.post(
            f"/v1/organizations/{self.org_id}/scans/{created.json()['id']}/retry",
            headers={"Idempotency-Key": "retry-native"},
        )
        self.assertEqual(201, retried.status_code, retried.text)
        with Session(self.engine) as session:
            self.assertEqual("hexstrike", session.get(Scan, retried.json()["id"]).execution_backend)

    def test_web_scan_gate_and_verified_url_only_submission(self):
        prefix = f"/v1/organizations/{self.org_id}/projects/{self.project_id}"
        url_body = {"target_url": "https://example.com/app", "scope_note": "owned website",
                    "profile": "standard", "authorized": True}
        self.assertFalse(self.client.get("/v1/capabilities").json()["web_scans_available"])
        self.assertEqual(503, self.client.post(f"{prefix}/scans", json=url_body,
                         headers={"Idempotency-Key": "url-disabled"}).status_code)
        self.client.app.state.settings.dynamic_scans_enabled = True
        self.client.app.state.settings.local_static_enabled = False
        self.client.app.state.settings.native_runner_ready = True
        with Session(self.engine) as session:
            session.add(NativeRunnerWorker(id=str(uuid.uuid4()), heartbeat_at=utcnow(),
                                           source_ready=True, url_ready=True))
            session.commit()
        proof = self.client.post(f"{prefix}/web-target-proofs",
                                 json={"target_url": url_body["target_url"]})
        self.assertEqual(201, proof.status_code, proof.text)
        proof_data = proof.json()
        from control_plane.web_targets import verify_web_proof as real_verify
        def verified(session, organization_id, project_id, actor_id, proof_id):
            return real_verify(session, organization_id, project_id, actor_id, proof_id,
                               fetcher=lambda _origin, _proof_id: proof_data["token"].encode())
        with patch("control_plane.app.verify_web_proof", side_effect=verified):
            response = self.client.post(f"{prefix}/web-target-proofs/{proof_data['id']}/verify")
        self.assertEqual(200, response.status_code, response.text)
        self._authorize_org()
        created = self.client.post(f"{prefix}/scans",
            json={**url_body, "web_target_proof_id": proof_data["id"]},
            headers={"Idempotency-Key": "url-enabled"})
        self.assertEqual(201, created.status_code, created.text)
        scan = self.client.get(f"/v1/organizations/{self.org_id}/scans/{created.json()['id']}")
        self.assertEqual("https://example.com/app", scan.json()["target_url"])
        self.assertTrue(scan.json()["dynamic_authorized"])

    def test_local_upload_to_authorized_scan(self):
        payload = b"PK\x03\x04fixture"
        prefix = f"/v1/organizations/{self.org_id}"
        grant = self.client.post(
            f"{prefix}/projects/{self.project_id}/uploads",
            json={"content_type": "application/zip", "declared_bytes": len(payload)},
            headers={"Idempotency-Key": "local-upload"},
        )
        self.assertEqual(201, grant.status_code, grant.text)
        grant_id = grant.json()["id"]
        uploaded = self.client.put(
            f"{prefix}/uploads/{grant_id}", content=payload,
            headers={"Content-Type": "application/zip"},
        )
        self.assertEqual(204, uploaded.status_code, uploaded.text)
        digest = hashlib.sha256(payload).hexdigest()
        finalized = self.client.post(
            f"{prefix}/uploads/{grant_id}/finalize", json={"sha256": digest},
        )
        self.assertEqual(201, finalized.status_code, finalized.text)
        scan = self.client.post(
            f"{prefix}/projects/{self.project_id}/scans",
            json={
                "source_artifact_id": finalized.json()["id"], "scope_note": "owned fixture",
                "profile": "standard", "authorized": True,
            },
            headers={"Idempotency-Key": "local-scan"},
        )
        self.assertEqual(201, scan.status_code, scan.text)
        self.assertEqual("authorized", scan.json()["state"])
        foreign_upload = self.client.put(
            f"/v1/organizations/{self.other_org_id}/uploads/{grant_id}", content=payload,
            headers={"Content-Type": "application/zip"},
        )
        self.assertEqual(404, foreign_upload.status_code)

    def test_rejected_size_does_not_leave_partial_upload(self):
        prefix = f"/v1/organizations/{self.org_id}"
        grant = self.client.post(
            f"{prefix}/projects/{self.project_id}/uploads",
            json={"content_type": "application/zip", "declared_bytes": 3},
            headers={"Idempotency-Key": "oversized-upload"},
        )
        grant_id = grant.json()["id"]
        rejected = self.client.put(
            f"{prefix}/uploads/{grant_id}", content=b"oversized",
            headers={"Content-Type": "application/zip"},
        )
        self.assertEqual(400, rejected.status_code)
        accepted = self.client.put(
            f"{prefix}/uploads/{grant_id}", content=b"abc",
            headers={"Content-Type": "application/zip"},
        )
        self.assertEqual(204, accepted.status_code)

    def test_findings_and_report_are_tenant_scoped(self):
        with Session(self.engine) as session:
            session.add(ScanFinding(
                organization_id=self.org_id, scan_id=self.scan_id,
                state="detected", source="sca", dependency="Flask@2.0.3",
                advisory_id="CVE-2024-0001", source_manifest="requirements.txt",
                scanner_version="2.0", database_version="fixture", scanner_output_sha256="d" * 64,
            ))
            session.add(ScanReport(
                organization_id=self.org_id, scan_id=self.scan_id,
                markdown="# Static report\n", sha256="e" * 64,
            ))
            session.commit()
        prefix = f"/v1/organizations/{self.org_id}/scans/{self.scan_id}"
        findings = self.client.get(f"{prefix}/findings")
        self.assertEqual(200, findings.status_code)
        self.assertEqual("detected", findings.json()[0]["state"])
        report = self.client.get(f"{prefix}/report")
        self.assertEqual(200, report.status_code)
        self.assertIn("Static report", report.json()["markdown"])
        foreign = self.client.get(
            f"/v1/organizations/{self.other_org_id}/scans/{self.scan_id}/report"
        )
        self.assertEqual(404, foreign.status_code)

    def test_scan_questions_read_persisted_state_only(self):
        path = f"/v1/organizations/{self.org_id}/scans/{self.scan_id}/questions"
        response = self.client.post(path, json={"question": "What is the scan status?"})
        self.assertEqual(200, response.status_code)
        self.assertIn("draft", response.json()["answer"])
        unsupported = self.client.post(path, json={"question": "Run a new tool now"})
        self.assertEqual(200, unsupported.status_code)
        self.assertIn("I can answer", unsupported.json()["answer"])
        foreign = self.client.post(
            f"/v1/organizations/{self.other_org_id}/scans/{self.scan_id}/questions",
            json={"question": "status"},
        )
        self.assertEqual(404, foreign.status_code)


if __name__ == "__main__":
    unittest.main()

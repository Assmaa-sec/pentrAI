"""Opt-in real Docker vertical: authenticated upload to native MCP finding."""

from __future__ import annotations

from io import BytesIO
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
import threading
import time
import unittest
from zipfile import ZipFile

from sqlalchemy.orm import Session

from control_plane.local_hexstrike_worker import run_once
from control_plane.local_hexstrike_readiness import publish_local_heartbeat
from control_plane.auth import current_actor, mint_local_token
from control_plane.local_store import LocalObjectStore
from control_plane.models import OrganizationCreditAccount, RunnerLease, Scan, ScanFinding, ScanState, User
from runner.assessment_smoke import FixtureModel
from pentrai_pipeline.agents.llm import LLMClient
from pentrai_pipeline.config import LLMSettings


@unittest.skipUnless(os.getenv("PENTRAI_DOCKER_INTEGRATION") == "true", "requires local Docker image")
class LocalHexStrikeDockerTest(unittest.TestCase):
    def setUp(self):
        from tests.test_control_plane_api import ControlPlaneApiTests
        self.api = ControlPlaneApiTests(methodName="test_local_upload_to_authorized_scan")
        self.api.setUp()
        self.api.client.app.state.settings.local_static_enabled = False
        self.api.client.app.state.settings.local_hexstrike_enabled = True
        self.api.client.app.dependency_overrides.pop(current_actor)
        self.assertEqual(401, self.api.client.get(
            f"/v1/organizations/{self.api.org_id}/projects/{self.api.project_id}").status_code)
        with Session(self.api.engine) as session:
            session.get(User, self.api.user_id).oidc_subject = "urn:pentrai:local|docker-owner"
            publish_local_heartbeat(session, "11111111-1111-4111-8111-111111111111")
            session.commit()
        token = mint_local_token("docker-owner", b"k" * 32, int(time.time()) + 300)
        self.api.client.headers.update({"Authorization": f"Bearer {token}"})
        self.assertEqual(200, self.api.client.get(
            f"/v1/organizations/{self.api.org_id}/projects/{self.api.project_id}").status_code)
        self.api._authorize_org()

    def tearDown(self):
        self.api.tearDown()

    def _upload_scan(self):
        archive_io = BytesIO()
        with ZipFile(archive_io, "w") as archive:
            archive.writestr("app.py", "PASSWORD = 'fixture-password'\n")
        payload = archive_io.getvalue()
        digest = hashlib.sha256(payload).hexdigest()
        prefix = f"/v1/organizations/{self.api.org_id}"
        grant = self.api.client.post(
            f"{prefix}/projects/{self.api.project_id}/uploads",
            json={"content_type": "application/zip", "declared_bytes": len(payload)},
            headers={"Idempotency-Key": "native-docker-upload"})
        self.assertEqual(201, grant.status_code, grant.text)
        uploaded = self.api.client.put(f"{prefix}/uploads/{grant.json()['id']}", content=payload,
                                       headers={"Content-Type": "application/zip"})
        self.assertEqual(204, uploaded.status_code, uploaded.text)
        artifact = self.api.client.post(f"{prefix}/uploads/{grant.json()['id']}/finalize",
                                        json={"sha256": digest})
        self.assertEqual(201, artifact.status_code, artifact.text)
        created = self.api.client.post(
            f"{prefix}/projects/{self.api.project_id}/scans",
            json={"source_artifact_id": artifact.json()["id"], "scope_note": "owned fixture",
                  "profile": "quick", "authorized": True},
            headers={"Idempotency-Key": "native-docker-scan"})
        self.assertEqual(201, created.status_code, created.text)
        return created.json()["id"]

    def test_upload_scan_native_finding(self):
        scan_id = self._upload_scan()
        with Session(self.api.engine) as session:
            self.assertEqual("hexstrike_local", session.get(Scan, scan_id).execution_backend)
        report_id = run_once(self.api.engine, self.api.org_id, scan_id,
                             self.api.client.app.state.settings,
                             LocalObjectStore(self.api.artifact_dir), FixtureModel())
        self.assertTrue(report_id)
        findings = self.api.client.get(f"/v1/organizations/{self.api.org_id}/scans/{scan_id}/findings")
        self.assertEqual(200, findings.status_code, findings.text)
        self.assertEqual("hexstrike", findings.json()[0]["source"])
        self.assertEqual("Hardcoded fixture credential", findings.json()[0]["title"])
        with Session(self.api.engine) as session:
            self.assertEqual(ScanState.COMPLETED, session.get(Scan, scan_id).state)
            self.assertEqual(1, session.query(ScanFinding).filter_by(scan_id=scan_id).count())
            account = session.get(OrganizationCreditAccount, self.api.org_id)
            self.assertGreater(account.spent, 0)
            self.assertEqual(0, account.reserved)

    def test_model_failure_cleans_container_and_allows_retry(self):
        scan_id = self._upload_scan()

        class FailingModel:
            def chat_tools(self, messages, *, tools):
                raise ValueError("owned fixture model failed")

        with self.assertRaisesRegex(ValueError, "owned fixture model failed"):
            run_once(self.api.engine, self.api.org_id, scan_id,
                     self.api.client.app.state.settings,
                     LocalObjectStore(self.api.artifact_dir), FailingModel())
        with Session(self.api.engine) as session:
            scan = session.get(Scan, scan_id)
            lease = session.query(RunnerLease).filter_by(scan_id=scan_id).one()
            self.assertEqual(ScanState.FAILED, scan.state)
            self.assertIsNotNone(lease.cleaned_at)
            self.assertEqual(0, session.query(ScanFinding).filter_by(scan_id=scan_id).count())

    def test_openai_compatible_model_exchange(self):
        scan_id = self._upload_scan()

        class FixtureEndpoint(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                self.server.turns += 1
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.server.turns == 1:
                    assert any(tool["function"]["name"] == "execute_command"
                               for tool in request["tools"])
                    message = {"role": "assistant", "content": None, "tool_calls": [{
                        "id": "fixture-http-1", "type": "function", "function": {
                            "name": "execute_command", "arguments": json.dumps({
                                "command": "grep -n PASSWORD /job/tmp/source/app.py", "use_cache": False})}}]}
                else:
                    tool_result = json.loads(request["messages"][-1]["content"])
                    assert "fixture-password" in tool_result["result_excerpt"]
                    message = {"role": "assistant", "content": json.dumps({"findings": [{
                        "title": "Model endpoint fixture credential", "severity": "low",
                        "explanation": "The source contains a hardcoded fixture credential.",
                        "evidence_sha256": [tool_result["output_sha256"]]}]})}
                response = json.dumps({"choices": [{"message": message}], "usage": {
                    "prompt_tokens": 11, "completion_tokens": 7}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

        server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureEndpoint)
        server.turns = 0
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            model = LLMClient(LLMSettings(base_url=f"http://127.0.0.1:{server.server_port}/v1",
                                          model="owned-fixture", api_key="local-test"))
            run_once(self.api.engine, self.api.org_id, scan_id,
                     self.api.client.app.state.settings,
                     LocalObjectStore(self.api.artifact_dir), model)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.assertEqual(2, server.turns)
        response = self.api.client.get(
            f"/v1/organizations/{self.api.org_id}/scans/{scan_id}/findings")
        self.assertEqual("Model endpoint fixture credential", response.json()[0]["title"])


if __name__ == "__main__":
    unittest.main()

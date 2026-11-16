"""Portable native workflow contract; Docker and native tools are test fixtures.

Uses real API authorization/upload, worker entry point/model selection, loopback
model HTTP, source staging, job/analysis loop, evidence checks, ledger, report
persistence, cleanup state transitions, and dashboard API responses. This does
not exercise a Linux image, MCP transport, or installed security executables.
"""
import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import AsyncMock, patch

from sqlalchemy import select
from sqlalchemy.orm import Session

from control_plane.local_hexstrike_worker import main
from control_plane.models import OrganizationCreditAccount, RunnerLease, Scan, ScanReport, ScanState
from execution_manager.job_agent import run_job
from execution_manager.stage_source import stage_source


class AssessmentWiringTests(unittest.TestCase):
    def setUp(self):
        from tests.test_local_hexstrike_docker import LocalHexStrikeDockerTest
        self.fixture = LocalHexStrikeDockerTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.api = self.fixture.api
        self.scan_id = self.fixture._upload_scan()
        self.path = f"/v1/organizations/{self.api.org_id}/scans/{self.scan_id}"

    def run_workflow(self, *, invalid_findings=False):
        outer = self
        requests = []
        endpoint_errors = []
        calls = []

        class ModelEndpoint(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                try:
                    outer.assertEqual("/v1/chat/completions", self.path)
                    outer.assertEqual("Bearer owned-wiring-key", self.headers["Authorization"])
                    request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    requests.append(request)
                    outer.assertEqual("owned-wiring-model", request["model"])
                    outer.assertTrue(any(tool["function"]["name"] == "execute_command"
                                         for tool in request["tools"]))
                    if len(requests) == 1:
                        outer.assertIn("app.py", request["messages"][-1]["content"])
                        message = {"role": "assistant", "content": None, "tool_calls": [{
                            "id": "owned-wiring-call", "type": "function", "function": {
                                "name": "execute_command", "arguments": json.dumps({
                                    "command": "inspect-owned-fixture", "use_cache": False})}}]}
                    else:
                        outer.assertEqual(2, len(requests))
                        tool_result = json.loads(request["messages"][-1]["content"])
                        outer.assertIn("fixture-password", tool_result["result_excerpt"])
                        message = {"role": "assistant", "content": json.dumps({"findings": [{
                            "title": "Owned wiring finding", "severity": "low",
                            "explanation": "An owned fixture credential appears in the source.",
                            "evidence_sha256": ["f" * 64 if invalid_findings
                                                else tool_result["output_sha256"]]}]})}
                    body = json.dumps({"choices": [{"message": message}],
                                       "usage": {"prompt_tokens": 11, "completion_tokens": 7}}).encode()
                    status = 200
                except Exception as exc:
                    endpoint_errors.append(exc)
                    body, status = b'{"error":"owned fixture assertion failed"}', 500
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        def assess(prepared, archive, model, **kwargs):
            outer.assertFalse(kwargs["is_cancelled"]())
            with TemporaryDirectory(prefix="assessment-wiring-", dir=".tmp") as directory:
                workspace = Path(directory).resolve()
                archive_path = workspace / "source.zip"
                archive_path.write_bytes(archive)
                source, _ = stage_source(archive_path, workspace,
                                         prepared.scope.source_digest, len(archive))

                class OwnedToolSession:
                    def __init__(self, bridge_path, server_url):
                        outer.assertEqual("pentrai_mcp.py", bridge_path.name)
                        outer.assertEqual("http://127.0.0.1:8888", server_url)

                    async def __aenter__(self):
                        return self

                    async def __aexit__(self, *_exc):
                        pass

                    async def list_tools(self):
                        return [{"name": "execute_command", "inputSchema": {
                            "type": "object", "properties": {
                                "command": {"type": "string"}, "use_cache": {"type": "boolean"}},
                            "required": ["command"]}}]

                    async def call_tool(self, name, arguments):
                        outer.assertEqual("execute_command", name)
                        outer.assertEqual({"command": "inspect-owned-fixture", "use_cache": False}, arguments)
                        calls.append(name)
                        # Read only the known fixture; never execute the proposed command.
                        return {"content": [{"type": "text", "text": (source / "app.py").read_text()}],
                                "isError": False}

                with patch("execution_manager.job_agent.HexStrikeMCP", OwnedToolSession), \
                     patch("execution_manager.job_agent._wait_for_server", new_callable=AsyncMock):
                    return asyncio.run(run_job(prepared.scope, model, source_root=source,
                                               on_stage=kwargs["on_stage"]))

        server = ThreadingHTTPServer(("127.0.0.1", 0), ModelEndpoint)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        catalog = [{"id": "managed", "label": "Owned wiring fixture",
                    "provider_model": "owned-wiring-model",
                    "base_url": f"http://127.0.0.1:{server.server_port}/v1",
                    "key_env": "PENTRAI_LLM_API_KEY",
                    "prompt_credit_rate": 1, "completion_credit_rate": 1}]
        # Keep platform variables needed by the real HTTP/TLS libraries while
        # isolating every application/provider setting from the user's session.
        env = {name: os.environ[name] for name in ("PATH", "SystemRoot", "WINDIR", "TEMP", "TMP")
               if name in os.environ}
        env.update({"PENTRAI_DATABASE_URL": "sqlite+pysqlite:///:memory:",
               "PENTRAI_GRANT_SIGNING_KEY": "k" * 32,
               "PENTRAI_LOCAL_DEV_AUTH": "true", "PENTRAI_LOCAL_HEXSTRIKE_ENABLED": "true",
               "PENTRAI_LOCAL_ARTIFACT_ROOT": str(self.api.artifact_dir),
               "PENTRAI_LLM_API_KEY": "owned-wiring-key",
               "PENTRAI_MODEL_OPTIONS_JSON": json.dumps(catalog)})
        try:
            with patch.dict(os.environ, env, clear=True), \
                 patch("sys.argv", ["worker", "--organization-id", self.api.org_id,
                                    "--scan-id", self.scan_id]), \
                 patch("control_plane.local_hexstrike_worker.create_engine", return_value=self.api.engine), \
                 patch("control_plane.local_hexstrike_worker.check_local_dependencies"), \
                 patch("control_plane.local_hexstrike_worker._docker_assessment", side_effect=assess), \
                 patch("control_plane.local_hexstrike_worker.LocalDockerClient.delete_namespace") as cleanup, \
                 patch("builtins.print"):
                if invalid_findings:
                    with patch("sys.stderr"), self.assertRaises(SystemExit) as error:
                        main()
                    self.assertEqual(1, error.exception.code)
                else:
                    main()
                cleanup.assert_called_once()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.assertEqual([], endpoint_errors)
        self.assertEqual(2, len(requests))
        self.assertEqual(["execute_command"], calls)

    def test_upload_to_worker_model_evidence_report_and_dashboard(self):
        self.run_workflow()
        response = self.api.client.get(self.path)
        self.assertEqual(200, response.status_code)
        self.assertEqual("completed", response.json()["state"])
        self.assertEqual("completed", response.json()["progress"]["health"])
        self.assertTrue(response.json()["progress"]["report_ready"])
        findings = self.api.client.get(self.path + "/findings")
        self.assertEqual(200, findings.status_code)
        self.assertEqual("Owned wiring finding", findings.json()[0]["title"])
        self.assertEqual("detected", findings.json()[0]["state"])
        report = self.api.client.get(self.path + "/report")
        self.assertEqual(200, report.status_code)
        self.assertIn("Owned wiring finding", report.json()["markdown"])
        for extension, signature in (("pdf", b"%PDF-"), ("docx", b"PK")):
            exported = self.api.client.get(self.path + "/report." + extension)
            self.assertEqual(200, exported.status_code)
            self.assertTrue(exported.content.startswith(signature))
        events = self.api.client.get(self.path + "/events?follow=false")
        self.assertEqual(200, events.status_code)
        self.assertIn("Assessment completed", events.text)
        self.assertNotIn("owned-wiring-key", events.text)
        with Session(self.api.engine) as session:
            scan = session.get(Scan, self.scan_id)
            self.assertEqual("hexstrike_local", scan.execution_backend)
            lease = session.scalar(select(RunnerLease).where(RunnerLease.scan_id == self.scan_id))
            self.assertIsNotNone(lease.cleaned_at)
            account = session.get(OrganizationCreditAccount, self.api.org_id)
            self.assertEqual((36, 0), (account.spent, account.reserved))

    def test_unbound_model_evidence_fails_and_dashboard_explains_failure(self):
        self.run_workflow(invalid_findings=True)
        response = self.api.client.get(self.path)
        self.assertEqual(200, response.status_code)
        self.assertEqual("failed", response.json()["state"])
        self.assertEqual("failed", response.json()["progress"]["health"])
        self.assertFalse(response.json()["progress"]["report_ready"])
        self.assertTrue(response.json()["progress"]["message"])
        self.assertEqual([], self.api.client.get(self.path + "/findings").json())
        with Session(self.api.engine) as session:
            self.assertEqual(ScanState.FAILED, session.get(Scan, self.scan_id).state)
            self.assertIsNone(session.scalar(select(ScanReport).where(ScanReport.scan_id == self.scan_id)))
            account = session.get(OrganizationCreditAccount, self.api.org_id)
            self.assertEqual((36, 0), (account.spent, account.reserved))

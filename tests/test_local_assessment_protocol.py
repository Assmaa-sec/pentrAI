"""Exercise bounded container stdio and stalled model calls without Docker."""
from datetime import timedelta
from io import BytesIO
import json
import struct
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from control_plane.assessment_health import AssessmentFailure
from control_plane.local_hexstrike_worker import _docker_assessment
from control_plane.models import utcnow


class Process:
    def __init__(self, lines):
        self.stdin = BytesIO()
        self.stdout = BytesIO(b"".join(lines))
        self.returncode = None
        self.killed = False

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


def prepared(seconds=60):
    return SimpleNamespace(lease=SimpleNamespace(namespace="scan-" + "a" * 32),
        scope=SimpleNamespace(scan_id="scan", organization_id="org", lease_id="lease",
            source_digest="a" * 64, scope_digest="b" * 64, source_present=True,
            target_url=None, scope_note="owned source", profile="quick",
            expires_at=utcnow() + timedelta(seconds=seconds)))


class LocalAssessmentProtocolTests(unittest.TestCase):
    def execute(self, process, model=None, scope=None, **kwargs):
        with patch("control_plane.local_hexstrike_worker.subprocess.Popen", return_value=process):
            return _docker_assessment(scope or prepared(), b"zip", model or Mock(),
                image="pentrai/hexstrike-runner:local", docker="docker", **kwargs)

    def test_stage_and_error_messages_are_allowlisted(self):
        stage = Mock()
        process = Process([b"PENTRAI_STATUS archive\n", b"PENTRAI_ERROR archive\n"])
        with self.assertRaisesRegex(AssessmentFailure, "archive could not be prepared"):
            self.execute(process, on_stage=stage)
        stage.assert_called_once_with("archive")
        for message in (b"PENTRAI_STATUS private-source-content\n",
                        b"PENTRAI_ERROR SECRET-API-KEY\n", b"unexpected bytes\n", b""):
            with self.subTest(message=message):
                with self.assertRaises(ValueError) as error:
                    self.execute(Process([message]))
                self.assertNotIn("SECRET-API-KEY", str(error.exception))
                self.assertNotIn("private-source", str(error.exception))

    def test_success_keeps_existing_result_protocol(self):
        process = Process([b'PENTRAI_RESULT {"owned": true}\n'])
        self.assertEqual({"owned": True}, self.execute(process))
        self.assertTrue(process.stdin.closed)
        self.assertTrue(process.stdout.closed)

    def test_partial_pipe_writes_do_not_truncate_the_uploaded_source(self):
        class ShortWriter(BytesIO):
            captured = b""

            def write(self, data):
                return super().write(data[:3])

            def close(self):
                self.captured = self.getvalue()
                super().close()

        process = Process([b'PENTRAI_RESULT {"owned": true}\n'])
        process.stdin = ShortWriter()
        self.execute(process)
        payload = process.stdin.captured
        self.assertGreater(len(payload), 4)
        header_size = struct.unpack("!I", payload[:4])[0]
        header = json.loads(payload[4:4 + header_size])
        self.assertEqual(3, header["archive_bytes"])
        self.assertEqual(b"zip", payload[4 + header_size:])

    def test_stalled_model_is_bounded_by_job_deadline(self):
        release = threading.Event()
        done = threading.Event()

        def hang(*args, **kwargs):
            try:
                release.wait(5)
                return SimpleNamespace(message={}, usage={})
            finally:
                done.set()

        model = Mock()
        model.chat_tools.side_effect = hang
        process = Process([b'PENTRAI_MODEL {"messages": [], "tools": [{}]}\n'])
        try:
            with self.assertRaisesRegex(AssessmentFailure, "time limit"):
                self.execute(process, model, prepared(0.1))
            self.assertTrue(process.killed)
        finally:
            release.set()
            self.assertTrue(done.wait(2))

    def test_cancellation_interrupts_waiting_model(self):
        release = threading.Event()
        finished = threading.Event()
        model = Mock()

        def hang(*args, **kwargs):
            try:
                release.wait(5)
                return SimpleNamespace(message={}, usage={})
            finally:
                finished.set()

        model.chat_tools.side_effect = hang
        process = Process([b'PENTRAI_MODEL {"messages": [], "tools": [{}]}\n'])
        try:
            with self.assertRaises(AssessmentFailure):
                self.execute(process, model, is_cancelled=lambda: True)
            self.assertTrue(process.killed)
        finally:
            release.set()
            self.assertTrue(finished.wait(2))

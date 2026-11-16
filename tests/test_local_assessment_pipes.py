"""Real subprocess pipes, using only an owned protocol peer (no security tools)."""
import hashlib
import random
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

from control_plane.assessment_health import AssessmentFailure
from control_plane.local_hexstrike_worker import _docker_assessment
from pentrai_pipeline.agents.llm import LLMToolTurn
from tests.test_local_assessment_protocol import prepared


PEER = r'''
import hashlib, json, struct, sys
reader, writer = sys.stdin.buffer, sys.stdout.buffer
fragment, turns = int(sys.argv[1]), int(sys.argv[2])
def exact(count):
    data = bytearray()
    while len(data) < count:
        chunk = reader.read(count - len(data))
        if not chunk:
            raise RuntimeError("truncated owned protocol input")
        data.extend(chunk)
    return bytes(data)
def emit(prefix, value):
    data = prefix + value + b"\n"
    for pos in range(0, len(data), fragment):
        writer.write(data[pos:pos + fragment])
        writer.flush()
count = struct.unpack("!I", exact(4))[0]
header = json.loads(exact(count))
archive = exact(header["archive_bytes"])
digest = hashlib.sha256(archive).hexdigest()
assert digest == header["scope"]["source_digest"]
emit(b"PENTRAI_STATUS ", b"archive")
emit(b"PENTRAI_STATUS ", b"tools")
for index in range(turns):
    request = {"messages": [{"role": "user", "content": "owned turn " + str(index)}],
               "tools": [{"type": "function", "function": {"name": "owned_tool"}}]}
    emit(b"PENTRAI_MODEL ", json.dumps(request).encode())
    line = reader.readline()
    assert line.startswith(b"PENTRAI_TURN ")
    result = json.loads(line[len(b"PENTRAI_TURN "):])
    assert result["message"]["content"] == "Owned response: caf\u00e9 \u4f60\u597d"
    assert result["usage"]["total_tokens"] == 2
emit(b"PENTRAI_RESULT ", json.dumps({"source_sha256": digest, "turns": turns}).encode())
'''


class LocalAssessmentPipeTests(unittest.TestCase):
    def launch(self, code, args=()):
        real_popen = subprocess.Popen
        processes = []

        def peer(_command, **kwargs):
            process = real_popen([sys.executable, "-u", "-c", code, *args], **kwargs)
            processes.append(process)
            return process

        return peer, processes

    def test_fragmented_round_trips_across_payload_sizes(self):
        rng = random.Random(20261115)
        for size in (1, 1023, 65535, 262144, 2 * 1024 * 1024):
            for fragment in (1, 1024):
                for turns in (1, 3):
                    with self.subTest(size=size, fragment=fragment, turns=turns):
                        archive = rng.randbytes(size)
                        job = prepared()
                        job.scope.source_digest = hashlib.sha256(archive).hexdigest()
                        model = Mock()
                        model.chat_tools.return_value = LLMToolTurn(
                            {"role": "assistant", "content": "Owned response: caf\u00e9 \u4f60\u597d"},
                            {"total_tokens": 2})
                        peer, processes = self.launch(PEER, (str(fragment), str(turns)))
                        with patch("control_plane.local_hexstrike_worker.subprocess.Popen", side_effect=peer):
                            result = _docker_assessment(job, archive, model,
                                image="pentrai/hexstrike-runner:local", docker="docker")
                        self.assertEqual({"source_sha256": job.scope.source_digest,
                                          "turns": turns}, result)
                        self.assertEqual(turns, model.chat_tools.call_count)
                        self.assertEqual(0, processes[0].poll())

    def test_silent_process_is_killed_at_deadline(self):
        peer, processes = self.launch("import time; time.sleep(30)")
        with patch("control_plane.local_hexstrike_worker.subprocess.Popen", side_effect=peer):
            with self.assertRaisesRegex(AssessmentFailure, "time limit"):
                _docker_assessment(prepared(0.2), b"owned", Mock(),
                    image="pentrai/hexstrike-runner:local", docker="docker")
        self.assertIsNotNone(processes[0].poll())
        self.assertTrue(processes[0].stdin.closed)
        self.assertTrue(processes[0].stdout.closed)

    def test_crashed_process_cannot_produce_a_success_result(self):
        peer, processes = self.launch("raise SystemExit(7)")
        with patch("control_plane.local_hexstrike_worker.subprocess.Popen", side_effect=peer):
            with self.assertRaises(ValueError):
                _docker_assessment(prepared(), b"owned", Mock(),
                    image="pentrai/hexstrike-runner:local", docker="docker")
        self.assertIsNotNone(processes[0].poll())

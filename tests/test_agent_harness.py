from __future__ import annotations

import unittest

from pentrai_pipeline.harness import AgentHarness, HarnessPolicy, SandboxTarget, ScanProfile, ToolRequest
from pentrai_pipeline.harness.contracts import ResultStatus


class FakeTransport:
    def __init__(self):
        self.calls = []

    def call(self, tool, **params):
        self.calls.append((tool, params))
        return {"success": True, "stdout": "found AKIAIOSFODNN7EXAMPLE"}


class AgentHarnessTests(unittest.TestCase):
    def setUp(self):
        self.transport = FakeTransport()
        self.policy = HarnessPolicy(
            scan_id="scan-1",
            profile=ScanProfile.STANDARD,
            authorized=True,
            allow_dynamic_validation=False,
            max_tool_calls=2,
        )
        self.harness = AgentHarness(
            self.policy,
            SandboxTarget("http://target:8000", "pentrai_scan_1", "scan-1"),
            self.transport,
        )

    def test_harness_injects_the_only_allowed_target(self):
        result = self.harness.execute(ToolRequest("http_probe"))

        self.assertEqual(ResultStatus.SUCCEEDED, result.status)
        self.assertEqual("httpx", self.transport.calls[0][0])
        self.assertEqual("http://target:8000", self.transport.calls[0][1]["target"])
        self.assertTrue(self.transport.calls[0][1]["tech_detect"])
        self.assertIn("[REDACTED]", result.redacted_output)

    def test_harness_refuses_agent_supplied_target(self):
        result = self.harness.execute(ToolRequest("http_probe", {"url": "https://outside.example"}))

        self.assertEqual(ResultStatus.DENIED, result.status)
        self.assertEqual([], self.transport.calls)

    def test_harness_refuses_raw_tool_flags(self):
        result = self.harness.execute(ToolRequest("port_scan", {"additional_args": "; whoami"}))

        self.assertEqual(ResultStatus.DENIED, result.status)
        self.assertEqual([], self.transport.calls)

    def test_profile_and_active_validation_are_enforced(self):
        result = self.harness.execute(ToolRequest("template_scan"))

        self.assertEqual(ResultStatus.DENIED, result.status)
        self.assertEqual([], self.transport.calls)

    def test_budget_stops_additional_calls(self):
        self.harness.execute(ToolRequest("http_probe"))
        self.harness.execute(ToolRequest("port_scan"))
        result = self.harness.execute(ToolRequest("http_probe"))

        self.assertEqual(ResultStatus.BUDGET_EXHAUSTED, result.status)
        self.assertEqual(2, len(self.transport.calls))


if __name__ == "__main__":
    unittest.main()

"""Compatibility facade for a job-owned, policy-limited tool harness.

There is no raw legacy HTTP access here. The harness injects the private target,
applies a reviewed catalog, and bounds and redacts observations.
"""

from __future__ import annotations

from typing import Any

from ..config import Settings
from ..harness.agent_harness import AgentHarness
from ..harness.contracts import ToolRequest


class PentrAIClient:
    def __init__(self, settings: Settings, harness: AgentHarness | None = None):
        self.settings = settings
        self.harness = harness

    def call(self, tool: str, **params: Any) -> dict[str, Any]:
        """Invoke a reviewed friendly tool name without caller-supplied parameters."""
        if self.harness is None:
            raise PermissionError("a job-owned policy harness is required")
        if params:
            raise ValueError("raw tool parameters are forbidden; use reviewed ToolRequest contracts")
        result = self.harness.execute(ToolRequest(tool=tool))
        return {"success": result.status.value == "succeeded", "status": result.status.value,
                "summary": result.summary, "output": result.redacted_output,
                "truncated": result.truncated}

    def port_scan(self, target: str, **kw: Any) -> dict[str, Any]:
        if self.harness is None or target != self.harness.target.hostname or kw:
            raise ValueError("port scan target or parameters are outside the job policy")
        return self.call("port_scan")

    def http_probe(self, url: str, **kw: Any) -> dict[str, Any]:
        if self.harness is None or url != self.harness.target.base_url or kw:
            raise ValueError("HTTP probe target or parameters are outside the job policy")
        return self.call("http_probe")

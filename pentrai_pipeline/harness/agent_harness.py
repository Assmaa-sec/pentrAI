"""The only agent-facing interface to the PentrAI tool runner.

This module deliberately does not call an LLM. Providers propose ``ToolRequest``
objects through a separate adapter; the harness makes the deterministic policy
decision and returns bounded, redacted observations for the next reasoning step.
"""

from __future__ import annotations

import re
from typing import Any, Protocol

from .contracts import (
    AgentContext,
    Decision,
    HarnessEvent,
    HarnessPolicy,
    ResultStatus,
    SandboxTarget,
    ToolRequest,
    ToolResult,
)
from .policy import TOOL_CATALOG, catalog_for, decide_request


class ToolTransport(Protocol):
    """Private runner adapter; implementations may call PentrAI over localhost."""

    def call(self, tool: str, **params: Any) -> dict[str, Any]:
        """Return a JSON-shaped tool result without raising for ordinary failures."""


_SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*[^\s<>]{6,}"),
)


class AgentHarness:
    def __init__(self, policy: HarnessPolicy, target: SandboxTarget, transport: ToolTransport):
        if policy.scan_id != target.scan_id:
            raise ValueError("policy and sandbox target must belong to the same scan")
        self.policy = policy
        self.target = target
        self.transport = transport
        self._calls_used = 0
        self.events: list[HarnessEvent] = []

    @property
    def calls_remaining(self) -> int:
        return max(0, self.policy.max_tool_calls - self._calls_used)

    def agent_context(self, stack: list[str] | tuple[str, ...] = ()) -> AgentContext:
        """Return model-safe job context and catalog descriptions."""
        return AgentContext(
            scan_id=self.policy.scan_id,
            profile=self.policy.profile,
            target_url=self.target.base_url,
            stack=tuple(stack),
            allowed_tools=catalog_for(self.policy),
            credential_profiles=tuple(sorted(self.policy.credential_profiles)),
            remaining_tool_calls=self.calls_remaining,
        )

    def execute(self, request: ToolRequest) -> ToolResult:
        decision = decide_request(request, self.policy, self.target, self._calls_used)
        self.events.append(
            HarnessEvent(
                scan_id=self.policy.scan_id,
                request_id=request.id,
                tool=request.tool,
                decision=decision.decision,
                reason=decision.reason,
            )
        )
        if decision.decision is Decision.DENY:
            status = ResultStatus.BUDGET_EXHAUSTED if self._calls_used >= self.policy.max_tool_calls else ResultStatus.DENIED
            result = ToolResult(request.id, request.tool, status, decision.reason)
            self._record_result(request, decision.reason, status)
            return result

        definition = TOOL_CATALOG[request.tool]
        self._calls_used += 1
        try:
            raw = self.transport.call(definition.server_tool, **decision.injected_parameters)
        except Exception as exc:  # transport adapter must not let tool failures crash the job
            result = ToolResult(
                request.id,
                request.tool,
                ResultStatus.TRANSPORT_ERROR,
                f"runner transport failed: {type(exc).__name__}",
            )
            self._record_result(request, result.summary, result.status)
            return result

        success = bool(raw.get("success", False))
        output = _extract_output(raw)
        redacted, truncated = _redact_and_limit(output, self.policy.max_output_chars)
        summary = "tool completed" if success else str(raw.get("error") or raw.get("stderr") or "tool reported failure")
        result = ToolResult(
            request_id=request.id,
            tool=request.tool,
            status=ResultStatus.SUCCEEDED if success else ResultStatus.FAILED,
            summary=summary[:512],
            raw=raw,
            redacted_output=redacted,
            truncated=truncated,
        )
        self._record_result(request, result.summary, result.status)
        return result

    def _record_result(self, request: ToolRequest, reason: str, status: ResultStatus) -> None:
        self.events.append(
            HarnessEvent(
                scan_id=self.policy.scan_id,
                request_id=request.id,
                tool=request.tool,
                decision=Decision.ALLOW,
                reason=reason,
                result_status=status,
            )
        )


def _extract_output(raw: dict[str, Any]) -> str:
    for key in ("stdout", "output", "result", "data", "stderr", "error"):
        value = raw.get(key)
        if isinstance(value, str):
            return value
    return ""


def _redact_and_limit(text: str, limit: int) -> tuple[str, bool]:
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    text = text.replace("\x00", "")
    if len(text) <= limit:
        return text, False
    return text[:limit] + "\n[output truncated by harness]", True

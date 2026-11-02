"""Typed contracts for the policy-limited agent tool harness.

The model never receives a generic shell or HTTP capability.  It proposes one of
these structured requests, and the harness injects the job-owned target before
delegating to the private PentrAI tool runner.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlparse
import uuid


def _new_id() -> str:
    return uuid.uuid4().hex


class ScanProfile(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


class ToolRisk(str, Enum):
    OBSERVATIONAL = "observational"
    ACTIVE_VALIDATION = "active_validation"


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class ResultStatus(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DENIED = "denied"
    BUDGET_EXHAUSTED = "budget_exhausted"
    TRANSPORT_ERROR = "transport_error"


@dataclass(frozen=True)
class SandboxTarget:
    """The only live system a dynamic tool call may address."""

    base_url: str
    network_name: str
    scan_id: str

    def __post_init__(self) -> None:
        parsed = urlparse(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("sandbox base_url must be an absolute http(s) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("sandbox base_url cannot include credentials, query, or fragment")

    @property
    def hostname(self) -> str:
        return urlparse(self.base_url).hostname or ""

    @property
    def port(self) -> int | None:
        return urlparse(self.base_url).port


@dataclass(frozen=True)
class ToolDefinition:
    """One reviewed PentrAI route exposed to an agent under a friendly name."""

    name: str
    server_tool: str
    target_field: str
    target_kind: str  # "url" or "host"
    risk: ToolRisk
    allowed_parameters: frozenset[str] = frozenset()
    fixed_parameters: dict[str, Any] = field(default_factory=dict)
    description: str = ""


@dataclass(frozen=True)
class HarnessPolicy:
    """Per-scan policy compiled by the control plane, never by the LLM."""

    scan_id: str
    profile: ScanProfile
    authorized: bool
    allow_dynamic_validation: bool
    max_tool_calls: int
    max_output_chars: int = 12_000
    allowed_tools: frozenset[str] = frozenset()
    credential_profiles: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.scan_id:
            raise ValueError("scan_id is required")
        if self.max_tool_calls < 1:
            raise ValueError("max_tool_calls must be positive")
        if self.max_output_chars < 256:
            raise ValueError("max_output_chars must be at least 256")


@dataclass(frozen=True)
class ToolRequest:
    """A structured action proposed by an agent.

    `parameters` must not contain a target, URL, hostname, command, script, or
    filesystem path. The harness owns target injection. In the first release,
    tool flags/templates are policy-owned fixed settings, so a request normally
    carries no parameters at all.
    """

    tool: str
    parameters: dict[str, Any] = field(default_factory=dict)
    rationale: str = ""
    credential_profile: str | None = None
    id: str = field(default_factory=_new_id)


@dataclass(frozen=True)
class ToolDecision:
    request_id: str
    tool: str
    decision: Decision
    reason: str
    injected_parameters: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolResult:
    request_id: str
    tool: str
    status: ResultStatus
    summary: str
    raw: dict[str, Any] = field(default_factory=dict)
    redacted_output: str = ""
    truncated: bool = False


@dataclass(frozen=True)
class HarnessEvent:
    """Append-only audit record. A future control plane persists this verbatim."""

    scan_id: str
    request_id: str
    tool: str
    decision: Decision
    reason: str
    result_status: ResultStatus | None = None


@dataclass(frozen=True)
class AgentContext:
    """Safe context passed to a model or deterministic planner.

    It intentionally contains no provider key, raw credential, host path, or
    legacy PentrAI server address.
    """

    scan_id: str
    profile: ScanProfile
    target_url: str
    stack: tuple[str, ...]
    allowed_tools: tuple[ToolDefinition, ...]
    credential_profiles: tuple[str, ...]
    remaining_tool_calls: int

"""Reviewed tool catalog and deterministic policy checks for agent actions."""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlparse

from .contracts import (
    Decision,
    HarnessPolicy,
    SandboxTarget,
    ScanProfile,
    ToolDecision,
    ToolDefinition,
    ToolRequest,
    ToolRisk,
)


# This catalog is intentionally small. Add tools only after defining their input
# contract, risk level, target semantics, output limits, and regression tests.
TOOL_CATALOG: dict[str, ToolDefinition] = {
    "http_probe": ToolDefinition(
        name="http_probe",
        server_tool="httpx",
        target_field="target",
        target_kind="url",
        risk=ToolRisk.OBSERVATIONAL,
        fixed_parameters={"probe": True, "tech_detect": True},
        description="Check HTTP reachability and identify the web stack.",
    ),
    "port_scan": ToolDefinition(
        name="port_scan",
        server_tool="nmap",
        target_field="target",
        target_kind="host",
        risk=ToolRisk.OBSERVATIONAL,
        description="Map the job-owned target's listening ports and services.",
    ),
    "template_scan": ToolDefinition(
        name="template_scan",
        server_tool="nuclei",
        target_field="target",
        target_kind="url",
        risk=ToolRisk.ACTIVE_VALIDATION,
        fixed_parameters={"severity": "critical,high"},
        description="Run approved validation templates against the sandbox target.",
    ),
    "web_crawl": ToolDefinition(
        name="web_crawl",
        server_tool="katana",
        target_field="url",
        target_kind="url",
        risk=ToolRisk.OBSERVATIONAL,
        fixed_parameters={"depth": 2, "js_crawl": True},
        description="Discover routes and parameters on the sandbox web application.",
    ),
}

_FORBIDDEN_PARAMETER_NAMES = frozenset(
    {
        "target",
        "targets",
        "url",
        "uri",
        "host",
        "hostname",
        "address",
        "command",
        "script",
        "path",
        "file",
        "filename",
        "directory",
        "cwd",
    }
)


def default_allowed_tools(profile: ScanProfile) -> frozenset[str]:
    if profile is ScanProfile.QUICK:
        return frozenset({"http_probe"})
    if profile is ScanProfile.STANDARD:
        return frozenset({"http_probe", "port_scan", "web_crawl"})
    return frozenset(TOOL_CATALOG)


def catalog_for(policy: HarnessPolicy) -> tuple[ToolDefinition, ...]:
    names = policy.allowed_tools or default_allowed_tools(policy.profile)
    return tuple(TOOL_CATALOG[name] for name in sorted(names) if name in TOOL_CATALOG)


def decide_request(
    request: ToolRequest,
    policy: HarnessPolicy,
    target: SandboxTarget,
    calls_used: int,
) -> ToolDecision:
    """Approve or deny one action without relying on model intent."""
    if not policy.authorized:
        return _deny(request, "scan authorization is missing or expired")
    if calls_used >= policy.max_tool_calls:
        return _deny(request, "tool-call budget exhausted")

    tool = TOOL_CATALOG.get(request.tool)
    if tool is None:
        return _deny(request, "tool is not in the reviewed harness catalog")

    allowed_names = policy.allowed_tools or default_allowed_tools(policy.profile)
    if request.tool not in allowed_names:
        return _deny(request, "tool is not enabled by this scan profile")
    if tool.risk is ToolRisk.ACTIVE_VALIDATION and not policy.allow_dynamic_validation:
        return _deny(request, "active validation requires explicit scan authorization")
    if request.credential_profile and request.credential_profile not in policy.credential_profiles:
        return _deny(request, "credential profile is not approved for this scan")

    given = set(request.parameters)
    if bad := sorted(given & _FORBIDDEN_PARAMETER_NAMES):
        return _deny(request, f"agent may not provide target, command, or path fields: {', '.join(bad)}")
    if unsupported := sorted(given - tool.allowed_parameters):
        return _deny(request, f"unsupported parameters for {request.tool}: {', '.join(unsupported)}")
    if not _safe_parameter_values(request.parameters):
        return _deny(request, "parameters contain an unsafe value type or oversized value")

    injected = dict(tool.fixed_parameters)
    injected.update(request.parameters)
    injected[tool.target_field] = _scoped_target_value(tool, target)
    if request.credential_profile:
        # This is an opaque selector. The runner-side credential broker resolves
        # it after policy approval; no raw credential enters the model context.
        injected["credential_profile"] = request.credential_profile
    return ToolDecision(
        request_id=request.id,
        tool=request.tool,
        decision=Decision.ALLOW,
        reason="approved for the job-owned sandbox target",
        injected_parameters=injected,
    )


def _deny(request: ToolRequest, reason: str) -> ToolDecision:
    return ToolDecision(request_id=request.id, tool=request.tool, decision=Decision.DENY, reason=reason)


def _scoped_target_value(tool: ToolDefinition, target: SandboxTarget) -> str:
    if tool.target_kind == "url":
        return target.base_url.rstrip("/")
    if tool.target_kind == "host":
        host = target.hostname
        # Docker service names are permitted. Literal IPs are only permitted if
        # they are loopback/private; public targets must never enter this layer.
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return host
        if not (ip.is_private or ip.is_loopback):
            raise ValueError("sandbox target host must be private or loopback")
        return host
    raise ValueError(f"unknown target kind: {tool.target_kind}")


def _safe_parameter_values(values: dict[str, Any]) -> bool:
    """Keep the first harness contract deliberately narrow and bounded."""
    for value in values.values():
        if isinstance(value, bool | int | float):
            continue
        if isinstance(value, str) and len(value) <= 512 and "\x00" not in value:
            continue
        return False
    return True

"""Build a job-owned harness after a target has entered its sandbox."""

from __future__ import annotations

from ..config import Settings
from ..contracts import DeployedTarget, IngestResult, Target
from .agent_harness import AgentHarness
from .contracts import HarnessPolicy, SandboxTarget, ScanProfile
from .transport import PentrAIHTTPTransport


def create_harness(
    target: Target,
    ingest: IngestResult,
    deployed: DeployedTarget,
    settings: Settings,
    *,
    profile: ScanProfile = ScanProfile.STANDARD,
    allow_dynamic_validation: bool = False,
) -> AgentHarness:
    """Construct the only dynamic-tool interface available to a job agent.

    The caller receives the harness, not the raw PentrAI HTTP client. Any
    submitted credentials remain an opaque broker-side profile name; their value
    is never copied into this object, logs, or model context.
    """
    credential_profiles = frozenset({"submitted-test-credentials"}) if ingest.has_secrets else frozenset()
    policy = HarnessPolicy(
        scan_id=target.id,
        profile=profile,
        authorized=target.authorized,
        allow_dynamic_validation=allow_dynamic_validation,
        max_tool_calls=settings.max_exploit_steps_per_finding,
        credential_profiles=credential_profiles,
    )
    sandbox_target = SandboxTarget(
        base_url=deployed.internal_base_url,
        network_name=deployed.network_name,
        scan_id=target.id,
    )
    transport = PentrAIHTTPTransport(settings.pentrai_server_url)
    return AgentHarness(policy, sandbox_target, transport)

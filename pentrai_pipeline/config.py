"""
Runtime configuration for the pipeline.

Everything the stages need to reach the outside world (the PentrAI tool server,
the LLM, Docker) is centralized here and sourced from the environment so the same
code runs on a dev laptop and in the eventual hosted product. Defaults match the
existing PentrAI setup (server on :8888, the llm_proxy on :8889).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .contracts import Posture


@dataclass
class LLMSettings:
    # Provider-agnostic, OpenAI-compatible. Points at the existing llm_proxy by
    # default (which forwards to DeepSeek and logs tool calls); override to hit any
    # OpenAI-compatible endpoint directly.
    base_url: str = field(default_factory=lambda: os.getenv("PENTRAI_LLM_BASE_URL", "http://127.0.0.1:8889/v1"))
    api_key: str = field(default_factory=lambda: os.getenv("PENTRAI_LLM_API_KEY", ""))
    model: str = field(default_factory=lambda: os.getenv("PENTRAI_LLM_MODEL", "deepseek-chat"))
    request_timeout_s: int = 300


@dataclass
class SandboxSettings:
    # The containment boundary. See docs/THREAT_MODEL.md.
    docker_bin: str = field(default_factory=lambda: os.getenv("PENTRAI_DOCKER_BIN", "docker"))
    # The sandbox network gets NO route to the public internet by default: the
    # target and the attacker tooling can reach each other and nothing else.
    allow_egress: bool = False
    # Hosts the sandbox may still reach even when egress is off (e.g. a local CVE
    # mirror). Keep empty for full isolation.
    egress_allowlist: list[str] = field(default_factory=list)
    build_timeout_s: int = 900
    healthcheck_timeout_s: int = 120
    # Image used to probe the target from INSIDE the sandbox network (healthchecks,
    # reachability). Pulled on the host; runs on the isolated network with no egress.
    probe_image: str = field(default_factory=lambda: os.getenv("PENTRAI_PROBE_IMAGE", "busybox"))

    # Runtime hardening for the (untrusted) target container — limits the blast
    # radius of running a stranger's code. See docs/THREAT_MODEL.md.
    # Capabilities dropped from / added to the target. Default drops NET_RAW (raw
    # sockets — low-breakage, most apps don't need it) on top of Docker's already
    # limited default set. Dropping ALL is NOT the default: it breaks common images
    # (nginx needs SETUID/SETGID/NET_BIND_SERVICE just to start). For a cooperative
    # target you can lock down harder: cap_drop=["ALL"], cap_add the few it needs.
    cap_drop: list = field(default_factory=lambda: ["NET_RAW"])
    cap_add: list = field(default_factory=list)
    no_new_privileges: bool = True     # docker: --security-opt no-new-privileges
    pids_limit: int = 512
    memory_limit: str = "512m"         # docker: --memory
    cpu_limit: str = "1.0"             # docker: --cpus
    # Network for the BUILD step. "" = docker default (has internet, needed for most
    # dependency installs); "none" for targets that vendor their deps. Build-time
    # code runs on the host daemon and is a residual risk — see THREAT_MODEL.md.
    build_network: str = ""


@dataclass
class Settings:
    # The existing PentrAI tool server (150-tool catalog) that stages drive.
    pentrai_server_url: str = field(default_factory=lambda: os.getenv("PENTRAI_SERVER_URL", "http://127.0.0.1:8888"))

    # Where the pipeline stages write working copies, logs and artifacts.
    work_dir: str = field(default_factory=lambda: os.getenv("PENTRAI_WORK_DIR", os.path.join(os.getcwd(), ".pentrai_runs")))

    default_posture: Posture = Posture.EXTERNAL

    # Which SCA backend to shell out to (all deterministic CVE scanners).
    sca_tool: str = field(default_factory=lambda: os.getenv("PENTRAI_SCA_TOOL", "osv-scanner"))

    # Budget guards for the exploitation agent so a job can't run forever / spend
    # unbounded tokens attempting one hypothesis.
    max_exploit_steps_per_finding: int = 20
    max_findings_to_validate: int = 25
    llm_source_consent: bool = field(default_factory=lambda: os.getenv("PENTRAI_MODEL_SOURCE_CONSENT", "").lower() == "true")
    isolated_runner_verified: bool = False

    llm: LLMSettings = field(default_factory=LLMSettings)
    sandbox: SandboxSettings = field(default_factory=SandboxSettings)

    @classmethod
    def from_env(cls) -> "Settings":
        return cls()

"""Development-only source worker using one networkless Docker container per scan."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import shutil
import struct
import subprocess
import threading
import time
import uuid

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from execution_manager.admission import prepare_runner_job
from execution_manager.leases import reap_expired_leases
from pentrai_pipeline.agents.llm import LLMClient
from pentrai_pipeline.config import LLMSettings

from .events import append_visible_event
from .local_store import LocalObjectStore
from .local_hexstrike_readiness import publish_local_heartbeat
from .models import RunnerLease, Scan, ScanState, SourceArtifact
from .runner_results import accept_runner_result
from .settings import Settings
from .credits import record_model_usage, require_model_budget
from .model_catalog import model_options


class LocalDockerClient:
    def __init__(self, docker: str):
        self.docker = docker

    def delete_namespace(self, namespace: str) -> None:
        if not namespace.startswith("scan-") or len(namespace) != 37:
            raise ValueError("invalid local runner container name")
        result = subprocess.run([self.docker, "rm", "-f", namespace],
                                capture_output=True, timeout=20, check=False)
        if result.returncode and b"No such container" not in result.stderr:
            raise RuntimeError("local runner container cleanup failed")


def reap_local_leases(engine, docker: str) -> int:
    with Session(engine) as session:
        count = reap_expired_leases(session, LocalDockerClient(docker), lambda _lease: None,
                                    execution_backend="hexstrike_local")
        session.commit()
        return count


def _scope_dict(scope) -> dict:
    return {key: getattr(scope, key) for key in (
        "scan_id", "organization_id", "lease_id", "source_digest", "scope_digest",
        "source_present", "target_url", "scope_note", "profile")
    } | {"expires_at": scope.expires_at.isoformat()}


def _docker_assessment(prepared, archive: bytes, model, *, image: str, docker: str,
                       is_cancelled=None) -> dict:
    """Keep the provider client on the host and send only model turns over stdio."""
    if not image.startswith("pentrai/hexstrike-runner:") or not prepared.scope.source_present:
        raise ValueError("local runner requires a pinned local HexStrike image and source")
    command = [docker, "run", "--rm", "-i", "--pull", "never", "--name", prepared.lease.namespace,
               "--network", "none", "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "--pids-limit", "128",
               "--memory", "1g", "--cpus", "1", "--tmpfs",
               "/job/tmp:rw,nosuid,nodev,size=256m,uid=10001,gid=10001",
               "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m",
               image, "python", "/opt/pentrai/local_assessment.py"]
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, bufsize=0)
    remaining = max(1, (prepared.scope.expires_at - datetime.now(timezone.utc)).total_seconds())
    watchdog = threading.Timer(remaining, process.kill)
    watchdog.daemon = True
    watchdog.start()
    stop_monitor = threading.Event()

    def monitor_cancel() -> None:
        while not stop_monitor.wait(1):
            if process.poll() is not None:
                return
            try:
                cancelled = is_cancelled is not None and is_cancelled()
            except Exception:
                cancelled = True
            if cancelled:
                process.kill()
                return

    monitor = threading.Thread(target=monitor_cancel, daemon=True)
    monitor.start()
    try:
        header = json.dumps({"scope": _scope_dict(prepared.scope),
                             "archive_bytes": len(archive)}).encode()
        assert process.stdin is not None and process.stdout is not None
        process.stdin.write(struct.pack("!I", len(header)) + header + archive)
        process.stdin.flush()
        for _ in range(24):
            line = process.stdout.readline(4 * 1024 * 1024 + 1)
            if not line or len(line) > 4 * 1024 * 1024:
                raise ValueError("local runner ended without a bounded result")
            if line.startswith(b"PENTRAI_MODEL "):
                request = json.loads(line[len(b"PENTRAI_MODEL "):])
                if not isinstance(request, dict) or set(request) != {"messages", "tools"}:
                    raise ValueError("invalid local model request")
                turn = model.chat_tools(request["messages"], tools=request["tools"])
                response = json.dumps({"message": turn.message, "usage": turn.usage}).encode()
                if len(response) > 1024 * 1024 - 32:
                    raise ValueError("local model response exceeds limit")
                process.stdin.write(b"PENTRAI_TURN " + response + b"\n")
                process.stdin.flush()
            elif line.startswith(b"PENTRAI_RESULT "):
                result = json.loads(line[len(b"PENTRAI_RESULT "):])
                process.stdin.close()
                if process.wait(timeout=10) != 0:
                    raise ValueError("local runner exited unsuccessfully")
                return result
            else:
                raise ValueError("unexpected local runner output")
        raise ValueError("local model turn limit exceeded")
    finally:
        stop_monitor.set()
        monitor.join(timeout=2)
        watchdog.cancel()
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)
        if process.stdin and not process.stdin.closed:
            process.stdin.close()
        if process.stdout:
            process.stdout.close()


def run_once(engine, organization_id: str, scan_id: str, settings: Settings,
             store: LocalObjectStore, model, *, image: str = "pentrai/hexstrike-runner:local",
             docker: str = "docker") -> str:
    if not settings.local_hexstrike_enabled or not settings.local_dev_auth:
        raise ValueError("local HexStrike worker is disabled")
    key = settings.grant_signing_key.get_secret_value().encode()
    with Session(engine, expire_on_commit=False) as session:
        prepared = prepare_runner_job(session, organization_id, scan_id, key)
        if prepared.artifact_id is None or prepared.scope.target_url:
            raise ValueError("local HexStrike worker accepts source-only scans")
        artifact = session.get(SourceArtifact, prepared.artifact_id)
        object_key = artifact.object_key
        session.commit()
    failed = True
    try:
        archive = b"".join(store.read_chunks(object_key))
        if (len(archive) != prepared.artifact_bytes
                or hashlib.sha256(archive).hexdigest() != prepared.scope.source_digest):
            raise ValueError("local source artifact changed")
        class MeteredModel:
            def chat_tools(self, messages, *, tools):
                with Session(engine) as session:
                    require_model_budget(session, scan_id)
                turn = model.chat_tools(messages, tools=tools)
                with Session(engine) as session:
                    record_model_usage(session, scan_id, turn.usage)
                    session.commit()
                return turn

        def is_cancelled() -> bool:
            with Session(engine) as session:
                current = session.get(Scan, scan_id)
                return current is None or current.state is not ScanState.QUEUED

        result = _docker_assessment(prepared, archive, MeteredModel(), image=image,
                                    docker=docker, is_cancelled=is_cancelled)
        with Session(engine) as session:
            report = accept_runner_result(session, result, prepared.grant_token, key)
            session.commit()
            report_id = report.id
        failed = False
        return report_id
    finally:
        if failed:
            with Session(engine) as session:
                scan = session.get(Scan, scan_id)
                if scan and scan.state is ScanState.QUEUED:
                    scan.state = ScanState.CLEANUP
                    append_visible_event(session, scan.id, organization_id, "warning",
                                         "Assessment failed. Cleanup is in progress")
                session.commit()
        reap_local_leases(engine, docker)
        with Session(engine) as session:
            lease = session.get(RunnerLease, prepared.lease.id)
            if lease is None or lease.cleaned_at is None:
                raise RuntimeError("local runner cleanup remains pending")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run local source scans through native HexStrike in Docker")
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--organization-id")
    parser.add_argument("--scan-id")
    args = parser.parse_args()
    if not args.serve and (not args.organization_id or not args.scan_id):
        parser.error("one-shot mode requires organization and scan IDs")
    settings = Settings.from_env()
    if not settings.local_hexstrike_enabled or not settings.local_artifact_root:
        parser.error("local HexStrike execution and artifact storage must be configured")
    if shutil.which(os.getenv("PENTRAI_DOCKER_BIN", "docker")) is None:
        parser.error("Docker CLI is unavailable")
    engine = create_engine(settings.database_url, pool_pre_ping=True)
    fixture_model = os.getenv("PENTRAI_LOCAL_FIXTURE_MODEL", "").lower() == "true"
    store = LocalObjectStore(settings.local_artifact_root)
    docker = os.getenv("PENTRAI_DOCKER_BIN", "docker")
    image = "pentrai/hexstrike-runner:local"
    checked = subprocess.run([docker, "image", "inspect", image], capture_output=True, timeout=20)
    if checked.returncode:
        parser.error("local HexStrike runner image is unavailable; build it first")
    worker_id = str(uuid.uuid4())

    def process(org: str, scan: str) -> None:
        if fixture_model:
            from runner.assessment_smoke import FixtureModel
            model = FixtureModel()
        else:
            with Session(engine) as session:
                selected = session.get(Scan, scan)
                if selected is None or selected.organization_id != org:
                    raise ValueError("scan is unavailable")
                model_id = selected.model_id
                prompt_rate = selected.prompt_credit_rate
                completion_rate = selected.completion_credit_rate
            option = model_options().get(model_id)
            if (option is None or option.prompt_credit_rate != prompt_rate
                    or option.completion_credit_rate != completion_rate):
                raise ValueError("selected model is unavailable")
            key = os.getenv(option.key_env, "")
            if not key:
                raise ValueError("selected model credential is not configured")
            model = LLMClient(LLMSettings(base_url=option.base_url, model=option.provider_model,
                                          api_key=key))
        run_once(engine, org, scan, settings, store, model, docker=docker)
        print(f"scan {scan}: completed", flush=True)

    if not args.serve:
        process(args.organization_id, args.scan_id)
        return
    print("Local HexStrike worker polling", flush=True)
    while True:
        reap_local_leases(engine, docker)
        with Session(engine) as session:
            publish_local_heartbeat(session, worker_id)
            session.commit()
        with Session(engine) as session:
            candidate = session.scalar(select(Scan).where(
                Scan.execution_backend == "hexstrike_local",
                Scan.state == ScanState.AUTHORIZED,
                Scan.target_url.is_(None),
            ).order_by(Scan.created_at).limit(1))
            target = (candidate.organization_id, candidate.id) if candidate else None
        if target:
            try:
                process(*target)
            except Exception as exc:
                print(f"scan {target[1]} failed: {type(exc).__name__}: {exc}", flush=True)
        else:
            time.sleep(2)


if __name__ == "__main__":
    main()

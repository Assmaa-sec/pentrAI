"""Development-only source worker using one networkless Docker container per scan."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import queue
import shutil
import struct
import subprocess
import threading
import tempfile
import time
import uuid

import httpx

from sqlalchemy import create_engine, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from execution_manager.admission import prepare_runner_job
from execution_manager.leases import reap_expired_leases
from pentrai_pipeline.agents.llm import LLMClient
from pentrai_pipeline.config import LLMSettings

from .events import append_visible_event
from .assessment_health import AssessmentFailure, FAILURES, STAGES
from .local_store import LocalObjectStore
from .local_hexstrike_readiness import publish_local_heartbeat
from .models import AuditEvent, LocalHexStrikeWorker, RunnerLease, Scan, ScanState, SourceArtifact
from .runner_results import accept_runner_result
from .settings import Settings
from .credits import CreditRejected, record_model_usage, require_model_budget, release_scan_credits
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


def _write_all(stream, data: bytes) -> None:
    """Raw pipes may accept fewer bytes than requested even in blocking mode."""
    pending = memoryview(data)
    while pending:
        written = stream.write(pending)
        if written is None or written <= 0:
            raise BrokenPipeError("assessment input pipe stopped accepting data")
        pending = pending[written:]
    stream.flush()


def _docker_assessment(prepared, archive: bytes, model, *, image: str, docker: str,
                       is_cancelled=None, on_stage=None) -> dict:
    """Keep the provider client on the host and send only model turns over stdio."""
    if not image.startswith("pentrai/hexstrike-runner:") or not prepared.scope.source_present:
        raise ValueError("local runner requires a pinned local HexStrike image and source")
    if prepared.scope.expires_at <= datetime.now(timezone.utc):
        raise AssessmentFailure("deadline")
    command = [docker, "run", "--rm", "-i", "--pull", "never", "--name", prepared.lease.namespace,
               "--network", "none", "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "--pids-limit", "128",
               "--memory", "1g", "--cpus", "1", "--tmpfs",
               "/job/tmp:rw,nosuid,nodev,size=256m,uid=10001,gid=10001",
               "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m",
               image, "python", "/opt/pentrai/local_assessment.py"]
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, bufsize=0)
    remaining = max(0.001, (prepared.scope.expires_at - datetime.now(timezone.utc)).total_seconds())
    stop_monitor = threading.Event()
    expired = threading.Event()
    aborted = threading.Event()

    def stop_at_deadline() -> None:
        expired.set()
        if process.poll() is None:
            process.kill()

    # The timer bounds pipe writes/reads as well as model calls.
    watchdog = threading.Timer(remaining, stop_at_deadline)
    watchdog.daemon = True
    watchdog.start()

    def monitor_cancel() -> None:
        while not stop_monitor.wait(1):
            if process.poll() is not None:
                return
            try:
                cancelled = is_cancelled is not None and is_cancelled()
            except Exception:
                cancelled = True
            if cancelled:
                aborted.set()
                process.kill()
                return

    monitor = threading.Thread(target=monitor_cancel, daemon=True)
    monitor.start()
    try:
        header = json.dumps({"scope": _scope_dict(prepared.scope),
                             "archive_bytes": len(archive)}).encode()
        assert process.stdin is not None and process.stdout is not None
        _write_all(process.stdin, struct.pack("!I", len(header)) + header + archive)
        # Bounded stage messages in addition to at most 24 model turns.
        turns = 0
        for _ in range(64):
            line = process.stdout.readline(4 * 1024 * 1024 + 1)
            if expired.is_set():
                raise AssessmentFailure("deadline")
            if aborted.is_set():
                raise AssessmentFailure("runner")
            if not line or len(line) > 4 * 1024 * 1024:
                raise AssessmentFailure("runner")
            if line.startswith(b"PENTRAI_STATUS "):
                stage = line[len(b"PENTRAI_STATUS "):].strip().decode("ascii")
                if stage not in {"archive", "tools", "analysis"}:
                    raise AssessmentFailure("runner")
                if on_stage:
                    on_stage(stage)
            elif line.startswith(b"PENTRAI_ERROR "):
                code = line[len(b"PENTRAI_ERROR "):].strip().decode("ascii")
                raise AssessmentFailure(code if code in {"archive", "tools", "runner"} else "runner")
            elif line.startswith(b"PENTRAI_MODEL "):
                turns += 1
                if turns > 24:
                    raise AssessmentFailure("budget")
                request = json.loads(line[len(b"PENTRAI_MODEL "):])
                if not isinstance(request, dict) or set(request) != {"messages", "tools"}:
                    raise ValueError("invalid local model request")
                if on_stage:
                    on_stage("model")
                # HTTP read timeouts alone do not impose a total job deadline.
                # A daemon call thread lets cancellation/deadline release this wait.
                outcome = queue.Queue(maxsize=1)

                def ask_model(request=request, outcome=outcome) -> None:
                    try:
                        outcome.put((True, model.chat_tools(request["messages"], tools=request["tools"])))
                    except Exception as exc:
                        outcome.put((False, exc))

                threading.Thread(target=ask_model, daemon=True).start()
                while True:
                    if expired.is_set() or datetime.now(timezone.utc) >= prepared.scope.expires_at:
                        raise AssessmentFailure("deadline")
                    if aborted.is_set() or process.poll() is not None:
                        raise AssessmentFailure("runner")
                    try:
                        ok, turn = outcome.get(timeout=0.25)
                        break
                    except queue.Empty:
                        continue
                if not ok:
                    raise turn
                if on_stage:
                    on_stage("analysis")
                response = json.dumps({"message": turn.message, "usage": turn.usage}).encode()
                if len(response) > 1024 * 1024 - 32:
                    raise ValueError("local model response exceeds limit")
                _write_all(process.stdin, b"PENTRAI_TURN " + response + b"\n")
            elif line.startswith(b"PENTRAI_RESULT "):
                result = json.loads(line[len(b"PENTRAI_RESULT "):])
                process.stdin.close()
                if process.wait(timeout=10) != 0:
                    raise ValueError("local runner exited unsuccessfully")
                return result
            else:
                raise ValueError("unexpected local runner output")
        raise AssessmentFailure("runner")
    except Exception as exc:
        if expired.is_set():
            raise AssessmentFailure("deadline") from exc
        raise
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
             docker: str = "docker", heartbeat=None) -> str:
    if not settings.local_hexstrike_enabled or not settings.local_dev_auth:
        raise ValueError("local HexStrike worker is disabled")
    key = settings.grant_signing_key.get_secret_value().encode()
    try:
        with Session(engine, expire_on_commit=False) as session:
            prepared = prepare_runner_job(session, organization_id, scan_id, key)
            if prepared.artifact_id is None or prepared.scope.target_url:
                raise ValueError("local HexStrike worker accepts source-only scans")
            artifact = session.get(SourceArtifact, prepared.artifact_id)
            object_key = artifact.object_key
            session.commit()
    except SQLAlchemyError as exc:
        raise AssessmentFailure("database") from exc
    except ValueError as exc:
        raise AssessmentFailure("admission") from exc
    failed = True
    failure_code = "source"
    stage = "source"
    last_notice = time.monotonic()
    last_heartbeat = 0.0
    status_lock = threading.Lock()

    def progress(value: str) -> None:
        nonlocal stage, last_notice
        with status_lock:
            stage = value
            last_notice = time.monotonic()
            with Session(engine) as session:
                current = session.get(Scan, scan_id)
                if current and current.organization_id == organization_id and current.state is ScanState.QUEUED:
                    kind, summary = STAGES[value]
                    append_visible_event(session, scan_id, organization_id, kind, summary)
                    session.commit()

    try:
        progress("source")
        if not 0 < prepared.artifact_bytes <= 50 * 1024 * 1024:
            raise AssessmentFailure("source")
        chunks = []
        total = 0
        for chunk in store.read_chunks(object_key):
            total += len(chunk)
            if total > prepared.artifact_bytes:
                raise AssessmentFailure("source")
            chunks.append(chunk)
        archive = b"".join(chunks)
        if (len(archive) != prepared.artifact_bytes
                or hashlib.sha256(archive).hexdigest() != prepared.scope.source_digest):
            raise ValueError("local source artifact changed")
        class MeteredModel:
            def chat_tools(self, messages, *, tools):
                with Session(engine) as session:
                    require_model_budget(session, scan_id)
                try:
                    turn = model.chat_tools(messages, tools=tools)
                except httpx.HTTPStatusError as exc:
                    status = exc.response.status_code
                    raise AssessmentFailure("provider_auth" if status in {401, 403} else
                                            "provider_limit" if status == 429 else "provider") from exc
                except httpx.TimeoutException as exc:
                    raise AssessmentFailure("provider_timeout") from exc
                except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
                    raise AssessmentFailure("provider") from exc
                with Session(engine) as session:
                    current = session.get(Scan, scan_id)
                    active = (current is not None and current.state is ScanState.QUEUED
                              and datetime.now(timezone.utc) < prepared.scope.expires_at)
                    # Provider work already happened. The ledger explicitly supports
                    # late usage after cancellation/cleanup releases a reservation.
                    record_model_usage(session, scan_id, turn.usage)
                    session.commit()
                if not active:
                    raise AssessmentFailure("deadline")
                return turn

        def check_status() -> bool:
            nonlocal last_heartbeat, last_notice
            now = time.monotonic()
            refresh = now - last_heartbeat >= 10
            if heartbeat and refresh:
                heartbeat()
            with Session(engine) as session:
                current = session.get(Scan, scan_id)
                cancelled = current is None or current.state is not ScanState.QUEUED
                if not cancelled and refresh:
                    lease = session.get(RunnerLease, prepared.lease.id)
                    if lease is None or lease.cleaned_at is not None:
                        return True
                    lease.heartbeat_at = datetime.now(timezone.utc)
                    last_heartbeat = now
                if not cancelled and now - last_notice >= 30:
                    append_visible_event(session, scan_id, organization_id, "status",
                                         f"Assessment service is responding. Current step: {STAGES[stage][1].lower()}. No completion confirmed yet.")
                    last_notice = now
                session.commit()
                return cancelled

        def is_cancelled() -> bool:
            with status_lock:
                return check_status()

        failure_code = "runner"
        result = _docker_assessment(prepared, archive, MeteredModel(), image=image,
                                    docker=docker, is_cancelled=is_cancelled, on_stage=progress)
        failure_code = "result"
        progress("result")
        with Session(engine) as session:
            report = accept_runner_result(session, result, prepared.grant_token, key)
            session.commit()
            report_id = report.id
        failed = False
        return report_id
    except Exception as exc:
        if isinstance(exc, AssessmentFailure):
            failure_code = exc.code
        elif isinstance(exc, CreditRejected):
            failure_code = "budget"
        elif isinstance(exc, SQLAlchemyError):
            failure_code = "database"
        raise
    finally:
        if failed:
            with Session(engine) as session:
                scan = session.get(Scan, scan_id)
                if scan and scan.state is ScanState.QUEUED:
                    scan.state = ScanState.CLEANUP
                    append_visible_event(session, scan.id, organization_id, "warning",
                                         FAILURES[failure_code] + " Cleanup is in progress.")
                    session.add(AuditEvent(
                        organization_id=organization_id, scan_id=scan_id,
                        actor_id="local-hexstrike-worker", action="scan.execution_failed",
                        payload={"reason": failure_code},
                    ))
                session.commit()
        reap_local_leases(engine, docker)
        with Session(engine) as session:
            lease = session.get(RunnerLease, prepared.lease.id)
            if lease is None or lease.cleaned_at is None:
                raise RuntimeError("local runner cleanup remains pending")


def fail_before_execution(engine, organization_id: str, scan_id: str,
                          code: str = "configuration") -> None:
    """Persist a safe failure only if this local scan has not been claimed."""
    with Session(engine) as session:
        with session.begin():
            scan = session.scalar(select(Scan).where(
                Scan.id == scan_id, Scan.organization_id == organization_id,
                Scan.execution_backend == "hexstrike_local",
                Scan.state == ScanState.AUTHORIZED,
            ).with_for_update())
            if scan is None:
                return
            scan.state = ScanState.FAILED
            release_scan_credits(session, scan)
            append_visible_event(session, scan.id, organization_id, "warning",
                                 FAILURES[code])
            session.add(AuditEvent(
                organization_id=organization_id, scan_id=scan.id,
                actor_id="local-hexstrike-worker", action="scan.start_failed",
                payload={"reason": code},
            ))


def check_local_dependencies(docker: str, image: str, *, fixture_model: bool = False) -> None:
    """Cheap dependency checks only; no provider request or uploaded code execution."""
    if not fixture_model:
        try:
            options = model_options().values()
            if not any(os.getenv(option.key_env, "").strip() for option in options):
                raise AssessmentFailure("credential")
        except AssessmentFailure:
            raise
        except (ValueError, TypeError) as exc:
            raise AssessmentFailure("configuration") from exc
    if shutil.which(docker) is None:
        raise AssessmentFailure("docker")
    try:
        # Image inspection also verifies daemon connectivity and permissions.
        checked = subprocess.run([docker, "image", "inspect", image],
                                 capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AssessmentFailure("docker") from exc
    if checked.returncode:
        raise AssessmentFailure("docker")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run local source scans through native HexStrike in Docker")
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--check", action="store_true", help="check configuration and dependencies without starting an assessment")
    parser.add_argument("--organization-id")
    parser.add_argument("--scan-id")
    args = parser.parse_args()
    if not args.serve and not args.check and (not args.organization_id or not args.scan_id):
        parser.error("one-shot mode requires organization and scan IDs")
    settings = Settings.from_env()
    if not settings.local_hexstrike_enabled or not settings.local_artifact_root:
        parser.error("local HexStrike execution and artifact storage must be configured")
    engine = create_engine(settings.database_url, pool_pre_ping=True)
    fixture_model = os.getenv("PENTRAI_LOCAL_FIXTURE_MODEL", "").lower() == "true"
    store = LocalObjectStore(settings.local_artifact_root)
    docker = os.getenv("PENTRAI_DOCKER_BIN", "docker")
    image = "pentrai/hexstrike-runner:local"
    worker_id = str(uuid.uuid4())

    if args.check:
        try:
            check_local_dependencies(docker, image, fixture_model=fixture_model)
            with tempfile.TemporaryFile(dir=store.root) as probe:
                probe.write(b"assessment health check")
            with Session(engine) as session:
                session.execute(select(Scan.id).limit(1))
                session.execute(select(RunnerLease.id).limit(1))
                session.execute(select(LocalHexStrikeWorker.id).limit(1))
        except AssessmentFailure as exc:
            parser.exit(1, f"{exc}\n")
        except Exception as exc:
            parser.exit(1, f"Assessment preflight failed ({type(exc).__name__}). Check database migrations and artifact directory permissions.\n")
        print("Assessment configuration, database tables, artifact write access, and Docker image checks passed. Provider authentication and tool support are checked during an assessment.", flush=True)
        return

    def heartbeat() -> None:
        with Session(engine) as session:
            publish_local_heartbeat(session, worker_id)
            session.commit()

    def execute(org: str, scan: str) -> None:
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
            try:
                option = model_options().get(model_id)
            except (ValueError, TypeError) as exc:
                raise AssessmentFailure("configuration") from exc
            if (option is None or option.prompt_credit_rate != prompt_rate
                    or option.completion_credit_rate != completion_rate):
                raise AssessmentFailure("model")
            key = os.getenv(option.key_env, "")
            if not key.strip():
                raise AssessmentFailure("credential")
            model = LLMClient(LLMSettings(base_url=option.base_url, model=option.provider_model,
                                          api_key=key))
        check_local_dependencies(docker, image, fixture_model=fixture_model)
        run_once(engine, org, scan, settings, store, model, docker=docker, heartbeat=heartbeat)
        print(f"scan {scan}: completed", flush=True)

    def process(org: str, scan: str) -> None:
        try:
            execute(org, scan)
        except Exception as exc:
            code = exc.code if isinstance(exc, AssessmentFailure) else "configuration"
            fail_before_execution(engine, org, scan, code)
            raise

    if not args.serve:
        try:
            process(args.organization_id, args.scan_id)
        except Exception as exc:
            detail = str(exc) if isinstance(exc, AssessmentFailure) else type(exc).__name__
            parser.exit(1, f"Assessment failed: {detail}\n")
        return
    print("Local HexStrike worker polling", flush=True)
    last_preflight = 0.0
    while True:
        try:
            reap_local_leases(engine, docker)
        except Exception as exc:
            print(f"Assessment cleanup check failed: {type(exc).__name__}. Retrying.", flush=True)
        if time.monotonic() - last_preflight >= 10:
            last_preflight = time.monotonic()
            try:
                check_local_dependencies(docker, image, fixture_model=fixture_model)
                heartbeat()
            except AssessmentFailure as exc:
                with Session(engine) as session:
                    status = session.get(LocalHexStrikeWorker, worker_id)
                    if status:
                        session.delete(status)
                        session.commit()
                print(str(exc), flush=True)
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
                # Raw provider errors can contain endpoints or credentials.
                detail = str(exc) if isinstance(exc, AssessmentFailure) else type(exc).__name__
                print(f"scan {target[1]} failed: {detail}", flush=True)
        else:
            time.sleep(2)


if __name__ == "__main__":
    main()

"""Local Docker source assessment. Model calls cross stdio; the container has no network."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys

from execution_manager.job_agent import JobScope, run_job
from execution_manager.stage_source import stage_source
from pentrai_pipeline.agents.llm import LLMToolTurn


class StdioModel:
    def chat_tools(self, messages, *, tools):
        request = json.dumps({"messages": messages, "tools": tools}, ensure_ascii=True).encode()
        if len(request) > 4 * 1024 * 1024:
            raise ValueError("model request exceeds local protocol limit")
        sys.stdout.buffer.write(b"PENTRAI_MODEL " + request + b"\n")
        sys.stdout.buffer.flush()
        response = sys.stdin.buffer.readline(1024 * 1024 + 1)
        if not response.startswith(b"PENTRAI_TURN ") or len(response) > 1024 * 1024:
            raise ValueError("invalid local model response")
        turn = json.loads(response[len(b"PENTRAI_TURN "):])
        if not isinstance(turn, dict) or set(turn) != {"message", "usage"}:
            raise ValueError("invalid local model turn")
        return LLMToolTurn(turn["message"], turn["usage"])


async def main() -> None:
    stream = sys.stdin.buffer
    header_size = stream.read(4)
    if len(header_size) != 4:
        raise ValueError("local job header missing")
    count = struct.unpack("!I", header_size)[0]
    if not 0 < count <= 16_384:
        raise ValueError("local job header too large")
    header = json.loads(stream.read(count))
    if not isinstance(header, dict) or set(header) != {"scope", "archive_bytes"}:
        raise ValueError("invalid local job header")
    scope = JobScope.from_dict(header["scope"])
    size = header["archive_bytes"]
    if not scope.source_present or scope.target_url or type(size) is not int or not 0 < size <= 50 * 1024 * 1024:
        raise ValueError("local Docker accepts source-only jobs")
    scratch = Path("/job/tmp")
    archive = scratch / "source.zip"
    with archive.open("xb") as output:
        remaining = size
        while remaining:
            chunk = stream.read(min(remaining, 1024 * 1024))
            if not chunk:
                raise ValueError("local archive truncated")
            output.write(chunk)
            remaining -= len(chunk)
    source, _ = stage_source(archive, scratch, scope.source_digest, size)
    archive.unlink()
    shutil.copyfile("/opt/pentrai/pentrai_mcp.py", scratch / "pentrai_mcp.py")
    server = subprocess.Popen([sys.executable, "/opt/pentrai/pentrai_server.py"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        result = await run_job(scope, StdioModel(), source_root=source)
        encoded = json.dumps(result, ensure_ascii=True).encode()
        if len(encoded) > 1024 * 1024:
            raise ValueError("local result exceeds size limit")
        sys.stdout.buffer.write(b"PENTRAI_RESULT " + encoded + b"\n")
        sys.stdout.buffer.flush()
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)


if __name__ == "__main__":
    asyncio.run(main())

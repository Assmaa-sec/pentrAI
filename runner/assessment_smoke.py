"""Local source-to-model-to-native-MCP assessment probe; never calls a provider."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

from execution_manager.job_agent import JobScope, run_job
from pentrai_pipeline.agents.llm import LLMToolTurn


class FixtureModel:
    def __init__(self) -> None:
        self.turns = 0

    def chat_tools(self, messages, *, tools):
        self.turns += 1
        if self.turns == 1:
            if not any(item["function"]["name"] == "execute_command" for item in tools):
                raise AssertionError("native command tool is absent from model catalog")
            return LLMToolTurn({
                "role": "assistant", "content": None,
                "tool_calls": [{"id": "fixture-call-1", "type": "function", "function": {
                    "name": "execute_command", "arguments": json.dumps({
                        "command": "grep -n PASSWORD /job/tmp/source/app.py", "use_cache": False,
                    }),
                }}],
            }, {"prompt_tokens": 20, "completion_tokens": 8})
        if messages[-1]["role"] != "tool":
            raise AssertionError("native tool result was not returned to the model")
        tool_result = json.loads(messages[-1]["content"])
        if "fixture-password" not in tool_result["result_excerpt"]:
            raise AssertionError("fixture source was not read by the native tool")
        finding = {"findings": [{"title": "Hardcoded fixture credential", "severity": "low",
                                "explanation": "The source contains a hardcoded fixture password.",
                                "evidence_sha256": [tool_result["output_sha256"]]}]}
        return LLMToolTurn({"role": "assistant", "content": json.dumps(finding)},
                           {"prompt_tokens": 16, "completion_tokens": 5})


async def main() -> None:
    source = Path("/job/tmp/source")
    source.mkdir(exist_ok=False)
    fixture = b"PASSWORD = 'fixture-password'\n"
    (source / "app.py").write_bytes(fixture)
    shutil.copyfile("/opt/pentrai/pentrai_mcp.py", "/job/tmp/pentrai_mcp.py")
    server = subprocess.Popen([sys.executable, "/opt/pentrai/pentrai_server.py"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        scope = JobScope.from_dict({
            "scan_id": "11111111-1111-4111-8111-111111111111",
            "organization_id": "22222222-2222-4222-8222-222222222222",
            "lease_id": "33333333-3333-4333-8333-333333333333",
            "source_digest": hashlib.sha256(fixture).hexdigest(),
            "scope_digest": hashlib.sha256(b"fixture scope").hexdigest(),
            "source_present": True, "target_url": None,
            "scope_note": "Inspect fixture source only", "profile": "quick",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        })
        result = await run_job(scope, FixtureModel(), source_root=source)
        if (len(result["events"]) != 1 or result["events"][0]["tool"] != "execute_command"
                or result["events"][0]["is_error"] or len(result["findings"]) != 1
                or result["findings"][0]["title"] != "Hardcoded fixture credential"):
            raise AssertionError("model-selected HexStrike source assessment failed")
        print("source-to-model-to-native-MCP assessment passed")
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)


if __name__ == "__main__":
    asyncio.run(main())

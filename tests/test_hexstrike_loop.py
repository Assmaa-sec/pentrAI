import asyncio
import json
import unittest

from pentrai_pipeline.agents.hexstrike_loop import LoopLimits, run_hexstrike_loop
from pentrai_pipeline.agents.llm import LLMToolTurn


class FakeModel:
    def __init__(self, turns):
        self.turns = iter(turns)
        self.messages = []
        self.tools = []

    def chat_tools(self, messages, *, tools):
        self.messages = list(messages)
        self.tools = tools
        return next(self.turns)


class FakeSession:
    def __init__(self):
        self.calls = []

    async def list_tools(self):
        return [{"name": "nmap_scan", "description": "Native scan",
                 "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}}}}]

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return {"result": "observed"}


def call_turn(name="nmap_scan", arguments=None):
    return LLMToolTurn({"role": "assistant", "content": None, "tool_calls": [{
        "id": "call_1", "type": "function", "function": {
            "name": name, "arguments": json.dumps(arguments or {"target": "example.test"})}}]},
        {"total_tokens": 10})


class HexStrikeLoopTests(unittest.TestCase):
    def test_native_tool_chain_and_usage(self):
        model = FakeModel([call_turn(), LLMToolTurn(
            {"role": "assistant", "content": "Possible issue with evidence."}, {"total_tokens": 7})])
        session = FakeSession()
        async def guard(name, arguments):
            self.assertEqual(arguments["target"], "example.test")
        result = asyncio.run(run_hexstrike_loop(model, session, [{"role": "user", "content": "Analyze"}], guard))
        self.assertEqual(result.usage["total_tokens"], 17)
        self.assertEqual(session.calls, [("nmap_scan", {"target": "example.test"})])
        self.assertEqual(model.messages[-1]["role"], "tool")
        self.assertEqual(json.loads(model.messages[-1]["content"])["output_sha256"],
                         result.events[0]["output_sha256"])
        self.assertEqual(len(result.events), 1)
        self.assertEqual(model.tools[0]["function"]["name"], "nmap_scan")

    def test_guard_rejection_prevents_execution(self):
        session = FakeSession()
        async def guard(_name, _arguments):
            raise PermissionError("out of scope")
        with self.assertRaises(PermissionError):
            asyncio.run(run_hexstrike_loop(FakeModel([call_turn()]), session, [], guard))
        self.assertEqual(session.calls, [])

    def test_budget_stops_before_execution(self):
        session = FakeSession()
        async def guard(_name, _arguments):
            pass
        with self.assertRaisesRegex(RuntimeError, "budget"):
            asyncio.run(run_hexstrike_loop(FakeModel([call_turn()]), session, [], guard,
                                         limits=LoopLimits(max_tool_calls=1, max_turns=1)))
        self.assertEqual(len(session.calls), 1)

    def test_unknown_tool_rejected(self):
        session = FakeSession()
        async def guard(_name, _arguments):
            pass
        with self.assertRaisesRegex(ValueError, "unknown"):
            asyncio.run(run_hexstrike_loop(FakeModel([call_turn("other")]), session, [], guard))
        self.assertEqual(session.calls, [])

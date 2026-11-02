import json
import asyncio
import unittest

from pentrai_pipeline.agents.hexstrike_findings import parse_finding_drafts, run_hexstrike_assessment
from pentrai_pipeline.agents.hexstrike_loop import LoopResult
from pentrai_pipeline.agents.llm import LLMToolTurn


class HexStrikeFindingTests(unittest.TestCase):
    def test_model_explanation_becomes_evidence_linked_draft(self):
        digest = "a" * 64
        result = LoopResult(json.dumps({"findings": [{
            "title": "Possible unsafe query", "severity": "high",
            "explanation": "The query includes unsanitized input.",
            "evidence_sha256": [digest]}]}), events=[{"output_sha256": digest}])
        draft = parse_finding_drafts(result)[0]
        self.assertEqual(draft.source, "hexstrike")
        self.assertEqual(draft.state, "detected")
        self.assertEqual(draft.explanation, "The query includes unsanitized input.")

    def test_invented_evidence_rejected(self):
        result = LoopResult(json.dumps({"findings": [{
            "title": "Issue", "severity": "high", "explanation": "Claim",
            "evidence_sha256": ["b" * 64]}]}), events=[{"output_sha256": "a" * 64}])
        with self.assertRaisesRegex(ValueError, "evidence"):
            parse_finding_drafts(result)

    def test_empty_finding_list_is_valid(self):
        self.assertEqual(parse_finding_drafts(LoopResult('{"findings": []}')), [])

    def test_assessment_requests_structured_findings(self):
        class Session:
            async def list_tools(self):
                return [{"name": "scan", "inputSchema": {"type": "object"}}]

            async def call_tool(self, _name, _args):
                raise AssertionError("no tool call expected")

        class Model:
            def chat_tools(self, messages, *, tools):
                self.asserted = messages[0]["role"] == "developer" and "findings" in messages[0]["content"]
                return LLMToolTurn({"role": "assistant", "content": '{"findings": []}'}, {})

        async def guard(_name, _arguments):
            pass
        model = Model()
        _result, findings = asyncio.run(run_hexstrike_assessment(model, Session(), [], guard))
        self.assertTrue(model.asserted)
        self.assertEqual(findings, [])

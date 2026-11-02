import unittest
from unittest.mock import patch

from pentrai_pipeline.agents.llm import LLMClient
from pentrai_pipeline.config import LLMSettings


class LLMToolTurnTests(unittest.TestCase):
    def setUp(self):
        self.client = LLMClient(LLMSettings())

    def test_native_call_and_usage(self):
        raw = {"choices": [{"message": {"role": "assistant", "content": None,
                "tool_calls": [{"id": "call_1", "type": "function", "function": {
                    "name": "nmap_scan", "arguments": "{}"}}]}}],
               "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}}
        with patch.object(self.client, "_completion", return_value=raw) as completion:
            turn = self.client.chat_tools([], tools=[{"type": "function"}])
        self.assertEqual(turn.usage["total_tokens"], 5)
        self.assertEqual(turn.message["tool_calls"][0]["function"]["name"], "nmap_scan")
        completion.assert_called_once()

    def test_duplicate_call_ids_rejected(self):
        call = {"id": "same", "type": "function", "function": {"name": "scan", "arguments": "{}"}}
        raw = {"choices": [{"message": {"role": "assistant", "tool_calls": [call, call]}}]}
        with patch.object(self.client, "_completion", return_value=raw):
            with self.assertRaisesRegex(ValueError, "invalid tool call"):
                self.client.chat_tools([], tools=[{"type": "function"}])

    def test_text_chat_rejects_raw_tools(self):
        with self.assertRaisesRegex(ValueError, "forbidden"):
            self.client.chat([], tools=[{"type": "function"}])

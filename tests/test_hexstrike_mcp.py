import asyncio
from pathlib import Path
import unittest
from unittest.mock import MagicMock

from pentrai_pipeline.agents.hexstrike_mcp import HexStrikeMCP


class HexStrikeMCPTests(unittest.TestCase):
    def setUp(self):
        self.bridge = Path(__file__).resolve().parents[1] / "pentrai_mcp.py"

    def test_rejects_nonlocal_server(self):
        with self.assertRaisesRegex(ValueError, "runner-local"):
            HexStrikeMCP(self.bridge, "http://example.com:8888")
        with self.assertRaisesRegex(ValueError, "runner-local"):
            HexStrikeMCP(self.bridge, "http://user:password@127.0.0.1:8888")

    def test_rejects_unconnected_calls(self):
        client = HexStrikeMCP(self.bridge, "http://127.0.0.1:8888")
        with self.assertRaisesRegex(RuntimeError, "not connected"):
            asyncio.run(client.list_tools())
        with self.assertRaisesRegex(RuntimeError, "not connected"):
            asyncio.run(client.call_tool("nmap_scan", {}))

    def test_native_tool_serialization(self):
        client = HexStrikeMCP(self.bridge, "http://127.0.0.1:8888")
        tool = MagicMock()
        tool.model_dump.return_value = {"name": "nmap_scan", "inputSchema": {"type": "object"}}
        response = MagicMock()
        response.tools = [tool]
        session = MagicMock()
        async def list_tools():
            return response
        session.list_tools = list_tools
        client._session = session
        self.assertEqual(asyncio.run(client.list_tools())[0]["name"], "nmap_scan")
        tool.model_dump.assert_called_once_with(mode="json", by_alias=True)

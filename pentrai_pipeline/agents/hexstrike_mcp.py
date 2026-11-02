"""Runner-local stdio client for the existing HexStrike MCP bridge."""

from __future__ import annotations

from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
import sys


class HexStrikeMCP:
    """Connect to pentrai_mcp.py inside an already isolated job runner.

    The bridge must reach a runner-local HexStrike server. Network containment,
    process isolation, and tool authorization belong to the runner and job guard.
    """

    def __init__(self, bridge_path: Path, server_url: str):
        parsed = urlsplit(server_url)
        if (parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
                or parsed.username or parsed.password or parsed.path not in {"", "/"}
                or parsed.query or parsed.fragment or parsed.port is None):
            raise ValueError("HexStrike server must be runner-local HTTP")
        if not bridge_path.is_file() or bridge_path.name != "pentrai_mcp.py":
            raise ValueError("native HexStrike MCP bridge is missing")
        self.bridge_path = bridge_path.resolve()
        self.server_url = server_url
        self._stack: AsyncExitStack | None = None
        self._session: Any = None

    async def __aenter__(self) -> "HexStrikeMCP":
        try:
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
        except ImportError as exc:
            raise RuntimeError("install the runner extra to use native HexStrike MCP") from exc
        stack = AsyncExitStack()
        try:
            params = StdioServerParameters(
                command=sys.executable,
                args=[str(self.bridge_path), "--server", self.server_url],
            )
            reader, writer = await stack.enter_async_context(stdio_client(params))
            self._session = await stack.enter_async_context(ClientSession(reader, writer))
            await self._session.initialize()
        except BaseException:
            await stack.aclose()
            self._session = None
            raise
        self._stack = stack
        return self

    async def __aexit__(self, *_exc: object) -> None:
        if self._stack is not None:
            await self._stack.aclose()
        self._stack = None
        self._session = None

    async def list_tools(self) -> list[dict[str, Any]]:
        if self._session is None:
            raise RuntimeError("HexStrike MCP session is not connected")
        response = await self._session.list_tools()
        return [tool.model_dump(mode="json", by_alias=True) for tool in response.tools]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if self._session is None:
            raise RuntimeError("HexStrike MCP session is not connected")
        response = await self._session.call_tool(name, arguments)
        return response.model_dump(mode="json", by_alias=True)

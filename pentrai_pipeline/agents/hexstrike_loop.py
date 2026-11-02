"""Bounded native HexStrike tool loop for an already authorized runner job."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Protocol

from .llm import LLMClient, LLMToolTurn


class HexStrikeSession(Protocol):
    async def list_tools(self) -> list[dict[str, Any]]: ...
    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any: ...


Guard = Callable[[str, dict[str, Any]], Awaitable[None]]


@dataclass(frozen=True)
class LoopLimits:
    max_turns: int = 12
    max_tool_calls: int = 32
    max_tool_output_chars: int = 16_000

    def __post_init__(self) -> None:
        if min(self.max_turns, self.max_tool_calls, self.max_tool_output_chars) <= 0:
            raise ValueError("loop limits must be positive")


@dataclass
class LoopResult:
    explanation: str
    usage: dict[str, int] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)


async def run_hexstrike_loop(
    model: LLMClient,
    session: HexStrikeSession,
    messages: list[dict[str, Any]],
    guard: Guard,
    *,
    limits: LoopLimits = LoopLimits(),
) -> LoopResult:
    """Give the model native schemas, then guard every proposed MCP call.

    This function requires a runner-enforced job guard. It does not authorize a
    job or contain the legacy engine by itself.
    """
    catalog = await session.list_tools()
    if not catalog or any(not isinstance(item, dict) for item in catalog):
        raise ValueError("HexStrike returned no usable tool catalog")
    names: set[str] = set()
    definitions = []
    for item in catalog:
        name = item.get("name")
        schema = item.get("inputSchema")
        if not isinstance(name, str) or not name or name in names or not isinstance(schema, dict):
            raise ValueError("HexStrike tool catalog is invalid")
        names.add(name)
        definitions.append({"type": "function", "function": {
            "name": name, "description": item.get("description") or "",
            "parameters": schema,
        }})

    conversation = list(messages)
    result = LoopResult("")
    calls_used = 0
    for _ in range(limits.max_turns):
        turn: LLMToolTurn = await asyncio.to_thread(model.chat_tools, conversation, tools=definitions)
        for key, value in turn.usage.items():
            result.usage[key] = result.usage.get(key, 0) + value
        conversation.append(turn.message)
        calls = turn.message.get("tool_calls") or []
        if not calls:
            result.explanation = turn.message["content"]
            return result
        if calls_used + len(calls) > limits.max_tool_calls:
            raise RuntimeError("HexStrike tool-call budget exhausted")
        for call in calls:
            name = call["function"]["name"]
            if name not in names:
                raise ValueError("model requested an unknown HexStrike tool")
            try:
                arguments = json.loads(call["function"]["arguments"])
            except json.JSONDecodeError as exc:
                raise ValueError("model supplied invalid tool arguments") from exc
            if not isinstance(arguments, dict):
                raise ValueError("HexStrike tool arguments must be an object")
            await guard(name, arguments)
            output = await session.call_tool(name, arguments)
            serialized = json.dumps(output, default=str, ensure_ascii=False)
            digest = hashlib.sha256(serialized.encode()).hexdigest()
            argument_digest = hashlib.sha256(json.dumps(arguments, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest()
            result.events.append({"tool": name, "arguments_sha256": argument_digest,
                                  "output_sha256": digest, "output_chars": len(serialized),
                                  "is_error": bool(output.get("isError")) if isinstance(output, dict) else False})
            conversation.append({"role": "tool", "tool_call_id": call["id"],
                                 "content": json.dumps({
                                     "output_sha256": digest,
                                     "result_excerpt": serialized[:limits.max_tool_output_chars],
                                     "truncated": len(serialized) > limits.max_tool_output_chars,
                                 })})
            calls_used += 1
    raise RuntimeError("HexStrike model-turn budget exhausted")

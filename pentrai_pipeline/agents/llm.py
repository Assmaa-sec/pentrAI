"""
Thin, provider-agnostic LLM client (OpenAI-compatible chat completions).

Defaults to the existing PentrAI `llm_proxy` (hooks/llm_proxy.py) so tool calls
keep being logged, but it will talk to any OpenAI-compatible endpoint. Kept
minimal on purpose: the agents build prompts and parse structured output; this
layer just does the HTTP round-trip and retries.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Optional
from urllib.parse import urlsplit

import httpx

from ..config import LLMSettings


@dataclass
class LLMResponse:
    text: str
    raw: dict[str, Any]


@dataclass(frozen=True)
class LLMToolTurn:
    """One model turn; tool calls are proposals, not executed by this client."""

    message: dict[str, Any]
    usage: dict[str, int]


class LLMClient:
    def __init__(self, settings: LLMSettings):
        self.settings = settings

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = 0.2,
        tools: Optional[list[dict]] = None,
        response_format: Optional[dict] = None,
    ) -> LLMResponse:
        """POST to `${base_url}/chat/completions` and return the assistant message.

        Implementation notes for later:
          * use `requests` with `self.settings.request_timeout_s`
          * pass `self.settings.model`, temperature, and (when given) `tools` /
            `response_format` straight through — the endpoint is OpenAI-shaped
          * retry idempotently on 5xx / timeout with backoff
        """
        if tools:
            raise ValueError("raw model tool calls are forbidden; use the policy harness")
        raw = self._completion(messages, temperature=temperature,
                               response_format=response_format)
        choices = raw.get("choices")
        message = choices[0].get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            raise ValueError("model response has no text")
        return LLMResponse(content, raw)

    def chat_tools(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: list[dict[str, Any]],
        temperature: float = 0.2,
    ) -> LLMToolTurn:
        """Request native function calls for a separately authorized tool runner.

        Returning a tool call never executes it. The caller must validate the
        name and arguments against its job-bound MCP session and policy.
        """
        if not tools or any(not isinstance(tool, dict) for tool in tools):
            raise ValueError("tool definitions are required")
        raw = self._completion(messages, temperature=temperature, tools=tools)
        message = raw["choices"][0]["message"]
        if not isinstance(message, dict) or message.get("role") != "assistant":
            raise ValueError("model response has no assistant message")
        calls = message.get("tool_calls") or []
        if not isinstance(calls, list):
            raise ValueError("model tool calls must be a list")
        seen: set[str] = set()
        for call in calls:
            function = call.get("function") if isinstance(call, dict) else None
            identifier = call.get("id") if isinstance(call, dict) else None
            if (
                not isinstance(identifier, str) or not identifier or identifier in seen
                or call.get("type") != "function"
                or not isinstance(function, dict)
                or not isinstance(function.get("name"), str)
                or not function["name"]
                or not isinstance(function.get("arguments"), str)
                or len(function["arguments"]) > 65_536
            ):
                raise ValueError("model returned an invalid tool call")
            seen.add(identifier)
        if not calls and not isinstance(message.get("content"), str):
            raise ValueError("model response has neither text nor tool calls")
        usage = raw.get("usage") or {}
        if not isinstance(usage, dict):
            raise ValueError("model usage must be an object")
        metered: dict[str, int] = {}
        for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
            value = usage.get(key)
            if value is not None:
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    raise ValueError("model usage is invalid")
                metered[key] = value
        return LLMToolTurn(message, metered)

    def _completion(
        self,
        messages: list[dict[str, Any]],
        *,
        temperature: float,
        tools: list[dict[str, Any]] | None = None,
        response_format: dict | None = None,
    ) -> dict[str, Any]:
        parsed = urlsplit(self.settings.base_url)
        if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}):
            raise ValueError("model endpoint must use HTTPS or loopback")
        if not self.settings.model or not 0 <= temperature <= 1:
            raise ValueError("model and bounded temperature are required")
        payload: dict[str, Any] = {"model": self.settings.model, "messages": messages,
                                   "temperature": temperature}
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        if response_format:
            payload["response_format"] = response_format
        headers = {"Authorization": f"Bearer {self.settings.api_key}"} if self.settings.api_key else {}
        with httpx.Client(timeout=min(self.settings.request_timeout_s, 120),
                          follow_redirects=False, trust_env=False) as client:
            response = client.post(f"{self.settings.base_url.rstrip('/')}/chat/completions",
                                   json=payload, headers=headers)
            response.raise_for_status()
            if len(response.content) > 1024 * 1024:
                raise ValueError("model response exceeds limit")
            raw = response.json()
        choices = raw.get("choices") if isinstance(raw, dict) else None
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise ValueError("model response has no choice")
        return raw

    def structured(self, messages: list[dict[str, str]], schema: dict) -> dict:
        """Chat constrained to a JSON schema; return the parsed object.

        Wraps `chat(response_format=...)` and validates the result against `schema`
        so stages get typed data, not free text.
        """
        response = self.chat(messages, temperature=0, response_format={"type": "json_object"})
        value = json.loads(response.text)
        if not isinstance(value, dict):
            raise ValueError("structured model response must be an object")
        required = schema.get("required", [])
        if not isinstance(required, list) or any(key not in value for key in required):
            raise ValueError("structured model response lacks required fields")
        return value

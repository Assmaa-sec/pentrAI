#!/usr/bin/env python3

import sys
import json
import os
import logging

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
LOG_FILE = os.path.join(PROJECT_DIR, "tool_logger.log")
CONFIG_FILE = os.path.join(PROJECT_DIR, "pentrai_config.json")

# The MCP server key as shown by `claude mcp list`.
# Hook receives pentrai MCP tool calls as "mcp__pentrai__<tool_name>".
PENTRAI_MCP_PREFIX = "mcp__pentrai__"

_logger = logging.getLogger("hook_tool_logger")
_logger.setLevel(logging.INFO)
_logger.propagate = False
_handler = logging.FileHandler(LOG_FILE)
_handler.setFormatter(logging.Formatter("%(message)s"))
_logger.addHandler(_handler)

def _load_config() -> dict:
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _is_session_active(config: dict) -> bool:
    """Return True only between start_timer() and stop_timer() calls.

    start_timer sets timer_start and resets elapsed_seconds to None.
    stop_timer sets elapsed_seconds to a float.
    So an active session has timer_start set and elapsed_seconds absent/null.
    """
    return bool(config.get("timer_start")) and config.get("elapsed_seconds") is None


def _summarise_input(tool_input: dict) -> str:
    try:
        parts = []
        for k, v in list(tool_input.items())[:3]:
            val = str(v)
            parts.append(f"{k}={val[:60]}{'…' if len(val) > 60 else ''}")
        return " | ".join(parts)
    except Exception:
        return ""


def main():
    try:
        raw = sys.stdin.read()
        event = json.loads(raw) if raw.strip() else {}
    except Exception:
        event = {}

    tool_name = event.get("tool_name") or event.get("name") or "unknown"
    tool_input = event.get("tool_input") or event.get("input") or {}

    # Pentrai MCP tools are logged by the MCP-side logger in pentrai_mcp.py.
    # Detect them by prefix so the list stays current as new tools are added to the server.
    if tool_name.startswith(PENTRAI_MCP_PREFIX):
        return

    config = _load_config()

    # Only log within an active CTF session (after start_timer, before stop_timer).
    # This eliminates noise from the setup phase and any post-session activity.
    if not _is_session_active(config):
        return

    params_summary = _summarise_input(tool_input)

    # pentrafix #5: during Exp 2/3 (pentrai-tools-only), any native tool call is a constraint
    # violation. Flag it in the log when the active experiment can be detected via prompt_type.
    prompt_type = str(config.get("prompt_type", "")).lower()
    is_strict = "experiment" in prompt_type and ("2" in prompt_type or "3" in prompt_type)
    if is_strict:
        _logger.info(
            f"NATIVE TOOL | tool={tool_name} | params={params_summary} | CONSTRAINT_VIOLATION ({prompt_type})"
        )
    else:
        _logger.info(f"NATIVE TOOL | tool={tool_name} | params={params_summary}")


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
PentrAI LLM API Proxy
=======================
Sits between any OpenAI-compatible client (roo-code, 5ire, trae, cursor, etc.)
and the real LLM API (DeepSeek, OpenAI, etc.).

Intercepts all tool_calls from LLM responses and logs them to tool_logger.log
as NATIVE TOOL lines inside the active session block.

Usage
-----
  python3 hooks/llm_proxy.py
  python3 hooks/llm_proxy.py --backend https://api.deepseek.com --port 8889

Then in your client:
  Base URL : http://127.0.0.1:8889/v1
"""

import argparse
import json
import logging
import os
import sys

import requests
from flask import Flask, request, Response, stream_with_context

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE    = os.path.join(PROJECT_DIR, "tool_logger.log")
CONFIG_FILE = os.path.join(PROJECT_DIR, "pentrai_config.json")

# ---------------------------------------------------------------------------
# Loggers
# ---------------------------------------------------------------------------

# Plain — no timestamp, writes inside the session block
_logger_plain = logging.getLogger("llm_proxy_plain")
_logger_plain.setLevel(logging.INFO)
_logger_plain.propagate = False
_fh_plain = logging.FileHandler(LOG_FILE)
_fh_plain.setFormatter(logging.Formatter("%(message)s"))
_logger_plain.addHandler(_fh_plain)

# Stdout — proxy activity visible in terminal
_logger_stdout = logging.getLogger("llm_proxy_stdout")
_logger_stdout.setLevel(logging.INFO)
_logger_stdout.propagate = False
_sh = logging.StreamHandler(sys.stdout)
_sh.setFormatter(logging.Formatter("%(asctime)s [llm-proxy] %(message)s"))
_logger_stdout.addHandler(_sh)

app = Flask(__name__)
BACKEND_URL = "https://api.deepseek.com"
# Upstream HTTP(S) proxy used to reach the backend (e.g. a local Clash/VPN proxy).
# Default preserves the original hard-coded value; set to "" to disable proxying.
UPSTREAM_PROXY = "http://127.0.0.1:7890"


# ---------------------------------------------------------------------------
# Config / session helpers
# ---------------------------------------------------------------------------

def _load_config() -> dict:
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _is_session_active(config: dict) -> bool:
    """True only between start_timer() and stop_timer()."""
    return bool(config.get("timer_start")) and config.get("elapsed_seconds") is None


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _log_tool_call(tool_name: str, tool_args: dict) -> None:
    # Skip PentrAI MCP tools regardless of how the client namespaces them
    # (Claude uses "mcp__pentrai__"; other clients vary). They are logged
    # MCP-side by pentrai_mcp.py, so logging them here would double-count them.
    if "pentrai" in tool_name.lower():
        return

    config = _load_config()
    if not _is_session_active(config):
        return

    parts = []
    for k, v in list(tool_args.items())[:3]:
        val = str(v)
        parts.append(f"{k}={val[:60]}{'…' if len(val) > 60 else ''}")
    params_str = " | ".join(parts) if parts else ""

    line = f"NATIVE TOOL | tool={tool_name} | params={params_str}"
    _logger_plain.info(line)
    _logger_stdout.info(line)


# ---------------------------------------------------------------------------
# Tool call extraction
# ---------------------------------------------------------------------------

def _log_from_complete_response(body: dict) -> None:
    try:
        for choice in body.get("choices", []):
            msg = choice.get("message", {})
            for tc in msg.get("tool_calls", []):
                name = tc.get("function", {}).get("name", "unknown")
                raw_args = tc.get("function", {}).get("arguments", "{}")
                try:
                    args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                except Exception:
                    args = {"_raw": str(raw_args)[:200]}
                _log_tool_call(name, args)
    except Exception:
        pass


def _log_from_stream_chunks(chunks: list) -> None:
    try:
        acc: dict = {}
        for chunk in chunks:
            for choice in chunk.get("choices", []):
                for tc in choice.get("delta", {}).get("tool_calls", []):
                    idx = tc.get("index", 0)
                    if idx not in acc:
                        acc[idx] = {"name": "", "arguments": ""}
                    fn = tc.get("function", {})
                    acc[idx]["name"]      += fn.get("name") or ""
                    acc[idx]["arguments"] += fn.get("arguments") or ""
        for entry in acc.values():
            name = entry["name"] or "unknown"
            raw_args = entry["arguments"]
            try:
                args = json.loads(raw_args) if raw_args else {}
            except Exception:
                args = {"_raw": raw_args[:200]}
            _log_tool_call(name, args)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Proxy route
# ---------------------------------------------------------------------------

@app.route("/v1/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy(path: str):
    target = f"{BACKEND_URL}/v1/{path}"

    fwd_headers = {
        k: v for k, v in request.headers
        if k.lower() not in ("host", "content-length", "transfer-encoding", "connection")
    }

    raw_body = request.get_data()

    try:
        body = json.loads(raw_body) if raw_body else {}
    except Exception:
        body = {}

    # --- 5ire / tool constraint enforcement (pentrafix #3) ---
    # Inject system-level constraint into chat completions to steer LLMs
    # toward pentrai tools and away from native client tools
    if path.startswith("chat/completions") and isinstance(body.get("messages"), list):
        config = _load_config()
        if _is_session_active(config):
            constraint_msg = {
                "role": "system",
                "content": (
                    "CRITICAL CONSTRAINT: Use ONLY the PentrAI MCP tools provided in this environment. "
                    "Do NOT use Bash, Read, Write, or any native/built-in client tools — they are disabled here. "
                    "For binary exploitation use pwntools_exploit. "
                    "For Python scripts use execute_python_script. "
                    "For HTTP requests use http_framework_test. "
                    "To run a shell command use the PentrAI execute_command tool."
                )
            }
            # Insert after existing system messages but before user messages
            messages = body["messages"]
            insert_idx = 0
            for i, m in enumerate(messages):
                if m.get("role") == "system":
                    insert_idx = i + 1
                else:
                    break
            messages.insert(insert_idx, constraint_msg)
            body["messages"] = messages
            raw_body = json.dumps(body).encode("utf-8")
            fwd_headers["Content-Length"] = str(len(raw_body))

    is_streaming = bool(body.get("stream", False))

    upstream = requests.request(
        method  = request.method,
        url     = target,
        headers = fwd_headers,
        data    = raw_body,
        stream  = is_streaming,
        timeout = 300,
        proxies = {"https": UPSTREAM_PROXY, "http": UPSTREAM_PROXY} if UPSTREAM_PROXY else None
    )

    excluded = {"transfer-encoding", "connection", "content-encoding", "content-length"}
    resp_headers = {k: v for k, v in upstream.headers.items() if k.lower() not in excluded}

    if is_streaming:
        def generate():
            chunks = []
            for raw_line in upstream.iter_lines(chunk_size=None):
                if not raw_line:
                    continue
                yield raw_line + b"\n\n"
                line = raw_line.decode("utf-8", errors="replace").strip()
                if line.startswith("data: ") and line != "data: [DONE]":
                    try:
                        chunks.append(json.loads(line[6:]))
                    except Exception:
                        pass
            _log_from_stream_chunks(chunks)

        return Response(
            stream_with_context(generate()),
            status       = upstream.status_code,
            headers      = resp_headers,
            content_type = upstream.headers.get("Content-Type", "text/event-stream"),
        )

    else:
        content = upstream.content
        try:
            _log_from_complete_response(json.loads(content))
        except Exception:
            pass
        return Response(content, status=upstream.status_code, headers=resp_headers)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="PentrAI LLM API proxy — logs all LLM tool_calls"
    )
    parser.add_argument(
        "--backend", default="https://api.deepseek.com",
        help="Real LLM API base URL (default: https://api.deepseek.com)"
    )
    parser.add_argument(
        "--port", type=int, default=8889,
        help="Local port to listen on (default: 8889)"
    )
    parser.add_argument(
        "--host", default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--upstream-proxy", default="http://127.0.0.1:7890",
        help="HTTP(S) proxy used to reach the backend, e.g. a local Clash/VPN "
             "(default: http://127.0.0.1:7890; pass '' to disable)"
    )
    args = parser.parse_args()

    global BACKEND_URL, UPSTREAM_PROXY
    BACKEND_URL = args.backend.rstrip("/")
    UPSTREAM_PROXY = args.upstream_proxy.strip()

    print(f"[pentrai-proxy] Listening on http://{args.host}:{args.port}/v1")
    print(f"[pentrai-proxy] Forwarding to {BACKEND_URL}")
    print(f"[pentrai-proxy] Logging to {LOG_FILE}")
    print(f"[pentrai-proxy] Set client Base URL = http://{args.host}:{args.port}/v1")

    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
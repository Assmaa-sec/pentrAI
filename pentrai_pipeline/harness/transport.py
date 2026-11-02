"""Private HTTP adapter from the harness to a PentrAI tool server."""

from __future__ import annotations

from typing import Any

import requests


class PentrAIHTTPTransport:
    """Call a PentrAI server reachable only inside a runner environment."""

    def __init__(self, base_url: str, timeout_s: int = 90):
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s

    def call(self, tool: str, **params: Any) -> dict[str, Any]:
        response = requests.post(
            f"{self.base_url}/api/tools/{tool}", json=params, timeout=self.timeout_s
        )
        try:
            body = response.json()
        except ValueError:
            body = {"success": False, "error": "tool server returned non-JSON output", "stdout": response.text}
        if not response.ok:
            body.setdefault("success", False)
            body.setdefault("error", f"tool server returned HTTP {response.status_code}")
        return body

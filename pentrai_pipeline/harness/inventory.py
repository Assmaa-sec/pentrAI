"""Static inventory of legacy routes and MCP tools.

This is an audit aid, not an executable broker registry. Every discovered tool
starts unsupported until a separate reviewed adapter is added to policy.py.
Parsing source avoids importing the legacy server and its side effects.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any


INVENTORY_SCHEMA_VERSION = 1


def _decorated_with(function: ast.FunctionDef, owner: str, method: str) -> ast.Call | None:
    for decorator in function.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        callee = decorator.func
        if (
            isinstance(callee, ast.Attribute)
            and callee.attr == method
            and isinstance(callee.value, ast.Name)
            and callee.value.id == owner
        ):
            return decorator
    return None


def _literal_endpoint(function: ast.FunctionDef) -> str | None:
    for node in ast.walk(function):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in {"safe_get", "safe_post"} or not node.args:
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value
    return None


def build_inventory(server_path: Path, mcp_path: Path) -> dict[str, Any]:
    """List the current legacy surface without importing or enabling any tool."""
    server = ast.parse(server_path.read_text(encoding="utf-8"), filename=str(server_path))
    mcp = ast.parse(mcp_path.read_text(encoding="utf-8"), filename=str(mcp_path))

    routes = []
    for node in ast.walk(server):
        if not isinstance(node, ast.FunctionDef):
            continue
        decorator = _decorated_with(node, "app", "route")
        if decorator is None or not decorator.args:
            continue
        path = ast.literal_eval(decorator.args[0])
        methods = next((ast.literal_eval(k.value) for k in decorator.keywords if k.arg == "methods"), ["GET"])
        routes.append({"path": path, "methods": methods, "handler": node.name, "line": node.lineno})

    client_endpoints: dict[str, str] = {}
    for node in ast.walk(mcp):
        if isinstance(node, ast.ClassDef) and node.name == "PentrAIClient":
            for method in node.body:
                if isinstance(method, ast.FunctionDef):
                    endpoint = _literal_endpoint(method)
                    if endpoint:
                        client_endpoints[method.name] = endpoint

    tools = []
    for node in ast.walk(mcp):
        if not isinstance(node, ast.FunctionDef) or _decorated_with(node, "mcp", "tool") is None:
            continue
        endpoint = _literal_endpoint(node)
        if endpoint is None:
            for call in ast.walk(node):
                if (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Attribute)
                    and isinstance(call.func.value, ast.Name)
                    and call.func.value.id == "pentrai_client"
                ):
                    endpoint = client_endpoints.get(call.func.attr)
                    if endpoint:
                        break
        parameters = [arg.arg for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]
        tools.append(
            {
                "name": node.name,
                "parameters": parameters,
                "server_endpoint": endpoint,
                "broker_status": "unsupported",
                "line": node.lineno,
            }
        )

    return {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "server_routes": sorted(routes, key=lambda route: route["path"]),
        "mcp_tools": sorted(tools, key=lambda tool: tool["name"]),
    }


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    inventory = build_inventory(root / "pentrai_server.py", root / "pentrai_mcp.py")
    print(json.dumps(inventory, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

"""Audit native MCP-to-HTTP wiring without executing customer-facing tools."""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pentrai_pipeline.harness.inventory import build_inventory


def _route_pattern(route: str) -> re.Pattern[str]:
    parts = re.split(r"(<(?:[^:>]+:)?[^>]+>)", route)
    pattern = "".join("[^/]+" if part.startswith("<") else re.escape(part)
                      for part in parts)
    return re.compile(f"^{pattern}$")


def _endpoint_call(node: ast.Call) -> tuple[str, str] | None:
    if not isinstance(node.func, ast.Attribute) or node.func.attr not in {"safe_get", "safe_post", "safe_delete"}:
        return None
    if not node.args:
        return None
    argument = node.args[0]
    method = {"safe_get": "GET", "safe_post": "POST", "safe_delete": "DELETE"}[node.func.attr]
    if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
        return argument.value, method
    if isinstance(argument, ast.JoinedStr):
        return ("".join(part.value if isinstance(part, ast.Constant) else "_value_"
                        for part in argument.values), method)
    return None


def audit_catalog(root: Path) -> dict:
    inventory = build_inventory(root / "pentrai_server.py", root / "pentrai_mcp.py")
    tree = ast.parse((root / "pentrai_mcp.py").read_text(encoding="utf-8"))
    functions = {node.name: node for node in ast.walk(tree)
                 if isinstance(node, ast.FunctionDef)}
    routes = inventory["server_routes"]
    patterns = [(_route_pattern(route["path"]), route["path"], route["methods"])
                for route in routes]
    audited = []
    for tool in inventory["mcp_tools"]:
        function = functions[tool["name"]]
        calls = sorted({endpoint for node in ast.walk(function)
                            if isinstance(node, ast.Call)
                            if (endpoint := _endpoint_call(node)) is not None})
        if not calls and tool["server_endpoint"]:
            calls = [(tool["server_endpoint"], "UNKNOWN")]
        matches = sorted({route for endpoint, method in calls
                          for pattern, route, methods in patterns
                          if pattern.fullmatch("/" + endpoint.lstrip("/"))
                          and (method == "UNKNOWN" or method in methods)})
        if calls and len(matches) == len(calls):
            status = "route_bound"
        elif calls:
            status = "missing_route"
        else:
            status = "mcp_local_or_composite"
        audited.append({"name": tool["name"], "status": status,
                        "requested_endpoints": [endpoint for endpoint, _ in calls],
                        "requested_methods": [method for _, method in calls],
                        "matched_routes": matches,
                        "source_line": tool["line"]})
    counts = {status: sum(tool["status"] == status for tool in audited)
              for status in ("route_bound", "mcp_local_or_composite", "missing_route")}
    return {"schema_version": 1, "total_mcp_tools": len(audited),
            "counts": counts, "tools": audited}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    report = audit_catalog(arguments.root)
    payload = json.dumps(report, indent=2) + "\n"
    if arguments.output:
        arguments.output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    if report["counts"]["missing_route"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

from __future__ import annotations

import unittest
from pathlib import Path

from runner.audit_catalog import _route_pattern, audit_catalog


ROOT = Path(__file__).resolve().parents[1]


class NativeToolAuditTests(unittest.TestCase):
    def test_dynamic_route_matching(self):
        route = _route_pattern("/api/processes/status/<int:pid>")
        self.assertTrue(route.fullmatch("/api/processes/status/_value_"))
        self.assertFalse(route.fullmatch("/api/processes/status/_value_/extra"))

    def test_every_declared_mcp_tool_is_accounted_for(self):
        report = audit_catalog(ROOT)
        self.assertEqual(169, report["total_mcp_tools"])
        self.assertEqual(report["total_mcp_tools"], sum(report["counts"].values()))
        self.assertEqual(len({tool["name"] for tool in report["tools"]}),
                         report["total_mcp_tools"])
        by_name = {tool["name"]: tool for tool in report["tools"]}
        self.assertEqual("route_bound", by_name["delete_file"]["status"])
        self.assertEqual(["DELETE"], by_name["delete_file"]["requested_methods"])
        self.assertEqual("missing_route", by_name["burpsuite_scan"]["status"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ToolInventoryTests(unittest.TestCase):
    def test_inventory_covers_legacy_surface_without_enabling_it(self):
        from pentrai_pipeline.harness.inventory import build_inventory

        inventory = build_inventory(ROOT / "pentrai_server.py", ROOT / "pentrai_mcp.py")
        self.assertEqual(1, inventory["schema_version"])
        self.assertGreaterEqual(len(inventory["server_routes"]), 170)
        self.assertGreaterEqual(len(inventory["mcp_tools"]), 160)
        self.assertTrue(all(tool["broker_status"] == "unsupported" for tool in inventory["mcp_tools"]))

        routes = {route["path"] for route in inventory["server_routes"]}
        nmap = next(tool for tool in inventory["mcp_tools"] if tool["name"] == "nmap_scan")
        self.assertEqual("api/tools/nmap", nmap["server_endpoint"])
        self.assertIn("/api/tools/nmap", routes)
        self.assertIn("target", nmap["parameters"])
        self.assertIn("api/command", {tool["server_endpoint"] for tool in inventory["mcp_tools"]})


if __name__ == "__main__":
    unittest.main()

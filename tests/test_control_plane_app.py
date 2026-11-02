from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient


class ControlPlaneAppTests(unittest.TestCase):
    def test_settings_reject_default_signing_key(self):
        from control_plane.settings import Settings

        with patch.dict(
            "os.environ",
            {"PENTRAI_DATABASE_URL": "postgresql+psycopg://localhost/pentrai", "PENTRAI_GRANT_SIGNING_KEY": "change-me"},
        ):
            with self.assertRaisesRegex(ValueError, "grant signing key"):
                Settings.from_env()

    def test_health_and_dynamic_default(self):
        from control_plane.app import create_app
        from control_plane.settings import Settings

        settings = Settings(database_url="sqlite+pysqlite:///:memory:", grant_signing_key="k" * 32)
        self.assertFalse(settings.dynamic_scans_enabled)
        with TestClient(create_app(settings)) as client:
            response = client.get("/healthz")
        self.assertEqual(200, response.status_code)
        self.assertEqual({"status": "ok"}, response.json())

    def test_static_backend_requires_local_development_mode(self):
        from control_plane.settings import Settings

        with self.assertRaisesRegex(ValueError, "local development"):
            Settings(database_url="sqlite+pysqlite:///:memory:",
                     grant_signing_key="k" * 32, local_static_enabled=True)
        with self.assertRaisesRegex(ValueError, "only one"):
            Settings(database_url="sqlite+pysqlite:///:memory:",
                     grant_signing_key="k" * 32, local_dev_auth=True,
                     local_static_enabled=True, native_runner_ready=True)


if __name__ == "__main__":
    unittest.main()

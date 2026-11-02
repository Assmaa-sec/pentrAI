"""Existing scans retain their executor when native routing is introduced."""

from __future__ import annotations

from contextlib import closing
import os
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch
from uuid import uuid4

from alembic import command
from alembic.config import Config


class ScanBackendMigrationTests(unittest.TestCase):
    def test_existing_source_and_url_scans_keep_distinct_routes(self):
        path = Path(".tmp") / f"scan-backend-migration-{uuid4().hex}.db"
        try:
            config = Config("alembic.ini")
            with patch.dict(os.environ, {"PENTRAI_DATABASE_URL": f"sqlite:///./{path.as_posix()}"}):
                command.upgrade(config, "d4f7c38a09b2")
                with closing(sqlite3.connect(path)) as db:
                    with db:
                        for scan_id, target_url in (("source", None), ("site", "https://example.com/")):
                            db.execute("""INSERT INTO scans
                            (id, organization_id, project_id, target_url, source_digest,
                             scope_digest, scope_note, profile, dynamic_authorized,
                             state, created_at, updated_at)
                            VALUES (?, 'org', 'project', ?, ?, ?, 'owned', 'standard',
                                    ?, 'AUTHORIZED', '2026-10-31', '2026-10-31')""",
                                (scan_id, target_url, "a" * 64, "b" * 64, target_url is not None))
                command.upgrade(config, "head")
            with closing(sqlite3.connect(path)) as db:
                with db:
                    db.execute("""INSERT INTO scans
                        (id, organization_id, project_id, source_digest,
                         scope_digest, scope_note, profile, dynamic_authorized,
                         state, created_at, updated_at)
                        VALUES ('new', 'org', 'project', ?, ?, 'owned', 'standard',
                                0, 'AUTHORIZED', '2026-10-31', '2026-10-31')""",
                        ("a" * 64, "b" * 64))
                rows = dict(db.execute("SELECT id, execution_backend FROM scans"))
            self.assertEqual({"source": "local_static", "site": "hexstrike",
                              "new": "hexstrike"}, rows)
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()

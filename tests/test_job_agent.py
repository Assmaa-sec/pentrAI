from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import unittest
from uuid import uuid4

from execution_manager.job_agent import JobScope, _collector_url, _source_inventory


class JobAgentScopeTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 30, tzinfo=timezone.utc)
        self.scope = {
            "scan_id": "11111111-1111-4111-8111-111111111111",
            "organization_id": "22222222-2222-4222-8222-222222222222",
            "lease_id": "33333333-3333-4333-8333-333333333333",
            "source_digest": "a" * 64,
            "scope_digest": "b" * 64,
            "source_present": True,
            "target_url": None,
            "scope_note": "Authorized source",
            "profile": "standard",
            "expires_at": (self.now + timedelta(minutes=10)).isoformat(),
        }

    def test_rejects_expired_scope_and_inconsistent_targets(self):
        self.assertTrue(JobScope.from_dict(self.scope, now=self.now).source_present)
        with self.assertRaisesRegex(ValueError, "expired"):
            JobScope.from_dict(self.scope, now=self.now + timedelta(minutes=11))
        with self.assertRaisesRegex(ValueError, "disagree"):
            JobScope.from_dict({**self.scope, "source_present": False}, now=self.now)
        with self.assertRaisesRegex(ValueError, "canonical"):
            JobScope.from_dict({**self.scope, "target_url": "https://EXAMPLE.com/"}, now=self.now)
        with self.assertRaisesRegex(ValueError, "no assessment"):
            JobScope.from_dict({**self.scope, "source_present": False,
                                "source_digest": __import__("hashlib").sha256(b"").hexdigest()}, now=self.now)

    def test_inventory_rejects_symlinks_and_answer_key(self):
        workspace = (Path(__file__).parents[1] / ".tmp").resolve()
        directory = (workspace / f"job-agent-test-{uuid4().hex}").resolve()
        self.assertTrue(directory.is_relative_to(workspace))
        directory.mkdir(exist_ok=False)
        try:
            (directory / "app.py").write_text("print('fixture')", encoding="utf-8")
            self.assertEqual('["app.py"]', _source_inventory(directory))
            (directory / "guinea_pig").mkdir()
            (directory / "guinea_pig" / "SOLUTIONS.md").write_text("secret", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "answer key"):
                _source_inventory(directory)
            (directory / "guinea_pig" / "SOLUTIONS.md").unlink()
            try:
                (directory / "link.py").symlink_to(directory / "app.py")
            except (OSError, NotImplementedError):
                return
            with self.assertRaisesRegex(ValueError, "symlink"):
                _source_inventory(directory)
        finally:
            shutil.rmtree(directory)

    def test_collector_must_be_private_https(self):
        self.assertEqual("https://10.4.0.3:443/internal/runner-results",
                         _collector_url("https://10.4.0.3:443"))
        for value in ("http://10.4.0.3:443", "https://8.8.8.8:443", "https://127.0.0.1:443"):
            with self.assertRaises(ValueError):
                _collector_url(value)


if __name__ == "__main__":
    unittest.main()

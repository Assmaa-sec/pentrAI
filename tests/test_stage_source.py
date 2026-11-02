from __future__ import annotations

import hashlib
import io
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch
from uuid import uuid4
from zipfile import ZipFile

import httpx

from execution_manager.stage_source import fetch_and_stage_source, stage_source
from static_worker.intake import IntakeRejected


class StageSourceTests(unittest.TestCase):
    def test_digest_and_safe_extraction_without_source_execution(self):
        root = (Path(__file__).parents[1] / ".tmp").resolve()
        workspace = (root / f"stage-test-{uuid4().hex}").resolve()
        self.assertTrue(workspace.is_relative_to(root))
        workspace.mkdir(exist_ok=False)
        try:
            archive = workspace / "input.zip"
            with ZipFile(archive, "w") as output:
                output.writestr("app.py", "raise RuntimeError('must not execute')\n")
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            destination, inventory = stage_source(archive, workspace, digest, archive.stat().st_size)
            self.assertEqual(workspace / "source", destination)
            self.assertEqual(digest, inventory.archive_sha256)
            self.assertTrue((destination / "app.py").is_file())
            with self.assertRaisesRegex(IntakeRejected, "digest"):
                stage_source(archive, workspace, "0" * 64, archive.stat().st_size)
        finally:
            shutil.rmtree(workspace)

    def test_private_broker_bytes_are_verified_before_extraction(self):
        root = (Path(__file__).parents[1] / ".tmp").resolve()
        workspace = (root / f"broker-stage-test-{uuid4().hex}").resolve()
        self.assertTrue(workspace.is_relative_to(root))
        workspace.mkdir(exist_ok=False)
        try:
            scratch = workspace / "scratch"
            staged = workspace / "staged"
            scratch.mkdir()
            staged.mkdir()
            token_path = scratch / "grant"
            token_path.write_text("fixture-token", encoding="utf-8")
            output = io.BytesIO()
            with ZipFile(output, "w") as archive:
                archive.writestr("app.py", "PASSWORD = 'fixture'\n")
            archive_bytes = output.getvalue()
            real_client = httpx.Client
            transport = httpx.MockTransport(lambda request: httpx.Response(200, content=archive_bytes))
            with patch("execution_manager.stage_source.httpx.Client",
                       side_effect=lambda **kwargs: real_client(transport=transport, **kwargs)):
                source, inventory = fetch_and_stage_source(
                    "https://10.4.0.4:443", "11111111-1111-4111-8111-111111111111",
                    token_path, scratch, staged, hashlib.sha256(archive_bytes).hexdigest(),
                    len(archive_bytes),
                )
            self.assertEqual(staged / "source", source)
            self.assertEqual(1, len(inventory.files))
            self.assertFalse((scratch / "source.zip").exists())
        finally:
            shutil.rmtree(workspace)


if __name__ == "__main__":
    unittest.main()

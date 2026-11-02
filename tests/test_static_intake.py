from __future__ import annotations

import stat
import unittest
import uuid
import zipfile
from pathlib import Path


class StaticIntakeTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(".tmp")
        self.root.mkdir(exist_ok=True)
        self.archive = self.root / f"intake-{uuid.uuid4().hex}.zip"

    def tearDown(self):
        self.archive.unlink(missing_ok=True)

    def _write(self, members: list[tuple[str | zipfile.ZipInfo, bytes]]) -> None:
        with zipfile.ZipFile(self.archive, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in members:
                archive.writestr(name, data)

    def test_normal_archive_inventory_has_digest(self):
        from static_worker.intake import IntakeLimits, inspect_archive

        self._write([("app.py", b"print('hi')"), ("requirements.txt", b"flask==3.0.0\n")])
        inventory = inspect_archive(self.archive, IntakeLimits())
        self.assertEqual({"app.py", "requirements.txt"}, {entry.path for entry in inventory.files})
        self.assertEqual(64, len(inventory.manifest_sha256))

    def test_rejects_traversal_and_absolute_paths(self):
        from static_worker.intake import IntakeLimits, IntakeRejected, inspect_archive

        for name in ("../secret", "/etc/passwd", "C:/Windows/file", "a\\..\\escape", "a/./b", "a//b"):
            with self.subTest(name=name):
                self._write([(name, b"x")])
                with self.assertRaisesRegex(IntakeRejected, "path"):
                    inspect_archive(self.archive, IntakeLimits())

    def test_rejects_symlink_and_duplicate_normalized_name(self):
        from static_worker.intake import IntakeLimits, IntakeRejected, inspect_archive

        symlink = zipfile.ZipInfo("link")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        self._write([(symlink, b"/outside")])
        with self.assertRaisesRegex(IntakeRejected, "links"):
            inspect_archive(self.archive, IntakeLimits())

        self._write([("App.py", b"a"), ("app.py", b"b")])
        with self.assertRaisesRegex(IntakeRejected, "duplicate"):
            inspect_archive(self.archive, IntakeLimits())

    def test_rejects_expanded_size_and_ratio(self):
        from static_worker.intake import IntakeLimits, IntakeRejected, inspect_archive

        self._write([("big.txt", b"a" * 4096)])
        with self.assertRaisesRegex(IntakeRejected, "expanded size"):
            inspect_archive(self.archive, IntakeLimits(max_expanded_bytes=1024))
        with self.assertRaisesRegex(IntakeRejected, "compression ratio"):
            inspect_archive(self.archive, IntakeLimits(max_compression_ratio=2))

    def test_extracts_only_after_validating_every_member(self):
        from static_worker.intake import IntakeLimits, IntakeRejected, extract_archive

        workspace = self.root / f"workspace-{uuid.uuid4().hex}"
        workspace.mkdir()
        self._write([("app.py", b"ok"), ("../escape", b"bad")])
        with self.assertRaises(IntakeRejected):
            extract_archive(self.archive, workspace, IntakeLimits())
        self.assertFalse((workspace / "source").exists())
        self.assertFalse((workspace.parent / "escape").exists())

        self._write([("src/app.py", b"ok")])
        extracted = extract_archive(self.archive, workspace, IntakeLimits())
        self.assertEqual(b"ok", (extracted / "src" / "app.py").read_bytes())
        (extracted / "src" / "app.py").unlink()
        (extracted / "src").rmdir()
        extracted.rmdir()
        workspace.rmdir()


if __name__ == "__main__":
    unittest.main()

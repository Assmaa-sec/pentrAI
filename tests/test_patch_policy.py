from __future__ import annotations

import unittest

from pentrai_pipeline.remediation.patch_policy import PatchPolicy, validate_patch


GOOD_DIFF = """diff --git a/src/app.py b/src/app.py
index 1234567..abcdef0 100644
--- a/src/app.py
+++ b/src/app.py
@@ -1,2 +1,2 @@
 first
-old
+new
"""


class PatchPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = PatchPolicy(("src/",), max_files=1, max_changed_lines=2)

    def test_small_modification_is_allowed(self):
        result = validate_patch(GOOD_DIFF, self.policy)
        self.assertTrue(result.allowed, result.reasons)
        self.assertEqual(("src/app.py",), result.files)
        self.assertEqual(2, result.changed_lines)

    def test_path_escape_and_change_budget_are_rejected(self):
        escaped = GOOD_DIFF.replace("src/app.py", "../.env")
        result = validate_patch(escaped, PatchPolicy(("src/",), max_changed_lines=1))
        self.assertFalse(result.allowed)
        self.assertIn("path", result.reasons)
        self.assertIn("changed_lines", result.reasons)
        hidden = GOOD_DIFF.replace("src/app.py", "src/.env")
        self.assertIn("path", validate_patch(hidden, self.policy).reasons)

    def test_rename_binary_and_mode_changes_are_rejected(self):
        for metadata in ("rename from src/app.py", "GIT binary patch", "new mode 100755"):
            with self.subTest(metadata=metadata):
                result = validate_patch(GOOD_DIFF.replace("--- a/src/app.py", metadata + "\n--- a/src/app.py"), self.policy)
                self.assertIn("format", result.reasons)

    def test_malformed_hunk_and_second_file_are_rejected(self):
        broken = GOOD_DIFF.replace("@@ -1,2 +1,2 @@", "@@ -1,3 +1,2 @@")
        self.assertIn("format", validate_patch(broken, self.policy).reasons)
        doubled = GOOD_DIFF + GOOD_DIFF.replace("src/app.py", "src/other.py")
        self.assertIn("files", validate_patch(doubled, self.policy).reasons)


if __name__ == "__main__":
    unittest.main()

"""Strict preflight for model-proposed unified diffs.

This is a policy gate, not a patch parser or proof that a patch applies. The
isolated remediation worker must still run git apply --check and tests on a
clean artifact-derived worktree.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath


@dataclass(frozen=True)
class PatchPolicy:
    allowed_roots: tuple[str, ...]
    max_files: int = 3
    max_changed_lines: int = 500
    max_diff_bytes: int = 256 * 1024


@dataclass(frozen=True)
class PatchValidation:
    allowed: bool
    reasons: tuple[str, ...]
    files: tuple[str, ...]
    changed_lines: int


_HEADER = re.compile(r"^diff --git a/([^\s]+) b/([^\s]+)$")
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$")
_INDEX = re.compile(r"^index [0-9a-f]{7,64}\.\.[0-9a-f]{7,64}(?: 100644)?$")
_FORBIDDEN_META = ("old mode ", "new mode ", "new file mode ", "deleted file mode ",
                   "rename from ", "rename to ", "copy from ", "copy to ",
                   "similarity index ", "dissimilarity index ", "GIT binary patch", "Binary files ")


def _safe_path(path: str, roots: tuple[str, ...]) -> bool:
    parts = path.split("/")
    reserved = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
                *(f"lpt{i}" for i in range(1, 10))}
    if (not path or path.startswith("/") or "\\" in path or ":" in path
            or PureWindowsPath(path).drive or any(
                part in {"", ".", ".."} or part.startswith(".")
                or part.rstrip(" .") != part or part.split(".", 1)[0].casefold() in reserved
                for part in parts)):
        return False
    normalized = PurePosixPath(path).as_posix()
    return normalized == path and any(path.startswith(root.rstrip("/") + "/") for root in roots)


def validate_patch(diff: str, policy: PatchPolicy) -> PatchValidation:
    """Reject ambiguous or over-budget Git-style modifications fail-closed."""
    reasons: set[str] = set()
    files: list[str] = []
    changed = 0
    if (not policy.allowed_roots or policy.max_files < 1 or policy.max_changed_lines < 1
            or any(not root or root.startswith("/") or "\\" in root or ".." in root.split("/")
                   for root in policy.allowed_roots)):
        return PatchValidation(False, ("policy",), (), 0)
    if len(diff.encode("utf-8")) > policy.max_diff_bytes or "\x00" in diff or "\r" in diff:
        return PatchValidation(False, ("format",), (), 0)
    lines = diff.splitlines()
    if not lines:
        return PatchValidation(False, ("format",), (), 0)
    current: str | None = None
    saw_old = saw_new = saw_hunk = False
    old_left = new_left = 0
    for line in lines:
        header = _HEADER.fullmatch(line)
        if header:
            if current is not None and (not saw_old or not saw_new or not saw_hunk or old_left or new_left):
                reasons.add("format")
            old_path, new_path = header.groups()
            if old_path != new_path:
                reasons.add("path")
            current = new_path
            if not _safe_path(current, policy.allowed_roots):
                reasons.add("path")
            if current in files:
                reasons.add("format")
            files.append(current)
            saw_old = saw_new = saw_hunk = False
            old_left = new_left = 0
            continue
        if current is None:
            reasons.add("format")
            continue
        if line.startswith(_FORBIDDEN_META):
            reasons.add("format")
            continue
        if line.startswith("index "):
            if saw_old or saw_new or saw_hunk or not _INDEX.fullmatch(line):
                reasons.add("format")
            continue
        if line.startswith("--- "):
            if saw_old or saw_new or saw_hunk or line != f"--- a/{current}":
                reasons.add("format")
            saw_old = True
            continue
        if line.startswith("+++ "):
            if not saw_old or saw_new or saw_hunk or line != f"+++ b/{current}":
                reasons.add("format")
            saw_new = True
            continue
        hunk = _HUNK.fullmatch(line)
        if hunk:
            if not saw_old or not saw_new or (saw_hunk and (old_left or new_left)):
                reasons.add("format")
            old_left = int(hunk.group(2) or 1)
            new_left = int(hunk.group(4) or 1)
            saw_hunk = True
            continue
        if line == "\\ No newline at end of file" and saw_hunk:
            continue
        if not saw_hunk or (old_left == 0 and new_left == 0):
            reasons.add("format")
            continue
        if line.startswith(" "):
            old_left -= 1
            new_left -= 1
        elif line.startswith("-"):
            old_left -= 1
            changed += 1
        elif line.startswith("+"):
            new_left -= 1
            changed += 1
        else:
            reasons.add("format")
        if old_left < 0 or new_left < 0:
            reasons.add("format")
    if current is None or not saw_old or not saw_new or not saw_hunk or old_left or new_left:
        reasons.add("format")
    if len(files) > policy.max_files:
        reasons.add("files")
    if changed > policy.max_changed_lines:
        reasons.add("changed_lines")
    return PatchValidation(not reasons, tuple(sorted(reasons)), tuple(files), changed)

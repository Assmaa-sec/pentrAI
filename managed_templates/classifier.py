"""Conservative Flask template match; never executes submitted source."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from static_worker.intake import SourceInventory


@dataclass(frozen=True)
class TemplateMatch:
    template_id: str
    entrypoint: str
    python_minor: str
    source_manifest_sha256: str


_REQUIRED = frozenset({"app.py", "wsgi.py", "requirements.txt"})
_REJECTED_NAMES = frozenset({"dockerfile", "docker-compose.yml", "docker-compose.yaml",
                             "compose.yml", "compose.yaml", "setup.py", "pyproject.toml"})
_FLASK_PIN = "Flask==3.1.3"


def _source_file(root: Path, relative: str, expected_size: int) -> str | None:
    path = root / relative
    if (path.is_symlink() or not path.is_file() or not path.resolve(strict=True).is_relative_to(root)
            or path.stat().st_size != expected_size):
        return None
    try:
        return path.read_text(encoding="utf-8", errors="strict")
    except (UnicodeError, OSError):
        return None


def classify_managed_flask(source_root: Path, inventory: SourceInventory) -> TemplateMatch | None:
    """Match one reviewed source shape; every other source stays static-only."""
    root = source_root.resolve(strict=True)
    entries = {entry.path: entry for entry in inventory.files}
    if not _REQUIRED <= entries.keys():
        return None
    if any(Path(name).name.casefold() in _REJECTED_NAMES or name.lower().endswith((".so", ".pyd", ".whl"))
           for name in entries):
        return None
    requirements = _source_file(root, "requirements.txt", entries["requirements.txt"].size)
    wsgi = _source_file(root, "wsgi.py", entries["wsgi.py"].size)
    app = _source_file(root, "app.py", entries["app.py"].size)
    if requirements is None or wsgi is None or app is None:
        return None
    if [line.strip() for line in requirements.splitlines() if line.strip() and not line.lstrip().startswith("#")] != [_FLASK_PIN]:
        return None
    try:
        wsgi_tree = ast.parse(wsgi, filename="wsgi.py")
        app_tree = ast.parse(app, filename="app.py")
    except (SyntaxError, ValueError):
        return None
    if len(wsgi_tree.body) != 1 or not isinstance(wsgi_tree.body[0], ast.ImportFrom):
        return None
    imported = wsgi_tree.body[0]
    if imported.module != "app" or imported.level != 0 or len(imported.names) != 1 or imported.names[0].name != "app" or imported.names[0].asname:
        return None
    has_flask_import = any(
        isinstance(node, ast.ImportFrom) and node.module == "flask"
        and any(alias.name == "Flask" and alias.asname is None for alias in node.names)
        for node in app_tree.body
    )
    has_app = any(
        isinstance(node, ast.Assign) and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "app"
        and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "Flask" and len(node.value.args) == 1
        and isinstance(node.value.args[0], ast.Name) and node.value.args[0].id == "__name__"
        for node in app_tree.body
    )
    if not has_flask_import or not has_app:
        return None
    return TemplateMatch("flask-3.1.3-v1", "wsgi:app", "3.12", inventory.manifest_sha256)

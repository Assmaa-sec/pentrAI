"""Small deterministic Python source checks that emit unvalidated hypotheses."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

from .intake import SourceInventory
from .sca import DetectedFinding


def analyze_python_source(source_root: Path, inventory: SourceInventory, max_findings: int = 100) -> list[DetectedFinding]:
    findings: list[DetectedFinding] = []
    seen: set[tuple[str, int, str]] = set()
    rules = {
        "eval": ("CWE-95", "dynamic evaluation"),
        "exec": ("CWE-95", "dynamic execution"),
        "pickle.loads": ("CWE-502", "unsafe deserialization"),
        "pickle.load": ("CWE-502", "unsafe deserialization"),
        "os.system": ("CWE-78", "shell execution"),
    }
    for entry in inventory.files:
        if not entry.path.endswith(".py") or entry.size > 1024 * 1024:
            continue
        path = source_root / entry.path
        if not path.is_file() or path.is_symlink() or path.stat().st_size != entry.size:
            continue
        source = path.read_bytes()
        digest = hashlib.sha256(source).hexdigest()
        try:
            tree = ast.parse(source.decode("utf-8", errors="replace"), filename=entry.path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = ""
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                name = f"{node.func.value.id}.{node.func.attr}"
            rule = rules.get(name)
            if name in {"subprocess.run", "subprocess.call", "subprocess.Popen"}:
                if any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant)
                       and keyword.value.value is True for keyword in node.keywords):
                    rule = ("CWE-78", "subprocess shell mode")
            if rule is None:
                continue
            cwe, label = rule
            identity = (entry.path, node.lineno, label)
            if identity in seen:
                continue
            seen.add(identity)
            findings.append(DetectedFinding(
                state="detected", source="sast", dependency=f"{entry.path}:{node.lineno} ({label})",
                advisory_id=cwe, source_manifest=entry.path,
                scanner_version="pentrai-ast-1", database_version="rules-v1",
                scanner_output_sha256=digest,
            ))
            if len(findings) >= max_findings:
                return findings
    return findings

"""Build an ignored Windows local runtime from the verified CPython embed ZIP.

Run with the populated pentrai-env interpreter. The resulting runtime is
application-owned and does not depend on the machine's Python installation.
"""

from __future__ import annotations

import hashlib
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath


VERSION = "3.14.3"
URL = f"https://www.python.org/ftp/python/{VERSION}/python-{VERSION}-embed-amd64.zip"
SHA256 = "ad4961a479dedbeb7c7d113253f8db1b1935586b73c27488712beec4f2c894e6"


def main() -> None:
    if sys.platform != "win32" or sys.version_info[:2] != (3, 14) or sys.maxsize < 2**32:
        raise SystemExit("run with the 64-bit Python 3.14 pentrai-env interpreter")
    root = Path(__file__).resolve().parents[1]
    cache = root / ".tmp"
    cache.mkdir(exist_ok=True)
    archive = cache / f"python-{VERSION}-embed-amd64.zip"
    runtime = cache / "python-runtime"
    if runtime.exists():
        raise SystemExit(f"runtime already exists: {runtime}")
    if not archive.exists():
        urllib.request.urlretrieve(URL, archive)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != SHA256:
        raise SystemExit("official CPython archive digest mismatch")
    source_packages = Path(sys.prefix) / "Lib" / "site-packages"
    if not source_packages.is_dir() or not (source_packages / "fastapi").is_dir():
        raise SystemExit("install the PentrAI project in pentrai-env first")
    runtime = runtime.resolve()
    if not runtime.is_relative_to(root.resolve()):
        raise SystemExit("runtime path escapes repository")
    runtime.mkdir(exist_ok=False)
    with zipfile.ZipFile(archive) as package:
        for member in package.infolist():
            path = PurePosixPath(member.filename)
            if path.is_absolute() or ".." in path.parts or len(path.parts) != 1:
                raise SystemExit("unexpected embedded Python archive entry")
        package.extractall(runtime)
    target_packages = runtime / "Lib" / "site-packages"
    shutil.copytree(source_packages, target_packages, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (runtime / "python314._pth").write_text(
        "python314.zip\n.\nLib\\site-packages\n..\\..\n", encoding="utf-8"
    )
    if not (runtime / "python.exe").is_file():
        raise SystemExit("embedded Python executable missing")
    print(f"Portable runtime ready: {runtime}")


if __name__ == "__main__":
    main()

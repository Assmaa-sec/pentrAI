"""Install the pinned Nikto Perl program and its data files."""

import hashlib
import io
import os
import tarfile
import urllib.request
from pathlib import Path


URL = "https://github.com/sullo/nikto/archive/refs/tags/2.6.1.tar.gz"
SHA256 = "d1ca1acb05d81a5a6f374c0afdd76b33afa0089278631a20673c0210a71d992f"
PREFIX = "nikto-2.6.1/program/"
DESTINATION = Path("/opt/nikto/program")


def main() -> None:
    request = urllib.request.Request(URL, headers={"User-Agent": "PentrAI-runner-build"})
    with urllib.request.urlopen(request, timeout=120) as response:
        archive = response.read()
    if hashlib.sha256(archive).hexdigest() != SHA256:
        raise ValueError("Nikto release digest mismatch")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as package:
        for member in package:
            if not member.name.startswith(PREFIX) or not member.isfile():
                continue
            relative = Path(member.name[len(PREFIX):])
            if not relative.parts or ".." in relative.parts:
                raise ValueError(f"Unsafe Nikto archive path: {member.name}")
            output = DESTINATION / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            source = package.extractfile(member)
            if source is None:
                raise ValueError(f"Missing Nikto archive member: {member.name}")
            output.write_bytes(source.read())
    launcher = Path("/usr/local/bin/nikto")
    launcher.write_text('#!/bin/sh\ncd /opt/nikto/program\nexec perl ./nikto.pl "$@"\n')
    os.chmod(launcher, 0o755)


if __name__ == "__main__":
    main()

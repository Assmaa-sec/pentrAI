"""Install the checksum-pinned RustScan Linux release."""

import hashlib
import io
import os
from pathlib import Path
import tarfile
import urllib.request
import zipfile


URL = "https://github.com/bee-san/RustScan/releases/download/2.4.1/x86_64-linux-rustscan.tar.gz.zip"
SHA256 = "f3a4365d939e3b81f25ba8c37852ce9ac9e938c3cc882c5b3e6fff6152c740be"


def main() -> None:
    request = urllib.request.Request(URL, headers={"User-Agent": "PentrAI-runner-build"})
    with urllib.request.urlopen(request, timeout=120) as response:
        archive = response.read()
    if hashlib.sha256(archive).hexdigest() != SHA256:
        raise ValueError("RustScan release digest mismatch")
    with zipfile.ZipFile(io.BytesIO(archive)) as outer:
        inner_archive = outer.read("x86_64-linux-rustscan.tar.gz")
    with tarfile.open(fileobj=io.BytesIO(inner_archive), mode="r:gz") as inner:
        source = inner.extractfile("rustscan")
        if source is None:
            raise ValueError("RustScan executable missing from release")
        target = Path("/usr/local/bin/rustscan")
        target.write_bytes(source.read())
    os.chmod(target, 0o755)


if __name__ == "__main__":
    main()

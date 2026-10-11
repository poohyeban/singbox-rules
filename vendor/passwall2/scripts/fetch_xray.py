"""Download only the official test binary, using pinned release SHA-256 values."""
import hashlib
import io
import platform
from pathlib import Path
import urllib.request
import zipfile

VERSION = "26.9.9"
ASSETS = {
    ("Darwin", "arm64"): ("macos-arm64-v8a", "b7cf765d60ccc703853d4218c49a1eacc5bca764543b9540bdeaf45c951afc7d"),
    ("Linux", "x86_64"): ("linux-64", "1eb9175d0f0a8f8149c9230a7fc5ae66ce332ed20a53155ce61fe62e3f58b7df"),
}


def fetch():
    asset, checksum = ASSETS[(platform.system(), platform.machine())]
    url = f"https://github.com/XTLS/Xray-core/releases/download/v{VERSION}/Xray-{asset}.zip"
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != checksum:
        raise ValueError("Official Xray asset checksum mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        binary = archive.read("xray")
    target = Path("build/tools/xray")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(binary)
    target.chmod(0o755)
    print("Verified official Xray", VERSION)


if __name__ == "__main__":
    fetch()

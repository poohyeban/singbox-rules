"""Fetch official Linux/amd64 releases; verify pinned or GitHub asset digests."""
from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
import re
import tarfile
import urllib.request

from .common import ROOT, sha, version
from vendor.passwall2.scripts.fetch_xray import fetch as fetch_xray

PINNED = {
    "1.13.0": "86db0f9df3f822ca2adccde2f7c1c9e21d64e646a77bf258274fde3be399025b",
    "1.14.3": "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee",
}


def fetch(v, checksum, root=ROOT):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", v) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise ValueError("Invalid release identity or digest")
    name = f"sing-box-{v}-linux-amd64"
    url = f"https://github.com/SagerNet/sing-box/releases/download/v{v}/{name}.tar.gz"
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read(200 * 1024 * 1024 + 1)
    if sha(data) != checksum:
        raise ValueError("Official sing-box asset checksum mismatch")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        member = archive.getmember(name + "/sing-box")
        if not member.isfile():
            raise ValueError("Release binary is not a regular file")
        binary = archive.extractfile(member).read()
    target = root / "build/tools" / name / "sing-box"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(binary)
    target.chmod(0o755)
    if version(target) != v:
        raise ValueError("Release version mismatch")
    print("Verified official sing-box", v)
    return target


def latest(root=ROOT):
    with urllib.request.urlopen("https://github.com/SagerNet/sing-box/releases/latest", timeout=90) as response:
        v = response.url.rsplit("/v", 1)[-1]
    if v in PINNED:
        target = root / f"build/tools/sing-box-{v}-linux-amd64/sing-box"
    else:
        # Future versions require GitHub's release-asset digest. No fallback to
        # an unchecked archive, prerelease or third-party mirror is allowed.
        with urllib.request.urlopen(f"https://api.github.com/repos/SagerNet/sing-box/releases/tags/v{v}", timeout=90) as response:
            release = json.load(response)
        if release["prerelease"] or release["draft"]:
            raise ValueError("Latest stable resolved to a prerelease or draft")
        asset = next(a for a in release["assets"] if a["name"] == f"sing-box-{v}-linux-amd64.tar.gz")
        digest = asset.get("digest", "")
        if not digest.startswith("sha256:"):
            raise ValueError("Latest release has no authenticated asset digest; review required")
        target = fetch(v, digest.removeprefix("sha256:"), root)
    alias = root / "build/tools/latest/sing-box"
    alias.parent.mkdir(parents=True, exist_ok=True)
    alias.write_bytes(target.read_bytes())
    alias.chmod(0o755)
    print("Latest stable compatibility target:", version(alias))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--latest", action="store_true")
    args = parser.parse_args()
    for v, digest in PINNED.items():
        fetch(v, digest)
    fetch_xray()
    if args.latest:
        latest()

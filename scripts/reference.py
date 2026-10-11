"""Audit the unmodified reference snapshot and report drift before publishing."""
from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
import subprocess
import urllib.request
import zipfile

from .common import ROOT, save_json, sha


def check_local(root=ROOT):
    lock = json.loads((root / "reference.lock.json").read_text())
    vendor = root / "vendor/passwall2"
    actual = {str(p.relative_to(vendor)): sha(p.read_bytes()) for p in vendor.rglob("*")
              if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"}
    if actual != lock["files"]:
        raise ValueError("Reference snapshot changed; review and update reference.lock.json")
    return lock


def check_remote(root=ROOT):
    lock = check_local(root)
    result = subprocess.run(["git", "ls-remote", lock["repository"] + ".git", "HEAD"],
                            text=True, capture_output=True, check=True, timeout=90)
    head = result.stdout.split()[0]
    # Check the complete selected inventory, including added/deleted scripts or
    # review inputs. Generated-data-only commits may update independently.
    with urllib.request.urlopen(f"https://codeload.github.com/poohyeban/passwall2-rules/zip/{head}", timeout=90) as response:
        data = response.read(100 * 1024 * 1024 + 1)
    if len(data) > 100 * 1024 * 1024:
        raise ValueError("Oversized reference snapshot")
    observed = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for info in archive.infolist():
            parts = info.filename.split("/", 1)
            if len(parts) != 2 or info.is_dir():
                continue
            path = parts[1]
            if path.startswith(("scripts/", "tests/", "data/", "licenses/")) or path in {
                "LICENSE", "NOTICE.md", "README.md", "README.zh-CN.md", "requirements.txt"
            }:
                if info.file_size > 5 * 1024 * 1024:
                    raise ValueError("Oversized reference file: " + path)
                observed[path] = sha(archive.read(info))
    changed = sorted(p for p in set(observed) | set(lock["files"]) if observed.get(p) != lock["files"].get(p))
    report = {"pinned_commit": lock["commit"], "observed_commit": head, "changed_files": changed,
              "status": "review-required" if changed else "equivalent-generator"}
    save_json(root / "build/reference-drift.json", report)
    if changed:
        raise ValueError("Reference logic or reviewed inputs changed: " + ", ".join(changed))
    print("Reference generator and reviewed inputs match the reviewed snapshot")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--remote", action="store_true")
    args = parser.parse_args()
    check_remote() if args.remote else check_local()

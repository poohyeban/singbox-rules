"""Check publishable files without recording machine-specific identifiers.

PRIVATE_IDENTIFIERS can be a JSON array supplied by a local auditor. Its values
are never printed or written. CI uses the generic checks and bot identity gate.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
ALLOWED = {".github", ".gitignore", "README.md", "README.zh-CN.md", "LICENSE", "NOTICE.md", "licenses",
           "requirements.txt", "scripts", "tests", "data", "rules", "dist"}


def scan(root: Path, history=False):
    tracked = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root)
    names = sorted(set(n.decode() for n in tracked.split(b"\0") if n))
    private = [v.casefold().encode() for v in json.loads(os.environ.get("PRIVATE_IDENTIFIERS", "[]")) if len(v) >= 5]
    patterns = [
        rb"/(?:Users|home)/[A-Za-z0-9_.-]+/",
        rb"-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----",
        rb"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
        rb"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
        rb"\b192\.168\.\d{1,3}\.\d{1,3}\b",
    ]
    failures = []
    for name in names:
        path = root / name
        if Path(name).parts[0] not in ALLOWED or path.is_symlink():
            failures.append((name, "unexpected path or symlink"))
            continue
        data = path.read_bytes()
        if any(p in data.lower() for p in private):
            failures.append((name, "private identifier"))
        if any(re.search(p, data) for p in patterns):
            failures.append((name, "private path, credential, or LAN address"))
        if name.startswith(".github/"):
            for address in re.findall(rb"[A-Za-z0-9_.+\[\]-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", data):
                if address.decode() != BOT_EMAIL:
                    failures.append((name, "non-bot workflow email"))
    if history:
        rows = subprocess.check_output(["git", "log", "--all", "--format=%an%x00%ae%x00%cn%x00%ce"], cwd=root).decode().splitlines()
        for row in rows:
            if row.split("\0") != [BOT_NAME, BOT_EMAIL, BOT_NAME, BOT_EMAIL]:
                failures.append(("commit metadata", "non-bot author or committer"))
    if failures:
        for name, reason in failures:
            print(f"Privacy check failed: {name}: {reason}")
        raise SystemExit(1)
    print(f"Privacy check passed: {len(names)} publishable files" + ("; bot-only history" if history else ""))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--history", action="store_true")
    args = parser.parse_args()
    scan(Path(__file__).resolve().parents[1], args.history)

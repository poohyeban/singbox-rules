"""Small shared utilities; no router configuration or credentials are inputs."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
LABELS = ("China", "Google", "OpenAI", "AdGuard", "WhatsApp", "Instagram", "Facebook")
FIELDS = {"full": "domain", "domain": "domain_suffix", "keyword": "domain_keyword", "regexp": "domain_regex"}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def save_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True, sort_keys=True) + "\n", encoding="utf-8")


def run(args, **kwargs):
    result = subprocess.run(list(map(str, args)), text=True, capture_output=True, timeout=120, **kwargs)
    if result.returncode:
        raise RuntimeError(f"Command failed: {args[0]} {args[1:]}\n{result.stdout[:2000]}{result.stderr[:2000]}")
    return result


def version(binary: Path) -> str:
    line = run([binary, "version"]).stdout.splitlines()[0]
    if not line.startswith("sing-box version "):
        raise ValueError("Unexpected sing-box binary identity")
    return line.removeprefix("sing-box version ").strip()


def binaries(root=ROOT):
    paths = [root / f"build/tools/sing-box-{v}-linux-amd64/sing-box" for v in ("1.13.0", "1.14.3")]
    latest = root / "build/tools/latest/sing-box"
    if latest.exists() and version(latest) not in {version(p) for p in paths}:
        paths.append(latest)
    return paths


def inventory(root: Path, directories=("rules", "rule-set", "reports")):
    return {str(p.relative_to(root)): sha(p.read_bytes()) for d in directories
            for p in sorted((root / d).rglob("*")) if p.is_file()}

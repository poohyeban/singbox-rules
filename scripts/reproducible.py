"""Rebuild from identical raw inputs and compare the complete output inventory."""
from .build import build
from .common import ROOT, inventory, save_json


if __name__ == "__main__":
    first = inventory(ROOT)
    if not first:
        raise ValueError("Build validated artifacts before testing reproducibility")
    build(offline=True)
    second = inventory(ROOT)
    if first != second:
        differing = sorted(k for k in set(first) | set(second) if first.get(k) != second.get(k))
        save_json(ROOT / "build/failure.json", {"status": "blocked", "stage": "deterministic-rebuild",
                  "reason": "Offline build differs", "changed_files": differing,
                  "remote_publication_attempted": False})
        raise AssertionError("Offline build differs: " + ", ".join(differing))
    print(f"Deterministic offline rebuild: {len(first)} identical files")

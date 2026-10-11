"""Build in isolation and publish only a completely verified candidate."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import traceback

from vendor.passwall2.scripts.build import build as build_reference
from .common import ROOT, LABELS, FIELDS, binaries, inventory, run, save_json, sha, version
from .convert import assert_equivalent, counts, parse_domains, parse_ips, project
from .reference import check_local
from .verify import verify


def build(root=ROOT, offline=False):
    lock = check_local(root)
    reference = root / "build/reference"
    shutil.copytree(root / "vendor/passwall2/data", reference / "data", dirs_exist_ok=True)
    previous = root / "reports/reference-manifest.json"
    baseline = previous if previous.exists() else root / "data/reference-baseline.json"
    if baseline.exists():
        (reference / "dist").mkdir(parents=True, exist_ok=True)
        shutil.copy2(baseline, reference / "dist/manifest.json")
    build_reference(reference, offline)
    candidate = root / "build/candidate"
    if candidate.exists():
        shutil.rmtree(candidate)
    candidate.mkdir(parents=True)
    shutil.copytree(reference / "rules", candidate / "rules")
    upstream = json.loads((reference / "dist/manifest.json").read_text())
    summary = {"status": "lossless", "reference_commit": lock["commit"],
               "mapping": FIELDS, "categories": {}, "unconverted_rules": [],
               "additional_conversion_omissions": 0,
               "inherited_adguard_diagnostics": len(json.loads((reference / "rules/AdGuard/Sources/omissions.json").read_text())),
               "scope": "Exact projection of the reference's resolved hostname/IP sets; not the entire upstream AdGuard language",
               "failure_policy": "Unknown syntax, altered inventory, engine errors, unexpected shrink or reference drift stop publication"}
    compiler = root / "build/tools/sing-box-1.14.3-linux-amd64/sing-box"
    if version(compiler) != "1.14.3":
        raise ValueError("Unexpected compiler version")
    for label in LABELS:
        tag = "pooban-" + label.lower()
        ds = parse_domains((candidate / f"rules/{label}/domains.txt").read_text(), f"rules/{label}/domains.txt")
        ipfile = candidate / f"rules/{label}/ip.txt"
        ips = parse_ips(ipfile.read_text(), f"rules/{label}/ip.txt") if ipfile.exists() else set()
        if counts(ds, ips) != upstream["counts"][tag]:
            raise ValueError("Reference manifest counts differ from resolved rules: " + label)
        variants = [(tag, ds, ips), (tag + "-domain", ds, ())]
        if ips:
            variants.append((tag + "-ip", (), ips))
        outputs = {}
        for name, domains, networks in variants:
            document = project(domains, networks)
            fields = assert_equivalent(document, domains, networks)
            source = candidate / f"rule-set/{name}.json"
            save_json(source, document)
            run([compiler, "rule-set", "compile", "--output", source.with_suffix(".srs"), source])
            outputs[name] = fields
            for extension in ("json", "srs"):
                artifact = source.with_suffix("." + extension)
                artifact.with_name(artifact.name + ".sha256sum").write_text(f"{sha(artifact.read_bytes())}  {artifact.name}\n")
        summary["categories"][tag] = {"counts": counts(ds, ips), "outputs": outputs,
                                       "regexps_copied_verbatim": sorted(r.value for r in ds if r.kind == "regexp")}
    save_json(candidate / "reports/conversion.json", summary)
    save_json(candidate / "reports/reference-manifest.json", upstream)
    validation = verify(candidate, reference, binaries(root), root / "build/tools/xray")
    save_json(candidate / "reports/validation.json", validation)
    save_json(candidate / "reports/manifest.json", {
        "format": 1, "target": "sing-box rule-set", "rule_set_version": 2,
        "compiler_version": "1.14.3", "tested_versions": [item["version"] for item in validation["engines"]],
        "reference_commit": lock["commit"], "counts": upstream["counts"],
        "sources": upstream["sources"], "reviewed_inputs": upstream["reviewed_inputs"],
        "artifacts": inventory(candidate), "conversion_omissions": 0,
        "inherited_adguard_diagnostics": summary["inherited_adguard_diagnostics"],
    })
    # Tracked outputs are touched only after every gate has passed. The workflow
    # commits these directories together, so a failed candidate is never served.
    for directory in ("rules", "rule-set", "reports"):
        destination = root / directory
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(candidate / directory, destination)
    print("Published a fully validated local candidate", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline", action="store_true", help="Use only the preceding successful raw-source cache")
    args = parser.parse_args()
    try:
        build(offline=args.offline)
    except Exception as error:
        save_json(ROOT / "build/failure.json", {"status": "blocked", "error_type": type(error).__name__,
                  "reason": str(error), "remote_publication_attempted": False,
                  "traceback": traceback.format_exc(), "unconverted_rules": "Inspect reason and source path; no partial candidate is published"})
        raise


if __name__ == "__main__":
    main()

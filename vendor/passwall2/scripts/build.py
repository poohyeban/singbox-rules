"""Fetch approved public sources, validate them, and produce native Xray assets."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import time
import urllib.request

import maxminddb

from . import adguard
from .google import google_domains
from .model import Domain, InvalidSource, geoip, geosite, networks, official_domains, v2fly
from .meta_common import SERVICES, compact, select_sukka

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "china-domain": "https://raw.githubusercontent.com/v2fly/domain-list-community/release/cn.txt",
    "google-domain": "https://codeload.github.com/v2fly/domain-list-community/zip/refs/heads/master",
    "openai-domain": "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/openai",
    "country": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb",
    "asn": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb",
    "voice": "https://openai.com/chatgpt-voice.json",
    "adguard": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    "sukka-meta": "https://raw.githubusercontent.com/SukkaW/Surge/master/Source/non_ip/global.conf",
}
ASNS = {401518, 401864}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def download(url: str) -> bytes:
    if not url.startswith("https://"):
        raise InvalidSource("Sources must use HTTPS")
    for attempt in range(4):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "passwall2-rules-builder"})
            with urllib.request.urlopen(request, timeout=90) as response:
                if not response.url.startswith("https://"):
                    raise InvalidSource("Refusing an insecure redirect")
                data = response.read(100 * 1024 * 1024 + 1)
            if not data or len(data) > 100 * 1024 * 1024:
                raise InvalidSource("Empty or oversized upstream source")
            return data
        except (OSError, ValueError):
            if attempt == 3:
                raise
            time.sleep(2 ** attempt)
    raise AssertionError("unreachable")


def voice_prefixes(data: bytes) -> list:
    doc = json.loads(data)
    if not isinstance(doc, dict) or not isinstance(doc.get("creationTime"), str):
        raise InvalidSource("Voice source has no creationTime")
    when = datetime.fromisoformat(doc["creationTime"].replace("Z", "+00:00"))
    if when.tzinfo is None or when > datetime.now(timezone.utc):
        raise InvalidSource("Invalid Voice source timestamp")
    rows = doc.get("prefixes")
    if not isinstance(rows, list) or not rows:
        raise InvalidSource("Empty Voice prefixes")
    values = []
    for row in rows:
        if not isinstance(row, dict) or len(row) != 1:
            raise InvalidSource("Unexpected Voice prefix schema")
        key = next(iter(row))
        if key not in {"ipv4Prefix", "ipv6Prefix"} or not isinstance(row[key], str):
            raise InvalidSource("Unexpected Voice prefix field")
        net = ipaddress.ip_network(row[key], strict=True)
        if net.version != (4 if key == "ipv4Prefix" else 6):
            raise InvalidSource("Voice prefix address-family mismatch")
        if not net.is_global:
            raise InvalidSource("Non-public Voice prefix")
        values.append(net)
    return networks(values)


def read_mmdb(path: Path, kind: str, coverage=None):
    result = []
    found = {asn: 0 for asn in sorted(ASNS)}
    with maxminddb.open_database(str(path)) as reader:
        expected = "GeoLite2-Country" if kind == "country" else "GeoLite2-ASN"
        if reader.metadata().database_type != expected:
            raise InvalidSource("Unexpected MaxMind database type")
        for net, record in reader:
            if not isinstance(record, dict):
                continue
            if kind == "country":
                include = (record.get("country") or {}).get("iso_code") == "CN"
            else:
                asn = record.get("autonomous_system_number")
                include = asn in ASNS
                if include:
                    found[asn] += 1
            if include:
                result.append(net)
    if kind == "asn" and coverage is not None:
        coverage.update({str(asn): count for asn, count in found.items()})
    if not result:
        raise InvalidSource("Empty MMDB selection")
    return networks(result)


def save_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True, sort_keys=True) + "\n", encoding="utf-8")


def write_lines(path: Path, values):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(v + "\n" for v in sorted(set(values))), encoding="utf-8")


def build(root: Path, offline: bool = False):
    cache = root / "build/sources"
    cache.mkdir(parents=True, exist_ok=True)
    if offline:
        raw = {name: (cache / name).read_bytes() for name in SOURCES}
    else:
        with ThreadPoolExecutor(max_workers=4) as pool:
            raw = dict(zip(SOURCES, pool.map(download, SOURCES.values())))
        for name, data in raw.items():
            (cache / name).write_bytes(data)
    china = v2fly(raw["china-domain"].decode("utf-8-sig"))
    google, google_categories = google_domains(raw["google-domain"])
    meta_primary, meta_categories = {}, {}
    for service in SERVICES:
        rules, meta_categories[service] = google_domains(raw["google-domain"], service.lower())
        meta_primary[service] = {(rule.kind, rule.value) for rule in rules}
    meta_review = (root / "data/Meta/sukka-review.json").read_bytes()
    meta_supplement, meta_selection = select_sukka(
        raw["sukka-meta"].decode("utf-8-sig"), meta_primary, json.loads(meta_review))
    meta_domains = {service: {Domain(*r) for r in compact(meta_primary[service] | meta_supplement[service])}
                    for service in SERVICES}
    openai_v2 = v2fly(raw["openai-domain"].decode("utf-8-sig"))
    source = (root / "data/OpenAI/official-domains.txt").read_text(encoding="utf-8")
    exclusions = (root / "data/OpenAI/official-domains-excluded.txt").read_text(encoding="utf-8")
    official = official_domains(source, exclusions)
    ads, adstats, omissions = adguard.convert(raw["adguard"].decode("utf-8-sig"))
    cn_ip = read_mmdb(cache / "country", "country")
    asn_coverage = {}
    ai_asn = read_mmdb(cache / "asn", "asn", asn_coverage)
    ai_voice = voice_prefixes(raw["voice"])
    domains = {"pooban-china": china, "pooban-google": google,
               "pooban-openai": openai_v2 | official, "pooban-adguard": ads}
    domains.update({"pooban-" + s.lower(): rules for s, rules in meta_domains.items()})
    ips = {"pooban-china": cn_ip, "pooban-openai": networks(ai_asn + ai_voice)}
    counts = {tag: {"domains": len(rules), "regexps": sum(r.kind == "regexp" for r in rules),
                    "ipv4": sum(n.version == 4 for n in ips.get(tag, [])),
                    "ipv6": sum(n.version == 6 for n in ips.get(tag, []))}
              for tag, rules in domains.items()}
    for tag, minimum in {"pooban-china": 100, "pooban-google": 500,
                         "pooban-openai": 5, "pooban-adguard": 1000,
                         "pooban-whatsapp": 5, "pooban-instagram": 5, "pooban-facebook": 10}.items():
        if counts[tag]["domains"] < minimum:
            raise InvalidSource("Domain source unexpectedly small: " + tag)
    previous = root / "dist/manifest.json"
    if previous.exists():
        old = json.loads(previous.read_text())["counts"]
        for tag in counts:
            if tag not in old:
                continue
            for metric in ("domains", "ipv4", "ipv6"):
                before, after = old[tag][metric], counts[tag][metric]
                if before and after < before * 0.65:
                    raise InvalidSource(f"Unexpected >35% shrink: {tag}/{metric}; manual source review required")
    source_domains = {
        "China/Sources/v2fly-domains.txt": china,
        "Google/Sources/v2fly-domains.txt": google,
        "OpenAI/Sources/v2fly-domains.txt": openai_v2,
        "OpenAI/Sources/official-domains.txt": official,
        "AdGuard/Sources/hostname-blocks.txt": ads,
    }
    source_ips = {
        "China/Sources/geolite-country-ip.txt": cn_ip,
        "OpenAI/Sources/geolite-asn-ip.txt": ai_asn,
        "OpenAI/Sources/voice-ip.txt": ai_voice,
    }
    for service in SERVICES:
        source_domains[f"{service}/Sources/v2fly-domains.txt"] = {Domain(*r) for r in meta_primary[service]}
        source_domains[f"{service}/Sources/sukka-domains.txt"] = {Domain(*r) for r in meta_supplement[service]}
    # Validate everything before changing tracked artifacts. CI publishes only
    # after a separate real-Xray gate; failed builds are never committed.
    site_data, ip_data = geosite(domains), geoip(ips)
    for path, rules in source_domains.items():
        write_lines(root / "rules" / path, (r.text() for r in rules))
    for path, nets in source_ips.items():
        write_lines(root / "rules" / path, map(str, nets))
    for label in ("China", "Google", "OpenAI", "AdGuard", *SERVICES):
        tag = "pooban-" + label.lower()
        write_lines(root / "rules" / label / "domains.txt", (r.text() for r in domains[tag]))
        if tag in ips:
            write_lines(root / "rules" / label / "ip.txt", map(str, ips[tag]))
    # Keep the AdGuard source alongside its modified form and license.
    # No user traffic/configuration is an input to this repository.
    upstream_ads = root / "rules/AdGuard/Sources/upstream-filter.txt"
    upstream_ads.write_bytes(raw["adguard"])
    (root / "dist").mkdir(exist_ok=True)
    for name, data in {"geosite.dat": site_data, "geoip.dat": ip_data}.items():
        (root / "dist" / name).write_bytes(data)
        (root / "dist" / (name + ".sha256sum")).write_text(f"{sha(data)}  {name}\n")
    save_json(root / "dist/manifest.json", {
        "format": 1, "target": "PassWall2 / Xray", "xray_test_version": "26.9.9",
        "counts": counts,
        "sources": {name: {"url": url, "sha256": sha(raw[name])} for name, url in SOURCES.items()},
        "reviewed_inputs": {"official-domains.txt": sha(source.encode()),
                            "official-domains-excluded.txt": sha(exclusions.encode()),
                            "Meta/sukka-review.json": sha(meta_review)},
        "artifacts": {"geosite.dat": sha(site_data), "geoip.dat": sha(ip_data)},
        "adguard": adstats,
        "asn_records": asn_coverage,
        "google_categories": google_categories,
        "meta_categories": meta_categories,
        "meta_sukka_selection": meta_selection,
        "meta_supplement_added": {s: [list(r) for r in sorted(
            {(r.kind, r.value) for r in meta_domains[s]} - compact(meta_primary[s]))] for s in SERVICES},
    })
    save_json(root / "rules/AdGuard/Sources/omissions.json", omissions)
    print(json.dumps(counts, indent=2))
    print("AdGuard:", json.dumps(adstats, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline", action="store_true", help="Rebuild from previously downloaded build/sources")
    args = parser.parse_args()
    build(ROOT, args.offline)

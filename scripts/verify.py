"""Inventory equality and real Xray/sing-box routing on isolated loopback SOCKS."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
from pathlib import Path
import queue
import re
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
from unittest.mock import patch

from vendor.passwall2.scripts import verify as reference_verify
from vendor.passwall2.scripts.model import Domain, geoip, geosite
from .common import ROOT, LABELS, binaries, inventory, run, save_json, sha, version
from .convert import assert_equivalent, parse_domains, parse_ips, project


def recv_exact(client, size):
    data = b""
    while len(data) < size:
        part = client.recv(size - len(data))
        if not part:
            raise RuntimeError("Truncated SOCKS handshake")
        data += part
    return data


def address(client):
    family = recv_exact(client, 1)[0]
    if family == 1:
        return str(ipaddress.ip_address(recv_exact(client, 4)))
    if family == 4:
        return str(ipaddress.ip_address(recv_exact(client, 16)))
    if family == 3:
        return recv_exact(client, recv_exact(client, 1)[0]).decode("ascii")
    raise ValueError("Unknown SOCKS address family")


class Capture(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class CaptureHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        greeting = recv_exact(self.request, 2)
        recv_exact(self.request, greeting[1])
        self.request.sendall(b"\x05\x00")
        header = recv_exact(self.request, 3)
        if header != b"\x05\x01\x00":
            raise ValueError("Unexpected outbound SOCKS command")
        target = address(self.request)
        port = struct.unpack("!H", recv_exact(self.request, 2))[0]
        self.server.observed.put((self.server.tag, target, port))
        self.request.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x01\xbb")


def probe(client_port, target):
    with socket.create_connection(("127.0.0.1", client_port), timeout=5) as client:
        client.sendall(b"\x05\x01\x00")
        if recv_exact(client, 2) != b"\x05\x00":
            raise RuntimeError("Inbound SOCKS handshake failed")
        try:
            ip = ipaddress.ip_address(target)
            encoded = bytes([1 if ip.version == 4 else 4]) + ip.packed
        except ValueError:
            value = target.encode("ascii")
            encoded = b"\x03" + bytes([len(value)]) + value
        client.sendall(b"\x05\x01\x00" + encoded + b"\x01\xbb")
        header = recv_exact(client, 3)
        if header != b"\x05\x00\x00":
            raise RuntimeError(f"Inbound CONNECT failed for {target}: {header!r}")
        address(client)
        recv_exact(client, 2)


def sing_probe(binary, rule_sets, rules, cases, scratch):
    observed = queue.Queue()
    servers = []
    for tag in ("hit", "miss"):
        server = Capture(("127.0.0.1", 0), CaptureHandler)
        server.tag, server.observed = tag, observed
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    cfg = {
        "log": {"level": "error", "timestamp": False},
        "inbounds": [{"type": "socks", "tag": "probe", "listen": "127.0.0.1", "listen_port": port}],
        # Both proxies are local capture servers. They never resolve or dial
        # any target and return the selected tag without Internet traffic.
        "outbounds": [{"type": "socks", "tag": server.tag, "server": "127.0.0.1",
                       "server_port": server.server_address[1]} for server in servers],
        "route": {"rule_set": rule_sets, "rules": rules, "final": "miss"},
    }
    scratch.mkdir(parents=True, exist_ok=True)
    path = scratch / "config.json"
    save_json(path, cfg)
    run([binary, "check", "-c", path])
    with (scratch / "log.txt").open("w+") as logfile:
        process = subprocess.Popen([str(binary), "run", "-c", str(path)], stdout=logfile, stderr=logfile)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    logfile.seek(0)
                    raise RuntimeError("sing-box probe exited: " + logfile.read()[:2000])
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.03)
            else:
                raise RuntimeError("sing-box probe did not listen")
            for target, expected in cases:
                probe(port, target)
                actual, forwarded, forwarded_port = observed.get(timeout=5)
                if actual != expected or forwarded.lower() != target.lower() or forwarded_port != 443:
                    raise AssertionError(f"Native sing-box {version(binary)}: {target} expected {expected}, observed {actual}/{forwarded}")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            # Stop servers together to avoid a half-second wait per server.
            with ThreadPoolExecutor(max_workers=2) as pool:
                list(pool.map(lambda s: s.shutdown(), servers))
            for server in servers:
                server.server_close()


def sampled_cases(domains, ips):
    # Deterministic samples cover first/middle/last domains and suffix label
    # boundaries. Their expected result considers every reference rule.
    canonical = sorted(r for r in domains if r.kind in {"domain", "full"})
    selected = [canonical[i] for i in sorted({0, len(canonical)//2, len(canonical)-1})]
    hosts = {"unlisted-test.invalid", "unrelated-regression.invalid"}
    for r in selected:
        hosts.update((r.value, "child." + r.value, "not" + r.value, r.value + ".evil.invalid"))
    exact = {r.value for r in domains if r.kind == "full"}
    suffix = {r.value for r in domains if r.kind == "domain"}
    keywords = [r.value for r in domains if r.kind == "keyword"]
    regexps = [re.compile(r.value, re.ASCII) for r in domains if r.kind == "regexp"]
    def matches(h):
        labels = h.split(".")
        return (h in exact or any(".".join(labels[i:]) in suffix for i in range(len(labels))) or
                any(k in h for k in keywords) or any(r.search(h) for r in regexps))
    result = [(h, "hit" if matches(h) else "miss") for h in sorted(hosts)]
    for family in (4, 6):
        family_nets = sorted((n for n in ips if n.version == family), key=lambda n: (int(n.network_address), n.prefixlen))
        if not family_nets:
            continue
        probes = set()
        for net in (family_nets[0], family_nets[len(family_nets)//2], family_nets[-1]):
            probes.update((net.network_address, net.broadcast_address))
            for offset in (-1, 1):
                value = int(net.network_address if offset < 0 else net.broadcast_address) + offset
                if 0 <= value < 2**(32 if family == 4 else 128):
                    probes.add((ipaddress.IPv4Address if family == 4 else ipaddress.IPv6Address)(value))
        result += [(str(ip), "hit" if any(ip in n for n in family_nets) else "miss") for ip in sorted(probes)]
    return result


def verify_resolved_inputs(root, reference):
    if inventory(root, ("rules",)) != inventory(reference, ("rules",)):
        raise AssertionError("Resolved rule/source inventory differs from the unmodified reference build")


def assert_official_binary(published, recompiled):
    if published.read_bytes() != recompiled.read_bytes():
        raise AssertionError("Published SRS differs from the official compiler's complete JSON projection: " + published.name)
    if published.read_bytes()[:4] != b"SRS\x02":
        raise AssertionError("Unexpected SRS format version")


def verify(root: Path, reference: Path, engines, xray: Path):
    root, reference = root.resolve(), reference.resolve()
    verify_resolved_inputs(root, reference)
    loaded = {}
    for label in LABELS:
        tag = "pooban-" + label.lower()
        ds = parse_domains((root / f"rules/{label}/domains.txt").read_text())
        ipfile = root / f"rules/{label}/ip.txt"
        ips = parse_ips(ipfile.read_text()) if ipfile.exists() else set()
        loaded[label] = (ds, ips)
        variants = [(tag, ds, ips), (tag + "-domain", ds, ())]
        if ips:
            variants.append((tag + "-ip", (), ips))
        for name, domains, networks in variants:
            document = json.loads((root / f"rule-set/{name}.json").read_text())
            assert_equivalent(document, domains, networks)
            for extension in ("json", "srs"):
                asset = root / f"rule-set/{name}.{extension}"
                if (asset.with_name(asset.name + ".sha256sum")).read_text() != f"{sha(asset.read_bytes())}  {asset.name}\n":
                    raise AssertionError("Artifact checksum mismatch: " + asset.name)
    groups = []
    original_probe = reference_verify.native_probe

    def record(assets, rules, cases, name):
        groups.append((rules, cases))
        original_probe(xray, assets, rules, cases, name)

    # Preserve every reference runtime regression and add independent boundary
    # probes. Xray's actual routing decisions gate the same sing-box probes.
    with patch.object(reference_verify, "native_probe", lambda binary, assets, rules, cases, scratch: record(assets, rules, cases, scratch)):
        reference_verify.verify(reference, xray)
    (root / "build").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=root / "build") as temporary:
        scratch = Path(temporary)
        fixture_domains = {Domain("full", "exact.example"), Domain("domain", "suffix.example"),
                           Domain("keyword", "needle"), Domain("regexp", r"^rx[0-9]+\.example$")}
        fixture_ips = {ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("2001:db8::/32")}
        fixtures = {"fixture-domain": project(fixture_domains), "fixture-ip": project((), fixture_ips)}
        # The apex of a wildcard is deliberately excluded; never turn this into
        # a domain_suffix which would silently add the apex to the match set.
        scope_domains = {Domain("regexp", r"^(?:[^.]+\.)+scope\.example$"),
                         Domain("regexp", r"^only[0-9]+\.example$"), Domain("full", "fixed.example")}
        fixtures["scope-domain"] = project(scope_domains)
        (scratch / "geosite.dat").write_bytes(geosite({"scope": scope_domains}))
        scope_rules = [{"type": "field", "domain": ["geosite:scope"], "outboundTag": "hit"}]
        scope_cases = [("scope.example", "miss"), ("a.scope.example", "hit"), ("a.b.scope.example", "hit"),
                       ("notscope.example", "miss"), ("only123.example", "hit"), ("only123.example.invalid", "miss"),
                       ("fixed.example", "hit"), ("child.fixed.example", "miss"),
                       ("FIXED.example", "hit"), ("fixed.example.", "miss")]
        (scratch / "scope-xray").mkdir()
        record(scratch, scope_rules, scope_cases, scratch / "scope-xray")
        witnesses = json.loads((ROOT / "tests/regex_witnesses.json").read_text())
        source_regexps = sorted({r.value for ds, _ in loaded.values() for r in ds if r.kind == "regexp"})
        for index, expression in enumerate(source_regexps):
            if expression not in witnesses:
                raise ValueError("New source regexp has no reviewed native regression witness: " + expression)
            regex = re.compile(expression, re.ASCII)
            cases = witnesses[expression]
            if not any(expected == "hit" for _, expected in cases) or not any(expected == "miss" for _, expected in cases):
                raise ValueError("Regexp witness must include positive and negative cases")
            if any(bool(regex.search(host)) != (expected == "hit") for host, expected in cases):
                raise ValueError("Regexp witness disagrees with preserved source expression: " + expression)
            category = f"regex{index:02}"
            rules = {Domain("regexp", expression)}
            fixtures[category + "-domain"] = project(rules)
            (scratch / "geosite.dat").write_bytes(geosite({category: rules}))
            probe_dir = scratch / (category + "-xray")
            probe_dir.mkdir()
            record(scratch, [{"type": "field", "domain": ["geosite:" + category], "outboundTag": "hit"}], cases, probe_dir)
        for label, (ds, ips) in loaded.items():
            tag = "pooban-" + label.lower()
            xrules = [{"type": "field", "domain": ["geosite:" + tag], "outboundTag": "hit"}]
            if ips:
                xrules.append({"type": "field", "ip": ["geoip:" + tag], "outboundTag": "hit"})
            case_dir = scratch / (label + "-xray")
            case_dir.mkdir()
            record(reference / "dist", xrules, sampled_cases(ds, ips), case_dir)
        fixture_root = scratch / "fixtures"
        for name, document in fixtures.items():
            source = fixture_root / (name + ".json")
            save_json(source, document)
            run([engines[1], "rule-set", "compile", "--output", source.with_suffix(".srs"), source])
        tested = []
        for engine in engines:
            native_count = 0
            for extension, file_format in (("json", "source"), ("srs", "binary")):
                # Load every published asset through the actual engine, including
                # all regexps. Also compile every JSON with each compatibility
                # engine; compile failures and parse failures both stop release.
                all_sets = []
                for source in sorted((root / "rule-set").glob("*.json")):
                    tag = source.stem
                    if extension == "json":
                        destination = scratch / version(engine) / (tag + ".srs")
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        run([engine, "rule-set", "compile", "--output", destination, source])
                        if version(engine) == "1.14.3":
                            assert_official_binary(source.with_suffix(".srs"), destination)
                    all_sets.append({"type": "local", "tag": tag, "format": file_format,
                                     "path": str(source.with_suffix("." + extension))})
                config = scratch / "load-all.json"
                save_json(config, {"outbounds": [{"type": "direct", "tag": "direct"}],
                                   "route": {"rule_set": all_sets, "final": "direct"}})
                run([engine, "check", "-c", config])
                for index, (xrules, cases) in enumerate(groups):
                    definitions, rules = {}, []
                    for xrule in xrules:
                        for field, suffix in (("domain", "-domain"), ("ip", "-ip")):
                            if field not in xrule:
                                continue
                            for value in xrule[field]:
                                category = value.split(":", 1)[1]
                                tag = category + suffix
                                base = fixture_root if tag in fixtures else root / "rule-set"
                                definitions[tag] = {"type": "local", "tag": tag, "format": file_format,
                                                    "path": str(base / (tag + "." + extension))}
                                rules.append({"rule_set": [tag], "action": "route", "outbound": xrule["outboundTag"]})
                    sing_probe(engine, list(definitions.values()), rules, cases,
                               scratch / (version(engine) + extension) / str(index))
                    native_count += len(cases)
            tested.append({"version": version(engine), "isolated_routing_checks": native_count,
                           "json_and_published_srs_loaded": True, "all_json_compiled": True})
            print(f"sing-box {version(engine)}: {native_count} isolated routing checks passed", flush=True)
    return {"status": "passed", "engines": tested, "xray_version": "26.9.9",
            "xray_isolated_routing_checks": sum(len(cases) for _, cases in groups),
            "all_rules_inventory_equal": True, "additional_conversion_omissions": 0,
            "all_resolved_sources_equal": True, "all_srs_official_compiler_equal": True,
            "source_regexps_with_isolated_native_witnesses": len(source_regexps),
            "checks": ["full reference regression suite", "exact/suffix/keyword/regexp boundaries",
                       "subdomain-only wildcard apex exclusion", "IPv4/IPv6 CIDR edge membership",
                       "Google-before-China precedence", "independent seven-category routing",
                       "every source regexp isolated from overlapping suffixes",
                       "official engine JSON/SRS loading, compilation and complete binary reproduction"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--reference", type=Path, default=ROOT / "build/reference")
    args = parser.parse_args()
    print(json.dumps(verify(args.root, args.reference, binaries(), ROOT / "build/tools/xray"), indent=2))

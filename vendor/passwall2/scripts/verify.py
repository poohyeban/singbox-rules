"""Gate publication on real Xray parsing and isolated loopback routing tests."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

from .model import Domain, geoip, geosite


def config(rules, port=None):
    value = {
        "log": {"loglevel": "error"},
        "outbounds": [{"protocol": "blackhole", "tag": tag} for tag in ("miss", "hit")],
        "routing": {"domainStrategy": "AsIs", "rules": rules + [
            {"type": "field", "network": "tcp,udp", "outboundTag": "miss"}]},
    }
    if port is not None:
        value["inbounds"] = [{"listen": "127.0.0.1", "port": port, "tag": "probe",
                              "protocol": "socks", "settings": {"auth": "noauth"}}]
    return value


def invoke_test(binary, root, cfg):
    env = dict(os.environ, XRAY_LOCATION_ASSET=str(root))
    result = subprocess.run([str(binary), "run", "-test", "-format", "json", "-c", "stdin:"],
                            input=json.dumps(cfg), text=True, capture_output=True, env=env, timeout=60)
    if result.returncode or "Configuration OK" not in result.stdout:
        raise RuntimeError("Xray rejected generated data:\n" + result.stdout + result.stderr)


def native_probe(binary, assets, rules, cases, scratch):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    cfg = config(rules, port)
    logfile = scratch / "access.log"
    cfg["log"]["access"] = str(logfile)
    cfgfile = scratch / "config.json"
    cfgfile.write_text(json.dumps(cfg))
    env = dict(os.environ, XRAY_LOCATION_ASSET=str(assets))
    process = subprocess.Popen([str(binary), "run", "-c", str(cfgfile)], env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for attempt in range(100):
            if process.poll() is not None:
                raise RuntimeError("Xray probe process exited before listening")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("Xray probe did not start")
        for target, expected in cases:
            before = logfile.stat().st_size if logfile.exists() else 0
            with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                client.sendall(b"\x05\x01\x00")
                if client.recv(2) != b"\x05\x00":
                    raise RuntimeError("SOCKS handshake failed")
                try:
                    ip = ipaddress.ip_address(target)
                    addr = bytes([1 if ip.version == 4 else 4]) + ip.packed
                except ValueError:
                    encoded = target.encode("ascii")
                    addr = b"\x03" + bytes([len(encoded)]) + encoded
                client.sendall(b"\x05\x01\x00" + addr + b"\x01\xbb")
                client.recv(32)
                client.sendall(b"probe")
                # Both outbounds are blackhole: no DNS or Internet connection.
                for attempt in range(100):
                    text = logfile.read_text()[before:] if logfile.exists() else ""
                    if "[probe ->" in text:
                        break
                    time.sleep(0.03)
                if f"[probe -> {expected}]" not in text:
                    raise AssertionError(f"Native routing mismatch for {target}: expected {expected}; {text.strip()}")
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def verify(root: Path, binary: Path):
    root, binary = root.resolve(), binary.resolve()
    version = subprocess.check_output([str(binary), "version"], text=True)
    if "Xray 26.9.9 " not in version:
        raise RuntimeError("Expected pinned Xray 26.9.9")
    manifest = json.loads((root / "dist/manifest.json").read_text())
    for name, expected in manifest["artifacts"].items():
        data = (root / "dist" / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise AssertionError("Manifest checksum mismatch")
        if (root / "dist" / (name + ".sha256sum")).read_text() != f"{expected}  {name}\n":
            raise AssertionError("Sidecar checksum mismatch")
    all_rules = []
    for tag in ("pooban-china", "pooban-google", "pooban-openai", "pooban-adguard",
                "pooban-whatsapp", "pooban-instagram", "pooban-facebook"):
        all_rules.append({"type": "field", "domain": ["geosite:" + tag], "outboundTag": "hit"})
    for tag in ("pooban-china", "pooban-openai"):
        all_rules.append({"type": "field", "ip": ["geoip:" + tag], "outboundTag": "hit"})
    invoke_test(binary, root / "dist", config(all_rules))
    # Independent engine-level coverage of all protobuf domain types, regex
    # boundaries, and both IP address families.
    fixtures = {"fixture": {Domain("full", "exact.example"), Domain("domain", "suffix.example"),
                             Domain("keyword", "needle"), Domain("regexp", r"^rx[0-9]+\.example$")}}
    (root / "build").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=root / "build") as tmp:
        base = Path(tmp)
        (base / "geosite.dat").write_bytes(geosite(fixtures))
        (base / "geoip.dat").write_bytes(geoip({"fixture": [ipaddress.ip_network("192.0.2.0/24"),
                                                            ipaddress.ip_network("2001:db8::/32")]}))
        groups = [
            (base, [{"type": "field", "domain": ["geosite:fixture"], "outboundTag": "hit"},
                    {"type": "field", "ip": ["geoip:fixture"], "outboundTag": "hit"}],
             [("exact.example", "hit"), ("child.exact.example", "miss"),
              ("suffix.example", "hit"), ("child.suffix.example", "hit"),
              ("notsuffix.example", "miss"), ("hasneedle.example", "hit"),
              ("rx123.example", "hit"), ("rx123.example.invalid", "miss"),
              ("192.0.2.15", "hit"), ("198.51.100.1", "miss"),
              ("2001:db8::123", "hit"), ("2001:db9::123", "miss")]),
        ]
        for label, host in (("China", "baidu.com"), ("Google", "google.com"),
                            ("OpenAI", "chatgpt.com"), ("AdGuard", None),
                            ("WhatsApp", "whatsapp.com"), ("Instagram", "instagram.com"),
                            ("Facebook", "facebook.com")):
            if host is None:
                lines = (root / f"rules/{label}/domains.txt").read_text().splitlines()
                host = next(l.split(":", 1)[1] for l in lines if l.startswith(("domain:", "full:")))
            tag = "pooban-" + label.lower()
            rules = [{"type": "field", "domain": ["geosite:" + tag], "outboundTag": "hit"}]
            cases = [(host, "hit"), ("unlisted-test.invalid", "miss")]
            if label == "OpenAI":
                cases.extend([("chatgpt.com.evil.invalid", "miss"),
                              ("chatgpt-async-webps-prod-example-12.webpubsub.azure.com", "hit")])
            if label == "AdGuard":
                cases.append(("ad.10010.com", "miss"))
            elif label in {"WhatsApp", "Instagram", "Facebook"}:
                positives = {
                    "WhatsApp": ["wa.me", "media.whatsapp.net", "graph.whatsapp.com"],
                    "Instagram": ["instagr.am", "cdninstagram.com", "ig.me"],
                    "Facebook": ["fbcdn.net", "tfbnw.net", "accountkit.com", "f8.com", "fbcdn-a.akamaihd.net"],
                }
                cases.extend((value, "hit") for value in positives[label])
                cases.extend((value, "miss") for value in (
                    host + ".evil.invalid", "not" + host, "threads.net", "oculus.com",
                    "messenger.com", "meta.com", "child.fbcdn-a.akamaihd.net", "192.0.2.1"))
                cases.extend((other, "miss") for other in ("whatsapp.com", "instagram.com", "facebook.com")
                             if other != host)
            elif label == "Google":
                cases.extend((host, "hit") for host in (
                    "www.youtube.com", "music.youtube.com", "youtu.be", "i.ytimg.com",
                    "rr1.sn-example.googlevideo.com", "mail.google.com", "drive.google.com",
                    "maps.google.com", "photos.google.com", "gemini.google.com",
                    "aistudio.google.com", "deepmind.google", "play.google.com",
                    "android.com", "mtalk.google.com", "firebase.google.com",
                    "example.firebaseapp.com", "example.run.app", "cloud.google.com",
                    "storage.googleapis.com", "fonts.gstatic.com", "google.cn",
                    "services.googleapis.cn", "xn--ngstr-lra8j.com",
                    "redirector.xn--ngstr-lra8j.com", "doubleclick.net"))
                cases.extend((host, "miss") for host in (
                    "notgoogle.com", "google.com.evil.invalid", "youtube.com.evil.invalid",
                    "chatgpt.com", "baidu.com", "unrelated.dev", "192.0.2.1"))
            else:
                rules.append({"type": "field", "ip": ["geoip:" + tag], "outboundTag": "hit"})
                nets = [ipaddress.ip_network(l) for l in (root / f"rules/{label}/ip.txt").read_text().splitlines()]
                for family in (4, 6):
                    selected = next((n for n in nets if n.version == family), None)
                    if selected:
                        cases.append((str(selected.network_address), "hit"))
                cases.append(("192.0.2.1", "miss"))
            groups.append((root / "dist", rules, cases))
        # Google must win over overlapping China domains in the intended order.
        groups.append((root / "dist", [
            {"type": "field", "domain": ["geosite:pooban-google"], "outboundTag": "hit"},
            {"type": "field", "domain": ["geosite:pooban-china"], "outboundTag": "miss"},
        ], [("google.cn", "hit"), ("redirector.xn--ngstr-lra8j.com", "hit"),
            ("fonts.gstatic.com", "hit"), ("baidu.com", "miss")]))
        total = 0
        for index, (assets, rules, cases) in enumerate(groups):
            scratch = base / str(index)
            scratch.mkdir()
            native_probe(binary, assets, rules, cases, scratch)
            total += len(cases)
    print(f"Xray 26.9.9: both DAT assets loaded; {total} isolated routing checks passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--xray", type=Path, default=Path("build/tools/xray"))
    args = parser.parse_args()
    verify(Path(__file__).resolve().parents[1], args.xray)

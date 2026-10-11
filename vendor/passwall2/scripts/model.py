"""Independent parsers and a minimal encoder for the public Xray geodata format.

Wire schema: XTLS/Xray-core common/geodata/geodat.proto (v26.9.9).
Generated files are also loaded by the actual Xray binary before publication.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re


class InvalidSource(ValueError):
    pass


def hostname(value: str) -> str:
    value = value.lower().encode("idna").decode("ascii")
    if value.endswith("."):
        value = value[:-1]
    if not value or len(value) > 253:
        raise InvalidSource("Invalid hostname length")
    if any(not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", p)
           for p in value.split(".")):
        raise InvalidSource("Invalid hostname")
    return value


@dataclass(frozen=True, order=True)
class Domain:
    kind: str
    value: str

    def text(self) -> str:
        # Xray's plain-string rule is a substring match, not a suffix match.
        return self.value if self.kind == "keyword" else f"{self.kind}:{self.value}"

    def matches(self, host: str) -> bool:
        host = hostname(host)
        if self.kind == "full":
            return host == self.value
        if self.kind == "domain":
            return host == self.value or host.endswith("." + self.value)
        if self.kind == "keyword":
            return self.value in host
        if self.kind == "regexp":
            return re.search(self.value, host, re.ASCII) is not None
        raise InvalidSource("Unknown domain rule kind")


def v2fly(text: str) -> set[Domain]:
    result = set()
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Release annotations and source annotations are not part of a regexp.
        line = re.split(r":@|\s+[@&]|\s+#", line, maxsplit=1)[0].strip()
        kind, value = line.split(":", 1) if ":" in line else ("domain", line)
        if kind not in {"domain", "full", "keyword", "regexp"}:
            raise InvalidSource(f"v2fly line {number}: unsupported type {kind}; source must be fully resolved")
        if not value or "\x00" in value or "\n" in value:
            raise InvalidSource(f"v2fly line {number}: empty or invalid rule")
        if kind in {"domain", "full"}:
            value = hostname(value)
        elif kind == "keyword":
            if re.search(r"\s", value):
                raise InvalidSource("Whitespace in domain keyword")
            value = value.lower()
        # Do not lowercase, expand, anchor, or otherwise alter source regexps.
        result.add(Domain(kind, value))
    if not result:
        raise InvalidSource("Empty v2fly domain source")
    return result


def official_domains(source: str, excluded: str) -> set[Domain]:
    def entries(text):
        return {l.split("#", 1)[0].strip().lower() for l in text.splitlines()
                if l.split("#", 1)[0].strip()}
    full, omit = entries(source), entries(excluded)
    if not omit <= full:
        raise InvalidSource("An official-domain exclusion is absent from the reviewed source")
    result = set()
    for entry in full:
        base = entry[2:] if entry.startswith("*.") else entry
        normalized = hostname(base)
        if entry in omit:
            continue
        if entry.startswith("*."):
            # At least one valid label; preserve subdomain-only scope.
            result.add(Domain("regexp", r"^(?:[^.]+\.)+" + re.escape(normalized) + "$"))
        else:
            result.add(Domain("full", normalized))
    if not result:
        raise InvalidSource("Empty reviewed OpenAI domain set")
    return result


def networks(values) -> list:
    nets = [ipaddress.ip_network(v, strict=True) for v in values]
    result = []
    for version in (4, 6):
        result.extend(ipaddress.collapse_addresses(n for n in nets if n.version == version))
    return result


def varint(n: int) -> bytes:
    out = bytearray()
    while n > 127:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)


def field(number: int, value: bytes | str | int) -> bytes:
    if isinstance(value, int):
        return varint(number << 3) + varint(value)
    if isinstance(value, str):
        value = value.encode("utf-8")
    return varint(number << 3 | 2) + varint(len(value)) + value


def geosite(groups: dict[str, set[Domain]]) -> bytes:
    out = bytearray()
    kinds = {"keyword": 0, "regexp": 1, "domain": 2, "full": 3}
    for tag, rules in sorted(groups.items()):
        if not rules:
            raise InvalidSource("Empty geosite category")
        entry = bytearray(field(1, tag.upper()))
        for rule in sorted(rules):
            entry += field(2, field(1, kinds[rule.kind]) + field(2, rule.value))
        out += field(1, entry)
    return bytes(out)


def geoip(groups: dict[str, list]) -> bytes:
    out = bytearray()
    for tag, nets in sorted(groups.items()):
        if not nets:
            raise InvalidSource("Empty geoip category")
        entry = bytearray(field(1, tag.upper()))
        for net in networks(nets):
            entry += field(2, field(1, net.network_address.packed) + field(2, net.prefixlen))
        out += field(1, entry)
    return bytes(out)

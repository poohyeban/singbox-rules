"""A lossless, field-for-field projection of the reference's resolved rules."""
from __future__ import annotations

from collections import Counter
import ipaddress

from vendor.passwall2.scripts.model import Domain, InvalidSource, hostname
from .common import FIELDS


class ConversionError(InvalidSource):
    pass


def parse_domains(text: str, source: str = "domains.txt") -> set[Domain]:
    result = set()
    for number, line in enumerate(text.splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        kind, value = line.split(":", 1) if ":" in line else ("keyword", line)
        if kind not in FIELDS or not value or value != value.strip() or "\x00" in value:
            raise ConversionError(f"{source}:{number}: unsupported or ambiguous rule: {line!r}")
        if kind in {"domain", "full"} and hostname(value) != value:
            raise ConversionError(f"{source}:{number}: non-canonical hostname; refusing to rewrite")
        if kind == "keyword" and (value != value.lower() or any(c.isspace() for c in value)):
            raise ConversionError(f"{source}:{number}: non-canonical keyword")
        # Regexps are copied byte-for-byte. Official engines validate Go syntax.
        result.add(Domain(kind, value))
    if not result:
        raise ConversionError(f"{source}: empty domain category")
    return result


def parse_ips(text: str, source: str = "ip.txt"):
    result = set()
    for number, line in enumerate(text.splitlines(), 1):
        try:
            net = ipaddress.ip_network(line, strict=True)
        except ValueError as error:
            raise ConversionError(f"{source}:{number}: invalid CIDR {line!r}") from error
        if str(net) != line:
            raise ConversionError(f"{source}:{number}: non-canonical CIDR; refusing to rewrite")
        result.add(net)
    if not result:
        raise ConversionError(f"{source}: empty IP category")
    return result


def project(domains, ips=()):
    rule = {}
    for kind, field in FIELDS.items():
        values = sorted({r.value for r in domains if r.kind == kind})
        if values:
            rule[field] = values
    unknown = {r.kind for r in domains} - set(FIELDS)
    if unknown:
        raise ConversionError("Unsupported domain types: " + ", ".join(sorted(unknown)))
    if ips:
        rule["ip_cidr"] = sorted(map(str, ips))
    if not rule:
        raise ConversionError("Refusing to emit an empty rule, which could match everything")
    # Domain fields and destination CIDRs are OR alternatives in a headless rule.
    # Format v2 retains optimized suffix encoding and requires no newer fields.
    return {"version": 2, "rules": [rule]}


def assert_equivalent(document, domains, ips=()):
    expected = project(domains, ips)
    if document != expected:
        raise ConversionError("JSON inventory differs from the exact reference projection")
    return {field: len(values) for field, values in expected["rules"][0].items()}


def counts(domains, ips=()):
    by_kind = Counter(r.kind for r in domains)
    return {"domains": len(domains), "regexps": by_kind["regexp"],
            "ipv4": sum(n.version == 4 for n in ips), "ipv6": sum(n.version == 6 for n in ips)}

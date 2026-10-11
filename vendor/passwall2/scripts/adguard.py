"""A conservative hostname-only projection of AdGuard DNS rules.

Exceptions are applied at build time, never converted into a direct/proxy policy.
Potentially intersecting blocks are removed when an exact subtraction is not
available. Unknown exceptions stop publication. This intentionally under-blocks.
"""
from __future__ import annotations

from collections import Counter
import ipaddress
import re
from .model import Domain, InvalidSource, hostname


def split_rule(line: str):
    exception = line.startswith("@@")
    body = line[2:] if exception else line
    if body.startswith("/"):
        # A regex can contain '$'; only text after the closing slash is a modifier.
        end = len(body) - 1
        while end > 0:
            # Count escaping explicitly; do not split inside a regex.
            if body[end] == "/":
                back = end - 1
                while back >= 0 and body[back] == "\\":
                    back -= 1
                if (end - 1 - back) % 2 == 0:
                    break
            end -= 1
        if end <= 0:
            raise InvalidSource("Unterminated AdGuard regexp")
        pattern, rest = body[:end + 1], body[end + 1:]
        if rest and not rest.startswith("$"):
            raise InvalidSource("Invalid AdGuard regexp suffix")
        mods = rest[1:].split(",") if rest else []
    else:
        pattern, separator, rest = body.partition("$")
        mods = rest.split(",") if separator else []
    return exception, pattern, mods


def impossible_hostname_regex(pattern: str) -> bool:
    """Prove a required literal cannot occur in a normalized hostname.

Unknown constructs are treated as possible, never as proof of irrelevance.
Used only to disregard exceptions that cannot apply to any hostname.
"""
    from re import _parser, _constants as c
    def impossible(seq):
        for op, arg in seq:
            if op == c.LITERAL and chr(arg) not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._":
                return True
            if op == c.SUBPATTERN and impossible(arg[-1]):
                return True
            if op == c.BRANCH and all(impossible(branch) for branch in arg[1]):
                return True
            if op in (c.MAX_REPEAT, c.MIN_REPEAT) and arg[0] > 0 and impossible(arg[2]):
                return True
        return False
    try:
        return impossible(_parser.parse(pattern, re.ASCII))
    except (re.error, ValueError):
        return False


def pattern_rule(pattern: str) -> Domain | None:
    if pattern.startswith("/") and pattern.endswith("/"):
        regex = pattern[1:-1]
        if impossible_hostname_regex(regex):
            return None
        return Domain("regexp", regex)
    # AdGuard domain-only lines match the apex only.
    if re.fullmatch(r"[\w.-]+", pattern, re.ASCII) and not pattern.startswith("."):
        return Domain("full", hostname(pattern))
    m = re.fullmatch(r"(\|\||\|)([a-zA-Z0-9_.-]+)(?:\^\|?|\|)", pattern)
    if m:
        return Domain("domain" if m[1] == "||" else "full", hostname(m[2]))
    # Hostname masks: preserve substring/boundary/wildcard semantics exactly.
    if re.search(r"[^a-zA-Z0-9_.\-*^|]", pattern):
        raise InvalidSource("Non-hostname or unsupported AdGuard pattern")
    head = ""
    if pattern.startswith("||"):
        head, pattern = r"(?:^|\.)", pattern[2:]
    elif pattern.startswith("|"):
        head, pattern = "^", pattern[1:]
    end = ""
    if pattern.endswith("^|"):
        end, pattern = "$", pattern[:-2]
    elif pattern.endswith(("^", "|")):
        end, pattern = "$", pattern[:-1]
    if "^" in pattern or "|" in pattern or not pattern:
        raise InvalidSource("Unsupported AdGuard anchor")
    regex = head + re.escape(pattern.lower()).replace(r"\*", ".*") + end
    return Domain("regexp", regex)


def intersects(a: Domain, b: Domain) -> bool:
    """True includes 'cannot prove disjoint'; it never just samples hostnames."""
    if a.kind == b.kind == "full":
        return a.value == b.value
    if a.kind == "full":
        return b.matches(a.value)
    if b.kind == "full":
        return a.matches(b.value)
    if a.kind == b.kind == "domain":
        return a.matches(b.value) or b.matches(a.value)
    # A regexp and an infinite suffix language require a language-intersection
    # proof. Do not replace that proof with a few example matches.
    return True


def exception_envelope(pattern: str) -> Domain | None:
    """An end-anchored mask's final complete labels bound every match.

    For example, cdn.us*.example.com cannot escape example.com. Exempting that
    whole suffix can under-block, but cannot violate the original exception.
    This proof is deliberately restricted to non-regexp hostname masks.
    """
    if pattern.startswith("/") or not pattern.endswith(("^", "|")):
        return None
    tail = pattern.removesuffix("|").removesuffix("^")
    match = re.search(r"\.([a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+)$", tail)
    return Domain("domain", hostname(match[1])) if match else None


def ancestors(value: str):
    parts = value.split(".")
    return [".".join(parts[i:]) for i in range(len(parts))]


def convert(text: str):
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith(("!", "#"))]
    disabled = set()
    diagnostics = []
    counts = Counter(input=len(lines))
    parsed = []
    for line in lines:
        try:
            exc, pattern, mods = split_rule(line)
        except InvalidSource:
            if line.startswith("@@"):
                raise
            diagnostics.append({"reason": "unsupported-syntax", "rule": line})
            continue
        if "badfilter" in mods:
            rest = tuple(sorted(m for m in mods if m != "badfilter"))
            disabled.add((exc, pattern, rest))
            counts["badfilter"] += 1
        else:
            parsed.append((line, exc, pattern, tuple(sorted(mods))))
    blocks, exceptions = set(), set()
    for line, exc, pattern, mods in parsed:
        if (exc, pattern, mods) in disabled:
            counts["disabled"] += 1
            continue
        if any(m != "important" for m in mods):
            if exc:
                raise InvalidSource("Unsupported conditional AdGuard exception")
            diagnostics.append({"reason": "conditional-modifier", "rule": line})
            continue
        try:
            # Only blocking hosts entries are representable. Redirects are not.
            words = pattern.split()
            if len(words) >= 2:
                addr = ipaddress.ip_address(words[0])
                if not (addr.is_unspecified or addr.is_loopback):
                    raise InvalidSource("DNS redirect is not a block")
                rules = {Domain("full", hostname(w)) for w in words[1:]}
            else:
                rule = pattern_rule(pattern)
                rules = {rule} if rule else set()
        except (InvalidSource, ValueError, UnicodeError):
            if exc:
                raise InvalidSource("Unrepresentable AdGuard exception; refusing to publish")
            diagnostics.append({"reason": "non-hostname-or-unsupported-pattern", "rule": line})
            continue
        if not rules:
            diagnostics.append({"reason": "cannot-match-hostname", "rule": line})
            continue
        if exc and any(r.kind == "regexp" for r in rules):
            envelope = exception_envelope(pattern)
            if envelope:
                rules = {envelope}
                diagnostics.append({"reason": "exception-conservative-suffix-envelope", "rule": line})
                counts["exception_envelopes"] += 1
        (exceptions if exc else blocks).update(rules)
        if mods:
            counts["important_conservatively_lowered"] += 1
    output = set()
    exact_exceptions = {r.value for r in exceptions if r.kind == "full"}
    suffix_exceptions = {r.value for r in exceptions if r.kind == "domain"}
    below_exception = {a for e in exact_exceptions | suffix_exceptions for a in ancestors(e)}
    complex_exceptions = {r for r in exceptions if r.kind not in {"full", "domain"}}
    for block in blocks:
        if block.kind in {"full", "domain"}:
            conflict = (block.value in exact_exceptions or
                        any(a in suffix_exceptions for a in ancestors(block.value)) or
                        (block.kind == "domain" and block.value in below_exception) or
                        any(intersects(block, e) for e in complex_exceptions))
        else:
            conflict = any(intersects(block, exception) for exception in exceptions)
        if conflict:
            diagnostics.append({"reason": "exception-overlap-or-not-provably-disjoint", "rule": block.text()})
        else:
            output.add(block)
    if not output:
        raise InvalidSource("Empty AdGuard output")
    counts.update(blocks_before_exceptions=len(blocks), exceptions=len(exceptions), output=len(output))
    counts["omitted"] = len(diagnostics)
    return output, dict(counts), sorted(diagnostics, key=lambda d: (d["reason"], d["rule"]))

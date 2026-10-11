import ipaddress
import json
import unittest
import io
import zipfile
from unittest.mock import patch
from types import SimpleNamespace
from pathlib import Path

from scripts.model import Domain, InvalidSource, hostname, networks, official_domains, v2fly
from scripts.adguard import convert, intersects, pattern_rule, split_rule
from scripts.build import voice_prefixes, read_mmdb
from scripts.google import google_domains


class GoogleTests(unittest.TestCase):
    def archive(self, files):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, text in files.items():
                archive.writestr("snapshot/data/" + name, text)
        return buffer.getvalue()

    def test_nested_includes_and_cn_ads_annotations_preserved(self):
        data = self.archive({"google": "include:youtube\ninclude:play\ngoogle.cn @cn\nads.example @ads",
                             "youtube": "include:video\nyoutube.com",
                             "video": "googlevideo.com", "play": "xn--ngstr-lra8j.com"})
        rules, names = google_domains(data)
        self.assertEqual(len(rules), 5)
        self.assertEqual(names, ["google", "play", "video", "youtube"])
        self.assertIn(Domain("domain", "google.cn"), rules)
        self.assertIn(Domain("domain", "ads.example"), rules)

    def test_missing_cycle_filtered_and_unsafe_includes_fail(self):
        for files in ({"google": "include:missing"},
                      {"google": "include:youtube", "youtube": "include:google"},
                      {"google": "include:youtube @cn", "youtube": "youtube.com"},
                      {"google": "include:../private"}):
            with self.subTest(files=files), self.assertRaises(InvalidSource):
                google_domains(self.archive(files))

    def test_full_and_regex_semantics_survive_archive_resolution(self):
        rules, _ = google_domains(self.archive({"google": "full:exact.example\nregexp:^r[0-9]+\\.example$ @cn"}))
        self.assertTrue(any(r.matches("r12.example") for r in rules))
        self.assertFalse(any(r.matches("child.exact.example") for r in rules))
        self.assertFalse(any(r.matches("r12.example.evil.invalid") for r in rules))

    def test_independent_meta_categories_share_snapshot_without_google_leakage(self):
        data = self.archive({"google": "google.example", "facebook": "include:fb-child\nfacebook.example",
                             "fb-child": "full:exact.example\nregexp:^r[0-9]+\\.example$",
                             "instagram": "instagram.example", "whatsapp": "whatsapp.example"})
        facebook, names = google_domains(data, "facebook")
        self.assertEqual(names, ["facebook", "fb-child"])
        self.assertTrue(any(r.matches("r12.example") for r in facebook))
        self.assertFalse(any(r.matches("child.exact.example") for r in facebook))
        for category in ("instagram", "whatsapp"):
            rules, names = google_domains(data, category)
            self.assertEqual(names, [category])
            self.assertEqual(rules, {Domain("domain", category + ".example")})
            self.assertFalse(any(r.matches("facebook.example") for r in rules))
        self.assertFalse(any(r.matches("google.example") for r in facebook))


class V2FlyTests(unittest.TestCase):
    def test_suffix_full_keyword_are_distinct(self):
        rules = v2fly("domain:example.cn\nfull:exact.example\nkeyword:needle\n")
        self.assertTrue(Domain("domain", "example.cn").matches("a.example.cn"))
        self.assertFalse(Domain("domain", "example.cn").matches("notexample.cn"))
        self.assertFalse(Domain("full", "exact.example").matches("a.exact.example"))
        self.assertIn(Domain("keyword", "needle"), rules)

    def test_regex_is_preserved_with_metadata_removed(self):
        regex = r"^chatgpt-async-\S+-\d+\.azure\.com$"
        rules = v2fly("regexp:" + regex + ":@cn\nexample.com @cn\n")
        self.assertIn(Domain("regexp", regex), rules)

    def test_unresolved_includes_fail(self):
        for source in ("include:other", "bogus:example.com", "# empty", "domain:"):
            with self.subTest(source=source), self.assertRaises(InvalidSource):
                v2fly(source)

    def test_hostname_boundary_validation(self):
        self.assertEqual(hostname("EXAMPLE.COM."), "example.com")
        for value in ("bad..example", "example.com/path", "-bad.example", "bad example"):
            with self.assertRaises((InvalidSource, UnicodeError)):
                hostname(value)


class OfficialTests(unittest.TestCase):
    def test_wildcard_excludes_apex_and_accepts_nested_children(self):
        rule = next(iter(official_domains("*.example.com", "")))
        self.assertFalse(rule.matches("example.com"))
        self.assertTrue(rule.matches("a.example.com"))
        self.assertTrue(rule.matches("a.b.example.com"))
        self.assertFalse(rule.matches("example.com.evil.invalid"))

    def test_exclusion_is_exact_source_entry(self):
        result = official_domains("*.example.com\nexample.com", "*.example.com")
        self.assertEqual(result, {Domain("full", "example.com")})

    def test_unknown_and_total_exclusions_fail(self):
        for exclusion in ("unknown.example", "example.com"):
            with self.assertRaises(InvalidSource):
                official_domains("example.com", exclusion)


class AdGuardTests(unittest.TestCase):
    def test_plain_host_is_exact(self):
        self.assertEqual(pattern_rule("example.com"), Domain("full", "example.com"))

    def test_anchor_scope(self):
        suffix = pattern_rule("||example.com^|")
        exact = pattern_rule("|example.com^|")
        self.assertTrue(suffix.matches("child.example.com"))
        self.assertFalse(suffix.matches("notexample.com"))
        self.assertFalse(exact.matches("child.example.com"))

    def test_regex_end_anchor_is_not_a_modifier(self):
        self.assertEqual(split_rule(r"/^ad\d+\.com$/"), (False, r"/^ad\d+\.com$/", []))
        self.assertEqual(split_rule(r"/ad$/" + "$important")[2], ["important"])

    def test_badfilter_is_applied_before_generation(self):
        result, stats, _ = convert("||ads.example^\n||ads.example^$badfilter\n||other.example^")
        self.assertEqual(result, {Domain("domain", "other.example")})
        self.assertEqual(stats["disabled"], 1)

    def test_exception_removes_overlapping_parent_block(self):
        result, _, _ = convert("||example.com^\n@@||good.example.com^\n||other.example^")
        self.assertEqual(result, {Domain("domain", "other.example")})

    def test_exception_does_not_overmatch_sibling_boundary(self):
        result, _, _ = convert("||notexample.com^\n@@||example.com^")
        self.assertEqual(result, {Domain("domain", "notexample.com")})

    def test_unknown_exception_stops_publication(self):
        with self.assertRaises(InvalidSource):
            convert("||ads.example^\n@@||example.com^$client=example")

    def test_url_only_exception_is_provably_irrelevant(self):
        result, _, _ = convert("||ads.example^\n@@/\\.png#(/ad/)?/")
        self.assertEqual(result, {Domain("domain", "ads.example")})

    def test_optional_or_alternative_forbidden_literal_is_not_proof(self):
        with self.assertRaises(InvalidSource):
            # This regexp can match real hostnames; its presence must not be ignored.
            convert("||ads.example^\n@@/(#|ads)/")

    def test_conditional_block_is_omitted(self):
        result, _, _ = convert("||context.example^$dnstype=A\n||ads.example^")
        self.assertEqual(result, {Domain("domain", "ads.example")})

    def test_hosts_exact_not_suffix(self):
        result, _, _ = convert("0.0.0.0 ads.example\n||other.example^")
        self.assertIn(Domain("full", "ads.example"), result)
        self.assertNotIn(Domain("domain", "ads.example"), result)

    def test_regex_kept_without_conflicting_exceptions(self):
        result, _, _ = convert(r"/^ad[0-9]+\.example$/")
        self.assertEqual(result, {Domain("regexp", r"^ad[0-9]+\.example$")})

    def test_unprovable_regex_suffix_intersection_is_removed(self):
        result, _, _ = convert(r"/^ad.*$/" + "\n@@||good.example^\n||other.example^")
        self.assertEqual(result, {Domain("domain", "other.example")})

    def test_wildcard_exception_envelope_is_bounded(self):
        result, stats, _ = convert("||example.com^\n@@||cdn.us*.example.com^|\n||other.example^")
        self.assertEqual(result, {Domain("domain", "other.example")})
        self.assertEqual(stats["exception_envelopes"], 1)

    def test_parent_exception_removes_child_block(self):
        result, _, _ = convert("||ads.child.example.com^\n@@||example.com^\n||other.example^")
        self.assertEqual(result, {Domain("domain", "other.example")})

    def test_mask_without_start_anchor_remains_substring(self):
        rule = pattern_rule(".ads.example^")
        self.assertTrue(rule.matches("child.ads.example"))
        self.assertFalse(rule.matches("ads.example"))

    def test_important_never_overrides_exception_in_safe_subset(self):
        result, _, _ = convert("||example.com^$important\n@@||example.com^\n||other.example^")
        self.assertEqual(result, {Domain("domain", "other.example")})


class IPTests(unittest.TestCase):
    def test_asn_absence_is_reported_without_guessed_prefixes(self):
        with patch("scripts.build.maxminddb.open_database") as opened:
            db = opened.return_value.__enter__.return_value
            db.metadata.return_value = SimpleNamespace(database_type="GeoLite2-ASN")
            db.__iter__.return_value = iter([
                (ipaddress.ip_network("192.0.2.0/24"), {"autonomous_system_number": 401518}),
                (ipaddress.ip_network("198.51.100.0/24"), {"autonomous_system_number": 8075}),
            ])
            coverage = {}
            result = read_mmdb(Path("unused"), "asn", coverage)
            self.assertEqual(result, [ipaddress.ip_network("192.0.2.0/24")])
            self.assertEqual(coverage, {"401518": 1, "401864": 0})

    def test_empty_asn_selection_fails(self):
        with patch("scripts.build.maxminddb.open_database") as opened:
            db = opened.return_value.__enter__.return_value
            db.metadata.return_value = SimpleNamespace(database_type="GeoLite2-ASN")
            db.__iter__.return_value = iter([])
            with self.assertRaises(InvalidSource):
                read_mmdb(Path("unused"), "asn")

    def test_collapse_preserves_both_families(self):
        result = networks(["192.0.2.0/25", "192.0.2.128/25", "2001:db8::/32"])
        self.assertEqual(result, [ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("2001:db8::/32")])

    def test_voice_schema_and_address_family(self):
        valid = {"creationTime": "2026-01-01T00:00:00+00:00", "prefixes": [{"ipv4Prefix": "8.8.8.8/32"}]}
        self.assertEqual(len(voice_prefixes(json.dumps(valid).encode())), 1)
        for prefix in ({"ipv6Prefix": "8.8.8.8/32"}, {"newField": "8.8.8.8/32"}, {}, {"ipv4Prefix": "127.0.0.1/32"}):
            with self.subTest(prefix=prefix), self.assertRaises((InvalidSource, ValueError)):
                voice_prefixes(json.dumps({**valid, "prefixes": [prefix]}).encode())


if __name__ == "__main__":
    unittest.main()

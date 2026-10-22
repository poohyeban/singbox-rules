"""Scope and fail-closed regressions independent of generated data size."""
import ipaddress
import json
from pathlib import Path
import tempfile
import unittest

from vendor.passwall2.scripts.model import Domain, official_domains
from scripts.convert import ConversionError, assert_equivalent, counts, parse_domains, parse_ips, project
from scripts.reference import check_local
from scripts.common import ROOT
from scripts.verify import assert_official_binary, verify_resolved_inputs


class ProjectionTests(unittest.TestCase):
    def test_all_four_types_are_preserved(self):
        ds = parse_domains("full:exact.example\ndomain:suffix.example\nneedle\nregexp:^rx[0-9]+\\.example$\n")
        self.assertEqual(project(ds), {"version": 2, "rules": [{"domain": ["exact.example"],
                         "domain_suffix": ["suffix.example"], "domain_keyword": ["needle"],
                         "domain_regex": [r"^rx[0-9]+\.example$"]}]})

    def test_bare_passwall_keyword_is_not_a_suffix(self):
        self.assertEqual(project(parse_domains("google\n"))["rules"], [{"domain_keyword": ["google"]}])

    def test_keyword_prefix_is_also_supported(self):
        self.assertEqual(parse_domains("keyword:needle"), {Domain("keyword", "needle")})

    def test_exact_never_becomes_suffix(self):
        result = project({Domain("full", "exact.example")})
        self.assertEqual(result["rules"], [{"domain": ["exact.example"]}])

    def test_suffix_apex_and_label_boundary(self):
        rule = Domain("domain", "scope.example")
        self.assertTrue(rule.matches("scope.example"))
        self.assertTrue(rule.matches("child.scope.example"))
        self.assertFalse(rule.matches("notscope.example"))
        self.assertFalse(rule.matches("scope.example.evil.invalid"))

    def test_official_wildcard_excludes_apex(self):
        ds = official_domains("*.scope.example", "")
        self.assertEqual(project(ds)["rules"], [{"domain_regex": [r"^(?:[^.]+\.)+scope\.example$"]}])
        rule = next(iter(ds))
        self.assertFalse(rule.matches("scope.example"))
        self.assertTrue(rule.matches("a.scope.example"))
        self.assertTrue(rule.matches("a.b.scope.example"))

    def test_regex_bytes_anchors_flags_escapes_and_case_unchanged(self):
        regex = r"(?i)^CaSe\S+\d{2}\.example$"
        self.assertEqual(project(parse_domains("regexp:" + regex))["rules"][0]["domain_regex"], [regex])

    def test_regex_colon_is_not_split_again(self):
        regex = r"^(?:one|two)\.example$"
        self.assertEqual(next(iter(parse_domains("regexp:" + regex))).value, regex)

    def test_duplicate_removal_does_not_compact_scopes(self):
        ds = parse_domains("domain:example.com\nfull:child.example.com\ndomain:example.com\n")
        self.assertEqual(len(ds), 2)
        self.assertIn("domain", project(ds)["rules"][0])

    def test_or_domain_and_ip_share_one_default_rule(self):
        result = project({Domain("full", "scope.example")}, {ipaddress.ip_network("2001:db8::/32")})
        self.assertEqual(result["rules"], [{"domain": ["scope.example"], "ip_cidr": ["2001:db8::/32"]}])

    def test_ipv4_ipv6_prefix_lengths_are_identical(self):
        ds = parse_ips("192.0.2.128/25\n2001:db8::/127\n")
        self.assertEqual(project((), ds)["rules"], [{"ip_cidr": ["192.0.2.128/25", "2001:db8::/127"]}])

    def test_host_cidrs_stay_host_cidrs(self):
        self.assertEqual(project((), parse_ips("192.0.2.1/32\n2001:db8::1/128"))["rules"],
                         [{"ip_cidr": ["192.0.2.1/32", "2001:db8::1/128"]}])

    def test_stable_order(self):
        one = project({Domain("full", "b.example"), Domain("full", "a.example")})
        self.assertEqual(one["rules"][0]["domain"], ["a.example", "b.example"])

    def test_inventory_rejects_widened_exact_domain(self):
        ds = {Domain("full", "exact.example")}
        with self.assertRaises(ConversionError):
            assert_equivalent({"version": 2, "rules": [{"domain_suffix": ["exact.example"]}]}, ds)

    def test_inventory_rejects_omission(self):
        ds = {Domain("full", "a.example"), Domain("full", "b.example")}
        with self.assertRaises(ConversionError):
            assert_equivalent(project({Domain("full", "a.example")}), ds)

    def test_inventory_rejects_shortened_ip_prefix(self):
        with self.assertRaises(ConversionError):
            assert_equivalent(project((), parse_ips("192.0.2.0/24")), (), parse_ips("192.0.2.0/25"))

    def test_counts_keep_both_address_families(self):
        self.assertEqual(counts({Domain("regexp", "rx")}, parse_ips("192.0.2.0/24\n2001:db8::/32")),
                         {"domains": 1, "regexps": 1, "ipv4": 1, "ipv6": 1})


class RejectionTests(unittest.TestCase):
    def test_unknown_and_unresolved_syntax_is_fatal(self):
        for line in ("include:google", "geosite:google", "unknown:example.com", "regexp:", "full:",
                     "full:EXAMPLE.com", "domain:example.com.", "domain:example.com ", "full:bad..example", "\x00"):
            with self.subTest(line=line), self.assertRaises(ValueError):
                parse_domains(line, "source-fixture")

    def test_diagnostic_identifies_source_and_line(self):
        with self.assertRaisesRegex(ConversionError, "my-source:2"):
            parse_domains("full:good.example\ninclude:future", "my-source")

    def test_invalid_keyword_is_fatal(self):
        for line in ("keyword:UPPER", "keyword:two words"):
            with self.subTest(line=line), self.assertRaises(ConversionError):
                parse_domains(line)

    def test_cidr_normalization_is_not_silent(self):
        for line in ("192.0.2.1/24", "2001:0db8::/32", "2001:db8::1/32", "192.0.2.1", "garbage", "0.0.0.0/33"):
            with self.subTest(line=line), self.assertRaises(ConversionError):
                parse_ips(line)

    def test_empty_output_is_fatal(self):
        for function in (lambda: parse_domains(""), lambda: parse_ips(""), lambda: project(())):
            with self.assertRaises(ConversionError):
                function()

    def test_unknown_domain_object_is_fatal(self):
        with self.assertRaises(ConversionError):
            project({Domain("future-kind", "scope.example")})

    def test_reference_snapshot_is_byte_identical(self):
        lock = check_local()
        self.assertEqual(lock["commit"], "e8448d37274cb2141405e224aac8161c28fbee95")

    def test_changed_reference_is_fatal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "vendor/passwall2").mkdir(parents=True)
            (root / "reference.lock.json").write_text(json.dumps({"files": {"a": "reviewed-checksum"}}))
            (root / "vendor/passwall2/a").write_text("changed")
            with self.assertRaises(ValueError):
                check_local(root)

    def test_omitted_resolved_rule_is_fatal_even_when_json_agrees(self):
        with tempfile.TemporaryDirectory() as temporary:
            a, b = Path(temporary) / "published", Path(temporary) / "reference"
            for root in (a, b):
                (root / "rules/Category").mkdir(parents=True)
            (a / "rules/Category/domains.txt").write_text("full:a.example\n")
            (b / "rules/Category/domains.txt").write_text("full:a.example\nfull:b.example\n")
            with self.assertRaises(AssertionError):
                verify_resolved_inputs(a, b)

    def test_tampered_srs_is_fatal_even_with_a_matching_sidecar(self):
        with tempfile.TemporaryDirectory() as temporary:
            published, expected = Path(temporary)/"published.srs", Path(temporary)/"expected.srs"
            published.write_bytes(b"SRS\x02tampered")
            expected.write_bytes(b"SRS\x02official-compiler-output")
            with self.assertRaises(AssertionError):
                assert_official_binary(published, expected)


if __name__ == "__main__":
    unittest.main()

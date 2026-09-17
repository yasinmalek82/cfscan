"""Tests for the validation helpers."""

from __future__ import annotations

import unittest

from cfscan.validate import (
    ValidationError,
    assert_no_secrets,
    validate_domain,
    validate_float,
    validate_http_status,
    validate_int,
    validate_ip,
    validate_ip_version,
    validate_loss,
    validate_output_filename,
    validate_port,
    validate_url_scheme,
)


class DomainTests(unittest.TestCase):
    def test_accepts_normal_domains(self):
        for value in ("gerr.yasin-ai-54.ir", "example.com", "a.b.co", "SUB.Example.COM"):
            with self.subTest(value=value):
                self.assertEqual(validate_domain(value), value.strip().lower())

    def test_strips_surrounding_whitespace(self):
        self.assertEqual(validate_domain("  example.com  "), "example.com")

    def test_rejects_malformed_domains(self):
        bad = [
            "",
            "   ",
            "-bad.com",
            "bad-.com",
            "bad..com",
            "no_tld",
            "example",
            "http://example.com",
            "example.com/",
            "exa mple.com",
            "example..com",
            "a" * 64 + ".com",
            "1.2.3.4",
        ]
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    validate_domain(value)

    def test_rejects_domain_that_is_too_long(self):
        with self.assertRaises(ValidationError):
            validate_domain(".".join(["abcdefgh"] * 40) + ".com")

    def test_rejects_secrets_passed_as_domain(self):
        with self.assertRaises(ValidationError):
            validate_domain("vless://abc-123-uuid")


class IpTests(unittest.TestCase):
    def test_accepts_ipv4_and_ipv6(self):
        self.assertEqual(str(validate_ip("104.21.54.105")), "104.21.54.105")
        self.assertEqual(str(validate_ip("2606:4700::1111")), "2606:4700::1111")

    def test_rejects_invalid_addresses(self):
        for value in ("999.1.1.1", "1.2.3", "abc", "1.2.3.4/24", "", "104.21.54.105:8443"):
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    validate_ip(value)

    def test_enforces_requested_version(self):
        self.assertEqual(str(validate_ip("104.21.54.105", version=4)), "104.21.54.105")
        with self.assertRaises(ValidationError):
            validate_ip("104.21.54.105", version=6)
        with self.assertRaises(ValidationError):
            validate_ip("2606:4700::1111", version=4)


class PortTests(unittest.TestCase):
    def test_accepts_valid_ports(self):
        for value, expected in ((1, 1), ("443", 443), (65535, 65535), (" 8443 ", 8443)):
            with self.subTest(value=value):
                self.assertEqual(validate_port(value), expected)

    def test_rejects_invalid_ports(self):
        for value in (0, -1, 65536, "443a", "", "0x10", "1.5", None, "1 2"):
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    validate_port(value)


class NumberTests(unittest.TestCase):
    def test_validate_int_bounds(self):
        self.assertEqual(validate_int("4", minimum=1, maximum=1000, field="attempts"), 4)
        with self.assertRaises(ValidationError):
            validate_int("abc", minimum=1, maximum=1000, field="attempts")
        with self.assertRaises(ValidationError):
            validate_int("0", minimum=1, maximum=1000, field="attempts")
        with self.assertRaises(ValidationError):
            validate_int("1001", minimum=1, maximum=1000, field="attempts")
        with self.assertRaises(ValidationError):
            validate_int("", minimum=1, maximum=1000, field="attempts")

    def test_validate_float_bounds(self):
        self.assertAlmostEqual(
            validate_float("1.5", minimum=0.0, maximum=10.0, field="latency"), 1.5
        )
        with self.assertRaises(ValidationError):
            validate_float("abc", minimum=0.0, maximum=10.0, field="latency")

    def test_loss_accepts_fractions_and_percentages(self):
        self.assertAlmostEqual(validate_loss("0.25"), 0.25)
        self.assertAlmostEqual(validate_loss("25%"), 0.25)
        self.assertAlmostEqual(validate_loss("25"), 0.25)
        self.assertAlmostEqual(validate_loss("100%"), 1.0)
        self.assertAlmostEqual(validate_loss("0"), 0.0)
        self.assertAlmostEqual(validate_loss("1"), 1.0)

    def test_loss_rejects_out_of_range_and_garbage(self):
        for value in ("101%", "-5%", "abc", "", "1.5.2"):
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    validate_loss(value)


class HttpStatusTests(unittest.TestCase):
    def test_accepts_valid_status_codes(self):
        for value in (200, "400", 599):
            with self.subTest(value=value):
                self.assertEqual(validate_http_status(value), int(value))

    def test_rejects_invalid_status_codes(self):
        for value in (99, 600, "abc", "", 0):
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    validate_http_status(value)


class IpVersionTests(unittest.TestCase):
    def test_normalises_versions(self):
        for value in (4, "4", "ipv4", "IPv4", "v4"):
            with self.subTest(value=value):
                self.assertEqual(validate_ip_version(value), 4)
        for value in (6, "6", "ipv6", "IPv6", "v6"):
            with self.subTest(value=value):
                self.assertEqual(validate_ip_version(value), 6)

    def test_rejects_unknown_versions(self):
        for value in (5, "ipv7", "", None):
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    validate_ip_version(value)


class SchemeTests(unittest.TestCase):
    def test_accepts_known_schemes(self):
        self.assertEqual(validate_url_scheme("https"), "https")
        self.assertEqual(validate_url_scheme(" HTTP "), "http")

    def test_rejects_unknown_schemes(self):
        for value in ("ftp", "", "file", "javascript"):
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    validate_url_scheme(value)


class OutputFilenameTests(unittest.TestCase):
    def test_accepts_safe_names(self):
        for value in ("scan.csv", "my-scan_2.csv", "ok name.csv"):
            with self.subTest(value=value):
                self.assertEqual(validate_output_filename(value), value)

    def test_rejects_unsafe_paths(self):
        bad = [
            "../../etc/passwd.csv",
            "/etc/passwd",
            "sub/dir.csv",
            "..\\evil.csv",
            ".hidden.csv",
            "scan.txt",
            "",
            "bad\x00name.csv",
            "bad\nname.csv",
            "a.csv; rm -rf /",
            "x" * 200 + ".csv",
        ]
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    validate_output_filename(value)

    def test_accepts_an_uppercase_csv_suffix(self):
        # endswith() is case-insensitive here, so the strict pattern must agree.
        for value in ("Report.CSV", "scan.Csv"):
            with self.subTest(value=value):
                self.assertEqual(validate_output_filename(value), value)

    def test_rejects_shell_metacharacters(self):
        for value in ("a;b.csv", "a|b.csv", "$(whoami).csv", "`id`.csv", "a&b.csv"):
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    validate_output_filename(value)


class SecretTests(unittest.TestCase):
    def test_accepts_harmless_values(self):
        for value in ("gerr.yasin-ai-54.ir", "104.21.54.105", "my-profile", "", "8443"):
            with self.subTest(value=value):
                assert_no_secrets(value)

    def test_rejects_secrets(self):
        bad = [
            "b2f1a3c4-1111-2222-3333-444455556666",
            "b2f1a3c4-1111-2222-3333-44445555666",  # 31 hex chars + dashes
            "vless://user@host:443",
            "vmess://eyJ2IjoiMiJ9",
            "ss://YWVzOnBhc3M@host:443",
            "trojan://pass@host:443",
            "password=hunter2",
            "password: hunter2",
            "uuid=abcd",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "subscription: https://example.com/sub?token=abc",
        ]
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    assert_no_secrets(value)


if __name__ == "__main__":
    unittest.main()

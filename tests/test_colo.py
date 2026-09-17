"""The region filter: which Cloudflare datacentres a scan is allowed to keep.

Cloudflare answers from the datacentre nearest to the line, and which one that
is decides the latency far more than the address does. The filter is therefore
part of the search - and it only works where the scanner can actually read the
datacentre back, which is what most of these tests are about.
"""

from __future__ import annotations

import unittest

from cfscan.menu import custom_scan
from cfscan.runner import build_scan_argv, build_verify_argv, colo_problem
from cfscan.validate import MAX_COLO_CODES, ValidationError, validate_colo

from tests.support import Fixture


def _profile(**overrides):
    base = {
        "domain": "example.com", "port": 443, "mode": "httping",
        "scheme": "https", "url_path": "/", "http_status": 400,
        "ip_version": 4, "ip_file": "/tmp/ip.txt", "attempts": 4,
        "concurrency": 200, "max_latency_ms": 1000, "max_loss": 0.25,
        "results_limit": 20, "download_test": False, "colo": "",
    }
    base.update(overrides)
    return base


class ValidateColoTests(unittest.TestCase):
    def test_codes_are_upper_cased_and_joined(self):
        self.assertEqual(validate_colo(" fra , ams "), "FRA,AMS")
        self.assertEqual(validate_colo("fra ams lhr"), "FRA,AMS,LHR")

    def test_empty_and_the_words_for_empty_mean_no_filter(self):
        for value in ("", "   ", "any", "ALL", "none", "-", None):
            self.assertEqual(validate_colo(value), "")

    def test_duplicates_collapse(self):
        self.assertEqual(validate_colo("FRA,fra,AMS"), "FRA,AMS")

    def test_a_country_code_is_accepted(self):
        self.assertEqual(validate_colo("de"), "DE")

    def test_nonsense_is_refused_with_an_example(self):
        for value in ("Frankfurt", "FR4", "F", "FRA;AMS", "104.16.0.1"):
            with self.assertRaises(ValidationError) as caught:
                validate_colo(value)
            self.assertIn("region code", str(caught.exception))

    def test_a_filter_longer_than_a_person_reads_is_refused(self):
        with self.assertRaises(ValidationError):
            validate_colo(",".join(f"A{index:02d}" for index in
                                   range(MAX_COLO_CODES + 1)))


class ScanArgumentTests(unittest.TestCase):
    def test_the_filter_reaches_the_scanner(self):
        argv = build_scan_argv("/bin/cfst", _profile(colo="FRA,AMS"), "/tmp/o.csv")
        self.assertIn("-cfcolo", argv)
        self.assertEqual(argv[argv.index("-cfcolo") + 1], "FRA,AMS")

    def test_no_filter_means_no_flag(self):
        argv = build_scan_argv("/bin/cfst", _profile(), "/tmp/o.csv")
        self.assertNotIn("-cfcolo", argv)

    def test_tcping_never_carries_the_flag(self):
        argv = build_scan_argv("/bin/cfst", _profile(mode="tcp", colo="FRA"),
                               "/tmp/o.csv")
        self.assertNotIn("-cfcolo", argv)

    def test_verification_is_never_filtered(self):
        # Verification asks "does this exact address still answer". Filtering
        # there would report an address that moved to another datacentre as
        # dead instead of saying that it moved.
        argv = build_verify_argv("/bin/cfst", _profile(colo="FRA"), "104.16.0.1",
                                 "/tmp/o.csv")
        self.assertNotIn("-cfcolo", argv)


class ColoProblemTests(unittest.TestCase):
    def test_no_filter_is_never_a_problem(self):
        self.assertIsNone(colo_problem(_profile()))
        self.assertIsNone(colo_problem(_profile(mode="tcp")))

    def test_https_httping_is_the_combination_that_works(self):
        self.assertIsNone(colo_problem(_profile(colo="FRA")))

    def test_tcping_cannot_read_a_datacentre(self):
        problem = colo_problem(_profile(mode="tcp", colo="FRA"))
        self.assertIn("HTTPing", problem)

    def test_plain_http_on_an_https_port_cannot_either(self):
        # Measured with curl: that request makes the edge answer its own 400
        # with "CF-RAY: -", so no datacentre is ever reported.
        problem = colo_problem(_profile(scheme="http", colo="FRA"))
        self.assertIn("CF-RAY", problem)


class CustomScanColoTests(unittest.TestCase):
    ANSWERS = [
        "filtered",             # profile name
        "example.com",          # domain
        "443",                  # port
        "4",                    # IPv4
        "1",                    # HTTPing
        "1",                    # scheme https
        "400",                  # expected status
        "fra, ams",             # region filter
        "4", "200", "1000", "25%", "10",
        "n",                    # download test
        "filtered.csv",         # output filename
        "y",                    # save the profile
    ]

    def test_the_filter_is_asked_for_saved_and_used(self):
        fixture = Fixture(answers=self.ANSWERS, dry_run=True)
        self.addCleanup(fixture.close)
        custom_scan(fixture.session, fixture.config)
        self.assertEqual(fixture.reload()["profiles"]["filtered"]["colo"],
                         "FRA,AMS")
        self.assertIn("-cfcolo FRA,AMS", fixture.text)

    def test_switching_to_tcping_clears_a_filter_that_cannot_work(self):
        answers = list(self.ANSWERS)
        answers[4] = "2"            # TCPing: no scheme, status or filter prompt
        del answers[5:8]
        fixture = Fixture(answers=answers, dry_run=True)
        self.addCleanup(fixture.close)
        fixture.profile()["colo"] = "FRA"
        custom_scan(fixture.session, fixture.config)
        self.assertEqual(fixture.reload()["profiles"]["filtered"]["colo"], "")
        self.assertIn("region filter was cleared", fixture.text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

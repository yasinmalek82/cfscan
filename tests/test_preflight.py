"""Tests for the one-address preflight and the explanations it prints.

A profile that cannot work - HTTPS on a port that only speaks plain HTTP, a
hostname Cloudflare does not serve, an origin that is down - used to be
discovered only after the scanner had measured every address in the range and
reported "no result". These tests pin the replacement: one address is measured
first and the scanner log is translated into the reason.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from cfscan.menu import EXIT_FAILED, preflight_probe, quick_scan
from cfscan.profiles import default_profile
from cfscan.runner import (
    CLOUDFLARE_HTTPS_PORTS,
    build_probe_argv,
    certificate_depth_hint,
    explain_failure,
    scheme_port_problem,
)

from tests.support import (
    FIXTURE_DOMAIN,
    FIXTURE_PORT,
    CSV_TWO_ROWS,
    LOG_HTTPS_ON_HTTP_PORT,
    LOG_NO_RESULTS,
    LOG_ORIGIN_UNREACHABLE,
    LOG_SUCCESS,
    Fixture,
    ScriptedSpawn,
)

CFST = "/opt/homebrew/bin/cfst"


def profile_with(**overrides):
    """The built in profile, given a target, with a few values replaced.

    The shipped default is a placeholder that scans refuse to run against, so
    these tests supply their own domain the way a set-up profile would.
    """
    profile = default_profile()
    profile.update(domain=FIXTURE_DOMAIN, port=FIXTURE_PORT)
    profile.update(overrides)
    return profile


class SchemePortProblemTests(unittest.TestCase):
    """The static check that catches the silent whole-scan failure."""

    def test_https_on_a_plain_http_port_is_explained(self):
        message = scheme_port_problem(profile_with(port=8080, scheme="https"))
        self.assertIn("8080", message)
        self.assertIn("plain-HTTP", message)
        self.assertIn("server gave HTTP response to HTTPS client", message)
        self.assertIn("scheme=http", message)

    def test_https_on_a_cloudflare_https_port_is_fine(self):
        for port in CLOUDFLARE_HTTPS_PORTS:
            self.assertIsNone(
                scheme_port_problem(profile_with(port=port, scheme="https")),
                f"port {port} does not speak HTTPS on the Cloudflare edge",
            )

    def test_plain_http_on_an_https_port_is_left_alone(self):
        # This is the documented origin-independent probe: Cloudflare answers
        # 400 itself, which is a legitimate way to find reachable addresses.
        self.assertIsNone(scheme_port_problem(profile_with(port=443, scheme="http")))
        self.assertIsNone(scheme_port_problem(profile_with(port=2087, scheme="http")))

    def test_tcp_mode_has_no_scheme_at_all(self):
        self.assertIsNone(
            scheme_port_problem(profile_with(port=8080, scheme="https", mode="tcp"))
        )


class ProbeArgumentTests(unittest.TestCase):
    def test_the_probe_measures_one_address_with_debug(self):
        argv = build_probe_argv(CFST, profile_with(port=2087, scheme="https"),
                                "104.16.0.1", "/tmp/probe.csv")
        self.assertEqual(argv[0], CFST)
        self.assertEqual(argv[argv.index("-ip") + 1], "104.16.0.1")
        self.assertNotIn("-f", argv)
        self.assertEqual(argv[argv.index("-t") + 1], "2")
        self.assertEqual(argv[argv.index("-p") + 1], "1")
        self.assertEqual(argv[argv.index("-tp") + 1], "2087")
        self.assertEqual(argv[argv.index("-url") + 1],
                         "https://node.example.test:2087/")
        self.assertIn("-debug", argv)
        self.assertIn("-dd", argv)


class ExplainFailureTests(unittest.TestCase):
    """The scanner's log turned into the reason a profile cannot work."""

    def test_a_plain_http_port_is_named(self):
        hints = explain_failure(LOG_HTTPS_ON_HTTP_PORT,
                                profile_with(port=8080, scheme="https"),
                                "104.24.28.30")
        self.assertEqual(1, len(hints))
        self.assertIn("8080", hints[0])
        self.assertIn("scheme=http", hints[0])

    def test_cloudflares_own_error_page_is_explained(self):
        hints = explain_failure(LOG_ORIGIN_UNREACHABLE,
                                profile_with(port=443, scheme="https"),
                                "104.24.28.30")
        self.assertTrue(hints)
        self.assertIn("521", hints[0])
        self.assertIn("not proxied", hints[0])
        self.assertIn("104.24.28.30", hints[0])

    def test_a_different_status_says_what_to_change(self):
        log = ("IP: 104.24.28.30, 延迟测速终止，HTTP 状态码: 301, "
               "指定的 HTTP 状态码 400, 测速地址: https://x.example:443/\n")
        hints = explain_failure(log, profile_with(port=443, scheme="https"))
        self.assertTrue(hints)
        self.assertIn("301", hints[0])

    def test_an_unrecognized_log_produces_no_hint(self):
        self.assertEqual([], explain_failure("nothing familiar here",
                                             profile_with()))

    def test_an_empty_log_produces_no_hint(self):
        self.assertEqual([], explain_failure("", profile_with()))


class PreflightFlowTests(unittest.TestCase):
    def make_fixture(self, spawn, answers=(), preflight=True, tty=False):
        fixture = Fixture(answers=answers, spawn=spawn, preflight=preflight,
                          tty=tty)
        self.addCleanup(fixture.close)
        fixture.session.verify_top_ips = False
        return fixture

    def test_a_passing_probe_lets_the_scan_run(self):
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=CSV_TWO_ROWS)
        fixture = self.make_fixture(spawn)
        fixture.session.assume_yes = True

        code = quick_scan(fixture.session, fixture.config, verify_prompt=False)

        self.assertEqual(code, 0)
        self.assertEqual(2, len(spawn.calls))
        self.assertIn("-ip", spawn.calls[0])
        self.assertIn("-f", spawn.calls[1])
        self.assertIn("Preflight passed", fixture.text)

    def test_a_passing_probe_leaves_no_result_file_behind(self):
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=CSV_TWO_ROWS)
        fixture = self.make_fixture(spawn)
        fixture.session.assume_yes = True

        quick_scan(fixture.session, fixture.config, verify_prompt=False)

        leftovers = list(Path(fixture.paths.results_dir).glob("*preflight*.csv"))
        self.assertEqual([], leftovers)

    def test_a_failed_probe_explains_why_and_still_scans_when_not_interactive(self):
        # Three Cloudflare addresses are tried for the probe, then the scan the
        # user asked for anyway.
        spawn = ScriptedSpawn(
            log_sequence=[LOG_HTTPS_ON_HTTP_PORT] * 3 + [LOG_NO_RESULTS],
            csv_sequence=[None, None, None, None],
        )
        # A plain-HTTP profile would have reached the edge check first; this one
        # is the https-on-an-HTTP-port kind, which fails before that.
        fixture = self.make_fixture(spawn)
        fixture.session.assume_yes = True
        fixture.config["profiles"]["england"] = profile_with(
            name="node.example.test", domain="node.example.test",
            port=8080, scheme="https",
        )
        fixture.config["profiles"]["england"]["ip_file"] = str(fixture.ipv4)
        fixture.config["active_profile"] = "england"

        code = quick_scan(fixture.session, fixture.config, verify_prompt=False)

        text = fixture.text
        self.assertTrue(text.count("Preflight") >= 1)
        self.assertIn("Why this profile cannot work", text)
        self.assertIn("8080", text)
        self.assertIn("plain-HTTP", text)
        # The scan still ran, because the user asked for it.
        self.assertEqual(4, len(spawn.calls))
        self.assertEqual(EXIT_FAILED, code)

    def test_an_interactive_user_can_stop_after_a_failed_probe(self):
        spawn = ScriptedSpawn(
            log_sequence=[LOG_HTTPS_ON_HTTP_PORT] * 3,
            csv_sequence=[None, None, None],
        )
        # Enter confirms "Run this scan now?", then "n" refuses the range scan.
        fixture = self.make_fixture(spawn, answers=["", "n"], tty=True)
        fixture.config["profiles"]["england"] = profile_with(
            name="node.example.test", domain="node.example.test",
            port=8080, scheme="https",
        )
        fixture.config["profiles"]["england"]["ip_file"] = str(fixture.ipv4)
        fixture.config["active_profile"] = "england"

        code = quick_scan(fixture.session, fixture.config, verify_prompt=False)

        self.assertEqual(EXIT_FAILED, code)
        # Only the three probes ran: the range scan never started.
        self.assertEqual(3, len(spawn.calls))
        for call in spawn.calls:
            self.assertIn("-ip", call)
        self.assertIn("Cancelled - nothing was executed.", fixture.text)

    def test_the_probe_can_be_switched_off(self):
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=CSV_TWO_ROWS)
        fixture = self.make_fixture(spawn, preflight=False)
        fixture.session.assume_yes = True

        quick_scan(fixture.session, fixture.config, verify_prompt=False)

        self.assertEqual(1, len(spawn.calls))
        self.assertIn("-f", spawn.calls[0])
        self.assertNotIn("Preflight", fixture.text)

    def test_the_probe_returns_true_when_switched_off(self):
        fixture = self.make_fixture(ScriptedSpawn(), preflight=False)
        self.assertTrue(preflight_probe(fixture.session, fixture.config,
                                        "example", fixture.profile()))

    def test_the_probe_is_skipped_for_a_dry_run(self):
        spawn = ScriptedSpawn()
        fixture = self.make_fixture(spawn)
        fixture.session.dry_run = True
        self.assertTrue(preflight_probe(fixture.session, fixture.config,
                                        "example", fixture.profile()))
        self.assertEqual([], spawn.calls)


class EdgeStatusTests(unittest.TestCase):
    """An origin-independent probe measures the edge, not the node behind it."""

    def make_fixture(self, spawn, profile, answers=()):
        fixture = Fixture(answers=answers, spawn=spawn, preflight=True)
        self.addCleanup(fixture.close)
        fixture.session.verify_top_ips = False
        fixture.session.assume_yes = True
        fixture.config["profiles"]["england"] = dict(profile)
        fixture.config["profiles"]["england"]["ip_file"] = str(fixture.ipv4)
        fixture.config["active_profile"] = "england"
        return fixture

    def edge_profile(self):
        # Exactly the working recipe: plain HTTP on 443, where Cloudflare itself
        # answers 400 (verified against the live edge).
        return profile_with(name="node.example.test",
                            domain="node.example.test",
                            port=443, scheme="http", http_status=400)

    def test_the_edge_probe_is_recognised(self):
        from cfscan.menu import _is_origin_independent_probe

        self.assertTrue(_is_origin_independent_probe(profile_with(port=443,
                                                                 scheme="http")))
        self.assertTrue(_is_origin_independent_probe(profile_with(port=2087,
                                                                 scheme="http")))
        self.assertFalse(_is_origin_independent_probe(profile_with(port=443,
                                                                  scheme="https")))
        # 80 and 8080 are plain-HTTP ports at the edge: no trick involved.
        self.assertFalse(_is_origin_independent_probe(profile_with(port=8080,
                                                                  scheme="http")))

    def test_an_edge_5xx_is_reported_next_to_the_results(self):
        spawn = ScriptedSpawn(
            log_sequence=[LOG_SUCCESS, LOG_ORIGIN_UNREACHABLE, LOG_SUCCESS],
            csv_sequence=[CSV_TWO_ROWS, None, CSV_TWO_ROWS],
        )
        fixture = self.make_fixture(spawn, self.edge_profile())

        quick_scan(fixture.session, fixture.config, verify_prompt=False)

        text = fixture.text
        self.assertIn("Preflight passed", text)
        self.assertIn("Cloudflare answered 521", text)
        self.assertIn("Origin Rule", text)
        # The copy-paste block must not promise a working client either.
        self.assertIn("plain-HTTP probe", text)
        # The third call is the real scan, with the profile's plain HTTP URL.
        self.assertEqual(
            "http://node.example.test:443/",
            spawn.calls[2][spawn.calls[2].index("-url") + 1],
        )
        self.assertEqual("599", spawn.calls[1][spawn.calls[1].index("-httping-code") + 1])
        self.assertIn("https://node.example.test:443/",
                      spawn.calls[1][spawn.calls[1].index("-url") + 1])

    def test_a_served_hostname_is_reported_as_good_news(self):
        served = ("IP: 104.24.28.30, 延迟测速终止，HTTP 状态码: 404, "
                  "指定的 HTTP 状态码 599, 测速地址: https://node.example.test:443/\n")
        spawn = ScriptedSpawn(
            log_sequence=[LOG_SUCCESS, served, LOG_SUCCESS],
            csv_sequence=[CSV_TWO_ROWS, None, CSV_TWO_ROWS],
        )
        fixture = self.make_fixture(spawn, self.edge_profile())

        quick_scan(fixture.session, fixture.config, verify_prompt=False)

        self.assertIn("The edge reached a server", fixture.text)
        self.assertIn("HTTP 404", fixture.text)

    def test_a_tls_profile_runs_no_extra_check(self):
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=CSV_TWO_ROWS)
        fixture = self.make_fixture(
            spawn, profile_with(name="node", domain="node.example.test",
                                port=443, scheme="https", http_status=400))

        quick_scan(fixture.session, fixture.config, verify_prompt=False)

        # Probe and scan only: the profile measures the origin by itself.
        self.assertEqual(2, len(spawn.calls))
        self.assertNotIn("Edge check", fixture.text)


class CertificateDepthHintTests(unittest.TestCase):
    def test_a_name_more_than_one_level_deep_gets_the_hint(self):
        hint = certificate_depth_hint("ws.node.example.test")
        self.assertIn("one level below its zone", hint)
        # It must name the parent, because that is what the certificate covers,
        # and point openssl at the zone, which is where the certificate lives.
        self.assertIn("covers node.example.test", hint)
        self.assertIn("-servername example.test", hint)

    def test_a_name_one_level_deep_gets_nothing(self):
        # *.zone covers exactly one label, so these are fine.
        self.assertIsNone(certificate_depth_hint("edge.example.test"))
        self.assertIsNone(certificate_depth_hint("node.example.test"))

    def test_an_apex_or_a_nonsense_value_gets_nothing(self):
        for value in ("example.test", "", None, "localhost"):
            self.assertIsNone(certificate_depth_hint(value))

    def test_it_never_claims_certainty(self):
        # co.ir and ac.ir exist and there is no public suffix list here, so four
        # labels is a strong signal and not a proof.
        self.assertIn("usual reason", certificate_depth_hint("a.b.example.com"))


class MissingCertificateTests(unittest.TestCase):
    """Telling "the edge has no certificate for this name" from "it is down".

    The scanner cannot tell them apart: its Go client wraps the TLS alert in its
    own timeout, so a hostname the edge refuses TLS for is reported as
    "context deadline exceeded" - exactly what a dead address reports (measured
    against a hostname whose handshake curl showed failing instantly). So the
    question is asked a second way, with a probe that needs no certificate.
    """

    @staticmethod
    def flat(text):
        """The output with its wrapping removed, so assertions survive it."""
        return " ".join(str(text).split())

    def make_fixture(self, spawn, answers=(), tty=False):
        fixture = Fixture(answers=answers, spawn=spawn, preflight=True, tty=tty)
        self.addCleanup(fixture.close)
        fixture.session.verify_top_ips = False
        profile = fixture.profile()
        profile["domain"] = "ws.node.example.test"
        profile["port"] = 443
        profile["scheme"] = "https"
        return fixture

    def timing_out_then_answering(self):
        """Every TLS probe times out; the plain-HTTP probe answers."""
        return ScriptedSpawn(
            log_text=LOG_NO_RESULTS,
            csv_sequence=[None, None, None, CSV_TWO_ROWS],
        )

    def test_the_certificate_is_named_as_the_problem(self):
        fixture = self.make_fixture(self.timing_out_then_answering())
        fixture.session.assume_yes = True
        profile = fixture.profile()

        went_ahead = preflight_probe(fixture.session, fixture.config,
                                     fixture.config["active_profile"], profile)

        text = fixture.text
        self.assertFalse(went_ahead)
        self.assertIn("refuses TLS", self.flat(text))
        self.assertIn("certificate problem, not an address problem",
                      self.flat(text))
        self.assertIn("No clean IP can fix it", self.flat(text))

    def test_the_depth_hint_is_included_for_a_deep_name(self):
        fixture = self.make_fixture(self.timing_out_then_answering())
        fixture.session.assume_yes = True
        preflight_probe(fixture.session, fixture.config,
                        fixture.config["active_profile"], fixture.profile())
        self.assertIn("one level below its zone", self.flat(fixture.text))

    def test_switching_scheme_is_not_offered_as_a_fix(self):
        # It makes the scan produce rows while the client still cannot connect.
        fixture = self.make_fixture(self.timing_out_then_answering())
        fixture.session.assume_yes = True
        preflight_probe(fixture.session, fixture.config,
                        fixture.config["active_profile"], fixture.profile())
        self.assertIn("would not fix anything", self.flat(fixture.text))

    def test_the_check_leaves_no_files_behind(self):
        fixture = self.make_fixture(self.timing_out_then_answering())
        fixture.session.assume_yes = True
        preflight_probe(fixture.session, fixture.config,
                        fixture.config["active_profile"], fixture.profile())
        left = sorted(item.name for item in
                      Path(fixture.paths.results_dir).glob("*tlscheck*"))
        self.assertEqual(left, [])

    def test_an_address_problem_is_still_reported_as_one(self):
        # Nothing answers, not even the probe that needs no certificate.
        spawn = ScriptedSpawn(log_text=LOG_ORIGIN_UNREACHABLE, create_csv=False)
        fixture = self.make_fixture(spawn)
        fixture.session.assume_yes = True

        preflight_probe(fixture.session, fixture.config,
                        fixture.config["active_profile"], fixture.profile())

        text = fixture.text
        self.assertNotIn("certificate problem", self.flat(text))
        self.assertIn("Why this profile cannot work", self.flat(text))

    def test_a_working_profile_never_runs_the_extra_check(self):
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=CSV_TWO_ROWS)
        fixture = self.make_fixture(spawn)
        fixture.session.assume_yes = True

        preflight_probe(fixture.session, fixture.config,
                        fixture.config["active_profile"], fixture.profile())

        self.assertEqual(len(spawn.calls), 1)
        self.assertNotIn("without TLS", fixture.text)


class ProfileRenderingTests(unittest.TestCase):
    """The mismatch is visible before anything runs."""

    def test_the_profile_view_warns_about_the_port(self):
        from cfscan.menu import _render_profile

        fixture = Fixture()
        self.addCleanup(fixture.close)
        _render_profile(fixture.console, "england",
                        profile_with(port=8080, scheme="https"))
        self.assertIn("plain-HTTP", fixture.text)

    def test_the_profile_view_is_quiet_when_the_port_matches(self):
        from cfscan.menu import _render_profile

        fixture = Fixture()
        self.addCleanup(fixture.close)
        _render_profile(fixture.console, "gerr", profile_with(port=2087,
                                                             scheme="https"))
        self.assertNotIn("plain-HTTP", fixture.text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

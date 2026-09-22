"""Tests for the command line interface."""

from __future__ import annotations

import os
import unittest
from unittest import mock

from cfscan import __version__
from cfscan.cli import main, source_note

from tests.support import CSV_TWO_ROWS, LOG_SUCCESS, Fixture, ScriptedSpawn


def cfscan_cli_file():
    from cfscan import cli

    return cli.__file__


def run(fixture, argv):
    return main(
        argv,
        paths=fixture.paths,
        console=fixture.console,
        spawn=fixture.spawn,
    )


class VersionAndHelpTests(unittest.TestCase):
    def test_version_flag(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        self.assertEqual(run(fixture, ["--version"]), 0)
        self.assertIn(__version__, fixture.text)

    def test_version_flag_names_the_folder_it_runs_from(self):
        # "Is my edit live?" must be answerable from the output, not guessed.
        fixture = Fixture()
        self.addCleanup(fixture.close)
        self.assertEqual(run(fixture, ["--version"]), 0)
        self.assertIn(os.path.dirname(os.path.abspath(cfscan_cli_file())),
                      fixture.text)

    def test_source_note_reports_a_dev_link_only_for_this_package(self):
        package_dir = os.path.dirname(os.path.abspath(cfscan_cli_file()))
        project_dir = os.path.dirname(package_dir)
        with mock.patch.dict(os.environ, {"CFSCAN_DEV_SOURCE": project_dir}):
            self.assertTrue(source_note().startswith("dev link:"))
        # A stale variable pointing somewhere else must not claim a dev link.
        with mock.patch.dict(os.environ, {"CFSCAN_DEV_SOURCE": "/nowhere"}):
            self.assertTrue(source_note().startswith("installed:"))
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(source_note().startswith("installed:"))

    def test_help_flag_documents_options(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        self.assertEqual(run(fixture, ["--help"]), 0)
        text = fixture.text
        for option in ("--quick", "--verify", "--profile", "--dry-run", "--no-color",
                       "--version"):
            self.assertIn(option, text)

    def test_help_never_touches_the_scanner(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        run(fixture, ["--help"])
        self.assertEqual(fixture.spawn.calls, [])


class QuickScanCliTests(unittest.TestCase):
    def test_download_flag_plans_a_second_pass_and_keeps_latency_on_dd(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        code = run(fixture, ["--quick", "--dry-run", "--download"])
        self.assertEqual(code, 0)
        text = fixture.text
        self.assertIn("-dd", text)
        self.assertIn("https://speed.cloudflare.com/__down?bytes=50000000", text)
        self.assertIn("-dn", text)
        self.assertIn("-dt", text)
        self.assertEqual(fixture.spawn.calls, [])

    def test_no_jitter_is_a_one_run_switch(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        code = run(fixture, ["--quick", "--dry-run", "--no-jitter"])
        self.assertEqual(code, 0)
        self.assertIn("Jitter: off", fixture.text)
        # The saved profile is not rewritten by a one-run flag.
        self.assertTrue(fixture.reload()["profiles"][
            fixture.config["active_profile"]]["jitter_test"])

    def test_download_and_no_download_together_are_refused(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        code = run(fixture, ["--download", "--no-download"])
        self.assertEqual(code, 2)
        self.assertIn("only one", fixture.text.lower())

    def test_quick_dry_run_prints_default_argv(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        code = run(fixture, ["--quick", "--dry-run"])
        self.assertEqual(code, 0)
        self.assertEqual(fixture.spawn.calls, [])
        text = fixture.text
        self.assertIn("-httping", text)
        self.assertIn("-tp 2087", text)
        self.assertIn("-httping-code 400", text)

    def test_quick_scan_can_run_with_injection(self):
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=CSV_TWO_ROWS)
        fixture = Fixture(spawn=spawn)
        self.addCleanup(fixture.close)
        code = run(fixture, ["--quick", "--yes", "--no-verify-top",
                             "--no-preflight"])
        self.assertEqual(code, 0)
        self.assertEqual(len(spawn.calls), 1)

    def test_quick_scan_without_yes_asks_for_confirmation(self):
        fixture = Fixture(answers=["n"])
        self.addCleanup(fixture.close)
        code = run(fixture, ["--quick"])
        self.assertEqual(code, 0)
        self.assertEqual(fixture.spawn.calls, [])

    def test_missing_scanner_binary_exit_code(self):
        fixture = Fixture(spawn=ScriptedSpawn(error=FileNotFoundError("nope")))
        self.addCleanup(fixture.close)
        self.assertEqual(run(fixture, ["--quick", "--yes"]), 3)


class ProfileCliTests(unittest.TestCase):
    def test_profile_selection_is_used_for_the_run(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.config["profiles"]["office"] = dict(fixture.profile())
        fixture.config["profiles"]["office"]["port"] = 2096
        from cfscan.profiles import save_config

        save_config(fixture.paths, fixture.config)

        code = run(fixture, ["--quick", "--dry-run", "--profile", "office"])
        self.assertEqual(code, 0)
        self.assertIn("-tp 2096", fixture.text)

    def test_unknown_profile_lists_available_names(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        code = run(fixture, ["--quick", "--profile", "ghost"])
        self.assertEqual(code, 2)
        self.assertIn("example", fixture.text)

    def test_show_profiles_flag(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        code = run(fixture, ["--list-profiles"])
        self.assertEqual(code, 0)
        self.assertIn("example", fixture.text)

    def test_profile_flag_switches_the_menu_session(self):
        fixture = Fixture(answers=["0"])
        self.addCleanup(fixture.close)
        fixture.config["profiles"]["office"] = dict(fixture.profile())
        fixture.config["profiles"]["office"]["domain"] = "office.example.com"
        fixture.save()
        code = run(fixture, ["--profile", "office"])
        self.assertEqual(code, 0)
        text = fixture.text
        self.assertIn("Using profile 'office' for this session", text)
        self.assertRegex(text, r"Profile\s+office")


class AutoVerifyCliTests(unittest.TestCase):
    def test_quick_scan_verifies_the_best_addresses_by_default(self):
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=CSV_TWO_ROWS)
        fixture = Fixture(spawn=spawn)
        self.addCleanup(fixture.close)
        self.assertEqual(run(fixture, ["--quick", "--yes", "--no-preflight"]), 0)
        self.assertEqual(len(spawn.calls), 2)
        self.assertIn("Verifying the best 2 addresses", fixture.text)

    def test_no_verify_top_skips_that_run(self):
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=CSV_TWO_ROWS)
        fixture = Fixture(spawn=spawn)
        self.addCleanup(fixture.close)
        self.assertEqual(run(fixture, ["--quick", "--yes", "--no-verify-top",
                                       "--no-preflight"]), 0)
        self.assertEqual(len(spawn.calls), 1)
        self.assertNotIn("Verifying the best", fixture.text)


class ScannerErrorCliTests(unittest.TestCase):
    """A scanner that cannot start is a friendly error, never a traceback."""

    def test_scanner_error_is_reported_not_raised(self):
        fixture = Fixture(spawn=ScriptedSpawn(error=OSError("Exec format error")))
        self.addCleanup(fixture.close)
        self.assertEqual(run(fixture, ["--quick", "--yes"]), 1)
        self.assertIn("could not be started", fixture.text)


class VerifyCliTests(unittest.TestCase):
    def test_verify_dry_run_prints_argv(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        code = run(fixture, ["--verify", "104.16.0.1", "--dry-run"])
        self.assertEqual(code, 0)
        self.assertEqual(fixture.spawn.calls, [])
        text = fixture.text
        self.assertIn("-ip 104.16.0.1", text)
        self.assertIn("-t 20", text)

    def test_verify_rejects_invalid_ip(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        self.assertEqual(run(fixture, ["--verify", "not-an-ip"]), 2)
        self.assertEqual(fixture.spawn.calls, [])

    def test_verify_returns_failure_code(self):
        fixture = Fixture(spawn=ScriptedSpawn(log_text="", create_csv=False))
        self.addCleanup(fixture.close)
        self.assertEqual(run(fixture, ["--verify", "104.16.0.1"]), 1)


class ColourTests(unittest.TestCase):
    def test_no_color_flag_removes_escapes(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        run(fixture, ["--no-color", "--quick", "--dry-run"])
        self.assertNotIn("\x1b[", fixture.text)

    def test_menu_respects_no_color(self):
        fixture = Fixture(answers=["0"])
        self.addCleanup(fixture.close)
        run(fixture, ["--no-color"])
        self.assertNotIn("\x1b[", fixture.text)


class ShowLastCliTests(unittest.TestCase):
    def test_show_last_before_any_scan(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        code = run(fixture, ["--show-last"])
        self.assertEqual(code, 0)
        self.assertIn("No saved results", fixture.text)


if __name__ == "__main__":
    unittest.main()

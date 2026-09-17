"""Tests for the paths a debug pass found were reachable but never run.

Everything here is something a real user can hit without touching the tests:
a configuration file ruined by hand editing, a result pointer left behind by
an old scan, an empty result file, a carrier round that verified nothing, and
the module entry point ``python3 -m cfscan``.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cfscan import __version__
from cfscan import multisip
from cfscan.cli import EXIT_OK, EXIT_USAGE, main
from cfscan.parser import parse_csv_text, parse_results_csv, rank_results, recommend
from cfscan.profiles import (
    CONFIG_VERSION,
    DEFAULT_PORT,
    DEFAULT_PROFILE_KEY,
    UnknownProfile,
    get_active,
    load_config,
    save_config,
)
from cfscan.results import ResultStore, open_in_finder

from tests.support import make_console, make_paths


class TempHome(unittest.TestCase):
    """A throw-away home directory, so no real configuration is touched."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.paths = make_paths(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def write_raw_config(self, text):
        path = Path(self.paths.config_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def write_config(self, payload):
        return self.write_raw_config(json.dumps(payload, indent=2))


class CorruptConfigTests(TempHome):
    """A broken config file must never lock the user out of the tool."""

    def test_invalid_json_is_backed_up_and_replaced(self):
        original = "{ this is not json"
        path = self.write_raw_config(original)

        config = load_config(self.paths)

        self.assertIn(DEFAULT_PROFILE_KEY, config["profiles"])
        self.assertEqual(config["active_profile"], DEFAULT_PROFILE_KEY)
        self.assertEqual(config["version"], CONFIG_VERSION)
        backup = Path(str(path) + ".corrupt-1")
        self.assertTrue(backup.exists(), "the damaged file should be kept")
        self.assertEqual(backup.read_text(encoding="utf-8"), original)
        # The replacement on disk is valid JSON again.
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["profiles"].keys(),
                         config["profiles"].keys())

    def test_a_second_corruption_does_not_overwrite_the_first_backup(self):
        path = self.write_raw_config("{ broken once")
        load_config(self.paths)
        self.write_raw_config("{ broken twice")

        load_config(self.paths)

        self.assertEqual(Path(str(path) + ".corrupt-1").read_text(encoding="utf-8"),
                         "{ broken once")
        self.assertEqual(Path(str(path) + ".corrupt-2").read_text(encoding="utf-8"),
                         "{ broken twice")

    def test_a_json_document_that_is_not_an_object_is_repaired(self):
        path = self.write_raw_config('["profiles", "active_profile"]')

        config = load_config(self.paths)

        self.assertIsInstance(config, dict)
        self.assertIn(DEFAULT_PROFILE_KEY, config["profiles"])
        self.assertTrue(Path(str(path) + ".corrupt-1").exists())

    def test_an_empty_file_is_not_treated_as_corruption(self):
        path = self.write_raw_config("")

        config = load_config(self.paths)

        self.assertIn(DEFAULT_PROFILE_KEY, config["profiles"])
        self.assertFalse(Path(str(path) + ".corrupt-1").exists())


class HandEditedProfileTests(TempHome):
    """Values a user can edit by hand must be repaired, not trusted."""

    def test_junk_values_fall_back_to_defaults(self):
        self.write_config({
            "version": CONFIG_VERSION,
            "active_profile": "mine",
            "profiles": {
                "mine": {"domain": "example.com", "port": "not-a-port",
                         "ip_version": "9", "mode": "carrier-pigeon",
                         "scheme": "ftp"},
                DEFAULT_PROFILE_KEY: {},
            },
        })

        profile = load_config(self.paths)["profiles"]["mine"]

        self.assertEqual(profile["port"], DEFAULT_PORT)
        self.assertEqual(profile["ip_version"], 4)
        self.assertEqual(profile["mode"], "httping")
        self.assertEqual(profile["scheme"], "https")
        self.assertEqual(profile["domain"], "example.com")

    def test_a_numeric_string_port_and_version_are_kept(self):
        self.write_config({
            "profiles": {
                "mine": {"domain": "example.com", "port": "8443", "ip_version": "6",
                         "mode": "tcp", "scheme": "http"},
            },
        })

        profile = load_config(self.paths)["profiles"]["mine"]

        self.assertEqual(profile["port"], 8443)
        self.assertEqual(profile["ip_version"], 6)
        self.assertEqual(profile["mode"], "tcp")
        self.assertEqual(profile["scheme"], "http")

    def test_a_profile_that_is_not_an_object_is_dropped(self):
        self.write_config({
            "profiles": {"broken": "just a string", "empty": None},
            "active_profile": "broken",
        })

        config = load_config(self.paths)

        self.assertNotIn("broken", config["profiles"])
        self.assertNotIn("empty", config["profiles"])
        self.assertEqual(config["active_profile"], DEFAULT_PROFILE_KEY)

    def test_a_profiles_key_that_is_not_an_object_is_replaced(self):
        self.write_config({"profiles": ["not", "a", "mapping"]})

        config = load_config(self.paths)

        self.assertIn(DEFAULT_PROFILE_KEY, config["profiles"])

    def test_an_active_profile_that_vanished_falls_back_to_the_default(self):
        self.write_config({
            "profiles": {DEFAULT_PROFILE_KEY: {}},
            "active_profile": "deleted-yesterday",
        })

        config = load_config(self.paths)

        self.assertEqual(config["active_profile"], DEFAULT_PROFILE_KEY)
        self.assertEqual(get_active(config)[0], DEFAULT_PROFILE_KEY)

    def test_get_active_reports_a_missing_active_profile(self):
        """Only reachable with a config built in memory, but it must not crash."""
        with self.assertRaises(UnknownProfile) as caught:
            get_active({"active_profile": "ghost", "profiles": {"real": {}}})

        message = str(caught.exception)
        self.assertIn("ghost", message)
        self.assertIn("real", message)

    def test_the_no_argument_message_still_reads_as_a_sentence(self):
        self.assertEqual(str(UnknownProfile()), "That profile does not exist.")

    def test_saving_leaves_no_temporary_files_behind(self):
        config = load_config(self.paths)
        config["profiles"]["mine"] = dict(config["profiles"][DEFAULT_PROFILE_KEY])

        save_config(self.paths, config)

        directory = Path(self.paths.config_file).parent
        leftovers = [item.name for item in directory.iterdir()
                     if item.name != Path(self.paths.config_file).name]
        self.assertEqual(leftovers, [])
        self.assertIn("mine", json.loads(
            Path(self.paths.config_file).read_text(encoding="utf-8"))["profiles"])


class StaleResultPointerTests(TempHome):
    """A pointer to a result the user moved or deleted must not break the menu."""

    def setUp(self):
        super().setUp()
        self.store = ResultStore(self.paths)

    def make_result(self, name, mtime):
        path = Path(self.paths.results_dir)
        path.mkdir(parents=True, exist_ok=True)
        item = path / name
        item.write_text("IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码\r\n",
                        encoding="utf-8")
        os.utime(item, (mtime, mtime))
        return item

    def test_pointer_to_a_deleted_file_falls_back_to_the_newest_csv(self):
        self.make_result("cfscan-old-20260901-000000.csv", 1_700_000_000)
        newest = self.make_result("cfscan-new-20260902-000000.csv", 1_700_100_000)
        config = {"last_result": {"csv": str(self.root / "gone.csv")}}

        self.assertEqual(self.store.latest(config), newest)

    def test_no_results_at_all_returns_nothing(self):
        self.assertIsNone(self.store.latest({"last_result": {"csv": "/nope.csv"}}))

    def test_a_live_pointer_wins_over_the_directory(self):
        older = self.make_result("cfscan-a-20260901-000000.csv", 1_700_000_000)
        self.make_result("cfscan-b-20260902-000000.csv", 1_700_100_000)
        config = {"last_result": {"csv": str(older)}}

        self.assertEqual(self.store.latest(config), older)

    def test_named_csv_never_overwrites_and_handles_missing_extension(self):
        first = self.store.named_csv("my list")
        self.assertEqual(first.name, "my list")
        first.write_text("mine", encoding="utf-8")

        second = self.store.named_csv("my list")
        third = self.store.named_csv("my list.csv")
        third.write_text("mine too", encoding="utf-8")
        fourth = self.store.named_csv("my list.csv")

        self.assertNotEqual(second, first)
        self.assertEqual(second.name, "my list-2")
        self.assertEqual(third.name, "my list.csv")
        self.assertEqual(fourth.name, "my list-2.csv")
        self.assertEqual(first.read_text(encoding="utf-8"), "mine")

    def test_open_in_finder_is_false_when_the_tool_is_missing(self):
        with mock.patch("cfscan.results.subprocess.run",
                        side_effect=FileNotFoundError("no open here")):
            self.assertFalse(open_in_finder(Path("/tmp")))

    def test_open_in_finder_reports_the_exit_status(self):
        completed = mock.Mock(returncode=0)
        with mock.patch("cfscan.results.subprocess.run", return_value=completed):
            self.assertTrue(open_in_finder(Path("/tmp")))
        completed.returncode = 1
        with mock.patch("cfscan.results.subprocess.run", return_value=completed):
            self.assertFalse(open_in_finder(Path("/tmp")))


class EmptyAndDamagedResultTests(TempHome):
    """Reading a result file that the scanner left empty must explain itself."""

    def test_empty_file_reports_a_reason_instead_of_raising(self):
        path = self.root / "empty.csv"
        path.write_text("", encoding="utf-8")

        report = parse_results_csv(path)

        self.assertEqual(report.results, [])
        self.assertTrue(any("empty" in item for item in report.warnings))

    def test_whitespace_only_text_reports_a_reason(self):
        report = parse_csv_text("   \n\t\n")

        self.assertEqual(report.results, [])
        self.assertTrue(report.warnings)

    def test_rows_with_a_broken_address_or_latency_are_skipped(self):
        text = (
            "IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码\r\n"
            "not-an-ip,4,4,0.00,100.00,0.00,N/A\r\n"
            "104.21.54.105,4,4,0.00,N/A,0.00,N/A\r\n"
            "172.67.213.151,4,4,0.00,438.32,0.00,SJC\r\n"
        )

        report = parse_csv_text(text)

        self.assertEqual([item.ip for item in report.results], ["172.67.213.151"])
        self.assertTrue(any("Skipped" in item for item in report.warnings))

    def test_an_unreadable_latency_is_never_recommended_as_the_fastest(self):
        """A row with no readable latency used to become 0 ms and win the ranking."""
        text = (
            "IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码\r\n"
            "104.21.54.105,4,4,0.00,N/A,0.00,N/A\r\n"
            "172.67.213.151,4,4,0.00,438.32,0.00,SJC\r\n"
        )

        report = parse_csv_text(text)

        self.assertEqual([item.ip for item in report.results], ["172.67.213.151"])
        self.assertEqual(rank_results(report.results)[0].ip, "172.67.213.151")
        self.assertEqual(recommend(report.results).ip, "172.67.213.151")

    def test_a_latency_with_a_unit_suffix_is_read_as_a_number(self):
        text = (
            "IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码\r\n"
            "172.67.213.151,4,4,0.00,438.32 ms,0.00,SJC\r\n"
        )

        report = parse_csv_text(text)

        self.assertEqual([item.ip for item in report.results], ["172.67.213.151"])
        self.assertEqual(report.results[0].latency_ms, 438.32)

    def test_a_row_whose_latency_column_is_absent_is_still_kept(self):
        text = (
            "IP 地址,已发送,已接收,丢包率,下载速度(MB/s),地区码\r\n"
            "172.67.213.151,4,4,0.00,0.00,SJC\r\n"
        )

        report = parse_csv_text(text)

        self.assertEqual([item.ip for item in report.results], ["172.67.213.151"])
        self.assertEqual(report.results[0].latency_ms, 0.0)


class NoMeasurementRoundTests(unittest.TestCase):
    """Carriers that produced nothing must be named, not silently dropped."""

    def test_a_carrier_with_no_measurement_is_reported_with_a_reason(self):
        best = multisip.best_per_line({"rounds": [
            {"isp": "mci", "verified": []},
            {"isp": "irancell", "verified": [{"ip": "104.21.0.1", "rtt_ms": None,
                                              "verdict": "PASS"}]},
        ]})

        self.assertEqual(best[0]["isp"], "mci")
        self.assertIsNone(best[0]["ip"])
        self.assertEqual(best[0]["reason"], "nothing was verified")
        self.assertEqual(best[1]["isp"], "irancell")
        self.assertIsNone(best[1]["ip"])
        self.assertEqual(best[1]["reason"], "no measurement")

    def test_empty_inputs_produce_empty_reports(self):
        self.assertEqual(multisip.common_rows([], 2), [])
        self.assertEqual(multisip.coverage_rows([], 2), [])
        self.assertEqual(multisip.join_rounds({}), [])
        self.assertEqual(multisip.best_per_line({}), [])

    def test_a_session_whose_rounds_total_is_zero_produces_no_common_rows(self):
        rows = [{"ip": "104.21.0.1", "covered": 0, "worst_rtt": None}]

        self.assertEqual(multisip.common_rows(rows, 0), [])
        self.assertEqual(multisip.coverage_rows(rows, 0), [])


class EntryPointTests(unittest.TestCase):
    """``python3 -m cfscan`` is how most people will ever start this."""

    def test_module_entry_point_prints_the_version(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as home:
            environ = dict(os.environ, HOME=home, PYTHONPATH=str(root))
            completed = subprocess.run(
                [sys.executable, "-m", "cfscan", "--version"],
                cwd=str(root), env=environ, capture_output=True, text=True,
                timeout=60,
            )

        self.assertEqual(completed.returncode, EXIT_OK, completed.stderr)
        self.assertIn(__version__, completed.stdout)

    def test_main_builds_its_own_console(self):
        """No console is passed on a real run, so that path must work too."""
        captured = io.StringIO()
        with mock.patch("sys.stdout", captured):
            code = main(["--version"])

        self.assertEqual(code, EXIT_OK)
        self.assertIn(__version__, captured.getvalue())

    def test_no_color_keeps_the_output_free_of_escape_codes(self):
        captured = io.StringIO()
        with mock.patch("sys.stdout", captured):
            code = main(["--version", "--no-color"])

        self.assertEqual(code, EXIT_OK)
        self.assertIn(__version__, captured.getvalue())
        self.assertNotIn("\x1b[", captured.getvalue())

    def test_help_runs_without_a_console_object(self):
        captured = io.StringIO()
        with mock.patch("sys.stdout", captured):
            code = main(["--help", "--no-color"])

        self.assertEqual(code, EXIT_OK)
        self.assertIn("cfscan", captured.getvalue().lower())

    def test_an_unknown_profile_in_usage_errors_out_loudly(self):
        """The interactive path validates before it opens the menu."""
        with tempfile.TemporaryDirectory() as home:
            paths = make_paths(home)
            console, out, _ = make_console()
            code = main(["--profile", "ghost"], paths=paths, console=console)

        text = out.getvalue()
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("Unknown profile 'ghost'", text)
        self.assertIn("Available profiles", text)

    def test_a_quick_scan_names_the_profile_it_cannot_find(self):
        with tempfile.TemporaryDirectory() as home:
            paths = make_paths(home)
            console, out, _ = make_console()
            code = main(["--quick", "--profile", "ghost"], paths=paths,
                        console=console)

        text = out.getvalue()
        self.assertNotEqual(code, EXIT_OK)
        self.assertIn("ghost", text)
        self.assertIn("does not exist", text)


if __name__ == "__main__":
    unittest.main()

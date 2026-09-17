"""The paths a coverage audit found untested, now pinned.

Running the suite under :mod:`trace` showed ~90% line coverage with 298 lines
never executed. They were mostly error handling and value coercion, so each
behaviour here was first probed by hand - this module keeps the results honest:
if one of these changes silently, the test says so instead of the user noticing
it in a scan report.
"""

from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cfscan.menu import (
    EXIT_FAILED,
    EXIT_MISSING_TOOL,
    EXIT_OK,
    Session,
    _colo_cell,
    _finish_scan_results,
    _metric_cell,
    _top_ips,
    _auto_verify_enabled,
    open_results_folder,
    quick_scan,
    switch_ip_version,
    multi_isp_round,
)
from cfscan.parser import _parse_float, _parse_int, _parse_loss
from cfscan.profiles import default_profile
from cfscan.runner import build_url, read_progress_file

from tests.support import (
    CSV_HEADER,
    LOG_NO_RESULTS,
    Fixture,
    ScriptedSpawn,
    csv_with_measurements,
)

RANGE = ["104.16.0.1", "172.64.0.1"]


class ParserValueTests(unittest.TestCase):
    def test_loss_fractions_and_percentages_are_both_understood(self):
        self.assertEqual(_parse_loss("0.25"), 0.25)
        self.assertEqual(_parse_loss("25%"), 0.25)
        self.assertEqual(_parse_loss("25 %"), 0.25)
        self.assertEqual(_parse_loss("1"), 1.0)

    def test_an_out_of_range_loss_can_never_outrank_a_real_one(self):
        # 150% used to be a way to look better than an honest 0%; it clamps.
        self.assertEqual(_parse_loss("150%"), 1.0)
        self.assertEqual(_parse_loss("250"), 1.0)
        self.assertEqual(_parse_loss("-5"), 0.0)

    def test_an_empty_or_unreadable_cell_reads_as_no_loss(self):
        for value in ("", "  ", "-", "N/A", "abc", "0,25"):
            self.assertEqual(_parse_loss(value), 0.0, value)

    def test_numbers_use_the_callers_default_when_unreadable(self):
        self.assertEqual(_parse_float("0.5", -1.0), 0.5)
        self.assertEqual(_parse_float("50%", -1.0), 0.5)
        self.assertEqual(_parse_float("abc", -1.0), -1.0)
        self.assertEqual(_parse_int("4", 0), 4)
        self.assertEqual(_parse_int("4.5", 7), 7)

    def test_the_loss_clamp_survives_a_full_parse(self):
        text = (CSV_HEADER + "\n"
                "104.21.0.1,20,20,150%,400.00,0.00,SOF\n")
        from cfscan.parser import parse_csv_text

        report = parse_csv_text(text)
        self.assertEqual(len(report.results), 1)
        self.assertLessEqual(report.results[0].loss, 1.0)
        self.assertFalse(report.results[0].is_loss_free)


class UrlPathTests(unittest.TestCase):
    def url_for(self, path):
        profile = default_profile()
        profile.update({"url_path": path, "scheme": "https", "port": 443,
                        "domain": "example.com"})
        return build_url(profile)

    def test_a_bare_path_gets_a_slash(self):
        self.assertEqual(self.url_for("diag"), "https://example.com:443/diag")
        self.assertEqual(self.url_for("/diag"), "https://example.com:443/diag")

    def test_an_empty_or_missing_path_is_the_root(self):
        for path in ("", "/", None):
            self.assertEqual(self.url_for(path), "https://example.com:443/")

    def test_a_trailing_slash_is_kept_and_a_query_still_joins(self):
        self.assertEqual(self.url_for("diag/"), "https://example.com:443/diag/")
        self.assertEqual(self.url_for("?q=1"), "https://example.com:443/?q=1")


class ProfileValueTests(unittest.TestCase):
    def test_auto_verification_reads_text_switches(self):
        session = type("S", (), {"top_ips": 10, "verify_attempts": 20})()
        for value, expected in ((True, True), (False, False), ("yes", True),
                                ("no", False), ("0", False), ("1", True),
                                ("off", False), ("TRUE", True), (None, True),
                                (0, False), (1, True)):
            profile = default_profile()
            profile["verify_top_ips"] = value
            self.assertEqual(_auto_verify_enabled(session, profile), expected,
                             f"verify_top_ips={value!r}")

    def test_the_top_address_count_falls_back_to_ten_and_never_goes_below_one(self):
        session = type("S", (), {"top_ips": 10, "verify_attempts": 20})()
        for value, expected in (("abc", 10), (None, 10), (0, 10), (-3, 1),
                                (4, 4), ("7", 7)):
            profile = default_profile()
            profile["top_ips"] = value
            self.assertEqual(_top_ips(session, profile), expected, repr(value))


class ReportCellTests(unittest.TestCase):
    def test_every_verdict_has_a_readable_cell(self):
        self.assertEqual(_metric_cell(None), "-")
        self.assertEqual(_metric_cell({"verdict": "PASS", "rtt_ms": 150.0}),
                         "150 ms")
        self.assertEqual(_metric_cell({"verdict": "FAIL", "rtt_ms": 900.0}),
                         "lost")
        self.assertEqual(_metric_cell({"verdict": "DEAD", "rtt_ms": None}),
                         "dead")
        self.assertEqual(_metric_cell({"verdict": "UNVERIFIED"}), "?")
        # A pass without a latency number is not a usable cell either.
        self.assertEqual(_metric_cell({"verdict": "PASS", "rtt_ms": None}), "-")
        self.assertEqual(_metric_cell({}), "-")

    def test_the_colo_comes_from_a_carrier_that_passed(self):
        row = {"passing": ["mci", "irancell"],
               "per_isp": {"mci": {"colo": "N/A"}, "irancell": {"colo": "SOF"}}}
        self.assertEqual(_colo_cell(row), "SOF")
        self.assertEqual(_colo_cell({"passing": ["mci"],
                                     "per_isp": {"mci": {"colo": "N/A"}}}), "-")
        self.assertEqual(_colo_cell({"passing": [], "per_isp": {}}), "-")


class ProgressTailTests(unittest.TestCase):
    def test_the_progress_line_is_found_at_the_end_of_a_big_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "big.log"
            log.write_text("".join(f"junk {index}\n" for index in range(20000)) +
                           "12 / 24 [____] 可用: 3 \n", encoding="utf-8")
            self.assertGreater(log.stat().st_size, 100000)
            report = read_progress_file(log, limit=4096)
            self.assertIsNotNone(report)
            self.assertEqual((report.done, report.total, report.available),
                             (12, 24, 3))

    def test_a_log_without_a_progress_line_reads_as_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "plain.log"
            log.write_text("nothing useful here\n", encoding="utf-8")
            self.assertIsNone(read_progress_file(log))


class CancelAndMissingFileTests(unittest.TestCase):
    def test_quick_scan_cancelled_at_the_prompt_runs_nothing(self):
        spawn = ScriptedSpawn()
        fixture = Fixture(answers=["n"], spawn=spawn)
        self.addCleanup(fixture.close)
        self.assertEqual(quick_scan(fixture.session, fixture.config), EXIT_OK)
        self.assertIn("Cancelled - nothing was executed.", fixture.text)
        self.assertEqual(spawn.calls, [])

    def test_quick_scan_without_the_scanner_binary_says_so(self):
        fixture = Fixture(answers=["y"])
        self.addCleanup(fixture.close)
        fixture.config["cfst_path"] = str(Path(fixture.tmp.name) / "missing-cfst")
        self.assertEqual(quick_scan(fixture.session, fixture.config),
                         EXIT_MISSING_TOOL)
        self.assertIn("not found", fixture.text.lower())

    def test_quick_scan_without_the_range_file_says_so(self):
        fixture = Fixture(answers=["y"])
        self.addCleanup(fixture.close)
        profile = fixture.config["profiles"][fixture.config["active_profile"]]
        profile["ip_file"] = str(Path(fixture.tmp.name) / "nope.txt")
        self.assertEqual(quick_scan(fixture.session, fixture.config),
                         EXIT_MISSING_TOOL)
        self.assertIn("IP range file was not found", fixture.text)

    def test_an_unreadable_result_file_fails_with_its_reason(self):
        # The scan succeeds and writes a CSV, but the file cannot be opened.
        good = csv_with_measurements([("104.21.0.1", 4, 4, 0.0, 120.0, "SOF")])
        fixture = Fixture(answers=["y"], spawn=ScriptedSpawn(csv_text=good),
                          preflight=False)
        self.addCleanup(fixture.close)
        fixture.session.verify_top_ips = False
        original = fixture.spawn.__call__

        def lock_the_csv(argv, log_handle):
            process = original(argv, log_handle)
            out = Path(argv[argv.index("-o") + 1])
            if out.exists():
                out.chmod(0o000)
                self.addCleanup(lambda: out.chmod(0o600) if out.exists() else None)
            return process

        fixture.session.spawn = lock_the_csv
        code = quick_scan(fixture.session, fixture.config, verify_prompt=False)
        if Path(fixture.paths.results_dir).exists():
            for leftover in Path(fixture.paths.results_dir).glob("*.csv"):
                leftover.chmod(0o600)
        if not Path(fixture.paths.results_dir).exists():
            self.skipTest("nothing was written")
        self.assertEqual(code, EXIT_FAILED)
        self.assertIn("could not be read", fixture.text)
        # The verdict block the menu repeats after the flow says what happened.
        self.assertIn("unreadable", str(fixture.session.last_result))

    def test_an_empty_scan_says_what_the_scanner_said(self):
        fixture = Fixture(answers=["y"], spawn=ScriptedSpawn(
            log_text=LOG_NO_RESULTS, create_csv=False))
        self.addCleanup(fixture.close)
        self.assertEqual(quick_scan(fixture.session, fixture.config), EXIT_FAILED)
        self.assertIn("No IP passed the filters this time", fixture.text)
        self.assertIn("Troubleshooting", fixture.text)

    def test_a_lossy_fastest_address_is_flagged_before_the_check(self):
        lossy = csv_with_measurements([("104.21.0.1", 4, 3, 0.25, 120.0, "SOF")])
        fixture = Fixture(answers=["y"], spawn=ScriptedSpawn(csv_text=lossy))
        self.addCleanup(fixture.close)
        # Auto-verification off, so the scan verdict is what is judged.
        fixture.session.verify_top_ips = False
        quick_scan(fixture.session, fixture.config, verify_prompt=False)
        self.assertIn("already lost packets during the scan", fixture.text)


class PreflightCancellationTests(unittest.TestCase):
    def test_a_failed_preflight_stops_a_quick_scan(self):
        fixture = Fixture(answers=[], spawn=ScriptedSpawn(), preflight=True)
        self.addCleanup(fixture.close)
        fixture.session.assume_yes = True
        with mock.patch("cfscan.menu.preflight_probe", return_value=False):
            self.assertEqual(quick_scan(fixture.session, fixture.config),
                             EXIT_FAILED)
        self.assertIn("Cancelled - nothing was executed.", fixture.text)

    def test_a_failed_preflight_stops_a_carrier_round_too(self):
        fixture = Fixture(answers=[], spawn=ScriptedSpawn(), preflight=True)
        self.addCleanup(fixture.close)
        with mock.patch("cfscan.menu.preflight_probe", return_value=False):
            self.assertEqual(multi_isp_round(fixture.session, fixture.config,
                                             isp="mci"), EXIT_FAILED)
        self.assertIn("Cancelled - nothing was measured.", fixture.text)
        self.assertEqual(fixture.spawn.calls, [])


class CandidateListErrorTests(unittest.TestCase):
    def test_an_empty_candidate_list_is_named(self):
        fixture = Fixture(answers=[], spawn=ScriptedSpawn())
        self.addCleanup(fixture.close)
        empty = Path(fixture.tmp.name) / "empty.txt"
        empty.write_text("# only a comment\n", encoding="utf-8")
        from cfscan.validate import ValidationError

        with self.assertRaises(ValidationError) as caught:
            multi_isp_round(fixture.session, fixture.config, isp="mci",
                            pool_path=str(empty))
        self.assertIn("is empty", str(caught.exception))

    def test_a_missing_range_file_names_the_file(self):
        fixture = Fixture(answers=[], spawn=ScriptedSpawn())
        self.addCleanup(fixture.close)
        profile = fixture.config["profiles"][fixture.config["active_profile"]]
        profile["ip_file"] = str(Path(fixture.tmp.name) / "gone.txt")
        from cfscan.validate import ValidationError

        with self.assertRaises(ValidationError) as caught:
            multi_isp_round(fixture.session, fixture.config, isp="mci")
        self.assertIn("IP range file was not found", str(caught.exception))

    def test_a_candidate_list_of_zero_is_refused(self):
        fixture = Fixture(answers=[], spawn=ScriptedSpawn())
        self.addCleanup(fixture.close)
        from cfscan.menu import _prepare_pool
        from cfscan.validate import ValidationError

        profile = fixture.config["profiles"][fixture.config["active_profile"]]
        with self.assertRaises(ValidationError) as caught:
            _prepare_pool(fixture.session, profile, fixture.session.console,
                          size=-2)
        self.assertIn("at least one address", str(caught.exception))


class RetryPathTests(unittest.TestCase):
    def test_the_last_carrier_is_offered_again_when_it_measures_nothing(self):
        from cfscan.menu import multi_isp_flow

        good = csv_with_measurements([("104.21.0.1", 4, 4, 0.0, 150.0, "SOF")])
        verify = csv_with_measurements([("104.21.0.1", 20, 20, 0.0, 150.0, "SOF")])
        spawn = ScriptedSpawn(csv_sequence=[
            good, verify,                       # mci
            csv_with_measurements([]),          # irancell: nothing
            good, verify,                       # irancell again after "yes"
        ])
        fixture = Fixture(answers=["2", "", "", "", "y", ""], spawn=spawn)
        self.addCleanup(fixture.close)
        self.assertEqual(multi_isp_flow(fixture.session, fixture.config),
                         EXIT_OK)
        self.assertIn("Measure irancell once more?", fixture.text)

    def test_a_carrier_name_is_asked_for_when_none_is_given(self):
        good = csv_with_measurements([("104.21.0.1", 4, 4, 0.0, 150.0, "SOF")])
        verify = csv_with_measurements([("104.21.0.1", 20, 20, 0.0, 150.0, "SOF")])
        fixture = Fixture(answers=["home line"], spawn=ScriptedSpawn(
            csv_sequence=[good, verify]))
        self.addCleanup(fixture.close)
        self.assertEqual(multi_isp_round(fixture.session, fixture.config),
                         EXIT_OK)
        self.assertIn("Carrier name", fixture.text)
        from cfscan import vantages

        record = vantages.load_session(vantages.latest_session(
            fixture.paths.results_dir, fixture.profile()["domain"]))
        self.assertEqual(vantages.isp_names(record), ["home line"])


class SmallFlowTests(unittest.TestCase):
    def test_switching_to_the_current_family_changes_nothing(self):
        fixture = Fixture(answers=["4"], spawn=ScriptedSpawn())
        self.addCleanup(fixture.close)
        self.assertEqual(switch_ip_version(fixture.session, fixture.config),
                         EXIT_OK)
        self.assertIn("Nothing to change", fixture.text)

    def test_an_unusable_results_folder_is_reported(self):
        fixture = Fixture(answers=[], spawn=ScriptedSpawn())
        self.addCleanup(fixture.close)
        session, config = fixture.session, fixture.config
        with mock.patch("cfscan.menu.Path.mkdir", side_effect=OSError("denied")):
            self.assertEqual(open_results_folder(session, config), EXIT_FAILED)
        self.assertIn("could not be created", fixture.text)

    def test_finder_failing_to_open_is_only_a_warning(self):
        fixture = Fixture(answers=[], spawn=ScriptedSpawn())
        self.addCleanup(fixture.close)
        with mock.patch("cfscan.menu.results_module.open_in_finder",
                        return_value=False):
            self.assertEqual(open_results_folder(fixture.session, fixture.config),
                             EXIT_OK)
        self.assertIn("could not be opened automatically", fixture.text)


class HelpAndRenderTests(unittest.TestCase):
    def test_the_render_helper_marks_and_limits_the_table(self):
        from cfscan.menu import _render_results_table
        from cfscan.parser import ScanResult
        from cfscan.ui import Console

        stream = io.StringIO()
        console = Console(out=stream, color=False)
        rows = [ScanResult("104.21.0.1", 4, 4, 0.0, 120.0),
                ScanResult("104.21.0.2", 4, 4, 0.0, 130.0),
                ScanResult("104.21.0.3", 4, 4, 0.0, 140.0)]
        _render_results_table(console, rows, limit=2, recommended_ip="104.21.0.1")
        text = stream.getvalue()
        self.assertIn("104.21.0.1", text)
        self.assertIn("104.21.0.2", text)
        self.assertNotIn("104.21.0.3", text)

    def test_the_finish_helper_handles_an_address_that_is_not_in_the_table(self):
        fixture = Fixture(answers=[], spawn=ScriptedSpawn())
        self.addCleanup(fixture.close)
        from cfscan.parser import ScanResult

        rows = [ScanResult("104.21.0.1", 4, 4, 0.0, 120.0)]
        fixture.session.verify_top_ips = False
        verified, passed, marked = _finish_scan_results(
            fixture.session, fixture.config,
            fixture.config["profiles"][fixture.config["active_profile"]],
            rows, top_n=1, recommended=None, csv_path="/tmp/x.csv",
            flow="Quick Scan")
        # No strict check ran, so there is no verdict and nothing to mark.
        self.assertIsNone(verified)
        self.assertEqual(passed, [])
        self.assertIsNone(marked)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

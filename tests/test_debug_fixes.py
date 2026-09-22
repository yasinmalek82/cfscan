"""Regressions for the bugs a full debug pass turned up.

Each test here started life as a real failure on the machine, not as a guess:
an IPv6 profile reaching a traceback from the menu, a candidate list size that
was silently clamped, a re-measured carrier that destroyed a stored session,
and a report whose columns collided. They are kept together so the story stays
readable.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cfscan import vantages
from cfscan.cli import main, pool_size_value
from cfscan.menu import (
    EXIT_FAILED,
    EXIT_OK,
    EXIT_USAGE,
    Session,
    make_pool_flow,
    multi_isp_flow,
    multi_isp_report,
    multi_isp_round,
)
from cfscan.pool import new_pool
from cfscan.profiles import Paths, load_config, save_config, upsert_profile
from cfscan.ui import Console
from cfscan.validate import ValidationError

from tests.support import (
    Fixture,
    ScriptedSpawn,
    csv_with_measurements,
    make_console,
    make_paths,
    write_ip_ranges,
)

SCAN_ONE = csv_with_measurements([("104.21.0.1", 4, 4, 0.0, 150.0, "SOF")])
VERIFY_ONE = csv_with_measurements([("104.21.0.1", 20, 20, 0.0, 150.0, "SOF")])
SCAN_TWO = csv_with_measurements([("104.21.0.9", 4, 4, 0.0, 160.0, "AMS")])
VERIFY_TWO = csv_with_measurements([("104.21.0.9", 20, 20, 0.0, 160.0, "AMS")])


def console_and_stream():
    return make_console([])


class Ipv6ProfileTests(unittest.TestCase):
    """An IPv6 profile cannot be compared across carriers; it must say so."""

    def setUp(self):
        self.fixture = Fixture(answers=[], spawn=ScriptedSpawn())
        self.addCleanup(self.fixture.close)
        v6 = Path(self.fixture.tmp.name) / "ipv6.txt"
        v6.write_text("2606:4700::/32\n2400:cb00::/32\n", encoding="utf-8")
        config = self.fixture.config
        upsert_profile(config, "v6test", {"domain": "v6.example.com", "port": 443,
                                         "ip_version": 6, "ipv6_file": str(v6)})
        save_config(self.fixture.paths, config)
        self.config = load_config(self.fixture.paths)

    def test_the_wizard_raises_a_readable_error_not_a_value_error(self):
        with self.assertRaises(ValidationError) as caught:
            multi_isp_flow(self.fixture.session, self.config,
                           profile_name="v6test", isps=["mci", "irancell"])
        self.assertIn("scans IPv6", str(caught.exception))
        self.assertIn("menu 7", str(caught.exception))

    def test_one_round_reports_it_the_same_way(self):
        with self.assertRaises(ValidationError):
            multi_isp_round(self.fixture.session, self.config,
                            profile_name="v6test", isp="mci")

    def test_the_cli_prints_it_instead_of_a_traceback(self):
        console, out, _scripted = console_and_stream()
        code = main(["--isp", "mci", "--profile", "v6test"],
                    paths=self.fixture.paths, console=console,
                    spawn=ScriptedSpawn())
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("scans IPv6", out.getvalue())

    def test_a_missing_candidate_list_is_a_usage_error_in_the_cli(self):
        console, out, _scripted = console_and_stream()
        code = main(["--isp", "mci", "--pool", "/nope/pool.txt"],
                    paths=self.fixture.paths, console=console,
                    spawn=ScriptedSpawn())
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("was not found", out.getvalue())


class CandidateListSizeTests(unittest.TestCase):
    def test_a_negative_size_is_refused_by_the_parser(self):
        self.assertEqual(pool_size_value(0), 0)
        self.assertEqual(pool_size_value("250"), 250)
        with self.assertRaises(Exception):
            pool_size_value("-5")
        with self.assertRaises(Exception):
            pool_size_value("abc")
        with self.assertRaises(Exception):
            pool_size_value(10 ** 9)

    def test_a_negative_size_is_a_usage_error_and_writes_nothing(self):
        fixture = Fixture(answers=[], spawn=ScriptedSpawn())
        self.addCleanup(fixture.close)
        console, out, _scripted = console_and_stream()
        code = main(["--make-pool", "-5"], paths=fixture.paths, console=console,
                    spawn=fixture.spawn)
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("Invalid usage", out.getvalue())
        self.assertEqual(list(Path(fixture.paths.results_dir).rglob("*.txt")), [])

    def test_new_pool_refuses_a_size_below_one(self):
        with self.assertRaises(ValueError):
            new_pool("104.16.0.0/24\n", size=0)
        with self.assertRaises(ValueError):
            new_pool("104.16.0.0/24\n", size=-3)

    def test_a_tiny_but_valid_size_is_still_accepted(self):
        fixture = Fixture(answers=[], spawn=ScriptedSpawn())
        self.addCleanup(fixture.close)
        console, _out, _scripted = console_and_stream()
        session = Session(paths=fixture.paths, console=console, dry_run=True,
                          preflight=False)
        self.assertEqual(make_pool_flow(session, fixture.config, size=1), EXIT_OK)


class RepeatedCarrierTests(unittest.TestCase):
    """Re-measuring a carrier must replace its round, never lose the session."""

    def test_a_second_carrier_is_added_to_the_same_session(self):
        spawn = ScriptedSpawn(csv_sequence=[SCAN_ONE, VERIFY_ONE,
                                            SCAN_TWO, VERIFY_TWO])
        fixture = Fixture(answers=[], spawn=spawn)
        self.addCleanup(fixture.close)
        domain = fixture.profile()["domain"]
        multi_isp_round(fixture.session, fixture.config, isp="mci")
        multi_isp_round(fixture.session, fixture.config, isp="irancell")
        self.assertEqual(len(vantages.list_sessions(fixture.paths.results_dir,
                                                    domain)), 1)

    def test_re_measuring_a_carrier_replaces_its_round_and_keeps_the_others(self):
        spawn = ScriptedSpawn(csv_sequence=[SCAN_ONE, VERIFY_ONE,
                                            SCAN_TWO, VERIFY_TWO,
                                            SCAN_ONE, VERIFY_ONE])
        fixture = Fixture(answers=[], spawn=spawn)
        self.addCleanup(fixture.close)
        domain = fixture.profile()["domain"]
        multi_isp_round(fixture.session, fixture.config, isp="mci")
        multi_isp_round(fixture.session, fixture.config, isp="irancell")
        multi_isp_round(fixture.session, fixture.config, isp="mci")

        paths = vantages.list_sessions(fixture.paths.results_dir, domain)
        self.assertEqual(len(paths), 1, "the session was split or overwritten")
        record = vantages.load_session(paths[0])
        # One round per carrier, and the carrier measured in between survives.
        self.assertEqual(vantages.isp_names(record), ["mci", "irancell"])
        self.assertIn("will be replaced", fixture.text)

    def test_the_message_says_what_is_being_replaced(self):
        spawn = ScriptedSpawn(csv_sequence=[SCAN_ONE, VERIFY_ONE,
                                            SCAN_ONE, VERIFY_ONE])
        fixture = Fixture(answers=[], spawn=spawn)
        self.addCleanup(fixture.close)
        multi_isp_round(fixture.session, fixture.config, isp="mci")
        multi_isp_round(fixture.session, fixture.config, isp="mci")
        self.assertIn("The stored mci round will be replaced", fixture.text)
        record = vantages.load_session(vantages.latest_session(
            fixture.paths.results_dir, fixture.profile()["domain"]))
        self.assertEqual(vantages.isp_names(record), ["mci"])

    def test_the_report_still_lists_every_carrier_after_a_retry(self):
        spawn = ScriptedSpawn(csv_sequence=[SCAN_ONE, VERIFY_ONE,
                                            SCAN_TWO, VERIFY_TWO,
                                            SCAN_ONE, VERIFY_ONE])
        fixture = Fixture(answers=[], spawn=spawn)
        self.addCleanup(fixture.close)
        multi_isp_round(fixture.session, fixture.config, isp="mci")
        multi_isp_round(fixture.session, fixture.config, isp="irancell")
        multi_isp_round(fixture.session, fixture.config, isp="mci")
        console, out, _scripted = console_and_stream()
        session = Session(paths=fixture.paths, console=console,
                          spawn=spawn, preflight=False)
        self.assertEqual(multi_isp_report(session, fixture.config), EXIT_OK)
        text = out.getvalue()
        self.assertIn("2 (mci, irancell)", text)
        self.assertIn("104.21.0.9", text)
        # The re-measured carrier appears once in the per-carrier table, in the
        # position it was first measured in.
        rows = [line for line in text.splitlines()
                if line.strip().startswith("mci ")]
        self.assertEqual(len(rows), 1, rows)
        self.assertLess(text.index("mci       104.21.0.1"),
                        text.index("irancell  104.21.0.9"))

    def test_two_sessions_in_the_same_second_get_separate_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            results = Path(tmp) / "results"
            first = vantages.new_session({"name": "p"}, "example.com", 443,
                                         "/tmp/pool.txt", "sha", ["mci"])
            second = vantages.new_session({"name": "p"}, "example.com", 443,
                                          "/tmp/pool.txt", "sha", ["mci"])
            first_path = vantages.save_session(results, first)
            second_path = vantages.save_session(results, second)
            self.assertNotEqual(first_path, second_path)
            self.assertTrue(second_path.exists())
            # Saving the same session twice still reuses its own file.
            self.assertEqual(vantages.save_session(results, first), first_path)
            self.assertEqual(len(vantages.list_sessions(results)), 2)


class ReportColumnTests(unittest.TestCase):
    def test_carrier_names_that_slugify_alike_get_distinct_columns(self):
        spawn = ScriptedSpawn(csv_sequence=[SCAN_ONE, VERIFY_ONE,
                                            SCAN_TWO, VERIFY_TWO])
        fixture = Fixture(answers=[], spawn=spawn)
        self.addCleanup(fixture.close)
        # Both names slugify to "profile": the columns must still be unique.
        multi_isp_round(fixture.session, fixture.config, isp="ایرانسل")
        multi_isp_round(fixture.session, fixture.config, isp="همراه اول")
        console, _out, _scripted = console_and_stream()
        session = Session(paths=fixture.paths, console=console, spawn=spawn,
                          preflight=False)
        self.assertEqual(multi_isp_report(session, fixture.config), EXIT_OK)
        directory = vantages.sessions_dir(fixture.paths.results_dir,
                                          fixture.profile()["domain"])
        header = sorted(directory.glob("report-*.csv"))[-1].read_text(
            encoding="utf-8").splitlines()[0].split(",")
        self.assertEqual(len(header), len(set(header)), header)
        self.assertIn("profile_verdict", header)
        self.assertIn("profile2_verdict", header)


class ReportCsvTests(unittest.TestCase):
    def test_a_carrier_name_with_a_comma_does_not_shift_the_columns(self):
        import csv

        spawn = ScriptedSpawn(csv_sequence=[SCAN_ONE, VERIFY_ONE,
                                            SCAN_TWO, VERIFY_TWO])
        fixture = Fixture(answers=[], spawn=spawn)
        self.addCleanup(fixture.close)
        multi_isp_round(fixture.session, fixture.config, isp="mci, home")
        multi_isp_round(fixture.session, fixture.config, isp="irancell")
        console, _out, _scripted = console_and_stream()
        session = Session(paths=fixture.paths, console=console, spawn=spawn,
                          preflight=False)
        self.assertEqual(multi_isp_report(session, fixture.config), EXIT_OK)
        directory = vantages.sessions_dir(fixture.paths.results_dir,
                                          fixture.profile()["domain"])
        report = sorted(directory.glob("report-*.csv"))[-1]
        rows = list(csv.reader(report.read_text(encoding="utf-8").splitlines()))
        width = len(rows[0])
        for row in rows:
            self.assertEqual(len(row), width, row)
        self.assertIn("mci-home_verdict", rows[0])


class WizardSafetyTests(unittest.TestCase):
    def test_yes_does_not_hide_the_switch_between_rounds(self):
        spawn = ScriptedSpawn(csv_sequence=[SCAN_ONE, VERIFY_ONE,
                                            SCAN_TWO, VERIFY_TWO])
        fixture = Fixture(answers=[], spawn=spawn, assume_yes=True)
        self.addCleanup(fixture.close)
        self.assertEqual(multi_isp_flow(fixture.session, fixture.config,
                                        isps=["mci", "irancell"]), EXIT_OK)
        # A skipped prompt is fine, a silent one is not: the user has to know
        # that no round waited for the connection to be switched.
        self.assertIn("--yes was given", fixture.text)
        self.assertNotIn("Switch this Mac to mci", fixture.text)

    def test_a_retried_carrier_does_not_add_a_second_column(self):
        # First round on "mci" measures nothing, the user picks "measure again",
        # then it works. The session must hold one mci round, not two.
        spawn = ScriptedSpawn(csv_sequence=[
            csv_with_measurements([]),          # mci: nothing answered
            SCAN_ONE, VERIFY_ONE,               # mci again
            SCAN_TWO, VERIFY_TWO,               # irancell
        ])
        fixture = Fixture(answers=["2", "", "", "", "1", "", ""], spawn=spawn)
        self.addCleanup(fixture.close)
        self.assertEqual(multi_isp_flow(fixture.session, fixture.config),
                         EXIT_OK)
        record = vantages.load_session(vantages.list_sessions(
            fixture.paths.results_dir, fixture.profile()["domain"])[-1])
        self.assertEqual(vantages.isp_names(record), ["mci", "irancell"])

    def test_a_carrier_that_is_named_twice_keeps_one_round(self):
        spawn = ScriptedSpawn(csv_sequence=[SCAN_ONE, VERIFY_ONE,
                                            SCAN_TWO, VERIFY_TWO])
        fixture = Fixture(answers=["2", "mci", "mci", "", ""], spawn=spawn)
        self.addCleanup(fixture.close)
        self.assertEqual(multi_isp_flow(fixture.session, fixture.config),
                         EXIT_OK)
        record = vantages.load_session(vantages.list_sessions(
            fixture.paths.results_dir, fixture.profile()["domain"])[-1])
        self.assertEqual(vantages.isp_names(record), ["mci"])


class ConflictingCommandTests(unittest.TestCase):
    def test_two_commands_at_once_are_refused(self):
        fixture = Fixture(answers=[], spawn=ScriptedSpawn())
        self.addCleanup(fixture.close)
        console, out, _scripted = console_and_stream()
        code = main(["--quick", "--isp", "mci"], paths=fixture.paths,
                    console=console, spawn=fixture.spawn)
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("Give one command at a time", out.getvalue())
        self.assertEqual(fixture.spawn.calls, [])

    def test_pool_without_a_carrier_is_refused(self):
        fixture = Fixture(answers=[], spawn=ScriptedSpawn())
        self.addCleanup(fixture.close)
        console, out, _scripted = console_and_stream()
        code = main(["--pool", "x.txt"], paths=fixture.paths, console=console,
                    spawn=fixture.spawn)
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("--isp NAME", out.getvalue())

    def test_session_without_the_report_command_is_refused(self):
        fixture = Fixture(answers=[], spawn=ScriptedSpawn())
        self.addCleanup(fixture.close)
        console, out, _scripted = console_and_stream()
        code = main(["--session", "x.json"], paths=fixture.paths, console=console,
                    spawn=fixture.spawn)
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("--multi-isp", out.getvalue())

    def test_make_pool_alone_uses_the_default_size(self):
        paths = make_paths(Path(self._tmp_dir()))
        write_ip_ranges(Path(paths.home) / "ranges" / "ip.txt")
        console, out, _scripted = console_and_stream()
        code = main(["--make-pool"], paths=paths, console=console,
                    spawn=ScriptedSpawn())
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Candidate list", out.getvalue())
        self.assertNotIn("Invalid usage", out.getvalue())

    def _tmp_dir(self):
        import tempfile

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return tmp.name


class SessionStoreTests(unittest.TestCase):
    def test_drop_round_keeps_the_order_of_the_others(self):
        session = vantages.new_session({"name": "p"}, "example.com", 443,
                                       "/tmp/pool.txt", "sha",
                                       ["mci", "irancell", "rightel"])
        for name in ("mci", "irancell", "rightel"):
            vantages.add_round(session, name, [])
        dropped = vantages.drop_round(session, "irancell")
        self.assertEqual(dropped["isp"], "irancell")
        self.assertEqual(vantages.isp_names(session), ["mci", "rightel"])
        self.assertIsNone(vantages.drop_round(session, "nothing"))

    def test_replace_round_keeps_the_position(self):
        session = vantages.new_session({"name": "p"}, "example.com", 443,
                                       "/tmp/pool.txt", "sha",
                                       ["mci", "irancell"])
        vantages.add_round(session, "mci", [])
        vantages.add_round(session, "irancell", [])
        replaced = vantages.replace_round(session, "mci",
                                          {"isp": "mci", "verified": "new"})
        self.assertTrue(replaced)
        rounds = session["rounds"]
        self.assertEqual([record["isp"] for record in rounds],
                         ["mci", "irancell"])
        self.assertEqual(rounds[0]["verified"], "new")
        self.assertFalse(vantages.replace_round(session, "rightel", {}))

    def test_round_for_finds_the_carrier(self):
        session = vantages.new_session({"name": "p"}, "example.com", 443,
                                       "/tmp/pool.txt", "sha", ["mci"])
        vantages.add_round(session, "mci", [])
        self.assertEqual(vantages.round_for(session, "mci")["isp"], "mci")
        self.assertIsNone(vantages.round_for(session, "irancell"))


class FailedRoundExplanationTests(unittest.TestCase):
    def test_a_round_that_scanned_nothing_shows_the_scanner_message(self):
        # The log says the candidate list could not be parsed; that reason has to
        # reach the user instead of a bare "no address answered".
        bad_log = (
            "# XIU2/CloudflareSpeedTest v2.3.5 \n"
            "\n"
            "ParseCIDR err invalid CIDR address: # a comment/128\n"
        )
        spawn = ScriptedSpawn(log_text=bad_log, create_csv=False)
        fixture = Fixture(answers=[], spawn=spawn)
        self.addCleanup(fixture.close)
        self.assertEqual(multi_isp_round(fixture.session, fixture.config,
                                         isp="mci"), EXIT_OK)
        text = fixture.text
        self.assertIn("No address answered on this carrier.", text)
        self.assertIn("ParseCIDR", text)
        self.assertIn("Raw scanner log", text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

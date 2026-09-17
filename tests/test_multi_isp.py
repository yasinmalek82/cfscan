"""End-to-end tests for the multi-carrier wizard (menu 10) and its commands.

The wizard is the user facing half of :mod:`cfscan.vantages` and
:mod:`cfscan.multisip`. What these tests pin down:

* every round scans the *same* candidate list (otherwise the carriers would
  never measure the same addresses and nothing could be compared),
* a later round verifies the addresses earlier rounds proved, so a shared
  address carries a verdict on every carrier,
* the session is stored as rounds finish, and the report is complete,
* a carrier that was not switched yet is caught and can be re-measured,
* the scripted commands (``--isp``, ``--multi-isp``, ``--make-pool``) do the
  same thing one step at a time.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from cfscan import vantages
from cfscan.cli import main
from cfscan.menu import (
    EXIT_FAILED,
    EXIT_OK,
    Session,
    multi_isp_flow,
    multi_isp_report,
    multi_isp_round,
)
from cfscan.profiles import default_profile
from cfscan.validate import ValidationError

from tests.support import Fixture, ScriptedSpawn, csv_with_measurements

# The profile the test fixture ships with, so assertions read from the same
# place the code does instead of hard-coding a domain twice.
PROFILE = default_profile()
DOMAIN = PROFILE["domain"]
PORT = PROFILE["port"]

ROUND_ONE_SCAN = csv_with_measurements([
    ("104.21.0.1", 4, 4, 0.0, 150.0, "SOF"),
    ("104.21.0.2", 4, 4, 0.0, 151.0, "SOF"),
])

ROUND_ONE_VERIFY = csv_with_measurements([
    ("104.21.0.1", 20, 20, 0.0, 150.0, "SOF"),
    ("104.21.0.2", 20, 20, 0.0, 151.0, "SOF"),
])

ROUND_TWO_SCAN = csv_with_measurements([
    ("104.21.0.9", 4, 4, 0.0, 160.0, "AMS"),
])

# The second carrier answers the shared address but loses packets on the other
# one, so exactly one address is common to both carriers.
ROUND_TWO_VERIFY = csv_with_measurements([
    ("104.21.0.1", 20, 20, 0.0, 155.0, "SOF"),
    ("104.21.0.2", 20, 18, 0.10, 900.0, "SOF"),
    ("104.21.0.9", 20, 20, 0.0, 160.0, "AMS"),
])


def scan_calls(spawn):
    """Every scanner run that scanned a candidate list (not a verification).

    A verification run carries ``-debug`` (so a status-code rejection is
    explained); a range scan never does.
    """
    return [call for call in spawn.calls if "-debug" not in call]


def candidate_files(spawn):
    """The ``-f`` argument of each scan run, in order."""
    return [call[call.index("-f") + 1] for call in scan_calls(spawn)]


class MultiIspFlowTests(unittest.TestCase):
    def fixture(self, **kwargs):
        spawn = kwargs.pop("spawn", None) or ScriptedSpawn(
            csv_sequence=[ROUND_ONE_SCAN, ROUND_ONE_VERIFY,
                          ROUND_TWO_SCAN, ROUND_TWO_VERIFY],
        )
        fixture = Fixture(answers=["2", "", "", "", ""], spawn=spawn, **kwargs)
        self.addCleanup(fixture.close)
        return fixture

    def test_two_carriers_scan_the_same_candidate_list(self):
        fixture = self.fixture()
        self.assertEqual(multi_isp_flow(fixture.session, fixture.config),
                         EXIT_OK)
        files = candidate_files(fixture.spawn)
        self.assertEqual(len(files), 2)
        self.assertEqual(files[0], files[1])
        self.assertTrue(Path(files[0]).exists())
        self.assertEqual(Path(files[0]).parent.name, "pools")
        # The list the wizard fixed is named by its fingerprint and holds plain
        # addresses only: the scanner aborts a run on any line it cannot parse.
        text = Path(files[0]).read_text(encoding="utf-8")
        self.assertNotIn("#", text)
        self.assertTrue(text.strip().splitlines())
        self.assertTrue(all(line.count(".") == 3
                            for line in text.strip().splitlines()), text)
        # The seed that rebuilds this exact list is kept in the session record.
        record = vantages.load_session(
            vantages.list_sessions(fixture.paths.results_dir, DOMAIN)[0])
        self.assertIsInstance(record["pool_seed"], int)

    def test_the_report_names_the_address_that_works_on_both_carriers(self):
        fixture = self.fixture()
        multi_isp_flow(fixture.session, fixture.config)
        text = fixture.text
        self.assertIn("Multi-carrier report", text)
        self.assertIn("2 (mci, irancell)", text)
        self.assertIn("1. Best on every carrier", text)
        self.assertIn("104.21.0.1", text)
        self.assertIn("2. Fastest verified address per carrier", text)
        self.assertIn("3. Partial coverage", text)
        self.assertIn("104.21.0.1 - passed on all 2 carriers", text)
        self.assertIn(f"sni {DOMAIN}", text)

    def test_a_later_round_verifies_what_earlier_rounds_proved(self):
        fixture = self.fixture()
        multi_isp_flow(fixture.session, fixture.config)
        sessions = vantages.list_sessions(fixture.paths.results_dir, DOMAIN)
        self.assertEqual(len(sessions), 1)
        record = vantages.load_session(sessions[0])
        self.assertEqual(vantages.isp_names(record), ["mci", "irancell"])
        second = record["rounds"][1]["verified"]
        ips = [row["ip"] for row in second]
        self.assertIn("104.21.0.1", ips)
        verdicts = {row["ip"]: row["verdict"] for row in second}
        self.assertEqual(verdicts["104.21.0.1"], vantages.PASS)
        self.assertEqual(verdicts["104.21.0.2"], vantages.FAIL)
        # The recipe is locked into the session, so the report can be rebuilt.
        self.assertEqual(record["port"], PORT)
        self.assertEqual(record["scheme"], PROFILE["scheme"])
        self.assertEqual(record["http_status"], PROFILE["http_status"])
        self.assertEqual(record["pool_sha256"], record["pool_sha256"].lower())

    def test_the_report_is_saved_next_to_the_session(self):
        fixture = self.fixture()
        multi_isp_flow(fixture.session, fixture.config)
        directory = vantages.sessions_dir(fixture.paths.results_dir, DOMAIN)
        reports = sorted(directory.glob("report-*.csv"))
        self.assertEqual(len(reports), 1)
        header = reports[0].read_text(encoding="utf-8").splitlines()[0]
        self.assertIn("mci_verdict", header)
        self.assertIn("irancell_ms", header)

    def test_every_round_is_stored_as_soon_as_it_finishes(self):
        inner = ScriptedSpawn(
            csv_sequence=[ROUND_ONE_SCAN, ROUND_ONE_VERIFY,
                          ROUND_TWO_SCAN, ROUND_TWO_VERIFY],
        )

        class StopOnSecondScan(object):
            """Interrupt the scanner the moment the second range scan starts."""

            def __call__(self, argv, log_handle):
                if len(inner.calls) >= 2:
                    raise KeyboardInterrupt
                return inner(argv, log_handle)

        fixture = Fixture(answers=["2", "", "", "", ""], spawn=StopOnSecondScan())
        self.addCleanup(fixture.close)
        self.assertEqual(multi_isp_flow(fixture.session, fixture.config),
                         EXIT_OK)
        sessions = vantages.list_sessions(fixture.paths.results_dir, DOMAIN)
        self.assertEqual(len(sessions), 1)
        record = vantages.load_session(sessions[0])
        # The first round survived the interruption of the second one.
        self.assertEqual(vantages.isp_names(record), ["mci"])
        self.assertIn("The round was stopped", fixture.text)
        self.assertIn("104.21.0.1", fixture.text)

    def test_a_carrier_that_was_not_switched_yet_is_offered_again(self):
        spawn = ScriptedSpawn(csv_sequence=[
            csv_with_measurements([]),          # mci: nothing answered
            ROUND_TWO_SCAN, ROUND_TWO_VERIFY,   # irancell
        ])
        fixture = Fixture(answers=["2", "", "", "", "2", ""], spawn=spawn)
        self.addCleanup(fixture.close)
        self.assertEqual(multi_isp_flow(fixture.session, fixture.config),
                         EXIT_OK)
        text = fixture.text
        self.assertIn("No address answered on this carrier.", text)
        self.assertIn("What now?", text)
        self.assertIn("Continue with the next carrier", text)
        self.assertIn("104.21.0.9", text)
        # Nothing was shared, so the partial coverage section leads.
        self.assertIn("1/2", text)
        self.assertIn("1 of 2", text)

    def test_the_names_are_asked_for_one_by_one(self):
        fixture = self.fixture()
        multi_isp_flow(fixture.session, fixture.config)
        text = fixture.text
        self.assertIn("How many carriers do you want to measure", text)
        self.assertIn("Name of carrier 1", text)
        self.assertIn("Name of carrier 2", text)
        self.assertIn("Press Enter to start the mci round", text)
        self.assertIn("Press Enter to start the irancell round", text)

    def test_a_dry_run_measures_nothing_and_waits_for_nothing(self):
        spawn = ScriptedSpawn()
        fixture = Fixture(answers=["2", "", ""], spawn=spawn, dry_run=True)
        self.addCleanup(fixture.close)
        self.assertEqual(multi_isp_flow(fixture.session, fixture.config),
                         EXIT_FAILED)
        self.assertEqual(spawn.calls, [])
        self.assertIn("Dry run - nothing will be executed", fixture.text)
        self.assertIn("-f ", fixture.text)
        self.assertEqual(vantages.list_sessions(fixture.paths.results_dir,
                                                DOMAIN), [])


class SingleRoundTests(unittest.TestCase):
    def test_one_carrier_can_be_measured_without_the_wizard(self):
        spawn = ScriptedSpawn(csv_sequence=[ROUND_ONE_SCAN, ROUND_ONE_VERIFY])
        fixture = Fixture(answers=[], spawn=spawn)
        self.addCleanup(fixture.close)
        self.assertEqual(multi_isp_round(fixture.session, fixture.config,
                                         isp="mci"), EXIT_OK)
        self.assertIn("104.21.0.1", fixture.text)
        sessions = vantages.list_sessions(fixture.paths.results_dir, DOMAIN)
        self.assertEqual(len(sessions), 1)
        record = vantages.load_session(sessions[0])
        self.assertEqual(record["isps"], ["mci"])
        self.assertEqual(len(record["rounds"]), 1)

    def test_the_next_round_continues_the_same_session_and_list(self):
        spawn = ScriptedSpawn(csv_sequence=[ROUND_ONE_SCAN, ROUND_ONE_VERIFY,
                                            ROUND_TWO_SCAN, ROUND_TWO_VERIFY])
        fixture = Fixture(answers=[], spawn=spawn)
        self.addCleanup(fixture.close)
        multi_isp_round(fixture.session, fixture.config, isp="mci")
        multi_isp_round(fixture.session, fixture.config, isp="irancell")
        sessions = vantages.list_sessions(fixture.paths.results_dir, DOMAIN)
        self.assertEqual(len(sessions), 1)
        record = vantages.load_session(sessions[0])
        self.assertEqual(vantages.isp_names(record), ["mci", "irancell"])
        # Both rounds scanned one and the same file.
        self.assertEqual(len({call[call.index("-f") + 1]
                              for call in scan_calls(spawn)}), 1)
        self.assertIn("already passed on every measured carrier", fixture.text)

    def test_a_round_feeds_an_explicit_candidate_list(self):
        spawn = ScriptedSpawn(csv_sequence=[ROUND_ONE_SCAN, ROUND_ONE_VERIFY])
        fixture = Fixture(answers=[], spawn=spawn)
        self.addCleanup(fixture.close)
        pool = Path(fixture.tmp.name) / "my-pool.txt"
        pool.write_text("104.21.0.1\n104.21.0.2\n", encoding="utf-8")
        multi_isp_round(fixture.session, fixture.config, isp="mci",
                        pool_path=str(pool), note="hotspot")
        self.assertEqual(candidate_files(spawn), [str(pool)])
        record = vantages.load_session(vantages.list_sessions(
            fixture.paths.results_dir, DOMAIN)[0])
        self.assertEqual(record["rounds"][0]["access"], "hotspot")

    def test_a_missing_candidate_list_is_reported_not_crashed(self):
        fixture = Fixture(answers=[], spawn=ScriptedSpawn())
        self.addCleanup(fixture.close)
        with self.assertRaises(ValidationError) as caught:
            multi_isp_round(fixture.session, fixture.config, isp="mci",
                            pool_path=str(Path(fixture.tmp.name) / "nope.txt"))
        self.assertIn("was not found", str(caught.exception))


class ReportCommandTests(unittest.TestCase):
    def test_the_stored_session_can_be_reported_again(self):
        spawn = ScriptedSpawn(csv_sequence=[ROUND_ONE_SCAN, ROUND_ONE_VERIFY,
                                            ROUND_TWO_SCAN, ROUND_TWO_VERIFY])
        fixture = Fixture(answers=[], spawn=spawn)
        self.addCleanup(fixture.close)
        multi_isp_round(fixture.session, fixture.config, isp="mci")
        multi_isp_round(fixture.session, fixture.config, isp="irancell")

        console, out, _scripted = _fresh_console()
        session = Session(paths=fixture.paths, console=console, spawn=spawn,
                          preflight=False)
        self.assertEqual(multi_isp_report(session, fixture.config), EXIT_OK)
        self.assertIn("passed on all 2 carriers", out.getvalue())

    def test_reporting_without_a_session_explains_what_to_do(self):
        fixture = Fixture(answers=[], spawn=ScriptedSpawn())
        self.addCleanup(fixture.close)
        self.assertEqual(multi_isp_report(fixture.session, fixture.config),
                         EXIT_FAILED)
        self.assertIn("No multi-carrier session was found yet", fixture.text)


class CliTests(unittest.TestCase):
    def test_make_pool_writes_the_list_the_rounds_share(self):
        fixture = Fixture(answers=[], spawn=ScriptedSpawn())
        self.addCleanup(fixture.close)
        code = main(["--make-pool", "40"], paths=fixture.paths,
                    console=fixture.console, spawn=fixture.spawn)
        self.assertEqual(code, EXIT_OK)
        directory = vantages.sessions_dir(fixture.paths.results_dir, DOMAIN) / "pools"
        pools = list(directory.glob("pool-*.txt"))
        self.assertEqual(len(pools), 1)
        self.assertEqual(len([line for line in
                              pools[0].read_text(encoding="utf-8").splitlines()
                              if line and not line.startswith("#")]), 40)
        self.assertIn(f'cfscan --isp <name> --pool "{pools[0]}"', fixture.text)

    def test_the_cli_measures_one_carrier_then_reports(self):
        spawn = ScriptedSpawn(csv_sequence=[ROUND_ONE_SCAN, ROUND_ONE_VERIFY,
                                            ROUND_TWO_SCAN, ROUND_TWO_VERIFY])
        fixture = Fixture(answers=[], spawn=spawn)
        self.addCleanup(fixture.close)
        first = main(["--isp", "mci", "--no-preflight", "--yes"],
                     paths=fixture.paths, console=fixture.console,
                     spawn=spawn)
        self.assertEqual(first, EXIT_OK)
        console, out, _scripted = _fresh_console()
        second = main(["--isp", "irancell", "--no-preflight", "--yes"],
                      paths=fixture.paths, console=console, spawn=spawn)
        self.assertEqual(second, EXIT_OK)
        self.assertIn("already passed on every measured carrier", out.getvalue())

        console, out, _scripted = _fresh_console()
        third = main(["--multi-isp"], paths=fixture.paths, console=console,
                     spawn=spawn)
        self.assertEqual(third, EXIT_OK)
        self.assertIn("Multi-carrier report", out.getvalue())
        self.assertIn("104.21.0.1", out.getvalue())

    def test_an_unknown_session_file_is_a_usage_error(self):
        fixture = Fixture(answers=[], spawn=ScriptedSpawn())
        self.addCleanup(fixture.close)
        code = main(["--multi-isp", "--session",
                     str(Path(fixture.tmp.name) / "missing.json")],
                    paths=fixture.paths, console=fixture.console,
                    spawn=fixture.spawn)
        self.assertEqual(code, EXIT_FAILED)
        self.assertIn("could not be read", fixture.text)


class SessionFileTests(unittest.TestCase):
    def test_the_session_file_is_readable_json(self):
        spawn = ScriptedSpawn(csv_sequence=[ROUND_ONE_SCAN, ROUND_ONE_VERIFY])
        fixture = Fixture(answers=[], spawn=spawn)
        self.addCleanup(fixture.close)
        multi_isp_round(fixture.session, fixture.config, isp="mci")
        path = vantages.list_sessions(fixture.paths.results_dir, DOMAIN)[0]
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["version"], vantages.SESSION_VERSION)
        self.assertEqual(data["domain"], DOMAIN)
        self.assertEqual(data["rounds"][0]["isp"], "mci")
        self.assertEqual(data["rounds"][0]["scanned"], 2)


def _fresh_console():
    from tests.support import make_console

    return make_console([])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

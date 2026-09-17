"""The bookkeeping around a scan: leftover files and duplicate names.

None of this changes a measurement. All of it decides whether what is left on
disk, and what the report claims, still makes sense a month later.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from cfscan.menu import (
    KEEP_RESULTS,
    _carrier_list,
    _discard_probe_result,
    open_results_folder,
    preflight_probe,
    prunable_results,
)

from tests.support import Fixture, LOG_NO_RESULTS, ScriptedSpawn, make_console


class ProbeCleanupTests(unittest.TestCase):
    def test_a_probe_leaves_neither_a_result_nor_a_log(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        directory = Path(fixture.paths.results_dir)
        directory.mkdir(parents=True, exist_ok=True)
        csv_path = directory / "cfscan-preflight-x.csv"
        log_path = directory / "cfscan-preflight-x.log"
        csv_path.write_text("x", encoding="utf-8")
        log_path.write_text("x", encoding="utf-8")

        _discard_probe_result(csv_path)

        self.assertFalse(csv_path.exists())
        self.assertFalse(log_path.exists())

    def test_a_failed_preflight_does_not_fill_the_results_folder(self):
        # The reason a preflight failed is printed while it is still relevant;
        # its log belongs to no scan and used to stay behind forever.
        spawn = ScriptedSpawn(log_text=LOG_NO_RESULTS, create_csv=False)
        fixture = Fixture(answers=["n"], spawn=spawn, preflight=True)
        self.addCleanup(fixture.close)
        name = fixture.config["active_profile"]

        preflight_probe(fixture.session, fixture.config, name, fixture.profile())

        left = sorted(item.name for item in
                      Path(fixture.paths.results_dir).glob("*preflight*"))
        self.assertEqual(left, [])


class PruneTests(unittest.TestCase):
    def _folder(self, count):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        directory = Path(fixture.paths.results_dir)
        directory.mkdir(parents=True, exist_ok=True)
        made = []
        for index in range(count):
            csv_path = directory / f"cfscan-scan-{index:03d}.csv"
            csv_path.write_text("ip\n", encoding="utf-8")
            csv_path.with_suffix(".log").write_text("log\n", encoding="utf-8")
            import os
            stamp = 1_000_000 + index
            os.utime(csv_path, (stamp, stamp))
            made.append(csv_path)
        return fixture, directory, made

    def test_a_small_folder_is_left_alone(self):
        fixture, directory, _made = self._folder(3)
        self.assertEqual(prunable_results(directory), [])

    def test_only_the_oldest_beyond_the_kept_count_are_listed(self):
        fixture, directory, made = self._folder(KEEP_RESULTS + 4)
        doomed = prunable_results(directory)
        # Four scans, each with its log.
        self.assertEqual(len(doomed), 8)
        self.assertIn(made[0], doomed)
        self.assertNotIn(made[-1], doomed)

    def test_the_file_the_configuration_points_at_is_never_listed(self):
        fixture, directory, made = self._folder(KEEP_RESULTS + 4)
        doomed = prunable_results(directory, protect=[str(made[0])])
        self.assertNotIn(made[0], doomed)

    def test_sessions_and_pools_are_not_touched(self):
        fixture, directory, _made = self._folder(KEEP_RESULTS + 4)
        session_dir = directory / "multi-isp" / "example-com"
        session_dir.mkdir(parents=True, exist_ok=True)
        record = session_dir / "example-com-20260101-000000.json"
        record.write_text("{}", encoding="utf-8")
        pool = session_dir / "pools" / "pool-abc.txt"
        pool.parent.mkdir(parents=True, exist_ok=True)
        pool.write_text("104.16.0.1\n", encoding="utf-8")

        doomed = prunable_results(directory)

        self.assertNotIn(record, doomed)
        self.assertNotIn(pool, doomed)

    def test_the_folder_flow_removes_them_only_after_a_yes(self):
        fixture, directory, made = self._folder(KEEP_RESULTS + 2)
        fixture.console, fixture.out, _ = make_console(["n"], is_tty=True)
        fixture.session.console = fixture.console
        open_results_folder(fixture.session, fixture.config)
        self.assertTrue(made[0].exists())

        fixture.console, fixture.out, _ = make_console(["y"], is_tty=True)
        fixture.session.console = fixture.console
        open_results_folder(fixture.session, fixture.config)
        self.assertFalse(made[0].exists())
        self.assertTrue(made[-1].exists())


class CarrierNameTests(unittest.TestCase):
    def test_a_duplicate_carrier_name_is_refused(self):
        # Two rounds sharing a name replace one another, so the report would
        # promise more carriers than were ever measured.
        console, stream, _ = make_console(["2", "mci", "mci", "irancell"])
        names = _carrier_list(console)
        self.assertEqual(names, ["mci", "irancell"])
        self.assertIn("already the name of carrier 1", stream.getvalue())

    def test_the_suggestion_is_dropped_once_it_is_taken(self):
        console, _stream, _ = make_console(["2", "irancell", "rightel"])
        self.assertEqual(_carrier_list(console), ["irancell", "rightel"])

    def test_names_given_up_front_are_used_as_they_are(self):
        console, _stream, _ = make_console([])
        self.assertEqual(_carrier_list(console, isps=["a", "b"]), ["a", "b"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

"""Tests for result file handling, the latest-result pointer and Finder."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from cfscan.profiles import Paths, load_config
from cfscan.results import (
    ResultStore,
    _sequence_of,
    latest_result_path,
    new_result_path,
    open_in_finder,
    timestamp_label,
)

from tests.support import read_config


class NewResultPathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name) / "Cloudflare Scanner Results"

    def test_builds_timestamped_name(self):
        when = datetime(2026, 9, 15, 16, 35, 1)
        path = new_result_path(self.dir, "example-ir", when=when)
        self.assertEqual(path.name, "cfscan-example-ir-20260915-163501.csv")
        self.assertEqual(path.parent, self.dir)

    def test_creates_results_directory(self):
        new_result_path(self.dir, "label")
        self.assertTrue(self.dir.is_dir())

    def test_never_overwrites_existing_result(self):
        when = datetime(2026, 9, 15, 16, 35, 1)
        first = new_result_path(self.dir, "label", when=when)
        first.write_text("keep me", encoding="utf-8")
        second = new_result_path(self.dir, "label", when=when)
        self.assertNotEqual(first, second)
        self.assertTrue(second.name.endswith("-2.csv"))
        self.assertEqual(first.read_text(encoding="utf-8"), "keep me")

    def test_increments_until_unique(self):
        when = datetime(2026, 9, 15, 16, 35, 1)
        names = set()
        for _ in range(4):
            path = new_result_path(self.dir, "label", when=when)
            names.add(path.name)
            path.write_text("x", encoding="utf-8")
        self.assertEqual(len(names), 4)

    def test_rejects_unsafe_label(self):
        path = new_result_path(self.dir, "../../etc/passwd", when=datetime(2026, 1, 1))
        self.assertEqual(path.parent, self.dir)
        self.assertNotIn("/", path.name.replace(".csv", ""))

    def test_timestamp_label_format(self):
        self.assertEqual(timestamp_label(datetime(2026, 9, 15, 16, 35, 1)), "20260915-163501")

    def test_same_second_suffix_sorts_after_the_first_file(self):
        # The clock fragment is six digits. It must not outrank the -2 file
        # written when two results land in the same second.
        first = "cfscan-label-20260922-165549.csv"
        second = "cfscan-label-20260922-165549-2.csv"
        self.assertLess(_sequence_of(first), _sequence_of(second))
        self.assertEqual(_sequence_of(first), 1)
        self.assertEqual(_sequence_of(second), 2)


class ResultStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.paths = Paths(home=Path(self.tmp.name))
        self.config = load_config(self.paths)
        self.store = ResultStore(self.paths)

    def test_csv_and_log_live_side_by_side(self):
        csv_path = self.store.new_csv("example-ir")
        log_path = self.store.log_for(csv_path)
        self.assertEqual(log_path.name, csv_path.name.replace(".csv", ".log"))
        self.assertEqual(log_path.parent, csv_path.parent)

    def test_record_latest_updates_config(self):
        csv_path = self.store.new_csv("example-ir")
        self.store.record_latest(
            self.config,
            csv_path,
            profile_name="example-ir",
            recommended_ip="104.16.0.1",
        )
        saved = read_config(self.paths)["last_result"]
        self.assertEqual(saved["csv"], str(csv_path))
        self.assertEqual(saved["recommended_ip"], "104.16.0.1")
        self.assertEqual(saved["profile"], "example-ir")
        self.assertIn("when", saved)

    def test_latest_pointer_survives_round_trip(self):
        csv_path = self.store.new_csv("label")
        csv_path.write_text("data", encoding="utf-8")
        self.store.record_latest(self.config, csv_path, profile_name="label")
        reloaded = load_config(self.paths)
        self.assertEqual(Path(latest_result_path(reloaded, self.paths)), csv_path)

    def test_latest_falls_back_to_newest_csv(self):
        first = self.store.new_csv("label")
        first.write_text("a", encoding="utf-8")
        second = self.store.new_csv("label")
        second.write_text("b", encoding="utf-8")
        self.assertEqual(Path(latest_result_path(self.config, self.paths)), second)

    def test_latest_is_none_when_no_results(self):
        self.assertIsNone(latest_result_path(self.config, self.paths))

    def test_latest_ignores_dangling_pointer(self):
        csv_path = self.store.new_csv("label")
        csv_path.write_text("a", encoding="utf-8")
        self.store.record_latest(self.config, csv_path, profile_name="label")
        csv_path.unlink()
        self.assertIsNone(latest_result_path(self.config, self.paths))


class OpenInFinderTests(unittest.TestCase):
    def test_uses_argument_list_without_a_shell(self):
        with mock.patch("cfscan.results.subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0)
            self.assertTrue(open_in_finder(Path("/tmp/example")))
            args = run.call_args[0][0]
            self.assertEqual(args[0], "open")
            self.assertEqual(args[1], "/tmp/example")
            self.assertNotIn("shell", run.call_args[1])

    def test_returns_false_on_failure(self):
        with mock.patch("cfscan.results.subprocess.run", side_effect=OSError("no open")):
            self.assertFalse(open_in_finder(Path("/tmp/example")))


if __name__ == "__main__":
    unittest.main()

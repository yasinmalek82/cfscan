"""Addresses a profile has already proven, and what menu 3 does with them.

A full scan measures thousands of addresses to offer ten. Those ten are the
cheapest candidates tomorrow, so they are remembered and re-proven in one short
run instead of being found again from scratch.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta

from cfscan import favourites
from cfscan.menu import quick_scan, verify_flow

from tests.support import (
    CSV_VERIFY_PASS,
    Fixture,
    ScriptedSpawn,
    csv_with_measurements,
    csv_with_rows,
    LOG_SUCCESS,
)


class _Row:
    """The part of a parser result the favourites module reads."""

    def __init__(self, ip, latency_ms, colo=None):
        self.ip = ip
        self.latency_ms = latency_ms
        self.colo = colo


class StoreTests(unittest.TestCase):
    def test_an_address_is_stored_with_what_the_verdict_was_worth(self):
        profile = {"domain": "example.com", "port": 443}
        favourites.remember(profile, "104.16.0.1", rtt_ms=138.2, colo="FRA")
        entry = favourites.entries_for(profile)[0]
        self.assertEqual(entry["ip"], "104.16.0.1")
        self.assertEqual(entry["colo"], "FRA")
        self.assertAlmostEqual(entry["rtt_ms"], 138.2)
        self.assertEqual(entry["port"], 443)

    def test_re_proving_moves_an_address_forward_instead_of_duplicating_it(self):
        profile = {"domain": "example.com", "port": 443}
        favourites.remember(profile, "1.1.1.1", rtt_ms=200.0)
        favourites.remember(profile, "2.2.2.2", rtt_ms=100.0)
        favourites.remember(profile, "1.1.1.1", rtt_ms=90.0)
        entries = favourites.entries_for(profile)
        self.assertEqual([item["ip"] for item in entries], ["1.1.1.1", "2.2.2.2"])
        self.assertAlmostEqual(entries[0]["rtt_ms"], 90.0)

    def test_many_are_stored_fastest_first(self):
        profile = {"domain": "example.com", "port": 443}
        favourites.remember_many(profile, [
            _Row("1.1.1.1", 300.0), _Row("2.2.2.2", 100.0), _Row("3.3.3.3", 200.0),
        ])
        self.assertEqual([item["ip"] for item in favourites.entries_for(profile)],
                         ["2.2.2.2", "3.3.3.3", "1.1.1.1"])

    def test_the_list_never_grows_past_what_a_person_reads(self):
        profile = {"domain": "example.com", "port": 443}
        for index in range(favourites.MAX_FAVOURITES + 5):
            favourites.remember(profile, f"10.0.0.{index}")
        self.assertEqual(len(favourites.entries_for(profile)),
                         favourites.MAX_FAVOURITES)

    def test_an_unknown_datacentre_is_not_recorded_as_one(self):
        profile = {"domain": "example.com", "port": 443}
        favourites.remember(profile, "1.1.1.1", colo="N/A")
        self.assertNotIn("colo", favourites.entries_for(profile)[0])

    def test_rubbish_in_the_stored_list_is_skipped_not_fatal(self):
        profile = {"favourites": [None, {}, {"ip": ""}, {"ip": "1.1.1.1"},
                                  "not a record", {"ip": "1.1.1.1"}]}
        self.assertEqual([item["ip"] for item in favourites.entries_for(profile)],
                         ["1.1.1.1"])

    def test_forget_removes_one_address(self):
        profile = {"domain": "example.com", "port": 443}
        favourites.remember(profile, "1.1.1.1")
        self.assertTrue(favourites.forget(profile, "1.1.1.1"))
        self.assertFalse(favourites.forget(profile, "1.1.1.1"))
        self.assertEqual(favourites.entries_for(profile), [])

    def test_age_is_reported_in_words(self):
        now = datetime(2026, 9, 17, 12, 0, 0)
        for delta, expected in ((timedelta(minutes=5), "5 min ago"),
                                (timedelta(hours=3), "3 h ago"),
                                (timedelta(days=2), "2 d ago")):
            entry = {"when": (now - delta).isoformat(timespec="seconds")}
            self.assertEqual(favourites.format_age(entry, now=now), expected)
        self.assertEqual(favourites.format_age({}, now=now), "unknown")
        self.assertEqual(favourites.format_age({"when": "nonsense"}, now=now),
                         "unknown")


class VerifyWriteBackTests(unittest.TestCase):
    def test_a_passing_verification_is_saved_on_the_profile(self):
        spawn = ScriptedSpawn(log_text="", csv_text=CSV_VERIFY_PASS)
        fixture = Fixture(spawn=spawn)
        self.addCleanup(fixture.close)

        code = verify_flow(fixture.session, fixture.config, ip="104.21.54.105")

        self.assertEqual(code, 0)
        saved = fixture.reload()["profiles"][fixture.config["active_profile"]]
        self.assertEqual(saved["recommended_ip"], "104.21.54.105")
        self.assertEqual([item["ip"] for item in saved["favourites"]],
                         ["104.21.54.105"])

    def test_a_verification_does_not_replace_the_last_scan(self):
        # Menu 4 promises the last scan. A single-address verification file used
        # to take that pointer, leaving menu 4 showing one row.
        scan = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=csv_with_rows(3))
        fixture = Fixture(answers=["y", "n"], spawn=scan)
        self.addCleanup(fixture.close)
        fixture.session.verify_top_ips = False
        quick_scan(fixture.session, fixture.config)
        scan_csv = fixture.reload()["last_result"]["csv"]

        fixture.session.spawn = ScriptedSpawn(log_text="", csv_text=CSV_VERIFY_PASS)
        verify_flow(fixture.session, fixture.config, ip="104.21.54.105")

        pointer = fixture.reload()["last_result"]
        self.assertEqual(pointer["csv"], scan_csv)
        self.assertEqual(pointer["recommended_ip"], "104.21.54.105")

    def test_a_scan_remembers_the_addresses_that_passed(self):
        rows = [("104.21.0.1", 4, 4, 0.0, 100.0, "FRA"),
                ("104.21.0.2", 4, 4, 0.0, 120.0, "FRA")]
        verified = [("104.21.0.1", 20, 20, 0.0, 101.0, "FRA"),
                    ("104.21.0.2", 20, 18, 0.10, 130.0, "FRA")]
        spawn = ScriptedSpawn(
            log_text=LOG_SUCCESS,
            csv_sequence=[csv_with_measurements(rows),
                          csv_with_measurements(verified)],
        )
        fixture = Fixture(answers=["y"], spawn=spawn)
        self.addCleanup(fixture.close)
        fixture.session.verify_top_ips = True

        quick_scan(fixture.session, fixture.config)

        saved = fixture.reload()["profiles"][fixture.config["active_profile"]]
        # Only the address that actually passed the strict check is kept.
        self.assertEqual([item["ip"] for item in saved["favourites"]],
                         ["104.21.0.1"])
        # And with the strict check's numbers, not the scan's: twenty attempts
        # beat a handful, and the check is what saw where it answers from now.
        self.assertAlmostEqual(saved["favourites"][0]["rtt_ms"], 101.0)
        # The proven winner becomes the profile's recommendation.
        self.assertEqual(saved["recommended_ip"], "104.21.0.1")


class Menu3Tests(unittest.TestCase):
    def _with_saved(self, answers, spawn=None):
        fixture = Fixture(answers=answers, spawn=spawn)
        self.addCleanup(fixture.close)
        profile = fixture.profile()
        favourites.remember(profile, "104.21.0.2", rtt_ms=120.0, colo="FRA")
        favourites.remember(profile, "104.21.0.1", rtt_ms=100.0, colo="FRA")
        fixture.save()
        return fixture

    def test_the_saved_list_is_offered_and_can_be_picked_by_number(self):
        spawn = ScriptedSpawn(log_text="", csv_text=csv_with_measurements(
            [("104.21.0.2", 20, 20, 0.0, 118.0, "FRA")]))
        fixture = self._with_saved(["2"], spawn=spawn)

        code = verify_flow(fixture.session, fixture.config)

        self.assertEqual(code, 0)
        self.assertIn("Saved good IPs", fixture.text)
        self.assertIn("104.21.0.2", fixture.text)

    def test_a_number_outside_the_list_is_explained_not_guessed(self):
        spawn = ScriptedSpawn(log_text="", csv_text=csv_with_measurements(
            [("104.21.0.1", 20, 20, 0.0, 100.0, "FRA")]))
        fixture = self._with_saved(["9", "1"], spawn=spawn)
        verify_flow(fixture.session, fixture.config)
        self.assertIn("There is no 9 in the list", fixture.text)

    def test_all_re_checks_every_saved_address_in_one_run(self):
        spawn = ScriptedSpawn(log_text="", csv_text=csv_with_measurements([
            ("104.21.0.1", 20, 20, 0.0, 95.0, "FRA"),
            ("104.21.0.2", 20, 15, 0.25, 210.0, "FRA"),
        ]))
        fixture = self._with_saved(["all"], spawn=spawn)

        code = verify_flow(fixture.session, fixture.config)

        self.assertEqual(code, 0)
        self.assertEqual(len(spawn.calls), 1)
        text = fixture.text
        self.assertIn("1 of 2 still pass", text)
        saved = fixture.reload()["profiles"][fixture.config["active_profile"]]
        self.assertEqual(saved["recommended_ip"], "104.21.0.1")
        # The address that failed today is kept: it is often fastest an hour on.
        self.assertEqual(sorted(item["ip"] for item in saved["favourites"]),
                         ["104.21.0.1", "104.21.0.2"])

    def test_all_failing_is_reported_without_losing_the_list(self):
        spawn = ScriptedSpawn(log_text="", csv_text=csv_with_measurements(
            [("104.21.0.1", 20, 3, 0.85, 900.0, "FRA")]))
        fixture = self._with_saved(["all"], spawn=spawn)

        code = verify_flow(fixture.session, fixture.config)

        self.assertEqual(code, 1)
        self.assertIn("Not one saved address answers", fixture.text)
        saved = fixture.reload()["profiles"][fixture.config["active_profile"]]
        self.assertEqual(len(saved["favourites"]), 2)

    def test_typing_an_address_still_works_with_a_saved_list(self):
        spawn = ScriptedSpawn(log_text="", csv_text=CSV_VERIFY_PASS)
        fixture = self._with_saved(["104.21.54.105"], spawn=spawn)
        self.assertEqual(verify_flow(fixture.session, fixture.config), 0)
        self.assertIn("PASS", fixture.text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

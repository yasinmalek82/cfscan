"""Ranking the edge locations from measurement rather than from a map.

The nearest datacentre is not the fast one - measured on one Iranian line, GYD
(Baku) was the slowest of every European colo - so the order has to come from
what was actually measured, and it has to know which line measured it.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta

from cfscan import edges
from cfscan.menu import _scan_profile, edge_locations, quick_scan

from tests.support import (
    Fixture,
    LOG_SUCCESS,
    ScriptedSpawn,
    csv_with_measurements,
    make_console,
)


class _Row:
    def __init__(self, ip, latency_ms, colo, loss_free=True):
        self.ip = ip
        self.latency_ms = latency_ms
        self.colo = colo
        self.is_loss_free = loss_free


def rows(*spec):
    return [_Row(f"104.21.0.{index}", latency, colo)
            for index, (latency, colo) in enumerate(spec, start=1)]


class LineTests(unittest.TestCase):
    def test_a_tunnel_interface_is_recognised(self):
        line = edges.describe_line(interface="utun18", gateway=None)
        self.assertTrue(line["tunnel"])
        self.assertEqual(line["label"], "tunnel:utun")

    def test_a_physical_interface_is_not_a_tunnel(self):
        line = edges.describe_line(interface="en0", gateway="172.20.10.1")
        self.assertFalse(line["tunnel"])
        self.assertEqual(line["label"], "direct:en0:172.20.10.1")

    def test_a_tunnel_keeps_its_label_when_macos_renumbers_it(self):
        # utun18 today, utun11 tomorrow, same tunnel: a score that reset on
        # every reconnect would be worthless.
        self.assertEqual(edges.line_label("utun18"), edges.line_label("utun3"))

    def test_an_unknown_route_is_labelled_rather_than_guessed(self):
        self.assertEqual(edges.line_label(""), edges.UNKNOWN_LINE)


class SummariseTests(unittest.TestCase):
    def test_one_row_per_datacentre(self):
        summary = edges.summarise(rows((100.0, "FRA"), (200.0, "FRA"),
                                       (150.0, "SOF")))
        self.assertEqual(summary["FRA"]["n"], 2)
        self.assertEqual(summary["FRA"]["min"], 100.0)
        self.assertEqual(summary["FRA"]["med"], 150.0)
        self.assertEqual(summary["SOF"]["n"], 1)

    def test_rows_with_no_datacentre_are_skipped_not_bucketed(self):
        # The scanner reports no colo for some recipes; an "unknown" bucket
        # would rank nothing and pretend to rank something.
        self.assertEqual(edges.summarise(rows((100.0, "N/A"), (120.0, ""))), {})

    def test_loss_free_addresses_are_counted(self):
        measured = [_Row("1.1.1.1", 100.0, "FRA", loss_free=True),
                    _Row("1.1.1.2", 110.0, "FRA", loss_free=False)]
        self.assertEqual(edges.summarise(measured)["FRA"]["clean"], 1)


class ScoreboardTests(unittest.TestCase):
    def _profile(self):
        return {"domain": "example.com", "port": 443, "edge_history": []}

    def _fill(self, profile, line, colo, latency, scans=2, per_scan=30):
        for index in range(scans):
            edges.observe(profile, [
                _Row(f"104.21.{index}.{n}", latency + n * 0.1, colo)
                for n in range(per_scan)
            ], line=line, when=datetime(2026, 9, 1) + timedelta(hours=index))

    def test_distance_never_enters_into_it(self):
        # GYD is the nearest datacentre and the slowest; the ranking is purely
        # what was measured.
        profile = self._profile()
        self._fill(profile, "direct:en0", "GYD", 232.0)
        self._fill(profile, "direct:en0", "FRA", 176.0)
        ranked, _meta = edges.scoreboard(profile)
        self.assertEqual([row["colo"] for row in ranked], ["FRA", "GYD"])

    def test_a_ranking_belongs_to_the_line_that_measured_it(self):
        profile = self._profile()
        self._fill(profile, "direct:en0", "FRA", 176.0)
        self._fill(profile, "tunnel:utun", "SOF", 120.0)
        direct, meta = edges.scoreboard(profile, line="direct:en0")
        self.assertEqual([row["colo"] for row in direct], ["FRA"])
        self.assertEqual(meta["scans"], 2)
        tunnelled, _ = edges.scoreboard(profile, line="tunnel:utun")
        self.assertEqual([row["colo"] for row in tunnelled], ["SOF"])
        self.assertEqual(sorted(meta["lines"]), ["direct:en0", "tunnel:utun"])

    def test_a_lucky_pair_of_addresses_never_outranks_a_measured_colo(self):
        profile = self._profile()
        self._fill(profile, "direct:en0", "FRA", 176.0)
        self._fill(profile, "direct:en0", "XYZ", 90.0, scans=1, per_scan=2)
        ranked, _meta = edges.scoreboard(profile)
        self.assertEqual(ranked[0]["colo"], "FRA")
        self.assertFalse(ranked[-1]["trusted"])

    def test_an_empty_scan_never_pushes_a_real_one_off_the_history(self):
        profile = self._profile()
        self._fill(profile, "direct:en0", "FRA", 176.0, scans=1)
        self.assertEqual(edges.observe(profile, rows((100.0, "N/A"))), {})
        self.assertEqual(len(edges.entries_for(profile)), 1)

    def test_history_is_capped(self):
        profile = self._profile()
        self._fill(profile, "direct:en0", "FRA", 176.0,
                   scans=edges.MAX_HISTORY + 5, per_scan=25)
        self.assertEqual(len(edges.entries_for(profile)), edges.MAX_HISTORY)

    def test_rubbish_in_the_history_is_skipped_not_fatal(self):
        profile = {"edge_history": [None, {}, {"colos": "nope"},
                                    {"colos": {"FRA": {"n": "x"}}},
                                    {"colos": {"FRA": {"n": 30, "min": 1.0,
                                                       "med": 2.0}}}]}
        self.assertEqual(len(edges.entries_for(profile)), 1)

    def test_a_filtered_run_of_scans_is_flagged_as_no_longer_learning(self):
        # Once a filter is on, the datacentres outside it are never measured
        # again, so the picture silently freezes.
        profile = self._profile()
        for index in range(5):
            edges.observe(profile, rows((150.0, "FRA")), line="direct:en0",
                          colo_filter="FRA", when=datetime(2026, 9, 1 + index))
        _ranked, meta = edges.scoreboard(profile)
        self.assertTrue(meta["stale"])
        self.assertEqual(meta["recent_filter"], "FRA")

    def test_unfiltered_scans_are_not_flagged(self):
        profile = self._profile()
        self._fill(profile, "direct:en0", "FRA", 150.0, scans=3)
        _ranked, meta = edges.scoreboard(profile)
        self.assertFalse(meta["stale"])


class RecommendationTests(unittest.TestCase):
    def test_only_measured_datacentres_are_offered(self):
        ranked = [{"colo": "FRA", "typical": 176.0, "trusted": True},
                  {"colo": "XYZ", "typical": 90.0, "trusted": False}]
        self.assertEqual(edges.recommended_filter(ranked), ["FRA"])

    def test_something_far_slower_than_the_best_is_left_out(self):
        ranked = [{"colo": "FRA", "typical": 170.0, "trusted": True},
                  {"colo": "SOF", "typical": 180.0, "trusted": True},
                  {"colo": "GYD", "typical": 400.0, "trusted": True}]
        self.assertEqual(edges.recommended_filter(ranked), ["FRA", "SOF"])

    def test_nothing_measured_means_no_suggestion(self):
        self.assertEqual(edges.recommended_filter([]), [])


class OverrideTests(unittest.TestCase):
    def test_a_one_run_filter_never_reaches_the_stored_profile(self):
        # The flows save the profile for their own reasons - a verified
        # address, a scan's observations - so an override written into it would
        # ride along into the configuration.
        measured = [("104.21.0.1", 4, 4, 0.0, 100.0, "FRA")]
        verified = [("104.21.0.1", 20, 20, 0.0, 101.0, "FRA")]
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_sequence=[
            csv_with_measurements(measured), csv_with_measurements(verified)])
        fixture = Fixture(answers=["y"], spawn=spawn)
        self.addCleanup(fixture.close)
        fixture.session.verify_top_ips = True
        fixture.session.colo_override = "LHR"

        quick_scan(fixture.session, fixture.config)

        saved = fixture.reload()["profiles"][fixture.config["active_profile"]]
        self.assertEqual(saved.get("colo"), "")
        # It did reach the scanner, though.
        self.assertIn("-cfcolo", spawn.calls[0])
        self.assertEqual(saved["edge_history"][-1]["filter"], "LHR")

    def test_without_an_override_the_profile_is_used_as_it_is(self):
        profile = {"colo": "FRA"}
        session = type("S", (), {"colo_override": None})()
        self.assertIs(_scan_profile(session, profile), profile)


class EdgeLocationsFlowTests(unittest.TestCase):
    def test_nothing_measured_yet_says_so(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        self.assertEqual(edge_locations(fixture.session, fixture.config), 0)
        self.assertIn("No scan has recorded a datacentre yet", fixture.text)

    def test_the_ranking_is_shown_and_can_be_applied(self):
        fixture = Fixture(answers=["y"], tty=True)
        self.addCleanup(fixture.close)
        profile = fixture.profile()
        line = edges.describe_line()["label"]
        for colo, latency in (("GYD", 232.0), ("FRA", 176.0), ("SOF", 171.0)):
            for index in range(2):
                edges.observe(profile, [
                    _Row(f"104.21.{index}.{n}", latency + n * 0.1, colo)
                    for n in range(30)
                ], line=line, when=datetime(2026, 9, 1 + index, 12, 0, 0))
        fixture.save()

        code = edge_locations(fixture.session, fixture.config)

        self.assertEqual(code, 0)
        text = fixture.text
        self.assertIn("SOF", text)
        self.assertIn("Suggested region filter: SOF,FRA", text)
        saved = fixture.reload()["profiles"][fixture.config["active_profile"]]
        self.assertEqual(saved["colo"], "SOF,FRA")

    def test_a_suggestion_that_cannot_work_is_refused_not_saved(self):
        fixture = Fixture(answers=["y"], tty=True)
        self.addCleanup(fixture.close)
        profile = fixture.profile()
        # TCPing never learns a datacentre, so a filter there would drop
        # everything.
        profile["mode"] = "tcp"
        line = edges.describe_line()["label"]
        for index in range(2):
            edges.observe(profile, [_Row(f"104.21.{index}.{n}", 150.0 + n, "FRA")
                                    for n in range(30)],
                          line=line, when=datetime(2026, 9, 1 + index))
        fixture.save()

        edge_locations(fixture.session, fixture.config)

        self.assertIn("HTTPing", fixture.text)
        saved = fixture.reload()["profiles"][fixture.config["active_profile"]]
        self.assertEqual(saved.get("colo"), "")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

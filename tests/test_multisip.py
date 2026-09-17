"""Tests for joining carrier rounds into the shared-address answer.

Everything in :mod:`cfscan.multisip` is a pure function over a stored session,
so the whole ranking can be pinned without a network: which addresses passed on
every carrier, which one is fastest per carrier, and what to recommend when
nothing passed everywhere.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cfscan import multisip, vantages

PROFILE = {"name": "england", "scheme": "https", "http_status": 400}


def entry(ip, verdict="PASS", rtt=100.0, loss=0.0, colo="SOF", sent=20,
          received=None):
    if received is None:
        received = sent if verdict == "PASS" else sent - 2
    return {"ip": ip, "sent": sent, "received": received, "loss": loss,
            "rtt_ms": rtt, "colo": colo, "verdict": verdict}


def make_session(rounds):
    """A session from ``[(carrier, [entry, ...]), ...]``."""
    session = vantages.new_session(PROFILE, "england.yasin-ai-54.ir", 443,
                                   "/tmp/pool-abc.txt", "abc123",
                                   [name for name, _ in rounds])
    for name, entries in rounds:
        vantages.add_round(session, name, entries)
    return session


def two_carriers(first, second):
    return make_session([("mci", first), ("irancell", second)])


class VerdictTests(unittest.TestCase):
    class Row(object):
        def __init__(self, sent, received, loss):
            self.sent = sent
            self.received = received
            self.loss = loss

    def test_a_missing_row_is_dead(self):
        self.assertEqual(vantages.verdict_of(None, 20), vantages.DEAD)

    def test_a_clean_full_measurement_passes(self):
        self.assertEqual(vantages.verdict_of(self.Row(20, 20, 0.0), 20),
                         vantages.PASS)

    def test_loss_or_a_short_measurement_fails(self):
        self.assertEqual(vantages.verdict_of(self.Row(20, 18, 0.10), 20),
                         vantages.FAIL)
        self.assertEqual(vantages.verdict_of(self.Row(4, 4, 0.0), 20),
                         vantages.FAIL)


class JoinTests(unittest.TestCase):
    def test_each_address_carries_one_column_per_carrier(self):
        session = two_carriers([entry("104.16.0.1", rtt=150.0)],
                               [entry("104.16.0.1", rtt=170.0)])
        rows = multisip.join_rounds(session)
        self.assertEqual(len(rows), 1)
        self.assertEqual(sorted(rows[0]["per_isp"]), ["irancell", "mci"])
        self.assertEqual(rows[0]["covered"], 2)
        self.assertEqual(rows[0]["total"], 2)
        self.assertEqual(rows[0]["worst_rtt"], 170.0)
        self.assertEqual(rows[0]["best_rtt"], 150.0)
        self.assertEqual(rows[0]["spread"], 20.0)

    def test_an_address_measured_by_one_carrier_only_is_not_covered_twice(self):
        session = two_carriers([entry("104.16.0.1")], [entry("104.16.0.2")])
        rows = {row["ip"]: row for row in multisip.join_rounds(session)}
        self.assertEqual(rows["104.16.0.1"]["covered"], 1)
        self.assertEqual(rows["104.16.0.2"]["covered"], 1)

    def test_metrics_are_read_from_the_addresses_that_passed(self):
        session = two_carriers([entry("104.16.0.1", rtt=150.0)],
                               [entry("104.16.0.1", verdict="FAIL", rtt=900.0)])
        row = multisip.join_rounds(session)[0]
        self.assertEqual(row["covered"], 1)
        # Only the carrier that passed contributes to the latency picture.
        self.assertEqual(row["worst_rtt"], 150.0)


class CommonRowTests(unittest.TestCase):
    def test_only_addresses_passing_everywhere_are_common(self):
        session = two_carriers(
            [entry("104.16.0.1"), entry("104.16.0.2")],
            [entry("104.16.0.1"), entry("104.16.0.2", verdict="FAIL")],
        )
        common = multisip.common_rows(multisip.join_rounds(session), 2)
        self.assertEqual([row["ip"] for row in common], ["104.16.0.1"])

    def test_a_steady_address_beats_one_that_is_fast_only_here(self):
        # 150 ms on MCI but 600 ms on Irancell loses to 200/210, even though its
        # average latency is lower: what matters is the worst carrier.
        session = two_carriers(
            [entry("104.16.0.1", rtt=150.0), entry("104.16.0.2", rtt=200.0)],
            [entry("104.16.0.1", rtt=600.0), entry("104.16.0.2", rtt=210.0)],
        )
        common = multisip.common_rows(multisip.join_rounds(session), 2)
        self.assertEqual([row["ip"] for row in common], ["104.16.0.2",
                                                         "104.16.0.1"])

    def test_steady_latency_breaks_a_tie_on_worst_case(self):
        session = two_carriers(
            [entry("104.16.0.1", rtt=150.0), entry("104.16.0.2", rtt=160.0)],
            [entry("104.16.0.1", rtt=200.0), entry("104.16.0.2", rtt=160.0)],
        )
        common = multisip.common_rows(multisip.join_rounds(session), 2)
        # Same worst case (200 ms); the smaller spread wins.
        self.assertEqual([row["ip"] for row in common], ["104.16.0.2",
                                                         "104.16.0.1"])

    def test_nothing_common_when_no_carrier_measured_the_same_address(self):
        session = two_carriers([entry("104.16.0.1")], [entry("104.16.0.2")])
        self.assertEqual(multisip.common_rows(multisip.join_rounds(session), 2),
                         [])


class CoverageRowTests(unittest.TestCase):
    def test_partial_cover_is_ranked_by_how_many_carriers_it_reaches(self):
        session = make_session([
            ("mci", [entry("104.16.0.1", rtt=150.0), entry("104.16.0.2", rtt=160.0)]),
            ("irancell", [entry("104.16.0.1", verdict="FAIL")]),
            ("mokhaberat", [entry("104.16.0.1", verdict="FAIL")]),
        ])
        coverage = multisip.coverage_rows(multisip.join_rounds(session), 3)
        self.assertEqual([row["ip"] for row in coverage], ["104.16.0.1",
                                                           "104.16.0.2"])
        self.assertEqual(coverage[0]["covered"], 1)
        self.assertEqual(coverage[0]["passing"], ["mci"])


class BestPerLineTests(unittest.TestCase):
    def test_the_fastest_verified_address_wins_per_carrier(self):
        session = two_carriers(
            [entry("104.16.0.1", rtt=190.0), entry("104.16.0.2", rtt=150.0)],
            [entry("104.16.0.9", rtt=170.0)],
        )
        best = multisip.best_per_line(session)
        self.assertEqual([item["ip"] for item in best],
                         ["104.16.0.2", "104.16.0.9"])
        self.assertTrue(all(item["verified"] for item in best))

    def test_a_carrier_without_a_verified_address_says_so(self):
        session = two_carriers([entry("104.16.0.1")],
                               [entry("104.16.0.9", verdict="FAIL", rtt=180.0)])
        best = multisip.best_per_line(session)
        self.assertEqual(best[1]["ip"], "104.16.0.9")
        self.assertFalse(best[1]["verified"])

    def test_a_carrier_with_no_measurement_at_all_is_marked(self):
        session = make_session([("mci", [entry("104.16.0.1")]),
                                ("irancell", [])])
        best = multisip.best_per_line(session)
        self.assertIsNone(best[1]["ip"])
        self.assertEqual(best[1]["reason"], "nothing was verified")


class RecommendationTests(unittest.TestCase):
    def test_a_shared_address_is_recommended_first(self):
        session = two_carriers([entry("104.16.0.1", rtt=150.0),
                                entry("104.16.0.2", rtt=140.0)],
                               [entry("104.16.0.1", rtt=160.0)])
        result = multisip.recommendation(session)
        self.assertEqual(result["kind"], "common")
        self.assertEqual(result["ip"], "104.16.0.1")
        self.assertIn("all 2 carriers", result["reason"])

    def test_without_a_shared_address_the_best_coverage_is_recommended(self):
        session = two_carriers([entry("104.16.0.1", rtt=150.0)],
                               [entry("104.16.0.9", rtt=160.0)])
        result = multisip.recommendation(session)
        self.assertEqual(result["kind"], "coverage")
        self.assertEqual(result["ip"], "104.16.0.1")
        self.assertIn("1 of 2", result["reason"])

    def test_with_one_carrier_measured_the_fastest_verified_address_wins(self):
        session = make_session([("mci", [entry("104.16.0.1", rtt=170.0),
                                         entry("104.16.0.2", rtt=150.0)])])
        result = multisip.recommendation(session)
        self.assertEqual(result["kind"], "common")
        self.assertEqual(result["ip"], "104.16.0.2")
        # One carrier is not "every carrier": the wording has to stay honest.
        self.assertIn("only carrier measured", result["reason"])
        self.assertNotIn("all 1", result["reason"])

    def test_nothing_verified_means_no_recommendation(self):
        session = two_carriers([entry("104.16.0.1", verdict="FAIL")],
                               [entry("104.16.0.9", verdict="DEAD", rtt=None)])
        self.assertIsNone(multisip.recommendation(session))


class ReportTests(unittest.TestCase):
    def test_the_report_carries_the_recipe_and_every_list(self):
        session = two_carriers([entry("104.16.0.1", rtt=150.0)],
                               [entry("104.16.0.1", rtt=170.0)])
        data = multisip.report(session)
        self.assertEqual(data["total"], 2)
        self.assertEqual(data["isps"], ["mci", "irancell"])
        self.assertEqual(data["verified_addresses"], 1)
        self.assertEqual([row["ip"] for row in data["common"]], ["104.16.0.1"])
        self.assertEqual(data["coverage"], [])
        self.assertEqual(data["recommendation"]["ip"], "104.16.0.1")
        self.assertIn("all 2 carriers", data["recommendation"]["reason"])

    def test_an_empty_session_reports_nothing_instead_of_failing(self):
        session = vantages.new_session(PROFILE, "example.com", 443, None, "",
                                       ["mci"])
        data = multisip.report(session)
        self.assertEqual(data["total"], 0)
        self.assertEqual(data["rows"], [])
        self.assertIsNone(data["recommendation"])


class SessionStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.results = Path(self.tmp.name) / "Cloudflare Scanner Results"

    def test_a_session_is_stored_under_its_domain_and_read_back(self):
        session = two_carriers([entry("104.16.0.1")], [entry("104.16.0.1")])
        path = vantages.save_session(self.results, session)
        self.assertTrue(path.exists())
        self.assertEqual(path.parent.parent.name, "multi-isp")
        self.assertEqual(path.parent.name, "england-yasin-ai-54-ir")
        loaded = vantages.load_session(path)
        self.assertEqual(vantages.isp_names(loaded), ["mci", "irancell"])
        self.assertEqual(loaded["pool_sha256"], "abc123")

    def test_the_latest_session_is_the_newest_one(self):
        first = two_carriers([entry("104.16.0.1")], [entry("104.16.0.1")])
        vantages.save_session(self.results, first)
        second = make_session([("mokhaberat", [entry("104.16.0.9")])])
        path = vantages.save_session(self.results, second)
        latest = vantages.latest_session(self.results, "england.yasin-ai-54.ir")
        self.assertEqual(latest, path)

    def test_saving_twice_keeps_one_file(self):
        session = two_carriers([entry("104.16.0.1")], [entry("104.16.0.1")])
        first = vantages.save_session(self.results, session)
        vantages.add_round(session, "rightel", [entry("104.16.0.9")])
        second = vantages.save_session(self.results, session)
        self.assertEqual(first, second)
        self.assertEqual(len(vantages.isp_names(vantages.load_session(second))),
                         3)

    def test_no_session_yet_is_not_an_error(self):
        self.assertIsNone(vantages.latest_session(self.results, "example.com"))
        self.assertEqual(vantages.list_sessions(self.results), [])

    def test_measured_addresses_are_listed_once_in_first_seen_order(self):
        session = two_carriers(
            [entry("104.16.0.1"), entry("104.16.0.2")],
            [entry("104.16.0.2"), entry("104.16.0.9", verdict="FAIL")],
        )
        self.assertEqual(vantages.measured_ip_list(session),
                         ["104.16.0.1", "104.16.0.2", "104.16.0.9"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

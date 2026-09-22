"""Tests for the scanner CSV parser."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cfscan.parser import (
    CsvError,
    ParseReport,
    ScanResult,
    parse_csv_text,
    parse_results_csv,
    rank_results,
    recommend,
    write_enriched_csv,
)

from tests.support import CSV_HEADER

BOM_HEADER = "\ufeff" + CSV_HEADER


class ParseCsvTextTests(unittest.TestCase):
    def test_parses_chinese_header_with_colo(self):
        text = (
            BOM_HEADER + "\r\n"
            "104.16.0.1,4,4,0.00,438.32,0.00,N/A\r\n"
            "172.67.213.151,4,3,0.25,512.10,0.00,SJC\r\n"
        )
        report = parse_csv_text(text)
        self.assertIsInstance(report, ParseReport)
        self.assertEqual(len(report.results), 2)

        first = report.results[0]
        self.assertEqual(first.ip, "104.16.0.1")
        self.assertEqual(first.sent, 4)
        self.assertEqual(first.received, 4)
        self.assertEqual(first.loss, 0.0)
        self.assertAlmostEqual(first.latency_ms, 438.32)
        self.assertEqual(first.colo, "N/A")
        self.assertFalse(first.has_colo)

        second = report.results[1]
        self.assertEqual(second.colo, "SJC")
        self.assertTrue(second.has_colo)
        self.assertAlmostEqual(second.loss_percent, 25.0)

    def test_parses_csv_without_colo_column(self):
        text = (
            "\ufeffIP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s)\r\n"
            "104.16.0.1,4,4,0.00,438.32,0.00\r\n"
        )
        report = parse_csv_text(text)
        self.assertEqual(len(report.results), 1)
        self.assertIsNone(report.results[0].colo)

    def test_parses_english_header(self):
        text = (
            "IP Address,Sent,Received,Loss,Latency,Download (MB/s),Colo\n"
            "104.16.0.1,4,4,0.00,438.32,0.00,HKG\n"
        )
        report = parse_csv_text(text)
        self.assertEqual(report.results[0].colo, "HKG")
        self.assertAlmostEqual(report.results[0].latency_ms, 438.32)

    def test_tolerates_unparseable_lines(self):
        text = (
            BOM_HEADER + "\r\n"
            "104.16.0.1,4,4,0.00,438.32,0.00,N/A\r\n"
            "this line is broken\r\n"
            "\r\n"
            "not-an-ip,4,4,0.00,1.00,0.00,N/A\r\n"
        )
        report = parse_csv_text(text)
        self.assertEqual(len(report.results), 1)
        self.assertTrue(report.warnings)

    def test_positional_fallback_when_header_unknown(self):
        text = "104.16.0.1,4,4,0.00,438.32,0.00,N/A\n"
        report = parse_csv_text(text)
        self.assertEqual(len(report.results), 1)
        self.assertTrue(report.used_positional_fallback)
        self.assertTrue(report.warnings)

    def test_empty_text_reports_no_rows(self):
        report = parse_csv_text("")
        self.assertEqual(report.results, [])
        self.assertTrue(report.warnings)

    def test_header_only_returns_no_results(self):
        report = parse_csv_text(BOM_HEADER + "\r\n")
        self.assertEqual(report.results, [])
        self.assertTrue(report.warnings)


class ParseResultsCsvTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_missing_file_raises(self):
        with self.assertRaises(CsvError):
            parse_results_csv(self.dir / "nope.csv")

    def test_directory_raises(self):
        with self.assertRaises(CsvError):
            parse_results_csv(self.dir)

    def test_reads_file_from_disk(self):
        path = self.dir / "result.csv"
        path.write_text(
            BOM_HEADER + "\r\n104.16.0.1,4,4,0.00,438.32,0.00,N/A\r\n",
            encoding="utf-8",
        )
        report = parse_results_csv(path)
        self.assertEqual(len(report.results), 1)
        self.assertEqual(report.results[0].ip, "104.16.0.1")

    def test_undecodable_bytes_are_tolerated(self):
        path = self.dir / "result.csv"
        path.write_bytes(
            BOM_HEADER.encode("utf-8")
            + b"\r\n104.16.0.1,4,4,0.00,438.32,0.00,N/A\r\n\xff\xfe\r\n"
        )
        report = parse_results_csv(path)
        self.assertEqual(len(report.results), 1)


class RankAndRecommendTests(unittest.TestCase):
    def make(self, text):
        return parse_csv_text(text).results

    def test_rank_results_puts_loss_free_addresses_first(self):
        results = self.make(
            BOM_HEADER + "\r\n"
            "1.1.1.9,4,4,0.00,900.00,0.00,N/A\r\n"
            "1.1.1.2,4,4,0.00,100.00,0.00,N/A\r\n"
            "1.1.1.5,4,3,0.25,200.00,0.00,N/A\r\n"
        )
        ranked = rank_results(results)
        # Lowest latency first, but an address that lost packets always ranks
        # below a loss free one, however fast it was.
        self.assertEqual([r.ip for r in ranked], ["1.1.1.2", "1.1.1.9", "1.1.1.5"])

    def test_rank_results_sorts_loss_free_by_latency(self):
        results = self.make(
            BOM_HEADER + "\r\n"
            "1.1.1.9,4,4,0.00,900.00,0.00,N/A\r\n"
            "1.1.1.2,4,4,0.00,100.00,0.00,N/A\r\n"
        )
        self.assertEqual([r.ip for r in rank_results(results)], ["1.1.1.2", "1.1.1.9"])

    def test_recommend_prefers_configured_ip(self):
        results = self.make(
            BOM_HEADER + "\r\n"
            "1.1.1.2,4,4,0.00,100.00,0.00,N/A\r\n"
            "104.16.0.1,4,4,0.00,438.32,0.00,N/A\r\n"
        )
        picked = recommend(results, preferred_ip="104.16.0.1")
        self.assertEqual(picked.ip, "104.16.0.1")

    def test_recommend_falls_back_to_fastest(self):
        results = self.make(
            BOM_HEADER + "\r\n"
            "1.1.1.9,4,4,0.00,900.00,0.00,N/A\r\n"
            "1.1.1.2,4,4,0.00,100.00,0.00,N/A\r\n"
        )
        picked = recommend(results, preferred_ip="104.16.0.1")
        self.assertEqual(picked.ip, "1.1.1.2")

    def test_recommend_prefers_loss_free_candidates(self):
        results = self.make(
            BOM_HEADER + "\r\n"
            "1.1.1.2,4,3,0.25,50.00,0.00,N/A\r\n"
            "1.1.1.9,4,4,0.00,120.00,0.00,N/A\r\n"
        )
        picked = recommend(results, preferred_ip=None)
        self.assertEqual(picked.ip, "1.1.1.9")

    def test_recommend_returns_none_for_empty_results(self):
        self.assertIsNone(recommend([], preferred_ip="104.16.0.1"))

    def test_latency_only_order_is_unchanged_when_nothing_else_was_measured(self):
        results = [
            ScanResult("1.1.1.9", 4, 4, 0.0, 119.0),
            ScanResult("1.1.1.2", 4, 4, 0.0, 100.0),
            ScanResult("1.1.1.5", 4, 3, 0.25, 50.0),
        ]
        self.assertEqual([item.ip for item in rank_results(results)],
                         ["1.1.1.2", "1.1.1.9", "1.1.1.5"])

    def test_jitter_reorders_only_inside_a_latency_band(self):
        steady = ScanResult("1.1.1.2", 4, 4, 0.0, 110.0, jitter_ms=1.0)
        jumpy = ScanResult("1.1.1.9", 4, 4, 0.0, 100.0, jitter_ms=25.0)
        slow = ScanResult("1.1.1.5", 4, 4, 0.0, 180.0, jitter_ms=0.2)
        ranked = rank_results([jumpy, slow, steady])
        # 100 ms and 110 ms share a band, so the steadier one wins.
        # 180 ms is a different band and stays last despite perfect jitter.
        self.assertEqual([item.ip for item in ranked],
                         ["1.1.1.2", "1.1.1.9", "1.1.1.5"])
        self.assertEqual(recommend([jumpy, slow, steady]).ip, "1.1.1.2")

    def test_download_speed_outranks_a_small_latency_gap(self):
        quick = ScanResult("1.1.1.2", 4, 4, 0.0, 100.0, download_mbps=2.0)
        fat = ScanResult("1.1.1.9", 4, 4, 0.0, 180.0, download_mbps=20.0)
        lossy = ScanResult("1.1.1.5", 4, 3, 0.25, 40.0, download_mbps=80.0)
        ranked = rank_results([quick, lossy, fat], download=True)
        self.assertEqual([item.ip for item in ranked],
                         ["1.1.1.9", "1.1.1.2", "1.1.1.5"])

    def test_close_download_speeds_fall_back_to_latency_and_jitter(self):
        jumpy = ScanResult("1.1.1.2", 4, 4, 0.0, 100.0, download_mbps=10.2,
                           jitter_ms=20.0)
        steady = ScanResult("1.1.1.9", 4, 4, 0.0, 108.0, download_mbps=10.8,
                            jitter_ms=1.0)
        ranked = rank_results([jumpy, steady], download=True)
        self.assertEqual([item.ip for item in ranked], ["1.1.1.9", "1.1.1.2"])

    def test_upload_is_used_when_download_was_not_measured(self):
        slow = ScanResult("1.1.1.2", 4, 4, 0.0, 90.0, upload_mbps=1.0)
        fast = ScanResult("1.1.1.9", 4, 4, 0.0, 140.0, upload_mbps=12.0)
        self.assertEqual([item.ip for item in rank_results([slow, fast])],
                         ["1.1.1.9", "1.1.1.2"])

    def test_enriched_csv_round_trip_keeps_jitter_and_upload(self):
        original = [
            ScanResult("104.16.0.1", 4, 4, 0.0, 140.0, download_mbps=8.5,
                       colo="FRA", jitter_ms=3.25, upload_mbps=1.5),
            ScanResult("104.16.0.2", 4, 4, 0.0, 150.0, colo="FRA"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.csv"
            write_enriched_csv(path, original)
            report = parse_results_csv(path)
        self.assertEqual(len(report.results), 2)
        first = report.results[0]
        self.assertAlmostEqual(first.jitter_ms, 3.25)
        self.assertAlmostEqual(first.upload_mbps, 1.5)
        self.assertAlmostEqual(first.download_mbps, 8.5)
        self.assertEqual(first.colo, "FRA")
        second = report.results[1]
        self.assertIsNone(second.jitter_ms)
        self.assertIsNone(second.upload_mbps)


if __name__ == "__main__":
    unittest.main()

"""Tests for the scanner CSV parser."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cfscan.parser import (
    CsvError,
    ParseReport,
    parse_csv_text,
    parse_results_csv,
    rank_results,
    recommend,
)

from tests.support import CSV_HEADER

BOM_HEADER = "\ufeff" + CSV_HEADER


class ParseCsvTextTests(unittest.TestCase):
    def test_parses_chinese_header_with_colo(self):
        text = (
            BOM_HEADER + "\r\n"
            "104.21.54.105,4,4,0.00,438.32,0.00,N/A\r\n"
            "172.67.213.151,4,3,0.25,512.10,0.00,SJC\r\n"
        )
        report = parse_csv_text(text)
        self.assertIsInstance(report, ParseReport)
        self.assertEqual(len(report.results), 2)

        first = report.results[0]
        self.assertEqual(first.ip, "104.21.54.105")
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
            "104.21.54.105,4,4,0.00,438.32,0.00\r\n"
        )
        report = parse_csv_text(text)
        self.assertEqual(len(report.results), 1)
        self.assertIsNone(report.results[0].colo)

    def test_parses_english_header(self):
        text = (
            "IP Address,Sent,Received,Loss,Latency,Download (MB/s),Colo\n"
            "104.21.54.105,4,4,0.00,438.32,0.00,HKG\n"
        )
        report = parse_csv_text(text)
        self.assertEqual(report.results[0].colo, "HKG")
        self.assertAlmostEqual(report.results[0].latency_ms, 438.32)

    def test_tolerates_unparseable_lines(self):
        text = (
            BOM_HEADER + "\r\n"
            "104.21.54.105,4,4,0.00,438.32,0.00,N/A\r\n"
            "this line is broken\r\n"
            "\r\n"
            "not-an-ip,4,4,0.00,1.00,0.00,N/A\r\n"
        )
        report = parse_csv_text(text)
        self.assertEqual(len(report.results), 1)
        self.assertTrue(report.warnings)

    def test_positional_fallback_when_header_unknown(self):
        text = "104.21.54.105,4,4,0.00,438.32,0.00,N/A\n"
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
            BOM_HEADER + "\r\n104.21.54.105,4,4,0.00,438.32,0.00,N/A\r\n",
            encoding="utf-8",
        )
        report = parse_results_csv(path)
        self.assertEqual(len(report.results), 1)
        self.assertEqual(report.results[0].ip, "104.21.54.105")

    def test_undecodable_bytes_are_tolerated(self):
        path = self.dir / "result.csv"
        path.write_bytes(
            BOM_HEADER.encode("utf-8")
            + b"\r\n104.21.54.105,4,4,0.00,438.32,0.00,N/A\r\n\xff\xfe\r\n"
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
            "104.21.54.105,4,4,0.00,438.32,0.00,N/A\r\n"
        )
        picked = recommend(results, preferred_ip="104.21.54.105")
        self.assertEqual(picked.ip, "104.21.54.105")

    def test_recommend_falls_back_to_fastest(self):
        results = self.make(
            BOM_HEADER + "\r\n"
            "1.1.1.9,4,4,0.00,900.00,0.00,N/A\r\n"
            "1.1.1.2,4,4,0.00,100.00,0.00,N/A\r\n"
        )
        picked = recommend(results, preferred_ip="104.21.54.105")
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
        self.assertIsNone(recommend([], preferred_ip="104.21.54.105"))


if __name__ == "__main__":
    unittest.main()

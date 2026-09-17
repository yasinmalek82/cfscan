"""Refreshing the Cloudflare range files.

The lists that ship with the scanner are a snapshot, and a range missing from
the file is simply never scanned. So these tests care most about one thing:
nothing that is not a range list may ever reach the file the scanner reads.
"""

from __future__ import annotations

import io
import unittest
from pathlib import Path

from cfscan import ranges
from cfscan.menu import update_ranges_flow

from tests.support import Fixture

IPV4_LIST = (
    "173.245.48.0/20\n103.21.244.0/22\n103.22.200.0/22\n103.31.4.0/22\n"
    "141.101.64.0/18\n108.162.192.0/18\n190.93.240.0/20\n188.114.96.0/20\n"
    "197.234.240.0/22\n198.41.128.0/17\n162.158.0.0/15\n104.16.0.0/13\n"
    "104.24.0.0/14\n172.64.0.0/13\n131.0.72.0/22\n"
)

IPV6_LIST = (
    "2400:cb00::/32\n2606:4700::/32\n2803:f800::/32\n2405:b500::/32\n"
    "2405:8100::/32\n2a06:98c0::/29\n2c0f:f248::/32\n"
)


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def read(self, size=None):
        return self._payload if size is None else self._payload[:size]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def opener_for(payload, record=None):
    def opener(request, timeout=None):
        if record is not None:
            record.append(request.full_url)
        return _FakeResponse(payload.encode("utf-8")
                             if isinstance(payload, str) else payload)
    return opener


class ParseTests(unittest.TestCase):
    def test_a_published_list_parses_in_order(self):
        found = ranges.parse_ranges(IPV4_LIST, 4)
        self.assertEqual(found[0], "173.245.48.0/20")
        self.assertEqual(len(found), 15)

    def test_the_other_family_is_skipped_not_mangled(self):
        mixed = IPV4_LIST + "2606:4700::/32\n"
        self.assertEqual(len(ranges.parse_ranges(mixed, 4)), 15)

    def test_asking_for_the_wrong_family_is_refused(self):
        with self.assertRaises(ranges.RangeError):
            ranges.parse_ranges(IPV6_LIST, 4)

    def test_a_login_page_is_refused_rather_than_written(self):
        # A captive portal answering the request must never reach the scanner:
        # it aborts the whole run on the first line it cannot parse.
        with self.assertRaises(ranges.RangeError):
            ranges.parse_ranges("<html><body>Sign in</body></html>", 4)

    def test_a_suspiciously_short_list_is_refused(self):
        with self.assertRaises(ranges.RangeError):
            ranges.parse_ranges("104.16.0.0/13\n172.64.0.0/13\n", 4)

    def test_comments_and_blank_lines_are_ignored(self):
        found = ranges.parse_ranges("# Cloudflare\n\n" + IPV4_LIST, 4)
        self.assertEqual(len(found), 15)


class FetchTests(unittest.TestCase):
    def test_the_published_url_is_used_per_family(self):
        seen = []
        ranges.fetch_text(ranges.url_for_version(4), opener=opener_for(IPV4_LIST, seen))
        ranges.fetch_text(ranges.url_for_version(6), opener=opener_for(IPV6_LIST, seen))
        self.assertEqual(seen, [ranges.IPV4_URL, ranges.IPV6_URL])

    def test_a_network_failure_becomes_a_readable_error(self):
        def opener(request, timeout=None):
            raise OSError("Network is unreachable")

        with self.assertRaises(ranges.RangeError) as caught:
            ranges.fetch_text(ranges.IPV4_URL, opener=opener)
        self.assertIn("could not be downloaded", str(caught.exception))

    def test_an_answer_far_too_large_is_refused(self):
        payload = b"x" * (ranges.MAX_DOWNLOAD_BYTES + 10)
        with self.assertRaises(ranges.RangeError):
            ranges.fetch_text(ranges.IPV4_URL, opener=opener_for(payload))


class MergeTests(unittest.TestCase):
    def test_neither_list_is_lost(self):
        # The shipped file is broader in one place and narrower in another, so
        # swapping one for the other drops addresses that answer today.
        mine = ["104.16.0.0/12"]
        published = ["104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13"]
        merged, stats = ranges.merge_ranges(mine, published)
        self.assertIn("104.16.0.0/12", merged)   # kept: covers 104.28-104.31
        self.assertIn("172.64.0.0/13", merged)   # gained
        self.assertGreater(stats["after"], stats["before"])
        self.assertGreater(stats["after"], stats["published"])

    def test_identical_lists_merge_to_themselves(self):
        merged, stats = ranges.merge_ranges(["104.16.0.0/13"], ["104.16.0.0/13"])
        self.assertEqual(merged, ["104.16.0.0/13"])
        self.assertEqual(stats["before"], stats["after"])

    def test_collapsing_into_fewer_entries_never_shrinks_the_area(self):
        # The IPv6 file ships 97 narrow prefixes that sit inside the seven wide
        # ones Cloudflare publishes, so the merge drops to seven entries while
        # covering strictly more.
        mine = ["2606:4700:10::/48", "2606:4700:130::/48"]
        published = ["2606:4700::/32"]
        merged, stats = ranges.merge_ranges(mine, published)
        self.assertEqual(merged, ["2606:4700::/32"])
        self.assertGreater(stats["after"], stats["before"])

    def test_adjacent_ranges_collapse(self):
        merged, _stats = ranges.merge_ranges(["104.16.0.0/14"], ["104.20.0.0/14"])
        self.assertEqual(merged, ["104.16.0.0/13"])

    def test_unreadable_entries_are_skipped(self):
        merged, _stats = ranges.merge_ranges(["nonsense", "104.16.0.0/13"], [])
        self.assertEqual(merged, ["104.16.0.0/13"])


class ReadRangesTests(unittest.TestCase):
    def test_only_the_asked_for_family_comes_back(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        Path(fixture.ipv4).write_text("104.16.0.0/13\n2606:4700::/32\n# note\n\n",
                                      encoding="utf-8")
        self.assertEqual(ranges.read_ranges(fixture.ipv4, 4), ["104.16.0.0/13"])
        self.assertEqual(ranges.read_ranges(fixture.ipv4, 6), ["2606:4700::/32"])

    def test_a_missing_file_is_simply_empty(self):
        self.assertEqual(ranges.read_ranges("/nonexistent/ip.txt", 4), [])


class InstallTests(unittest.TestCase):
    def test_the_previous_file_is_kept_beside_the_new_one(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        target = Path(fixture.ipv4)
        before = target.read_text(encoding="utf-8")
        written, backup = ranges.install_ranges(target,
                                                ranges.parse_ranges(IPV4_LIST, 4))
        self.assertEqual(Path(written), target)
        self.assertEqual(Path(backup).read_text(encoding="utf-8"), before)
        self.assertIn("104.24.0.0/14", target.read_text(encoding="utf-8"))

    def test_the_written_file_holds_ranges_and_nothing_else(self):
        # The scanner parses every line as a range and aborts on one it cannot
        # read, so a header comment would break the next scan.
        fixture = Fixture()
        self.addCleanup(fixture.close)
        ranges.install_ranges(fixture.ipv4, ranges.parse_ranges(IPV4_LIST, 4))
        for line in Path(fixture.ipv4).read_text(encoding="utf-8").splitlines():
            self.assertRegex(line, r"^\d+\.\d+\.\d+\.\d+/\d+$")


class DescribeTests(unittest.TestCase):
    def test_a_missing_file_says_so(self):
        info = ranges.describe_file("/nonexistent/ip.txt")
        self.assertFalse(info["exists"])

    def test_an_existing_file_is_counted_and_dated(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        info = ranges.describe_file(fixture.ipv4)
        self.assertTrue(info["exists"])
        self.assertEqual(info["ranges"], 3)
        self.assertIsNotNone(info["modified"])


class UpdateFlowTests(unittest.TestCase):
    def _fixture(self, answers=("y",)):
        fixture = Fixture(answers=list(answers))
        self.addCleanup(fixture.close)
        return fixture

    def test_both_families_are_updated_and_reported(self):
        fixture = self._fixture()
        payloads = {ranges.IPV4_URL: IPV4_LIST, ranges.IPV6_URL: IPV6_LIST}
        original = ranges.fetch_text
        ranges.fetch_text = lambda url, **kw: payloads[url]
        self.addCleanup(setattr, ranges, "fetch_text", original)

        code = update_ranges_flow(fixture.session, fixture.config)

        self.assertEqual(code, 0)
        self.assertIn("104.24.0.0/14", Path(fixture.ipv4).read_text(encoding="utf-8"))
        self.assertIn("2a06:98c0::/29", Path(fixture.ipv6).read_text(encoding="utf-8"))
        # The ranges the fixture already had are still there afterwards.
        self.assertIn("173.245.48.0/20", Path(fixture.ipv4).read_text(encoding="utf-8"))
        self.assertIn("addresses in range now", fixture.text)
        # An IPv6 address count has thirty digits and means nothing to a
        # reader, so that family is reported in ranges instead.
        self.assertIn("range(s) now", fixture.text)
        self.assertNotRegex(fixture.text, r"\d{20,}")

    def test_a_refused_download_leaves_the_file_untouched(self):
        fixture = self._fixture()
        before = Path(fixture.ipv4).read_text(encoding="utf-8")

        def refuse(url, **kwargs):
            raise ranges.RangeError("the answer was not a range list")

        original = ranges.fetch_text
        ranges.fetch_text = refuse
        self.addCleanup(setattr, ranges, "fetch_text", original)

        code = update_ranges_flow(fixture.session, fixture.config)

        self.assertEqual(code, 1)
        self.assertEqual(Path(fixture.ipv4).read_text(encoding="utf-8"), before)
        self.assertIn("not a range list", fixture.text)

    def test_a_dry_run_downloads_nothing(self):
        fixture = Fixture(dry_run=True)
        self.addCleanup(fixture.close)

        def explode(url, **kwargs):  # pragma: no cover - must never run
            raise AssertionError("a dry run must not download anything")

        original = ranges.fetch_text
        ranges.fetch_text = explode
        self.addCleanup(setattr, ranges, "fetch_text", original)

        self.assertEqual(update_ranges_flow(fixture.session, fixture.config), 0)
        self.assertIn("Dry run", fixture.text)

    def test_declining_the_prompt_changes_nothing(self):
        fixture = Fixture(answers=["n"], tty=True)
        self.addCleanup(fixture.close)
        before = Path(fixture.ipv4).read_text(encoding="utf-8")

        def explode(url, **kwargs):  # pragma: no cover - must never run
            raise AssertionError("nothing may be downloaded after 'n'")

        original = ranges.fetch_text
        ranges.fetch_text = explode
        self.addCleanup(setattr, ranges, "fetch_text", original)

        self.assertEqual(update_ranges_flow(fixture.session, fixture.config), 0)
        self.assertEqual(Path(fixture.ipv4).read_text(encoding="utf-8"), before)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

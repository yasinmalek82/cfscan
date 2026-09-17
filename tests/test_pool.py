"""Tests for the frozen candidate list every carrier round shares.

The whole point of this module is determinism: the scanner draws a fresh sample
from the range file on every run, so a carrier comparison has to fix the list
once and reuse it. If sampling were not reproducible, two carriers would
measure different addresses and the "works everywhere" list could never be
anything but empty.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cfscan.pool import (
    DEFAULT_POOL_SIZE,
    new_pool,
    pool_file_name,
    pool_sha,
    prefixes_in,
    read_pool,
    sample_addresses,
    write_pool,
)

# The shape of the shipped Cloudflare range file: CIDR ranges, CRLF, a comment
# line and a bare address.
RANGES = (
    "# Cloudflare ranges\r\n"
    "173.245.48.0/20\r\n"
    "103.21.244.0/22\r\n"
    "104.21.54.0/24\r\n"
    "162.158.0.1\r\n"
    "not-an-address\r\n"
    "2606:4700::/32\r\n"
    "104.21.54.0/24  # duplicate on purpose\r\n"
)


class PrefixesTests(unittest.TestCase):
    def test_every_range_becomes_24_prefixes(self):
        prefixes = prefixes_in(RANGES)
        # /20 -> 16, /22 -> 4, /24 -> 1, bare address -> 1; duplicates collapse.
        self.assertEqual(len(prefixes), 22)
        self.assertIn("173.245.48.0/24", prefixes)
        self.assertIn("103.21.244.0/24", prefixes)
        self.assertIn("104.21.54.0/24", prefixes)
        self.assertIn("162.158.0.0/24", prefixes)

    def test_unreadable_lines_are_skipped(self):
        prefixes = prefixes_in("junk\n\n#\n104.16.0.0/24\n")
        self.assertEqual(prefixes, ["104.16.0.0/24"])

    def test_ipv6_only_input_yields_nothing(self):
        self.assertEqual(prefixes_in("2606:4700::/32\n"), [])

    def test_a_huge_range_is_sampled_instead_of_enumerated(self):
        prefixes = prefixes_in("10.0.0.0/8\n")
        self.assertTrue(prefixes)
        self.assertLessEqual(len(prefixes), 8192)


class SamplingTests(unittest.TestCase):
    def test_the_same_seed_always_gives_the_same_addresses(self):
        first = sample_addresses(["104.16.0.0/24"], per_prefix=4, seed=99)
        second = sample_addresses(["104.16.0.0/24"], per_prefix=4, seed=99)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 4)

    def test_another_seed_gives_other_addresses(self):
        first = sample_addresses(["104.16.0.0/24"], per_prefix=4, seed=1)
        second = sample_addresses(["104.16.0.0/24"], per_prefix=4, seed=2)
        self.assertNotEqual(first, second)

    def test_samples_stay_inside_their_prefix(self):
        prefixes = ["104.16.0.0/24", "172.64.5.0/24"]
        addresses = sample_addresses(prefixes, per_prefix=6, seed=3)
        for address in addresses:
            self.assertTrue(address.startswith("104.16.0.") or
                            address.startswith("172.64.5."), address)
        # Host 0 and 255 are never used.
        self.assertNotIn("104.16.0.0", addresses)
        self.assertNotIn("104.16.0.255", addresses)

    def test_no_prefixes_means_no_addresses(self):
        self.assertEqual(sample_addresses([], per_prefix=8, seed=1), [])


class PoolTests(unittest.TestCase):
    def test_a_pool_has_the_requested_size_and_the_requested_prefixes(self):
        pool = new_pool(RANGES, size=40, per_prefix=4, seed=7)
        self.assertEqual(len(pool["addresses"]), 40)
        self.assertEqual(pool["prefixes"], 10)
        self.assertEqual(len(set(pool["addresses"])), 40)

    def test_the_same_seed_rebuilds_the_very_same_pool(self):
        first = new_pool(RANGES, size=24, per_prefix=8, seed=11)
        second = new_pool(RANGES, size=24, per_prefix=8, seed=11)
        self.assertEqual(first["addresses"], second["addresses"])
        self.assertEqual(first["sha256"], second["sha256"])

    def test_a_different_seed_gives_a_different_fingerprint(self):
        first = new_pool(RANGES, size=24, per_prefix=8, seed=11)
        second = new_pool(RANGES, size=24, per_prefix=8, seed=12)
        self.assertNotEqual(first["sha256"], second["sha256"])

    def test_a_pool_never_exceeds_what_the_ranges_offer(self):
        pool = new_pool(RANGES, size=DEFAULT_POOL_SIZE, per_prefix=8, seed=5)
        self.assertEqual(pool["addresses"], sorted(pool["addresses"], key=_as_int))
        self.assertEqual(len(pool["addresses"]), pool["prefixes"] * 8)
        self.assertLess(len(pool["addresses"]), DEFAULT_POOL_SIZE)

    def test_an_unusable_range_file_is_reported(self):
        with self.assertRaises(ValueError):
            new_pool("# nothing here\n", size=10)

    def test_the_file_name_follows_the_fingerprint(self):
        pool = new_pool(RANGES, size=16, per_prefix=8, seed=2)
        name = pool_file_name(pool)
        self.assertTrue(name.startswith("pool-"))
        self.assertTrue(name.endswith(".txt"))
        self.assertIn(pool["sha256"][:16], name)

    def test_the_fingerprint_ignores_the_order_of_the_list(self):
        self.assertEqual(pool_sha(["1.1.1.1", "2.2.2.2"]),
                         pool_sha(["2.2.2.2", "1.1.1.1"]))
        self.assertNotEqual(pool_sha(["1.1.1.1"]), pool_sha(["1.1.1.2"]))


class PoolFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name) / "pools"

    def test_a_pool_survives_a_round_trip(self):
        pool = new_pool(RANGES, size=16, per_prefix=4, seed=4)
        path = write_pool(self.directory, pool)
        self.assertTrue(path.exists())
        self.assertEqual(read_pool(path), pool["addresses"])

    def test_the_file_holds_addresses_and_nothing_else(self):
        # The scanner parses this file as a CIDR list and aborts the whole run on
        # a line it cannot read: a real run died with code 1 on the comment line
        # this file used to carry ("ParseCIDR err ... # cfscan candidate pool ...").
        pool = new_pool(RANGES, size=8, per_prefix=4, seed=1)
        path = write_pool(self.directory, pool)
        text = path.read_text(encoding="utf-8")
        self.assertNotIn("#", text)
        lines = text.splitlines()
        self.assertEqual(len(lines), 8)
        for line in lines:
            self.assertEqual(len(line.split(".")), 4)
            self.assertTrue(line.replace(".", "").isdigit(), line)

    def test_a_hand_written_list_with_comments_is_still_read(self):
        path = Path(self.tmp.name) / "mine.txt"
        path.write_text("# my own list\n104.16.0.1\n\n172.64.0.2  # keep\n",
                        encoding="utf-8")
        self.assertEqual(read_pool(path), ["104.16.0.1", "172.64.0.2"])

    def test_the_same_pool_lands_in_the_same_file(self):
        pool = new_pool(RANGES, size=8, per_prefix=4, seed=6)
        first = write_pool(self.directory, pool)
        second = write_pool(self.directory, pool)
        self.assertEqual(first, second)


def _as_int(address):
    parts = [int(item) for item in str(address).split(".")]
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

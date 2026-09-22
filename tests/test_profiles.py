"""Tests for configuration and profile storage."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cfscan.profiles import (
    is_placeholder,
    DEFAULT_PROFILE_KEY,
    Paths,
    atomic_write_json,
    default_profile,
    delete_profile,
    get_active,
    load_config,
    new_config,
    profile_slug,
    save_config,
    set_active,
    upsert_profile,
)

from tests.support import read_config, write_config, write_fake_cfst, write_ip_ranges


class PathsTests(unittest.TestCase):
    def test_derives_expected_locations(self):
        paths = Paths(home=Path("/Users/example"))
        self.assertEqual(
            Path(paths.config_file), Path("/Users/example/.config/cfscan/config.json")
        )
        self.assertEqual(
            Path(paths.results_dir),
            Path("/Users/example/Documents/Cloudflare Scanner Results"),
        )


class DefaultProfileTests(unittest.TestCase):
    def test_default_profile_matches_specification(self):
        profile = default_profile()
        # A fresh installation must not point at anybody's real server: a scan
        # would send thousands of requests to whatever domain is configured.
        self.assertEqual(profile["domain"], "example.com")
        self.assertTrue(is_placeholder(profile))
        self.assertEqual(profile["port"], 443)
        self.assertEqual(profile["mode"], "httping")
        self.assertEqual(profile["scheme"], "https")
        self.assertEqual(profile["http_status"], 400)
        self.assertEqual(profile["ip_version"], 4)
        self.assertEqual(profile["attempts"], 4)
        self.assertEqual(profile["concurrency"], 200)
        self.assertAlmostEqual(profile["max_loss"], 0.25)
        self.assertEqual(profile["max_latency_ms"], 1000)
        self.assertEqual(profile["results_limit"], 20)
        self.assertFalse(profile["download_test"])
        self.assertEqual(profile["download_url"], "")
        self.assertFalse(profile["upload_test"])
        self.assertTrue(profile["jitter_test"])
        self.assertEqual(profile["jitter_samples"], 6)
        self.assertIsNone(profile["recommended_ip"])
        self.assertEqual(profile["verify_attempts"], 20)

    def test_default_profile_has_no_secret_fields(self):
        blob = json.dumps(default_profile()).lower()
        for forbidden in ("uuid", "password", "private_key", "secret", "subscription"):
            self.assertNotIn(forbidden, blob)


class LoadConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.paths = Paths(home=self.root)

    def test_creates_config_with_defaults(self):
        config = load_config(self.paths)
        self.assertIn(DEFAULT_PROFILE_KEY, config["profiles"])
        self.assertEqual(config["active_profile"], DEFAULT_PROFILE_KEY)
        self.assertTrue(Path(self.paths.config_file).exists())

    def test_creates_parent_directories(self):
        load_config(self.paths)
        self.assertTrue(Path(self.paths.config_dir).is_dir())

    def test_preserves_existing_values_and_unknown_keys(self):
        write_config(
            self.paths,
            {
                "version": 1,
                "active_profile": "custom",
                "custom_tool_key": {"keep": "me"},
                "profiles": {
                    "custom": {
                        "domain": "example.com",
                        "port": 443,
                        "extra_field": True,
                    }
                },
            },
        )
        config = load_config(self.paths)
        self.assertEqual(config["custom_tool_key"], {"keep": "me"})
        self.assertEqual(config["active_profile"], "custom")
        self.assertEqual(config["profiles"]["custom"]["domain"], "example.com")
        self.assertIn("extra_field", config["profiles"]["custom"])

    def test_incomplete_profile_is_filled_from_defaults(self):
        write_config(
            self.paths,
            {"active_profile": "custom", "profiles": {"custom": {"domain": "example.com"}}},
        )
        config = load_config(self.paths)
        profile = config["profiles"]["custom"]
        self.assertEqual(profile["domain"], "example.com")
        self.assertEqual(profile["port"], 443)
        self.assertEqual(profile["attempts"], 4)

    def test_corrupt_config_is_backed_up_and_replaced(self):
        path = write_config(self.paths, {})
        path.write_text("{ this is not json", encoding="utf-8")
        config = load_config(self.paths)
        self.assertIn(DEFAULT_PROFILE_KEY, config["profiles"])
        backups = list(Path(self.paths.config_dir).glob("config.json.corrupt-*"))
        self.assertEqual(len(backups), 1)

    def test_dangling_active_profile_falls_back_to_default(self):
        write_config(self.paths, {"active_profile": "ghost", "profiles": {}})
        config = load_config(self.paths)
        self.assertIn(config["active_profile"], config["profiles"])

    def test_a_deleted_shipped_profile_stays_deleted(self):
        # It used to be re-added on every load, so a profile the user deleted
        # on purpose came back every time the configuration was read.
        write_config(
            self.paths,
            {"active_profile": "mine",
             "profiles": {"mine": {"domain": "mine.test"}}},
        )
        config = load_config(self.paths)
        self.assertNotIn(DEFAULT_PROFILE_KEY, config["profiles"])
        self.assertEqual(config["active_profile"], "mine")

    def test_a_profile_always_exists_when_none_is_left(self):
        write_config(self.paths, {"active_profile": "gone", "profiles": {}})
        config = load_config(self.paths)
        self.assertIn(DEFAULT_PROFILE_KEY, config["profiles"])
        self.assertEqual(config["active_profile"], DEFAULT_PROFILE_KEY)


class AtomicWriteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_writes_file_and_leaves_no_temp_files(self):
        target = self.root / "config.json"
        atomic_write_json(target, {"a": 1})
        self.assertEqual(json.loads(target.read_text(encoding="utf-8")), {"a": 1})
        leftovers = [p.name for p in self.root.iterdir() if p.name != "config.json"]
        self.assertEqual(leftovers, [])

    def test_creates_directories(self):
        target = self.root / "deep" / "nested" / "config.json"
        atomic_write_json(target, {"a": 1})
        self.assertTrue(target.exists())

    def test_failure_keeps_previous_content(self):
        target = self.root / "config.json"
        atomic_write_json(target, {"a": 1})
        with mock.patch("cfscan.profiles.os.replace", side_effect=OSError("boom")):
            with self.assertRaises(OSError):
                atomic_write_json(target, {"a": 2})
        self.assertEqual(json.loads(target.read_text(encoding="utf-8")), {"a": 1})
        self.assertEqual(
            [p.name for p in self.root.iterdir() if p.name != "config.json"], []
        )

    def test_writes_restrictive_permissions(self):
        target = self.root / "config.json"
        atomic_write_json(target, {"a": 1})
        mode = target.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)


class ProfileMutationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.paths = Paths(home=Path(self.tmp.name))
        self.config = load_config(self.paths)

    def test_upsert_adds_and_edits(self):
        upsert_profile(self.config, "office", {"domain": "office.example.com", "port": 8443})
        save_config(self.paths, self.config)
        saved = read_config(self.paths)
        self.assertEqual(saved["profiles"]["office"]["port"], 8443)
        self.assertEqual(saved["profiles"]["office"]["attempts"], 4)

        upsert_profile(self.config, "office", {"port": 2053})
        self.assertEqual(self.config["profiles"]["office"]["port"], 2053)
        self.assertEqual(
            self.config["profiles"]["office"]["domain"], "office.example.com"
        )

    def test_get_active_and_set_active(self):
        name, profile = get_active(self.config)
        self.assertEqual(name, DEFAULT_PROFILE_KEY)
        self.assertEqual(profile["domain"], "example.com")

        upsert_profile(self.config, "second", {"domain": "second.example.com"})
        set_active(self.config, "second")
        self.assertEqual(get_active(self.config)[0], "second")
        with self.assertRaises(KeyError):
            set_active(self.config, "missing")

    def test_delete_profile(self):
        upsert_profile(self.config, "temp", {"domain": "temp.example.com"})
        self.assertTrue(delete_profile(self.config, "temp"))
        self.assertNotIn("temp", self.config["profiles"])
        self.assertFalse(delete_profile(self.config, "temp"))

    def test_delete_active_profile_moves_active_pointer(self):
        upsert_profile(self.config, "temp", {"domain": "temp.example.com"})
        set_active(self.config, "temp")
        delete_profile(self.config, "temp")
        self.assertIn(self.config["active_profile"], self.config["profiles"])


class ProfileSlugTests(unittest.TestCase):
    def test_makes_safe_filenames(self):
        self.assertEqual(profile_slug("node.example.test"), "node-example-test")
        self.assertEqual(profile_slug("My Profile!"), "my-profile")
        self.assertEqual(profile_slug("  "), "profile")

    def test_never_contains_path_separators(self):
        slug = profile_slug("../../etc/passwd")
        self.assertNotIn("/", slug)
        self.assertNotIn("..", slug)


class IpFileSelectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_profile_uses_version_specific_range_file(self):
        from cfscan.profiles import ip_file_for

        ipv4 = write_ip_ranges(self.root / "ip.txt")
        ipv6 = write_ip_ranges(self.root / "ipv6.txt")
        profile = {"ip_version": 4, "ip_file": str(ipv4), "ipv6_file": str(ipv6)}
        self.assertEqual(Path(ip_file_for(profile)), ipv4)
        profile["ip_version"] = 6
        self.assertEqual(Path(ip_file_for(profile)), ipv6)

    def test_new_config_detects_installed_cfst(self):
        binary = write_fake_cfst(self.root)
        config = new_config(cfst_path=str(binary))
        self.assertEqual(config["cfst_path"], str(binary))


if __name__ == "__main__":
    unittest.main()

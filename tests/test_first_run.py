"""What a fresh installation does before anybody has configured anything.

This matters more than it looks. A scan measures thousands of addresses against
whatever domain the active profile names, so a default pointing at a real
server would turn every installation of this tool into traffic aimed at that
server - and would tell every user a domain that is none of their business.
"""

from __future__ import annotations

import unittest

from cfscan.menu import custom_scan, quick_scan, render_menu
from cfscan.profiles import (
    DEFAULT_PROFILE_KEY,
    default_profile,
    is_placeholder,
    new_config,
)

from tests.support import Fixture, ScriptedSpawn


class ShippedDefaultTests(unittest.TestCase):
    def test_the_shipped_profile_names_nobody(self):
        profile = default_profile()
        self.assertTrue(is_placeholder(profile))
        self.assertIsNone(profile["recommended_ip"])
        # example.com is reserved by RFC 2606 exactly so it cannot be anyone's.
        self.assertEqual(profile["domain"], "example.com")

    def test_no_real_hostname_or_address_is_shipped(self):
        # A guard against a real target creeping back into the defaults.
        blob = repr(new_config(cfst_path="/bin/true"))
        for leak in (".ir", ".io", "104.21.", "172.6", "vpn", "node."):
            self.assertNotIn(leak, blob)

    def test_a_configured_profile_is_not_a_placeholder(self):
        self.assertFalse(is_placeholder({"domain": "node.example.test"}))
        self.assertFalse(is_placeholder({}))
        self.assertFalse(is_placeholder(None))

    def test_placeholder_matching_ignores_case_and_spacing(self):
        self.assertTrue(is_placeholder({"domain": "  Example.COM "}))


class RefusesToScanThePlaceholderTests(unittest.TestCase):
    def placeholder_fixture(self, answers=()):
        fixture = Fixture(answers=answers, spawn=ScriptedSpawn())
        self.addCleanup(fixture.close)
        # Undo the target the fixture hands out, back to what ships.
        fixture.profile().update(default_profile())
        fixture.profile()["ip_file"] = str(fixture.ipv4)
        fixture.save()
        return fixture

    def test_a_quick_scan_stops_before_the_scanner_is_started(self):
        fixture = self.placeholder_fixture()
        fixture.session.assume_yes = True

        code = quick_scan(fixture.session, fixture.config, verify_prompt=False)

        self.assertEqual(code, 2)
        self.assertEqual(fixture.spawn.calls, [])
        text = fixture.text
        self.assertIn("still points at example.com", text)
        self.assertIn("menu 6, option 3", text.lower())

    def test_every_scanning_flow_refuses_it(self):
        # A guard against a flow being added later that scans without checking.
        from cfscan.menu import custom_scan, multi_isp_flow, multi_isp_round

        for flow, kwargs in ((quick_scan, {"verify_prompt": False}),
                             (multi_isp_flow, {}),
                             (multi_isp_round, {"isp": "alfa"})):
            fixture = self.placeholder_fixture()
            fixture.session.assume_yes = True
            code = flow(fixture.session, fixture.config, **kwargs)
            self.assertEqual(code, 2, flow.__name__)
            self.assertEqual(fixture.spawn.calls, [], flow.__name__)
            self.assertIn("still points at example.com", fixture.text,
                          flow.__name__)

    def test_the_menu_says_so_before_anything_is_chosen(self):
        fixture = self.placeholder_fixture()
        render_menu(fixture.session, fixture.config)
        self.assertIn("Not set up yet", fixture.text)

    def test_a_configured_profile_is_never_flagged(self):
        fixture = Fixture(spawn=ScriptedSpawn())
        self.addCleanup(fixture.close)
        render_menu(fixture.session, fixture.config)
        self.assertNotIn("Not set up yet", fixture.text)


class TheShippedProfileIsDeletableTests(unittest.TestCase):
    def test_it_does_not_come_back_once_another_profile_exists(self):
        from cfscan.profiles import delete_profile, load_config, save_config

        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.config["profiles"]["mine"] = dict(default_profile(),
                                                  domain="mine.example.test")
        fixture.config["active_profile"] = "mine"
        self.assertTrue(delete_profile(fixture.config, DEFAULT_PROFILE_KEY))
        save_config(fixture.paths, fixture.config)

        reloaded = load_config(fixture.paths)

        self.assertNotIn(DEFAULT_PROFILE_KEY, reloaded["profiles"])
        self.assertEqual(reloaded["active_profile"], "mine")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

"""The IPv6 capability check, and the two places it speaks up.

An IPv6 scan on a machine without an IPv6 route can only ever return nothing,
and the empty result looks exactly like a broken profile. Measured on this Mac:
the scanner accepts an IPv6 range file and reports "0 of 2 reachable" while
``curl -6`` fails instantly with "No route to host". The check below finds that
out without sending a packet (a UDP ``connect`` only consults the routing
table), so cfscan can say why before the scan and after an empty one.
"""

from __future__ import annotations

import socket
import unittest
from unittest import mock

from cfscan.menu import quick_scan, switch_ip_version
from cfscan.runner import ipv6_route_available

from tests.support import LOG_NO_RESULTS, Fixture, ScriptedSpawn


class RouteCheckTests(unittest.TestCase):
    def test_a_missing_route_is_reported_as_unavailable(self):
        fake = mock.Mock()
        fake.connect.side_effect = OSError(65, "No route to host")
        with mock.patch("cfscan.runner.socket.socket", return_value=fake):
            self.assertFalse(ipv6_route_available())
        fake.close.assert_called_once()

    def test_a_present_route_is_reported_as_available(self):
        fake = mock.Mock()
        with mock.patch("cfscan.runner.socket.socket", return_value=fake):
            self.assertTrue(ipv6_route_available())
        # The probe address is the argument, so the check really is IPv6.
        args, _kwargs = fake.connect.call_args
        self.assertTrue(str(args[0][0]).startswith("2606:4700"))

    def test_a_machine_without_ipv6_sockets_is_not_an_error(self):
        with mock.patch("cfscan.runner.socket.socket",
                        side_effect=OSError("address family not supported")):
            self.assertFalse(ipv6_route_available())

    def test_the_real_check_runs_on_this_machine(self):
        # Whatever the answer here, the call must not raise and must be a bool.
        self.assertIsInstance(ipv6_route_available(timeout=0.2), bool)

    def test_it_uses_a_datagram_socket_so_nothing_is_sent(self):
        with mock.patch("cfscan.runner.socket.socket") as factory:
            factory.return_value = mock.Mock()
            ipv6_route_available()
        family, kind = factory.call_args[0]
        self.assertEqual(family, socket.AF_INET6)
        self.assertEqual(kind, socket.SOCK_DGRAM)


class SwitchFlowTests(unittest.TestCase):
    def test_switching_to_ipv6_warns_when_there_is_no_route(self):
        fixture = Fixture(answers=["6", "y"], spawn=ScriptedSpawn())
        self.addCleanup(fixture.close)
        with mock.patch("cfscan.menu.ipv6_route_available", return_value=False):
            self.assertEqual(switch_ip_version(fixture.session, fixture.config), 0)
        text = fixture.text
        self.assertIn("no route to an IPv6 address", text)
        self.assertIn("ifconfig | grep inet6", text)
        self.assertIn("menu 7 switches back to IPv4", text)

    def test_switching_to_ipv6_is_silent_when_the_route_exists(self):
        fixture = Fixture(answers=["6", "y"], spawn=ScriptedSpawn())
        self.addCleanup(fixture.close)
        with mock.patch("cfscan.menu.ipv6_route_available", return_value=True):
            self.assertEqual(switch_ip_version(fixture.session, fixture.config), 0)
        self.assertNotIn("no route to an IPv6 address", fixture.text)

    def test_switching_back_to_ipv4_never_mentions_ipv6_routes(self):
        fixture = Fixture(answers=["4", "y"], spawn=ScriptedSpawn())
        self.addCleanup(fixture.close)
        fixture.config["profiles"][fixture.config["active_profile"]]["ip_version"] = 6
        with mock.patch("cfscan.menu.ipv6_route_available", return_value=False):
            switch_ip_version(fixture.session, fixture.config)
        self.assertNotIn("no route to an IPv6 address", fixture.text)


class EmptyScanExplanationTests(unittest.TestCase):
    def test_an_empty_ipv6_scan_says_why(self):
        spawn = ScriptedSpawn(log_text=LOG_NO_RESULTS, create_csv=False)
        fixture = Fixture(answers=["y"], spawn=spawn)
        self.addCleanup(fixture.close)
        fixture.config["profiles"][fixture.config["active_profile"]]["ip_version"] = 6
        with mock.patch("cfscan.menu.ipv6_route_available", return_value=False):
            quick_scan(fixture.session, fixture.config, verify_prompt=False)
        text = fixture.text
        self.assertIn("scans IPv6 and this Mac has no route", text)
        # The line wraps at 96 columns, so match a phrase that stays together.
        self.assertIn("IPv4 in menu 7", text)

    def test_an_empty_ipv4_scan_does_not_mention_ipv6(self):
        spawn = ScriptedSpawn(log_text=LOG_NO_RESULTS, create_csv=False)
        fixture = Fixture(answers=["y"], spawn=spawn)
        self.addCleanup(fixture.close)
        with mock.patch("cfscan.menu.ipv6_route_available", return_value=False):
            quick_scan(fixture.session, fixture.config, verify_prompt=False)
        self.assertNotIn("scans IPv6", fixture.text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

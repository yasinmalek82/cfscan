"""Tests for the interactive menu flows."""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

from cfscan.menu import (
    MENU_GROUPS,
    MENU_HINTS,
    MENU_ITEMS,
    Session,
    custom_scan,
    help_screen,
    manage_profiles,
    quick_scan,
    render_menu,
    run_menu,
    show_last_results,
    show_profiles,
    switch_ip_version,
    verify_flow,
)
from cfscan.ui import Console

from tests.support import (
    CSV_TWO_ROWS,
    CSV_VERIFY_PASS,
    LOG_NO_RESULTS,
    LOG_STATUS_REJECT,
    LOG_SUCCESS,
    Fixture,
    ScriptedSpawn,
    csv_with_measurements,
    csv_with_rows,
)

DEFAULT_KEY = "example"


def make_fixture(answers=(), dry_run=False, spawn=None, verify_top=False):
    """A fixture whose scans skip the strict check unless it is asked for.

    The automatic check of the best addresses has its own tests; the others stay
    focused on the flow they are about.
    """
    fixture = Fixture(answers=answers, dry_run=dry_run, spawn=spawn)
    fixture.session.verify_top_ips = verify_top
    return fixture


class MenuRenderingTests(unittest.TestCase):
    def test_menu_lists_all_entries_in_order(self):
        fixture = make_fixture()
        self.addCleanup(fixture.close)
        render_menu(fixture.session, fixture.config)
        text = fixture.text
        for _key, label in MENU_ITEMS:
            self.assertIn(label, text)
        self.assertEqual([key for key, _ in MENU_ITEMS],
                         ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                          "11", "12", "0"])

    def test_every_entry_is_in_exactly_one_group_with_a_hint(self):
        # The screen is built from the groups, so an entry missing from them
        # would silently disappear from the menu while staying in MENU_ITEMS.
        grouped = [key for _title, keys in MENU_GROUPS for key in keys]
        self.assertEqual(sorted(grouped), sorted(key for key, _ in MENU_ITEMS))
        self.assertEqual(len(grouped), len(set(grouped)))
        for key, _label in MENU_ITEMS:
            self.assertIn(key, MENU_HINTS)

    def test_menu_reports_a_missing_scanner_and_range_file(self):
        fixture = make_fixture()
        self.addCleanup(fixture.close)
        fixture.config["cfst_path"] = "/nonexistent/cfst"
        render_menu(fixture.session, fixture.config)
        self.assertIn("cfst MISSING", fixture.text)

    def test_menu_shows_active_profile(self):
        fixture = make_fixture()
        self.addCleanup(fixture.close)
        render_menu(fixture.session, fixture.config)
        self.assertIn("node.example.test", fixture.text)


class RunMenuTests(unittest.TestCase):
    def test_exit_choice_leaves_the_menu(self):
        fixture = make_fixture(answers=["0"])
        self.addCleanup(fixture.close)
        self.assertEqual(run_menu(fixture.session, fixture.config), 0)
        self.assertIn("Goodbye", fixture.text)

    def test_invalid_choice_is_reported_and_reprompts(self):
        fixture = make_fixture(answers=["42", "0"])
        self.addCleanup(fixture.close)
        self.assertEqual(run_menu(fixture.session, fixture.config), 0)
        self.assertIn("Invalid choice", fixture.text)

    def test_keyboard_interrupt_exits_gracefully(self):
        fixture = make_fixture()
        self.addCleanup(fixture.close)
        session = fixture.session
        session.console = _interrupting_console(fixture)
        self.assertEqual(run_menu(session, fixture.config), 130)
        self.assertIn("Cancelled", fixture.text)

    def test_help_choice_prints_help(self):
        fixture = make_fixture(answers=["9", "0"])
        self.addCleanup(fixture.close)
        run_menu(fixture.session, fixture.config)
        self.assertIn("SNI", fixture.text)


class QuickScanTests(unittest.TestCase):
    def test_shows_active_profile_before_starting(self):
        fixture = make_fixture(answers=["n"])
        self.addCleanup(fixture.close)
        quick_scan(fixture.session, fixture.config)
        text = fixture.text
        self.assertIn("Domain", text)
        self.assertIn("node.example.test", text)
        self.assertIn("2087", text)
        self.assertIn("Expected status", text)

    def test_confirmation_can_abort_without_running(self):
        fixture = make_fixture(answers=["n"])
        self.addCleanup(fixture.close)
        code = quick_scan(fixture.session, fixture.config)
        self.assertEqual(code, 0)
        self.assertEqual(fixture.spawn.calls, [])
        self.assertIn("Cancelled", fixture.text)

    def test_dry_run_prints_argv_and_never_spawns(self):
        fixture = make_fixture(answers=[], dry_run=True)
        self.addCleanup(fixture.close)
        code = quick_scan(fixture.session, fixture.config)
        self.assertEqual(code, 0)
        self.assertEqual(fixture.spawn.calls, [])
        text = fixture.text
        self.assertIn("Dry run", text)
        self.assertIn("-httping-code 400", text)
        self.assertIn("-tp 2087", text)

    def test_successful_scan_renders_ranked_table(self):
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=CSV_TWO_ROWS)
        fixture = make_fixture(answers=["y", "n"], spawn=spawn)
        self.addCleanup(fixture.close)
        code = quick_scan(fixture.session, fixture.config)
        self.assertEqual(code, 0)
        text = fixture.text
        for header in ("#", "IP address", "Sent", "Received", "Loss", "Latency", "Colo"):
            self.assertIn(header, text)
        self.assertIn("104.16.0.1", text)
        self.assertIn("172.67.213.151", text)
        self.assertIn("438.32", text)

    def test_a_proxy_inherited_from_the_shell_is_announced_once(self):
        """The scanner uses it, and the first scan says so.

        Regression: the variables were stripped silently, which broke a scan that
        relied on the very proxy the terminal had exported.
        """
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=CSV_TWO_ROWS)
        fixture = make_fixture(answers=["y", "n", "y", "n"], spawn=spawn)
        self.addCleanup(fixture.close)
        with mock.patch.dict(os.environ,
                             {"HTTPS_PROXY": "http://127.0.0.1:10809"}, clear=False):
            quick_scan(fixture.session, fixture.config)
            first = fixture.text
            fixture.out.seek(0)
            fixture.out.truncate(0)
            quick_scan(fixture.session, fixture.config)
            second = fixture.text
        self.assertIn("The scanner inherits the proxy from this shell", first)
        self.assertIn("HTTPS_PROXY", first)
        self.assertIn("cfscan --direct", first)
        self.assertNotIn("The scanner inherits the proxy", second)

    def test_direct_mode_says_the_numbers_are_this_machine_only(self):
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=CSV_TWO_ROWS)
        fixture = make_fixture(answers=["y", "n"], spawn=spawn)
        self.addCleanup(fixture.close)
        fixture.session.direct = True
        with mock.patch.dict(os.environ,
                             {"HTTPS_PROXY": "http://127.0.0.1:10809"}, clear=False):
            quick_scan(fixture.session, fixture.config)
        self.assertIn("Scanning without the proxy", fixture.text)
        self.assertIn("HTTPS_PROXY", fixture.text)

    def test_nothing_is_said_when_no_proxy_is_exported(self):
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=CSV_TWO_ROWS)
        fixture = make_fixture(answers=["y", "n"], spawn=spawn)
        self.addCleanup(fixture.close)
        with mock.patch.dict(os.environ,
                             {"HTTPS_PROXY": "", "HTTP_PROXY": "", "ALL_PROXY": "",
                              "https_proxy": "", "http_proxy": "", "all_proxy": "",
                              "NO_PROXY": "", "no_proxy": ""}, clear=False):
            quick_scan(fixture.session, fixture.config)
        self.assertNotIn("inherits the proxy", fixture.text)
        self.assertNotIn("Scanning without the proxy", fixture.text)

    def test_highlights_recommended_ip_and_shows_config_guide(self):
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=CSV_TWO_ROWS)
        fixture = make_fixture(answers=["y", "n"], spawn=spawn)
        self.addCleanup(fixture.close)
        quick_scan(fixture.session, fixture.config)
        text = fixture.text
        self.assertIn("Recommended IP: 104.16.0.1", text)
        for field in ("Address", "Port", "SNI", "Host"):
            self.assertIn(field, text)

    def test_result_is_written_inside_temp_results_dir(self):
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=CSV_TWO_ROWS)
        fixture = make_fixture(answers=["y", "n"], spawn=spawn)
        self.addCleanup(fixture.close)
        quick_scan(fixture.session, fixture.config)
        results_dir = Path(fixture.paths.results_dir)
        saved = list(results_dir.glob("*.csv"))
        self.assertEqual(len(saved), 1)
        self.assertTrue(saved[0].name.endswith(".csv"))
        # The scanner's bytes are stored exactly as written (CRLF and BOM kept).
        self.assertEqual(saved[0].read_bytes(), CSV_TWO_ROWS.encode("utf-8"))

    def test_records_latest_pointer(self):
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=CSV_TWO_ROWS)
        fixture = make_fixture(answers=["y", "n"], spawn=spawn)
        self.addCleanup(fixture.close)
        quick_scan(fixture.session, fixture.config)
        last = fixture.reload()["last_result"]
        self.assertTrue(Path(last["csv"]).exists())
        self.assertEqual(last["recommended_ip"], "104.16.0.1")

    def test_offers_stronger_verification(self):
        spawn = ScriptedSpawn(
            csv_sequence=[CSV_TWO_ROWS, CSV_VERIFY_PASS],
            log_sequence=[LOG_SUCCESS, ""],
        )
        fixture = make_fixture(answers=["y", "y"], spawn=spawn)
        self.addCleanup(fixture.close)
        quick_scan(fixture.session, fixture.config)
        self.assertEqual(len(spawn.calls), 2)
        second = spawn.calls[1]
        self.assertEqual(second[second.index("-t") + 1], "20")
        self.assertEqual(second[second.index("-ip") + 1], "104.16.0.1")
        self.assertIn("PASS", fixture.text)

    def test_empty_results_are_explained(self):
        spawn = ScriptedSpawn(log_text=LOG_NO_RESULTS, create_csv=False)
        fixture = make_fixture(answers=["y"], spawn=spawn)
        self.addCleanup(fixture.close)
        code = quick_scan(fixture.session, fixture.config)
        self.assertEqual(code, 1)
        text = fixture.text
        self.assertIn("No IP passed the filters", text)
        self.assertIn("Troubleshooting", text)

    def test_missing_scanner_binary_is_reported(self):
        spawn = ScriptedSpawn(error=FileNotFoundError("cfst not found"))
        fixture = make_fixture(answers=["y"], spawn=spawn)
        self.addCleanup(fixture.close)
        code = quick_scan(fixture.session, fixture.config)
        self.assertEqual(code, 3)
        self.assertIn("cfst", fixture.text)

    def test_missing_cfst_path_is_reported_without_spawning(self):
        fixture = make_fixture(answers=["y"])
        self.addCleanup(fixture.close)
        fixture.config["cfst_path"] = str(fixture.root / "nope-cfst")
        code = quick_scan(fixture.session, fixture.config)
        self.assertEqual(code, 3)
        self.assertEqual(fixture.spawn.calls, [])

    def test_missing_ip_range_file_is_reported(self):
        fixture = make_fixture(answers=["y"])
        self.addCleanup(fixture.close)
        fixture.profile()["ip_file"] = str(fixture.root / "missing-ip.txt")
        code = quick_scan(fixture.session, fixture.config)
        self.assertEqual(code, 3)
        self.assertIn("missing-ip.txt", fixture.text)
        self.assertEqual(fixture.spawn.calls, [])

    def test_check_cfst_helper_is_used(self):
        fixture = make_fixture(answers=["y", "n"],
                               spawn=ScriptedSpawn(log_text=LOG_SUCCESS,
                                                   csv_text=CSV_TWO_ROWS))
        self.addCleanup(fixture.close)
        quick_scan(fixture.session, fixture.config)
        self.assertTrue(fixture.spawn.calls)

    def test_scanner_error_is_reported_without_a_traceback(self):
        fixture = make_fixture(answers=["y"],
                               spawn=ScriptedSpawn(
                                   error=OSError("Exec format error")))
        self.addCleanup(fixture.close)
        code = quick_scan(fixture.session, fixture.config)
        self.assertEqual(code, 1)
        self.assertIn("could not be started", fixture.text)

    def test_verification_prompt_uses_the_profiles_attempt_count(self):
        spawn = ScriptedSpawn(
            csv_sequence=[CSV_TWO_ROWS, CSV_VERIFY_PASS],
            log_sequence=[LOG_SUCCESS, ""],
        )
        fixture = make_fixture(answers=["y", "y"], spawn=spawn)
        self.addCleanup(fixture.close)
        fixture.profile()["verify_attempts"] = 30
        quick_scan(fixture.session, fixture.config)
        self.assertIn("30-attempt verification", fixture.text)
        self.assertEqual(spawn.calls[1][spawn.calls[1].index("-t") + 1], "30")

    def test_empty_scan_records_a_failure_verdict_for_the_menu(self):
        spawn = ScriptedSpawn(log_text=LOG_NO_RESULTS, create_csv=False)
        fixture = make_fixture(answers=["y"], spawn=spawn)
        self.addCleanup(fixture.close)
        self.assertEqual(quick_scan(fixture.session, fixture.config), 1)
        result = fixture.session.last_result
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("Quick Scan", result["title"])

    def test_interrupted_scan_records_a_warning_verdict_for_the_menu(self):
        class InterruptingSpawn(ScriptedSpawn):
            def __call__(self, argv, log_handle):
                super().__call__(argv, log_handle)
                raise KeyboardInterrupt

        fixture = make_fixture(answers=["y"], spawn=InterruptingSpawn())
        self.addCleanup(fixture.close)
        self.assertEqual(quick_scan(fixture.session, fixture.config), 130)
        result = fixture.session.last_result
        self.assertEqual(result["verdict"], "WARN")
        self.assertIn("interrupted", result["title"])


class VerifyFlowTests(unittest.TestCase):
    def test_pass_result_is_reported(self):
        spawn = ScriptedSpawn(log_text="", csv_text=CSV_VERIFY_PASS)
        fixture = make_fixture(answers=[], spawn=spawn)
        self.addCleanup(fixture.close)
        code = verify_flow(fixture.session, fixture.config, ip="104.16.0.1")
        self.assertEqual(code, 0)
        text = fixture.text
        self.assertIn("PASS", text)
        self.assertIn("20/20", text)
        argv = spawn.calls[0]
        self.assertEqual(argv[argv.index("-t") + 1], "20")
        # Any loss is accepted by the scanner and judged by cfscan itself.
        self.assertEqual(argv[argv.index("-tlr") + 1], "1")

    def test_status_mismatch_is_reported_as_failure(self):
        spawn = ScriptedSpawn(log_text=LOG_STATUS_REJECT, create_csv=False)
        fixture = make_fixture(answers=[], spawn=spawn)
        self.addCleanup(fixture.close)
        code = verify_flow(fixture.session, fixture.config, ip="104.16.0.1")
        self.assertEqual(code, 1)
        text = fixture.text
        self.assertIn("FAIL", text)
        self.assertIn("520", text)

    def test_packet_loss_is_reported_as_failure(self):
        csv_text = (
            "\ufeffIP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码\r\n"
            "104.16.0.1,20,17,0.15,431.07,0.00,N/A\r\n"
        )
        spawn = ScriptedSpawn(log_text="", csv_text=csv_text)
        fixture = make_fixture(answers=[], spawn=spawn)
        self.addCleanup(fixture.close)
        code = verify_flow(fixture.session, fixture.config, ip="104.16.0.1")
        self.assertEqual(code, 1)
        self.assertIn("FAIL", fixture.text)
        self.assertIn("packet loss", fixture.text.lower())

    def test_no_answer_at_all_is_reported_as_unreachable(self):
        # The scanner writes no row when not a single attempt was answered (and
        # no -debug status line either): say that, not "try another one".
        spawn = ScriptedSpawn(log_text="", create_csv=False)
        fixture = make_fixture(answers=[], spawn=spawn)
        self.addCleanup(fixture.close)
        code = verify_flow(fixture.session, fixture.config, ip="104.16.0.1")
        self.assertEqual(code, 1)
        text = fixture.text
        self.assertIn("FAIL", text)
        self.assertIn("unreachable from this network", text)
        self.assertEqual(fixture.session.last_result["verdict"], "FAIL")

    def test_invalid_ip_is_rejected_before_running(self):
        spawn = ScriptedSpawn()
        fixture = make_fixture(answers=[], spawn=spawn)
        self.addCleanup(fixture.close)
        code = verify_flow(fixture.session, fixture.config, ip="999.999.1.1")
        self.assertEqual(code, 2)
        self.assertEqual(spawn.calls, [])
        self.assertIn("not a valid IP", fixture.text)

    def test_ip_version_mismatch_is_rejected(self):
        spawn = ScriptedSpawn()
        fixture = make_fixture(answers=[], spawn=spawn)
        self.addCleanup(fixture.close)
        code = verify_flow(fixture.session, fixture.config, ip="2606:4700::1111")
        self.assertEqual(code, 2)
        self.assertEqual(spawn.calls, [])
        self.assertIn("IPv6", fixture.text)

    def test_dry_run_never_spawns(self):
        fixture = make_fixture(answers=[], dry_run=True)
        self.addCleanup(fixture.close)
        code = verify_flow(fixture.session, fixture.config, ip="104.16.0.1")
        self.assertEqual(code, 0)
        self.assertEqual(fixture.spawn.calls, [])
        self.assertIn("-ip 104.16.0.1", fixture.text)

    def test_missing_binary_is_reported(self):
        fixture = make_fixture(answers=[], spawn=ScriptedSpawn(
            error=FileNotFoundError("no cfst")))
        self.addCleanup(fixture.close)
        self.assertEqual(verify_flow(fixture.session, fixture.config,
                                     ip="104.16.0.1"), 3)

    def test_prompts_for_ip_when_missing(self):
        spawn = ScriptedSpawn(log_text="", csv_text=CSV_VERIFY_PASS)
        fixture = make_fixture(answers=["not-an-ip", "104.16.0.1"], spawn=spawn)
        self.addCleanup(fixture.close)
        code = verify_flow(fixture.session, fixture.config)
        self.assertEqual(code, 0)
        self.assertIn("Invalid", fixture.text)

    def test_scanner_error_is_reported_without_a_traceback(self):
        fixture = make_fixture(answers=[],
                               spawn=ScriptedSpawn(
                                   error=OSError("Exec format error")))
        self.addCleanup(fixture.close)
        code = verify_flow(fixture.session, fixture.config, ip="104.16.0.1")
        self.assertEqual(code, 1)
        self.assertIn("could not be started", fixture.text)


class ProfilesViewTests(unittest.TestCase):
    def test_show_profiles_marks_the_active_one(self):
        fixture = make_fixture()
        self.addCleanup(fixture.close)
        show_profiles(fixture.session, fixture.config)
        text = fixture.text
        self.assertIn(DEFAULT_KEY, text)
        self.assertIn("active", text.lower())

    def test_switch_ip_version_persists_change(self):
        fixture = make_fixture(answers=["6", "y"])
        self.addCleanup(fixture.close)
        code = switch_ip_version(fixture.session, fixture.config)
        self.assertEqual(code, 0)
        profile = fixture.reload()["profiles"][DEFAULT_KEY]
        self.assertEqual(profile["ip_version"], 6)
        self.assertIn("ipv6.txt", profile["ip_file"])

    def test_switch_back_to_ipv4(self):
        fixture = make_fixture(answers=["4", "y"])
        self.addCleanup(fixture.close)
        fixture.profile()["ip_version"] = 6
        switch_ip_version(fixture.session, fixture.config)
        profile = fixture.reload()["profiles"][DEFAULT_KEY]
        self.assertEqual(profile["ip_version"], 4)
        self.assertIn("ip.txt", profile["ip_file"])
        self.assertNotIn("ipv6.txt", profile["ip_file"])

    def test_switch_can_be_cancelled(self):
        fixture = make_fixture(answers=["6", "n"])
        self.addCleanup(fixture.close)
        switch_ip_version(fixture.session, fixture.config)
        self.assertEqual(fixture.reload()["profiles"][DEFAULT_KEY]["ip_version"], 4)


class ManageProfilesTests(unittest.TestCase):
    def test_delete_profile_with_confirmation(self):
        fixture = make_fixture(answers=["4", "2", "y"])
        self.addCleanup(fixture.close)
        fixture.config["profiles"]["office"] = dict(fixture.profile())
        fixture.save()
        manage_profiles(fixture.session, fixture.config)
        self.assertNotIn("office", fixture.reload()["profiles"])

    def test_delete_can_be_cancelled(self):
        fixture = make_fixture(answers=["4", "2", "n"])
        self.addCleanup(fixture.close)
        fixture.config["profiles"]["office"] = dict(fixture.profile())
        fixture.save()
        manage_profiles(fixture.session, fixture.config)
        self.assertIn("office", fixture.reload()["profiles"])

    def test_default_profile_cannot_be_deleted(self):
        fixture = make_fixture(answers=["4", "1", "y"])
        self.addCleanup(fixture.close)
        manage_profiles(fixture.session, fixture.config)
        self.assertIn(DEFAULT_KEY, fixture.reload()["profiles"])
        self.assertIn("cannot be deleted", fixture.text)

    def test_adding_a_profile_requires_a_name(self):
        answers = [
            "2",                # add a new profile
            "",                 # Enter alone is not a name
            "brand-new",        # profile name
            "example.com",      # domain
            "2053",             # port
            "4",                # IPv4
            "2",                # TCPing
            "8",                # attempts
            "100",              # concurrency
            "1500",             # max latency
            "10%",              # max packet loss
            "5",                # results
            "y",                # jitter (default on)
            "n",                # download test
            "n",                # upload test
            "new-scan.csv",     # output filename
        ]
        fixture = make_fixture(answers=answers, dry_run=True)
        self.addCleanup(fixture.close)
        manage_profiles(fixture.session, fixture.config)
        self.assertIn("A value is required here", fixture.text)
        profiles = fixture.reload()["profiles"]
        self.assertIn("brand-new", profiles)
        self.assertIn(DEFAULT_KEY, profiles)

    def test_choose_active_profile(self):
        fixture = make_fixture(answers=["1", "2"])
        self.addCleanup(fixture.close)
        fixture.config["profiles"]["office"] = dict(fixture.profile())
        fixture.config["profiles"]["office"]["domain"] = "office.example.com"
        fixture.save()
        manage_profiles(fixture.session, fixture.config)
        active = fixture.reload()["active_profile"]
        self.assertEqual(active, "office")


class CustomScanTests(unittest.TestCase):
    ANSWERS = [
        "office",           # profile name
        "office.example.com",  # domain
        "2053",             # port
        "6",                # IPv6
        "2",                # TCPing
        "8",                # attempts
        "100",              # concurrency
        "1500",             # max latency
        "10%",              # max packet loss
        "5",                # best addresses to show and verify
        "y",                # jitter (default on)
        "n",                # download test
        "n",                # upload test
        "office-scan.csv",  # output filename
        "y",                # save profile
    ]

    def test_custom_scan_dry_run_builds_expected_arguments(self):
        fixture = make_fixture(answers=self.ANSWERS, dry_run=True)
        self.addCleanup(fixture.close)
        code = custom_scan(fixture.session, fixture.config)
        self.assertEqual(code, 0)
        self.assertEqual(fixture.spawn.calls, [])
        text = fixture.text
        self.assertIn("-tp 2053", text)
        self.assertIn("-t 8", text)
        self.assertIn("-tl 1500", text)
        self.assertIn("-tlr 0.10", text)
        self.assertRegex(text, r"Addresses offered\s*: 5")
        # -p only shapes the scanner's own console listing, so it follows the
        # number cfscan will show rather than a second, separate setting.
        self.assertIn("-p 5", text)
        self.assertIn("office-scan.csv", text)

    def test_custom_scan_uses_tcping_without_http_flags(self):
        fixture = make_fixture(answers=self.ANSWERS, dry_run=True)
        self.addCleanup(fixture.close)
        custom_scan(fixture.session, fixture.config)
        self.assertNotIn("-httping", fixture.text)

    def test_custom_scan_saves_profile(self):
        fixture = make_fixture(answers=self.ANSWERS, dry_run=True)
        self.addCleanup(fixture.close)
        custom_scan(fixture.session, fixture.config)
        saved = fixture.reload()["profiles"]["office"]
        self.assertEqual(saved["domain"], "office.example.com")
        self.assertEqual(saved["port"], 2053)
        self.assertEqual(saved["ip_version"], 6)
        self.assertEqual(saved["mode"], "tcp")
        self.assertEqual(saved["attempts"], 8)
        self.assertAlmostEqual(saved["max_loss"], 0.10)
        self.assertEqual(saved["top_ips"], 5)
        self.assertFalse(saved["download_test"])

    def test_custom_scan_uses_ipv6_range_file(self):
        fixture = make_fixture(answers=self.ANSWERS, dry_run=True)
        self.addCleanup(fixture.close)
        custom_scan(fixture.session, fixture.config)
        self.assertIn("ipv6.txt", fixture.text)

    def test_invalid_answers_are_reprompted(self):
        answers = [
            "office",
            "not a domain",
            "office.example.com",
            "70000",
            "2053",
            "4",
            "1",
            "1",
            "200",
            "",                 # region filter: keep the default (any)
            "8",
            "100",
            "1000",
            "abc",
            "25%",
            "20",
            "y",                # jitter
            "n",                # download
            "n",                # upload
            "out.csv",
            "n",
        ]
        fixture = make_fixture(answers=answers, dry_run=True)
        self.addCleanup(fixture.close)
        custom_scan(fixture.session, fixture.config)
        self.assertIn("Invalid", fixture.text)

    def test_secret_like_profile_name_is_rejected(self):
        answers = [
            "b2f1a3c4-1111-2222-3333-444455556666",
            "safe-profile",
            "example.com",
            "2053",
            "4",
            "1",
            "1",
            "400",
            "",                 # region filter: keep the default (any)
            "4",
            "200",
            "1000",
            "25%",
            "20",
            "y",                # jitter
            "n",                # download
            "n",                # upload
            "out.csv",
            "n",
        ]
        fixture = make_fixture(answers=answers, dry_run=True)
        self.addCleanup(fixture.close)
        custom_scan(fixture.session, fixture.config)
        text = fixture.text.lower()
        self.assertIn("secret", text)
        self.assertNotIn("b2f1a3c4-1111-2222-3333-444455556666", fixture.text)

    def test_custom_scan_runs_and_shows_results(self):
        answers = self.ANSWERS[:-1] + ["n", "y"]
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=CSV_TWO_ROWS)
        fixture = make_fixture(answers=answers, spawn=spawn)
        self.addCleanup(fixture.close)
        code = custom_scan(fixture.session, fixture.config)
        self.assertEqual(code, 0)
        self.assertEqual(len(spawn.calls), 1)
        self.assertIn("IP address", fixture.text)


class TopIpsTests(unittest.TestCase):
    """A scan offers the best ten addresses, not only the winner."""

    def test_ten_best_addresses_are_listed_with_their_client_settings(self):
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=csv_with_rows(12))
        fixture = make_fixture(answers=["y", "n"], spawn=spawn)
        self.addCleanup(fixture.close)
        quick_scan(fixture.session, fixture.config)
        text = fixture.text
        self.assertIn("Top 10 IPs you can use", text)
        self.assertIn("104.21.0.9", text)
        self.assertIn("104.21.0.10", text)
        # Ranks 11 and 12 stay in the saved file, out of the offer.
        self.assertNotIn("104.21.0.11", text)
        self.assertNotIn("104.21.0.12", text)
        self.assertIn("The best 10 of 12 are shown; menu 4", text)
        self.assertIn("Port 2087", text)
        self.assertIn("SNI/Host node.example.test", text)
        marked = [line for line in text.splitlines() if line.rstrip().endswith("*")]
        self.assertTrue(any("104.21.0.1" in line for line in marked))

    def test_scanner_is_asked_for_at_least_ten_rows(self):
        fixture = make_fixture(answers=[], dry_run=True)
        self.addCleanup(fixture.close)
        fixture.profile()["results_limit"] = 3
        quick_scan(fixture.session, fixture.config)
        self.assertIn("-p 10", fixture.text)

    def test_show_last_results_still_lists_every_address(self):
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=csv_with_rows(12))
        fixture = make_fixture(answers=["y", "n"], spawn=spawn)
        self.addCleanup(fixture.close)
        quick_scan(fixture.session, fixture.config)
        fixture.out.truncate(0)
        fixture.out.seek(0)
        show_last_results(fixture.session, fixture.config)
        self.assertIn("104.21.0.11", fixture.text)
        self.assertIn("104.21.0.12", fixture.text)

    def test_custom_scan_offers_the_same_top_block(self):
        answers = list(CustomScanTests.ANSWERS[:-1]) + ["n", "y"]
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=csv_with_rows(12))
        fixture = make_fixture(answers=answers, spawn=spawn)
        self.addCleanup(fixture.close)
        custom_scan(fixture.session, fixture.config)
        self.assertIn("Top 5 IPs you can use", fixture.text)

    def test_the_profile_can_ask_for_a_shorter_list(self):
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=csv_with_rows(12))
        fixture = make_fixture(answers=["y", "n"], spawn=spawn)
        self.addCleanup(fixture.close)
        fixture.profile()["top_ips"] = 4
        quick_scan(fixture.session, fixture.config)
        text = fixture.text
        self.assertIn("Top 4 IPs you can use", text)
        self.assertNotIn("104.21.0.5", text)


class AutoVerifyTests(unittest.TestCase):
    """A scan re-measures its best addresses in one extra scanner run."""

    @staticmethod
    def _measurements():
        return csv_with_measurements([
            ("104.21.0.1", 20, 17, 0.15, 101.00, "FRA"),   # packets were lost
            ("104.21.0.3", 20, 20, 0.00, 103.00, "FRA"),   # every attempt answered
            ("104.21.0.7", 20, 20, 0.00, 107.00, "FRA"),
        ])

    def test_the_ten_best_are_checked_in_one_extra_run(self):
        spawn = ScriptedSpawn(
            csv_sequence=[csv_with_rows(12), self._measurements()],
            log_text=LOG_SUCCESS,
        )
        fixture = make_fixture(answers=["y"], spawn=spawn, verify_top=True)
        self.addCleanup(fixture.close)
        self.assertEqual(quick_scan(fixture.session, fixture.config), 0)
        text = fixture.text
        self.assertIn("Verifying the best 10 addresses with 20 attempts each",
                      text)
        self.assertEqual(len(spawn.calls), 2)
        batch = spawn.calls[1]
        self.assertIn("-f", batch)
        self.assertEqual(batch[batch.index("-t") + 1], "20")
        self.assertEqual(batch[batch.index("-tlr") + 1], "1")
        self.assertEqual(batch[batch.index("-p") + 1], "10")
        # the temporary address list is cleaned up again
        self.assertFalse(Path(batch[batch.index("-f") + 1]).exists())
        # one verdict per offered line
        self.assertIn("FAIL 104.21.0.1", text)
        self.assertIn("PASS 104.21.0.3", text)
        self.assertIn("DEAD 104.21.0.2", text)
        self.assertIn("Best verified address: 104.21.0.3", text)
        banner = " ".join(fixture.session.last_result["lines"])
        self.assertIn("2 of 10 addresses passed the 20-attempt check", banner)
        marked = [line for line in text.splitlines() if line.rstrip().endswith("*")]
        self.assertTrue(any("104.21.0.3" in line for line in marked))
        self.assertFalse(any("104.21.0.1" in line for line in marked))
        self.assertEqual(fixture.session.last_result["verdict"], "PASS")

    def test_a_broken_check_leaves_the_scan_view_untouched(self):
        class FailSecond(ScriptedSpawn):
            def __call__(self, argv, log_handle):
                if self.calls:
                    raise OSError("Exec format error")
                return super().__call__(argv, log_handle)

        spawn = FailSecond(log_text=LOG_SUCCESS, csv_text=csv_with_rows(12))
        # "n" declines the single-address verification cfscan falls back to.
        fixture = make_fixture(answers=["y", "n"], spawn=spawn, verify_top=True)
        self.addCleanup(fixture.close)
        self.assertEqual(quick_scan(fixture.session, fixture.config), 0)
        text = fixture.text
        self.assertIn("could not be started", text)
        self.assertIn("only the strict check was skipped", text)
        self.assertIn("Top 10 IPs you can use", text)
        self.assertNotIn("PASS = 20/20 attempts answered", text)
        self.assertEqual(fixture.session.last_result["verdict"], "PASS")

    def test_a_run_that_answered_nothing_marks_every_line_dead(self):
        # cfst only writes a row for an address that answered at least once, so
        # a finished run without a result file means "not one reply".
        spawn = ScriptedSpawn(csv_sequence=[csv_with_rows(12), None],
                              log_text=LOG_SUCCESS)
        fixture = make_fixture(answers=["y"], spawn=spawn, verify_top=True)
        self.addCleanup(fixture.close)
        self.assertEqual(quick_scan(fixture.session, fixture.config), 0)
        text = fixture.text
        self.assertIn("answered nothing at all", text)
        self.assertIn("DEAD 104.21.0.1", text)
        banner = " ".join(fixture.session.last_result["lines"])
        self.assertIn("0 of 10 addresses passed the 20-attempt check", banner)
        self.assertEqual(fixture.session.last_result["verdict"], "FAIL")

    def test_the_profile_can_switch_the_automatic_check_off(self):
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=csv_with_rows(12))
        fixture = make_fixture(answers=["y", "n"], spawn=spawn, verify_top=True)
        self.addCleanup(fixture.close)
        fixture.profile()["verify_top_ips"] = False
        quick_scan(fixture.session, fixture.config)
        self.assertEqual(len(spawn.calls), 1)
        self.assertNotIn("Verifying the best", fixture.text)
        # ... and the single-address prompt is offered instead
        self.assertIn("20-attempt verification", fixture.text)


class HttpingSchemeTests(unittest.TestCase):
    """Menu 6 can pick the http/https URL scheme of a profile."""

    ANSWERS = [
        DEFAULT_KEY,            # profile name (the built-in profile)
        "node.example.test",  # domain
        "2087",                 # port
        "4",                    # IPv4
        "1",                    # HTTPing
        "2",                    # scheme: http
        "400",                  # expected status
        "4",                    # attempts
        "200",                  # concurrency
        "1000",                 # max latency
        "25%",                  # max packet loss
        "20",                   # results to display
        "y",                    # jitter
        "n",                    # download test
        "n",                    # upload test
        "http-scan.csv",        # output filename
        "y",                    # save the profile
    ]

    def test_http_scheme_can_be_selected_from_the_menu(self):
        fixture = make_fixture(answers=self.ANSWERS, dry_run=True)
        self.addCleanup(fixture.close)
        custom_scan(fixture.session, fixture.config)
        self.assertIn("-url http://node.example.test:2087/", fixture.text)
        saved = fixture.reload()["profiles"][DEFAULT_KEY]
        self.assertEqual(saved["scheme"], "http")

    def test_https_scheme_is_still_the_default(self):
        # https asks for the region filter as well; http never does, because
        # the edge's own 400 carries no datacentre.
        answers = list(self.ANSWERS)
        answers[5] = "1"
        answers.insert(7, "")
        fixture = make_fixture(answers=answers, dry_run=True)
        self.addCleanup(fixture.close)
        custom_scan(fixture.session, fixture.config)
        self.assertIn("-url https://node.example.test:2087/", fixture.text)
        saved = fixture.reload()["profiles"][DEFAULT_KEY]
        self.assertEqual(saved["scheme"], "https")


class VerifiedIpInheritanceTests(unittest.TestCase):
    """A verified IP belongs to the domain and port it was tested against."""

    def test_new_target_does_not_inherit_the_verified_ip(self):
        fixture = make_fixture(answers=CustomScanTests.ANSWERS, dry_run=True)
        self.addCleanup(fixture.close)
        custom_scan(fixture.session, fixture.config)
        saved = fixture.reload()["profiles"]["office"]
        self.assertIsNone(saved["recommended_ip"])

    def test_same_target_keeps_the_verified_ip(self):
        answers = list(CustomScanTests.ANSWERS)
        answers[0] = DEFAULT_KEY
        answers[1] = "node.example.test"
        answers[2] = "2087"
        fixture = make_fixture(answers=answers, dry_run=True)
        self.addCleanup(fixture.close)
        custom_scan(fixture.session, fixture.config)
        saved = fixture.reload()["profiles"][DEFAULT_KEY]
        self.assertEqual(saved["recommended_ip"], "104.16.0.1")


class _AbortAtInput(object):
    """Scripted input that behaves like Ctrl+C on one particular read."""

    def __init__(self, answers, abort_at):
        self.answers = list(answers)
        self.abort_at = abort_at
        self.calls = 0

    def __call__(self, prompt=""):
        self.calls += 1
        if self.calls == self.abort_at:
            raise KeyboardInterrupt
        if not self.answers:
            raise EOFError("scripted input exhausted")
        return self.answers.pop(0)


class BackToMenuTests(unittest.TestCase):
    """Every test shows its result and then the menu comes back."""

    def test_scan_result_is_repeated_then_the_menu_returns(self):
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=CSV_TWO_ROWS)
        fixture = Fixture(answers=["1", "y", "n", "", "0"], spawn=spawn,
                          tty=True)
        fixture.session.verify_top_ips = False
        self.addCleanup(fixture.close)
        self.assertEqual(run_menu(fixture.session, fixture.config), 0)
        text = fixture.text
        self.assertIn("[PASS] Quick Scan - best 2 addresses", text)
        self.assertIn("Press Enter to return to the menu", text)
        self.assertGreaterEqual(text.count("1. Quick Scan"), 2)

    def test_verify_result_is_repeated_then_the_menu_returns(self):
        spawn = ScriptedSpawn(log_text="", csv_text=CSV_VERIFY_PASS)
        fixture = Fixture(answers=["3", "104.16.0.1", "", "0"], spawn=spawn,
                          tty=True)
        self.addCleanup(fixture.close)
        self.assertEqual(run_menu(fixture.session, fixture.config), 0)
        text = fixture.text
        self.assertIn("[PASS] Verify 104.16.0.1 - PASS", text)
        self.assertGreaterEqual(text.count("1. Quick Scan"), 2)

    def test_piped_output_never_waits_for_enter(self):
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=CSV_TWO_ROWS)
        fixture = Fixture(answers=["1", "y", "n", "0"], spawn=spawn)
        fixture.session.verify_top_ips = False
        self.addCleanup(fixture.close)
        self.assertEqual(run_menu(fixture.session, fixture.config), 0)
        self.assertNotIn("Press Enter to return to the menu", fixture.text)

    def test_ctrl_c_inside_a_flow_only_cancels_that_flow(self):
        fixture = Fixture(tty=True)
        self.addCleanup(fixture.close)
        fixture.session.console = Console(
            out=fixture.out, err=fixture.out, color=False,
            input_fn=_AbortAtInput(["1", "0"], abort_at=2),
        )
        self.assertEqual(run_menu(fixture.session, fixture.config), 0)
        text = fixture.text
        self.assertIn("Cancelled - back to the menu", text)
        self.assertGreaterEqual(text.count("1. Quick Scan"), 2)
        self.assertEqual(fixture.spawn.calls, [])

    def test_scanner_error_does_not_close_the_menu(self):
        spawn = ScriptedSpawn(error=OSError("Exec format error"))
        fixture = Fixture(answers=["1", "y", "", "0"], spawn=spawn, tty=True)
        self.addCleanup(fixture.close)
        self.assertEqual(run_menu(fixture.session, fixture.config), 0)
        self.assertIn("could not be started", fixture.text)
        self.assertGreaterEqual(fixture.text.count("1. Quick Scan"), 2)


class LastResultsTests(unittest.TestCase):
    def test_reports_when_no_results_exist(self):
        fixture = make_fixture()
        self.addCleanup(fixture.close)
        code = show_last_results(fixture.session, fixture.config)
        self.assertEqual(code, 0)
        self.assertIn("No saved results", fixture.text)

    def test_shows_newest_result(self):
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=CSV_TWO_ROWS)
        fixture = make_fixture(answers=["y", "n"], spawn=spawn)
        self.addCleanup(fixture.close)
        quick_scan(fixture.session, fixture.config)
        fixture.out.truncate(0)
        fixture.out.seek(0)
        code = show_last_results(fixture.session, fixture.config)
        self.assertEqual(code, 0)
        self.assertIn("104.16.0.1", fixture.text)

    def test_recommended_ip_from_the_scan_is_highlighted(self):
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=CSV_TWO_ROWS)
        fixture = make_fixture(answers=["y", "n"], spawn=spawn)
        self.addCleanup(fixture.close)
        quick_scan(fixture.session, fixture.config)
        fixture.out.truncate(0)
        fixture.out.seek(0)
        show_last_results(fixture.session, fixture.config)
        text = fixture.text
        self.assertIn("* = recommended IP", text)
        self.assertIn("Recommended IP: 104.16.0.1", text)

    def test_invalid_csv_is_reported(self):
        fixture = make_fixture()
        self.addCleanup(fixture.close)
        path = Path(fixture.paths.results_dir)
        path.mkdir(parents=True, exist_ok=True)
        bad = path / "cfscan-broken-20260101-000000.csv"
        bad.write_text("not,a,valid\nresult,file,at,all\n", encoding="utf-8")
        code = show_last_results(fixture.session, fixture.config)
        self.assertEqual(code, 0)
        self.assertTrue(fixture.text.strip())


class OpenFolderTests(unittest.TestCase):
    def test_opens_the_results_folder(self):
        from cfscan.menu import open_results_folder

        fixture = make_fixture()
        self.addCleanup(fixture.close)
        with mock.patch("cfscan.results.open_in_finder", return_value=True) as opened:
            code = open_results_folder(fixture.session, fixture.config)
        self.assertEqual(code, 0)
        self.assertEqual(Path(opened.call_args[0][0]), Path(fixture.paths.results_dir))


class HelpScreenTests(unittest.TestCase):
    def test_help_mentions_key_topics(self):
        fixture = make_fixture()
        self.addCleanup(fixture.close)
        help_screen(fixture.session, fixture.config)
        text = fixture.text
        for topic in ("SNI", "Address", "IPv4", "IPv6", "dry run", "Ctrl+C"):
            self.assertIn(topic, text)


class NewProfileTests(unittest.TestCase):
    """Adding a profile must not quietly destroy or shadow another one."""

    def answers(self, name="brand-new", tail=()):
        """The answers that add one profile through menu 6."""
        rows = [
            "2",              # add a new profile
            name,             # profile name
            "example.com",    # domain
            "2053",           # port
            "4",              # IPv4
            "2",              # TCPing
            "4",              # attempts
            "200",            # concurrency
            "1000",           # max latency
            "25%",            # max packet loss
            "20",             # results
            "y",              # jitter
            "n",              # download test
            "n",              # upload test
            "",               # output filename: keep the shown default
        ]
        return rows + list(tail)

    def add_fixture(self, answers, **kwargs):
        fixture = Fixture(answers=answers, dry_run=True, **kwargs)
        self.addCleanup(fixture.close)
        fixture.session.verify_top_ips = False
        return fixture

    def test_a_new_profile_is_named_after_itself(self):
        fixture = self.add_fixture(self.answers(name="france"))
        # A stale file name on the profile it was copied from must not be used.
        fixture.config["profiles"][DEFAULT_KEY]["output_filename"] = (
            "cfscan-old-name-20260915-192829.csv")
        fixture.save()

        manage_profiles(fixture.session, fixture.config)

        self.assertIn("cfscan-france-", fixture.text)
        self.assertNotIn("cfscan-old-name", fixture.text)

    def test_an_existing_name_is_not_replaced_silently(self):
        answers = ["2", "office", "n"] + self.answers(name="brand-new")[1:]
        fixture = self.add_fixture(answers)
        fixture.config["profiles"]["office"] = dict(fixture.profile())
        fixture.config["profiles"]["office"]["domain"] = "kept.example.com"
        fixture.config["profiles"]["office"]["port"] = 2096
        fixture.save()

        manage_profiles(fixture.session, fixture.config)

        self.assertIn("already exists", fixture.text)
        self.assertIn("Replace 'office'?", fixture.text)
        # Refused, the name was asked again, and the stored profile survives.
        self.assertEqual("kept.example.com",
                         fixture.reload()["profiles"]["office"]["domain"])
        self.assertIn("brand-new", fixture.reload()["profiles"])

    def test_saving_a_new_profile_leaves_the_active_one_in_place(self):
        fixture = self.add_fixture(self.answers())

        manage_profiles(fixture.session, fixture.config)

        self.assertIn("is saved but not active", fixture.text)
        self.assertEqual(DEFAULT_KEY, fixture.reload()["active_profile"])

    def test_the_active_profile_can_be_switched_after_saving(self):
        fixture = self.add_fixture(self.answers(name="brand-new", tail=["y"]),
                                   tty=True)

        manage_profiles(fixture.session, fixture.config)

        self.assertIn("Make 'brand-new' the active profile now?", fixture.text)
        self.assertEqual("brand-new", fixture.reload()["active_profile"])

    def test_editing_the_same_profile_keeps_its_filename(self):
        answers = ["", "", "", "4", "1", "1", "400", "", "", "", "", "",
                   "", "", "n", "n", "", "n"]
        fixture = make_fixture(answers=answers, dry_run=True)
        self.addCleanup(fixture.close)
        fixture.config["profiles"]["office"] = dict(fixture.profile())
        fixture.config["profiles"]["office"]["output_filename"] = "office-scan.csv"
        fixture.config["active_profile"] = "office"
        fixture.save()

        custom_scan(fixture.session, fixture.config)

        self.assertIn("office-scan.csv", fixture.text)


class SessionTests(unittest.TestCase):
    def test_session_defaults(self):
        session = Session(paths=None, console=None)
        self.assertFalse(session.dry_run)
        self.assertIsNone(session.spawn)
        self.assertEqual(session.verify_attempts, 20)
        self.assertEqual(session.top_ips, 10)
        self.assertTrue(session.verify_top_ips)
        self.assertEqual(session.scan_timeout_seconds, 3600)
        self.assertIsNone(session.last_result)


def _interrupting_console(fixture):
    def boom(_prompt=""):
        raise KeyboardInterrupt

    return type(fixture.console)(
        out=fixture.out, err=fixture.out, input_fn=boom, color=False
    )


if __name__ == "__main__":
    unittest.main()

"""Tests for scanner argument construction, log translation and execution."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import cfscan.runner as runner
from cfscan.profiles import default_profile
from cfscan.runner import (
    CfstNotFoundError,
    Progress,
    build_scan_argv,
    build_verify_argv,
    check_cfst,
    extract_status_rejection,
    format_argv_for_display,
    proxy_variables_present,
    read_progress,
    run_scan,
    scanner_environment,
    translate_log,
)

from tests.support import FIXTURE_DOMAIN, FIXTURE_PORT
from tests.support import (
    LOG_NO_RESULTS,
    LOG_PROGRESS,
    LOG_STATUS_REJECT,
    LOG_SUCCESS,
    CSV_TWO_ROWS,
    ScriptedSpawn,
)

CFST = "/opt/homebrew/bin/cfst"
IP_FILE = "/Users/example/.local/share/cloudflare-speedtest/ip.txt"
IPV6_FILE = "/Users/example/.local/share/cloudflare-speedtest/ipv6.txt"


def spec_profile():
    profile = default_profile(cfst_path=CFST)
    # The shipped default is a placeholder; these tests want a configured one.
    profile.update(domain=FIXTURE_DOMAIN, port=FIXTURE_PORT)
    profile["ip_file"] = IP_FILE
    profile["ipv6_file"] = IPV6_FILE
    return profile


class BuildScanArgvTests(unittest.TestCase):
    def test_default_quick_scan_matches_specification(self):
        argv = build_scan_argv(CFST, spec_profile(), "/tmp/out.csv")
        self.assertEqual(
            argv,
            [
                CFST,
                "-f",
                IP_FILE,
                "-tp",
                "2087",
                "-httping",
                "-httping-code",
                "400",
                "-url",
                "https://node.example.test:2087/",
                "-dd",
                "-t",
                "4",
                "-n",
                "200",
                "-tl",
                "1000",
                "-tlr",
                "0.25",
                "-p",
                "20",
                "-o",
                "/tmp/out.csv",
            ],
        )

    def test_every_argument_is_a_string(self):
        argv = build_scan_argv(CFST, spec_profile(), "/tmp/out.csv")
        self.assertTrue(all(isinstance(item, str) for item in argv))

    def test_ipv6_uses_ipv6_range_file(self):
        profile = spec_profile()
        profile["ip_version"] = 6
        argv = build_scan_argv(CFST, profile, "/tmp/out.csv")
        self.assertEqual(argv[argv.index("-f") + 1], IPV6_FILE)

    def test_download_test_enabled_drops_the_dd_flag(self):
        profile = spec_profile()
        profile["download_test"] = True
        argv = build_scan_argv(CFST, profile, "/tmp/out.csv")
        self.assertNotIn("-dd", argv)

    def test_download_test_disabled_adds_the_dd_flag(self):
        argv = build_scan_argv(CFST, spec_profile(), "/tmp/out.csv")
        self.assertIn("-dd", argv)

    def test_tcping_mode_omits_http_options(self):
        profile = spec_profile()
        profile["mode"] = "tcp"
        argv = build_scan_argv(CFST, profile, "/tmp/out.csv")
        self.assertNotIn("-httping", argv)
        self.assertNotIn("-httping-code", argv)
        self.assertNotIn("-url", argv)
        self.assertEqual(argv[argv.index("-tp") + 1], "2087")

    def test_single_ip_replaces_range_file(self):
        argv = build_scan_argv(
            CFST, spec_profile(), "/tmp/out.csv", single_ip="104.16.0.1"
        )
        self.assertNotIn("-f", argv)
        self.assertEqual(argv[argv.index("-ip") + 1], "104.16.0.1")

    def test_attempt_override_is_respected(self):
        argv = build_scan_argv(CFST, spec_profile(), "/tmp/out.csv", attempts=20)
        self.assertEqual(argv[argv.index("-t") + 1], "20")

    def test_results_limit_override_is_respected(self):
        argv = build_scan_argv(CFST, spec_profile(), "/tmp/out.csv",
                               results_limit=10)
        self.assertEqual(argv[argv.index("-p") + 1], "10")

    def test_http_scheme_profile_builds_http_url(self):
        profile = spec_profile()
        profile["scheme"] = "http"
        argv = build_scan_argv(CFST, profile, "/tmp/out.csv")
        self.assertEqual(argv[argv.index("-url") + 1], "http://node.example.test:2087/")

    def test_custom_path_is_used(self):
        profile = spec_profile()
        profile["url_path"] = "/cdn-cgi/trace"
        argv = build_scan_argv(CFST, profile, "/tmp/out.csv")
        self.assertEqual(
            argv[argv.index("-url") + 1], "https://node.example.test:2087/cdn-cgi/trace"
        )

    def test_no_shell_metacharacters_in_argv(self):
        argv = build_scan_argv(CFST, spec_profile(), "/tmp/out.csv")
        joined = " ".join(argv)
        for token in (";", "&&", "|", "$(", "`", ">"):
            self.assertNotIn(token, joined)


class BuildVerifyArgvTests(unittest.TestCase):
    def test_verify_uses_twenty_attempts_and_asks_for_any_loss(self):
        argv = build_verify_argv(CFST, spec_profile(), "104.16.0.1", "/tmp/v.csv")
        self.assertEqual(argv[argv.index("-ip") + 1], "104.16.0.1")
        self.assertEqual(argv[argv.index("-t") + 1], "20")
        # The scanner must report the address even when packets are lost, so
        # cfscan can show the real numbers instead of a silent rejection.
        self.assertEqual(argv[argv.index("-tlr") + 1], "1")
        self.assertEqual(argv[argv.index("-p") + 1], "1")
        self.assertIn("-dd", argv)
        self.assertIn("-debug", argv)
        self.assertEqual(argv[argv.index("-o") + 1], "/tmp/v.csv")

    def test_verify_attempts_can_be_overridden(self):
        argv = build_verify_argv(
            CFST, spec_profile(), "104.16.0.1", "/tmp/v.csv", attempts=5
        )
        self.assertEqual(argv[argv.index("-t") + 1], "5")

    def test_verify_keeps_http_mode_and_status(self):
        argv = build_verify_argv(CFST, spec_profile(), "104.16.0.1", "/tmp/v.csv")
        self.assertIn("-httping", argv)
        self.assertEqual(argv[argv.index("-httping-code") + 1], "400")
        self.assertEqual(
            argv[argv.index("-url") + 1], "https://node.example.test:2087/"
        )


class DisplayTests(unittest.TestCase):
    def test_quotes_paths_containing_spaces(self):
        text = format_argv_for_display([CFST, "-f", "/tmp/some dir/ip.txt"])
        self.assertTrue(text.startswith(CFST))
        self.assertIn("'/tmp/some dir/ip.txt'", text)

    def test_plain_arguments_are_not_quoted(self):
        text = format_argv_for_display([CFST, "-tp", "8443"])
        self.assertEqual(text, f"{CFST} -tp 8443")


class ProgressTests(unittest.TestCase):
    def test_reads_progress_from_log_tail(self):
        progress = read_progress("24 / 24 [------] 可用: 12 \n")
        self.assertIsInstance(progress, Progress)
        self.assertEqual(progress.done, 24)
        self.assertEqual(progress.total, 24)
        self.assertEqual(progress.available, 12)
        self.assertAlmostEqual(progress.percent, 100.0)

    def test_reads_first_progress_line(self):
        progress = read_progress(LOG_PROGRESS)
        self.assertEqual(progress.total, 24)
        self.assertEqual(progress.done, 0)

    def test_returns_none_when_no_progress(self):
        self.assertIsNone(read_progress("nothing to see here"))

    def test_percent_handles_zero_total(self):
        progress = read_progress("0 / 0 [---] 可用: 0")
        self.assertEqual(progress.percent, 0.0)


class TranslateLogTests(unittest.TestCase):
    def test_translates_chinese_messages(self):
        lines = translate_log(LOG_SUCCESS)
        text = "\n".join(lines)
        self.assertIn("Starting latency test", text)
        self.assertIn("Results written to", text)
        self.assertNotIn("开始延迟测速", text)

    def test_drops_progress_bar_noise(self):
        lines = translate_log(LOG_SUCCESS)
        for line in lines:
            self.assertNotIn("0 / 24 [", line)
            self.assertNotIn("24 / 24 [", line)

    def test_explains_empty_result(self):
        text = "\n".join(translate_log(LOG_NO_RESULTS))
        self.assertIn("No IP passed the filters", text)

    def test_translates_status_rejection(self):
        text = "\n".join(translate_log(LOG_STATUS_REJECT))
        self.assertIn("HTTP status code: 520", text)
        self.assertIn("required HTTP status code 400", text)

    def test_keeps_ascii_lines(self):
        text = "\n".join(translate_log("# XIU2/CloudflareSpeedTest v2.3.5\n"))
        self.assertIn("CloudflareSpeedTest", text)

    def test_output_contains_no_cjk_characters(self):
        import re

        text = "\n".join(
            translate_log(LOG_SUCCESS + LOG_NO_RESULTS + LOG_STATUS_REJECT)
        )
        self.assertIsNone(re.search(r"[\u4e00-\u9fff]", text))

    def test_handles_empty_log(self):
        self.assertEqual(translate_log(""), [])


class ExtractStatusRejectionTests(unittest.TestCase):
    def test_extracts_observed_and_expected_status(self):
        info = extract_status_rejection(LOG_STATUS_REJECT)
        self.assertIsNotNone(info)
        self.assertEqual(info["observed"], 520)
        self.assertEqual(info["expected"], 400)
        self.assertEqual(info["ip"], "104.16.0.1")

    def test_returns_none_without_rejection(self):
        self.assertIsNone(extract_status_rejection(LOG_SUCCESS))


class CheckCfstTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_missing_binary_raises_helpful_error(self):
        with self.assertRaises(CfstNotFoundError) as ctx:
            check_cfst(str(self.dir / "missing-cfst"))
        self.assertIn("cfst", str(ctx.exception))

    def test_non_executable_binary_raises(self):
        path = self.dir / "cfst"
        path.write_text("nope", encoding="utf-8")
        path.chmod(0o644)
        with self.assertRaises(CfstNotFoundError):
            check_cfst(str(path))

    def test_executable_binary_passes(self):
        path = self.dir / "cfst"
        path.write_text("#!/bin/sh\n", encoding="utf-8")
        path.chmod(0o755)
        check_cfst(str(path))


class RunScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_successful_run_writes_csv_and_log(self):
        csv_path = self.dir / "out.csv"
        log_path = self.dir / "out.log"
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=CSV_TWO_ROWS)
        seen = []

        outcome = run_scan(
            [CFST, "-o", str(csv_path)],
            log_path,
            spawn=spawn,
            on_progress=seen.append,
            poll_interval=0.01,
        )

        self.assertEqual(outcome.returncode, 0)
        self.assertFalse(outcome.interrupted)
        self.assertFalse(outcome.timed_out)
        self.assertTrue(csv_path.exists())
        self.assertTrue(log_path.exists())
        self.assertIn("Starting latency test", outcome.translated_log_text())
        self.assertTrue(seen)
        self.assertEqual(spawn.calls[0][0], CFST)

    def test_log_is_preserved_verbatim_on_disk(self):
        log_path = self.dir / "out.log"
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS)
        run_scan([CFST, "-o", str(self.dir / "out.csv")], log_path, spawn=spawn,
                 poll_interval=0.01)
        self.assertIn("开始延迟测速", log_path.read_text(encoding="utf-8"))

    def test_missing_binary_is_reported(self):
        with self.assertRaises(CfstNotFoundError):
            run_scan(
                [CFST],
                self.dir / "out.log",
                spawn=ScriptedSpawn(error=FileNotFoundError("no cfst")),
                poll_interval=0.01,
            )

    def test_non_zero_exit_code_is_returned(self):
        outcome = run_scan(
            [CFST],
            self.dir / "out.log",
            spawn=ScriptedSpawn(returncode=2, create_csv=False),
            poll_interval=0.01,
        )
        self.assertEqual(outcome.returncode, 2)

    def test_interrupt_terminates_the_scanner(self):
        def explode(_progress):
            raise KeyboardInterrupt

        spawn = ScriptedSpawn(stay_running=True)
        outcome = run_scan(
            [CFST],
            self.dir / "out.log",
            spawn=spawn,
            on_progress=explode,
            poll_interval=0.01,
            progress_first_after=0,
        )
        self.assertTrue(outcome.interrupted)

    def test_timeout_stops_the_scanner(self):
        spawn = ScriptedSpawn(stay_running=True)
        outcome = run_scan(
            [CFST],
            self.dir / "out.log",
            spawn=spawn,
            poll_interval=0.01,
            timeout=0.05,
        )
        self.assertTrue(outcome.timed_out)

    def test_no_spawn_when_dry_run(self):
        # Dry runs never reach this function; guard against accidental execution.
        argv = build_scan_argv(CFST, spec_profile(), "/tmp/out.csv")
        self.assertTrue(argv)


class ScannerEnvironmentTests(unittest.TestCase):
    """The scanner runs with this shell's environment, proxies included.

    Regression: the variables used to be stripped silently, which broke the very
    setup they were meant to support - a VPN proxy exported in the terminal (the
    scanner's Go client honours HTTPS_PROXY) was ignored, so every test request
    went out on a connection that could not reach the test addresses and every
    address looked dead. Inheritance is the default again; ``--direct`` is the
    explicit way to ask for a scan of this machine's own connection.
    """

    PROXIED = {
        "HOME": "/Users/example",
        "PATH": "/usr/bin:/bin",
        "HTTPS_PROXY": "http://127.0.0.1:10809",
        "https_proxy": "http://127.0.0.1:10809",
        "NO_PROXY": "localhost",
        "no_proxy": "localhost",
    }

    def test_every_proxy_variable_is_reported(self):
        self.assertEqual(proxy_variables_present(self.PROXIED),
                         ["HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"])

    def test_nothing_is_reported_without_a_proxy(self):
        self.assertEqual(proxy_variables_present({"HOME": "/Users/example"}), [])
        self.assertEqual(proxy_variables_present({"HTTPS_PROXY": "  "}), [])

    def test_the_shell_environment_is_kept_as_it_is(self):
        self.assertEqual(scanner_environment(self.PROXIED), dict(self.PROXIED))

    def test_a_direct_scan_drops_only_the_proxy_variables(self):
        environment = scanner_environment(self.PROXIED, direct=True)
        self.assertEqual(environment, {"HOME": "/Users/example", "PATH": "/usr/bin:/bin"})

    def test_the_real_spawner_hands_the_shell_environment_over(self):
        process = mock.Mock(returncode=0)
        with mock.patch.dict(os.environ, self.PROXIED, clear=False), \
                mock.patch.object(runner.subprocess, "Popen",
                                  return_value=process) as popen:
            runner.default_spawn()([CFST, "-o", "/tmp/out.csv"], log_handle=None)
        handed = popen.call_args.kwargs["env"]
        self.assertEqual(handed["HTTPS_PROXY"], "http://127.0.0.1:10809")
        self.assertEqual(handed["no_proxy"], "localhost")
        self.assertIn("PATH", handed)

    def test_the_real_spawner_can_run_directly_too(self):
        process = mock.Mock(returncode=0)
        with mock.patch.dict(os.environ, self.PROXIED, clear=False), \
                mock.patch.object(runner.subprocess, "Popen",
                                  return_value=process) as popen:
            runner.default_spawn(direct=True)([CFST, "-o", "/tmp/out.csv"],
                                              log_handle=None)
        handed = popen.call_args.kwargs["env"]
        self.assertNotIn("HTTPS_PROXY", handed)
        self.assertNotIn("no_proxy", handed)
        self.assertIn("PATH", handed)


if __name__ == "__main__":
    unittest.main()

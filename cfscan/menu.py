"""The interactive menu and every user flow cfscan offers.

Each flow returns an exit code:

* ``0``  - finished successfully
* ``1``  - finished but produced nothing usable (for example no IP passed)
* ``2``  - the user gave something invalid
* ``3``  - the scanner or an IP range file is missing
* ``130``- the user cancelled (Ctrl+C)
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from . import multisip as multisip_module
from . import pool as pool_module
from . import results as results_module
from . import vantages as vantages_module
from .parser import CsvError, rank_results, parse_results_csv, recommend
from .profiles import (
    DEFAULT_PROFILE_KEY,
    UnknownProfile,
    delete_profile,
    find_cfst,
    get_active,
    ip_file_for,
    profile_slug,
    save_config,
    set_active,
    set_ip_version,
    upsert_profile,
)
from .results import ResultStore, latest_result_path, timestamp_label
from .runner import (
    CLOUDFLARE_HTTPS_PORTS,
    PROBE_ADDRESSES,
    CfstNotFoundError,
    ScanError,
    build_probe_argv,
    build_scan_argv,
    build_verify_argv,
    build_verify_many_argv,
    check_cfst,
    default_spawn,
    explain_failure,
    extract_status_rejection,
    format_argv_for_display,
    ipv6_route_available,
    proxy_variables_present,
    run_scan,
    scheme_port_problem,
)
from .ui import Aborted
from .validate import (
    ValidationError,
    validate_domain,
    validate_http_status,
    validate_ip,
    validate_output_filename,
    validate_port,
    validate_profile_name,
)

__all__ = [
    "EXIT_FAILED",
    "EXIT_INTERRUPTED",
    "EXIT_MISSING_TOOL",
    "EXIT_OK",
    "EXIT_USAGE",
    "MENU_ITEMS",
    "Session",
    "custom_scan",
    "help_screen",
    "make_pool_flow",
    "manage_profiles",
    "multi_isp_flow",
    "multi_isp_report",
    "multi_isp_round",
    "open_results_folder",
    "quick_scan",
    "render_multi_isp_report",
    "render_menu",
    "run_menu",
    "show_client_guide",
    "show_top_ips",
    "verify_top_candidates",
    "show_last_results",
    "show_profiles",
    "switch_ip_version",
    "verify_flow",
]

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_MISSING_TOOL = 3
EXIT_INTERRUPTED = 130

MENU_ITEMS = (
    ("1", "Quick Scan"),
    ("2", "Custom Scan"),
    ("3", "Verify an IP"),
    ("4", "Show Last Results"),
    ("5", "Show Saved Profiles"),
    ("6", "Add or Edit Profile"),
    ("7", "Switch IPv4 / IPv6"),
    ("8", "Open Results Folder"),
    ("9", "Help"),
    ("10", "Multi-carrier scan"),
    ("0", "Exit"),
)


@dataclass
class Session:
    """Everything a flow needs, so tests can inject their own pieces."""

    paths: object
    console: object
    spawn: object = None
    dry_run: bool = False
    assume_yes: bool = False
    verify_attempts: int = 20
    #: How many of the best addresses are offered after a scan.
    top_ips: int = 10
    #: Whether a scan verifies those addresses right away (20 attempts each).
    verify_top_ips: bool = True
    #: Whether a scan measures one address first, so a profile that cannot work
    #: is explained in seconds instead of after a full range. Tests turn this
    #: off to keep the exact scanner conversation they assert on.
    preflight: bool = True
    #: How many candidate addresses a multi-carrier session fixes for all of its
    #: rounds (0 uses the pool module's default).
    pool_size: int = 0
    #: Whether the scanner runs without the proxy variables of this shell, so the
    #: numbers describe this machine's own connection (``cfscan --direct``).
    direct: bool = False
    #: A safety net against a scanner that never exits (the run is stopped and
    #: whatever came back is used). Long enough never to cut a real scan short.
    scan_timeout_seconds: int = 3600
    #: A short record of the last flow's verdict, shown again before the menu
    #: redraws itself so a test result never scrolls away.
    last_result: object = None
    #: Whether the "your shell exports a proxy" notice was already shown, so it
    #: appears once per session instead of before every single scan.
    proxy_notice_shown: bool = False


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def _profile_pair(config, name=None):
    """Resolve a profile by name, falling back to the active one."""
    profiles = config.get("profiles") or {}
    if name is None:
        name = config.get("active_profile")
    if name not in profiles:
        available = ", ".join(profiles) or "none"
        raise UnknownProfile(
            f"Profile '{name}' does not exist. Available profiles: {available} "
            "(create one from menu 6)."
        )
    return name, profiles[name]


def _cfst_path(config):
    # Falls back to the same lookup the configuration uses (PATH first, then the
    # Homebrew default), so a scanner installed somewhere else still works.
    return config.get("cfst_path") or find_cfst()


def _render_profile(console, name, profile):
    console.key_value("Profile", name)
    console.key_value("Domain", profile.get("domain"))
    console.key_value("Port", profile.get("port"))
    mode = str(profile.get("mode", "httping")).lower()
    if mode == "httping":
        scheme = str(profile.get("scheme", "https")).upper()
        console.key_value("Protocol", f"HTTPing ({scheme} request)")
        console.key_value("Test URL", _url_for(profile))
    else:
        console.key_value("Protocol", "TCPing (plain TCP connect)")
    console.key_value("Expected status", profile.get("http_status")
                      if mode == "httping" else "-")
    console.key_value("IP version", f"IPv{profile.get('ip_version', 4)}")
    console.key_value("IP range file", ip_file_for(profile))
    console.key_value("Attempts", profile.get("attempts"))
    console.key_value("Concurrency", profile.get("concurrency"))
    console.key_value("Max latency", f"{profile.get('max_latency_ms')} ms")
    console.key_value("Max packet loss", f"{float(profile.get('max_loss', 0)) * 100:g}%")
    console.key_value("Results to display", profile.get("results_limit"))
    console.key_value("Download test",
                      "enabled" if profile.get("download_test") else "disabled")
    if profile.get("recommended_ip"):
        console.key_value("Recommended IP", profile.get("recommended_ip"))
    problem = scheme_port_problem(profile)
    if problem:
        console.blank()
        console.warn(problem)


def _url_for(profile):
    from .runner import build_url

    return build_url(profile)


def _top_ips(session, profile):
    """How many of the best addresses a test should offer (default 10)."""
    raw = profile.get("top_ips") or getattr(session, "top_ips", None) or 10
    try:
        number = int(raw)
    except (TypeError, ValueError):
        return 10
    return max(1, number)


def _auto_verify_enabled(session, profile):
    """Whether a scan should verify its best addresses straight away."""
    raw = profile.get("verify_top_ips")
    if raw is None:
        return bool(getattr(session, "verify_top_ips", True))
    if isinstance(raw, str):
        return raw.strip().lower() not in ("", "0", "false", "no", "off")
    return bool(raw)


def _verify_verdict(row, attempts):
    """The verdict for one measured address: PASS, FAIL or DEAD.

    PASS means every attempt was answered with no loss at all. DEAD means the
    scanner wrote no row for it, so not a single attempt came back.
    """
    if row is None:
        return "DEAD"
    if row.received >= attempts and row.sent >= attempts and row.loss <= 0.0:
        return "PASS"
    return "FAIL"


def _requested_results(profile, top_n):
    """Ask the scanner for at least ``top_n`` rows so that many can be offered."""
    try:
        configured = int(profile.get("results_limit") or 0)
    except (TypeError, ValueError):
        configured = 0
    return max(configured, int(top_n))


def _print_dry_run(console, argv, csv_path=None, log_path=None):
    console.heading("Dry run - nothing will be executed")
    console.line("Safe argument list (handed to the scanner as a list, never "
                 "through a shell):")
    console.blank()
    console.line("  " + format_argv_for_display(argv))
    console.blank()
    for position, argument in enumerate(argv, start=1):
        console.line(f"    {position:>2}. {argument}")
    if csv_path:
        console.blank()
        console.line(f"Result file: {csv_path}")
    if log_path:
        console.line(f"Scanner log: {log_path}")


def _notice_about_shell_proxy_once(session):
    """Say once per session that the scanner inherits the shell's proxy.

    The scanner's HTTP client honours HTTPS_PROXY and friends, so a proxy
    exported for a VPN carries every test request: the scan then measures the
    route through that proxy, and with the VPN switched off it measures a dead
    port - which looks exactly like "no address is reachable". Either way it is
    announced before the numbers appear, with the way out.
    """
    if getattr(session, "proxy_notice_shown", False):
        return
    session.proxy_notice_shown = True
    inherited = proxy_variables_present()
    if not inherited:
        return
    names = ", ".join(inherited)
    if getattr(session, "direct", False):
        session.console.info(
            f"Scanning without the proxy this shell exports ({names}); the numbers "
            "describe this machine's own connection."
        )
        return
    session.console.warn(
        f"The scanner inherits the proxy from this shell ({names}), so the addresses "
        "are tested through it - keep that VPN/proxy running for the whole scan, or "
        f"the results mean nothing. For a plain scan use: cfscan --direct "
        f"(or unset {' '.join(inherited)})"
    )


def _execute_scan(session, argv, log_path, label="Scanning", timeout=None):
    """Run the scanner with a live English progress indicator.

    ``timeout`` defaults to the session's safety net, so a scanner that never
    exits cannot freeze cfscan forever.
    """
    console = session.console
    if timeout is None:
        timeout = getattr(session, "scan_timeout_seconds", None)
    _notice_about_shell_proxy_once(session)
    state = {}

    def on_progress(progress):
        if progress is None:
            console.progress_line(f"{label}...")
            return
        state["progress"] = progress
        console.progress_line(f"{label}... {progress.text}")

    outcome = run_scan(
        argv,
        log_path,
        spawn=session.spawn or default_spawn(getattr(session, "direct", False)),
        on_progress=on_progress,
        timeout=timeout,
    )

    progress = state.get("progress")
    summary = f"Finished in {outcome.seconds:.1f}s"
    if progress is not None:
        summary += (f" - checked {progress.done}/{progress.total} addresses, "
                    f"{progress.available if progress.available is not None else '?'} reachable")
    console.progress_end(summary + ".")

    if outcome.interrupted:
        console.warn("The scan was interrupted (Ctrl+C).")
    elif outcome.timed_out:
        console.warn("The scanner was taking too long and was stopped.")
    elif outcome.returncode != 0:
        console.warn(f"The scanner exited with code {outcome.returncode}.")
    return outcome


def remember_result(session, verdict, lines, title=None):
    """Record the one-line verdict of a flow for the menu to repeat.

    Flows already print everything in full. This small record is the part that
    is shown again, right before the menu comes back, so the outcome of a test
    is the last thing on screen instead of a wall of scanner chatter.
    """
    session.last_result = {
        "verdict": str(verdict).upper(),
        "title": str(title) if title else str(verdict).upper(),
        "lines": [str(line) for line in lines if str(line).strip()],
    }
    return session.last_result


def _print_result_banner(console, result):
    """Print a saved verdict record as a short, colour-aware block."""
    verdict = str(result.get("verdict") or "INFO").upper()
    styles = {
        "PASS": ("green", "bold"),
        "OK": ("green", "bold"),
        "WARN": ("yellow", "bold"),
        "FAIL": ("red", "bold"),
    }
    console.line(f"{console.style('[' + verdict + ']', *styles.get(verdict, ('bold',)))}"
                 f" {console.style(result.get('title') or verdict, 'bold')}")
    for line in result.get("lines") or ():
        console.line(f"  {line}")


def _finish_flow(session):
    """Keep the result visible, wait for Enter, then let the menu redraw."""
    console = session.console
    console.rule()
    if session.last_result:
        _print_result_banner(console, session.last_result)
    console.blank()
    if not console.interactive:
        return
    try:
        console.pause("Press Enter to return to the menu")
    except Aborted:
        pass
    console.blank()


def _render_results_table(console, results, limit=None, recommended_ip=None):
    shown = list(results)
    if limit is not None and limit > 0:
        shown = shown[:limit]
    rows = []
    highlight = set()
    for position, item in enumerate(shown):
        rows.append([
            str(position + 1),
            item.ip,
            str(item.sent),
            str(item.received),
            item.loss_text(),
            item.latency_text(),
            item.colo_text(),
        ])
        if recommended_ip is not None and item.ip == recommended_ip:
            highlight.add(position)
    console.table(
        ["#", "IP address", "Sent", "Received", "Loss", "Latency", "Colo"],
        rows,
        aligns=["r", "l", "r", "r", "r", "r", "l"],
        highlight_rows=highlight,
        marker_col=1,
        legend="* = recommended IP" if highlight else None,
    )


def show_client_guide(console, profile, ip):
    """Explain exactly how to plug a verified IP into a client."""
    console.heading("How to use this IP in your client")
    console.key_value("Address", ip)
    console.key_value("Port", profile.get("port"))
    console.key_value("SNI", profile.get("domain"))
    console.key_value("Host", profile.get("domain"))
    console.blank()
    console.bullet(
        "Address - the verified Cloudflare IP. In your client's server list, "
        "replace the address (the 'address'/'server' field) with this IP."
    )
    console.bullet(
        f"Port - keep {profile.get('port')}, the port the scan measured. A "
        "different port usually means a different service and must be verified "
        "again."
    )
    console.bullet(
        f"SNI (TLS server name) - set it to {profile.get('domain')}. The client "
        "sends this name during the TLS handshake, so the CDN knows which site "
        "you want."
    )
    console.bullet(
        f"Host (HTTP Host header) - usually the same as SNI "
        f"({profile.get('domain')}). Only change it when your CDN expects a "
        "different host."
    )
    console.bullet(
        "cfscan never touches DNS, your VPN or your Cloudflare account, and it "
        "never asks for a UUID, password, private key or subscription link - you "
        "keep the credentials you already have."
    )


def show_top_ips(console, profile, results, limit=None, recommended_ip=None,
                 verified=None):
    """List the best addresses as ready-to-paste client settings.

    Every line carries its own IP, port and name, so any of them can be copied
    straight into a client - not only the single best one. When ``verified`` is
    given (a mapping of address to the measurement from the strict check), each
    line also carries that check's PASS/FAIL/DEAD verdict.
    """
    shown = list(results)
    if limit is not None and limit > 0:
        shown = shown[:limit]
    if not shown:
        return shown

    attempts = int(profile.get("verify_attempts") or 20)
    port = profile.get("port")
    domain = profile.get("domain")
    console.heading(f"Top {len(shown)} IPs you can use")
    for position, item in enumerate(shown, start=1):
        status = ""
        measured = item
        if verified is not None:
            row = verified.get(item.ip)
            status = _verify_verdict(row, attempts)
            if row is not None:
                measured = row
        if status == "DEAD":
            latency, loss, colo = "-", "-", "-"
        else:
            latency = measured.latency_text()
            loss = measured.loss_text()
            colo = measured.colo_text()
        style = {"PASS": ("green", "bold"), "FAIL": ("red", "bold"),
                 "DEAD": ("red", "bold")}.get(status)
        prefix = ""
        if verified is not None:
            prefix = console.style(f"{status:<4}", *style) + " "
        marker = "  *" if item.ip == recommended_ip else ""
        console.line(
            f"{position:>3}. {prefix}{item.ip:<15} {latency:>10} "
            f"{loss:>4}  {colo:<3}  Port {port}  SNI/Host {domain}{marker}"
        )
    console.blank()
    if verified is not None:
        console.line(console.style(
            f"PASS = {attempts}/{attempts} attempts answered, 0% loss   "
            "FAIL = packets were lost   DEAD = not one attempt came back   "
            "* = recommended IP", "dim"))
        console.blank()
    if _is_origin_independent_probe(profile):
        # This recipe is answered by Cloudflare itself, so a PASS proves the
        # address reaches the edge from this line - not that the node behind it
        # can be served. Saying "use this in your client" would be a lie until
        # the origin side answers too.
        console.bullet(
            "Each line above is complete: put its IP in the Address (server) "
            f"field of your client, keep port {port}, and set SNI and Host to "
            f"{domain}. What was measured is Cloudflare's edge answering from "
            "this line, because this profile's test URL is the plain-HTTP probe "
            "Cloudflare replies to itself. For the client to work, the node must "
            "also be reachable by Cloudflare (menu 1's preflight reports that)."
        )
    else:
        console.bullet(
            "Each line above is complete: put its IP in the Address (server) field "
            f"of your client, keep port {port}, and set SNI and Host to {domain}. "
            "The columns are the measured latency, packet loss and Cloudflare colo."
        )
    if verified is not None:
        console.bullet(
            f"Those marks come from {attempts} fresh attempts per address, run "
            "just now. A FAIL or DEAD address was still fast a minute ago, so it "
            "may be worth re-checking - but only a PASS is proven right now. "
            "Menu 3 re-measures a single address."
        )
    else:
        console.bullet(
            f"The first line is the fastest one. Menu 3 verifies any of them with "
            f"{attempts} attempts and 0% packet loss required, so verify the "
            "address you actually use."
        )
    return shown


def verify_addresses(session, config, profile, addresses, label="Verifying the best"):
    """Measure an explicit list of addresses in a single scanner run.

    Returns a mapping of address to the measurement the scanner reported; an
    address missing from that mapping answered nothing. ``None`` means no
    verdict is available at all (nothing to check, the run could not start, or
    it was stopped), and in that case the caller simply keeps the scan view.
    The scan measurements are never lost either way. A multi-carrier round
    verifies its own best addresses *plus* everything earlier rounds proved, so
    every verified address carries a verdict on every carrier.
    """
    console = session.console
    addresses = [str(item) for item in addresses if str(item or "").strip()]
    if not addresses:
        return None

    attempts = int(profile.get("verify_attempts") or session.verify_attempts or 20)
    cfst = _cfst_path(config)
    store = ResultStore(session.paths)
    csv_path = store.new_csv(f"verify-top-{len(addresses)}")
    log_path = store.log_for(csv_path)

    list_path = None
    try:
        handle = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False,
            prefix="cfscan-verify-", suffix=".txt",
        )
        try:
            handle.write("\n".join(addresses) + "\n")
        finally:
            handle.close()
        list_path = handle.name
    except OSError as error:
        console.warn(f"The addresses to verify could not be listed: {error}")
        return None

    argv = build_verify_many_argv(cfst, profile, list_path, csv_path,
                                  attempts=attempts,
                                  results_limit=len(addresses))
    try:
        console.blank()
        console.line(f"{label} {len(addresses)} addresses with "
                     f"{attempts} attempts each (0% packet loss required). "
                     "Press Ctrl+C to skip this step.")
        outcome = _execute_scan(session, argv, log_path, label="Verifying")
    except (CfstNotFoundError, ScanError) as exc:
        console.error(str(exc))
        console.line("The scan results above are still valid; only the strict "
                     "check was skipped.")
        return None
    finally:
        if list_path:
            try:
                os.unlink(list_path)
            except OSError:
                pass

    if outcome.interrupted:
        console.warn("The strict check was stopped, so no verdicts are shown; "
                     "the scan measurements stay as they were.")
        return None

    try:
        report = parse_results_csv(csv_path)
    except CsvError:
        if outcome.returncode == 0 and not outcome.has_result:
            # The run finished normally and wrote nothing: the scanner reports an
            # address only once it has answered at least once, so every one of
            # them is DEAD right now. Saying that is more useful than showing no
            # verdict at all.
            console.warn(f"The strict check answered nothing at all for these "
                         f"{len(addresses)} addresses; the scanner log shows why "
                         f"({log_path}).")
            return {}
        return None
    return {item.ip: item for item in report.results}


def verify_top_candidates(session, config, profile, results, limit=None):
    """Measure the best addresses of a scan in one scanner run."""
    return verify_addresses(session, config, profile,
                            [item.ip for item in list(results)[:limit]])


def _finish_scan_results(session, config, profile, results, top_n, recommended,
                         csv_path, flow):
    """Verify the best addresses, print the table and the offer, record a verdict.

    Returns ``(verified, passed, marked_ip)``: the measurements from the strict
    check (``None`` when it did not run), the addresses that passed it, and the
    address presented as the recommendation.
    """
    console = session.console
    attempts = int(profile.get("verify_attempts") or session.verify_attempts or 20)
    shown = list(results)[:top_n]

    verified = None
    if _auto_verify_enabled(session, profile):
        verified = verify_top_candidates(session, config, profile, results, top_n)

    passed = [item for item in shown
              if verified is not None
              and _verify_verdict(verified.get(item.ip), attempts) == "PASS"]
    if passed:
        marked_ip = passed[0].ip
    elif recommended is not None:
        marked_ip = recommended.ip
    else:
        marked_ip = None

    console.blank()
    console.heading(f"Results ({len(results)} reachable address(es))")
    _render_results_table(console, shown, recommended_ip=marked_ip)
    if len(results) > top_n:
        console.line(f"The best {top_n} of {len(results)} are shown; menu 4 "
                     "lists every address in the saved file.")

    console.blank()
    if verified is not None and passed:
        best = passed[0]
        console.ok(f"Best verified address: {best.ip} - {best.latency_text()}, "
                   f"0% loss, colo {best.colo_text()}.")
    elif verified is not None:
        console.warn("None of the tested addresses passed the strict check right "
                     "now; the numbers in the list below come from the scan.")
    elif recommended is not None:
        console.ok(
            f"Recommended IP: {recommended.ip} - {recommended.latency_text()}, "
            f"{recommended.loss_text()} packet loss, colo {recommended.colo_text()}."
        )

    show_top_ips(console, profile, shown, recommended_ip=marked_ip,
                 verified=verified)

    lines = []
    if verified is None:
        if recommended is not None:
            lines.append(f"Recommended IP: {recommended.ip} - "
                         f"{recommended.latency_text()}, "
                         f"{recommended.loss_text()} packet loss, colo "
                         f"{recommended.colo_text()}")
        verdict = ("PASS" if recommended is not None and recommended.is_loss_free
                   else "WARN")
    else:
        lines.append(f"{len(passed)} of {len(shown)} addresses passed the "
                     f"{attempts}-attempt check (0% loss required)")
        if passed:
            best = passed[0]
            lines.append(f"Fastest verified: {best.ip} - {best.latency_text()}, "
                         f"colo {best.colo_text()}")
        else:
            lines.append("No address passed - re-run the scan, or verify one "
                         "address from menu 3")
        verdict = "PASS" if passed else "FAIL"
    lines.append(f"Saved: {csv_path}")
    remember_result(session, verdict, lines,
                    title=f"{flow} - best {len(shown)} addresses")
    return verified, passed, marked_ip


def _explain_empty(console, outcome, profile, session):
    console.warn("No IP passed the filters this time, so there is no ranking to show.")
    if int(profile.get("ip_version", 4) or 4) == 6 and not ipv6_route_available():
        console.bullet(
            "This profile scans IPv6 and this Mac has no route to an IPv6 "
            "address, so no candidate can answer. Check 'ifconfig | grep inet6' "
            "for a global address, or switch the profile back to IPv4 in menu 7."
        )
    translated = outcome.translated_log()
    if translated:
        console.blank()
        console.line("Scanner messages (translated):")
        for line in translated:
            console.line(f"  {line}")
    console.heading("Troubleshooting")
    console.bullet(
        f"Expected HTTP status is {profile.get('http_status')}. If the site behind "
        f"{profile.get('domain')} is down or has no certificate on port "
        f"{profile.get('port')}, Cloudflare answers with 5xx and every candidate "
        "is filtered out."
    )
    console.bullet(
        "Check the domain in a browser first. When it answers normally, set the "
        "expected status to 200 (menu 6 -> edit the profile)."
    )
    console.bullet(
        "Scheme tip: with scheme=https the scanner performs a real TLS request. "
        "Using scheme=http sends a plain request to the HTTPS port instead, which "
        "makes Cloudflare itself answer 400 - a quick port liveness probe that "
        "does not depend on your origin server."
    )
    console.bullet(
        f"Make sure the IP range file exists and has content: {ip_file_for(profile)}"
    )
    console.bullet(
        f"Filters may be too strict: max latency {profile.get('max_latency_ms')} ms, "
        f"max packet loss {float(profile.get('max_loss', 0)) * 100:g}%."
    )
    if outcome.log_path:
        console.bullet(f"Raw scanner log: {outcome.log_path}")


def _probe_candidates(profile):
    """The addresses the preflight tries, best first (at most three)."""
    candidates = []
    preferred = str(profile.get("recommended_ip") or "").strip()
    if preferred:
        candidates.append(preferred)
    for address in PROBE_ADDRESSES:
        if address not in candidates:
            candidates.append(address)
    return candidates[:3]


def _discard_probe_result(csv_path):
    """Remove a preflight result file, so it is never mistaken for a scan."""
    try:
        if csv_path and Path(csv_path).exists():
            Path(csv_path).unlink()
    except OSError:  # pragma: no cover - nothing to do about it
        pass


#: A status code no real server returns. Asking the scanner for it makes it
#: report the status the edge actually answered, instead of silently dropping
#: the address as a mismatch.
EDGE_PROBE_STATUS = 599


def _is_origin_independent_probe(profile):
    """True for the plain-HTTP-on-an-HTTPS-port probe.

    Cloudflare answers that combination itself, so the numbers only describe the
    edge: the node behind it is not measured at all, and an address that passes
    can still be useless to a TLS client when the edge has no origin to reach.
    """
    if str(profile.get("mode") or "httping").lower() != "httping":
        return False
    if str(profile.get("scheme") or "https").lower() != "http":
        return False
    try:
        return int(profile.get("port")) in CLOUDFLARE_HTTPS_PORTS
    except (TypeError, ValueError):
        return False


def _edge_status_check(session, cfst, name, profile, address):
    """Ask the edge for the TLS URL and return the status rejection it printed."""
    store = ResultStore(session.paths)
    csv_path = store.new_csv(f"edgecheck-{profile_slug(name)}")
    log_path = store.log_for(csv_path)
    tls_profile = dict(profile, scheme="https", http_status=EDGE_PROBE_STATUS)
    argv = build_probe_argv(cfst, tls_profile, address, csv_path, attempts=2)
    outcome = _execute_scan(session, argv, log_path, label="Edge check")
    _discard_probe_result(csv_path)
    if outcome.interrupted:
        return None
    return extract_status_rejection(outcome.log_text)


def _report_edge_status(console, profile, rejection):
    """Say whether the addresses found can also serve a TLS client."""
    domain = profile.get("domain")
    if not rejection:
        console.info("The TLS check for this domain answered nothing, so nothing "
                     "is known about the node behind the edge.")
        return
    observed = int(rejection["observed"])
    if 500 <= observed <= 599:
        console.warn(
            f"Cloudflare answered {observed} for the TLS URL of {domain}: that is "
            "its own error page, not your node. The addresses below do reach the "
            "edge, but a client (TLS + SNI) fails until the edge can reach the "
            "node - nothing is listening on the origin port Cloudflare uses "
            "(443 unless an Origin Rule says otherwise), or the node's transport "
            "is not HTTP(S)."
        )
    else:
        console.ok(f"The edge reached a server for {domain} (HTTP {observed} on "
                   "443), so these addresses can serve the client too.")


def preflight_probe(session, config, name, profile):
    """Measure one address with the profile's own test URL before a full scan.

    A profile that cannot work - a scheme the port does not speak, a hostname
    Cloudflare does not serve, an origin that is down - spends minutes over
    thousands of addresses and then reports "no result" without saying why.
    Measuring a single address first turns that into an immediate explanation
    and costs one request. Returns True when the scan should go ahead.
    """
    console = session.console
    if session.dry_run or int(profile.get("ip_version", 4)) == 6:
        return True
    if not getattr(session, "preflight", True):
        return True

    cfst = _cfst_path(config)
    try:
        check_cfst(cfst)
    except CfstNotFoundError as exc:
        console.error(str(exc))
        return False

    store = ResultStore(session.paths)
    csv_path = store.new_csv(f"preflight-{profile_slug(name)}")
    log_path = store.log_for(csv_path)
    candidates = _probe_candidates(profile)

    console.blank()
    console.line("Preflight: measuring one address with this profile's own test "
                 f"URL ({_url_for(profile)}) before the whole range.")

    outcome = None
    address = candidates[0] if candidates else None
    for address in candidates:
        argv = build_probe_argv(cfst, profile, address, csv_path, attempts=2)
        outcome = _execute_scan(session, argv, log_path, label="Preflight")
        if outcome.interrupted:
            _discard_probe_result(csv_path)
            console.warn("The preflight was stopped, so the scan was not started.")
            return False
        if outcome.has_result:
            break

    if outcome is not None and outcome.has_result:
        _discard_probe_result(csv_path)
        console.ok(f"Preflight passed: {address} answered the test URL, so this "
                   "profile can produce results.")
        if _is_origin_independent_probe(profile):
            # Cloudflare answered the test URL itself, so the scan below measures
            # the edge only. Whether the node behind it is reachable decides if
            # the addresses are usable, so ask that too.
            _report_edge_status(console, profile,
                                _edge_status_check(session, cfst, name, profile,
                                                   address))
        return True

    _discard_probe_result(csv_path)
    console.warn(f"Preflight failed: none of the {len(candidates)} Cloudflare "
                 "addresses tried answered this profile's test URL, so a full "
                 "scan is expected to return nothing.")
    hints = explain_failure(outcome.log_text if outcome is not None else "",
                            profile, address)
    if not hints:
        hints = [
            f"Check that {_url_for(profile)} answers at all, and that the expected "
            f"status {profile.get('http_status')} is the one it really returns "
            "(menu 6 edits the profile).",
        ]
    console.blank()
    console.line("Why this profile cannot work:")
    for hint in hints[:3]:
        console.bullet(hint)
    if outcome is not None and outcome.log_path:
        console.line(f"Preflight scanner log: {outcome.log_path}")

    if not console.interactive or session.assume_yes:
        console.warn("Scanning the range anyway; the result file will most "
                     "likely be empty.")
        return True
    console.blank()
    return console.ask_yes_no("Scan the whole range anyway?", default=False)


def _guard(session, config, argv, log_path, csv_path, flow="Scan"):
    """Shared tail for scan flows: run, then return the outcome or a code."""
    try:
        outcome = _execute_scan(session, argv, log_path)
    except CfstNotFoundError as exc:
        session.console.error(str(exc))
        return EXIT_MISSING_TOOL, None
    except ScanError as exc:
        # Anything else that went wrong while starting or driving the scanner
        # (a binary this machine cannot run, an unwritable results folder, ...)
        # must never reach the user as a Python traceback.
        session.console.error(str(exc))
        session.console.line("Check 'cfst_path' and the results folder, then "
                             "try again (menu 6 edits the profile).")
        return EXIT_FAILED, None
    if outcome.interrupted:
        remember_result(session, "WARN", [
            "The scan was stopped before it finished - nothing else was changed.",
            f"Raw scanner log: {log_path}",
        ], title=f"{flow} - interrupted")
        return EXIT_INTERRUPTED, outcome
    if not outcome.has_result:
        _explain_empty(session.console, outcome, _active_for_log(config), session)
        remember_result(session, "FAIL", [
            "The scanner wrote no result file for this run.",
            f"Raw scanner log: {log_path}",
        ], title=f"{flow} - no usable result")
        return EXIT_FAILED, outcome
    return EXIT_OK, outcome


def _active_for_log(config):
    try:
        return get_active(config)[1]
    except UnknownProfile:  # pragma: no cover - defensive
        return {}


# --------------------------------------------------------------------------
# Flow 1: quick scan
# --------------------------------------------------------------------------

def quick_scan(session, config, profile_name=None, verify_prompt=True):
    """Scan with the active profile, then show a ranked table."""
    console = session.console
    name, profile = _profile_pair(config, profile_name)

    console.heading("Quick Scan")
    console.line("The active profile is used. Press Ctrl+C at any time to stop.")
    console.blank()
    _render_profile(console, name, profile)

    cfst = _cfst_path(config)
    store = ResultStore(session.paths)
    csv_path = store.new_csv(profile_slug(name))
    log_path = store.log_for(csv_path)
    top_n = _top_ips(session, profile)
    argv = build_scan_argv(cfst, profile, csv_path,
                           results_limit=_requested_results(profile, top_n))

    if session.dry_run:
        _print_dry_run(console, argv, csv_path, log_path)
        return EXIT_OK

    try:
        check_cfst(cfst)
    except CfstNotFoundError as exc:
        console.error(str(exc))
        return EXIT_MISSING_TOOL

    range_file = Path(ip_file_for(profile))
    if not range_file.exists():
        console.error(f"The IP range file was not found: {range_file}")
        console.line("Install the Cloudflare IP lists, or point the profile at "
                     "another file (menu 6 -> edit the profile).")
        return EXIT_MISSING_TOOL

    console.blank()
    if not session.assume_yes and not console.ask_yes_no("Run this scan now?",
                                                         default=True):
        console.warn("Cancelled - nothing was executed.")
        return EXIT_OK

    if not preflight_probe(session, config, name, profile):
        console.warn("Cancelled - nothing was executed.")
        return EXIT_FAILED

    code, outcome = _guard(session, config, argv, log_path, csv_path,
                           flow="Quick Scan")
    if outcome is None or code != EXIT_OK:
        return code

    try:
        report = parse_results_csv(csv_path)
    except CsvError as exc:
        console.error(str(exc))
        remember_result(session, "FAIL", [str(exc)],
                        title="Quick Scan - unreadable result file")
        return EXIT_FAILED

    for warning in report.warnings:
        console.warn(warning)

    results = rank_results(report.results)
    if not results:
        _explain_empty(console, outcome, profile, session)
        remember_result(session, "FAIL", [
            "No IP passed the filters this time.",
            f"Raw scanner log: {log_path}",
        ], title="Quick Scan - no usable result")
        return EXIT_FAILED

    recommended = recommend(results, preferred_ip=profile.get("recommended_ip"))
    if recommended is not None and not recommended.is_loss_free:
        console.warn("The fastest address already lost packets during the scan; "
                     "the strict check below decides what to trust.")

    verified, passed, marked_ip = _finish_scan_results(
        session, config, profile, results, top_n, recommended, csv_path,
        flow="Quick Scan",
    )

    store.record_latest(config, csv_path, profile_name=name,
                        recommended_ip=marked_ip)
    console.blank()
    console.line(f"Saved: {csv_path}")
    console.line(f"Scanner log: {log_path}")
    console.line("Open menu 8 to show the results folder in Finder.")

    if verified is None:
        if verify_prompt and recommended is not None:
            attempts = int(profile.get("verify_attempts")
                           or session.verify_attempts or 20)
            console.blank()
            question = (f"Run a stronger {attempts}-attempt verification "
                        f"on {recommended.ip}?")
            if console.ask_yes_no(question, default=True):
                return verify_flow(session, config, ip=recommended.ip,
                                   profile_name=name)
    else:
        console.blank()
        console.line("Menu 3 re-measures one address, and menu 4 lists every "
                     "address from this scan.")
    return EXIT_OK


# --------------------------------------------------------------------------
# Flow 2: custom scan
# --------------------------------------------------------------------------

def _ask_profile_name(console, config, current, force_save):
    """Ask for the profile name, refusing to replace one by accident.

    Every other prompt in this flow starts from the *active* profile's values,
    so typing the name of a profile that already exists would silently replace
    it with a copy of the active one. That is called out and confirmed instead.
    """
    while True:
        if force_save:
            # A new profile must be named: pressing Enter alone would otherwise
            # overwrite the active profile.
            typed = console.ask("Profile name", default=None,
                               validate=validate_profile_name)
        else:
            typed = console.ask("Profile name", default=current,
                                validate=validate_profile_name)
        if not force_save or typed == current:
            return typed
        stored = (config.get("profiles") or {}).get(typed)
        if stored is None:
            return typed
        console.warn(
            f"A profile named '{typed}' already exists (domain "
            f"{stored.get('domain')}, port {stored.get('port')}). The prompts "
            f"below start from '{current}', so continuing would replace the "
            "saved one with those values."
        )
        if console.ask_yes_no(f"Replace '{typed}'?", default=False):
            return typed


def _offer_to_activate(session, config, name):
    """Say which profile stays active, and offer to switch to the saved one."""
    active = config.get("active_profile")
    if name == active:
        return
    console = session.console
    console.warn(f"'{name}' is saved but not active; scans keep using "
                 f"'{active}' until you make it active (menu 6).")
    if not console.interactive or session.assume_yes:
        return
    if console.ask_yes_no(f"Make '{name}' the active profile now?", default=True):
        set_active(config, name)
        save_config(session.paths, config)
        console.ok(f"Active profile: {name}")


def custom_scan(session, config, profile_name=None, force_save=False,
                save_prompt=True):
    """Ask for every setting, then optionally save and run it."""
    console = session.console
    name, base = _profile_pair(config, profile_name)

    console.heading("Custom Scan")
    console.line("Press Enter to keep the value shown in brackets.")

    # "Add a new profile" must not silently reuse the current name: without a
    # default, pressing Enter alone re-prompts instead of overwriting.
    new_name = _ask_profile_name(console, config, name, force_save)
    domain = console.ask("Domain", default=base.get("domain"),
                         validate=validate_domain)
    port = console.ask("Port", default=base.get("port"), validate=validate_port)
    ip_version = int(console.ask_choice(
        "IP version", [("4", "IPv4"), ("6", "IPv6")],
        default=str(base.get("ip_version", 4)),
    ))
    mode_key = console.ask_choice(
        "Protocol mode",
        [("1", "HTTPing (send an HTTP/S request to the domain)"),
         ("2", "TCPing (plain TCP connect, no HTTP status to match)")],
        default="1" if str(base.get("mode")) == "httping" else "2",
    )
    mode = "httping" if mode_key == "1" else "tcp"

    if mode == "httping":
        scheme_key = console.ask_choice(
            "URL scheme used for the test request",
            [("1", "https - a real TLS request, the same thing your client does"),
             ("2", "http - a plain request to the HTTPS port; Cloudflare answers "
                   "400 (origin independent)")],
            default="1" if str(base.get("scheme") or "https").lower() == "https"
            else "2",
        )
        scheme = "https" if scheme_key == "1" else "http"
        http_status = console.ask("Expected HTTP status code",
                                  default=base.get("http_status"),
                                  validate=validate_http_status)
    else:
        scheme = str(base.get("scheme") or "https").lower()
        http_status = base.get("http_status")

    attempts = console.ask_int("Number of ping attempts", default=base.get("attempts"),
                               minimum=1, maximum=100, field="attempts")
    concurrency = console.ask_int("Concurrency (parallel workers)",
                                  default=base.get("concurrency"), minimum=1,
                                  maximum=1000, field="concurrency")
    max_latency = console.ask_int("Maximum average latency (ms)",
                                  default=base.get("max_latency_ms"), minimum=1,
                                  maximum=60000, field="maximum latency")
    max_loss = console.ask_loss("Maximum packet loss (percent)",
                                default=base.get("max_loss"))
    results_limit = console.ask_int("Number of results to display",
                                    default=base.get("results_limit"), minimum=1,
                                    maximum=1000, field="displayed results")
    download_test = console.ask_yes_no(
        "Enable the download speed test (slower)?",
        default=bool(base.get("download_test")),
    )
    # Editing the profile in front of you keeps its established file name; a new
    # profile gets one named after itself, instead of inheriting the file name
    # of the profile it was copied from.
    if new_name == name and base.get("output_filename"):
        default_filename = str(base["output_filename"])
    else:
        default_filename = f"cfscan-{profile_slug(new_name)}-{timestamp_label()}.csv"
    filename = console.ask(
        "Output filename",
        default=default_filename,
        validate=validate_output_filename,
    )

    profile = dict(base)
    profile.update({
        "name": new_name,
        "domain": domain,
        "port": port,
        "mode": mode,
        "scheme": scheme,
        "http_status": http_status,
        "attempts": attempts,
        "concurrency": concurrency,
        "max_latency_ms": max_latency,
        "max_loss": max_loss,
        "results_limit": results_limit,
        "download_test": download_test,
        "output_filename": filename,
    })
    set_ip_version(profile, ip_version)

    # A verified IP only means something for the domain and port it was tested
    # against, so a different target must not inherit it (it would otherwise
    # outrank faster addresses in the ranking below).
    if domain != base.get("domain") or port != base.get("port"):
        profile["recommended_ip"] = None

    if force_save:
        save_it = True
    elif save_prompt:
        save_it = console.ask_yes_no("Save this profile for later?", default=False)
    else:
        save_it = False

    if save_it:
        upsert_profile(config, new_name, profile)
        save_config(session.paths, config)
        console.ok(f"Profile '{new_name}' saved to {session.paths.config_file}")
        _offer_to_activate(session, config, new_name)

    cfst = _cfst_path(config)
    store = ResultStore(session.paths)
    csv_path = store.named_csv(filename)
    log_path = store.log_for(csv_path)
    top_n = _top_ips(session, profile)
    argv = build_scan_argv(cfst, profile, csv_path,
                           results_limit=_requested_results(profile, top_n))

    console.blank()
    console.heading("Summary")
    _render_profile(console, new_name, profile)

    if session.dry_run:
        _print_dry_run(console, argv, csv_path, log_path)
        return EXIT_OK

    try:
        check_cfst(cfst)
    except CfstNotFoundError as exc:
        console.error(str(exc))
        return EXIT_MISSING_TOOL

    range_file = Path(ip_file_for(profile))
    if not range_file.exists():
        console.error(f"The IP range file was not found: {range_file}")
        return EXIT_MISSING_TOOL

    console.blank()
    if not session.assume_yes and not console.ask_yes_no("Run this scan now?",
                                                         default=True):
        console.warn("Cancelled - nothing was executed.")
        return EXIT_OK

    if not preflight_probe(session, config, new_name, profile):
        console.warn("Cancelled - nothing was executed.")
        return EXIT_FAILED

    code, outcome = _guard(session, config, argv, log_path, csv_path,
                           flow="Custom Scan")
    if outcome is None or code != EXIT_OK:
        return code

    try:
        report = parse_results_csv(csv_path)
    except CsvError as exc:
        console.error(str(exc))
        remember_result(session, "FAIL", [str(exc)],
                        title="Custom Scan - unreadable result file")
        return EXIT_FAILED
    for warning in report.warnings:
        console.warn(warning)

    results = rank_results(report.results)
    if not results:
        _explain_empty(console, outcome, profile, session)
        remember_result(session, "FAIL", [
            "No IP passed the filters this time.",
            f"Raw scanner log: {log_path}",
        ], title="Custom Scan - no usable result")
        return EXIT_FAILED

    recommended = recommend(results, preferred_ip=profile.get("recommended_ip"))
    if recommended is not None and not recommended.is_loss_free:
        console.warn("The fastest address already lost packets during the scan; "
                     "the strict check below decides what to trust.")

    verified, passed, marked_ip = _finish_scan_results(
        session, config, profile, results, top_n, recommended, csv_path,
        flow="Custom Scan",
    )

    store.record_latest(config, csv_path, profile_name=new_name,
                        recommended_ip=marked_ip)
    console.blank()
    console.line(f"Saved: {csv_path}")
    console.line("Use menu 3 (Verify an IP) to re-check one address before you "
                 "use it.")
    return EXIT_OK


# --------------------------------------------------------------------------
# Flow 3: verify a single IP
# --------------------------------------------------------------------------

def verify_flow(session, config, ip=None, profile_name=None):
    """Prove (or disprove) one address with 20 attempts and zero loss allowed."""
    console = session.console
    name, profile = _profile_pair(config, profile_name)
    version = int(profile.get("ip_version", 4))
    attempts = int(profile.get("verify_attempts") or session.verify_attempts or 20)

    console.heading("Verify an IP")

    if ip is None:
        ip = console.ask(
            f"IP address to verify (IPv{version})",
            default=profile.get("recommended_ip"),
            validate=lambda value: str(validate_ip(value, version=version)),
        )
    else:
        try:
            ip = str(validate_ip(ip, version=version))
        except ValidationError as exc:
            console.error(str(exc))
            return EXIT_USAGE

    console.line(
        f"Verifying {ip} against {profile.get('domain')} on port "
        f"{profile.get('port')} with {attempts} attempts."
    )
    console.line("The address passes only when every attempt is answered "
                 "(0% packet loss). The scanner reports what it measured even "
                 "when packets are lost, so a failure comes with its numbers.")

    cfst = _cfst_path(config)
    store = ResultStore(session.paths)
    csv_path = store.new_csv(f"verify-{ip}")
    log_path = store.log_for(csv_path)
    argv = build_verify_argv(cfst, profile, ip, csv_path, attempts=attempts)

    if session.dry_run:
        _print_dry_run(console, argv, csv_path, log_path)
        return EXIT_OK

    try:
        check_cfst(cfst)
    except CfstNotFoundError as exc:
        console.error(str(exc))
        return EXIT_MISSING_TOOL

    try:
        outcome = _execute_scan(session, argv, log_path)
    except CfstNotFoundError as exc:
        console.error(str(exc))
        return EXIT_MISSING_TOOL
    except ScanError as exc:
        console.error(str(exc))
        console.line("Check 'cfst_path' and the results folder, then try again.")
        return EXIT_FAILED

    if outcome.interrupted:
        console.warn("Verification interrupted (Ctrl+C).")
        remember_result(session, "WARN",
                        [f"{ip} was not verified - the run was stopped."],
                        title=f"Verify {ip} - interrupted")
        return EXIT_INTERRUPTED

    row = None
    try:
        report = parse_results_csv(csv_path)
        row = next((item for item in report.results if item.ip == ip), None)
    except CsvError:
        row = None

    console.blank()
    if _verify_verdict(row, attempts) == "PASS":
        console.ok(
            f"PASS - {ip} answered {row.received}/{row.sent} attempts with 0% "
            "packet loss."
        )
        console.line(f"Average latency: {row.latency_text()}    "
                     f"Colo: {row.colo_text()}")
        show_client_guide(console, profile, ip)
        store.record_latest(config, csv_path, profile_name=name, recommended_ip=ip)
        remember_result(
            session, "PASS",
            [f"{ip} answered {row.received}/{row.sent} attempts, 0% packet loss",
             f"Average latency {row.latency_text()}    Colo {row.colo_text()}",
             f"Client fields - Address {ip}, Port {profile.get('port')}, "
             f"SNI {profile.get('domain')}, Host {profile.get('domain')}"],
            title=f"Verify {ip} - PASS",
        )
        return EXIT_OK

    console.error(f"FAIL - {ip} did not pass verification.")
    reasons = []
    if row is not None:
        console.line(f"Replies: {row.received}/{row.sent}    "
                     f"Packet loss: {row.loss_text()}    "
                     f"Average latency: {row.latency_text()}")
        reasons.append(f"Replies {row.received}/{row.sent}, packet loss "
                       f"{row.loss_text()}, latency {row.latency_text()}")
        if row.received < row.sent:
            console.line("Packet loss must be exactly 0% to pass, but "
                         f"{row.loss_text()} was measured. Re-run the scan and "
                         "pick another address.")
    info = extract_status_rejection(outcome.log_text)
    if info is not None:
        expected = info.get("expected")
        console.line(
            f"The address is reachable, but the scanner observed HTTP status "
            f"{info['observed']} while {expected} was required. Fix the expected "
            "status (menu 6) or make sure the site answers on that URL."
        )
        reasons.append(f"HTTP status {info['observed']} observed while "
                       f"{expected} was required")
    else:
        console.line("Not one attempt was answered, and the scanner reported no "
                     "HTTP status either, so the address is currently unreachable "
                     "from this network - pick another candidate.")
        reasons.append("No attempt was answered and no HTTP status was reported - "
                       "the address is unreachable right now")

    console.line(f"Raw scanner log: {log_path}")
    if latest_result_path(config, session.paths):
        console.line("Menu 4 shows the last full scan, menu 3 lets you try "
                     "another address.")
    remember_result(session, "FAIL",
                    reasons + [f"Scanner log: {log_path}"],
                    title=f"Verify {ip} - FAIL")
    return EXIT_FAILED


# --------------------------------------------------------------------------
# Flow 4: last results
# --------------------------------------------------------------------------

def show_last_results(session, config, path=None):
    console = session.console
    console.heading("Last results")

    target = Path(path) if path else latest_result_path(config, session.paths)
    if target is None:
        console.warn("No saved results yet. Run a Quick Scan first (menu 1).")
        return EXIT_OK

    try:
        report = parse_results_csv(target)
    except CsvError as exc:
        console.error(str(exc))
        return EXIT_FAILED

    try:
        saved_at = datetime.fromtimestamp(target.stat().st_mtime)
    except OSError:
        saved_at = None

    console.line(f"File: {target}")
    if saved_at is not None:
        console.line(f"Saved: {saved_at:%Y-%m-%d %H:%M:%S}")
    for warning in report.warnings:
        console.warn(warning)

    results = rank_results(report.results)
    if not results:
        console.line("There is nothing to display in this file.")
        remember_result(session, "WARN",
                        [f"{target.name} has no usable row"],
                        title="Last results")
        return EXIT_OK

    # The IP that was recommended when this file was written is highlighted, so
    # the file matches what the scan told the user at the time.
    preferred = (config.get("last_result") or {}).get("recommended_ip")
    _render_results_table(console, results, recommended_ip=preferred)
    console.blank()
    console.line(f"{len(results)} address(es) in this file.")
    if preferred:
        console.ok(f"Recommended IP: {preferred} - marked with * in the table.")
    remember_result(session, "INFO", [
        f"{len(results)} address(es) in {target.name}",
        f"Recommended IP: {preferred}" if preferred else "No recommended IP stored",
        f"File: {target}",
    ], title="Last results")
    return EXIT_OK


# --------------------------------------------------------------------------
# Flow 5: profiles
# --------------------------------------------------------------------------

def show_profiles(session, config):
    console = session.console
    console.heading("Saved profiles")
    active = config.get("active_profile")
    rows = []
    for name, profile in (config.get("profiles") or {}).items():
        rows.append([
            name,
            str(profile.get("domain")),
            str(profile.get("port")),
            f"IPv{profile.get('ip_version', 4)}",
            str(profile.get("mode")),
            "active" if name == active else "",
        ])
    console.table(["Profile", "Domain", "Port", "IP", "Mode", "State"], rows)
    console.blank()
    console.line(f"Configuration file: {session.paths.config_file}")
    console.line("Menu 7 switches IPv4/IPv6, menu 6 adds, edits or deletes profiles.")
    return EXIT_OK


def _profile_choices(config):
    return [(str(index), name)
            for index, name in enumerate(config.get("profiles") or {}, start=1)]


def manage_profiles(session, config):
    console = session.console
    show_profiles(session, config)
    choice = console.ask_choice(
        "What would you like to do?",
        [("1", "Make a profile active"),
         ("2", "Add a new profile"),
         ("3", "Delete a profile"),
         ("0", "Back to the main menu")],
        default="0",
    )

    if choice == "1":
        return _make_profile_active(session, config)
    if choice == "2":
        return custom_scan(session, config, force_save=True, save_prompt=False)
    if choice == "3":
        return _delete_profile_flow(session, config)
    return EXIT_OK


def _make_profile_active(session, config):
    console = session.console
    choices = _profile_choices(config)
    selected = console.ask_choice("Which profile should be active?", choices,
                                  default="1")
    names = [name for _, name in choices]
    index = int(selected) - 1
    if index < 0 or index >= len(names):
        console.error("Invalid choice.")
        return EXIT_USAGE
    name = names[index]
    set_active(config, name)
    save_config(session.paths, config)
    console.ok(f"'{name}' is now the active profile.")
    return EXIT_OK


def _delete_profile_flow(session, config):
    console = session.console
    choices = _profile_choices(config)
    selected = console.ask_choice("Which profile should be deleted?", choices,
                                  default="1")
    names = [name for _, name in choices]
    index = int(selected) - 1
    if index < 0 or index >= len(names):
        console.error("Invalid choice.")
        return EXIT_USAGE
    name = names[index]

    if name == DEFAULT_PROFILE_KEY:
        console.warn(f"The built-in default profile '{DEFAULT_PROFILE_KEY}' cannot "
                     "be deleted, so there is always a working fallback.")
        return EXIT_OK

    if not console.ask_yes_no(f"Delete profile '{name}'? This cannot be undone.",
                              default=False):
        console.warn("Cancelled - the profile was kept.")
        return EXIT_OK

    delete_profile(config, name)
    save_config(session.paths, config)
    console.ok(f"Profile '{name}' deleted.")
    return EXIT_OK


# --------------------------------------------------------------------------
# Flow 7: IPv4 / IPv6
# --------------------------------------------------------------------------

def switch_ip_version(session, config):
    console = session.console
    name, profile = _profile_pair(config)
    current = int(profile.get("ip_version", 4))

    console.heading("Switch IPv4 / IPv6")
    console.line(f"Profile: {name}")
    console.line(f"Current: IPv{current} - {ip_file_for(profile)}")
    console.blank()

    choice = console.ask_choice(
        "Which address family should this profile use?",
        [("4", "IPv4 (recommended for most networks)"), ("6", "IPv6")],
        default=str(current),
    )
    target = int(choice)
    if target == current:
        console.ok(f"Nothing to change - IPv{current} is already selected.")
        return EXIT_OK

    probe = dict(profile)
    set_ip_version(probe, target)
    console.blank()
    if not console.ask_yes_no(
        f"Switch to IPv{target} and use {ip_file_for(probe)}?", default=True
    ):
        console.warn("Cancelled - the profile was left unchanged.")
        return EXIT_OK

    set_ip_version(profile, target)
    save_config(session.paths, config)
    console.ok(f"Profile '{name}' now uses IPv{target} ({ip_file_for(profile)}).")
    console.line("The next scan uses the new address family.")
    if target == 6 and not ipv6_route_available():
        # An IPv6 scan is guaranteed to come back empty here, and the reason is
        # never the scanner: most lines simply have no IPv6 route.
        console.blank()
        console.warn(
            "This Mac has no route to an IPv6 address right now, so an IPv6 "
            "scan cannot find anything (the scanner is fine - it reports 0 of "
            "every candidate). Check with 'ifconfig | grep inet6': a global "
            "address is needed, not only 'fe80::' link-local ones. Most mobile "
            "and home lines are IPv4-only; menu 7 switches back to IPv4."
        )
    return EXIT_OK


# --------------------------------------------------------------------------
# Flow 8 and 9
# --------------------------------------------------------------------------

def open_results_folder(session, config):
    console = session.console
    directory = Path(session.paths.results_dir)
    console.heading("Results folder")
    console.line(str(directory))
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        console.error(f"The results folder could not be created: {exc}")
        return EXIT_FAILED
    if results_module.open_in_finder(directory):
        console.ok("Finder opened.")
        return EXIT_OK
    console.warn("Finder could not be opened automatically. Open the path above "
                 "in Finder manually.")
    return EXIT_OK


def help_screen(session, config):
    console = session.console
    console.heading("Help")
    console.line("cfscan is a friendly wrapper around XIU2/CloudflareSpeedTest "
                 "(the cfst binary). It never rewrites the scanner; it builds "
                 "safe arguments, hides the Chinese output and ranks the results.")
    console.blank()

    console.line(console.style("Menu", "bold"))
    for key, label in MENU_ITEMS:
        console.bullet(f"{key}. {label}")

    console.blank()
    console.line(console.style("How a scan works", "bold"))
    console.bullet("Every address from the IP range file is pinged with HTTPing or "
                   "TCPing. With HTTPing the scanner sends a request to the test "
                   "URL and matches the HTTP status code you configured.")
    console.bullet("Filters decide what counts as a good address: maximum average "
                   "latency and maximum packet loss. Everything else is dropped "
                   "before the ranking is built.")
    console.bullet("The download speed test is optional and much slower, so it is "
                   "off by default.")

    console.blank()
    console.line(console.style("Choosing an address you can trust", "bold"))
    console.bullet("Use menu 3 to verify one address with 20 attempts. It only "
                   "passes when every attempt is answered (0% packet loss).")
    console.bullet("A pass means the address answered your port and matched your "
                   "expected status right now. Networks change, so re-verify after "
                   "switching Wi-Fi, VPN or carrier.")

    console.blank()
    console.line(console.style("Client configuration", "bold"))
    console.bullet("Address - the verified Cloudflare IP (the 'server' field in "
                   "your client).")
    console.bullet("Port - the port measured by the scan.")
    console.bullet("SNI - your domain name, sent during the TLS handshake.")
    console.bullet("Host - the HTTP Host header, normally the same as SNI.")
    console.bullet("cfscan never asks for or stores a UUID, password, private key "
                   "or subscription link, and it never changes DNS or VPN settings "
                   "for you.")

    console.blank()
    console.line(console.style("IPv4 and IPv6", "bold"))
    console.bullet("Menu 7 switches the active profile between IPv4 and IPv6; each "
                   "version uses its own IP range file.")

    console.blank()
    console.line(console.style("Several carriers", "bold"))
    console.bullet("Menu 10 measures the same candidate list on several carriers "
                   "(MCI, Irancell, ...) in one sitting: it asks how many first, "
                   "then waits between rounds so you can switch the connection, "
                   "and finishes with the addresses that work on every carrier, "
                   "the fastest address per carrier, and - when nothing works "
                   "everywhere - the address that covers the most carriers.")
    console.bullet("Every round scans the very same addresses. The scanner draws a "
                   "fresh sample from the range file on each run, so without a "
                   "fixed list two carriers would never measure the same "
                   "addresses and nothing could be compared.")
    console.bullet("The rounds are stored as you go (results folder -> multi-isp), "
                   "so the report survives a dropped hotspot and can be printed "
                   "again with 'cfscan --multi-isp'.")

    console.blank()
    console.line(console.style("Command line", "bold"))
    console.bullet("cfscan                     open this menu")
    console.bullet("cfscan --quick --yes       run the active profile right away")
    console.bullet("cfscan --verify 104.21.54.105   strict 20-attempt check")
    console.bullet("cfscan --quick --dry-run   print the argument list only")
    console.bullet("cfscan --profile NAME      use another saved profile")
    console.bullet("cfscan --make-pool 2000    fix the candidate list for all rounds")
    console.bullet("cfscan --isp mci --pool pool-xxxx.txt   measure one carrier")
    console.bullet("cfscan --multi-isp         print the report of the last session")
    console.bullet("cfscan --no-color          disable ANSI colours")
    console.bullet("Press Ctrl+C at any time to stop safely; a dry run never "
                   "executes the scanner.")

    console.blank()
    console.line(console.style("Files", "bold"))
    console.bullet(f"Configuration: {session.paths.config_file}")
    console.bullet(f"Results: {session.paths.results_dir}")
    console.bullet("Every run also keeps the raw scanner log next to its CSV file.")
    return EXIT_OK


# --------------------------------------------------------------------------
# Flow 10: the same candidate list on several carriers
# --------------------------------------------------------------------------

#: Carrier names offered as the default answer, in the order most people check.
CARRIER_SUGGESTIONS = ("mci", "irancell", "rightel", "mokhaberat", "shatel")

#: How many carriers one wizard run may measure.
MAX_CARRIERS = 6

#: How many of a carrier's own best addresses are verified in each round.
DEFAULT_TOP_PER_ROUND = 10

#: Never verify more than this many addresses in one round (this carrier's own
#: best plus everything earlier carriers proved).
VERIFY_CAP = 40

#: Scan rows kept in a session record; the report only reads the top ones.
SCAN_ROWS_KEPT = 500


def _carrier_list(console, isps=None):
    """Ask how many carriers to measure, then what to call each one."""
    if isps:
        return [str(item) for item in isps][:MAX_CARRIERS]
    count = int(console.ask_int("How many carriers do you want to measure?",
                                default=2, minimum=2, maximum=MAX_CARRIERS,
                                field="number of carriers"))
    names = []
    for index in range(count):
        suggestion = (CARRIER_SUGGESTIONS[index]
                      if index < len(CARRIER_SUGGESTIONS) else None)
        label = console.ask(f"Name of carrier {index + 1}", default=suggestion)
        names.append(str(label).strip())
    return names


def _prepare_pool(session, profile, console, pool_path=None, size=None):
    """The candidate list every round must share.

    Returns ``(path, sha, count, seed)``. The scanner draws a fresh sample from
    the range file on every run (measured: 5,955 of 1,524,480 addresses, and two
    runs shared no address at all), so a carrier comparison has to fix the list
    once and reuse it.
    """
    if pool_path:
        path = Path(pool_path)
        if not path.exists():
            raise ValidationError(f"The candidate list was not found: {path}")
        addresses = pool_module.read_pool(path)
        if not addresses:
            raise ValidationError(f"The candidate list is empty: {path}")
        console.info(f"Candidate list: {path} ({len(addresses)} addresses)")
        return path, pool_module.pool_sha(addresses), len(addresses), None

    range_file = Path(ip_file_for(profile))
    if not range_file.exists():
        raise ValidationError(f"The IP range file was not found: {range_file}")
    wanted = int(size or getattr(session, "pool_size", 0)
                 or pool_module.DEFAULT_POOL_SIZE)
    if wanted < 1:
        raise ValidationError(
            f"A candidate list needs at least one address, not {wanted}."
        )
    try:
        population = pool_module.new_pool(
            range_file.read_text(encoding="utf-8", errors="replace"), size=wanted)
    except ValueError as exc:
        # The scanner's IPv6 list has no IPv4 range in it, and a candidate pool
        # is IPv4 only. Saying so beats a traceback from the menu.
        if int(profile.get("ip_version", 4) or 4) == 6:
            raise ValidationError(
                "This profile scans IPv6 (see menu 7), and a carrier comparison "
                "needs IPv4 addresses: the clean-IP trick only works against "
                "Cloudflare's IPv4 edge. Switch the profile to IPv4 (menu 7) and "
                "try again."
            )
        raise ValidationError(str(exc))
    directory = vantages_module.sessions_dir(session.paths.results_dir,
                                             profile.get("domain")) / "pools"
    path = pool_module.write_pool(directory, population)
    console.info(f"Candidate list: {path.name} ({len(population['addresses'])} "
                 f"addresses over {population['prefixes']} prefixes, seed "
                 f"{population['seed']})")
    return (path, population["sha256"], len(population["addresses"]),
            population["seed"])


def _round_row(address, row, attempts):
    """One address as a session round stores it."""
    if row is None:
        return {"ip": address, "sent": 0, "received": 0, "loss": None,
                "rtt_ms": None, "colo": None,
                "verdict": vantages_module.verdict_of(None, attempts)}
    return {
        "ip": address,
        "sent": int(getattr(row, "sent", 0) or 0),
        "received": int(getattr(row, "received", 0) or 0),
        "loss": float(getattr(row, "loss", 0.0) or 0.0),
        "rtt_ms": float(getattr(row, "latency_ms", 0.0) or 0.0),
        "colo": getattr(row, "colo", None),
        "verdict": vantages_module.verdict_of(row, attempts),
    }


def _explain_empty_round(console, outcome, profile):
    """Say why a carrier round came back empty, in the scanner's own words.

    A round that fails for a reason of its own - a candidate list the scanner
    cannot parse, a binary that cannot run - otherwise looks exactly like a
    connection that was not switched yet, and the user would keep switching
    networks for nothing.
    """
    translated = outcome.translated_log() if outcome is not None else []
    if translated:
        console.line("Scanner messages (translated):")
        for line in translated[:6]:
            console.line(f"  {line}")
    if outcome is not None and outcome.log_path:
        console.bullet(f"Raw scanner log: {outcome.log_path}")


def _measure_carrier(session, config, profile, name, pool_file, proved=()):
    """Scan the shared candidate list once and verify this round's set.

    The verified set is this carrier's own best addresses plus every address
    earlier carriers already proved, so a shared address carries a verdict on
    each carrier instead of only on the one that happened to find it first.
    Returns ``None`` when the user stopped the round.
    """
    console = session.console
    cfst = _cfst_path(config)
    check_cfst(cfst)
    store = ResultStore(session.paths)
    csv_path = store.new_csv(f"multi-{profile_slug(name)}")
    log_path = store.log_for(csv_path)
    top_n = max(int(getattr(session, "top_ips", DEFAULT_TOP_PER_ROUND)
                    or DEFAULT_TOP_PER_ROUND), DEFAULT_TOP_PER_ROUND)
    argv = build_scan_argv(cfst, profile, csv_path,
                           results_limit=_requested_results(profile, top_n),
                           candidate_file=str(pool_file))
    if session.dry_run:
        _print_dry_run(console, argv, csv_path, log_path)
        return {"verified": [], "scan": [], "csv": str(csv_path),
                "log": str(log_path), "scanned": 0, "dry_run": True}

    outcome = _execute_scan(session, argv, log_path, label="Scanning")
    if outcome.interrupted:
        return None

    try:
        parsed = parse_results_csv(csv_path)
    except CsvError as exc:
        console.error(str(exc))
        parsed = None
    results = rank_results(parsed.results) if parsed is not None else []
    for warning in (parsed.warnings if parsed is not None else []):
        console.warn(warning)
    if not results:
        console.warn("No address answered on this carrier.")
        _explain_empty_round(console, outcome, profile)

    wanted = [item.ip for item in results[:top_n]]
    for address in proved:
        if address not in wanted:
            wanted.append(address)
    wanted = wanted[:VERIFY_CAP]

    verified = {}
    if wanted:
        verified = verify_addresses(session, config, profile, wanted) or {}
    attempts = int(profile.get("verify_attempts") or session.verify_attempts or 20)
    if verified:
        rows = [_round_row(address, verified.get(address), attempts)
                for address in wanted]
    else:
        # Nothing could be proven in this round, which is not the same as every
        # address being dead: say so instead of claiming a verdict.
        rows = [{"ip": address, "sent": 0, "received": 0, "loss": None,
                 "rtt_ms": None, "colo": None, "verdict": "UNVERIFIED"}
                for address in wanted]

    scan_rows = [{"ip": item.ip, "sent": item.sent, "received": item.received,
                  "loss": item.loss, "rtt_ms": item.latency_ms,
                  "colo": item.colo}
                 for item in results[:SCAN_ROWS_KEPT]]
    return {"verified": rows, "scan": scan_rows, "csv": str(csv_path),
            "log": str(log_path), "scanned": len(results), "dry_run": False}


def _metric_cell(entry):
    """One carrier's column in the report."""
    if not entry:
        return "-"
    verdict = str(entry.get("verdict") or "")
    rtt = entry.get("rtt_ms")
    if verdict == "PASS" and rtt is not None:
        return f"{float(rtt):.0f} ms"
    return {"FAIL": "lost", "DEAD": "dead", "UNVERIFIED": "?"}.get(verdict,
                                                                        "-")


def _colo_cell(row):
    for name in row.get("passing") or []:
        entry = (row.get("per_isp") or {}).get(name) or {}
        colo = entry.get("colo")
        if colo and str(colo).upper() not in ("N/A", "NA", "-"):
            return str(colo)
    return "-"


def render_multi_isp_report(console, record):
    """Print the standard multi-carrier report. Returns the computed data."""
    data = multisip_module.report(record)
    carriers = data["isps"]
    domain = record.get("domain")
    scheme = record.get("scheme") or "https"
    console.heading("Multi-carrier report")
    console.key_value("Domain", domain)
    console.key_value("Test URL", f"{scheme}://{domain}:{record.get('port')}/")
    console.key_value("Expected status", record.get("http_status"))
    console.key_value("Carriers measured", f"{data['total']} ({', '.join(carriers)})")
    console.key_value("Verified addresses", data["verified_addresses"])
    if record.get("path"):
        console.key_value("Session file", record["path"])

    console.heading("1. Best on every carrier")
    if data["common"]:
        rows = []
        for position, row in enumerate(data["common"][:10], start=1):
            rows.append([str(position), row["ip"]]
                        + [_metric_cell((row["per_isp"] or {}).get(isp))
                           for isp in carriers]
                        + [f"{multisip_module.worst_case_rtt(row):.0f} ms",
                           f"±{(row.get('spread') or 0.0):.0f} ms",
                           _colo_cell(row)])
        console.table(["#", "IP"] + carriers + ["worst", "spread", "colo"],
                      rows,
                      aligns=["r", "l"] + ["r"] * len(carriers) + ["r", "r", "l"])
        console.line("These are the addresses to use when the same config has to "
                     "work on several networks.")
    else:
        console.warn("No address passed on every carrier - see section 3 for the "
                     "best partial coverage.")

    console.heading("2. Fastest verified address per carrier")
    rows = []
    for item in data["best_per_line"]:
        if item.get("ip"):
            rows.append([item["isp"], item["ip"],
                         f"{(item.get('rtt_ms') or 0):.0f} ms",
                         "verified" if item.get("verified") else "not verified",
                         item.get("colo") or "-"])
        else:
            rows.append([item["isp"], "-", "-", "-",
                         item.get("reason") or "-"])
    console.table(["carrier", "IP", "latency", "check", "colo"], rows,
                  aligns=["l", "l", "r", "l", "l"])

    console.heading("3. Partial coverage")
    if data["coverage"]:
        rows = []
        for position, row in enumerate(data["coverage"][:10], start=1):
            rows.append([str(position), row["ip"],
                         f"{row['covered']}/{row['total']}",
                         ", ".join(row["passing"]),
                         f"{multisip_module.worst_case_rtt(row):.0f} ms"])
        console.table(["#", "IP", "covered", "carriers", "worst"], rows,
                      aligns=["r", "l", "r", "l", "r"])
    else:
        console.line("None: every verified address either works everywhere or "
                     "nowhere.")

    console.heading("What to use")
    recommendation = data["recommendation"]
    if recommendation:
        console.ok(f"{recommendation['ip']} - {recommendation['reason']}")
        console.bullet(
            f"Client: address {recommendation['ip']}, port {record.get('port')}, "
            f"security=tls, sni {domain}, allowInsecure off."
        )
        if recommendation["kind"] != "common":
            console.bullet(
                "That address is not proven on every carrier, so keep the "
                "per-carrier line of section 2 as the fallback for the network "
                "it did not pass on."
            )
    else:
        console.warn("Nothing was verified on any carrier; run the rounds again.")
    return data


def _csv_cell(value):
    """One CSV cell, quoted when it could break the row.

    The carrier names are typed by hand, and one of them may well contain a
    comma ("mci, home") - that cell carries several names joined by spaces, so
    an unquoted comma would silently shift every column after it.
    """
    text = str(value)
    if any(character in text for character in (",", '"', "\n", "\r")):
        return '"' + text.replace('"', '""') + '"'
    return text


def _save_multi_report(results_dir, record, data):
    """Write the report as a CSV next to its session file."""
    directory = vantages_module.sessions_dir(results_dir, record.get("domain"))
    directory.mkdir(parents=True, exist_ok=True)
    slug = profile_slug(str(record.get("domain") or "multi-isp"))
    path = directory / f"report-{slug}-{timestamp_label()}.csv"
    carriers = data["isps"]
    header = ["ip", "covered", "total", "passing", "worst_ms", "spread_ms"]
    # Two carrier names can slugify to the same word ("mci" and "mci!", or any
    # two Persian names, which slug to "profile"), and two identical column names
    # would make the file unusable in a spreadsheet. Number them when they clash.
    used = {}
    for isp in carriers:
        slug = profile_slug(isp)
        used[slug] = used.get(slug, 0) + 1
        label = slug if used[slug] == 1 else f"{slug}{used[slug]}"
        header += [f"{label}_verdict", f"{label}_ms"]
    lines = [",".join(_csv_cell(cell) for cell in header)]
    ordered = ([row for row in data["common"]]
               + [row for row in data["coverage"]]
               + [row for row in data["rows"]
                  if row not in data["common"] and row not in data["coverage"]])
    for row in ordered:
        cells = [row["ip"], str(row["covered"]), str(row["total"]),
                 " ".join(row["passing"]),
                 f"{multisip_module.worst_case_rtt(row):.0f}",
                 f"{(row.get('spread') or 0.0):.0f}"]
        for isp in carriers:
            entry = (row["per_isp"] or {}).get(isp) or {}
            cells.append(str(entry.get("verdict") or "-"))
            rtt = entry.get("rtt_ms")
            cells.append(f"{float(rtt):.0f}" if rtt is not None else "")
        lines.append(",".join(_csv_cell(cell) for cell in cells))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def multi_isp_flow(session, config, profile_name=None, isps=None, pool_path=None,
                   note=None):
    """Measure one candidate list on several carriers in one sitting.

    Asks how many carriers first, then runs one round per carrier, waiting
    between rounds so the connection can be switched. Every round is stored as
    soon as it finishes, so the report is available even when the wizard is
    stopped half way.
    """
    console = session.console
    name, profile = _profile_pair(config, profile_name)

    console.heading("Multi-carrier scan")
    console.line("One round per carrier. Every round measures the same candidate "
                 "list, so the carriers can be compared address by address.")
    console.blank()
    _render_profile(console, name, profile)

    carriers = _carrier_list(console, isps=isps)
    pool_file, sha, count, seed = _prepare_pool(session, profile, console,
                                                pool_path=pool_path)
    console.line(f"Every round below scans these {count} addresses.")

    if not session.dry_run and not preflight_probe(session, config, name, profile):
        console.warn("Cancelled - nothing was measured.")
        return EXIT_FAILED

    record = vantages_module.new_session(profile, profile.get("domain"),
                                         profile.get("port"), pool_file, sha,
                                         carriers, pool_seed=seed)
    index = 0
    if session.assume_yes and not session.dry_run:
        console.warn(
            "--yes was given, so the wizard will not stop between rounds. Every "
            "round is labelled with the carrier you named for it, so switch the "
            "connection yourself before each one - otherwise the report compares "
            "one network with itself."
        )
    while index < len(carriers):
        carrier = carriers[index]
        console.heading(f"Round {index + 1} of {len(carriers)} - {carrier}")
        # One carrier gets one round: a retry replaces the measurement that just
        # came back empty instead of adding a second column with the same name.
        vantages_module.drop_round(record, carrier)
        # A dry run executes nothing, so waiting for a connection switch would
        # only stall the user for no reason.
        if not session.assume_yes and not session.dry_run:
            console.line(f"Switch this Mac to {carrier} (hotspot, SIM or router) "
                         "now. Ctrl+C stops here and still shows the report.")
            try:
                console.pause(f"Press Enter to start the {carrier} round")
            except Aborted:
                console.warn("Round cancelled - the report covers the rounds "
                             "that finished.")
                break

        measured = _measure_carrier(session, config, profile, name, pool_file,
                                    proved=vantages_module.measured_ip_list(record))
        if measured is None:
            console.warn("The round was stopped - the report covers the rounds "
                         "that finished.")
            break
        if measured.get("dry_run"):
            index += 1
            continue

        added = vantages_module.add_round(
            record, carrier, measured["verified"], csv_path=measured["csv"],
            log_path=measured["log"], access=note, scanned=measured["scanned"],
        )
        vantages_module.save_session(session.paths.results_dir, record)
        passing = [row for row in added["verified"]
                   if str(row.get("verdict")) == vantages_module.PASS]
        if passing:
            best = min(passing, key=lambda row: row.get("rtt_ms") or float("inf"))
            console.ok(f"{len(passing)} address(es) verified on {carrier} - "
                       f"fastest {best['ip']} "
                       f"({(best.get('rtt_ms') or 0):.0f} ms).")
            index += 1
            continue

        console.warn(f"No address was verified on {carrier}, which usually means "
                     "the connection was not switched yet.")
        if index + 1 >= len(carriers):
            if console.ask_yes_no(f"Measure {carrier} once more?", default=True):
                continue
            break
        choice = console.ask_choice(
            "What now?",
            [("1", f"Measure {carrier} again"),
             ("2", "Continue with the next carrier"),
             ("0", "Stop and show the report")],
            default="1",
        )
        if choice == "0":
            break
        if choice == "1":
            continue
        index += 1

    if not record["rounds"]:
        console.warn("No round finished, so there is nothing to compare.")
        remember_result(session, "FAIL", ["No carrier round was measured."],
                        title="Multi-carrier - nothing measured")
        return EXIT_FAILED

    console.blank()
    data = render_multi_isp_report(console, record)
    csv_path = _save_multi_report(session.paths.results_dir, record, data)
    console.blank()
    console.line(f"Report saved: {csv_path}")
    if record.get("path"):
        console.line(f"Session file: {record['path']}")

    recommendation = data["recommendation"]
    verdict = "PASS" if data["common"] else "WARN"
    lines = [f"{data['total']} carrier(s): {', '.join(data['isps'])}",
             f"{len(data['common'])} address(es) passed on every carrier"]
    if recommendation:
        lines.append(f"Use {recommendation['ip']} - {recommendation['reason']}")
    lines.append(f"Report: {csv_path}")
    remember_result(session, verdict, lines, title="Multi-carrier report")
    return EXIT_OK


def _reusable_session(session, profile, isp):
    """The stored session a single-carrier round belongs to.

    Returns ``(session, already_measured)``, or ``(None, False)`` when a fresh
    session is the right thing (nothing stored yet, or its candidate list is
    gone). A carrier that was measured before is reported rather than ignored:
    its round is then replaced instead of quietly starting a second session and
    hiding the carriers already measured.
    """
    latest = vantages_module.latest_session(session.paths.results_dir,
                                            profile.get("domain"))
    if latest is None:
        return None, False
    try:
        record = vantages_module.load_session(latest)
    except (OSError, ValueError):
        return None, False
    stored = record.get("pool_file")
    if not stored or not Path(stored).exists():
        return None, False
    return record, str(isp) in vantages_module.isp_names(record)


def multi_isp_round(session, config, profile_name=None, isp=None, pool_path=None,
                    note=None):
    """Measure one carrier and add it to the session (the scripted path)."""
    console = session.console
    name, profile = _profile_pair(config, profile_name)
    verdict = str(isp or "").strip()
    if not verdict:
        verdict = str(console.ask("Carrier name", default="carrier")).strip()

    console.heading(f"Carrier round - {verdict}")
    record, repeated = _reusable_session(session, profile, verdict)
    if record is None:
        pool_file, sha, count, seed = _prepare_pool(session, profile, console,
                                                    pool_path=pool_path)
        record = vantages_module.new_session(profile, profile.get("domain"),
                                             profile.get("port"), pool_file, sha,
                                             [verdict], pool_seed=seed)
        console.line(f"Starting a new multi-carrier session with {count} "
                     "candidate addresses.")
    else:
        console.line(f"Continuing the session in {record.get('path')} - "
                     "the same candidate list is measured again.")
        if repeated:
            console.info(f"The stored {verdict} round will be replaced by this "
                         "measurement; the other carriers stay where they are.")

    if not session.dry_run and not preflight_probe(session, config, name, profile):
        console.warn("Cancelled - nothing was measured.")
        return EXIT_FAILED

    measured = _measure_carrier(session, config, profile, name,
                                record.get("pool_file"),
                                proved=vantages_module.measured_ip_list(record))
    if measured is None:
        console.warn("The round was stopped - nothing was stored.")
        return EXIT_INTERRUPTED
    if measured.get("dry_run"):
        return EXIT_OK

    added = vantages_module.add_round(
        record, verdict, measured["verified"], csv_path=measured["csv"],
        log_path=measured["log"], access=note, scanned=measured["scanned"],
        replace=repeated,
    )
    path = vantages_module.save_session(session.paths.results_dir, record)
    passing = [row for row in added["verified"]
               if str(row.get("verdict")) == vantages_module.PASS]
    console.blank()
    if passing:
        best = min(passing, key=lambda row: row.get("rtt_ms") or float("inf"))
        console.ok(f"{len(passing)} address(es) verified on {verdict} - fastest "
                   f"{best['ip']} ({(best.get('rtt_ms') or 0):.0f} ms).")
    else:
        console.warn(f"No address was verified on {verdict}.")
    console.line(f"Session: {path} ({len(vantages_module.isp_names(record))} "
                 "carrier round(s) so far)")
    console.line("Switch the connection and run the next round, then "
                 "'cfscan --multi-isp' for the report.")

    data = multisip_module.report(record)
    remember_result(session, "OK", [
        f"{verdict}: {len(passing)} verified address(es)",
        f"Session: {path}",
    ], title=f"Carrier round - {verdict}")
    if len(vantages_module.isp_names(record)) > 1 and data["common"]:
        console.ok(f"{len(data['common'])} address(es) already passed on every "
                   "measured carrier.")
    return EXIT_OK


def multi_isp_report(session, config, profile_name=None, session_path=None):
    """Print the report of a stored multi-carrier session."""
    console = session.console
    path = Path(session_path) if session_path else None
    if path is None:
        name, profile = _profile_pair(config, profile_name)
        path = vantages_module.latest_session(session.paths.results_dir,
                                              profile.get("domain"))
    if path is None:
        console.warn("No multi-carrier session was found yet. Use menu 10 (or "
                     "'cfscan --isp NAME' per carrier) to measure one.")
        return EXIT_FAILED
    try:
        record = vantages_module.load_session(path)
    except (OSError, ValueError) as exc:
        console.error(f"The session could not be read: {exc}")
        return EXIT_FAILED

    data = render_multi_isp_report(console, record)
    csv_path = _save_multi_report(session.paths.results_dir, record, data)
    console.blank()
    console.line(f"Report saved: {csv_path}")
    return EXIT_OK


def make_pool_flow(session, config, size=None, profile_name=None):
    """Build the candidate list that the carrier rounds will share."""
    console = session.console
    name, profile = _profile_pair(config, profile_name)
    console.heading("Candidate list")
    pool_file, sha, count, seed = _prepare_pool(session, profile, console,
                                                size=size)
    console.ok(f"{count} addresses written to {pool_file}")
    console.line(f"sha256: {sha}")
    console.line(f"seed: {seed}")
    # Quoted, because the results folder path contains a space.
    console.line(f'Use it with: cfscan --isp <name> --pool "{pool_file}"')
    return EXIT_OK


# --------------------------------------------------------------------------
# Menu
# --------------------------------------------------------------------------

_HANDLERS = {
    "1": lambda session, config: quick_scan(session, config),
    "2": lambda session, config: custom_scan(session, config),
    "3": lambda session, config: verify_flow(session, config),
    "4": lambda session, config: show_last_results(session, config),
    "5": lambda session, config: show_profiles(session, config),
    "6": lambda session, config: manage_profiles(session, config),
    "7": lambda session, config: switch_ip_version(session, config),
    "8": lambda session, config: open_results_folder(session, config),
    "9": lambda session, config: help_screen(session, config),
    "10": lambda session, config: multi_isp_flow(session, config),
}


def render_menu(session, config):
    console = session.console
    try:
        name, profile = get_active(config)
        summary = (f"{profile.get('domain')}:{profile.get('port')}  |  "
                   f"IPv{profile.get('ip_version', 4)}  |  {profile.get('mode')}")
    except UnknownProfile:  # pragma: no cover - defensive
        name, summary = "none", "no active profile"

    console.rule()
    console.line(f"{console.style('cfscan', 'bold', 'cyan')} - "
                 "Cloudflare IP scanner (wraps XIU2/CloudflareSpeedTest)")
    console.line(f"Active profile: {console.style(name, 'bold')}  ({summary})")
    console.rule()
    for key, label in MENU_ITEMS:
        console.line(f"  {key}. {label}")
    console.blank()


def run_menu(session, config):
    """Run the interactive menu until the user exits.

    Every flow prints its own result; the menu then repeats the verdict in one
    short block and waits for Enter before it redraws, so the outcome of a test
    stays on screen instead of being buried in scanner output. Ctrl+C inside a
    flow cancels that flow only - only Ctrl+C at the menu prompt leaves cfscan,
    and option 0 always exits.
    """
    console = session.console
    if session.dry_run:
        console.warn("Dry run mode: scans print their argument list and never "
                     "execute.")

    while True:
        render_menu(session, config)
        try:
            choice = console.ask_raw("Choose an option (0-10)").strip()
        except Aborted:
            console.blank()
            console.warn("Cancelled.")
            return EXIT_INTERRUPTED

        if choice == "0":
            console.ok("Goodbye - run cfscan again whenever you need a fresh IP.")
            return EXIT_OK

        handler = _HANDLERS.get(choice)
        if handler is None:
            console.error("Invalid choice. Please pick one of the numbers shown "
                          "above.")
            continue

        session.last_result = None
        cancelled = False
        try:
            handler(session, config)
        except Aborted:
            console.blank()
            console.warn("Cancelled - back to the menu.")
            cancelled = True
        except KeyboardInterrupt:  # pragma: no cover - safety net
            console.blank()
            console.warn("Cancelled - back to the menu.")
            cancelled = True
        except UnknownProfile as exc:
            console.error(str(exc))
        except ValidationError as exc:
            console.error(str(exc))
        except ScanError as exc:
            console.error(str(exc))
            console.warn("Nothing was changed - the menu is still here.")

        if not cancelled:
            _finish_flow(session)

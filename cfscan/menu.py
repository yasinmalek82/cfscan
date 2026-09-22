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

from . import __version__, running_from_dev_link
from . import edges as edges_module
from . import favourites as favourites_module
from . import multisip as multisip_module
from . import pool as pool_module
from . import ranges as ranges_module
from . import results as results_module
from . import vantages as vantages_module
from .measure import (
    DEFAULT_DOWNLOAD_URL,
    DEFAULT_UPLOAD_URL,
    measure_jitter_ms,
    measure_upload_mbps,
)
from .parser import (
    CsvError,
    apply_measurements,
    parse_results_csv,
    rank_results,
    recommend,
    write_enriched_csv,
)
from .profiles import (
    DEFAULT_PROFILE_KEY,
    UnknownProfile,
    is_placeholder,
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
    certificate_depth_hint,
    colo_problem,
    PROBE_ADDRESSES,
    CfstNotFoundError,
    ScanError,
    build_download_argv,
    build_probe_argv,
    build_scan_argv,
    download_target_problem,
    explain_zero_download,
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
    validate_colo,
    validate_domain,
    validate_http_status,
    validate_ip,
    validate_output_filename,
    validate_port,
    validate_profile_name,
    validate_speed_url,
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
    "prunable_results",
    "edge_locations",
    "show_last_results",
    "show_profiles",
    "update_ranges_flow",
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
    ("11", "Update IP ranges"),
    ("12", "Edge locations"),
    ("0", "Exit"),
)

#: How the entries above are grouped on screen. Eleven items in one flat list
#: read as eleven equally likely choices; grouped, the screen says what kind of
#: thing each one is before the user reads a single label.
MENU_GROUPS = (
    ("Scan", ("1", "2", "10")),
    ("Check one address", ("3",)),
    ("Results", ("4", "8")),
    ("Setup", ("5", "6", "7", "11", "12")),
    ("", ("9", "0")),
)

#: The dim half-line after each entry. It answers "what does this actually do?"
#: for someone who has not read the help screen, which is most people most of
#: the time.
MENU_HINTS = {
    "1": "scan the range with the active profile",
    "2": "ask for every setting, then scan",
    "3": "re-check a saved address, or any address you type",
    "4": "the newest saved result file",
    "5": "what is stored and which one is active",
    "6": "add, edit, activate or delete a profile",
    "7": "switch the active profile's address family",
    "8": "reveal the CSV and log files in Finder",
    "9": "what every setting means",
    "10": "compare carriers on one fixed candidate list",
    "11": "download Cloudflare's current range lists",
    "12": "rank the datacentres, or clear the filter",
    "0": "",
}


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
    #: The same, for the "your default route is a tunnel" notice.
    tunnel_notice_shown: bool = False
    #: A region filter for this run only (``cfscan --colo``). It is kept here
    #: rather than written into the profile because the flows save the profile
    #: for their own reasons - a verified address, a scan's observations - and
    #: a one-run experiment must not ride along into the stored configuration.
    colo_override: object = None
    #: One-run measurement switches (``--download``, ``--jitter``, ``--upload``
    #: and their URLs). Applied on top of the profile for the scan only.
    measurement_override: object = None
    #: Real runs open jitter/upload sockets. A test that injects the scanner
    #: leaves this off so the suite never touches the network; ``main`` turns
    #: it on when it is starting the real ``cfst``.
    probes: bool = True


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


def _scan_profile(session, profile):
    """The profile as a scan should see it, with any one-run override applied.

    Returns a copy when an override is set, so everything written back - the
    verified address, the datacentre observations - still lands on the real
    profile and the override never does.
    """
    override = getattr(session, "colo_override", None)
    measurements = dict(getattr(session, "measurement_override", None) or {})
    if override is None and not measurements:
        return profile
    scanned = dict(profile)
    if override is not None:
        scanned["colo"] = override
    download_fill = measurements.pop("download_url_if_empty", None)
    upload_fill = measurements.pop("upload_url_if_empty", None)
    scanned.update(measurements)
    if download_fill and not str(scanned.get("download_url") or "").strip():
        scanned["download_url"] = download_fill
    if upload_fill and not str(scanned.get("upload_url") or "").strip():
        scanned["upload_url"] = upload_fill
    return scanned


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
    console.key_value("Region filter", str(profile.get("colo") or "")
                      or "any datacentre")
    console.key_value("IP version", f"IPv{profile.get('ip_version', 4)}")
    console.key_value("IP range file", ip_file_for(profile))
    console.key_value("Attempts", profile.get("attempts"))
    console.key_value("Concurrency", profile.get("concurrency"))
    console.key_value("Max latency", f"{profile.get('max_latency_ms')} ms")
    console.key_value("Max packet loss", f"{float(profile.get('max_loss', 0)) * 100:g}%")
    console.key_value("Addresses offered", profile.get("top_ips") or 10)
    console.key_value("Jitter",
                      "enabled" if profile.get("jitter_test", True) else "disabled")
    if profile.get("download_test"):
        download_url = str(profile.get("download_url") or "").strip()
        console.key_value("Download test",
                          download_url or "enabled (profile test URL)")
    else:
        console.key_value("Download test", "disabled")
    if profile.get("upload_test"):
        console.key_value("Upload test",
                          str(profile.get("upload_url") or "").strip()
                          or "enabled (no URL)")
    else:
        console.key_value("Upload test", "disabled")
    if profile.get("recommended_ip"):
        console.key_value("Recommended IP", profile.get("recommended_ip"))
    saved = favourites_module.entries_for(profile)
    if saved:
        console.key_value("Saved good IPs", f"{len(saved)} (menu 3)")
    for problem in (scheme_port_problem(profile), colo_problem(profile)):
        if problem:
            console.blank()
            console.warn(problem)


def _url_for(profile):
    from .runner import build_url

    return build_url(profile)


def _top_ips(session, profile):
    """How many of the best addresses a test should offer (default 10).

    This is the number that decides what the user sees. The profile's
    ``results_limit`` does not: it only becomes the scanner's ``-p``, which
    caps the scanner's own console output - output cfscan never reads, because
    it parses the result file instead (measured: ``-p 1`` over five addresses
    still wrote all five rows to the CSV).
    """
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
    """What to pass the scanner as ``-p``.

    ``-p`` caps the scanner's own console listing and nothing else - the result
    file always holds every address that passed the filters (measured: ``-p 1``
    over five addresses still wrote all five rows). cfscan reads that file, so
    this number is cosmetic; matching it to the number cfscan will show keeps
    the scanner's hidden log and the screen telling the same story.
    """
    return max(1, int(top_n))


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


def _notice_about_tunnel_once(session):
    """Say once per session that every measurement goes through a tunnel.

    When the default route is a tunnel, the scanner does not measure this
    machine's connection to Cloudflare at all: it measures the path through the
    tunnel and out of its exit. The address that wins is then the best address
    *for that tunnel*, which is rarely the address wanted - the point of a clean
    IP is usually to carry the tunnel, not to be reached through one.

    Two measurements from one such line make it concrete: the TCP handshake came
    back in 0.4 ms, because a TUN-mode client answers it locally rather than
    from Cloudflare, while the TLS handshake to the same address took 920 ms.
    Anything that judges an address by its TCP connect - TCPing mode - is
    therefore meaningless while a tunnel is up.
    """
    if getattr(session, "tunnel_notice_shown", False):
        return None
    session.tunnel_notice_shown = True
    line = edges_module.describe_line()
    if not line["tunnel"]:
        return line
    session.console.warn(
        f"This Mac's default route is a tunnel ({line['interface']}), so the "
        "scan measures the path through it and out of its exit - not this "
        "machine's own connection. The winning address will be the best one for "
        "that tunnel. Turn the tunnel off to scan the real line; --direct does "
        "not help, because it only clears this shell's proxy variables and "
        "cannot change a system route."
    )
    session.console.line("  Results are labelled with the line they were "
                         "measured on, so menu 12 still ranks the edge "
                         "locations correctly for this one.")
    return line


def _execute_scan(session, argv, log_path, label="Scanning", timeout=None):
    """Run the scanner with a live English progress indicator.

    ``timeout`` defaults to the session's safety net, so a scanner that never
    exits cannot freeze cfscan forever.
    """
    console = session.console
    if timeout is None:
        timeout = getattr(session, "scan_timeout_seconds", None)
    _notice_about_shell_proxy_once(session)
    _notice_about_tunnel_once(session)
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


def _visible_metrics(results, profile=None):
    """Which extra columns this table should show.

    A latency-only scan stays the seven-column table it always was. Download
    appears when the test was switched on (even if every speed is 0.00, which
    is itself the result) or when a saved file already has a non-zero speed.
    Jitter and upload appear only once a number exists, so an old CSV does
    not grow empty columns.
    """
    profile = profile or {}
    download = bool(profile.get("download_test")) or any(
        float(item.download_mbps or 0.0) > 0.0 for item in results)
    upload = any(item.upload_mbps is not None for item in results)
    jitter = any(item.jitter_ms is not None for item in results)
    return download, upload, jitter


def _render_results_table(console, results, limit=None, recommended_ip=None,
                          profile=None):
    shown = list(results)
    if limit is not None and limit > 0:
        shown = shown[:limit]
    show_download, show_upload, show_jitter = _visible_metrics(shown, profile)
    headers = ["#", "IP address", "Sent", "Received", "Loss", "Latency"]
    aligns = ["r", "l", "r", "r", "r", "r"]
    if show_jitter:
        headers.append("Jitter")
        aligns.append("r")
    if show_download:
        headers.append("Download")
        aligns.append("r")
    if show_upload:
        headers.append("Upload")
        aligns.append("r")
    headers.append("Colo")
    aligns.append("l")
    rows = []
    highlight = set()
    for position, item in enumerate(shown):
        row = [
            str(position + 1),
            item.ip,
            str(item.sent),
            str(item.received),
            item.loss_text(),
            item.latency_text(),
        ]
        if show_jitter:
            row.append(item.jitter_text())
        if show_download:
            row.append(item.download_text())
        if show_upload:
            row.append(item.upload_text())
        row.append(item.colo_text())
        rows.append(row)
        if recommended_ip is not None and item.ip == recommended_ip:
            highlight.add(position)
    console.table(
        headers,
        rows,
        aligns=aligns,
        highlight_rows=highlight,
        marker_col=1,
        legend="* = recommended IP" if highlight else None,
    )


def _metric_phrase(item, profile=None):
    """Jitter, download and upload, when there is something to say."""
    if item is None:
        return ""
    profile = profile or {}
    parts = []
    if item.jitter_ms is not None:
        parts.append(f"jitter {item.jitter_text()}")
    if profile.get("download_test") or float(item.download_mbps or 0.0) > 0.0:
        parts.append(f"down {item.download_mbps:.2f} MB/s")
    if item.upload_mbps is not None:
        parts.append(f"up {item.upload_mbps:.2f} MB/s")
    return ", ".join(parts)


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
        extra = _metric_phrase(measured, profile)
        console.line(
            f"{position:>3}. {prefix}{item.ip:<15} {latency:>10} "
            f"{loss:>4}  {colo:<3}  Port {port}  SNI/Host {domain}{marker}"
            f"{('  ' + extra) if extra else ''}"
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
            "The columns are the measured latency, packet loss and Cloudflare colo"
            " (plus jitter, download and upload when those were measured)."
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
                         csv_path, flow, colo_filter=None):
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
    _render_results_table(console, shown, recommended_ip=marked_ip, profile=profile)
    if len(results) > top_n:
        console.line(f"The best {top_n} of {len(results)} are shown; menu 4 "
                     "lists every address in the saved file.")

    console.blank()
    if verified is not None and passed:
        best = passed[0]
        extra = _metric_phrase(best, profile)
        console.ok(f"Best verified address: {best.ip} - {best.latency_text()}, "
                   f"0% loss, colo {best.colo_text()}"
                   f"{(', ' + extra) if extra else ''}.")
    elif verified is not None:
        console.warn("None of the tested addresses passed the strict check right "
                     "now; the numbers in the list below come from the scan.")
    elif recommended is not None:
        extra = _metric_phrase(recommended, profile)
        console.ok(
            f"Recommended IP: {recommended.ip} - {recommended.latency_text()}, "
            f"{recommended.loss_text()} packet loss, colo {recommended.colo_text()}"
            f"{(', ' + extra) if extra else ''}."
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

    # Every scan is one more measurement of where the fast datacentres are on
    # this line, whether or not anything passed the strict check.
    observed = edges_module.observe(
        profile, results, line=edges_module.describe_line(),
        colo_filter=colo_filter if colo_filter is not None
        else profile.get("colo"))
    if observed:
        top = sorted(observed.items(), key=lambda item: item[1]["med"])[:3]
        console.blank()
        console.line("Datacentres in this scan: " + ", ".join(
            f"{colo} ({stats['n']} at {stats['med']:.0f} ms)"
            for colo, stats in top) + "  -  menu 12 ranks them over time.")

    if passed:
        # Tomorrow's scan starts from what was proven today: re-measuring these
        # is one short run, where finding them again cost a full range scan.
        #
        # What is stored is the strict check's measurement, not the scan's: it
        # is twenty attempts against the scan's handful, and it is the one that
        # saw where the address answers from now (observed in one run: four
        # addresses the scan recorded as FRA answered the check from AMS, MUC,
        # VIE and LHR).
        favourites_module.remember_many(
            profile, [verified.get(item.ip) or item for item in passed])
        # The profile keeps the proven winner too, so the next scan's preflight
        # starts from an address that is known to answer.
        if marked_ip:
            profile["recommended_ip"] = marked_ip
        try:
            save_config(session.paths, config)
        except OSError as error:  # pragma: no cover - the scan itself is done
            console.warn(f"The verified addresses could not be saved: {error}")
        else:
            console.blank()
            console.line(f"{len(passed)} verified address(es) saved to this "
                         "profile - menu 3 re-checks them in one short run.")
    elif observed:
        try:
            save_config(session.paths, config)
        except OSError:  # pragma: no cover - the scan itself is done
            pass
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
    """Remove a preflight's files, so they never pile up or look like a scan.

    The log goes with the result file. Keeping it only filled the results folder
    with preflight logs that belong to no scan, and the reason a preflight
    failed is printed on screen while it is still relevant.
    """
    if not csv_path:
        return
    candidate = Path(csv_path)
    for path in (candidate, candidate.with_suffix(".log")):
        try:
            if path.exists():
                path.unlink()
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


def _tls_capability_check(session, cfst, name, profile, address):
    """Does the edge serve this hostname at all, when TLS is taken out of it?

    This is the only way to tell "the edge has no certificate for this name"
    from "the network is down", because the scanner cannot tell them apart: its
    Go client wraps the TLS alert in its own timeout, so a hostname the edge
    refuses to do TLS for is reported as ``context deadline exceeded`` - exactly
    what an unreachable address reports (measured against a hostname whose
    handshake curl showed failing instantly).

    So the question is asked a second way. Plain HTTP to an HTTPS port is
    answered by Cloudflare itself with a 400 and needs no certificate at all, so
    an address that answers *that* while failing the TLS probe proves the edge is
    alive for this hostname and the certificate is what is missing.

    Returns True (the edge answered without TLS), False (it did not) or None
    (the question does not apply, or the user stopped it).
    """
    if str(profile.get("mode") or "httping").lower() != "httping":
        return None
    if str(profile.get("scheme") or "https").lower() != "https":
        return None
    try:
        if int(profile.get("port")) not in CLOUDFLARE_HTTPS_PORTS:
            # On any other port the edge does not answer a plain request itself,
            # so a failure there would say nothing about the certificate.
            return None
    except (TypeError, ValueError):
        return None

    store = ResultStore(session.paths)
    csv_path = store.new_csv(f"tlscheck-{profile_slug(name)}")
    log_path = store.log_for(csv_path)
    plain = dict(profile, scheme="http", http_status=400)
    argv = build_probe_argv(cfst, plain, address, csv_path, attempts=2)
    session.console.line("Checking whether the edge serves this hostname at all "
                         "without TLS ...")
    outcome = _execute_scan(session, argv, log_path, label="TLS check")
    answered = outcome.has_result
    _discard_probe_result(csv_path)
    if outcome.interrupted:
        return None
    return answered


def _report_missing_certificate(console, profile):
    """Say that the edge is alive but has no certificate for this hostname."""
    domain = profile.get("domain")
    console.blank()
    console.error(
        f"The edge answers for {domain} over plain HTTP but refuses TLS for it, "
        "so this is a certificate problem, not an address problem."
    )
    console.bullet(
        "No clean IP can fix it. Every Cloudflare address will behave the same "
        "way, and your client will fail for the same reason the scan does - it "
        "needs the same TLS handshake."
    )
    hint = certificate_depth_hint(domain)
    if hint:
        console.bullet(hint)
    console.bullet(
        "Ways out: use a hostname one level below the zone (a.example.com "
        "rather than a.b.example.com), buy Cloudflare's Advanced Certificate "
        "Manager / Total TLS for the deeper wildcard, or upload a custom "
        "certificate that covers this hostname on the zone."
    )
    console.bullet(
        "Setting scheme=http would make this scan produce results again, but it "
        "would not fix anything: the edge answers that probe itself, so the scan "
        "would measure the edge while your client still could not connect."
    )


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

    # Before guessing from the log, ask the one question the log cannot answer:
    # is the edge serving this hostname at all? A "yes" here means the addresses
    # are fine and the certificate is not.
    if _tls_capability_check(session, cfst, name, profile, address):
        _report_missing_certificate(console, profile)
        if outcome is not None and outcome.log_path:
            console.line(f"Preflight scanner log: {outcome.log_path}")
        if not console.interactive or session.assume_yes:
            console.warn("Not scanning the range: it cannot produce a usable "
                         "address while the certificate is missing.")
            return False
        console.blank()
        return console.ask_yes_no("Scan the whole range anyway?", default=False)

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


def _refuse_placeholder(session, name, profile):
    """Stop a scan aimed at the shipped placeholder domain.

    ``example.com`` is not served by any Cloudflare edge for this user, so the
    scan would measure thousands of addresses and find nothing - and the reason
    would look like a network problem rather than "you have not set this up".
    """
    if not is_placeholder(profile):
        return False
    console = session.console
    console.blank()
    console.error(
        f"Profile '{name}' still points at {profile.get('domain')}, the "
        "placeholder a fresh installation starts with. Nothing can be measured "
        "against it."
    )
    console.bullet("Menu 6, option 3 edits the active profile - put the domain "
                   "your own service answers on into it. Menu 9 explains what "
                   "each setting means.")
    console.bullet("The domain is the name your client sends as SNI; cfscan "
                   "finds Cloudflare addresses that serve it quickly.")
    remember_result(session, "FAIL",
                    [f"Profile '{name}' is still the placeholder "
                     f"({profile.get('domain')}).",
                     "Set your own domain first: menu 6, option 3."],
                    title="Not set up yet")
    return True


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


def _probe_limit(profile):
    """How many of the best addresses jitter and upload should touch."""
    try:
        raw = int(profile.get("jitter_count") or 0)
    except (TypeError, ValueError):
        raw = 0
    if raw <= 0:
        try:
            raw = int(profile.get("top_ips") or 10)
        except (TypeError, ValueError):
            raw = 10
    return max(1, min(raw, 50))


def _print_measurement_plan(console, profile, direct=False, cfst_path="cfst"):
    """What a dry run will measure besides the latency scan."""
    if profile.get("jitter_test", True):
        samples = int(profile.get("jitter_samples") or 6)
        console.line(
            f"Jitter: {samples} TCP samples on the best addresses, "
            f"port {profile.get('port')}"
            + (" (proxy variables ignored)." if direct else ".")
        )
    else:
        console.line("Jitter: off for this run.")
    url = str(profile.get("download_url") or "").strip()
    if profile.get("download_test") and url:
        preview = build_download_argv(
            cfst_path, profile, "<best-addresses.txt>", "<download.csv>")
        console.blank()
        console.line(
            "Download pass (a second cfst run: -url cannot be both the "
            "latency check and a large file):"
        )
        console.line("  " + format_argv_for_display(preview))
    elif profile.get("download_test"):
        console.line("Download: cfst download test on the profile URL "
                     "(-dn/-dt, no -dd).")
    if profile.get("upload_test"):
        upload = str(profile.get("upload_url") or "").strip() or "(no URL set)"
        console.line(
            f"Upload: {upload} through each candidate address"
            + (" (proxy variables ignored)." if direct else ".")
        )


def _download_pass(session, config, profile, results):
    """Run cfst's download test against ``download_url`` and merge speeds.

    Returns ``(results, changed)``. A failure leaves the latency rows as they
    were: a missing speed is more honest than a traceback.
    """
    console = session.console
    url = str(profile.get("download_url") or "").strip()
    if not url or not results:
        return results, False
    count = max(1, min(int(profile.get("download_count") or 10), len(results), 50))
    chosen = [item.ip for item in rank_results(results, download=False)[:count]]
    seconds = int(profile.get("download_seconds") or 10)
    console.blank()
    console.line(
        f"Download test: {url} through {len(chosen)} address(es) "
        f"({seconds}s each). cfst has a single -url, so this is a separate "
        "pass from the latency scan."
    )
    cfst = _cfst_path(config)
    store = ResultStore(session.paths)
    csv_path = store.new_csv("download")
    log_path = store.log_for(csv_path)
    list_path = None
    try:
        handle = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False,
            prefix="cfscan-download-", suffix=".txt",
        )
        try:
            handle.write("\n".join(chosen) + "\n")
        finally:
            handle.close()
        list_path = handle.name
        argv = build_download_argv(cfst, profile, list_path, csv_path)
        try:
            outcome = _execute_scan(session, argv, log_path, label="Download")
        except (CfstNotFoundError, ScanError) as error:
            console.warn(f"The download pass did not run: {error}")
            return results, False
        if outcome.interrupted:
            console.warn("The download pass was stopped. Latency results are kept.")
            return results, False
        speeds = {ip: 0.0 for ip in chosen}
        try:
            report = parse_results_csv(csv_path)
        except CsvError as error:
            warning = explain_zero_download(outcome.log_text, speeds, url)
            if warning:
                console.warn(warning)
            else:
                console.warn(f"The download pass wrote nothing usable: {error}")
            return apply_measurements(results, download_by_ip=speeds), True
        for item in report.results:
            if item.ip in speeds:
                speeds[item.ip] = item.download_mbps
        warning = explain_zero_download(outcome.log_text, speeds, url)
        if warning:
            console.warn(warning)
        elif not report.results:
            console.warn(
                "The download pass measured no address. cfst records a speed "
                "only when the URL returns HTTP 200 and a body that lasts for "
                "the download time; anything else stays 0.00."
            )
        return apply_measurements(results, download_by_ip=speeds), True
    finally:
        if list_path:
            try:
                os.unlink(list_path)
            except OSError:
                pass


def _jitter_pass(session, profile, results, direct):
    console = session.console
    chosen = rank_results(results, download=False)[:_probe_limit(profile)]
    samples = max(2, min(int(profile.get("jitter_samples") or 6), 30))
    port = int(profile["port"])
    console.blank()
    console.line(
        f"Measuring jitter on {len(chosen)} address(es) "
        f"({samples} TCP samples each, port {port})."
    )
    if direct:
        console.line("These probes ignore proxy variables, the same as --direct.")
    found = {}
    for item in chosen:
        found[item.ip] = measure_jitter_ms(
            item.ip, port, samples=samples, direct=direct)
    return apply_measurements(results, jitter_by_ip=found)


def _upload_pass(session, profile, results, direct):
    console = session.console
    url = str(profile.get("upload_url") or "").strip()
    if not url:
        console.warn("Upload is enabled but no upload URL is set, so it was skipped.")
        return results
    chosen = rank_results(results, download=False)[:_probe_limit(profile)]
    seconds = max(1, min(int(profile.get("upload_seconds") or 8), 60))
    console.blank()
    console.line(
        f"Measuring upload on {len(chosen)} address(es) via {url} "
        f"({seconds}s each)."
    )
    if direct:
        console.line("These probes ignore proxy variables, the same as --direct.")
    found = {}
    for item in chosen:
        found[item.ip] = measure_upload_mbps(
            item.ip, url, seconds=seconds, direct=direct)
    return apply_measurements(results, upload_by_ip=found)


def _augment_results(session, config, profile, results, csv_path):
    """Download pass, jitter and upload, then the ranked list.

    The download pass is another cfst run, so it follows the injected scanner
    the tests already replace. Jitter and upload open sockets and run only
    when ``session.probes`` is on, which a normal ``cfscan`` process sets and
    the test suite does not.
    """
    results = list(results)
    changed = False
    if profile.get("download_test") and str(profile.get("download_url") or "").strip():
        results, did = _download_pass(session, config, profile, results)
        changed = changed or did
    if getattr(session, "probes", False) and not getattr(session, "dry_run", False):
        direct = bool(getattr(session, "direct", False))
        if profile.get("jitter_test", True):
            results = _jitter_pass(session, profile, results, direct)
            changed = True
        if profile.get("upload_test"):
            results = _upload_pass(session, profile, results, direct)
            changed = True
    if changed and csv_path:
        try:
            write_enriched_csv(csv_path, results)
        except OSError as error:
            session.console.warn(
                "The extra measurements could not be written into the result "
                f"file: {error}"
            )
    return rank_results(results, download=bool(profile.get("download_test")))


def _note_measurements(console, profile):
    """One line each, before the scan, so a slow test is not a surprise."""
    problem = download_target_problem(profile)
    if problem:
        console.warn(problem)
    url = str(profile.get("download_url") or "").strip()
    if profile.get("download_test") and url:
        console.line(
            "Download speed is a second scanner pass against "
            f"{url}. cfst's -url cannot be both the latency check and a large file."
        )
    if profile.get("upload_test"):
        upload = str(profile.get("upload_url") or "").strip()
        if upload:
            console.line(
                f"Upload speed is measured by cfscan (not cfst) against {upload}, "
                "through each candidate address."
            )


# --------------------------------------------------------------------------
# Flow 1: quick scan
# --------------------------------------------------------------------------

def quick_scan(session, config, profile_name=None, verify_prompt=True):
    """Scan with the active profile, then show a ranked table."""
    console = session.console
    name, profile = _profile_pair(config, profile_name)

    console.heading("Quick Scan")
    if _refuse_placeholder(session, name, profile):
        return EXIT_USAGE
    console.line("The active profile is used. Press Ctrl+C at any time to stop.")
    console.blank()
    scanned = _scan_profile(session, profile)
    _render_profile(console, name, scanned)
    _note_measurements(console, scanned)

    cfst = _cfst_path(config)
    store = ResultStore(session.paths)
    csv_path = store.new_csv(profile_slug(name))
    log_path = store.log_for(csv_path)
    top_n = _top_ips(session, profile)
    argv = build_scan_argv(cfst, scanned, csv_path,
                           results_limit=_requested_results(profile, top_n))

    if session.dry_run:
        _print_dry_run(console, argv, csv_path, log_path)
        _print_measurement_plan(console, scanned, direct=getattr(session, "direct", False),
                                cfst_path=cfst)
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

    results = _augment_results(session, config, scanned, report.results, csv_path)
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
        flow="Quick Scan", colo_filter=scanned.get("colo"),
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

def _ask_measurements(console, base):
    """Jitter, download and upload. Download and upload stay opt-in.

    Jitter defaults on: it is a few TCP handshakes against the addresses the
    scan already kept. Download and upload need a URL that actually carries a
    body, so they stay off until asked.
    """
    jitter_test = console.ask_yes_no(
        "Measure jitter (how much the ping fluctuates)?",
        default=bool(base.get("jitter_test", True)),
    )
    download_test = console.ask_yes_no(
        "Enable the download speed test (slower)?",
        default=bool(base.get("download_test")),
    )
    download_url = str(base.get("download_url") or "")
    try:
        download_count = int(base.get("download_count") or 10)
    except (TypeError, ValueError):
        download_count = 10
    try:
        download_seconds = int(base.get("download_seconds") or 10)
    except (TypeError, ValueError):
        download_seconds = 10
    if download_test:
        console.line(
            "cfst records a download speed only for an HTTP 200 response with "
            "a large body. The profile test URL is usually a short status "
            "check, so the default below is a separate file. Type 'profile' "
            "to download the test URL instead."
        )
        download_url = console.ask(
            "Download URL",
            default=download_url or DEFAULT_DOWNLOAD_URL,
            validate=lambda value: validate_speed_url(value, allow_profile=True),
        )
        download_count = console.ask_int(
            "How many of the fastest addresses to download-test",
            default=download_count, minimum=1, maximum=50,
            field="download count",
        )
        download_seconds = console.ask_int(
            "Seconds to download from each address",
            default=download_seconds, minimum=1, maximum=60,
            field="download seconds",
        )
    upload_test = console.ask_yes_no(
        "Enable the upload speed test (slower, needs a URL)?",
        default=bool(base.get("upload_test")),
    )
    upload_url = str(base.get("upload_url") or "")
    try:
        upload_seconds = int(base.get("upload_seconds") or 8)
    except (TypeError, ValueError):
        upload_seconds = 8
    if upload_test:
        upload_url = console.ask(
            "Upload URL",
            default=upload_url or DEFAULT_UPLOAD_URL,
            validate=validate_speed_url,
        )
        upload_seconds = console.ask_int(
            "Seconds to upload to each address",
            default=upload_seconds, minimum=1, maximum=60,
            field="upload seconds",
        )
    return {
        "jitter_test": jitter_test,
        "download_test": download_test,
        "download_url": download_url,
        "download_count": download_count,
        "download_seconds": download_seconds,
        "upload_test": upload_test,
        "upload_url": upload_url,
        "upload_seconds": upload_seconds,
    }


def _ask_region_filter(console, current):
    """Ask which datacentres to keep, with "none of them" always on screen.

    An earlier version asked for the list as free text and told the user to
    "leave it empty" to measure the whole edge. That was wrong twice over: an
    empty answer makes :meth:`Console.ask` fall back to the default, so pressing
    Enter *kept* the filter, and the only spellings that really cleared it -
    "any", "all", "none" - were never shown anywhere. A filter that cannot be
    switched off from the screen that sets it is a trap, so the choice is on
    screen instead of being a word you have to know.
    """
    current = str(current or "").strip()
    console.blank()
    console.line("A region filter keeps only the addresses whose datacentre you "
                 "name (FRA, AMS, LHR, ...). Without one, the whole edge is "
                 "measured - which is what you want when you do not yet know "
                 "which datacentres are fast on your line (menu 12 ranks them).")
    if not current:
        answer = console.ask_choice(
            "Region filter",
            [("1", "Measure every datacentre (no filter)"),
             ("2", "Keep only the datacentres I name")],
            default="1",
        )
        if answer == "1":
            return ""
        return console.ask("Datacentres to keep", default="FRA,AMS",
                           validate=validate_colo)

    answer = console.ask_choice(
        "Region filter",
        [("1", f"Keep {current}"),
         ("2", "Measure every datacentre (clear the filter)"),
         ("3", "Type a different list")],
        default="1",
    )
    if answer == "1":
        return current
    if answer == "2":
        return ""
    return console.ask("Datacentres to keep", default=current,
                       validate=validate_colo)


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
                save_prompt=True, scan=True):
    """Ask for every setting, then optionally save and run it.

    ``scan=False`` stops after the profile is saved and shown. Menu 6 needs
    that: it is called "Add or Edit Profile" and had no way to change a setting
    that did not also cost a full scan, which is how the region filter ended up
    feeling permanent.
    """
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
        if scheme == "https":
            colo = _ask_region_filter(console, base.get("colo"))
        else:
            # The edge answers this recipe itself with an empty CF-RAY, so the
            # datacentre is never reported and a filter would drop everything.
            colo = ""
            if base.get("colo"):
                console.warn("The region filter was cleared: it cannot work "
                             "with scheme=http (see menu 9).")
    else:
        scheme = str(base.get("scheme") or "https").lower()
        http_status = base.get("http_status")
        colo = ""
        if base.get("colo"):
            console.warn("The region filter was cleared: TCPing never learns "
                         "which datacentre answered.")

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
    # Not "results to display": that was the scanner's -p, which only caps the
    # scanner's own console output - output cfscan hides. This number is the one
    # the user actually sees, and the one the strict check re-measures.
    top_ips = console.ask_int("How many of the best addresses to show and verify",
                              default=base.get("top_ips") or 10, minimum=1,
                              maximum=50, field="addresses offered")
    measurements = _ask_measurements(console, base)
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
        "colo": colo,
        "top_ips": top_ips,
        "output_filename": filename,
    })
    profile.update(measurements)
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
    scanned = _scan_profile(session, profile)
    argv = build_scan_argv(cfst, scanned, csv_path,
                           results_limit=_requested_results(profile, top_n))

    console.blank()
    console.heading("Summary")
    _render_profile(console, new_name, scanned)
    _note_measurements(console, scanned)

    if not scan:
        console.blank()
        if save_it:
            console.ok(f"Profile '{new_name}' saved. Nothing was scanned.")
        else:
            console.warn("These settings were not saved, and nothing was "
                         "scanned.")
        remember_result(session, "INFO",
                        [f"Profile '{new_name}' "
                         + ("saved" if save_it else "left unsaved"),
                         "No scan was run."],
                        title="Edit profile")
        return EXIT_OK

    if session.dry_run:
        _print_dry_run(console, argv, csv_path, log_path)
        _print_measurement_plan(console, scanned,
                                direct=getattr(session, "direct", False),
                                cfst_path=cfst)
        return EXIT_OK

    try:
        check_cfst(cfst)
    except CfstNotFoundError as exc:
        console.error(str(exc))
        return EXIT_MISSING_TOOL

    if _refuse_placeholder(session, new_name, profile):
        return EXIT_USAGE

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

    results = _augment_results(session, config, scanned, report.results, csv_path)
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
        flow="Custom Scan", colo_filter=scanned.get("colo"),
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

def _show_saved_addresses(console, profile, saved):
    """List a profile's proven addresses, newest first."""
    console.blank()
    console.line(console.style(f"Saved good IPs for {profile.get('domain')}",
                               "bold"))
    rows = []
    for position, entry in enumerate(saved, start=1):
        rtt = entry.get("rtt_ms")
        rows.append([
            str(position),
            entry["ip"],
            f"{float(rtt):.0f} ms" if rtt is not None else "-",
            str(entry.get("colo") or "-"),
            favourites_module.format_age(entry),
        ])
    console.table(["#", "IP address", "Latency", "Colo", "Proven"], rows,
                  aligns=["r", "l", "r", "l", "l"])
    console.line(console.style(
        "Those numbers are from when the address was proven, not from now - "
        "that is what this check is for.", "dim"))


def _ask_verify_target(console, profile, version):
    """What menu 3 should measure: ``("all", None)`` or ``("one", address)``.

    The saved list is offered first because it is almost always the answer: a
    scan's winners from yesterday are the cheapest candidates today, and
    re-proving ten of them is one short run rather than a full range scan.
    """
    saved = favourites_module.entries_for(profile)
    if not saved:
        address = console.ask(
            f"IP address to verify (IPv{version})",
            default=profile.get("recommended_ip"),
            validate=lambda value: str(validate_ip(value, version=version)),
        )
        return "one", address

    _show_saved_addresses(console, profile, saved)
    console.blank()

    def resolve(value):
        text = str(value).strip()
        if text.lower() in ("a", "all"):
            return ("all", None)
        if text.isdigit() and 1 <= int(text) <= len(saved):
            return ("one", saved[int(text) - 1]["ip"])
        if text.isdigit():
            raise ValidationError(
                f"There is no {text} in the list above: pick 1 to {len(saved)}, "
                "type 'all', or type an IP address."
            )
        return ("one", str(validate_ip(text, version=version)))

    return console.ask(
        f"Number from the list, 'all' to re-check every saved address, or an "
        f"IPv{version} address",
        default=profile.get("recommended_ip"),
        validate=resolve,
    )


def verify_saved_flow(session, config, name, profile, saved):
    """Re-measure every saved address of a profile in one scanner run."""
    console = session.console
    attempts = int(profile.get("verify_attempts") or session.verify_attempts or 20)
    addresses = [entry["ip"] for entry in saved]
    console.line(f"Re-checking {len(addresses)} saved address(es) with "
                 f"{attempts} attempts each.")
    verified = verify_addresses(session, config, profile, addresses,
                                label="Re-checking")
    if verified is None:
        console.warn("The check did not produce verdicts, so nothing was "
                     "changed.")
        remember_result(session, "WARN",
                        ["The saved addresses could not be re-checked."],
                        title="Saved addresses - no verdict")
        return EXIT_FAILED

    rows = []
    passing = []
    for entry in saved:
        row = verified.get(entry["ip"])
        verdict = _verify_verdict(row, attempts)
        if verdict == "PASS":
            passing.append(row)
        rows.append([
            verdict,
            entry["ip"],
            row.latency_text() if row is not None else "-",
            row.loss_text() if row is not None else "-",
            (row.colo_text() if row is not None else None)
            or str(entry.get("colo") or "-"),
        ])
    console.blank()
    console.heading(f"Saved addresses - {len(passing)} of {len(saved)} still pass")
    console.table(["Verdict", "IP address", "Latency", "Loss", "Colo"], rows,
                  aligns=["l", "l", "r", "r", "l"])

    if passing:
        # Re-proving refreshes the numbers and the order; nothing is dropped for
        # failing today, because an address that is unreachable this minute is
        # often the fastest one an hour later.
        favourites_module.remember_many(profile, passing)
        best = min(passing, key=lambda row: row.latency_ms)
        profile["recommended_ip"] = best.ip
        try:
            save_config(session.paths, config)
        except OSError as error:
            console.warn(f"The profile could not be saved: {error}")
        console.blank()
        console.ok(f"Fastest address that still passes: {best.ip} - "
                   f"{best.latency_text()}, colo {best.colo_text()}.")
        show_client_guide(console, profile, best.ip)
        remember_result(session, "PASS", [
            f"{len(passing)} of {len(saved)} saved addresses still pass",
            f"Fastest: {best.ip} - {best.latency_text()}, colo {best.colo_text()}",
            f"Client fields - Address {best.ip}, Port {profile.get('port')}, "
            f"SNI {profile.get('domain')}, Host {profile.get('domain')}",
        ], title=f"Saved addresses - {len(passing)}/{len(saved)} PASS")
        return EXIT_OK

    console.blank()
    console.warn("Not one saved address answers right now. They are kept - an "
                 "address that is unreachable this minute is often the fastest "
                 "one an hour later - but a fresh scan (menu 1) is the way "
                 "forward if this repeats.")
    remember_result(session, "FAIL",
                    [f"None of the {len(saved)} saved addresses passed."],
                    title="Saved addresses - none pass")
    return EXIT_FAILED


def _point_last_result_at(session, config, store, csv_path, name, ip):
    """Record a verified address without losing the last full scan.

    Menu 4 is "show the last scan". Replacing its pointer with a single-address
    verification file used to leave that menu showing one row, right after the
    same screen had promised it would show the scan. So the scan keeps the
    pointer and only the recommended address is refreshed; a verification with
    no scan behind it does become the pointer, because then it is all there is.
    """
    pointer = config.get("last_result") or {}
    stored = str(pointer.get("csv") or "")
    if stored and Path(stored).exists() and stored != str(csv_path):
        pointer["recommended_ip"] = ip
        config["last_result"] = pointer
        try:
            save_config(session.paths, config)
        except OSError as error:  # pragma: no cover - the verdict still stands
            session.console.warn(f"The result pointer could not be saved: {error}")
        return pointer
    return store.record_latest(config, csv_path, profile_name=name,
                               recommended_ip=ip)


def verify_flow(session, config, ip=None, profile_name=None):
    """Prove (or disprove) one address with 20 attempts and zero loss allowed."""
    console = session.console
    name, profile = _profile_pair(config, profile_name)
    version = int(profile.get("ip_version", 4))
    attempts = int(profile.get("verify_attempts") or session.verify_attempts or 20)

    console.heading("Verify an IP")

    if ip is None:
        target, ip = _ask_verify_target(console, profile, version)
        if target == "all":
            return verify_saved_flow(session, config, name, profile,
                                     favourites_module.entries_for(profile))
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
        wanted = str(profile.get("colo") or "")
        if wanted and row.has_colo and row.colo.upper() not in wanted.upper().split(","):
            console.warn(f"{ip} answers from {row.colo_text()}, which is not in "
                         f"this profile's region filter ({wanted}). It works - "
                         "it is just not where you asked for.")
        show_client_guide(console, profile, ip)

        # The profile keeps what was proven, so the next scan prefers it and the
        # preflight starts from an address that is known to answer.
        profile["recommended_ip"] = ip
        favourites_module.remember(profile, ip, rtt_ms=row.latency_ms,
                                   colo=row.colo)
        _point_last_result_at(session, config, store, csv_path, name, ip)
        console.line(f"Saved to profile '{name}' - menu 3 offers it first from "
                     "now on.")
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

    try:
        _shown_name, shown_profile = get_active(config)
    except UnknownProfile:
        shown_profile = {}
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
    _render_results_table(console, results, recommended_ip=preferred,
                          profile=shown_profile)
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
         ("3", "Edit the active profile (no scan)"),
         ("4", "Delete a profile"),
         ("0", "Back to the main menu")],
        default="0",
    )

    if choice == "1":
        return _make_profile_active(session, config)
    if choice == "2":
        return custom_scan(session, config, force_save=True, save_prompt=False)
    if choice == "3":
        # Editing works on the active profile because every prompt starts from
        # its values; editing another one from here would copy the active
        # profile's settings onto it. Option 1 switches first.
        return custom_scan(session, config, force_save=True, save_prompt=False,
                           scan=False)
    if choice == "4":
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

    if len(config.get("profiles") or {}) <= 1:
        console.warn(f"'{name}' is the only profile left, and it cannot "
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

#: Scans kept when the results folder is tidied. Twenty covers weeks of normal
#: use, and the newest one is never among the files that go.
KEEP_RESULTS = 20


def prunable_results(results_dir, keep=KEEP_RESULTS, protect=()):
    """The result files a tidy-up would remove, oldest first.

    A scan is one CSV plus its log, so they are counted and removed as a pair.
    Multi-carrier sessions, candidate lists and anything the configuration still
    points at are never touched: they are records, not leftovers.
    """
    directory = Path(results_dir)
    if not directory.is_dir():
        return []
    protected = {str(item) for item in protect if item}
    scans = [item for item in directory.glob("*.csv")
             if item.is_file() and str(item) not in protected]
    scans.sort(key=lambda item: item.stat().st_mtime_ns)
    if len(scans) <= max(0, int(keep)):
        return []
    doomed = []
    for csv_path in scans[:len(scans) - int(keep)]:
        doomed.append(csv_path)
        log_path = csv_path.with_suffix(".log")
        if log_path.exists():
            doomed.append(log_path)
    return doomed


def _tidy_results(session, config, directory):
    """Offer to remove the oldest scans once the folder has grown."""
    console = session.console
    pointer = (config.get("last_result") or {})
    protect = [pointer.get("csv"), pointer.get("log")]
    doomed = prunable_results(directory, protect=protect)
    if not doomed:
        return
    console.blank()
    console.line(f"{len(doomed)} old file(s) are older than the newest "
                 f"{KEEP_RESULTS} scans.")
    if not console.interactive or session.assume_yes or session.dry_run:
        console.line("Run menu 8 in a terminal to remove them.")
        return
    if not console.ask_yes_no(f"Delete those {len(doomed)} file(s)?",
                              default=False):
        console.line("Kept - nothing was deleted.")
        return
    removed = 0
    for path in doomed:
        try:
            path.unlink()
            removed += 1
        except OSError as error:
            console.warn(f"{path.name} could not be removed: {error}")
    console.ok(f"{removed} file(s) removed; the newest {KEEP_RESULTS} scans, "
               "every multi-carrier session and every candidate list are still "
               "there.")


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
    files = sorted(directory.glob("*.csv"))
    if files:
        console.line(f"{len(files)} saved scan(s).")
    _tidy_results(session, config, directory)
    console.blank()
    if results_module.open_in_finder(directory):
        console.ok("Finder opened.")
        return EXIT_OK
    console.warn("Finder could not be opened automatically. Open the path above "
                 "in Finder manually.")
    return EXIT_OK


def _range_age_note(info):
    """How old a range file is, in one short phrase."""
    if not info["exists"]:
        return "missing"
    parts = [f"{info['ranges']} range(s)"]
    modified = info.get("modified")
    if modified is not None:
        days = max(0, (datetime.now() - modified).days)
        parts.append(f"{modified:%Y-%m-%d}")
        if days >= 180:
            parts.append(f"{days // 30} months old")
    return ", ".join(parts)


def update_ranges_flow(session, config, profile_name=None, assume_yes=None,
                       allow_unattended=False):
    """Download Cloudflare's current range lists over the ones on disk.

    The lists that ship with the scanner are a snapshot, and a range that is
    missing from the file is simply never scanned - so this is not cosmetic: it
    decides which part of the edge can be found at all.
    """
    console = session.console
    name, profile = _profile_pair(config, profile_name)
    console.heading("Update IP ranges")
    console.line("Cloudflare publishes its current ranges as plain text. The "
                 "files below are what the scanner reads.")

    targets = []
    for version, key in ((4, "ipv4_file"), (6, "ipv6_file")):
        path = profile.get(key) or (profile.get("ip_file")
                                    if version == 4 else None)
        if not path:
            continue
        info = ranges_module.describe_file(path)
        targets.append((version, Path(path), info))

    if not targets:  # pragma: no cover - defensive
        console.warn("This profile names no range file to update.")
        return EXIT_FAILED

    console.blank()
    for version, path, info in targets:
        console.key_value(f"IPv{version}", f"{path}")
        console.key_value("  now", _range_age_note(info))
        console.key_value("  source", ranges_module.url_for_version(version))

    if session.dry_run:
        console.blank()
        console.warn("Dry run - nothing was downloaded and nothing was changed.")
        return EXIT_OK

    console.blank()
    console.line("The published list is merged into your file rather than "
                 "swapping it: neither list contains the other. Your file "
                 "covers 104.28-104.31, which Cloudflare does not publish and "
                 "which answers today; the published list covers 172.68-172.71, "
                 "which your file never had.")
    console.line("The current file is kept next to the new one as "
                 "'<name>.previous', so this is reversible.")
    if assume_yes is None:
        assume_yes = session.assume_yes
    if not assume_yes:
        if console.interactive:
            if not console.ask_yes_no("Download the current lists now?",
                                      default=True):
                console.warn("Cancelled - nothing was downloaded.")
                return EXIT_OK
        elif not allow_unattended:
            # Reached from the menu with nothing to answer with. Downloading a
            # file and overwriting the range lists is not something to do when
            # the question cannot be asked.
            console.warn("Nothing was downloaded: this was started from the "
                         "menu with no terminal to confirm in. Run "
                         "'cfscan --update-ranges' instead.")
            return EXIT_OK

    updated = 0
    failed = 0
    lines = []
    for version, path, info in targets:
        url = ranges_module.url_for_version(version)
        console.blank()
        console.line(f"Downloading the IPv{version} list from {url} ...")
        try:
            text = ranges_module.fetch_text(url)
            found = ranges_module.parse_ranges(text, version)
        except ranges_module.RangeError as error:
            console.error(str(error))
            lines.append(f"IPv{version}: not updated ({error})")
            failed += 1
            continue
        mine = ranges_module.read_ranges(path, version)
        merged, stats = ranges_module.merge_ranges(mine, found)
        try:
            written, backup = ranges_module.install_ranges(path, merged)
        except ranges_module.RangeError as error:
            console.error(str(error))
            lines.append(f"IPv{version}: not written ({error})")
            failed += 1
            continue
        gained = stats["after"] - stats["before"]
        kept = stats["after"] - stats["published"]
        console.ok(f"IPv{version}: {len(merged)} range(s) written to {written}.")
        if version == 4:
            console.line(f"  {stats['after']:,} addresses in range now "
                         f"({gained:+,} compared with before).")
            summary = f"{stats['after']:,} addresses ({gained:+,})"
        else:
            # An IPv6 address count runs to thirty digits and tells a reader
            # nothing, so the entry count is what is shown. Fewer entries than
            # before is normal and never a loss: this is a union, and ranges
            # that sit inside a wider one collapse into it.
            note = ""
            if len(merged) < len(mine):
                note = (f" ({len(mine)} before, collapsed into wider entries - "
                        "the area covered only ever grows)")
            elif len(mine):
                note = f" ({len(mine)} before)"
            console.line(f"  {len(merged)} range(s) now{note}.")
            summary = f"{len(merged)} range(s), {len(mine)} before"
        if kept > 0:
            console.line("  Some of your ranges are not in Cloudflare's "
                         "published list and were kept, because dropping a live "
                         "range costs more than scanning a dead one.")
        if backup:
            console.line(f"  previous file kept as {backup}")
        lines.append(f"IPv{version}: {summary}")
        updated += 1

    console.blank()
    if updated:
        console.line("A scan started from now on measures the new ranges. A "
                     "candidate list built earlier (menu 10) still holds the old "
                     "addresses - rebuild it with 'cfscan --make-pool'.")
    remember_result(session, "PASS" if updated and not failed else
                    ("WARN" if updated else "FAIL"),
                    lines or ["Nothing was updated."],
                    title="Update IP ranges")
    return EXIT_OK if updated and not failed else EXIT_FAILED


def _import_edge_history(session, profile, name):
    """Build a scoreboard out of the result files already on disk.

    A profile that has never recorded an observation still has months of saved
    scans sitting in the results folder, and throwing that away to start
    counting from zero would be silly. The line those scans were taken on is
    unknown, so they are labelled as such rather than being claimed for the
    line that happens to be up now.
    """
    directory = Path(session.paths.results_dir)
    if not directory.is_dir():
        return 0
    prefix = f"cfscan-{profile_slug(name)}-"
    files = sorted((item for item in directory.glob(f"{prefix}*.csv")
                    if item.is_file()),
                   key=lambda item: item.stat().st_mtime_ns)
    imported = 0
    for path in files[-edges_module.MAX_HISTORY:]:
        try:
            report = parse_results_csv(path)
        except CsvError:
            continue
        when = datetime.fromtimestamp(path.stat().st_mtime)
        if edges_module.observe(profile, report.results,
                                line=edges_module.UNKNOWN_LINE, when=when):
            imported += 1
    return imported


def _render_scoreboard(console, rows, meta):
    table = []
    for position, row in enumerate(rows, start=1):
        table.append([
            str(position),
            row["colo"],
            f"{row['typical']:.0f} ms",
            f"{row['best']:.0f} ms",
            f"{row['clean'] * 100:.0f}%",
            str(row["samples"]),
            str(row["scans"]),
            "" if row["trusted"] else "too few",
        ])
    console.table(["#", "Colo", "Typical", "Best", "Loss-free", "Addresses",
                   "Scans", "Note"], table,
                  aligns=["r", "l", "r", "r", "r", "r", "r", "l"])
    console.blank()
    console.line(console.style(
        "Typical is the median of each scan's median, so one bad scan cannot "
        "move it. A row marked 'too few' has not been measured enough to mean "
        "anything yet and never wins.", "dim"))


def edge_locations(session, config, profile_name=None):
    """Rank the datacentres from what has actually been measured on this line.

    Distance does not decide which edge is fast, so nothing here is derived
    from a map: the order comes from the scans this profile has run, grouped by
    the line they ran on.
    """
    console = session.console
    name, profile = _profile_pair(config, profile_name)
    console.heading("Edge locations")

    if not edges_module.entries_for(profile):
        imported = _import_edge_history(session, profile, name)
        if imported:
            console.info(f"Built a first scoreboard from {imported} saved scan(s) "
                         "in the results folder.")
            try:
                save_config(session.paths, config)
            except OSError as error:  # pragma: no cover - read-only home
                console.warn(f"It could not be saved: {error}")
        else:
            console.warn("No scan has recorded a datacentre yet. Run menu 1 "
                         "once and come back.")
            return EXIT_OK

    line = edges_module.describe_line()
    everything, _meta = edges_module.scoreboard(profile)
    rows, meta = edges_module.scoreboard(profile, line=line["label"])
    scope = line["label"]
    if not rows:
        # Nothing measured on this line yet: show what there is and say whose
        # measurements they are, rather than pretending they describe this one.
        rows, meta = everything, _meta
        scope = "all lines"

    console.key_value("Profile", name)
    console.key_value("Line now", f"{line['label']}"
                      + ("  (a tunnel - these numbers describe its path)"
                         if line["tunnel"] else ""))
    console.key_value("Ranking from", f"{meta['scans']} scan(s) on {scope}")
    if len(meta["lines"]) > 1:
        console.key_value("Lines recorded", ", ".join(meta["lines"]))
    console.blank()
    _render_scoreboard(console, rows, meta)

    if meta["stale"]:
        console.blank()
        console.warn(
            f"The recent scans were all filtered to {meta['recent_filter']}, so "
            "the datacentres outside that filter are no longer being measured "
            "and cannot climb back. Run one scan with the filter cleared now and "
            "then to keep this honest."
        )

    suggestion = edges_module.recommended_filter(rows)
    console.blank()
    current = str(profile.get("colo") or "")
    if not suggestion:
        console.line("Not enough measured yet to suggest a filter. Run a few "
                     "more scans.")
        remember_result(session, "INFO",
                        [f"{len(rows)} datacentre(s) ranked from "
                         f"{meta['scans']} scan(s)"],
                        title="Edge locations")
        return EXIT_OK

    wanted = ",".join(suggestion)
    console.ok(f"Suggested region filter: {wanted}")
    console.line(f"  (the fastest measured datacentres on {scope}, dropping any "
                 "that is far slower than the best)")
    if current:
        console.line(f"  This profile currently uses: {current}")

    if console.interactive and not session.assume_yes:
        # Clearing has to be on this screen. It is the screen that warns the
        # filter has stopped the ranking from refreshing, and offering no way to
        # act on that warning is what made the filter feel like a one-way door.
        options = []
        if wanted != current:
            options.append(("1", f"Use the suggested filter: {wanted}"))
        if current:
            options.append(("2", "Measure every datacentre (clear the filter)"))
            options.append(("3", f"Keep {current}"))
        else:
            options.append(("3", "Keep measuring every datacentre"))
        console.blank()
        answer = console.ask_choice("What should this profile scan?", options,
                                    default=options[0][0])
        if answer in ("1", "2"):
            chosen = wanted if answer == "1" else ""
            profile["colo"] = chosen
            problem = colo_problem(profile)
            if problem:
                profile["colo"] = current
                console.error(problem)
            else:
                try:
                    save_config(session.paths, config)
                except OSError as error:
                    console.error(f"The profile could not be saved: {error}")
                else:
                    console.ok(f"Profile '{name}' now scans "
                               + (f"only {chosen}." if chosen
                                  else "every datacentre."))
    elif wanted == current:
        console.line("The profile already uses exactly that.")
    else:
        console.line(f"  Apply it with: cfscan --colo {wanted}")
        if current:
            console.line("  Or clear it with: cfscan --colo any")

    remember_result(session, "INFO", [
        f"{len(rows)} datacentre(s) ranked from {meta['scans']} scan(s) on {scope}",
        f"Fastest: {rows[0]['colo']} at {rows[0]['typical']:.0f} ms typical",
        f"Suggested filter: {wanted}",
    ], title="Edge locations")
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
    console.bullet("Jitter (how much the ping fluctuates) is measured on the best "
                   "addresses after the scan and is on by default. Two addresses "
                   "with the same latency are ranked by the steadier one.")
    console.bullet("The download speed test is optional. cfst only records a "
                   "speed for an HTTP 200 body large enough to fill the download "
                   "window, and it has a single -url, so a separate download URL "
                   "is measured in a second pass. It is off until you set that.")
    console.bullet("Upload is not a cfst feature. When you enable it, cfscan "
                   "POSTs to an upload URL through each candidate address. It "
                   "is off until a URL is set.")
    console.bullet("cfscan --direct applies to those probes as well as to cfst: "
                   "proxy variables in the shell are ignored, so the numbers "
                   "describe this machine's own connection.")

    console.blank()
    console.line(console.style("Picking the datacentre (region filter)", "bold"))
    console.bullet("Cloudflare answers from the datacentre nearest to your line, "
                   "and which one that is decides the latency far more than the "
                   "address does. A region filter keeps only the addresses whose "
                   "datacentre you name - FRA (Frankfurt), AMS (Amsterdam), LHR "
                   "(London) - and menu 2 asks for it.")
    console.bullet("Measured on one line here: an unfiltered scan returned 1,385 "
                   "addresses in GYD (Baku) and two in FRA, while 'FRA,AMS,LHR' "
                   "returned 36 addresses, all of them FRA or LHR at 138-150 ms. "
                   "The filter is how you ask for the second result.")
    console.bullet("It needs HTTPing with scheme=https. TCPing never reads a "
                   "header, and plain HTTP to an HTTPS port makes the edge answer "
                   "its own 400, whose CF-RAY header is empty - so in both cases "
                   "the datacentre stays unknown and the filter would drop every "
                   "address. cfscan says so instead of letting that happen.")
    console.bullet("Verification is never filtered: the question there is whether "
                   "one address still answers, so an address that moved to "
                   "another datacentre is reported as moved, not as dead.")

    console.bullet("Which datacentres to name is not a question of distance. "
                   "Measured on one Iranian line over roughly six thousand "
                   "addresses, GYD (Baku) - the nearest datacentre of all - had "
                   "a median of 232 ms and was the slowest of every European "
                   "colo, while FRA, some 3,000 km further away, had a median of "
                   "176 ms and the fastest address of the whole set at 134 ms. "
                   "What decides it is the route your carrier takes, not the "
                   "distance.")
    console.bullet("So menu 12 does not guess it from a map: every scan records "
                   "which datacentres answered and how fast, and menu 12 ranks "
                   "them from that and offers the filter. The ranking is kept "
                   "per line - a scan taken through a tunnel describes the "
                   "tunnel's path, not this machine's own connection, and mixing "
                   "the two would describe neither.")
    console.bullet("Once a filter is on, the datacentres it leaves out are never "
                   "measured again and cannot climb back, so menu 12 says when "
                   "the picture has stopped refreshing. Clearing the filter for "
                   "one scan now and then keeps it honest.")
    console.bullet("Turning it off is always one choice away: menu 2 and menu 12 "
                   "both offer \"measure every datacentre\", menu 6 edits it "
                   "without running a scan, and 'cfscan --colo any' ignores the "
                   "saved filter for a single run.")

    console.blank()
    console.line(console.style("Scanning through a tunnel", "bold"))
    console.bullet("When this Mac's default route is a tunnel, the scanner "
                   "measures the path through it and out of its exit - so the "
                   "address it recommends is the best one for that tunnel, which "
                   "is rarely what a clean IP is wanted for. cfscan says so "
                   "before the first scan.")
    console.bullet("--direct does not help here: it only clears this shell's "
                   "proxy variables and cannot change a system route. Turn the "
                   "tunnel off to measure the real line.")
    console.bullet("TCPing is meaningless while a tunnel is up. A TUN-mode "
                   "client answers the TCP handshake locally: measured on one "
                   "such line, the handshake came back in 0.4 ms while the TLS "
                   "handshake to the same address took 920 ms.")

    console.blank()
    console.line(console.style("Choosing an address you can trust", "bold"))
    console.bullet("Use menu 3 to verify one address with 20 attempts. It only "
                   "passes when every attempt is answered (0% packet loss).")
    console.bullet("Every address that passes is saved on its profile, and menu 3 "
                   "offers that list before it asks you to type anything. 'all' "
                   "re-checks the whole list in one scanner run - seconds, where "
                   "finding those addresses cost a full scan.")
    console.bullet("An address that fails today is kept, not dropped: the same "
                   "address is often the fastest one an hour later.")
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
    console.line(console.style("Keeping the IP ranges current", "bold"))
    console.bullet("A range that is missing from the range file is never scanned, "
                   "so the file decides which part of Cloudflare's edge can be "
                   "found at all. Menu 11 downloads the lists Cloudflare "
                   "publishes today.")
    console.bullet("It merges rather than replaces, because neither list contains "
                   "the other: the file shipped with the scanner covers "
                   "104.28-104.31, which Cloudflare does not publish and which "
                   "answers today, while the published list covers 172.68-172.71, "
                   "which the shipped file never had. The previous file is kept "
                   "beside the new one as '<name>.previous'.")

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
    console.bullet("cfscan --quick --download  also measure download (needs a URL)")
    console.bullet("cfscan --quick --upload    also measure upload (needs a URL)")
    console.bullet("cfscan --quick --no-jitter skip the jitter samples")
    console.bullet("cfscan --verify 104.16.0.1  strict 20-attempt check")
    console.bullet("cfscan --quick --dry-run   print the argument list only")
    console.bullet("cfscan --profile NAME      use another saved profile")
    console.bullet("cfscan --make-pool 2000    fix the candidate list for all rounds")
    console.bullet("cfscan --isp mci --pool pool-xxxx.txt   measure one carrier")
    console.bullet("cfscan --multi-isp         print the report of the last session")
    console.bullet("cfscan --colo FRA,AMS      keep only those datacentres, this run")
    console.bullet("cfscan --update-ranges     download the current range lists")
    console.bullet("cfscan --edges             rank the datacentres you measured")
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
        if suggestion in names:
            suggestion = None
        while True:
            label = str(console.ask(f"Name of carrier {index + 1}",
                                    default=suggestion)).strip()
            # One carrier gets one round, so two rounds sharing a name would
            # replace one another: the report would then promise more carriers
            # than were ever measured.
            if label and label.lower() in [item.lower() for item in names]:
                console.error(f"'{label}' is already the name of carrier "
                              f"{[item.lower() for item in names].index(label.lower()) + 1}. "
                              "Give each carrier a name of its own.")
                continue
            if not label:
                console.error("A carrier needs a name.")
                continue
            break
        names.append(label)
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
    scanned = _scan_profile(session, profile)
    argv = build_scan_argv(cfst, scanned, csv_path,
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
    if parsed is not None and parsed.results:
        results = _augment_results(session, config, scanned, parsed.results,
                                   csv_path)
    else:
        results = []
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
    if _refuse_placeholder(session, name, profile):
        return EXIT_USAGE
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
    if _refuse_placeholder(session, name, profile):
        return EXIT_USAGE
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
    "11": lambda session, config: update_ranges_flow(session, config),
    "12": lambda session, config: edge_locations(session, config),
}


MENU_WIDTH = 66


def _recipe_line(profile):
    """The profile's test recipe as one readable line."""
    parts = [f"port {profile.get('port')}", f"IPv{profile.get('ip_version', 4)}"]
    mode = str(profile.get("mode") or "httping").lower()
    if mode == "httping":
        scheme = str(profile.get("scheme") or "https").lower()
        parts.append(f"HTTPing/{scheme}")
        parts.append(f"expects {profile.get('http_status')}")
    else:
        parts.append("TCPing")
    colo = str(profile.get("colo") or "").strip()
    parts.append(f"only {colo}" if colo else "any colo")
    return "  ".join(parts)


def _last_run_line(config):
    """One line about the newest stored result, or None when there is none."""
    pointer = (config.get("last_result") or {})
    if not pointer.get("csv"):
        return None
    parts = []
    address = pointer.get("recommended_ip")
    parts.append(str(address) if address else "no address recommended")
    when = str(pointer.get("when") or "")
    try:
        parts.append(f"{datetime.fromisoformat(when):%d %b %H:%M}")
    except ValueError:
        if when:
            parts.append(when)
    if not Path(str(pointer["csv"])).exists():
        parts.append("file removed")
    return "  ".join(parts)


def _scanner_line(session, config, profile):
    """One line saying whether the two things a scan needs are actually there.

    A missing binary or a missing range file stops a scan seconds after it is
    started, with an error the user then has to read. Saying it on the menu
    turns that into something visible before anything is chosen.
    """
    problems = []
    try:
        check_cfst(_cfst_path(config))
        scanner = "cfst ready"
    except CfstNotFoundError:
        scanner = "cfst MISSING"
        problems.append("scanner")
    info = ranges_module.describe_file(ip_file_for(profile))
    name = Path(info["path"]).name
    if not info["exists"]:
        problems.append("ranges")
        return f"{scanner}  {name} MISSING", problems
    ranges = f"{name} {info['ranges']} ranges"
    modified = info.get("modified")
    if modified is not None:
        days = max(0, (datetime.now() - modified).days)
        # A stale list is not an error - it still scans - but it quietly hides
        # every range Cloudflare published since, so it is worth saying.
        if days >= 365:
            problems.append("ranges")
            ranges += f", {days // 365} year(s) old - menu 11 updates them"
        else:
            ranges += f", {modified:%Y-%m-%d}"
    return f"{scanner}  {ranges}", problems


def render_menu(session, config):
    """Draw the menu screen: what is loaded, then what can be done with it."""
    console = session.console
    try:
        name, profile = get_active(config)
    except UnknownProfile:  # pragma: no cover - defensive
        name, profile = "none", {}

    title = f"cfscan {__version__}"
    subtitle = "clean Cloudflare IP finder"
    if running_from_dev_link():
        subtitle += "  [dev link]"
    console.line(console.style("=" * MENU_WIDTH, "dim"))
    console.line(f"  {console.style(title, 'bold', 'cyan')}  "
                 f"{console.style(subtitle, 'dim')}")
    console.line(console.style("=" * MENU_WIDTH, "dim"))

    console.line(f"  {console.style('Profile ', 'dim')}  "
                 f"{console.style(name, 'bold')}")
    if profile:
        console.line(f"  {console.style('Target  ', 'dim')}  "
                     f"{profile.get('domain')}   "
                     f"{console.style(_recipe_line(profile), 'dim')}")
        scanner, problems = _scanner_line(session, config, profile)
        console.line(f"  {console.style('Ready   ', 'dim')}  "
                     + (console.style(scanner, 'yellow', 'bold') if problems
                        else console.style(scanner, 'dim')))
    last = _last_run_line(config)
    if last:
        saved = len(favourites_module.entries_for(profile)) if profile else 0
        if saved:
            last += f"  ({saved} saved IP(s) in menu 3)"
        console.line(f"  {console.style('Last run', 'dim')}  "
                     f"{console.style(last, 'dim')}")
    if profile and is_placeholder(profile):
        console.line("  " + console.style(
            "Not set up yet - this profile is a placeholder. Put your own "
            "domain in it with menu 6, option 3.", "yellow"))
    if session.dry_run:
        console.line("  " + console.style("Dry run - scans print their argument "
                                          "list and never execute", "yellow"))
    console.line(console.style("-" * MENU_WIDTH, "dim"))

    labels = dict(MENU_ITEMS)
    for group, keys in MENU_GROUPS:
        if group:
            console.line(f"  {console.style(group, 'bold')}")
        for key in keys:
            label = labels.get(key)
            if label is None:  # pragma: no cover - guarded by a test
                continue
            hint = MENU_HINTS.get(key) or ""
            entry = f"{key:>2}. {label}"
            if hint:
                console.line(f"   {entry.ljust(26)}{console.style(hint, 'dim')}")
            else:
                console.line(f"   {entry}")
    console.line(console.style("-" * MENU_WIDTH, "dim"))
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

    drawn = 0
    while True:
        # The first draw joins whatever the command line already printed; every
        # later one follows a flow the user has just dismissed with Enter, so the
        # menu comes back on a clean screen instead of under a wall of scanner
        # output. Nothing is lost: the terminal's scrollback still has it all.
        if drawn:
            console.clear()
        render_menu(session, config)
        drawn += 1
        try:
            choice = console.ask_raw("Choose an option (0-12)").strip()
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

"""Run the external scanner: argument building, progress, translation.

cfscan never re-implements scanning. It builds an argument list for the
existing ``cfst`` binary and runs it with :mod:`subprocess` in list form -
without ``shell=True`` and without string interpolation - so no user supplied
value can ever become a shell command.

the scanner's own output is Chinese and noisy; :func:`translate_log` turns it
into short English lines, and the raw output is kept in a ``.log`` file next to
the result CSV for troubleshooting.
"""

from __future__ import annotations

import os
import re
import shlex
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .profiles import ip_file_for
from .results import ensure_dir

__all__ = [
    "CLOUDFLARE_HTTP_PORTS",
    "CLOUDFLARE_HTTPS_PORTS",
    "CfstNotFoundError",
    "PROBE_ADDRESSES",
    "PROXY_ENV_VARS",
    "Progress",
    "ScanError",
    "ScanOutcome",
    "build_probe_argv",
    "build_scan_argv",
    "build_url",
    "build_verify_argv",
    "build_verify_many_argv",
    "check_cfst",
    "colo_problem",
    "default_spawn",
    "explain_failure",
    "extract_status_rejection",
    "format_argv_for_display",
    "ipv6_route_available",
    "proxy_variables_present",
    "read_progress",
    "read_progress_file",
    "run_scan",
    "scanner_environment",
    "scheme_port_problem",
    "translate_log",
]

DEFAULT_POLL_INTERVAL = 0.2
KILL_GRACE_SECONDS = 3.0

# The scanner's Go HTTP client honours the proxy variables in its environment, so
# a proxy exported in the shell carries every test request with it: the scan then
# measures the route through that proxy, not the connection from this machine.
# That inheritance is deliberate - starting the scanner exactly the way a manual
# run of cfst would is the least surprising behaviour - but it is never silent:
# the first scan of a session says which variables were inherited, and
# ``--direct`` (or a scan started with the variables unset) measures the plain
# connection instead.
#: A Cloudflare address used only to ask the routing table about IPv6. Nothing
#: is sent to it: a UDP ``connect`` never puts a packet on the wire.
IPV6_ROUTE_PROBE = "2606:4700:4700::1111"

PROXY_ENV_VARS = (
    "HTTP_PROXY", "http_proxy",
    "HTTPS_PROXY", "https_proxy",
    "ALL_PROXY", "all_proxy",
    "FTP_PROXY", "ftp_proxy",
    "NO_PROXY", "no_proxy",
)


def ipv6_route_available(timeout=1.0):
    """Whether this Mac can reach an IPv6 address at all.

    An IPv6 scan can only ever return nothing when the machine has no global
    IPv6 address, which is the normal state on an IPv4-only line (measured on
    this Mac: `-f` with an IPv6 list is accepted by the scanner and then
    reports 0 of 2 reachable, while `curl -6` fails instantly).

    The check is a UDP ``connect`` to a public address: that consults the
    routing table and **sends no packet at all**, unlike a ping or a connect
    test. Returns False when there is no route, and never raises.
    """
    try:
        probe = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    except (OSError, AttributeError):
        return False
    try:
        probe.settimeout(float(timeout))
        probe.connect((IPV6_ROUTE_PROBE, 443, 0, 0))
        return True
    except OSError:
        return False
    finally:
        try:
            probe.close()
        except OSError:  # pragma: no cover - defensive
            pass


def proxy_variables_present(environ=None):
    """The proxy variable names that are set in ``environ`` (the shell's, by default)."""
    environ = os.environ if environ is None else environ
    return [name for name in PROXY_ENV_VARS if str(environ.get(name) or "").strip()]


def scanner_environment(environ=None, direct=False):
    """The environment the scanner runs with.

    By default this is the shell's environment unchanged, so the scanner behaves
    exactly like a manual ``cfst`` run in the same terminal. With ``direct=True``
    the proxy variables are removed, which is what ``cfscan --direct`` asks for
    when the point of the scan is to measure this machine's own connection.
    """
    environ = os.environ if environ is None else environ
    if not direct:
        return dict(environ)
    return {key: value for key, value in environ.items() if key not in PROXY_ENV_VARS}


class ScanError(Exception):
    """Raised for anything that goes wrong while scanning."""


class CfstNotFoundError(ScanError):
    """Raised when the cfst binary is missing or not executable."""


# Cloudflare's edge accepts connections on these ports only. A test URL whose
# scheme does not match its port can never succeed, and the failure is easy to
# miss: the edge answers an HTTP-only port with a plain HTTP response, which a
# TLS client reports as "server gave HTTP response to HTTPS client". Every
# address then fails and the scan ends with no result at all - which looks
# exactly like a network problem.
CLOUDFLARE_HTTPS_PORTS = (443, 2053, 2083, 2087, 2096, 8443)
CLOUDFLARE_HTTP_PORTS = (80, 8080, 8880, 2052, 2082, 2086, 2095)

# Long-lived Cloudflare anycast addresses, used to test a profile against a
# single address before thousands are measured. Any Cloudflare edge address
# serves the same hostname, so one answering is enough to know a profile works.
PROBE_ADDRESSES = ("104.16.0.1", "172.64.0.1", "104.24.0.1")


def scheme_port_problem(profile):
    """Explain a scheme/port pair the Cloudflare edge cannot answer, if any.

    Plain HTTP to an HTTPS port is deliberately allowed: Cloudflare then answers
    400 itself, which is the origin-independent liveness probe the help screen
    documents. HTTPS to a plain-HTTP port is the combination that silently kills
    a whole scan.
    """
    if str(profile.get("mode") or "httping").lower() != "httping":
        return None
    if str(profile.get("scheme") or "https").lower() != "https":
        return None
    try:
        port = int(profile.get("port"))
    except (TypeError, ValueError):
        return None
    if port not in CLOUDFLARE_HTTP_PORTS:
        return None
    https_ports = ", ".join(str(item) for item in CLOUDFLARE_HTTPS_PORTS)
    return (
        f"Port {port} is one of Cloudflare's plain-HTTP ports, so "
        f"{build_url(profile)} can never be answered: the edge replies with a "
        "plain HTTP response and the scanner rejects every address with "
        "\"server gave HTTP response to HTTPS client\". Use scheme=http for "
        f"this port, or move the test URL to an HTTPS port ({https_ports})."
    )


def colo_problem(profile):
    """Explain a region filter the scanner cannot honour, if any.

    The filter works by reading the ``CF-RAY`` header of the edge's answer, so
    it needs a real HTTP conversation with Cloudflare. Two settings make that
    header useless, and in both cases the filter would quietly reject every
    address instead of failing loudly:

    * TCPing measures a bare TCP connect, so no header is ever read.
    * Plain HTTP to an HTTPS port makes the edge answer its own 400, and that
      answer carries an empty ``CF-RAY`` (measured: ``CF-RAY: -``), so the
      datacentre stays unknown even though the address answers.
    """
    if not str(profile.get("colo") or "").strip():
        return None
    if str(profile.get("mode") or "httping").lower() != "httping":
        return ("A region filter needs HTTPing: TCPing only opens a TCP "
                "connection, so the scanner never learns which datacentre "
                "answered. Switch the profile to HTTPing, or clear the filter.")
    if str(profile.get("scheme") or "https").lower() == "http":
        return ("A region filter cannot work with scheme=http on an HTTPS port: "
                "Cloudflare answers that request itself with a 400 whose CF-RAY "
                "header is empty, so no datacentre is reported and every address "
                "would be filtered away. Use scheme=https for a region filter, "
                "or clear the filter.")
    return None


# --------------------------------------------------------------------------
# Argument construction
# --------------------------------------------------------------------------

def build_url(profile):
    """Build the test URL for HTTPing mode."""
    scheme = str(profile.get("scheme") or "https").lower()
    domain = profile["domain"]
    port = int(profile["port"])
    path = str(profile.get("url_path") or "/")
    if not path.startswith("/"):
        path = "/" + path
    return f"{scheme}://{domain}:{port}{path}"


def _format_loss(value):
    return f"{float(value):.2f}"


def build_scan_argv(cfst_path, profile, output_path, single_ip=None, attempts=None,
                    results_limit=None, candidate_file=None):
    """Build the scanner argument list for a profile.

    The default profile produces exactly::

        cfst -f <ip.txt> -tp 2087 -httping -httping-code 400 \\
             -url https://gerr.yasin-ai-54.ir:2087/ -dd -t 4 -n 200 \\
             -tl 1000 -tlr 0.25 -p 20 -o <timestamped-output.csv>

    ``candidate_file`` scans an explicit list of addresses instead of the
    profile's range file. A multi-carrier session needs that: the scanner draws
    a fresh sample from the ranges on every run, so two carriers would otherwise
    never measure the same addresses.
    """
    argv = [str(cfst_path)]

    if single_ip:
        argv += ["-ip", str(single_ip)]
    else:
        argv += ["-f", str(candidate_file) if candidate_file
                 else ip_file_for(profile)]

    argv += ["-tp", str(int(profile["port"]))]

    mode = str(profile.get("mode") or "httping").lower()
    if mode == "httping":
        argv += ["-httping", "-httping-code", str(int(profile["http_status"]))]
        argv += ["-url", build_url(profile)]
        # A region filter belongs to the search, not to the proof: verification
        # re-measures addresses this scan already found, and filtering there
        # would report an address that moved to another datacentre as dead
        # rather than saying it moved. See _build_verify_argv.
        colo = str(profile.get("colo") or "").strip()
        if colo:
            argv += ["-cfcolo", colo]

    if not profile.get("download_test"):
        argv += ["-dd"]

    argv += ["-t", str(int(attempts if attempts is not None else profile["attempts"]))]
    argv += ["-n", str(int(profile["concurrency"]))]
    argv += ["-tl", str(int(profile["max_latency_ms"]))]
    argv += ["-tlr", _format_loss(profile["max_loss"])]
    argv += ["-p", str(int(results_limit if results_limit is not None
                          else profile["results_limit"]))]
    argv += ["-o", str(output_path)]
    return argv


def _build_verify_argv(cfst_path, profile, selection, output_path, attempts,
                       latency_cap_ms, results_limit):
    """Shared body of the single and multi address verification commands.

    Verification disables the download test and uses a generous latency cap, so
    the verdict hinges on reachability and packet loss. The zero-loss rule is
    enforced by cfscan itself (see :func:`cfscan.menu.verify_flow`) rather than
    by the scanner's filter: with ``-tlr 1`` the scanner always writes the
    address it measured, which is what lets cfscan report "17/20 replies, 15%
    loss" instead of silently reporting a rejection. ``-debug`` is enabled so a
    status-code rejection is explained too.
    """
    argv = [str(cfst_path)]
    argv += list(selection)
    argv += ["-tp", str(int(profile["port"]))]

    mode = str(profile.get("mode") or "httping").lower()
    if mode == "httping":
        argv += ["-httping", "-httping-code", str(int(profile["http_status"]))]
        argv += ["-url", build_url(profile)]

    # No -cfcolo here on purpose: the question being asked is "does this exact
    # address still answer", and a region filter would turn "it answers from
    # another datacentre now" into "it is dead". The colo of every row is parsed
    # and shown instead, so a move is visible rather than fatal.
    argv += ["-dd"]
    argv += ["-t", str(int(attempts))]
    argv += ["-n", str(int(profile["concurrency"]))]
    argv += ["-tl", str(int(latency_cap_ms))]
    # 1 = "any packet loss is acceptable" for the scanner, so it reports the
    # address instead of dropping it before cfscan can look at the numbers.
    argv += ["-tlr", "1"]
    argv += ["-p", str(int(results_limit))]
    argv += ["-o", str(output_path)]
    argv += ["-debug"]
    return argv


def build_verify_argv(cfst_path, profile, ip, output_path, attempts=20,
                      latency_cap_ms=10000):
    """Build the argument list for a strict single-IP verification."""
    return _build_verify_argv(cfst_path, profile, ["-ip", str(ip)], output_path,
                              attempts, latency_cap_ms, 1)


def build_verify_many_argv(cfst_path, profile, ip_list_path, output_path,
                           attempts=20, latency_cap_ms=10000, results_limit=10):
    """Build the argument list that verifies several addresses in one run.

    ``ip_list_path`` holds one address per line - the same format as an IP
    range file - so checking ten candidates costs one scanner run, not ten.
    """
    return _build_verify_argv(cfst_path, profile, ["-f", str(ip_list_path)],
                              output_path, attempts, latency_cap_ms,
                              results_limit)


def build_probe_argv(cfst_path, profile, ip, output_path, attempts=2,
                     latency_cap_ms=10000):
    """Build the one-address argument list that tests a profile before a scan.

    It is the verification command reduced to a single address and wrapped
    around the profile's own test URL, with ``-debug`` kept on so the scanner
    prints why an address failed instead of only dropping it.
    """
    return _build_verify_argv(cfst_path, profile, ["-ip", str(ip)], output_path,
                              attempts, latency_cap_ms, 1)


def format_argv_for_display(argv):
    """Render an argument list the way a user would type it."""
    return " ".join(shlex.quote(str(item)) for item in argv)


def check_cfst(cfst_path):
    """Make sure the scanner binary exists and is executable."""
    path = str(cfst_path or "")
    if not path:
        raise CfstNotFoundError(
            "The CloudflareSpeedTest binary 'cfst' was not found. Install it "
            "(for example: brew install cloudflare-speedtest) or set 'cfst_path' "
            "to its location in ~/.config/cfscan/config.json."
        )
    if not os.path.exists(path):
        raise CfstNotFoundError(
            f"The scanner binary was not found at {path}. Install "
            "XIU2/CloudflareSpeedTest or update 'cfst_path' in "
            "~/.config/cfscan/config.json."
        )
    if os.path.isdir(path) or not os.access(path, os.X_OK):
        raise CfstNotFoundError(
            f"{path} is not an executable file, so cfst cannot be started."
        )
    return path


# --------------------------------------------------------------------------
# Progress and log translation
# --------------------------------------------------------------------------

_PROGRESS_RE = re.compile(r"(\d+)\s*/\s*(\d+)\s*\[")
_AVAILABLE_RE = re.compile(r"可用\s*[:：]\s*(\d+)")
_PROGRESS_MARK_RE = re.compile(r"\[[_\-]{3,}")
_CJK_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\u3000-\u303f\uff00-\uffef]")


@dataclass
class Progress:
    """A snapshot of the scanner's progress."""

    done: int
    total: int
    available: Optional[int] = None
    percent: float = 0.0

    @property
    def text(self):
        reachable = "" if self.available is None else f" - reachable: {self.available}"
        return f"{self.done}/{self.total} ({self.percent:.0f}%){reachable}"


def read_progress(text):
    """Extract the newest progress snapshot from scanner output."""
    if not text:
        return None
    tail = text[-4000:]

    last = None
    for match in _PROGRESS_RE.finditer(tail):
        last = match
    if last is None:
        return None

    done = int(last.group(1))
    total = int(last.group(2))
    available = None
    for match in _AVAILABLE_RE.finditer(tail):
        available = int(match.group(1))

    percent = (done / total * 100.0) if total else 0.0
    return Progress(done=done, total=total, available=available, percent=percent)


def read_progress_file(path, limit=8192):
    """Read the tail of a log file and extract progress from it."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as handle:
            if size > limit:
                handle.seek(size - limit)
            raw = handle.read()
    except OSError:
        return None
    return read_progress(raw.decode("utf-8", errors="replace"))


_PHRASES = (
    (r"完整测速结果 IP 数量为 0，跳过输出结果。",
     "No IP passed the filters; the scanner skipped writing a result file."),
    (r"完整测速结果已写入 (.+?) 文件，可使用记事本/表格软件查看。",
     r"Results written to \1"),
    (r"测速结果已写入 (.+?) 文件，可使用记事本/表格软件查看。",
     r"Results written to \1"),
    (r"延迟测速终止", "latency test stopped"),
    (r"下载测速终止", "download test stopped"),
)

_WORDS = (
    (r"开始延迟测速", "Starting latency test"),
    (r"开始下载测速", "Starting download test"),
    (r"跳过下载测速", "Skipping download test"),
    (r"\[信息\]", "[info]"),
    (r"\[调试\]", "[debug]"),
    (r"HTTP 状态码", "HTTP status code"),
    (r"测速地址", "test URL"),
    (r"指定的", "required"),
    (r"模式", "mode"),
    (r"端口", "port"),
    (r"范围", "range"),
    (r"丢包", "loss"),
    (r"可用", "available"),
    (r"平均延迟", "avg latency"),
    (r"下载速度", "download"),
    (r"地区码", "colo"),
    (r"已发送", "sent"),
    (r"已接收", "received"),
    (r"当前为最新版本", "already the latest version"),
    (r"检查版本更新中", "checking for updates"),
    (r"IP[:：]", "IP:"),
)

_PUNCTUATION = (
    ("（", " ("),
    ("）", ")"),
    ("，", ", "),
    ("：", ": "),
    ("、", ", "),
    ("；", "; "),
    ("！", "!"),
)


def translate_log(text):
    """Turn scanner output into short, readable English lines.

    Progress bars are dropped, known Chinese messages are translated, and any
    line that is still Chinese is hidden (the raw log stays available on disk).
    """
    if not text:
        return []

    lines = []
    hidden = 0
    for segment in re.split(r"[\r\n]+", text):
        line = segment.strip()
        if not line:
            continue
        if _PROGRESS_MARK_RE.search(line):
            continue
        translated = line
        for pattern, replacement in _PHRASES:
            translated = re.sub(pattern, replacement, translated)
        for pattern, replacement in _WORDS:
            translated = re.sub(pattern, replacement, translated)
        for source, replacement in _PUNCTUATION:
            translated = translated.replace(source, replacement)
        translated = re.sub(r"\s{2,}", " ", translated).strip()
        if not translated:
            continue
        if _CJK_RE.search(translated):
            hidden += 1
            continue
        lines.append(translated)

    if hidden:
        lines.append(
            f"[scanner] {hidden} untranslated scanner message(s) hidden. "
            "The raw output is saved in the matching .log file."
        )
    return lines


_OBSERVED_STATUS_RE = re.compile(r"HTTP 状态码\s*[:：]\s*(\d{3})")
_EXPECTED_STATUS_RE = re.compile(r"指定的 HTTP 状态码\s*[:：]?\s*(\d{3})")
_REJECTED_IP_RE = re.compile(r"IP\s*[:：]\s*([0-9A-Fa-f:.]+)")


def extract_status_rejection(text):
    """Explain a status-code rejection from the scanner log, if there was one."""
    if not text:
        return None
    observed = _OBSERVED_STATUS_RE.search(text)
    if not observed:
        return None
    expected = _EXPECTED_STATUS_RE.search(text)
    address = _REJECTED_IP_RE.search(text)
    return {
        "observed": int(observed.group(1)),
        "expected": int(expected.group(1)) if expected else None,
        "ip": address.group(1) if address else None,
    }


# The scanner prints the transport error of a failed address verbatim, in the
# ``错误信息:`` ("error message") field. These are the ones that mean the profile
# itself cannot work, rather than the address being unlucky.
_HTTPS_ON_HTTP_ERROR = "server gave HTTP response to HTTPS client"
_UNREACHABLE_ERRORS = (
    ("connection refused", "the address refused the connection"),
    ("i/o timeout", "the connection timed out"),
    ("context deadline exceeded", "the attempt timed out"),
    ("no route to host", "there is no route to the address"),
)


def explain_failure(log_text, profile, address=None):
    """Turn a failed scanner run into the reason, in plain words.

    Returns a list of hints, most specific first. An empty list means the log
    carries nothing recognizable and the caller should fall back to the generic
    troubleshooting list.
    """
    if not log_text:
        return []

    hints = []
    domain = profile.get("domain")
    port = profile.get("port")
    where = f" (measured on {address})" if address else ""

    problem = scheme_port_problem(profile)
    if problem:
        hints.append(problem)
    elif _HTTPS_ON_HTTP_ERROR in log_text:
        hints.append(
            f"The scanner asked for HTTPS on port {port} and the other side "
            "answered in plain HTTP, so that port does not speak TLS at all. "
            "Use an HTTPS port, or set scheme=http and expect the plain status "
            "the edge returns."
        )

    status = extract_status_rejection(log_text)
    if status:
        observed = int(status["observed"])
        expected = status.get("expected") or profile.get("http_status")
        if 520 <= observed <= 530:
            hints.append(
                f"Cloudflare answered {observed} - its own error page, not your "
                f"service{where}. The edge has nothing healthy to forward to for "
                f"{domain}: either the DNS record is not proxied (a grey cloud "
                "resolves straight to the origin, so no Cloudflare address can "
                "ever serve it), or the origin is down, or it does not answer on "
                "a port Cloudflare can reach."
            )
        else:
            hints.append(
                f"The edge answered HTTP {observed} where the profile expects "
                f"{expected}. Fix it by setting the expected status to {observed} "
                "(menu 6), or by keeping 400 and using scheme=http on an HTTPS "
                "port, where Cloudflare answers 400 by itself."
            )

    if not status and _HTTPS_ON_HTTP_ERROR not in log_text:
        lowered = log_text.lower()
        for needle, phrase in _UNREACHABLE_ERRORS:
            if needle in lowered:
                hints.append(
                    f"The scanner reported that {phrase}{where} - that is a "
                    "network or address problem, not a profile problem. A scan "
                    "of the whole range may still find addresses that answer."
                )
                break

    return hints


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------

@dataclass
class ScanOutcome:
    """What happened when the scanner ran."""

    returncode: int = 0
    log_path: Optional[str] = None
    csv_path: Optional[str] = None
    interrupted: bool = False
    timed_out: bool = False
    seconds: float = 0.0
    log_text: str = ""

    @property
    def ok(self):
        return self.returncode == 0 and not self.interrupted and not self.timed_out

    @property
    def has_result(self):
        return bool(self.csv_path) and os.path.exists(str(self.csv_path))

    def translated_log(self):
        return translate_log(self.log_text)

    def translated_log_text(self):
        return "\n".join(self.translated_log())


def _default_spawn(argv, log_handle, working_dir=None, direct=False):
    """Start the scanner with an argument list. No shell is ever involved.

    The environment is the shell's own, unless ``direct`` is set (see
    :func:`scanner_environment`), so a proxy exported for a VPN keeps working and
    a scan without it measures the plain connection.
    """
    return subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        cwd=working_dir,
        env=scanner_environment(direct=direct),
        start_new_session=True,
    )


def default_spawn(direct=False):
    """The production spawn function, fixed to one environment choice.

    ``direct=True`` runs the scanner without any proxy variable, so the numbers
    describe this machine's own connection to the test addresses.
    """
    def spawn(argv, log_handle, working_dir=None):
        return _default_spawn(argv, log_handle, working_dir, direct=direct)

    return spawn


def _terminate(process):
    try:
        process.terminate()
    except (OSError, AttributeError):
        pass
    deadline = time.time() + KILL_GRACE_SECONDS
    while time.time() < deadline:
        try:
            if process.poll() is not None:
                return
        except (OSError, AttributeError):
            return
        time.sleep(0.05)
    try:
        process.kill()
    except (OSError, AttributeError):
        pass


def run_scan(argv, log_path, spawn=None, on_progress=None,
             poll_interval=DEFAULT_POLL_INTERVAL, timeout=None,
             progress_first_after=0.0):
    """Run the scanner and return a :class:`ScanOutcome`.

    ``spawn`` is the single boundary that tests replace; in production it is
    :func:`default_spawn`, which starts the real binary with this shell's
    environment (proxy variables included).
    """
    log_path = Path(log_path)
    try:
        ensure_dir(log_path.parent)
    except OSError as error:
        raise ScanError(f"The scanner log could not be created: {error}")

    spawn = spawn or default_spawn()
    outcome = ScanOutcome(log_path=str(log_path), csv_path=None)
    argv = list(argv)
    if "-o" in argv:
        outcome.csv_path = argv[argv.index("-o") + 1]
    elif "--output" in argv:  # pragma: no cover - defensive
        outcome.csv_path = argv[argv.index("--output") + 1]

    started = time.time()
    reports = 0
    process = None

    with open(str(log_path), "wb") as log_handle:
        try:
            try:
                process = spawn(argv, log_handle)
            except FileNotFoundError:
                raise CfstNotFoundError(
                    f"The scanner binary {argv[0]} could not be started. Check "
                    "'cfst_path' in ~/.config/cfscan/config.json."
                )
            except OSError as error:
                raise ScanError(f"The scanner could not be started: {error}")

            while True:
                if process.poll() is not None:
                    break
                elapsed = time.time() - started
                if timeout is not None and elapsed > timeout:
                    outcome.timed_out = True
                    _terminate(process)
                    break
                time.sleep(poll_interval)
                if on_progress is not None:
                    elapsed = time.time() - started
                    if elapsed >= progress_first_after:
                        on_progress(read_progress_file(log_path))
                        reports += 1

            if on_progress is not None and reports == 0 and not outcome.timed_out:
                report = read_progress_file(log_path)
                if report is not None:
                    on_progress(report)
                    reports += 1

            outcome.returncode = process.returncode if process.returncode is not None else 0
        except KeyboardInterrupt:
            if process is not None:
                _terminate(process)
            outcome.interrupted = True

    outcome.seconds = time.time() - started
    outcome.csv_path = str(outcome.csv_path) if outcome.csv_path else None
    try:
        with open(str(log_path), "rb") as handle:
            outcome.log_text = handle.read().decode("utf-8", errors="replace")
    except OSError:
        outcome.log_text = ""
    return outcome

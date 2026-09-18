"""Shared helpers for the cfscan test suite.

Every helper builds objects from temporary directories, so tests never touch
the real user configuration or the real results folder.

Only one boundary is ever faked: the execution of the external ``cfst``
binary (see ``ScriptedSpawn``). Everything else runs for real.
"""

from __future__ import annotations

import io
import json
import tempfile
from pathlib import Path


# --------------------------------------------------------------------------
# Paths / home directory
# --------------------------------------------------------------------------

#: What the fixture profile targets. Not a real domain anywhere: ".test" is
#: reserved by RFC 6761 precisely so it can never resolve.
FIXTURE_DOMAIN = "node.example.test"
FIXTURE_PORT = 2087
FIXTURE_RECOMMENDED_IP = "104.16.0.1"


def make_paths(root):
    """Build a Paths object whose home directory is a temporary directory."""
    from cfscan.profiles import Paths

    return Paths(home=Path(root))


def write_ip_ranges(path):
    """Create a small but realistic IP range file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "173.245.48.0/20\r\n103.21.244.0/22\r\n104.21.54.0/24\r\n",
        encoding="utf-8",
    )
    return path


def write_fake_cfst(root, name="cfst"):
    """Create an executable stand-in for the scanner binary."""
    path = Path(root) / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


# --------------------------------------------------------------------------
# Console helpers
# --------------------------------------------------------------------------

class ScriptedInput:
    """Replacement for ``input`` that returns pre-recorded answers."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.prompts = []

    def __call__(self, prompt=""):
        self.prompts.append(prompt)
        if not self.answers:
            raise EOFError("scripted input exhausted")
        return self.answers.pop(0)


class TtyStringIO(io.StringIO):
    """A captured stream that claims to be a terminal.

    Used to exercise the parts of cfscan that only happen for a real terminal
    (colour, the live progress line and the "press Enter" pause).
    """

    def isatty(self):
        return True


def make_console(answers=None, color=False, out=None, is_tty=False):
    """Return (console, output_stream, scripted_input)."""
    from cfscan.ui import Console

    if out is not None:
        stream = out
    else:
        stream = TtyStringIO() if is_tty else io.StringIO()
    scripted = ScriptedInput(answers or [])
    console = Console(out=stream, err=stream, input_fn=scripted, color=color)
    return console, stream, scripted


def text_of(stream):
    return stream.getvalue()


# --------------------------------------------------------------------------
# External process boundary
# --------------------------------------------------------------------------

class FakeProcess:
    """Minimal stand-in for ``subprocess.Popen``."""

    def __init__(self, returncode=0, stay_running=False):
        self.returncode = 0 if stay_running else returncode
        self._stay_running = stay_running
        self.terminated = False
        self.killed = False

    def poll(self):
        if self.terminated or self.killed:
            return self.returncode
        return None if self._stay_running else self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True


class ScriptedSpawn:
    """Drop-in replacement for the cfst execution boundary.

    Records every argument list it is called with, writes a scanner log into
    the provided file handle and, unless told otherwise, writes a CSV to the
    ``-o`` path found in the argument list.
    """

    def __init__(
        self,
        log_text="",
        csv_text=None,
        returncode=0,
        create_csv=True,
        error=None,
        stay_running=False,
        csv_sequence=None,
        log_sequence=None,
    ):
        self.log_text = log_text
        self.csv_text = csv_text
        self.returncode = returncode
        self.create_csv = create_csv
        self.error = error
        self.stay_running = stay_running
        self.csv_sequence = list(csv_sequence or [])
        self.log_sequence = list(log_sequence or [])
        self.calls = []

    def _nth(self, sequence, index, fallback):
        if not sequence:
            return fallback
        return sequence[min(index, len(sequence) - 1)]

    def __call__(self, argv, log_handle):
        index = len(self.calls)
        self.calls.append(list(argv))
        if self.error is not None:
            raise self.error
        log_text = self._nth(self.log_sequence, index, self.log_text)
        csv_text = self._nth(self.csv_sequence, index, self.csv_text)
        if log_text:
            log_handle.write(log_text.encode("utf-8"))
            log_handle.flush()
        if csv_text is not None and self.create_csv and "-o" in argv:
            out = Path(argv[argv.index("-o") + 1])
            out.parent.mkdir(parents=True, exist_ok=True)
            # Bytes, not text: the scanner's CRLF line endings are significant.
            out.write_bytes(csv_text.encode("utf-8"))
        return FakeProcess(self.returncode, stay_running=self.stay_running)


# --------------------------------------------------------------------------
# Realistic scanner payloads
# --------------------------------------------------------------------------

CSV_HEADER = "IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码"

CSV_TWO_ROWS = (
    "\ufeff" + CSV_HEADER + "\r\n"
    "104.16.0.1,4,4,0.00,438.32,0.00,N/A\r\n"
    "172.67.213.151,4,3,0.25,512.10,0.00,SJC\r\n"
)

CSV_VERIFY_PASS = (
    "\ufeff" + CSV_HEADER + "\r\n"
    "104.16.0.1,20,20,0.00,431.07,0.00,N/A\r\n"
)


def csv_with_rows(count, first_latency_ms=100.0):
    """A scanner CSV with ``count`` loss-free rows, the fastest one first.

    Ranks are distinct and ordered, so a test can tell which rows were shown
    (latency grows by 1 ms per row: 104.21.0.1 at 100.00 ms, and so on).
    """
    lines = ["\ufeff" + CSV_HEADER]
    for index in range(int(count)):
        ip = f"104.21.{index // 250}.{index % 250 + 1}"
        lines.append(f"{ip},4,4,0.00,{first_latency_ms + index:.2f},0.00,LOC")
    return "\r\n".join(lines) + "\r\n"


def csv_with_measurements(rows):
    """A scanner CSV from explicit ``(ip, sent, received, loss, latency, colo)``.

    Used for verification runs, where the numbers decide the PASS/FAIL verdict.
    """
    lines = ["\ufeff" + CSV_HEADER]
    for ip, sent, received, loss, latency, colo in rows:
        lines.append(f"{ip},{sent},{received},{loss:.2f},{latency:.2f},0.00,{colo}")
    return "\r\n".join(lines) + "\r\n"

LOG_LATENCY_START = (
    "# XIU2/CloudflareSpeedTest v2.3.5 \n"
    "\n"
    "开始延迟测速（模式：HTTP, 端口：2087, 范围：0 ~ 1000 ms, 丢包：0.25)\n"
)

LOG_PROGRESS = (
    "0 / 24 [___________________________________________________________________________________]"
    " 可用:   0 / 24 ["
)

LOG_SUCCESS = (
    "# XIU2/CloudflareSpeedTest v2.3.5 \n"
    "开始延迟测速（模式：HTTP, 端口：2087, 范围：0 ~ 1000 ms, 丢包：0.25)\n"
    "0 / 24 [______] 可用: 12 \n"
    "24 / 24 [------] 可用: 12 \n"
    "IP 地址           已发送  已接收  丢包率  平均延迟  下载速度(MB/s)  地区码  \n"
    "104.16.0.1     4       4       0.00    438.32    0.00            N/A     \n"
    "\n"
    "完整测速结果已写入 /tmp/out.csv 文件，可使用记事本/表格软件查看。\n"
)

LOG_NO_RESULTS = (
    "# XIU2/CloudflareSpeedTest v2.3.5 \n"
    "开始延迟测速（模式：HTTP, 端口：2087, 范围：0 ~ 1000 ms, 丢包：0.25)\n"
    "0 / 24 [______] 可用: 0 \n"
    "[信息] 完整测速结果 IP 数量为 0，跳过输出结果。\n"
)

LOG_STATUS_REJECT = (
    "开始延迟测速（模式：HTTP, 端口：2087, 范围：0 ~ 1000 ms, 丢包：0.25)\n"
    "[调试] IP: 104.16.0.1, 延迟测速终止，HTTP 状态码: 520, "
    "指定的 HTTP 状态码 400, 测速地址: https://node.example.test:2087/\n"
    "[信息] 完整测速结果 IP 数量为 0，跳过输出结果。\n"
)

# The scanner's own words when the port answered in plain HTTP although the test
# URL asked for HTTPS. Copied from a real run against a Cloudflare address.
LOG_HTTPS_ON_HTTP_PORT = (
    "# XIU2/CloudflareSpeedTest v2.3.5 \n"
    "开始延迟测速（模式：HTTP, 端口：8080, 范围：0 ~ 1000 ms, 丢包：1.00)\n"
    "0 / 1  可用:    IP: 104.24.28.30, 延迟测速失败，错误信息: "
    "Head \"https://node.example.test:8080/\": "
    "http: server gave HTTP response to HTTPS client, "
    "测速地址: https://node.example.test:8080/\n"
    "1 / 1  可用: 0  \n"
    " 完整测速结果 IP 数量为 0，跳过输出结果。\n"
)

# Cloudflare's own error page instead of the site: the edge has no healthy
# origin to forward to for that hostname.
LOG_ORIGIN_UNREACHABLE = (
    "0 / 1  可用:    IP: 104.24.28.30, 延迟测速终止，HTTP 状态码: 521, "
    "指定的 HTTP 状态码 400, 测速地址: https://node.example.test:443/\n"
    "1 / 1  可用: 0  \n"
)


# --------------------------------------------------------------------------
# Config helpers
# --------------------------------------------------------------------------

class Fixture:
    """A temporary, self-contained cfscan environment.

    Builds a throw-away home directory with its own configuration, results
    folder and IP range files, plus a console wired to scripted answers and a
    fake scanner process boundary.
    """

    def __init__(self, answers=(), spawn=None, dry_run=False, color=False,
                 cfst=None, config=None, tty=False, preflight=False,
                 assume_yes=False, pool_size=0):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.paths = make_paths(self.root)

        self.ipv4 = write_ip_ranges(self.root / "ranges" / "ip.txt")
        self.ipv6 = write_ip_ranges(self.root / "ranges" / "ipv6.txt")
        self.cfst = Path(cfst) if cfst else write_fake_cfst(self.root)

        loaded = load_config_file(self.paths, config)
        for profile in loaded["profiles"].values():
            profile["ip_file"] = str(self.ipv4)
            profile["ipv6_file"] = str(self.ipv6)
            # These tests are about scanning behaviour, and a scan refuses to
            # run against the shipped placeholder domain on purpose. Give the
            # fixture a target of its own; PlaceholderTests covers the refusal.
            if str(profile.get("domain") or "").lower() in ("example.com",):
                profile["domain"] = FIXTURE_DOMAIN
                profile["port"] = FIXTURE_PORT
                profile["recommended_ip"] = FIXTURE_RECOMMENDED_IP
        loaded["cfst_path"] = str(self.cfst)
        save_config_file(self.paths, loaded)
        self.config = load_config_file(self.paths)

        from cfscan.menu import Session

        self.console, self.out, self.scripted = make_console(answers, color=color,
                                                            is_tty=tty)
        self.spawn = spawn if spawn is not None else ScriptedSpawn()
        # The one-address preflight runs before a real scan; it is off by
        # default here so a flow test keeps the exact scanner conversation it
        # asserts on. PreflightBehaviourTests turns it back on.
        self.session = Session(
            paths=self.paths,
            console=self.console,
            spawn=self.spawn,
            dry_run=dry_run,
            preflight=preflight,
            assume_yes=assume_yes,
            pool_size=pool_size,
        )

    @property
    def text(self):
        return self.out.getvalue()

    def close(self):
        self.tmp.cleanup()

    def reload(self):
        self.config = load_config_file(self.paths)
        return self.config

    def save(self):
        """Persist in-memory changes, so reload() reflects them."""
        save_config_file(self.paths, self.config)
        return self.config

    def profile(self, name=None):
        from cfscan.profiles import get_active

        if name is None:
            return get_active(self.config)[1]
        return self.config["profiles"][name]


def load_config_file(paths, config=None):
    """Load a config, replacing it with provided content when given."""
    from cfscan.profiles import load_config as _load

    if config is not None:
        path = Path(paths.config_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return _load(paths)


def save_config_file(paths, config):
    from cfscan.profiles import save_config as _save

    _save(paths, config)


def write_config(paths, config):
    path = Path(paths.config_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return path


def read_config(paths):
    return json.loads(Path(paths.config_file).read_text(encoding="utf-8"))

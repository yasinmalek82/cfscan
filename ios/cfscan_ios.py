# -*- coding: utf-8 -*-
"""CF Scanner for iPhone - finds a clean Cloudflare address per carrier.

Runs inside Pythonista 3 on the iPhone. With the VPN off and the phone on one
carrier (MCI, Irancell, home Wi-Fi, ...), one tap:

1. re-checks the address the carrier's DNS record points at now,
2. if it is broken, scans Cloudflare addresses on this very connection
   (known-good ones and their /24 neighbours first, then random ones),
3. re-measures the fastest few with several attempts each (latency, jitter,
   loss, and a real WebSocket upgrade on the config's path when one is set),
4. points the carrier's DNS-only record (``mci.example.com``) at the winner
   through the Cloudflare API.

Every carrier has its own record, and the panel's hosts use those records as
their address, so the panel itself never has to be touched.

Secrets: the Cloudflare API token lives in the iOS Keychain, never in the
data file. Everything else (settings, carrier state, history) is kept in
``cfscan_ios_data.json`` next to this script. ``cfscan_ios_log.txt`` holds a
step log for bug reports; it never contains the token.

The network, Cloudflare and scan code does not import any Pythonista module,
so it is unit tested on a computer (``tests/test_ios_app.py``).
"""

from __future__ import annotations

import base64
import copy
import faulthandler
import http.client
import ipaddress
import json
import os
import random
import socket
import ssl
import statistics
import threading
import time
import urllib.parse

try:  # Pythonista only; everything below the UI marker needs these.
    import ui
    import console
    import dialogs
    import clipboard
except ImportError:
    ui = console = dialogs = clipboard = None

try:
    from objc_util import on_main_thread
except ImportError:
    def on_main_thread(fn):
        return fn

APP_NAME = "CF Scanner"
APP_VERSION = "1.0"

try:
    _HERE = os.path.dirname(os.path.abspath(__file__))
except NameError:
    _HERE = os.getcwd()
DATA_PATH = os.path.join(_HERE, "cfscan_ios_data.json")
LOG_PATH = os.path.join(_HERE, "cfscan_ios_log.txt")
LOG_LIMIT_BYTES = 256 * 1024

KEYCHAIN_SERVICE = "cfscan_ios"
KEYCHAIN_ACCOUNT = "cloudflare_api_token"

USER_AGENT = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
              "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 "
              "Safari/604.1")

#: Cloudflare's published ranges (https://www.cloudflare.com/ips/). The app
#: can refresh them from the API; these are the fallback.
CF_RANGES_V4 = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
)
CF_RANGES_V6 = (
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)

DEFAULT_SETTINGS = {
    "sni": "",              # CDN domain (orange cloud): SNI and Host header
    "path": "",             # WebSocket path of the config; empty = trace test only
    "port": 443,
    "tls": True,
    "zone_id": "",          # optional; looked up from the record name when empty
    "ttl": 60,
    "ips_per_record": 1,
    "auto_apply": True,
    "candidates": 500,
    "workers": 32,
    "timeout": 2.0,
    "stop_after": 25,       # stop the fast pass after this many answers (0 = all)
    "verify_top": 6,
    "verify_attempts": 8,
    "max_loss_pct": 0,
    "max_ping_ms": 800,
    "colos": "",            # allowed datacentres, e.g. "FRA,AMS"; empty = any
    "ip_version": 4,
    "bad_ttl_hours": 6,
}

#: (minimum, maximum) for every numeric setting.
SETTING_LIMITS = {
    "port": (1, 65535), "ttl": (60, 86400), "ips_per_record": (1, 3),
    "candidates": (20, 5000), "workers": (1, 128), "timeout": (0.5, 10.0),
    "stop_after": (0, 1000), "verify_top": (1, 20), "verify_attempts": (2, 30),
    "max_loss_pct": (0, 50), "max_ping_ms": (50, 5000), "ip_version": (4, 6),
    "bad_ttl_hours": (0, 168),
}

DEFAULT_PROFILES = [
    {"id": "mci", "name": "همراه اول", "record": ""},
    {"id": "mtn", "name": "ایرانسل", "record": ""},
    {"id": "home", "name": "اینترنت خانگی", "record": ""},
]

HISTORY_LIMIT = 300
GOOD_LIMIT = 200
BAD_LIMIT = 5000


# ---------------------------------------------------------------- logging

_log_lock = threading.Lock()


def log(message):
    """Append one line to the log file; it survives a crash."""
    line = "%s [%s] %s\n" % (time.strftime("%m-%d %H:%M:%S"),
                             threading.current_thread().name, message)
    with _log_lock:
        try:
            if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > LOG_LIMIT_BYTES:
                with open(LOG_PATH, "rb") as fh:
                    fh.seek(-LOG_LIMIT_BYTES // 2, os.SEEK_END)
                    tail = fh.read()
                with open(LOG_PATH, "wb") as fh:
                    fh.write(tail)
            with open(LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError:
            pass


def enable_crash_trace():
    try:
        faulthandler.enable(file=open(LOG_PATH, "a", encoding="utf-8"), all_threads=True)
    except Exception as exc:
        log("faulthandler unavailable: %r" % (exc,))


def read_log_tail(lines=60):
    try:
        with open(LOG_PATH, encoding="utf-8", errors="replace") as fh:
            return "".join(fh.readlines()[-lines:])
    except OSError:
        return ""


# ---------------------------------------------------------------- storage

def _coerce(key, value):
    """``value`` as the type of the default for ``key``, clamped to its limits."""
    default = DEFAULT_SETTINGS[key]
    if isinstance(default, bool):
        if isinstance(value, str):
            return value.strip().lower() in ("1", "true", "yes", "on")
        return bool(value)
    if isinstance(default, (int, float)):
        number = float(str(value).strip())
        low, high = SETTING_LIMITS.get(key, (None, None))
        if low is not None and number < low:
            raise ValueError("%s must be at least %s" % (key, low))
        if high is not None and number > high:
            raise ValueError("%s must be at most %s" % (key, high))
        if key == "ip_version" and int(number) not in (4, 6):
            raise ValueError("ip_version must be 4 or 6")
        return int(number) if isinstance(default, int) else number
    return str(value).strip()


def normalise_data(raw):
    """A complete data document built from whatever was stored."""
    raw = raw if isinstance(raw, dict) else {}
    settings = dict(DEFAULT_SETTINGS)
    for key, value in (raw.get("settings") or {}).items():
        if key in DEFAULT_SETTINGS:
            try:
                settings[key] = _coerce(key, value)
            except (TypeError, ValueError):
                pass
    profiles = []
    seen = set()
    for p in raw.get("profiles") or copy.deepcopy(DEFAULT_PROFILES):
        if not isinstance(p, dict) or not p.get("id") or p["id"] in seen:
            continue
        seen.add(p["id"])
        profiles.append({"id": str(p["id"]), "name": str(p.get("name") or p["id"]),
                         "record": normalise_host(p.get("record") or "")})
    state = raw.get("state") if isinstance(raw.get("state"), dict) else {}
    history = [h for h in (raw.get("history") or []) if isinstance(h, dict)]
    return {
        "version": 1,
        "settings": settings,
        "profiles": profiles,
        "state": state,
        "history": history[-HISTORY_LIMIT:],
        "zones": raw.get("zones") if isinstance(raw.get("zones"), dict) else {},
        "ranges": raw.get("ranges") if isinstance(raw.get("ranges"), dict) else {},
    }


def normalise_host(value):
    return str(value or "").strip().strip(".").lower()


def normalise_path(value):
    path = str(value or "").strip()
    if path and not path.startswith("/"):
        path = "/" + path
    return path


class Secrets:
    """The Cloudflare token: iOS Keychain in Pythonista, memory elsewhere."""

    def __init__(self):
        self._memory = ""
        try:
            import keychain
        except ImportError:
            keychain = None
        self._keychain = keychain

    def get(self):
        if self._keychain is None:
            return self._memory
        return self._keychain.get_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT) or ""

    def set(self, token):
        token = (token or "").strip()
        if self._keychain is None:
            self._memory = token
        elif token:
            self._keychain.set_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, token)
        else:
            try:
                self._keychain.delete_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
            except Exception:
                pass


class Store:
    """Settings, carriers, per-carrier state and history in one JSON file."""

    def __init__(self, path=DATA_PATH, secrets=None):
        self.path = path
        self.secrets = secrets or Secrets()
        self.lock = threading.RLock()
        try:
            with open(path, encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, ValueError):
            raw = {}
        self.data = normalise_data(raw)

    def save(self):
        with self.lock:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, self.path)

    @property
    def settings(self):
        return self.data["settings"]

    @property
    def profiles(self):
        return self.data["profiles"]

    def profile(self, pid):
        for p in self.profiles:
            if p["id"] == pid:
                return p
        raise KeyError(pid)

    def state(self, pid):
        with self.lock:
            st = self.data["state"].setdefault(pid, {})
            st.setdefault("current", [])
            st.setdefault("status", "unknown")
            st.setdefault("good", {})
            st.setdefault("bad", {})
            return st

    def update_settings(self, values):
        """Validate every value first, so a bad one changes nothing."""
        clean = {key: _coerce(key, value) for key, value in values.items()
                 if key in DEFAULT_SETTINGS}
        with self.lock:
            self.settings.update(clean)
            self.save()

    def add_profile(self, name, record):
        with self.lock:
            base = "p%d" % int(time.time())
            pid, n = base, 1
            ids = {p["id"] for p in self.profiles}
            while pid in ids:
                n += 1
                pid = "%s_%d" % (base, n)
            self.profiles.append({"id": pid, "name": name.strip() or pid,
                                  "record": normalise_host(record)})
            self.save()
            return pid

    def edit_profile(self, pid, name, record):
        with self.lock:
            p = self.profile(pid)
            p["name"] = name.strip() or p["name"]
            new_record = normalise_host(record)
            if new_record != p["record"]:
                p["record"] = new_record
                self.state(pid)["current"] = []
                self.state(pid)["status"] = "unknown"
            self.save()

    def delete_profile(self, pid):
        with self.lock:
            self.data["profiles"] = [p for p in self.profiles if p["id"] != pid]
            self.data["state"].pop(pid, None)
            self.save()

    def add_history(self, pid, kind, old=(), new=(), note=""):
        with self.lock:
            self.data["history"].append({"ts": time.time(), "profile": pid, "kind": kind,
                                         "old": list(old), "new": list(new), "note": note})
            del self.data["history"][:-HISTORY_LIMIT]

    def history(self, pid=None):
        items = self.data["history"]
        if pid:
            items = [h for h in items if h.get("profile") == pid]
        return list(reversed(items))

    def previous_ips(self, pid):
        """The addresses the record had before its last change, if any."""
        for h in self.history(pid):
            if h.get("kind") in ("apply", "manual", "rollback") and h.get("old"):
                return list(h["old"])
        return []

    def remember_good(self, pid, ip, ping, colo):
        with self.lock:
            st = self.state(pid)
            st["good"][ip] = {"ts": time.time(), "ping": ping, "colo": colo}
            st["bad"].pop(ip, None)
            if len(st["good"]) > GOOD_LIMIT:
                keep = sorted(st["good"].items(), key=lambda kv: -kv[1].get("ts", 0))
                st["good"] = dict(keep[:GOOD_LIMIT])

    def remember_bad(self, pid, ips, forget_good=False):
        with self.lock:
            st = self.state(pid)
            now = time.time()
            for ip in ips:
                st["bad"][ip] = now
                if forget_good:
                    st["good"].pop(ip, None)
            if len(st["bad"]) > BAD_LIMIT:
                keep = sorted(st["bad"].items(), key=lambda kv: -kv[1])
                st["bad"] = dict(keep[:BAD_LIMIT])

    def clear_bad(self):
        with self.lock:
            for st in self.data["state"].values():
                st["bad"] = {}
            self.save()

    def zone_for(self, record):
        return self.data["zones"].get(record, "")

    def remember_zone(self, record, zone):
        with self.lock:
            self.data["zones"][record] = zone

    def ranges(self, version):
        stored = self.data["ranges"].get("v6" if version == 6 else "v4")
        if stored:
            return list(stored)
        return list(CF_RANGES_V6 if version == 6 else CF_RANGES_V4)

    def export_json(self):
        """Settings and carriers as JSON, without the token or history."""
        return json.dumps({"app": "cfscan_ios", "settings": self.settings,
                           "profiles": self.profiles}, ensure_ascii=False, indent=1)

    def import_json(self, text):
        raw = json.loads(text)
        if not isinstance(raw, dict) or raw.get("app") != "cfscan_ios":
            raise ValueError("not a CF Scanner export")
        merged = normalise_data({"settings": raw.get("settings"),
                                 "profiles": raw.get("profiles")})
        with self.lock:
            self.data["settings"] = merged["settings"]
            self.data["profiles"] = merged["profiles"]
            self.save()


# ---------------------------------------------------------------- probes

class Target:
    """What a probe connects as: the config's SNI/Host, path, port and TLS."""

    def __init__(self, sni, path="", port=443, tls=True):
        self.sni = normalise_host(sni)
        self.path = normalise_path(path)
        self.port = int(port)
        self.tls = bool(tls)

    @classmethod
    def from_settings(cls, s):
        return cls(s["sni"], s["path"], s["port"], s["tls"])


def make_context():
    ctx = ssl.create_default_context()
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except (NotImplementedError, AttributeError):
        pass
    return ctx


def describe_error(exc):
    if isinstance(exc, socket.timeout):
        return "timeout"
    if isinstance(exc, ssl.SSLError):
        return "TLS " + (getattr(exc, "reason", None) or exc.__class__.__name__)
    if isinstance(exc, ConnectionResetError):
        return "reset"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, OSError):
        return exc.strerror or exc.__class__.__name__
    return exc.__class__.__name__


def _connect(ip, target, ctx, timeout):
    """An open (TLS) socket to ``ip``, its start time and the TCP time in ms."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    raw = socket.socket(family, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    start = time.perf_counter()
    try:
        raw.connect((ip, target.port))
    except BaseException:
        raw.close()
        raise
    tcp_ms = (time.perf_counter() - start) * 1000
    if not target.tls:
        return raw, start, tcp_ms
    try:
        return ctx.wrap_socket(raw, server_hostname=target.sni), start, tcp_ms
    except BaseException:
        raw.close()
        raise


def _read(sock, until_head=False, limit=16384):
    data = b""
    while len(data) < limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if until_head and b"\r\n\r\n" in data:
            break
    return data


def parse_status(data):
    parts = data.split(b"\r\n", 1)[0].decode("latin-1").split()
    if len(parts) >= 2 and parts[0].startswith("HTTP/") and parts[1].isdigit():
        return int(parts[1])
    return None


def parse_trace(data):
    text = data.decode("utf-8", "replace")
    body = text.split("\r\n\r\n", 1)[-1]
    out = {}
    for line in body.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            out[key.strip()] = value.strip()
    return out


def _blank_result(ip):
    return {"ip": ip, "ok": False, "tcp": None, "total": None, "status": None,
            "colo": "", "loc": "", "client": "", "error": ""}


def trace_probe(ip, target, ctx, timeout):
    """``GET /cdn-cgi/trace`` through ``ip`` as the CDN domain.

    A 200 with a ``colo=`` line means Cloudflare answered for our hostname on
    this address from this connection.
    """
    r = _blank_result(ip)
    sock = None
    try:
        sock, start, r["tcp"] = _connect(ip, target, ctx, timeout)
        request = ("GET /cdn-cgi/trace HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
                   "Accept: */*\r\nConnection: close\r\n\r\n" % (target.sni, USER_AGENT))
        sock.sendall(request.encode("ascii"))
        data = _read(sock)
        r["total"] = (time.perf_counter() - start) * 1000
        r["status"] = parse_status(data)
        info = parse_trace(data)
        r["colo"], r["loc"], r["client"] = info.get("colo", ""), info.get("loc", ""), info.get("ip", "")
        r["ok"] = r["status"] == 200 and bool(r["colo"])
        if not r["ok"]:
            r["error"] = "HTTP %s" % r["status"] if r["status"] else "empty answer"
    except Exception as exc:
        r["error"] = describe_error(exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return r


def ws_probe(ip, target, ctx, timeout):
    """A WebSocket upgrade on the config's path; ``101`` means the whole
    chain (Cloudflare, the server and Xray) answered."""
    r = _blank_result(ip)
    sock = None
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    try:
        sock, start, r["tcp"] = _connect(ip, target, ctx, timeout)
        request = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
                   "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                   "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n"
                   % (target.path or "/", target.sni, USER_AGENT, key))
        sock.sendall(request.encode("ascii"))
        data = _read(sock, until_head=True)
        r["total"] = (time.perf_counter() - start) * 1000
        r["status"] = parse_status(data)
        r["ok"] = r["status"] == 101
        if not r["ok"]:
            r["error"] = "HTTP %s" % r["status"] if r["status"] else "empty answer"
    except Exception as exc:
        r["error"] = describe_error(exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return r


def successive_jitter_ms(samples):
    """Mean absolute gap between consecutive samples (as in cfscan.measure)."""
    if not samples or len(samples) < 2:
        return None
    gaps = [abs(samples[i] - samples[i - 1]) for i in range(1, len(samples))]
    return sum(gaps) / len(gaps)


def measure(ip, target, ctx, attempts, timeout, use_ws, cancel=None, pause=0.15,
            probe_trace=trace_probe, probe_ws=ws_probe):
    """``attempts`` sequential probes of one address, summarised."""
    tcp, total, errors = [], [], []
    colo = ""
    for i in range(int(attempts)):
        if cancel is not None and cancel.is_set():
            break
        r = (probe_ws if use_ws else probe_trace)(ip, target, ctx, timeout)
        if r["ok"]:
            tcp.append(r["tcp"])
            total.append(r["total"])
            colo = r.get("colo") or colo
        else:
            errors.append(r["error"])
        if pause and i < attempts - 1:
            time.sleep(pause)
    done = len(tcp) + len(errors)
    return {
        "ip": ip, "attempts": done, "ok": len(tcp),
        "loss": 100.0 * len(errors) / done if done else 100.0,
        "ping": statistics.median(tcp) if tcp else None,
        "total": statistics.median(total) if total else None,
        "jitter": successive_jitter_ms(tcp),
        "colo": colo, "errors": errors,
    }


def score(m):
    """Lower is better: response time, twice the jitter, heavy loss penalty."""
    if m.get("total") is None:
        return float("inf")
    return m["total"] + 2 * (m.get("jitter") or 0) + 50 * m.get("loss", 100)


def is_healthy(m, max_loss, max_ping):
    return (m.get("ok", 0) > 0 and m.get("loss", 100) <= max_loss
            and m.get("ping") is not None and m["ping"] <= max_ping)


def parse_colos(text):
    return {c.strip().upper() for c in str(text or "").replace(" ", ",").split(",") if c.strip()}


def error_summary(errors, top=3):
    counts = {}
    for e in errors:
        counts[e] = counts.get(e, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: -kv[1])[:top]
    return ", ".join("%s x%d" % (e, n) for e, n in ranked)


# ---------------------------------------------------------------- candidates

def random_address(net, rng):
    if net.version == 4:
        for _ in range(64):
            addr = net.network_address + rng.randrange(1, max(2, net.num_addresses - 1))
            if int(addr) & 0xFF not in (0, 255):
                return str(addr)
        return str(net.network_address + 1)
    return str(net.network_address + rng.randrange(1, net.num_addresses - 1))


def neighbours(ip, rng, count):
    """Other addresses in the same /24 (IPv4) or /120 (IPv6) as ``ip``."""
    prefix = 24 if ":" not in ip else 120
    net = ipaddress.ip_network("%s/%d" % (ip, prefix), strict=False)
    picks, tries = [], 0
    while len(picks) < count and tries < count * 6:
        tries += 1
        addr = random_address(net, rng)
        if addr != ip and addr not in picks:
            picks.append(addr)
    return picks


def build_candidates(state, count, version, ranges, rng=random, now=None,
                     bad_ttl_s=6 * 3600, exclude=()):
    """The scan order: known-good, their neighbours, then random addresses.

    Addresses that failed on this carrier within ``bad_ttl_s`` are skipped.
    """
    now = time.time() if now is None else now
    bad = {ip for ip, ts in (state.get("bad") or {}).items() if now - ts < bad_ttl_s}
    seen = set(exclude) | bad
    out = []

    def add(ip):
        if ip in seen or ((":" in ip) != (version == 6)):
            return
        seen.add(ip)
        out.append(ip)

    good = sorted((state.get("good") or {}).items(), key=lambda kv: -kv[1].get("ts", 0))
    good = [ip for ip, _ in good if ip not in seen]  # not excluded, not failed lately
    for ip in good:
        add(ip)
    for ip in good[:20]:
        for n in neighbours(ip, rng, 8):
            add(n)
    nets = [ipaddress.ip_network(r) for r in ranges]
    nets = [n for n in nets if n.version == version]
    if nets:
        weights = [n.num_addresses if version == 4 else 1 for n in nets]
        tries = 0
        while len(out) < count and tries < count * 20:
            tries += 1
            add(random_address(rng.choices(nets, weights)[0], rng))
    return out[:count]


# ---------------------------------------------------------------- Cloudflare API

class CFError(Exception):
    """Cloudflare answered, and refused (bad token, missing zone, ...)."""


class NetError(Exception):
    """Cloudflare could not be reached at all."""


class _PinnedHTTPS(http.client.HTTPSConnection):
    """HTTPS to ``host`` that connects to ``ip`` when one is given."""

    def __init__(self, host, ip, timeout, context):
        super().__init__(host, 443, timeout=timeout, context=context)
        self._pinned_ip = ip

    def connect(self):
        sock = socket.create_connection((self._pinned_ip or self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def plan_sync(existing, ips):
    """The record changes that leave exactly ``ips`` on a name.

    ``existing`` are Cloudflare records (``id``, ``content``). Records already
    holding a wanted address stay; the others are rewritten before anything
    is deleted, so the name never has no address in between.
    """
    want = list(dict.fromkeys(ips))
    have = {r.get("content") for r in existing}
    missing = [ip for ip in want if ip not in have]
    updates, deletes, seen = [], [], set()
    for r in existing:
        content = r.get("content")
        if content in want and content not in seen:
            seen.add(content)
        elif missing:
            updates.append(("update", r["id"], missing.pop(0)))
        else:
            deletes.append(("delete", r["id"], content))
    creates = [("create", None, ip) for ip in missing]
    return updates + creates + deletes


class CloudflareAPI:
    HOST = "api.cloudflare.com"
    BASE = "/client/v4"

    def __init__(self, token="", via_ip=None, timeout=15, context=None):
        self.token = token
        self.via_ip = via_ip
        self.timeout = timeout
        self.context = context or ssl.create_default_context()

    def call(self, method, path, query=None, body=None):
        url = self.BASE + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        payload = None
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        conn = _PinnedHTTPS(self.HOST, self.via_ip, self.timeout, self.context)
        try:
            conn.request(method, url, body=payload, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            status = resp.status
        except (OSError, http.client.HTTPException) as exc:
            raise NetError(describe_error(exc))
        finally:
            conn.close()
        try:
            data = json.loads(raw.decode("utf-8"))
        except ValueError:
            raise CFError("HTTP %s from Cloudflare" % status)
        if not data.get("success"):
            messages = "; ".join(str(e.get("message", "")) for e in data.get("errors") or [])
            raise CFError(messages or "HTTP %s" % status)
        return data.get("result")

    def verify_token(self):
        return self.call("GET", "/user/tokens/verify")

    def public_ranges(self):
        result = self.call("GET", "/ips")
        return list(result.get("ipv4_cidrs") or []), list(result.get("ipv6_cidrs") or [])

    def find_zone(self, record):
        labels = normalise_host(record).split(".")
        for i in range(len(labels) - 1):
            name = ".".join(labels[i:])
            result = self.call("GET", "/zones", {"name": name})
            if result:
                return result[0]["id"]
        raise CFError("zone for %s not found (token needs Zone:Read, or set the Zone ID)" % record)

    def list_records(self, zone, name, rtype):
        return self.call("GET", "/zones/%s/dns_records" % zone,
                         {"type": rtype, "name": name, "per_page": 100}) or []

    def sync_records(self, zone, name, ips, rtype, ttl):
        existing = self.list_records(zone, name, rtype)
        ops = plan_sync(existing, ips)
        for kind, rid, ip in ops:
            if kind == "update":
                self.call("PATCH", "/zones/%s/dns_records/%s" % (zone, rid),
                          body={"content": ip, "ttl": ttl, "proxied": False})
            elif kind == "create":
                self.call("POST", "/zones/%s/dns_records" % zone,
                          body={"type": rtype, "name": name, "content": ip,
                                "ttl": ttl, "proxied": False})
            else:
                self.call("DELETE", "/zones/%s/dns_records/%s" % (zone, rid))
        other = "A" if rtype == "AAAA" else "AAAA"
        for r in self.list_records(zone, name, other):
            self.call("DELETE", "/zones/%s/dns_records/%s" % (zone, r["id"]))
            ops.append(("delete", r["id"], r.get("content")))
        return ops


def _api_attempts(store, via_ips, api_factory):
    """API clients to try: direct first, then through up to three clean IPs."""
    token = store.secrets.get()
    if not token:
        raise CFError("توکن کلادفلر در تنظیمات وارد نشده")
    yield api_factory(token)
    for ip in list(via_ips)[:3]:
        yield api_factory(token, via_ip=ip)


def with_api(store, via_ips, fn, api_factory=CloudflareAPI):
    """``fn(api)`` directly, or through a clean address if the API is blocked."""
    last = None
    for api in _api_attempts(store, via_ips, api_factory):
        try:
            return fn(api), api.via_ip
        except NetError as exc:
            last = exc
            log("api unreachable via %s: %s" % (api.via_ip or "direct", exc))
    raise last or NetError("unreachable")


def _zone(store, api, record):
    zone = store.settings["zone_id"].strip() or store.zone_for(record)
    if not zone:
        zone = api.find_zone(record)
        store.remember_zone(record, zone)
    return zone


def read_record_ips(store, profile, rtype, via_ips=(), api_factory=CloudflareAPI):
    record = profile["record"]

    def fn(api):
        return [r["content"] for r in api.list_records(_zone(store, api, record), record, rtype)]

    return with_api(store, via_ips, fn, api_factory)[0]


def apply_ips(store, pid, ips, via_ips=(), kind="apply", note="", api_factory=CloudflareAPI):
    """Point the carrier's record at ``ips``; returns the ops and the route."""
    profile = store.profile(pid)
    record = profile["record"]
    if not record:
        raise CFError("زیردامنهٔ این اپراتور تنظیم نشده")
    if not ips:
        raise CFError("هیچ IP برای اعمال نیست")
    rtype = "AAAA" if ":" in ips[0] else "A"
    ttl = int(store.settings["ttl"])

    def fn(api):
        return api.sync_records(_zone(store, api, record), record, ips, rtype, ttl)

    ops, via = with_api(store, via_ips, fn, api_factory)
    with store.lock:
        st = store.state(pid)
        old = list(st.get("current") or [])
        st["current"] = list(ips)
        st["status"] = "ok"
        st["checked_at"] = time.time()
        store.add_history(pid, kind, old, ips, note or ("via %s" % via if via else ""))
        store.save()
    log("applied %s -> %s (%s)" % (record, ips, kind))
    return ops, via


# ---------------------------------------------------------------- scan engine

STEP_TITLES = ("بررسی IP فعلی", "اسکن کاندیدها", "تأیید دقیق", "به‌روزرسانی DNS")


class Events:
    """What the scan reports; the screen overrides these."""

    def step(self, index, status, detail=""):
        pass

    def progress(self, done, total, found):
        pass

    def found(self, rows):
        pass

    def note(self, text):
        pass

    def finished(self, result):
        pass


class UserError(Exception):
    pass


class ScanJob:
    """One carrier's check -> scan -> verify -> apply run.

    ``mode``: ``auto`` scans only when the current address is broken,
    ``force`` scans anyway, ``check`` only re-checks the current address.
    """

    def __init__(self, store, pid, events=None, mode="auto", context_factory=make_context,
                 api_factory=CloudflareAPI, candidates=None, rng=None,
                 probe_trace=trace_probe, probe_ws=ws_probe):
        self.store = store
        self.pid = pid
        self.events = events or Events()
        self.mode = mode
        self.context_factory = context_factory
        self.api_factory = api_factory
        self.fixed_candidates = candidates
        self.rng = rng or random.Random()
        self.probe_trace = probe_trace
        self.probe_ws = probe_ws
        self.cancel_event = threading.Event()
        self.result = None
        self.running = False

    def cancel(self):
        self.cancel_event.set()

    @property
    def cancelled(self):
        return self.cancel_event.is_set()

    def run(self):
        self.running = True
        log("job start %s mode=%s" % (self.pid, self.mode))
        try:
            result = self._run()
        except (UserError, CFError, NetError) as exc:
            result = {"kind": "error", "message": str(exc)}
        except Exception as exc:
            log("job crashed: %r" % (exc,))
            result = {"kind": "error", "message": "%s: %s" % (exc.__class__.__name__, exc)}
        result.setdefault("profile", self.pid)
        self.result = result
        self.running = False
        log("job end %s: %s" % (self.pid, result.get("kind")))
        self.events.finished(result)
        return result

    # -- the steps -------------------------------------------------------

    def _run(self):
        s = self.store.settings
        profile = self.store.profile(self.pid)
        target = Target.from_settings(s)
        if not target.sni:
            raise UserError("دامنهٔ CDN در تنظیمات خالی است")
        version = int(s["ip_version"])
        rtype = "AAAA" if version == 6 else "A"
        ctx = self.context_factory()
        use_ws = bool(target.path)
        started = time.time()
        result = {"kind": None, "profile": self.pid, "current": [], "current_measure": [],
                  "verified": [], "chosen": [], "warning": "", "scanned": 0,
                  "answered": 0, "errors": "", "record": profile["record"]}

        # 1. the address the record has now
        self.events.step(0, "run")
        current = []
        if profile["record"] and self.store.secrets.get():
            try:
                current = read_record_ips(self.store, profile, rtype,
                                          api_factory=self.api_factory)
            except (CFError, NetError) as exc:
                self.events.note("خواندن رکورد از کلادفلر نشد: %s" % exc)
                current = list(self.store.state(self.pid).get("current") or [])
        else:
            current = list(self.store.state(self.pid).get("current") or [])
        current = [ip for ip in current if (":" in ip) == (version == 6)]
        result["current"] = current
        healthy = None
        if current:
            attempts = max(4, int(s["verify_attempts"]) // 2)
            ms = self._measure_many(current, target, ctx, attempts, use_ws)
            result["current_measure"] = ms
            healthy = all(is_healthy(m, s["max_loss_pct"], s["max_ping_ms"]) for m in ms)
            first = ms[0]
            with self.store.lock:
                st = self.store.state(self.pid)
                st.update(current=current, status="ok" if healthy else "bad",
                          checked_at=time.time(), ping=first["ping"],
                          detail=self._measure_text(first))
                if not healthy:
                    dead = [m["ip"] for m in ms if m["ok"] == 0]
                    self.store.remember_bad(self.pid, dead, forget_good=True)
                self.store.save()
            self.events.step(0, "ok" if healthy else "fail",
                             "  ".join(self._measure_text(m) for m in ms))
        else:
            self.events.step(0, "skip", "هنوز IP ثبت نشده")
        if self.cancelled:
            return self._stopped(result)
        if self.mode == "check" or (healthy and self.mode == "auto"):
            for i in (1, 2, 3):
                self.events.step(i, "skip")
            result["kind"] = "healthy" if healthy else ("broken" if healthy is False else "unknown")
            self.store.add_history(self.pid, "check", current, current,
                                   "سالم" if healthy else "خراب")
            self.store.save()
            return result

        # 2. fast pass over the candidates
        self.events.step(1, "run")
        st = self.store.state(self.pid)
        if self.fixed_candidates is not None:
            cands = list(self.fixed_candidates)
        else:
            cands = build_candidates(st, int(s["candidates"]), version,
                                     self.store.ranges(version), rng=self.rng,
                                     bad_ttl_s=float(s["bad_ttl_hours"]) * 3600,
                                     exclude=current)
        answered, scanned, failed, errors = self._fast_pass(cands, target, ctx, s)
        result["scanned"], result["answered"] = scanned, len(answered)
        result["errors"] = error_summary(errors)
        locs = {r["loc"] for r in answered if r.get("loc")}
        if locs and "IR" not in locs:
            result["warning"] = ("به نظر VPN روشن است (موقعیت: %s). نتیجه مال این اینترنت نیست."
                                 % ", ".join(sorted(locs)))
            self.events.note(result["warning"])
        if answered:
            self.store.remember_bad(self.pid, failed)
            self.store.save()
        if self.cancelled:
            return self._stopped(result)
        if not answered:
            self.events.step(1, "fail", "هیچ IP پاسخ نداد (%s)" % result["errors"])
            result["kind"] = "nothing"
            result["hint"] = self._hint(errors, version)
            return result
        self.events.step(1, "ok", "%d از %d پاسخ داد" % (len(answered), scanned))

        # 3. careful re-measure of the fastest few
        self.events.step(2, "run")
        top = sorted(answered, key=lambda r: r["total"])[:int(s["verify_top"])]
        colo_of = {r["ip"]: r["colo"] for r in top}
        ms = self._measure_many([r["ip"] for r in top], target, ctx,
                                int(s["verify_attempts"]), use_ws)
        for m in ms:
            m["colo"] = m["colo"] or colo_of.get(m["ip"], "")
        ms.sort(key=score)
        result["verified"] = ms
        self.events.found(ms)
        passing = [m for m in ms if m["ok"] > 0 and m["loss"] <= s["max_loss_pct"]]
        for m in passing:
            self.store.remember_good(self.pid, m["ip"], m["ping"], m["colo"])
        self.store.save()
        if self.cancelled:
            return self._stopped(result)
        if not passing:
            errs = [e for m in ms for e in m["errors"]]
            self.events.step(2, "fail", "هیچ IP از تأیید رد نشد (%s)" % error_summary(errs))
            result["kind"] = "nothing"
            result["hint"] = self._hint(errs, version, verify=True, use_ws=use_ws)
            return result
        best = passing[0]
        self.events.step(2, "ok", "بهترین: %s  %s" % (best["ip"], self._measure_text(best)))

        # 4. the DNS record
        chosen = [m["ip"] for m in passing[:int(s["ips_per_record"])]]
        result["chosen"] = chosen
        result["via"] = [m["ip"] for m in passing]
        result["elapsed"] = time.time() - started
        if current and sorted(current) == sorted(chosen):
            self.events.step(3, "ok", "رکورد همین IP را دارد")
            result["kind"] = "unchanged"
        elif not profile["record"] or not self.store.secrets.get():
            self.events.step(3, "skip", "زیردامنه یا توکن تنظیم نشده")
            result["kind"] = "found"
        elif not s["auto_apply"]:
            self.events.step(3, "wait", "منتظر تأیید شما")
            result["kind"] = "pending"
        else:
            self.apply(chosen, result)
        return result

    def apply(self, ips, result=None, kind="apply"):
        """Change the record; used by the job and by the screen's buttons."""
        result = result if result is not None else (self.result or {})
        self.events.step(3, "run")
        try:
            ops, via = apply_ips(self.store, self.pid, ips, result.get("via") or [],
                                 kind=kind, api_factory=self.api_factory)
        except (CFError, NetError) as exc:
            self.events.step(3, "fail", str(exc))
            result["kind"] = "apply_failed"
            result["message"] = str(exc)
            return False
        record = self.store.profile(self.pid)["record"]
        detail = "%s → %s" % (record, ", ".join(ips))
        if via:
            detail += "  (API از طریق %s)" % via
        self.events.step(3, "ok", detail)
        result["kind"] = "applied"
        result["chosen"] = list(ips)
        return True

    # -- helpers ---------------------------------------------------------

    def _fast_pass(self, cands, target, ctx, s):
        queue = list(cands)
        total = len(queue)
        lock = threading.Lock()
        answered, failed, errors = [], [], []
        counters = {"done": 0, "last_emit": 0.0}
        colos = parse_colos(s["colos"])
        stop_after = int(s["stop_after"])
        timeout = float(s["timeout"])

        def worker():
            while not self.cancelled:
                with lock:
                    if not queue or (stop_after and len(answered) >= stop_after):
                        return
                    ip = queue.pop(0)
                r = self.probe_trace(ip, target, ctx, timeout)
                with lock:
                    counters["done"] += 1
                    if r["ok"] and (not colos or r["colo"] in colos):
                        answered.append(r)
                        top = sorted(answered, key=lambda x: x["total"])[:8]
                    else:
                        top = None
                        if not r["ok"]:
                            failed.append(ip)
                            errors.append(r["error"])
                    done, found = counters["done"], len(answered)
                    now = time.time()
                    emit = top is not None or done == total or now - counters["last_emit"] > 0.15
                    if emit:
                        counters["last_emit"] = now
                if emit:
                    self.events.progress(done, total, found)
                if top is not None:
                    self.events.found(top)

        workers = max(1, min(int(s["workers"]), total or 1))
        threads = [threading.Thread(target=worker, name="scan-%d" % i, daemon=True)
                   for i in range(workers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.events.progress(counters["done"], total, len(answered))
        return answered, counters["done"], failed, errors

    def _measure_many(self, ips, target, ctx, attempts, use_ws):
        out = [None] * len(ips)
        timeout = float(self.store.settings["timeout"]) + 1.0

        def one(i, ip):
            out[i] = measure(ip, target, ctx, attempts, timeout, use_ws,
                             cancel=self.cancel_event, probe_trace=self.probe_trace,
                             probe_ws=self.probe_ws)

        threads = [threading.Thread(target=one, args=(i, ip), name="verify-%d" % i, daemon=True)
                   for i, ip in enumerate(ips)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return [m for m in out if m is not None]

    @staticmethod
    def _measure_text(m):
        if m.get("ping") is None:
            return "%s: پاسخ نداد (%s)" % (m["ip"], error_summary(m.get("errors") or [], 1))
        return "%.0fms  jitter %.0f  loss %.0f%%" % (m["ping"], m.get("jitter") or 0, m["loss"])

    def _stopped(self, result):
        result["kind"] = "stopped"
        return result

    @staticmethod
    def _hint(errors, version, verify=False, use_ws=False):
        joined = " ".join(errors)
        if version == 6 and ("unreachable" in joined.lower() or "No route" in joined):
            return "این اینترنت IPv6 ندارد؛ در تنظیمات IPv4 را انتخاب کنید."
        if verify and use_ws and "HTTP 404" in joined:
            return "پاسخ 404 گرفتیم: path کانفیگ در تنظیمات با inbound سرور یکی نیست."
        if verify and use_ws and any(code in joined for code in ("HTTP 52", "HTTP 50")):
            return "کلادفلر به سرور شما وصل نشد (خطای 5xx): سرور یا پورت را بررسی کنید."
        if "TLS" in joined or "reset" in joined:
            return "اتصال TLS قطع می‌شود؛ ممکن است SNI دامنهٔ شما روی این اپراتور فیلتر باشد."
        if errors and all(e == "timeout" for e in errors):
            return "همه timeout شدند؛ اینترنت، حالت هواپیما یا روشن بودن VPN را بررسی کنید."
        return ""


def ago(ts, now=None):
    """A short Persian "time ago" for a timestamp."""
    if not ts:
        return "هرگز"
    seconds = max(0, (now or time.time()) - ts)
    if seconds < 60:
        return "همین الان"
    if seconds < 3600:
        return "%d دقیقه پیش" % (seconds // 60)
    if seconds < 86400:
        return "%d ساعت پیش" % (seconds // 3600)
    return "%d روز پیش" % (seconds // 86400)


def format_measure_row(m):
    if m.get("ping") is None:
        return "%-15s  FAIL" % m["ip"]
    return "%-15s %4.0fms j%-3.0f %3.0f%% %s" % (m["ip"], m["ping"], m.get("jitter") or 0,
                                                 m["loss"], m.get("colo", ""))


def format_trace_row(r):
    return "%-15s %4.0fms  %s" % (r["ip"], r["total"], r.get("colo", ""))


# ======================================================================= UI
# Everything below runs only inside Pythonista.

BG = "#F3F1EC"
CARD = "#FFFFFF"
INK = "#17181C"
MUTED = "#5B5E66"
LINE = "#E2DED6"
BORDER = "#C9C4B8"
ACCENT = "#1F4FD1"
GOOD = "#17663F"
GOOD_BG = "#E3F2EA"
BAD = "#A3261C"
BAD_BG = "#FBE7E4"
NEUTRAL = "#4A4D55"
NEUTRAL_BG = "#ECEAE4"
WARN = "#5C4400"
WARN_BG = "#FFF4D6"
RLM = "‏"


def fa(text):
    """Right-to-left mark first, so a line starting with Latin stays RTL."""
    return RLM + text if text and not text.startswith(RLM) else text


if ui is not None:

    ALIGN = {"right": ui.ALIGN_RIGHT, "left": ui.ALIGN_LEFT, "center": ui.ALIGN_CENTER}

    def make_label(text="", size=15, bold=False, color=INK, align="right", mono=False, lines=1):
        lab = ui.Label()
        lab.text = text if mono else fa(text)
        lab.font = ("Menlo" if mono else ("<System-Bold>" if bold else "<System>"), size)
        lab.text_color = color
        lab.alignment = ALIGN[align]
        lab.number_of_lines = lines
        return lab

    def make_button(title, action, primary=False, color=None, size=16):
        b = ui.Button()
        b.title = title
        b.font = ("<System-Bold>", size)
        b.corner_radius = 12
        b.action = action
        if primary:
            b.background_color = ACCENT
            b.tint_color = "white"
        else:
            b.background_color = CARD
            b.tint_color = color or INK
            b.border_width = 1
            b.border_color = BORDER
        return b

    def run_bg(fn, *args):
        """Dialogs block, so every dialog flow runs off the main thread."""
        def wrapper():
            try:
                fn(*args)
            except KeyboardInterrupt:
                pass  # a dialog was cancelled
            except Exception as exc:
                log("flow %s failed: %r" % (getattr(fn, "__name__", fn), exc))
                try:
                    console.alert("خطا", "%s: %s" % (exc.__class__.__name__, exc), "باشه",
                                  hide_cancel_button=True)
                except KeyboardInterrupt:
                    pass
        threading.Thread(target=wrapper, name="flow", daemon=True).start()

    def alert(title, message="", *buttons):
        """console.alert with Persian defaults; returns the pressed index or 0."""
        try:
            if buttons:
                return console.alert(title, message, *buttons)
            console.alert(title, message, "باشه", hide_cancel_button=True)
            return 1
        except KeyboardInterrupt:
            return 0

    STATUS_STYLE = {
        "ok": ("سالم", GOOD, GOOD_BG),
        "bad": ("قطع", BAD, BAD_BG),
        "unknown": ("بررسی نشده", NEUTRAL, NEUTRAL_BG),
        "unset": ("تنظیم نشده", NEUTRAL, NEUTRAL_BG),
    }

    class ProfileCard(ui.View):
        HEIGHT = 168

        def __init__(self, app, profile):
            self.app = app
            self.pid = profile["id"]
            st = app.store.state(self.pid)
            status = st.get("status", "unknown") if profile["record"] else "unset"
            text, fg, bg = STATUS_STYLE.get(status, STATUS_STYLE["unknown"])
            self.background_color = CARD
            self.corner_radius = 18
            self.border_width = 1.5 if status == "bad" else 1
            self.border_color = BAD if status == "bad" else LINE

            self.name_label = make_label(profile["name"], 18, bold=True)
            self.record_label = make_label(profile["record"] or "زیردامنه تنظیم نشده",
                                           12, color=MUTED, mono=bool(profile["record"]))
            self.pill = make_label(text, 13, bold=True, color=fg, align="center")
            self.pill.background_color = bg
            self.pill.corner_radius = 12
            ips = st.get("current") or []
            self.ip_label = make_label(", ".join(ips) or "—", 15, mono=True, align="left",
                                       color=MUTED if status == "bad" else INK)
            info = ago(st.get("checked_at"))
            if st.get("ping") is not None and status == "ok":
                info = "%.0fms · %s" % (st["ping"], info)
            elif status == "bad" and st.get("detail"):
                info = "%s · %s" % (st["detail"], info)
            self.info_label = make_label(info, 12, color=BAD if status == "bad" else MUTED)
            self.go = make_button("تست و اصلاح", self.tapped_go, primary=(status == "bad"))
            self.more = make_button("بیشتر", self.tapped_more, size=15)
            for v in (self.name_label, self.record_label, self.pill, self.ip_label,
                      self.info_label, self.go, self.more):
                self.add_subview(v)

        def layout(self):
            w = self.width
            self.pill.frame = (16, 16, 96, 26)
            self.name_label.frame = (120, 12, w - 136, 26)
            self.record_label.frame = (16, 42, w - 32, 18)
            self.ip_label.frame = (16, 70, w - 32, 22)
            self.info_label.frame = (16, 94, w - 32, 18)
            self.more.frame = (16, 120, 86, 36)
            self.go.frame = (110, 120, w - 126, 36)

        def tapped_go(self, sender):
            self.app.start_scan(self.pid, "auto")

        def tapped_more(self, sender):
            run_bg(self.app.profile_menu, self.pid)

    class MainView(ui.View):
        def __init__(self, app):
            self.app = app
            self.name = APP_NAME
            self.background_color = BG
            self.scroll = ui.ScrollView()
            self.scroll.always_bounce_vertical = True
            self.add_subview(self.scroll)
            self.subtitle = make_label("IP تمیز برای هر اپراتور", 14, color=MUTED)
            self.banner = ui.View()
            self.banner.background_color = WARN_BG
            self.banner.corner_radius = 14
            self.banner_label = make_label(
                "قبل از اسکن VPN را خاموش کنید و اینترنت گوشی را روی همان اپراتور بگذارید.",
                13, color=WARN, lines=2)
            self.banner.add_subview(self.banner_label)
            self.footer = make_label("", 12, color=MUTED, align="center", lines=2)
            for v in (self.subtitle, self.banner, self.footer):
                self.scroll.add_subview(v)
            self.cards = []
            self.right_button_items = [
                ui.ButtonItem(title="تنظیمات", action=lambda s: run_bg(self.app.open_settings)),
                ui.ButtonItem(title="ابزارها", action=lambda s: run_bg(self.app.open_tools)),
            ]
            self.refresh()

        @on_main_thread
        def refresh(self):
            for c in self.cards:
                self.scroll.remove_subview(c)
            self.cards = [ProfileCard(self.app, p) for p in self.app.store.profiles]
            for c in self.cards:
                self.scroll.add_subview(c)
            s = self.app.store.settings
            if not s["sni"] or not self.app.store.secrets.get():
                self.footer.text = fa("اول «تنظیمات» را کامل کنید: دامنهٔ CDN و توکن کلادفلر.")
                self.footer.text_color = BAD
            else:
                self.footer.text = fa("%s · IPv%d · %s" % (s["sni"], s["ip_version"],
                                                          "اعمال خودکار" if s["auto_apply"]
                                                          else "اعمال با تأیید"))
                self.footer.text_color = MUTED
            self.layout()

        def layout(self):
            w, h = self.width, self.height
            pad = 16
            inner = w - 2 * pad
            self.scroll.frame = (0, 0, w, h)
            y = 10
            self.subtitle.frame = (pad, y, inner, 22)
            y += 30
            self.banner.frame = (pad, y, inner, 56)
            self.banner_label.frame = (12, 6, inner - 24, 44)
            y += 68
            for c in self.cards:
                c.frame = (pad, y, inner, ProfileCard.HEIGHT)
                y += ProfileCard.HEIGHT + 12
            self.footer.frame = (pad, y, inner, 40)
            y += 56
            self.scroll.content_size = (w, y)

    STEP_ICONS = {"wait": ("○", MUTED), "run": ("●", ACCENT), "ok": ("✓", GOOD),
                  "fail": ("✕", BAD), "skip": ("–", MUTED)}

    class ScanView(ui.View):
        """Implements the :class:`Events` methods the scan calls."""

        def __init__(self, app, pid, mode):
            self.app = app
            self.pid = pid
            profile = app.store.profile(pid)
            self.name = profile["name"]
            self.background_color = BG
            self.result = None
            self.rows = []

            self.scroll = ui.ScrollView()
            self.add_subview(self.scroll)
            self.record_label = make_label(profile["record"] or "", 13, color=MUTED, mono=True)
            self.scroll.add_subview(self.record_label)

            self.step_card = ui.View()
            self.step_card.background_color = CARD
            self.step_card.corner_radius = 18
            self.step_card.border_width = 1
            self.step_card.border_color = LINE
            self.scroll.add_subview(self.step_card)
            self.step_views = []
            for title in STEP_TITLES:
                icon = make_label("○", 18, bold=True, color=MUTED, align="center")
                name = make_label(title, 15, bold=True, color=MUTED)
                detail = make_label("", 12, color=MUTED, lines=2)
                for v in (icon, name, detail):
                    self.step_card.add_subview(v)
                self.step_views.append((icon, name, detail))

            self.track = ui.View()
            self.track.background_color = "#E7E3DA"
            self.track.corner_radius = 4
            self.fill = ui.View()
            self.fill.background_color = ACCENT
            self.fill.corner_radius = 4
            self.track.add_subview(self.fill)
            self.step_card.add_subview(self.track)
            self.counter = make_label("", 12, color=MUTED)
            self.step_card.add_subview(self.counter)
            self.fraction = 0.0

            self.notes = make_label("", 13, color=WARN, lines=4)
            self.notes.background_color = WARN_BG
            self.notes.corner_radius = 12
            self.notes.hidden = True
            self.scroll.add_subview(self.notes)

            self.table_title = make_label("بهترین‌ها تا این لحظه", 14, bold=True)
            self.scroll.add_subview(self.table_title)
            self.table = ui.TableView()
            self.table.corner_radius = 16
            self.table.border_width = 1
            self.table.border_color = LINE
            self.table.row_height = 40
            self.ds = ui.ListDataSource([])
            self.ds.font = ("Menlo", 13)
            self.ds.text_color = INK
            self.ds.action = self.row_tapped
            self.table.data_source = self.ds
            self.table.delegate = self.ds
            self.scroll.add_subview(self.table)
            self.table_hint = make_label("روی هر ردیف بزنید تا همان IP را اعمال یا کپی کنید.",
                                         12, color=MUTED)
            self.table_hint.hidden = True
            self.scroll.add_subview(self.table_hint)

            self.stop_btn = make_button("توقف", self.tapped_stop, color=BAD)
            self.apply_btn = make_button("اعمال روی DNS", self.tapped_apply, primary=True)
            self.copy_btn = make_button("کپی IPها", self.tapped_copy)
            self.again_btn = make_button("اسکن دوباره", self.tapped_again)
            for v in (self.stop_btn, self.apply_btn, self.copy_btn, self.again_btn):
                self.add_subview(v)
            self.apply_btn.hidden = self.copy_btn.hidden = self.again_btn.hidden = True

            self.mode = mode
            self.job = ScanJob(app.store, pid, events=self, mode=mode)

        def start(self):
            console.set_idle_timer_disabled(True)
            threading.Thread(target=self.job.run, name="job", daemon=True).start()

        def layout(self):
            w, h = self.width, self.height
            pad = 16
            inner = w - 2 * pad
            bottom = 76
            self.scroll.frame = (0, 0, w, h - bottom)
            y = 8
            self.record_label.frame = (pad, y, inner, 20)
            y += 28
            row_y = 14
            for icon, name, detail in self.step_views:
                icon.frame = (inner - 40, row_y, 28, 24)
                name.frame = (12, row_y, inner - 56, 24)
                detail.frame = (12, row_y + 24, inner - 56, 32)
                row_y += 60
            self.track.frame = (12, row_y + 2, inner - 24, 8)
            self.fill.frame = (0, 0, (inner - 24) * self.fraction, 8)
            self.counter.frame = (12, row_y + 14, inner - 24, 18)
            card_h = row_y + 40
            self.step_card.frame = (pad, y, inner, card_h)
            y += card_h + 12
            if not self.notes.hidden:
                self.notes.frame = (pad, y, inner, 72)
                y += 84
            self.table_title.frame = (pad, y, inner, 22)
            y += 28
            table_h = max(4, len(self.rows)) * 40
            self.table.frame = (pad, y, inner, table_h)
            y += table_h + 6
            self.table_hint.frame = (pad, y, inner, 18)
            y += 30
            self.scroll.content_size = (w, y)
            by = h - bottom + 12
            if self.stop_btn.hidden:
                visible = [b for b in (self.apply_btn, self.again_btn, self.copy_btn)
                           if not b.hidden]
                gap = 8
                bw = (inner - gap * (len(visible) - 1)) / max(1, len(visible))
                x = w - pad - bw  # right to left
                for b in visible:
                    b.frame = (x, by, bw, 50)
                    x -= bw + gap
            else:
                self.stop_btn.frame = (pad, by, inner, 50)

        # -- Events (called from worker threads) -------------------------

        @on_main_thread
        def step(self, index, status, detail=""):
            icon, name, det = self.step_views[index]
            symbol, color = STEP_ICONS.get(status, STEP_ICONS["wait"])
            icon.text = symbol
            icon.text_color = color
            name.text_color = INK if status in ("run", "ok", "fail") else MUTED
            if detail:
                det.text = fa(detail)
                det.text_color = BAD if status == "fail" else MUTED
            if index == 2 and status == "run":
                self.table_title.text = fa("نتیجهٔ تأیید دقیق")

        @on_main_thread
        def progress(self, done, total, found):
            self.fraction = (done / float(total)) if total else 0.0
            self.fill.width = self.track.width * self.fraction
            self.counter.text = fa("%d / %d بررسی شد · %d پاسخ" % (done, total, found))

        @on_main_thread
        def found(self, rows):
            self.rows = list(rows)
            self.ds.items = [format_measure_row(r) if "attempts" in r else format_trace_row(r)
                             for r in rows]
            self.layout()

        @on_main_thread
        def note(self, text):
            self.notes.text = fa(((self.notes.text or "").strip(RLM) + "\n" + text).strip())
            self.notes.hidden = False
            self.layout()

        @on_main_thread
        def finished(self, result):
            self.result = result
            console.set_idle_timer_disabled(False)
            kind = result.get("kind")
            self.stop_btn.hidden = True
            self.again_btn.hidden = False
            self.copy_btn.hidden = not (result.get("verified") or result.get("chosen"))
            self.apply_btn.hidden = kind not in ("pending", "apply_failed")
            self.table_hint.hidden = not result.get("verified")
            messages = {
                "healthy": ("IP فعلی سالم است", "success"),
                "applied": ("IP جدید اعمال شد", "success"),
                "unchanged": ("بهترین IP همان قبلی است", "success"),
                "pending": ("IP پیدا شد؛ «اعمال» را بزنید", "success"),
                "found": ("IP پیدا شد", "success"),
                "stopped": ("متوقف شد", "error"),
                "broken": ("IP فعلی خراب است", "error"),
                "nothing": ("IP سالمی پیدا نشد", "error"),
                "apply_failed": ("اعمال روی DNS نشد", "error"),
                "error": ("خطا", "error"),
            }
            text, icon = messages.get(kind, ("تمام شد", "success"))
            console.hud_alert(text, icon, 1.6)
            extra = result.get("hint") or result.get("message") or ""
            if extra:
                self.note(extra)
            self.layout()
            self.app.main.refresh()

        # -- buttons ------------------------------------------------------

        def tapped_stop(self, sender):
            self.job.cancel()
            sender.enabled = False
            sender.title = "در حال توقف..."

        def tapped_again(self, sender):
            self.app.pop_and_scan(self.pid, "force")

        def tapped_copy(self, sender):
            r = self.result or {}
            ips = r.get("chosen") or [m["ip"] for m in r.get("verified", []) if m.get("ping")]
            clipboard.set("\n".join(ips))
            console.hud_alert("کپی شد")

        def tapped_apply(self, sender):
            r = self.result or {}
            if r.get("chosen"):
                sender.enabled = False
                run_bg(self._apply_flow, list(r["chosen"]))

        def _apply_flow(self, ips):
            ok = self.job.apply(ips, self.result)
            self._after_apply(ok)

        @on_main_thread
        def _after_apply(self, ok):
            self.apply_btn.enabled = True
            self.apply_btn.hidden = ok
            console.hud_alert("اعمال شد" if ok else "اعمال نشد", "success" if ok else "error")
            self.layout()
            self.app.main.refresh()

        def row_tapped(self, ds):
            index = ds.selected_row
            if self.result is None or index < 0 or index >= len(self.rows):
                return
            run_bg(self._row_menu, self.rows[index])

        def _row_menu(self, row):
            ip = row["ip"]
            choice = dialogs.list_dialog(ip, ["اعمال همین IP روی رکورد", "کپی IP",
                                              "تست دوباره (۱۰ بار)"])
            if choice == "کپی IP":
                clipboard.set(ip)
                console.hud_alert("کپی شد")
            elif choice == "اعمال همین IP روی رکورد":
                if alert("اعمال", "رکورد %s روی %s تنظیم شود؟" % (
                        self.app.store.profile(self.pid)["record"], ip), "اعمال") == 1:
                    self._apply_flow([ip])
            elif choice:
                self.app.test_ip_flow(ip, self.pid)

    class HistoryView(ui.View):
        def __init__(self, app, pid=None):
            self.name = "تاریخچه"
            self.background_color = BG
            names = {p["id"]: p["name"] for p in app.store.profiles}
            kinds = {"apply": "تغییر", "manual": "دستی", "rollback": "برگشت", "check": "بررسی"}
            items = []
            for h in app.store.history(pid):
                when = time.strftime("%m/%d %H:%M", time.localtime(h.get("ts", 0)))
                old = ",".join(h.get("old") or []) or "—"
                new = ",".join(h.get("new") or []) or "—"
                if h.get("kind") == "check":
                    change = "%s %s" % (new, h.get("note", ""))
                else:
                    change = "%s → %s" % (old, new)
                items.append(fa("%s · %s · %s · %s" % (when, names.get(h.get("profile"), "?"),
                                                       kinds.get(h.get("kind"), h.get("kind")),
                                                       change)))
            self.table = ui.TableView()
            self.ds = ui.ListDataSource(items or [fa("هنوز چیزی ثبت نشده")])
            self.ds.font = ("<System>", 13)
            self.table.data_source = self.table.delegate = self.ds
            self.table.row_height = 48
            self.table.allows_selection = False
            self.add_subview(self.table)

        def layout(self):
            self.table.frame = (0, 0, self.width, self.height)

    class App:
        def __init__(self, store):
            self.store = store
            self.active = None  # the ScanView of a running job
            self.main = None
            self.nav = None

        def run(self):
            log("=== app start v%s ===" % APP_VERSION)
            enable_crash_trace()
            self.main = MainView(self)
            self.nav = ui.NavigationView(self.main)
            self.nav.present("fullscreen", hide_title_bar=False)
            s = self.store.settings
            if not s["sni"] or not self.store.secrets.get():
                run_bg(self.first_run)

        @on_main_thread
        def push(self, view_class, *args):
            """Build the view on the main thread, then show it."""
            self.nav.push_view(view_class(self, *args))

        @on_main_thread
        def pop_and_scan(self, pid, mode):
            self.nav.pop_view()
            ui.delay(lambda: self.start_scan(pid, mode), 0.5)

        @on_main_thread
        def start_scan(self, pid, mode):
            if self.active is not None and self.active.job.running:
                if self.active.pid == pid:
                    self.nav.push_view(self.active)
                else:
                    console.hud_alert("یک اسکن دیگر در حال اجراست", "error")
                return
            view = ScanView(self, pid, mode)
            self.active = view
            self.nav.push_view(view)
            view.start()

        # -- flows (background threads) -----------------------------------

        def first_run(self):
            alert("خوش آمدید",
                  "برای شروع: دامنهٔ CDN (همان SNI کانفیگ‌ها)، path و توکن کلادفلر را "
                  "وارد کنید، بعد از «ابزارها» زیردامنهٔ هر اپراتور را تنظیم کنید.")
            self.open_settings()

        def open_settings(self):
            s = self.store.settings
            has_token = bool(self.store.secrets.get())

            def text(key, title, value=None, kind="text"):
                return {"type": kind, "key": key, "title": title,
                        "value": str(s[key] if value is None else value),
                        "autocorrection": False, "autocapitalization": ui.AUTOCAPITALIZE_NONE}

            def switch(key, title, value=None):
                return {"type": "switch", "key": key, "title": title,
                        "value": bool(s[key] if value is None else value)}

            sections = [
                ("کانفیگ", [
                    text("sni", "دامنهٔ CDN (SNI)"),
                    text("path", "WebSocket path"),
                    text("port", "پورت", kind="number"),
                    switch("tls", "TLS"),
                ], "همان دامنه و path که در هاست‌های پنل است. با path خالی فقط /cdn-cgi/trace تست می‌شود."),
                ("کلادفلر", [
                    {"type": "password", "key": "token",
                     "title": "API Token (%s)" % ("ذخیره شده" if has_token else "خالی"),
                     "value": ""},
                    text("zone_id", "Zone ID (اختیاری)"),
                    text("ttl", "TTL (ثانیه)", kind="number"),
                    text("ips_per_record", "تعداد IP در رکورد (۱ تا ۳)", kind="number"),
                    switch("auto_apply", "اعمال خودکار بعد از تست"),
                ], "توکن فقط در Keychain آیفون ذخیره می‌شود. خالی گذاشتن یعنی بدون تغییر؛ برای پاک کردن «-» بنویسید."),
                ("اسکن", [
                    text("candidates", "تعداد کاندید", kind="number"),
                    text("workers", "تست همزمان", kind="number"),
                    text("timeout", "مهلت هر اتصال (ثانیه)", kind="number"),
                    text("stop_after", "توقف بعد از این تعداد پاسخ (۰=همه)", kind="number"),
                    text("verify_top", "تعداد IP برای تأیید دقیق", kind="number"),
                    text("verify_attempts", "تلاش برای هر IP", kind="number"),
                    text("max_loss_pct", "حداکثر افت مجاز (٪)", kind="number"),
                    text("max_ping_ms", "حداکثر پینگ سالم (ms)", kind="number"),
                    text("colos", "فقط این دیتاسنترها (مثلاً FRA,AMS)"),
                    switch("ip_version", "IPv6 به جای IPv4", value=s["ip_version"] == 6),
                    text("bad_ttl_hours", "نادیده گرفتن IPهای بد (ساعت)", kind="number"),
                ]),
            ]
            values = dialogs.form_dialog("تنظیمات", sections=sections, done_button_title="ذخیره")
            if values is None:
                return
            token = (values.pop("token", "") or "").strip()
            values["ip_version"] = 6 if values.get("ip_version") else 4
            values["path"] = normalise_path(values.get("path"))
            values["sni"] = normalise_host(values.get("sni"))
            try:
                self.store.update_settings(values)
            except ValueError as exc:
                alert("مقدار نامعتبر", str(exc))
                return self.open_settings()
            if token == "-":
                self.store.secrets.set("")
            elif token:
                self.store.secrets.set(token)
            self.main.refresh()
            console.hud_alert("ذخیره شد")
            if token and token != "-":
                self.test_cloudflare()

        def open_tools(self):
            items = [
                "تاریخچهٔ تغییرات",
                "اپراتورها و زیردامنه‌ها",
                "تست یک IP دلخواه",
                "تست اتصال به کلادفلر",
                "به‌روزرسانی رنج IP کلادفلر",
                "پاک کردن حافظهٔ IPهای بد",
                "کپی تنظیمات (بدون توکن)",
                "وارد کردن تنظیمات از کلیپ‌بورد",
                "کپی لاگ برای گزارش خطا",
            ]
            choice = dialogs.list_dialog("ابزارها", items)
            if choice is None:
                return
            index = items.index(choice)
            if index == 0:
                self.push(HistoryView)
            elif index == 1:
                self.manage_profiles()
            elif index == 2:
                ip = console.input_alert("تست یک IP", "آدرس IP کلادفلر", "", "تست").strip()
                self.test_ip_flow(ip, None)
            elif index == 3:
                self.test_cloudflare()
            elif index == 4:
                self.refresh_ranges()
            elif index == 5:
                self.store.clear_bad()
                console.hud_alert("پاک شد")
            elif index == 6:
                clipboard.set(self.store.export_json())
                console.hud_alert("کپی شد")
            elif index == 7:
                try:
                    self.store.import_json(clipboard.get() or "")
                except ValueError as exc:
                    alert("وارد نشد", "متن کلیپ‌بورد خروجی CF Scanner نیست (%s)." % exc)
                    return
                self.main.refresh()
                console.hud_alert("وارد شد")
            elif index == 8:
                clipboard.set(read_log_tail(120))
                console.hud_alert("لاگ کپی شد")

        def manage_profiles(self):
            while True:
                profiles = self.store.profiles
                items = ["%s — %s" % (p["name"], p["record"] or "بدون زیردامنه") for p in profiles]
                items.append("+ افزودن اپراتور")
                choice = dialogs.list_dialog("اپراتورها", items)
                if choice is None:
                    break
                index = items.index(choice)
                if index == len(profiles):
                    self.edit_profile(None)
                else:
                    self.edit_profile(profiles[index]["id"])
            self.main.refresh()

        def edit_profile(self, pid):
            p = self.store.profile(pid) if pid else {"name": "", "record": ""}
            fields = [
                {"type": "text", "key": "name", "title": "نام", "value": p["name"]},
                {"type": "text", "key": "record", "title": "زیردامنه (ابر خاکستری)",
                 "value": p["record"], "autocorrection": False,
                 "autocapitalization": ui.AUTOCAPITALIZE_NONE},
            ]
            if pid:
                fields.append({"type": "switch", "key": "delete", "title": "حذف این اپراتور",
                               "value": False})
            values = dialogs.form_dialog("ویرایش اپراتور" if pid else "اپراتور جدید", fields,
                                         done_button_title="ذخیره")
            if values is None:
                return
            if pid and values.get("delete"):
                if alert("حذف", "«%s» حذف شود؟ رکورد DNS دست نمی‌خورد." % p["name"], "حذف") == 1:
                    self.store.delete_profile(pid)
                return
            if pid:
                self.store.edit_profile(pid, values["name"], values["record"])
            else:
                self.store.add_profile(values["name"], values["record"])

        def profile_menu(self, pid):
            p = self.store.profile(pid)
            items = [
                "فقط بررسی IP فعلی",
                "اسکن کامل (حتی اگر سالم است)",
                "تنظیم IP دستی",
                "برگرداندن IP قبلی",
                "IPهای خوب ذخیره‌شده",
                "تاریخچهٔ این اپراتور",
                "ویرایش نام و زیردامنه",
            ]
            choice = dialogs.list_dialog(p["name"], items)
            if choice is None:
                return
            index = items.index(choice)
            if index == 0:
                self.start_scan(pid, "check")
            elif index == 1:
                self.start_scan(pid, "force")
            elif index == 2:
                text = console.input_alert("IP دستی", "یک یا چند IP، با کاما جدا کنید", "", "اعمال")
                ips = [x.strip() for x in text.replace(" ", ",").split(",") if x.strip()]
                self._apply_manual(pid, ips, "manual")
            elif index == 3:
                old = self.store.previous_ips(pid)
                if not old:
                    alert("برگرداندن", "IP قبلی برای این اپراتور ثبت نشده.")
                elif alert("برگرداندن", "رکورد به %s برگردد؟" % ", ".join(old), "برگردان") == 1:
                    self._apply_manual(pid, old, "rollback")
            elif index == 4:
                self.good_list(pid)
            elif index == 5:
                self.push(HistoryView, pid)
            elif index == 6:
                self.edit_profile(pid)
                self.main.refresh()

        def _apply_manual(self, pid, ips, kind):
            try:
                for ip in ips:
                    ipaddress.ip_address(ip)
            except ValueError:
                alert("IP نامعتبر", ", ".join(ips))
                return
            if not ips:
                return
            console.show_activity()
            try:
                apply_ips(self.store, pid, ips, kind=kind)
            except (CFError, NetError) as exc:
                alert("اعمال نشد", str(exc))
                return
            finally:
                console.hide_activity()
            self.main.refresh()
            console.hud_alert("اعمال شد")

        def good_list(self, pid):
            good = sorted(self.store.state(pid)["good"].items(), key=lambda kv: -kv[1].get("ts", 0))
            if not good:
                alert("IPهای خوب", "هنوز IP خوبی برای این اپراتور ذخیره نشده.")
                return
            items = ["%s  %sms  %s  %s" % (ip, "%.0f" % g["ping"] if g.get("ping") else "?",
                                            g.get("colo", ""), ago(g.get("ts")))
                     for ip, g in good[:60]]
            choice = dialogs.list_dialog("IPهای خوب", items)
            if choice is None:
                return
            ip = good[items.index(choice)][0]
            if alert(ip, "این IP دوباره تست شود یا مستقیم اعمال شود؟",
                     "تست", "اعمال مستقیم") == 2:
                self._apply_manual(pid, [ip], "manual")
            else:
                self.test_ip_flow(ip, pid)

        def test_ip_flow(self, ip, pid):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                alert("IP نامعتبر", ip)
                return
            s = self.store.settings
            target = Target.from_settings(s)
            if not target.sni:
                alert("تنظیمات", "اول دامنهٔ CDN را در تنظیمات وارد کنید.")
                return
            console.show_activity()
            try:
                trace = trace_probe(ip, target, make_context(), float(s["timeout"]) + 1)
                m = measure(ip, target, make_context(), 10, float(s["timeout"]) + 1,
                            bool(target.path))
            finally:
                console.hide_activity()
            lines = ["دیتاسنتر: %s" % (trace.get("colo") or "—"),
                     "پینگ: %s" % ("%.0f ms" % m["ping"] if m["ping"] is not None else "—"),
                     "jitter: %.0f" % (m["jitter"] or 0),
                     "افت: %.0f%% (%d از %d)" % (m["loss"], m["ok"], m["attempts"]),
                     "آزمون: %s" % ("WebSocket" if target.path else "trace")]
            if m["errors"]:
                lines.append("خطاها: %s" % error_summary(m["errors"]))
            if trace.get("loc") and trace["loc"] != "IR":
                lines.append("هشدار: موقعیت %s؛ VPN روشن است؟" % trace["loc"])
            if m["ok"] == 0:
                alert(ip, "\n".join(lines))
                return
            if pid:
                self.store.remember_good(pid, ip, m["ping"], trace.get("colo", ""))
                self.store.save()
            names = [p["name"] for p in self.store.profiles if p["record"]]
            if not names:
                alert(ip, "\n".join(lines))
                return
            if alert(ip, "\n".join(lines), "اعمال روی یک اپراتور") != 1:
                return
            target_pid = pid
            if target_pid is None:
                choice = dialogs.list_dialog("روی کدام اپراتور؟", names)
                if choice is None:
                    return
                target_pid = [p["id"] for p in self.store.profiles if p["name"] == choice][0]
            self._apply_manual(target_pid, [ip], "manual")

        def test_cloudflare(self):
            token = self.store.secrets.get()
            if not token:
                alert("کلادفلر", "توکن وارد نشده.")
                return
            console.show_activity()
            lines = []
            try:
                try:
                    info, via = with_api(self.store, [], lambda api: api.verify_token())
                    lines.append("توکن: %s" % (info or {}).get("status", "?"))
                except (CFError, NetError) as exc:
                    lines.append("توکن: خطا (%s)" % exc)
                    alert("تست کلادفلر", "\n".join(lines))
                    return
                rtype = "AAAA" if self.store.settings["ip_version"] == 6 else "A"
                for p in self.store.profiles:
                    if not p["record"]:
                        lines.append("%s: زیردامنه ندارد" % p["name"])
                        continue
                    try:
                        ips = read_record_ips(self.store, p, rtype)
                        lines.append("%s: %s" % (p["name"], ", ".join(ips) or "رکورد %s ندارد" % rtype))
                    except (CFError, NetError) as exc:
                        lines.append("%s: خطا (%s)" % (p["name"], exc))
                self.store.save()
            finally:
                console.hide_activity()
            alert("تست کلادفلر", "\n".join(lines))

        def refresh_ranges(self):
            console.show_activity()
            try:
                v4, v6 = CloudflareAPI().public_ranges()
            except (CFError, NetError) as exc:
                alert("رنج‌ها", "دریافت نشد: %s" % exc)
                return
            finally:
                console.hide_activity()
            if v4:
                self.store.data["ranges"] = {"v4": v4, "v6": v6, "ts": time.time()}
                self.store.save()
            alert("رنج‌ها", "%d رنج IPv4 و %d رنج IPv6 ذخیره شد." % (len(v4), len(v6)))


def main():
    if ui is None:
        print("CF Scanner runs inside Pythonista on the iPhone.")
        return
    App(Store()).run()


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
"""CF Scanner for iPhone - one clean-IP record that works on every network.

Runs inside Pythonista 3 on the iPhone. The idea in one line: a clean
Cloudflare address depends only on the customer's network, never on the
server (the SNI picks the server), so one DNS-only record, ``ip1``, can
serve every CDN config of every server.

With the VPN off, pick the network the phone is on (MCI, Irancell, home...)
and tap "scan this network":

1. the addresses ``ip1`` holds now are re-checked on this network,
2. if one fails here, Cloudflare addresses are scanned - first the ones
   that already work on the other networks, then known-good ones and their
   /24 neighbours, then random ones,
3. every answer lands in a coverage table (address x network), and ``ip1``
   gets the addresses that work on the most networks, ranked by their
   worst ping; each is confirmed with a real WebSocket upgrade on every
   CDN server,
4. ``ip1`` is pointed at them through the Cloudflare API. An optional
   ``ip2`` takes the best addresses for the networks ``ip1`` cannot cover.

Secrets: the Cloudflare API token lives in the iOS Keychain, never in the
data file. Everything else is kept in ``cfscan_ios_data.json`` next to this
script; ``cfscan_ios_log.txt`` holds a step log for bug reports.

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
import re
import socket
import ssl
import statistics
import threading
import time
import urllib.parse
import urllib.request

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
APP_VERSION = "3.0"

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
    "ip1": "",              # DNS-only record every CDN config uses as its address
    "ip2": "",              # optional record for networks ip1 cannot cover
    "zone_id": "",          # optional; looked up from the record name when empty
    "ttl": 60,
    "ips_per_record": 2,
    "auto_apply": True,
    "fresh_hours": 48,      # how long a network's results count for coverage
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

#: A CDN server: only used to confirm addresses with its SNI and path.
SERVER_DEFAULTS = {
    "name": "",
    "sni": "",              # CDN domain (orange cloud): SNI and Host header
    "path": "",             # WebSocket path of the config; empty = trace test only
    "port": 443,
    "tls": True,
}

_ALL_DEFAULTS = dict(SERVER_DEFAULTS)
_ALL_DEFAULTS.update(DEFAULT_SETTINGS)

#: (minimum, maximum) for every numeric setting.
SETTING_LIMITS = {
    "port": (1, 65535), "ttl": (60, 86400), "ips_per_record": (1, 3),
    "fresh_hours": (1, 168), "candidates": (20, 5000), "workers": (1, 128),
    "timeout": (0.5, 10.0), "stop_after": (0, 1000), "verify_top": (1, 20),
    "verify_attempts": (2, 30), "max_loss_pct": (0, 50), "max_ping_ms": (50, 5000),
    "ip_version": (4, 6), "bad_ttl_hours": (0, 168),
}

DEFAULT_NETWORKS = [
    {"id": "mci", "name": "همراه اول"},
    {"id": "mtn", "name": "ایرانسل"},
    {"id": "home", "name": "خانگی"},
]

RECORDS = ("ip1", "ip2")
HISTORY_LIMIT = 300
MATRIX_LIMIT = 400
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

_INVISIBLE = r"[\s​-‏⁠﻿]"


def normalise_host(value):
    """A bare hostname from a pasted value (``https://A.b.com/x`` -> ``a.b.com``)."""
    host = re.sub(_INVISIBLE, "", str(value or ""))
    host = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", host)
    host = host.split("/", 1)[0].split("?", 1)[0]
    if host.count(":") == 1:  # a port, not an IPv6 address
        host = host.split(":", 1)[0]
    return host.strip(".").lower()


def normalise_path(value):
    path = re.sub(_INVISIBLE, "", str(value or ""))
    if path and not path.startswith("/"):
        path = "/" + path
    return path


def _coerce(key, value):
    """``value`` as the type of the default for ``key``, clamped to its limits."""
    default = _ALL_DEFAULTS[key]
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
    if key in ("sni", "ip1", "ip2"):
        return normalise_host(value)
    if key == "path":
        return normalise_path(value)
    return str(value).strip()


def suggest_record(sni, name="ip1"):
    """``ip1.example.com`` from a CDN domain like ``de.example.com``."""
    labels = normalise_host(sni).split(".")
    if len(labels) >= 3:
        labels = labels[1:]
    return "%s.%s" % (name, ".".join(labels)) if len(labels) >= 2 else ""


def _server(raw, index):
    raw = raw if isinstance(raw, dict) else {}
    server = {"id": str(raw.get("id") or "s%d" % index)}
    for key, default in SERVER_DEFAULTS.items():
        try:
            server[key] = _coerce(key, raw.get(key, default))
        except (TypeError, ValueError):
            server[key] = default
    server["name"] = server["name"] or server["sni"] or "سرور %d" % index
    return server


def normalise_data(raw):
    """A complete version-3 document from whatever was stored.

    Older layouts are migrated: version 1 (one CDN domain in the settings,
    carriers as ``profiles``) and version 2 (servers with a record per
    carrier). Their carriers become networks and the addresses remembered
    as good on each become coverage entries; the per-carrier records are
    left alone in Cloudflare.
    """
    raw = raw if isinstance(raw, dict) else {}
    version = raw.get("version") or (1 if "profiles" in raw else 3)
    raw_settings = raw.get("settings") if isinstance(raw.get("settings"), dict) else {}

    settings = dict(DEFAULT_SETTINGS)
    for key, value in raw_settings.items():
        if key in DEFAULT_SETTINGS:
            try:
                settings[key] = _coerce(key, value)
            except (TypeError, ValueError):
                pass

    if version == 1:
        server_list = [dict(raw_settings, id="s1")] if raw_settings.get("sni") else []
        net_list = raw.get("profiles") or []
        memory = {cid: st for cid, st in (raw.get("state") or {}).items() if isinstance(st, dict)}
    elif version == 2:
        server_list = raw.get("servers") or []
        net_list = raw.get("carriers") or []
        memory = raw.get("memory") if isinstance(raw.get("memory"), dict) else {}
        if not settings["zone_id"]:
            zones = [s.get("zone_id") for s in server_list if isinstance(s, dict) and s.get("zone_id")]
            settings["zone_id"] = str(zones[0]).strip() if zones else ""
    else:
        server_list = raw.get("servers") or []
        net_list = raw.get("networks") or []
        memory = {}

    servers, ids = [], set()
    for i, s in enumerate(server_list, 1):
        server = _server(s, i)
        if server["id"] not in ids:
            ids.add(server["id"])
            servers.append(server)

    networks, seen = [], set()
    for n in net_list or copy.deepcopy(DEFAULT_NETWORKS):
        if isinstance(n, dict) and n.get("id") and str(n["id"]) not in seen:
            seen.add(str(n["id"]))
            networks.append({"id": str(n["id"]), "name": str(n.get("name") or n["id"])})
    if not networks:
        networks = copy.deepcopy(DEFAULT_NETWORKS)

    matrix = raw.get("matrix") if isinstance(raw.get("matrix"), dict) else {}
    bad = raw.get("bad") if isinstance(raw.get("bad"), dict) else {}
    for nid, mem in memory.items():
        if not isinstance(mem, dict):
            continue
        for ip, g in (mem.get("good") or {}).items():
            g = g if isinstance(g, dict) else {}
            matrix.setdefault(ip, {})[nid] = {"ok": True, "ping": g.get("ping"),
                                              "colo": g.get("colo", ""), "ts": g.get("ts", 0)}
        if mem.get("bad"):
            bad.setdefault(nid, {}).update(mem["bad"])

    if not settings["ip1"] and servers:
        settings["ip1"] = suggest_record(servers[0]["sni"], "ip1")

    net_ids = [n["id"] for n in networks]
    current = raw.get("network")
    return {
        "version": 3,
        "settings": settings,
        "servers": servers,
        "networks": networks,
        "network": current if current in net_ids else net_ids[0],
        "matrix": matrix,
        "bad": bad,
        "records": raw.get("records") if version == 3 and isinstance(raw.get("records"), dict) else {},
        "history": [h for h in raw.get("history") or [] if isinstance(h, dict)][-HISTORY_LIMIT:],
        "zones": raw.get("zones") if isinstance(raw.get("zones"), dict) else {},
        "ranges": raw.get("ranges") if isinstance(raw.get("ranges"), dict) else {},
    }


class Secrets:
    """The Cloudflare token: iOS Keychain in Pythonista, memory elsewhere."""

    def __init__(self):
        self._memory = ""
        try:
            import keychain
        except ImportError:
            keychain = None
        self._keychain = keychain

    def get(self, sid=None):
        if self._keychain is None:
            return self._memory
        return self._keychain.get_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT) or ""

    def set(self, token, sid=None):
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
    """Settings, servers, networks, the coverage table and history."""

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
    def token(self):
        return sanitize_token(self.secrets.get())

    # -- settings ----------------------------------------------------------

    @property
    def settings(self):
        return self.data["settings"]

    def update_settings(self, values):
        """Validate every value first, so a bad one changes nothing."""
        clean = {key: _coerce(key, value) for key, value in values.items()
                 if key in DEFAULT_SETTINGS}
        with self.lock:
            self.settings.update(clean)
            self.save()

    # -- servers -----------------------------------------------------------

    @property
    def servers(self):
        return self.data["servers"]

    def server(self, sid):
        for s in self.servers:
            if s["id"] == sid:
                return s
        raise KeyError(sid)

    def save_server(self, sid, values):
        """Create (``sid`` None) or update a CDN server; returns its id."""
        clean = {key: _coerce(key, value) for key, value in values.items()
                 if key in SERVER_DEFAULTS}
        with self.lock:
            if sid is None:
                n = len(self.servers) + 1
                ids = {s["id"] for s in self.servers}
                while "s%d" % n in ids:
                    n += 1
                sid = "s%d" % n
                self.servers.append(_server(dict(clean, id=sid), n))
            else:
                server = self.server(sid)
                server.update(clean)
                server["name"] = server["name"] or server["sni"] or sid
            if not self.settings["ip1"]:
                self.settings["ip1"] = suggest_record(self.server(sid)["sni"], "ip1")
            self.save()
            return sid

    def delete_server(self, sid):
        with self.lock:
            self.data["servers"] = [s for s in self.servers if s["id"] != sid]
            self.save()

    # -- networks ----------------------------------------------------------

    @property
    def networks(self):
        return self.data["networks"]

    def network(self, nid):
        for n in self.networks:
            if n["id"] == nid:
                return n
        raise KeyError(nid)

    @property
    def current_network(self):
        return self.network(self.data["network"])

    def set_network(self, nid):
        with self.lock:
            self.network(nid)
            self.data["network"] = nid
            self.save()

    def save_network(self, nid, name):
        with self.lock:
            if nid is None:
                n = 1
                ids = {x["id"] for x in self.networks}
                while "n%d" % n in ids:
                    n += 1
                nid = "n%d" % n
                self.networks.append({"id": nid, "name": name.strip() or nid})
            else:
                self.network(nid)["name"] = name.strip() or nid
            self.save()
            return nid

    def delete_network(self, nid):
        with self.lock:
            if len(self.networks) <= 1:
                raise ValueError("at least one network is needed")
            self.data["networks"] = [n for n in self.networks if n["id"] != nid]
            for cells in self.data["matrix"].values():
                cells.pop(nid, None)
            self.data["bad"].pop(nid, None)
            if self.data["network"] == nid:
                self.data["network"] = self.networks[0]["id"]
            self.save()

    # -- the coverage table: address x network ------------------------------

    @property
    def matrix(self):
        return self.data["matrix"]

    def record_result(self, ip, nid, ok, ping=None, colo="", ts=None):
        with self.lock:
            self.matrix.setdefault(ip, {})[nid] = {
                "ok": bool(ok), "ping": ping, "colo": colo or "",
                "ts": time.time() if ts is None else ts}
            if ok:
                self.data["bad"].get(nid, {}).pop(ip, None)
            if len(self.matrix) > MATRIX_LIMIT:
                newest = sorted(self.matrix.items(),
                                key=lambda kv: -max(c.get("ts", 0) for c in kv[1].values()))
                self.data["matrix"] = dict(newest[:MATRIX_LIMIT])

    def bad_for(self, nid):
        return self.data["bad"].setdefault(nid, {})

    def remember_bad(self, nid, ips):
        with self.lock:
            bad = self.bad_for(nid)
            now = time.time()
            for ip in ips:
                bad[ip] = now
            if len(bad) > BAD_LIMIT:
                self.data["bad"][nid] = dict(sorted(bad.items(), key=lambda kv: -kv[1])[:BAD_LIMIT])

    def clear_bad(self):
        with self.lock:
            self.data["bad"] = {}
            self.save()

    def clear_matrix(self):
        with self.lock:
            self.data["matrix"] = {}
            self.save()

    # -- what the records point at ------------------------------------------

    def record_ips(self, key):
        return list((self.data["records"].get(key) or {}).get("ips") or [])

    def set_record_ips(self, key, ips, merged=None):
        """``merged``: the record holds a separate address per network."""
        with self.lock:
            entry = self.data["records"].get(key) or {}
            if list(ips) != entry.get("ips"):
                entry = {"ips": list(ips), "ts": time.time(), "merged": False}
            if merged is not None:
                entry["merged"] = bool(merged)
            self.data["records"][key] = entry

    def record_merged(self, key):
        return bool((self.data["records"].get(key) or {}).get("merged"))

    # -- history -----------------------------------------------------------

    def add_history(self, record, old, new, network="", kind="apply", note=""):
        with self.lock:
            self.data["history"].append({"ts": time.time(), "record": record, "kind": kind,
                                         "network": network, "old": list(old),
                                         "new": list(new), "note": note})
            del self.data["history"][:-HISTORY_LIMIT]

    def history(self):
        return list(reversed(self.data["history"]))

    def previous_ips(self, record):
        for h in self.history():
            if h.get("record") == record and h.get("old"):
                return list(h["old"])
        return []

    # -- misc --------------------------------------------------------------

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
        """Settings, servers and networks as JSON, without the token."""
        return json.dumps({"app": "cfscan_ios", "version": 3, "settings": self.settings,
                           "servers": self.servers, "networks": self.networks},
                          ensure_ascii=False, indent=1)

    def import_json(self, text):
        raw = json.loads(text)
        if not isinstance(raw, dict) or raw.get("app") != "cfscan_ios":
            raise ValueError("not a CF Scanner export")
        merged = normalise_data(raw)
        with self.lock:
            for key in ("settings", "servers", "networks", "network"):
                self.data[key] = merged[key]
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
                     bad_ttl_s=6 * 3600, exclude=(), shared=()):
    """The scan order: known-good, ``shared``, neighbours, then random.

    ``shared`` are addresses found for other carriers (an Irancell address is
    sometimes the fastest on MCI too). Addresses that failed on this carrier
    within ``bad_ttl_s`` are skipped.
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
    for ip in shared:
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

    def __init__(self, message, codes=()):
        super().__init__(message)
        self.codes = tuple(codes)


#: Cloudflare error codes worth a plain-language explanation.
CF_ERROR_HINTS = {
    1000: "توکن پذیرفته نشد؛ دوباره کپی کنید (بدون فاصله و بدون کلمهٔ Bearer)",
    6003: "هدر احراز هویت نامعتبر است؛ احتمالاً Global API Key وارد شده، نه API Token",
    6111: "هدر احراز هویت نامعتبر است؛ احتمالاً Global API Key وارد شده، نه API Token",
    9109: "توکن محدودیت IP دارد و از این اینترنت اجازه ندارد (Client IP Address Filtering)",
    10000: "توکن دسترسی لازم را ندارد (Zone → DNS → Edit)",
    7000: "Zone ID اشتباه است؛ از صفحهٔ Overview دامنه «Zone ID» (نه Account ID) را کپی کنید یا خالی بگذارید",
    7003: "Zone ID اشتباه است؛ از صفحهٔ Overview دامنه «Zone ID» (نه Account ID) را کپی کنید یا خالی بگذارید",
}


def sanitize_token(text):
    """The token alone, from whatever was pasted.

    Drops a leading ``Bearer``, quotes, spaces, line breaks and invisible
    characters that copying on a phone tends to add.
    """
    token = str(text or "").strip().strip("\"'")
    if token.lower().startswith("bearer "):
        token = token[7:]
    return re.sub(r"[^A-Za-z0-9_.\-]", "", token)


def token_problem(token):
    """A Persian explanation when ``token`` cannot be an API token, else ''."""
    if not token:
        return "توکن کلادفلر در تنظیمات وارد نشده"
    if re.fullmatch(r"[0-9a-f]{37}", token):
        return ("این Global API Key است. از بخش API Tokens یک توکن با دسترسی "
                "Zone → DNS → Edit بسازید و آن را وارد کنید.")
    if len(token) < 30:
        return "توکن کوتاه است (%d کاراکتر)؛ احتمالاً کامل کپی نشده." % len(token)
    return ""


def token_fingerprint(token):
    """Enough of the token to compare with the dashboard, never all of it."""
    if len(token) < 12:
        return "(%d کاراکتر)" % len(token)
    return "%s…%s (%d کاراکتر)" % (token[:5], token[-4:], len(token))


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
            errors = data.get("errors") or []
            codes = [e.get("code") for e in errors if isinstance(e, dict)]
            messages = "; ".join("%s (%s)" % (e.get("message", ""), e.get("code"))
                                 for e in errors if isinstance(e, dict))
            hints = [CF_ERROR_HINTS[c] for c in codes if c in CF_ERROR_HINTS]
            if hints:
                messages += " — " + hints[0]
            raise CFError(messages or "HTTP %s" % status, codes)
        return data.get("result")

    def verify_token(self):
        """The token's status, for user tokens and account tokens alike.

        Account API tokens (``cfat_...``) are refused by the user endpoint
        with code 1000 even when valid; they verify under their account.
        """
        try:
            result = self.call("GET", "/user/tokens/verify") or {}
            result["kind"] = "user"
            return result
        except CFError as exc:
            if 1000 not in exc.codes:
                raise
            first = exc
        try:
            zones = self.call("GET", "/zones", {"per_page": 50}) or []
        except CFError:
            raise first
        accounts = []
        for z in zones:
            account = (z.get("account") or {}).get("id")
            if account and account not in accounts:
                accounts.append(account)
        for account in accounts:
            try:
                result = self.call("GET", "/accounts/%s/tokens/verify" % account) or {}
                result["kind"] = "account"
                return result
            except CFError:
                continue
        if zones:
            return {"status": "active", "kind": "account"}
        raise first

    def public_ranges(self):
        result = self.call("GET", "/ips")
        return list(result.get("ipv4_cidrs") or []), list(result.get("ipv6_cidrs") or [])

    def zones(self):
        return self.call("GET", "/zones", {"per_page": 50}) or []

    def find_zone(self, record):
        """The id of the zone ``record`` lives in (``mtn.cdn.example.com`` ->
        ``example.com``), or a Persian explanation of why there is none."""
        record = normalise_host(record)
        labels = record.split(".")
        for i in range(len(labels) - 1):
            result = self.call("GET", "/zones", {"name": ".".join(labels[i:])})
            if result:
                return result[0]["id"]
        visible = self.zones()
        for z in sorted(visible, key=lambda z: -len(z.get("name", ""))):
            name = z.get("name", "")
            if record == name or record.endswith("." + name):
                return z["id"]
        if not visible:
            raise CFError("توکن اجازهٔ دیدن دامنه‌ها را ندارد. یا دسترسی Zone → Zone → Read "
                          "را به توکن اضافه کنید، یا Zone ID دامنه را در تنظیمات وارد کنید.")
        names = ", ".join(z.get("name", "") for z in visible[:5])
        raise CFError("%s زیر هیچ‌کدام از دامنه‌های این توکن (%s) نیست؛ آدرس کامل را "
                      "در «اپراتورها و زیردامنه‌ها» وارد کنید." % (record, names))

    def zone_name(self, zone):
        return (self.call("GET", "/zones/%s" % zone) or {}).get("name", "")

    def inspect_record(self, zone, name, rtype):
        """The addresses on ``name`` and Persian notes on anything wrong."""
        records = self.call("GET", "/zones/%s/dns_records" % zone,
                            {"name": name, "per_page": 100}) or []
        ips = [r.get("content") for r in records if r.get("type") == rtype]
        notes = []
        other = sorted({str(r.get("type")) for r in records if r.get("type") != rtype})
        if other:
            notes.append("رکورد %s هم دارد؛ باید فقط %s باشد" % ("/".join(other), rtype))
        if any(r.get("proxied") for r in records if r.get("type") == rtype):
            notes.append("ابر نارنجی است؛ باید خاکستری (DNS only) باشد")
        if not records:
            first = name.split(".")[0]
            similar = self.call("GET", "/zones/%s/dns_records" % zone,
                                {"type": rtype, "per_page": 100}) or []
            close = sorted({r.get("name", "") for r in similar
                            if r.get("name", "").split(".")[0] == first})
            note = "رکوردی با این نام در کلادفلر نیست"
            if close:
                note += "؛ شاید منظورتان %s است" % ", ".join(close[:3])
            notes.append(note)
        return ips, notes

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




# ---------------------------------------------------------------- Cloudflare records

def with_api(store, via_ips, fn, api_factory=CloudflareAPI):
    """``fn(api)`` directly, or through a clean address if the API is blocked."""
    token = store.token
    problem = token_problem(token)
    if problem:
        raise CFError(problem)
    last = None
    for via in [None] + list(via_ips)[:3]:
        api = api_factory(token) if via is None else api_factory(token, via_ip=via)
        try:
            return fn(api), via
        except NetError as exc:
            last = exc
            log("api unreachable via %s: %s" % (via or "direct", exc))
    raise last or NetError("unreachable")


#: Codes Cloudflare gives for a zone id that does not exist.
_BAD_ZONE_CODES = (7000, 7003, 1001)


def with_zone(store, api, record, fn):
    """``fn(zone_id)`` for the zone ``record`` is in.

    The Zone ID from the settings, else the one remembered for this record,
    else a lookup. A wrong Zone ID (an Account ID pasted by mistake) or a
    stale remembered one falls back to the lookup.
    """
    configured = (store.settings.get("zone_id") or "").strip()
    zone = configured or store.zone_for(record)
    if zone:
        try:
            return fn(zone)
        except CFError as exc:
            if configured and not set(exc.codes) & set(_BAD_ZONE_CODES):
                raise
            log("zone %s failed for %s (%s); looking it up" % (zone, record, exc))
            with store.lock:
                store.data["zones"].pop(record, None)
    zone = api.find_zone(record)
    store.remember_zone(record, zone)
    return fn(zone)


def record_name(store, key):
    name = store.settings.get(key) or ""
    if not name:
        raise CFError("نام رکورد %s در تنظیمات خالی است" % key)
    return name


def read_record(store, key, rtype, via_ips=(), api_factory=CloudflareAPI):
    record = record_name(store, key)

    def fn(api):
        return with_zone(store, api, record,
                         lambda zone: [r["content"] for r in api.list_records(zone, record, rtype)])

    return with_api(store, via_ips, fn, api_factory)[0]


def inspect_record(store, key, rtype, api_factory=CloudflareAPI):
    """(zone name, addresses, notes) for the Cloudflare check."""
    record = record_name(store, key)

    def fn(api):
        def look(zone):
            ips, notes = api.inspect_record(zone, record, rtype)
            try:
                zone_name = api.zone_name(zone)
            except CFError:
                zone_name = ""
            return zone_name, ips, notes
        return with_zone(store, api, record, look)

    return with_api(store, [], fn, api_factory)[0]


def apply_record(store, key, ips, via_ips=(), network="", kind="apply",
                 api_factory=CloudflareAPI, merged=False):
    """Point record ``key`` (``ip1``/``ip2``) at ``ips``; returns the route used."""
    record = record_name(store, key)
    if not ips:
        raise CFError("هیچ IP برای اعمال نیست")
    rtype = "AAAA" if ":" in ips[0] else "A"
    ttl = int(store.settings["ttl"])

    def fn(api):
        return with_zone(store, api, record,
                         lambda zone: api.sync_records(zone, record, ips, rtype, ttl))

    _, via = with_api(store, via_ips, fn, api_factory)
    with store.lock:
        old = store.record_ips(key)
        store.set_record_ips(key, ips, merged)
        store.add_history(key, old, ips, network, kind, "via %s" % via if via else "")
        store.save()
    log("applied %s -> %s" % (record, ips))
    return via


def connection_check(timeout=6.0, url="https://speed.cloudflare.com/cdn-cgi/trace"):
    """Where Cloudflare sees this phone: ``{"ok", "loc", "ip", "colo", "error"}``.

    ``loc`` other than ``IR`` means the traffic leaves through a VPN.
    """
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            info = parse_trace(b"\r\n\r\n" + resp.read(4096))
        return {"ok": True, "loc": info.get("loc", ""), "ip": info.get("ip", ""),
                "colo": info.get("colo", ""), "error": ""}
    except Exception as exc:
        return {"ok": False, "loc": "", "ip": "", "colo": "", "error": describe_error(exc)}


# ---------------------------------------------------------------- coverage

def fresh_cell(cell, now, window_s):
    return bool(cell) and now - cell.get("ts", 0) < window_s


def active_networks(matrix, network_ids, now, window_s):
    """Networks with at least one result inside the window, in list order."""
    return [n for n in network_ids
            if any(fresh_cell(cells.get(n), now, window_s) for cells in matrix.values())]


def coverage(matrix, ip, networks, now, window_s):
    """(networks where ``ip`` works now, its worst ping there)."""
    cells = matrix.get(ip) or {}
    covered = [n for n in networks
               if fresh_cell(cells.get(n), now, window_s) and cells[n].get("ok")]
    pings = [cells[n].get("ping") or 0 for n in covered]
    return covered, (max(pings) if pings else float("inf"))


def rank_addresses(matrix, networks, now, window_s, among=None):
    """Addresses that work somewhere: most networks first, then best worst-ping."""
    rows = []
    for ip in (among if among is not None else matrix):
        covered, worst = coverage(matrix, ip, networks, now, window_s)
        if covered:
            rows.append((ip, covered, worst))
    rows.sort(key=lambda r: (-len(r[1]), r[2]))
    return rows


def choose_addresses(matrix, networks, now, window_s, count, must_work_on=None,
                     merge_gaps=False):
    """What ip1 and ip2 should hold.

    ``ip1``: up to ``count`` addresses that all cover the widest set of
    networks, best worst-ping first; between equally wide sets the one with
    ``must_work_on`` (the network just scanned) wins. A network no common
    address reaches never pulls ip1 away from the others: it is left to
    ``ip2``, the best addresses for the networks ip1 leaves out.

    ``merge_gaps`` (no ip2 record): those addresses join ip1 instead - one
    record holding a separate address per network beats a network with none.
    """
    rows = rank_addresses(matrix, networks, now, window_s)
    rows.sort(key=lambda r: (-len(r[1]), must_work_on not in r[1], r[2]))
    if not rows:
        return {"ip1": [], "ip2": [], "covered": [], "uncovered": list(networks)}
    best_set = set(rows[0][1])
    ip1 = [ip for ip, covered, _ in rows if set(covered) == best_set][:count]
    uncovered = [n for n in networks if n not in best_set]
    ip2 = []
    if uncovered:
        scored = []
        for ip, covered, _ in rows:
            gain = [n for n in covered if n in uncovered]
            if gain and ip not in ip1:
                pings = [matrix[ip][n].get("ping") or 0 for n in gain]
                scored.append((ip, len(gain), max(pings)))
        scored.sort(key=lambda r: (-r[1], r[2]))
        ip2 = [ip for ip, _, _ in scored[:count]]
    merged = bool(merge_gaps and ip2)
    if merged:
        extra, still = [], set(uncovered)
        for ip in ip2:
            gain = still & set(coverage(matrix, ip, networks, now, window_s)[0])
            if gain:
                extra.append(ip)
                still -= gain
        ip1 = ip1[:max(1, min(count, 3) - len(extra))] + extra
        ip1 = ip1[:3]
        ip2 = []
    covered = set()
    for ip in ip1:
        covered.update(coverage(matrix, ip, networks, now, window_s)[0])
    return {"ip1": ip1, "ip2": ip2, "merged": merged,
            "covered": [n for n in networks if n in covered],
            "uncovered": uncovered}


def seeds_for(matrix, nid, networks, now, window_s, limit=60):
    """Addresses to try first on ``nid``: working elsewhere, not yet here."""
    others = [n for n in networks if n != nid]
    rows = rank_addresses(matrix, others, now, window_s)
    out = []
    for ip, _, _ in rows:
        here = (matrix.get(ip) or {}).get(nid)
        if not fresh_cell(here, now, window_s):
            out.append(ip)
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------- scan engine

STEP_TITLES = ("بررسی ip1 روی این اینترنت", "اسکن", "انتخاب و تأیید روی سرورها",
               "به‌روزرسانی DNS")


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
    """One network: check ip1 here -> scan -> choose -> confirm -> apply.

    ``mode``: ``auto`` scans only when ip1 fails on this network, ``force``
    scans anyway.
    """

    def __init__(self, store, nid, events=None, mode="auto", context_factory=make_context,
                 api_factory=CloudflareAPI, candidates=None, rng=None,
                 probe_trace=trace_probe, probe_ws=ws_probe, now=None):
        self.store = store
        self.nid = nid
        self.events = events or Events()
        self.mode = mode
        self.context_factory = context_factory
        self.api_factory = api_factory
        self.fixed_candidates = candidates
        self.rng = rng or random.Random()
        self.probe_trace = probe_trace
        self.probe_ws = probe_ws
        self.clock = now or time.time
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
        log("job start %s mode=%s" % (self.nid, self.mode))
        started = time.time()
        try:
            result = self._run()
        except (UserError, CFError, NetError, KeyError) as exc:
            result = {"kind": "error", "message": str(exc)}
        except Exception as exc:
            log("job crashed: %r" % (exc,))
            result = {"kind": "error", "message": "%s: %s" % (exc.__class__.__name__, exc)}
        result.setdefault("network", self.nid)
        result["elapsed"] = time.time() - started
        self.result = result
        self.running = False
        log("job end %s: %s" % (self.nid, result.get("kind")))
        self.events.finished(result)
        return result

    # -- the steps -------------------------------------------------------

    def _run(self):
        store = self.store
        s = store.settings
        servers = [sv for sv in store.servers if sv.get("sni")]
        if not servers:
            raise UserError("اول یک سرور CDN (دامنه و path) در تنظیمات اضافه کنید")
        target = Target.from_settings(servers[0])
        version = int(s["ip_version"])
        rtype = "AAAA" if version == 6 else "A"
        ctx = self.context_factory()
        use_ws = bool(target.path)
        has_token = bool(store.token)
        window = float(s["fresh_hours"]) * 3600
        net_ids = [n["id"] for n in store.networks]
        result = {"kind": None, "network": self.nid, "ip1": [], "ip2": [], "current": [],
                  "verified": [], "covered": [], "uncovered": [], "warning": "",
                  "scanned": 0, "answered": 0, "errors": ""}

        # 1. what ip1 (and ip2) hold now, measured on this network
        self.events.step(0, "run")
        current = {}
        for key in RECORDS:
            ips = store.record_ips(key)
            if s.get(key) and has_token:
                try:
                    ips = read_record(store, key, rtype, api_factory=self.api_factory)
                    store.set_record_ips(key, ips)
                except (CFError, NetError) as exc:
                    self.events.note("خواندن %s از کلادفلر نشد: %s" % (key, exc))
            current[key] = [ip for ip in ips if (":" in ip) == (version == 6)]
        result["current"] = current["ip1"]
        checked = current["ip1"] + [ip for ip in current["ip2"] if ip not in current["ip1"]]
        healthy = None
        if checked:
            attempts = max(4, int(s["verify_attempts"]) // 2)
            ms = self._measure_many(checked, target, ctx, attempts, use_ws)
            self._record(ms)
            by_ip = {m["ip"]: m for m in ms}

            def serves_here(key):
                """Every address works here - or, in a record holding one
                address per network, at least one does."""
                ips = current[key]
                if not ips:
                    return False
                ok = [self._ok(by_ip[ip]) for ip in ips]
                return any(ok) if store.record_merged(key) else all(ok)

            healthy = any(serves_here(key) for key in RECORDS)
            store.save()
            self.events.step(0, "ok" if healthy else "fail",
                             "  ".join(self._measure_text(by_ip[ip]) for ip in checked))
        else:
            self.events.step(0, "skip", "ip1 هنوز IP ندارد")
        if self.cancelled:
            return self._stopped(result)
        if healthy and self.mode == "auto":
            for i in (1, 2, 3):
                self.events.step(i, "skip")
            self._fill_coverage(result, net_ids, window)
            result["kind"] = "healthy"
            result["ip1"] = current["ip1"]
            return result

        # 2. scan: addresses working elsewhere first
        self.events.step(1, "run")
        now = self.clock()
        seeds = seeds_for(store.matrix, self.nid, net_ids, now, window)
        if self.fixed_candidates is not None:
            cands = list(self.fixed_candidates)
        else:
            own_good = {ip: {"ts": cells[self.nid].get("ts", 0)}
                        for ip, cells in store.matrix.items()
                        if (cells.get(self.nid) or {}).get("ok")}
            cands = build_candidates({"good": own_good, "bad": store.bad_for(self.nid)},
                                     int(s["candidates"]), version, store.ranges(version),
                                     rng=self.rng, bad_ttl_s=float(s["bad_ttl_hours"]) * 3600,
                                     exclude=[ip for ip in checked if ip not in own_good],
                                     shared=seeds)
        answered, scanned, failed, errors = self._fast_pass(cands, target, ctx, s)
        result["scanned"], result["answered"] = scanned, len(answered)
        result["errors"] = error_summary(errors)
        locs = {r["loc"] for r in answered if r.get("loc")}
        if locs and "IR" not in locs:
            result["warning"] = ("به نظر VPN روشن است (موقعیت: %s). نتیجه مال این اینترنت نیست."
                                 % ", ".join(sorted(locs)))
            self.events.note(result["warning"])
        if answered:
            store.remember_bad(self.nid, failed)
        for ip in seeds:
            if ip in failed:
                store.record_result(ip, self.nid, False)
        if self.cancelled:
            return self._stopped(result)
        if not answered:
            store.save()
            self.events.step(1, "fail", "هیچ IP پاسخ نداد (%s)" % result["errors"])
            result["kind"] = "nothing"
            result["hint"] = self._hint(errors, version)
            return result
        self.events.step(1, "ok", "%d از %d پاسخ داد" % (len(answered), scanned))

        # 3. careful measure, then choose by coverage and confirm on every server
        self.events.step(2, "run")
        top = sorted(answered, key=lambda r: r["total"])[:int(s["verify_top"])]
        seeded = [r for r in answered if r["ip"] in seeds and r not in top][:int(s["verify_top"])]
        colo_of = {r["ip"]: r["colo"] for r in answered}
        ms = self._measure_many([r["ip"] for r in top + seeded], target, ctx,
                                int(s["verify_attempts"]), use_ws)
        for m in ms:
            m["colo"] = m["colo"] or colo_of.get(m["ip"], "")
        self._record(ms)
        store.save()
        ms.sort(key=score)
        result["verified"] = ms
        self.events.found(ms)
        if self.cancelled:
            return self._stopped(result)
        count = int(s["ips_per_record"])
        choice = self._choose_confirmed(servers[1:], ctx, net_ids, window, count)
        result.update(ip1=choice["ip1"], ip2=choice["ip2"] if s.get("ip2") else [],
                      covered=choice["covered"], uncovered=choice["uncovered"],
                      merged=choice.get("merged", False))
        if not choice["ip1"]:
            errs = [e for m in ms for e in m["errors"]]
            self.events.step(2, "fail", "هیچ IP از تأیید رد نشد (%s)" % error_summary(errs))
            result["kind"] = "nothing"
            result["hint"] = self._hint(errs, version, verify=True, use_ws=use_ws)
            return result
        names = {n["id"]: n["name"] for n in store.networks}
        detail = "ip1: %s · پوشش: %s" % (", ".join(choice["ip1"]),
                                         "، ".join(names[n] for n in choice["covered"]))
        if choice["uncovered"]:
            detail += " · بدون پوشش: %s" % "، ".join(names[n] for n in choice["uncovered"])
        self.events.step(2, "ok", detail)
        if choice.get("merged"):
            self.events.note("IP مشترکی برای %s پیدا نشد؛ ip1 برای هر اینترنت IP جدا گرفت. "
                             "اگر ادامه داشت، رکورد ip2 را در تنظیمات فعال کنید."
                             % "، ".join(names[n] for n in choice["uncovered"]))

        # 4. the records
        result["via"] = [m["ip"] for m in ms if m["ok"]]
        changes = {k: result[k] for k in RECORDS
                   if result[k] and sorted(result[k]) != sorted(current[k])}
        result["changes"] = changes
        if not changes:
            self.events.step(3, "ok", "رکوردها همین IPها را دارند")
            result["kind"] = "unchanged"
        elif not has_token or not s.get("ip1"):
            self.events.step(3, "skip", "توکن یا نام رکورد ip1 تنظیم نشده")
            result["kind"] = "found"
        elif not s["auto_apply"]:
            self.events.step(3, "wait", "منتظر تأیید شما")
            result["kind"] = "pending"
        else:
            self.apply(result)
        return result

    def apply(self, result=None, changes=None):
        """Write the chosen addresses; used by the job and by the screen."""
        result = result if result is not None else (self.result or {})
        changes = changes if changes is not None else result.get("changes") or {}
        self.events.step(3, "run")
        done = []
        try:
            for key, ips in changes.items():
                apply_record(self.store, key, ips, result.get("via") or [], self.nid,
                             api_factory=self.api_factory,
                             merged=key == "ip1" and bool(result.get("merged")))
                done.append("%s → %s" % (self.store.settings[key], ", ".join(ips)))
        except (CFError, NetError) as exc:
            self.events.step(3, "fail", str(exc))
            result["kind"] = "apply_failed"
            result["message"] = str(exc)
            return False
        self.events.step(3, "ok", "\n".join(done))
        result["kind"] = "applied"
        return True

    # -- helpers ---------------------------------------------------------

    def _ok(self, m):
        s = self.store.settings
        return is_healthy(m, s["max_loss_pct"], s["max_ping_ms"])

    def _record(self, ms):
        for m in ms:
            self.store.record_result(m["ip"], self.nid, self._ok(m), m.get("ping"),
                                     m.get("colo", ""))

    def _fill_coverage(self, result, net_ids, window):
        now = self.clock()
        active = active_networks(self.store.matrix, net_ids, now, window)
        covered = set()
        for ip in result.get("current") or []:
            covered.update(coverage(self.store.matrix, ip, active, now, window)[0])
        result["covered"] = [n for n in active if n in covered]
        result["uncovered"] = [n for n in active if n not in covered]

    def _choose_confirmed(self, other_servers, ctx, net_ids, window, count):
        """choose_addresses, dropping any address another server refuses."""
        refused = set()
        while True:
            now = self.clock()
            active = active_networks(self.store.matrix, net_ids, now, window)
            matrix = {ip: cells for ip, cells in self.store.matrix.items() if ip not in refused}
            choice = choose_addresses(matrix, active, now, window, count, must_work_on=self.nid,
                                      merge_gaps=not self.store.settings.get("ip2"))
            if not other_servers:
                return choice
            bad = [ip for ip in choice["ip1"] + choice["ip2"]
                   if not self._works_on_servers(ip, other_servers, ctx)]
            if not bad:
                return choice
            refused.update(bad)
            self.events.note("رد شد روی سرور دیگر: %s" % ", ".join(bad))

    def _works_on_servers(self, ip, servers, ctx):
        timeout = float(self.store.settings["timeout"]) + 1.0
        for server in servers:
            target = Target.from_settings(server)
            m = measure(ip, target, ctx, 3, timeout, bool(target.path), cancel=self.cancel_event,
                        pause=0.05, probe_trace=self.probe_trace, probe_ws=self.probe_ws)
            if m["ok"] == 0:
                return False
        return True

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
        return "%s %.0fms loss %.0f%%" % (m["ip"], m["ping"], m["loss"])

    @staticmethod
    def _stopped(result):
        result["kind"] = "stopped"
        return result

    @staticmethod
    def _hint(errors, version, verify=False, use_ws=False):
        joined = " ".join(errors)
        if version == 6 and ("unreachable" in joined.lower() or "No route" in joined):
            return "این اینترنت IPv6 ندارد؛ در تنظیمات اسکن IPv4 را انتخاب کنید."
        if verify and use_ws and "HTTP 404" in joined:
            return "پاسخ 404: path سرور اول با inbound یکی نیست."
        if verify and use_ws and any(code in joined for code in ("HTTP 52", "HTTP 50")):
            return "کلادفلر به سرور وصل نشد (خطای 5xx): سرور یا پورت را بررسی کنید."
        if "TLS" in joined or "reset" in joined:
            return ("اتصال TLS قطع می‌شود؛ احتمالاً SNI دامنهٔ CDN روی این اینترنت فیلتر است. "
                    "دامنهٔ ذخیره را جایگزین کنید.")
        if errors and all(e == "timeout" for e in errors):
            return "همه timeout شدند؛ اینترنت، حالت هواپیما یا روشن بودن VPN را بررسی کنید."
        return ""


RESULT_TEXT = {
    "healthy": "ip1 روی این اینترنت سالم است",
    "applied": "رکورد به‌روز شد",
    "unchanged": "بهترین IPها همان قبلی‌اند",
    "pending": "IP پیدا شد؛ «اعمال» را بزنید",
    "found": "IP پیدا شد (توکن یا رکورد تنظیم نشده)",
    "stopped": "متوقف شد",
    "nothing": "IP سالمی پیدا نشد",
    "apply_failed": "اعمال روی DNS نشد",
    "error": "خطا",
}
GOOD_KINDS = ("healthy", "applied", "unchanged", "pending", "found")


def result_line(result):
    """One Persian line for a finished run."""
    kind = result.get("kind")
    text = RESULT_TEXT.get(kind, kind or "?")
    if result.get("ip1") and kind in ("applied", "pending", "unchanged", "found", "healthy"):
        text += ": " + ", ".join(result["ip1"])
    if kind in ("error", "apply_failed") and result.get("message"):
        text += " — " + result["message"]
    return text


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


def cell_text(cell, now, window_s):
    """``52`` for a fresh pass, ``✕`` for a fresh failure, ``؟`` otherwise."""
    if not fresh_cell(cell, now, window_s):
        return "؟"
    if not cell.get("ok"):
        return "✕"
    return "%.0f" % cell["ping"] if cell.get("ping") is not None else "✓"


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

    def make_card():
        v = ui.View()
        v.background_color = CARD
        v.corner_radius = 18
        v.border_width = 1
        v.border_color = LINE
        return v

    def run_bg(fn, *args):
        """Dialogs block, so every dialog flow runs off the main thread."""
        def wrapper():
            try:
                fn(*args)
            except KeyboardInterrupt:
                pass  # a dialog was cancelled
            except Exception as exc:
                log("flow %s failed: %r" % (getattr(fn, "__name__", fn), exc))
                alert("خطا", "%s: %s" % (exc.__class__.__name__, exc))
        threading.Thread(target=wrapper, name="flow", daemon=True).start()

    def alert(title, message="", *buttons):
        """console.alert with Persian defaults; the pressed index, 0 on cancel."""
        try:
            if buttons:
                return console.alert(title, message, *buttons)
            console.alert(title, message, "باشه", hide_cancel_button=True)
            return 1
        except KeyboardInterrupt:
            return 0

    def pick(title, items):
        """list_dialog returning the index, or None."""
        items = list(items)
        choice = dialogs.list_dialog(title, items)
        return None if choice is None else items.index(choice)

    def text_field(key, title, value, kind="text"):
        return {"type": kind, "key": key, "title": title, "value": str(value),
                "autocorrection": False, "autocapitalization": ui.AUTOCAPITALIZE_NONE}

    CHIP = {"ok": (GOOD, GOOD_BG), "fail": (BAD, BAD_BG), "unknown": (NEUTRAL, NEUTRAL_BG)}

    def chip_state(cell, now, window):
        if not fresh_cell(cell, now, window):
            return "unknown"
        return "ok" if cell.get("ok") else "fail"

    # ------------------------------------------------------------------ record card

    class RecordCard(ui.View):
        """One record (ip1 or ip2): its addresses and where each one works."""

        ROW = 58

        def __init__(self, app, key):
            self.app = app
            self.key = key
            store = app.store
            s = store.settings
            now = time.time()
            window = float(s["fresh_hours"]) * 3600
            networks = store.networks
            self.background_color = CARD
            self.corner_radius = 18
            self.border_width = 1
            self.border_color = ACCENT if key == "ip1" else LINE
            self.heading = make_label("%s · %s" % (key, s.get(key) or "تنظیم نشده"), 15, bold=True)
            self.add_subview(self.heading)
            ips = store.record_ips(key)
            self.rows = []
            for ip in ips:
                ip_label = make_label(ip, 15, mono=True, align="left")
                chips = []
                for n in networks:
                    cell = (store.matrix.get(ip) or {}).get(n["id"])
                    state = chip_state(cell, now, window)
                    fg, bg = CHIP[state]
                    text = "%s %s" % (n["name"], cell_text(cell, now, window))
                    chip = make_label(text, 12, bold=True, color=fg, align="center")
                    chip.background_color = bg
                    chip.corner_radius = 10
                    chips.append(chip)
                for v in [ip_label] + chips:
                    self.add_subview(v)
                self.rows.append((ip_label, chips))
            active = active_networks(store.matrix, [n["id"] for n in networks], now, window)
            covered = set()
            for ip in ips:
                covered.update(coverage(store.matrix, ip, active, now, window)[0])
            parts = []
            for n in networks:
                mark = "✓" if n["id"] in covered else ("✕" if n["id"] in active else "؟")
                parts.append("%s %s" % (n["name"], mark))
            last = (store.data["records"].get(key) or {}).get("ts")
            summary = "پوشش: %s" % " · ".join(parts) if ips else "هنوز IP ندارد؛ «اسکن این اینترنت» را بزنید"
            if last:
                summary += "\nآخرین تغییر: %s" % ago(last)
            self.summary = make_label(summary, 12, color=MUTED, lines=2)
            self.add_subview(self.summary)

        @property
        def height_needed(self):
            return 44 + max(1, len(self.rows)) * self.ROW + 44

        def layout(self):
            w = self.width
            self.heading.frame = (16, 12, w - 32, 22)
            y = 42
            for ip_label, chips in self.rows:
                ip_label.frame = (16, y, w - 32, 22)
                n = max(1, len(chips))
                gap = 6
                cw = (w - 32 - gap * (n - 1)) / n
                x = w - 16 - cw  # right to left, same order as the networks
                for chip in chips:
                    chip.frame = (x, y + 26, cw, 24)
                    x -= cw + gap
                y += self.ROW
            if not self.rows:
                y += self.ROW
            self.summary.frame = (16, y, w - 32, 36)

    class MainView(ui.View):
        def __init__(self, app):
            self.app = app
            self.name = APP_NAME
            self.background_color = BG
            self.scroll = ui.ScrollView()
            self.scroll.always_bounce_vertical = True
            self.add_subview(self.scroll)

            self.ask = make_label("الان روی کدام اینترنت هستید؟", 14, bold=True, color=MUTED)
            self.networks = ui.SegmentedControl()
            self.networks.action = self.network_changed
            self.net_btn = ui.Button()
            self.net_btn.corner_radius = 14
            self.net_btn.font = ("<System-Bold>", 13)
            self.net_btn.action = lambda s: run_bg(self.app.check_connection)
            self.scan_btn = make_button("اسکن این اینترنت", self.tapped_scan, primary=True, size=19)
            self.scan_btn.corner_radius = 16
            self.more_btn = make_button("اسکن کامل، حتی اگر سالم است", self.tapped_force, size=13)
            self.more_btn.border_width = 0
            self.more_btn.background_color = BG
            self.more_btn.tint_color = ACCENT
            self.setup = make_label("", 13, color=BAD, lines=3)
            for v in (self.ask, self.networks, self.net_btn, self.scan_btn, self.more_btn, self.setup):
                self.scroll.add_subview(v)
            self.cards = []
            self.right_button_items = [
                ui.ButtonItem(title="ابزارها", action=lambda s: run_bg(self.app.open_tools)),
                ui.ButtonItem(title="تنظیمات", action=lambda s: run_bg(self.app.open_settings)),
            ]
            self.set_connection(None)
            self.refresh()

        @on_main_thread
        def refresh(self):
            store = self.app.store
            names = [n["name"] for n in store.networks]
            self.networks.segments = names
            ids = [n["id"] for n in store.networks]
            self.networks.selected_index = ids.index(store.data["network"])
            for c in self.cards:
                self.scroll.remove_subview(c)
            keys = [k for k in RECORDS if k == "ip1" or store.settings.get(k)]
            self.cards = [RecordCard(self.app, k) for k in keys]
            for c in self.cards:
                self.scroll.add_subview(c)
            problems = []
            if not store.token:
                problems.append("توکن کلادفلر")
            if not store.servers:
                problems.append("یک سرور CDN")
            if not store.settings.get("ip1"):
                problems.append("نام رکورد ip1")
            self.setup.text = fa("برای شروع در «تنظیمات» وارد کنید: %s" % "، ".join(problems)) \
                if problems else ""
            self.setup.hidden = not problems
            self.layout()

        @on_main_thread
        def set_connection(self, info):
            if info is None:
                text, fg, bg = "در حال بررسی اتصال…", NEUTRAL, NEUTRAL_BG
            elif not info["ok"]:
                text, fg, bg = "اینترنت در دسترس نیست (%s) — بزنید" % info["error"], BAD, BAD_BG
            elif info["loc"] and info["loc"] != "IR":
                text, fg, bg = "VPN روشن است (%s) — خاموشش کنید و بزنید" % info["loc"], BAD, BAD_BG
            else:
                text, fg, bg = "✓ اینترنت ایران · %s · %s" % (info["ip"], info["colo"]), GOOD, GOOD_BG
            self.net_btn.title = fa(text)
            self.net_btn.tint_color = fg
            self.net_btn.background_color = bg

        def network_changed(self, sender):
            nid = self.app.store.networks[sender.selected_index]["id"]
            self.app.store.set_network(nid)

        def tapped_scan(self, sender):
            self.app.start_scan("auto")

        def tapped_force(self, sender):
            self.app.start_scan("force")

        def layout(self):
            w, h = self.width, self.height
            pad = 16
            inner = w - 2 * pad
            self.scroll.frame = (0, 0, w, h)
            y = 14
            self.ask.frame = (pad, y, inner, 20)
            y += 26
            self.networks.frame = (pad, y, inner, 34)
            y += 46
            self.net_btn.frame = (pad, y, inner, 38)
            y += 50
            self.scan_btn.frame = (pad, y, inner, 60)
            y += 64
            self.more_btn.frame = (pad, y, inner, 30)
            y += 40
            if not self.setup.hidden:
                self.setup.frame = (pad, y, inner, 54)
                y += 62
            for c in self.cards:
                ch = c.height_needed
                c.frame = (pad, y, inner, ch)
                y += ch + 12
            self.scroll.content_size = (w, y + 24)

    # ------------------------------------------------------------------ scan screen

    STEP_ICONS = {"wait": ("○", MUTED), "run": ("●", ACCENT), "ok": ("✓", GOOD),
                  "fail": ("✕", BAD), "skip": ("–", MUTED)}

    class ScanView(ui.View):
        """Implements the :class:`Events` methods the job calls."""

        def __init__(self, app, nid, mode):
            self.app = app
            self.nid = nid
            self.mode = mode
            self.rows = []
            self.result = None
            self.started = time.time()
            self.name = app.store.network(nid)["name"]
            self.background_color = BG

            self.scroll = ui.ScrollView()
            self.add_subview(self.scroll)
            self.step_card = make_card()
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
            self.counter = make_label("", 12, color=MUTED)
            self.step_card.add_subview(self.track)
            self.step_card.add_subview(self.counter)
            self.fraction = 0.0

            self.outcome = make_label("", 16, bold=True, lines=3, align="center")
            self.outcome.corner_radius = 14
            self.outcome.hidden = True
            self.notes = make_label("", 13, color=WARN, lines=5)
            self.notes.background_color = WARN_BG
            self.notes.corner_radius = 12
            self.notes.hidden = True
            self.table_title = make_label("بهترین‌ها تا این لحظه", 14, bold=True)
            self.table = ui.TableView()
            self.table.corner_radius = 16
            self.table.border_width = 1
            self.table.border_color = LINE
            self.table.row_height = 40
            self.ds = ui.ListDataSource([])
            self.ds.font = ("Menlo", 13)
            self.ds.text_color = INK
            self.ds.action = self.row_tapped
            self.table.data_source = self.table.delegate = self.ds
            for v in (self.outcome, self.notes, self.table_title, self.table):
                self.scroll.add_subview(v)

            self.stop_btn = make_button("توقف", self.tapped_stop, color=BAD)
            self.apply_btn = make_button("اعمال روی DNS", self.tapped_apply, primary=True)
            self.done_btn = make_button("بازگشت", self.tapped_done)
            for v in (self.stop_btn, self.apply_btn, self.done_btn):
                self.add_subview(v)
            self.apply_btn.hidden = self.done_btn.hidden = True
            self.job = ScanJob(app.store, nid, events=self, mode=mode)

        @property
        def running(self):
            return self.job.running

        def start(self):
            console.set_idle_timer_disabled(True)
            threading.Thread(target=self.job.run, name="job", daemon=True).start()

        def layout(self):
            w, h = self.width, self.height
            pad = 16
            inner = w - 2 * pad
            bottom = 76
            self.scroll.frame = (0, 0, w, h - bottom)
            y = 10
            row_y = 14
            for icon, name, detail in self.step_views:
                icon.frame = (inner - 40, row_y, 28, 24)
                name.frame = (12, row_y, inner - 56, 24)
                detail.frame = (12, row_y + 24, inner - 56, 34)
                row_y += 62
            self.track.frame = (12, row_y + 2, inner - 24, 8)
            self.fill.frame = (0, 0, (inner - 24) * self.fraction, 8)
            self.counter.frame = (12, row_y + 14, inner - 24, 18)
            card_h = row_y + 40
            self.step_card.frame = (pad, y, inner, card_h)
            y += card_h + 12
            if not self.outcome.hidden:
                self.outcome.frame = (pad, y, inner, 76)
                y += 88
            if not self.notes.hidden:
                self.notes.frame = (pad, y, inner, 84)
                y += 96
            self.table_title.frame = (pad, y, inner, 22)
            y += 28
            table_h = max(3, len(self.ds.items)) * 40
            self.table.frame = (pad, y, inner, table_h)
            y += table_h + 20
            self.scroll.content_size = (w, y)
            by = h - bottom + 12
            if self.stop_btn.hidden:
                visible = [b for b in (self.apply_btn, self.done_btn) if not b.hidden]
                gap = 8
                bw = (inner - gap * (len(visible) - 1)) / max(1, len(visible))
                x = w - pad - bw
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
                self.table_title.text = fa("اندازه‌گیری دقیق روی این اینترنت")

        @on_main_thread
        def progress(self, done, total, found):
            self.fraction = (done / float(total)) if total else 0.0
            self.fill.width = self.track.width * self.fraction
            self.counter.text = fa("%d / %d · %d پاسخ · %d ثانیه" % (
                done, total, found, time.time() - self.started))

        @on_main_thread
        def found(self, rows):
            self.rows = list(rows)
            self.ds.items = [format_measure_row(r) if "attempts" in r else format_trace_row(r)
                             for r in rows]
            self.layout()

        @on_main_thread
        def note(self, text):
            old = (self.notes.text or "").replace(RLM, "").strip()
            if text in old:
                return
            self.notes.text = fa((old + "\n" + text).strip())
            self.notes.hidden = False
            self.layout()

        @on_main_thread
        def finished(self, result):
            self.result = result
            console.set_idle_timer_disabled(False)
            kind = result.get("kind")
            if result.get("hint") or (kind in ("error", "apply_failed") and result.get("message")):
                self.note(result.get("hint") or result["message"])
            self.stop_btn.hidden = True
            self.done_btn.hidden = False
            self.apply_btn.hidden = kind not in ("pending", "apply_failed")
            self._show_outcome(result_line(result), kind in GOOD_KINDS)
            console.hud_alert("تمام شد · %.0f ثانیه" % (time.time() - self.started),
                              "success" if kind in GOOD_KINDS else "error", 1.2)
            self.layout()
            self.app.main.refresh()

        def _show_outcome(self, text, good):
            self.outcome.text = fa(text)
            self.outcome.text_color = GOOD if good else BAD
            self.outcome.background_color = GOOD_BG if good else BAD_BG
            self.outcome.hidden = False

        # -- buttons ------------------------------------------------------

        def tapped_stop(self, sender):
            self.job.cancel()
            sender.enabled = False
            sender.title = "در حال توقف…"

        def tapped_done(self, sender):
            self.app.nav.pop_view()

        def tapped_apply(self, sender):
            sender.enabled = False
            run_bg(self._apply_flow)

        def _apply_flow(self):
            ok = self.job.apply(self.result)
            self._after_apply(ok)

        @on_main_thread
        def _after_apply(self, ok):
            self.apply_btn.enabled = True
            self.apply_btn.hidden = ok
            self._show_outcome(result_line(self.result or {}), ok)
            self.layout()
            self.app.main.refresh()

        def row_tapped(self, ds):
            index = ds.selected_row
            if self.running or index < 0 or index >= len(self.rows):
                return
            run_bg(self.app.address_menu, self.rows[index]["ip"])

    # ------------------------------------------------------------------ lists

    class ListView(ui.View):
        """A titled, read-only list of lines."""

        def __init__(self, app, title, lines, row_height=52, mono=False):
            self.name = title
            self.background_color = BG
            self.table = ui.TableView()
            self.ds = ui.ListDataSource(lines or [fa("هنوز چیزی ثبت نشده")])
            self.ds.font = ("Menlo", 12) if mono else ("<System>", 13)
            self.table.data_source = self.table.delegate = self.ds
            self.table.row_height = row_height
            self.table.allows_selection = False
            self.add_subview(self.table)

        def layout(self):
            self.table.frame = (0, 0, self.width, self.height)

    def history_lines(store):
        names = {n["id"]: n["name"] for n in store.networks}
        lines = []
        for h in store.history():
            when = time.strftime("%m/%d %H:%M", time.localtime(h.get("ts", 0)))
            old = ",".join(h.get("old") or []) or "—"
            new = ",".join(h.get("new") or []) or "—"
            where = names.get(h.get("network"), h.get("network") or "")
            lines.append(fa("%s · %s · %s → %s%s" % (when, h.get("record", "?"), old, new,
                                                     " · " + where if where else "")))
        return lines

    def matrix_lines(store):
        s = store.settings
        now = time.time()
        window = float(s["fresh_hours"]) * 3600
        networks = [n["id"] for n in store.networks]
        names = {n["id"]: n["name"] for n in store.networks}
        in_records = set(store.record_ips("ip1")) | set(store.record_ips("ip2"))
        lines = []
        for ip, covered, worst in rank_addresses(store.matrix, networks, now, window):
            cells = store.matrix.get(ip) or {}
            parts = ["%s %s" % (names[n], cell_text(cells.get(n), now, window)) for n in networks]
            mark = "★ " if ip in in_records else ""
            lines.append(fa("%s%s · %s" % (mark, ip, " · ".join(parts))))
        return lines

    # ------------------------------------------------------------------ the app

    class App:
        def __init__(self, store):
            self.store = store
            self.active_scan = None
            self.main = None
            self.nav = None

        def run(self):
            log("=== app start v%s ===" % APP_VERSION)
            enable_crash_trace()
            self.main = MainView(self)
            self.nav = ui.NavigationView(self.main)
            self.nav.present("fullscreen", hide_title_bar=False)
            run_bg(self.check_connection)
            if not self.store.token or not self.store.servers:
                run_bg(self.first_run)

        @on_main_thread
        def push_list(self, title, lines, mono=False):
            self.nav.push_view(ListView(self, title, lines, mono=mono))

        @on_main_thread
        def start_scan(self, mode):
            if self.active_scan is not None and self.active_scan.running:
                self.nav.push_view(self.active_scan)
                return
            view = ScanView(self, self.store.data["network"], mode)
            self.active_scan = view
            self.nav.push_view(view)
            view.start()

        # -- flows (background threads) ----------------------------------

        def check_connection(self):
            self.main.set_connection(None)
            self.main.set_connection(connection_check())

        def first_run(self):
            alert("خوش آمدید",
                  "دو قدم:\n۱. توکن کلادفلر و نام رکورد ip1\n"
                  "۲. سرورهای CDN (دامنه و path) برای تأیید\n\n"
                  "بعد روی هر اینترنت «اسکن این اینترنت» را بزنید.")
            if not self.store.servers:
                self.edit_server(None)
            self.edit_main()

        def open_settings(self):
            index = pick("تنظیمات", ["توکن و رکوردها", "سرورهای CDN", "اینترنت‌ها",
                                     "پیشرفته (اسکن)"])
            if index == 0:
                self.edit_main()
            elif index == 1:
                self.manage_servers()
            elif index == 2:
                self.manage_networks()
            elif index == 3:
                self.edit_advanced()

        def edit_main(self):
            s = self.store.settings
            has = bool(self.store.token)
            sections = [
                ("کلادفلر", [
                    {"type": "password", "key": "token",
                     "title": "API Token (%s)" % ("ذخیره شده" if has else "خالی"), "value": ""},
                    text_field("zone_id", "Zone ID (اختیاری)", s["zone_id"]),
                ], "توکن فقط در Keychain ذخیره می‌شود. خالی = بدون تغییر، «-» = پاک کردن."),
                ("رکوردها (ابر خاکستری)", [
                    text_field("ip1", "ip1 (همهٔ کانفیگ‌های CDN)", s["ip1"]),
                    text_field("ip2", "ip2 (اختیاری)", s["ip2"]),
                    text_field("ips_per_record", "تعداد IP در هر رکورد (۱ تا ۳)", s["ips_per_record"], "number"),
                    {"type": "switch", "key": "auto_apply", "title": "اعمال خودکار", "value": s["auto_apply"]},
                ], "ip1 را در پنل به‌عنوان address همهٔ هاست‌های CDN بگذارید. ip2 فقط وقتی لازم است "
                   "که IP مشترکی برای یک اینترنت پیدا نشود."),
            ]
            values = dialogs.form_dialog("توکن و رکوردها", sections=sections, done_button_title="ذخیره")
            if values is None:
                return
            raw = (values.pop("token", "") or "").strip()
            try:
                self.store.update_settings(values)
            except ValueError as exc:
                alert("مقدار نامعتبر", str(exc))
                return self.edit_main()
            if raw == "-":
                self.store.secrets.set("")
            elif raw:
                token = sanitize_token(raw)
                problem = token_problem(token)
                if problem:
                    alert("توکن", problem)
                    return
                self.store.secrets.set(token)
            self.main.refresh()
            console.hud_alert("ذخیره شد")
            if raw and raw != "-":
                self.test_cloudflare()

        def edit_advanced(self):
            s = self.store.settings
            fields = [
                text_field("fresh_hours", "اعتبار نتیجهٔ هر اینترنت (ساعت)", s["fresh_hours"], "number"),
                text_field("ttl", "TTL رکورد (ثانیه)", s["ttl"], "number"),
                text_field("candidates", "تعداد کاندید", s["candidates"], "number"),
                text_field("workers", "تست همزمان", s["workers"], "number"),
                text_field("timeout", "مهلت هر اتصال (ثانیه)", s["timeout"], "number"),
                text_field("stop_after", "توقف بعد از N پاسخ (۰=همه)", s["stop_after"], "number"),
                text_field("verify_top", "تعداد IP برای اندازه‌گیری دقیق", s["verify_top"], "number"),
                text_field("verify_attempts", "تلاش برای هر IP", s["verify_attempts"], "number"),
                text_field("max_loss_pct", "حداکثر افت مجاز (٪)", s["max_loss_pct"], "number"),
                text_field("max_ping_ms", "حداکثر پینگ سالم (ms)", s["max_ping_ms"], "number"),
                text_field("colos", "فقط این دیتاسنترها (مثلاً FRA,AMS)", s["colos"]),
                {"type": "switch", "key": "ip_version", "title": "IPv6 به جای IPv4",
                 "value": s["ip_version"] == 6},
                text_field("bad_ttl_hours", "نادیده گرفتن IPهای بد (ساعت)", s["bad_ttl_hours"], "number"),
            ]
            values = dialogs.form_dialog("پیشرفته", sections=[("اسکن", fields,
                "پیش‌فرض‌ها برای بیشتر وقت‌ها مناسب‌اند.")], done_button_title="ذخیره")
            if values is None:
                return
            values["ip_version"] = 6 if values.get("ip_version") else 4
            try:
                self.store.update_settings(values)
            except ValueError as exc:
                alert("مقدار نامعتبر", str(exc))
                return self.edit_advanced()
            self.main.refresh()
            console.hud_alert("ذخیره شد")

        def edit_server(self, sid):
            server = self.store.server(sid) if sid else dict(SERVER_DEFAULTS)
            fields = [
                text_field("name", "نام (مثلاً DE)", server["name"]),
                text_field("sni", "دامنهٔ CDN (SNI)", server["sni"]),
                text_field("path", "WebSocket path", server["path"]),
                text_field("port", "پورت", server["port"], "number"),
                {"type": "switch", "key": "tls", "title": "TLS", "value": server["tls"]},
            ]
            if sid:
                fields.append({"type": "switch", "key": "delete", "title": "حذف این سرور",
                               "value": False})
            values = dialogs.form_dialog("سرور CDN", sections=[("سرور", fields,
                "همان دامنه و path هاست CDN در پنل. هر IP قبل از اعمال روی همهٔ سرورها تأیید می‌شود.")],
                done_button_title="ذخیره")
            if values is None:
                return
            if sid and values.get("delete"):
                if alert("حذف", "سرور «%s» حذف شود؟" % server["name"], "حذف") == 1:
                    self.store.delete_server(sid)
                return
            if not normalise_host(values.get("sni")):
                alert("دامنهٔ CDN", "دامنهٔ CDN را وارد کنید.")
                return self.edit_server(sid)
            try:
                self.store.save_server(sid, values)
            except ValueError as exc:
                alert("مقدار نامعتبر", str(exc))
                return self.edit_server(sid)
            self.main.refresh()

        def manage_servers(self):
            while True:
                servers = self.store.servers
                items = ["%s — %s %s" % (s["name"], s["sni"], s["path"]) for s in servers]
                index = pick("سرورهای CDN", items + ["+ سرور جدید"])
                if index is None:
                    break
                self.edit_server(servers[index]["id"] if index < len(servers) else None)
            self.main.refresh()

        def manage_networks(self):
            store = self.store
            while True:
                networks = store.networks
                index = pick("اینترنت‌ها", [n["name"] for n in networks] + ["+ اینترنت جدید"])
                if index is None:
                    break
                if index == len(networks):
                    name = console.input_alert("اینترنت جدید", "مثلاً رایتل، شاتل یا مخابرات", "", "افزودن")
                    if name.strip():
                        store.save_network(None, name)
                    continue
                n = networks[index]
                action = pick(n["name"], ["تغییر نام", "حذف"])
                if action == 0:
                    store.save_network(n["id"], console.input_alert("نام", "", n["name"], "ذخیره"))
                elif action == 1 and alert("حذف", "«%s» و نتایجش حذف شود؟" % n["name"], "حذف") == 1:
                    try:
                        store.delete_network(n["id"])
                    except ValueError:
                        alert("حذف", "حداقل یک اینترنت لازم است.")
            self.main.refresh()

        def open_tools(self):
            items = [
                "جدول همهٔ IPها",
                "تاریخچهٔ تغییرات",
                "تست یک IP روی این اینترنت",
                "تنظیم دستی ip1",
                "برگرداندن ip1 قبلی",
                "تست اتصال به کلادفلر",
                "بررسی دوبارهٔ اتصال اینترنت",
                "به‌روزرسانی رنج IP کلادفلر",
                "پاک کردن IPهای بد و جدول",
                "کپی تنظیمات (بدون توکن)",
                "وارد کردن تنظیمات از کلیپ‌بورد",
                "کپی لاگ برای گزارش خطا",
            ]
            index = pick("ابزارها", items)
            if index == 0:
                self.push_list("جدول IPها (★ = در رکورد)", matrix_lines(self.store))
            elif index == 1:
                self.push_list("تاریخچه", history_lines(self.store))
            elif index == 2:
                ip = console.input_alert("تست یک IP", "آدرس IP کلادفلر", "", "تست").strip()
                self.test_ip(ip)
            elif index == 3:
                text = console.input_alert("ip1 دستی", "یک یا چند IP، با کاما جدا کنید", "", "اعمال")
                self.apply_manual("ip1", [x.strip() for x in text.replace(" ", ",").split(",") if x.strip()])
            elif index == 4:
                old = self.store.previous_ips("ip1")
                if not old:
                    alert("برگرداندن", "IP قبلی ثبت نشده.")
                elif alert("برگرداندن", "ip1 به %s برگردد؟" % ", ".join(old), "برگردان") == 1:
                    self.apply_manual("ip1", old, "rollback")
            elif index == 5:
                self.test_cloudflare()
            elif index == 6:
                self.check_connection()
            elif index == 7:
                self.refresh_ranges()
            elif index == 8:
                if alert("پاک کردن", "حافظهٔ IPهای بد و جدول پوشش پاک شود؟", "پاک کن") == 1:
                    self.store.clear_bad()
                    self.store.clear_matrix()
                    self.main.refresh()
            elif index == 9:
                clipboard.set(self.store.export_json())
                console.hud_alert("کپی شد")
            elif index == 10:
                try:
                    self.store.import_json(clipboard.get() or "")
                except ValueError as exc:
                    alert("وارد نشد", "متن کلیپ‌بورد خروجی CF Scanner نیست (%s)." % exc)
                    return
                self.main.refresh()
                console.hud_alert("وارد شد")
            elif index == 11:
                clipboard.set(read_log_tail(120))
                console.hud_alert("لاگ کپی شد")

        def address_menu(self, ip):
            items = ["کپی IP", "گذاشتن روی ip1", "تست دوباره (۱۰ بار)"]
            if self.store.settings.get("ip2"):
                items.insert(2, "گذاشتن روی ip2")
            index = pick(ip, items)
            if index is None:
                return
            choice = items[index]
            if choice == "کپی IP":
                clipboard.set(ip)
                console.hud_alert("کپی شد")
            elif choice.startswith("گذاشتن"):
                key = "ip2" if "ip2" in choice else "ip1"
                if alert(key, "%s فقط روی %s تنظیم شود؟" % (key, ip), "بله") == 1:
                    self.apply_manual(key, [ip])
            else:
                self.test_ip(ip)

        def apply_manual(self, key, ips, kind="manual"):
            if not ips:
                return
            try:
                for ip in ips:
                    ipaddress.ip_address(ip)
            except ValueError:
                alert("IP نامعتبر", ", ".join(ips))
                return
            console.show_activity()
            try:
                apply_record(self.store, key, ips, network=self.store.data["network"], kind=kind)
            except (CFError, NetError) as exc:
                alert("اعمال نشد", str(exc))
                return
            finally:
                console.hide_activity()
            self.main.refresh()
            console.hud_alert("اعمال شد")

        def test_ip(self, ip):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                alert("IP نامعتبر", ip)
                return
            store = self.store
            servers = [sv for sv in store.servers if sv.get("sni")]
            if not servers:
                alert("سرور", "اول یک سرور CDN اضافه کنید.")
                return
            s = store.settings
            target = Target.from_settings(servers[0])
            console.show_activity()
            try:
                trace = trace_probe(ip, target, make_context(), float(s["timeout"]) + 1)
                m = measure(ip, target, make_context(), 10, float(s["timeout"]) + 1,
                            bool(target.path))
            finally:
                console.hide_activity()
            net = store.current_network
            ok = is_healthy(m, s["max_loss_pct"], s["max_ping_ms"])
            store.record_result(ip, net["id"], ok, m["ping"], trace.get("colo", ""))
            store.save()
            self.main.refresh()
            lines = ["اینترنت: %s" % net["name"],
                     "نتیجه: %s" % ("سالم" if ok else "ناسالم"),
                     "دیتاسنتر: %s" % (trace.get("colo") or "—"),
                     "پینگ: %s" % ("%.0f ms" % m["ping"] if m["ping"] is not None else "—"),
                     "jitter: %.0f · افت: %.0f%%" % (m["jitter"] or 0, m["loss"])]
            if m["errors"]:
                lines.append("خطاها: %s" % error_summary(m["errors"]))
            if trace.get("loc") and trace["loc"] != "IR":
                lines.append("هشدار: موقعیت %s؛ VPN روشن است؟" % trace["loc"])
            alert(ip, "\n".join(lines))

        def test_cloudflare(self):
            store = self.store
            token = store.token
            problem = token_problem(token)
            if problem:
                alert("کلادفلر", problem)
                return
            console.show_activity()
            lines = ["توکن: %s" % token_fingerprint(token)]
            try:
                try:
                    info, _ = with_api(store, [], lambda api: api.verify_token())
                    kind = "توکن حساب" if (info or {}).get("kind") == "account" else "توکن کاربر"
                    lines.append("وضعیت: %s (%s)" % ((info or {}).get("status", "?"), kind))
                except (CFError, NetError) as exc:
                    lines.append("وضعیت: خطا (%s)" % exc)
                    alert("تست کلادفلر", "\n".join(lines))
                    return
                rtype = "AAAA" if store.settings["ip_version"] == 6 else "A"
                for key in RECORDS:
                    if not store.settings.get(key):
                        continue
                    try:
                        zone_name, ips, notes = inspect_record(store, key, rtype)
                        store.set_record_ips(key, ips)
                        line = "%s (%s): %s" % (key, store.settings[key],
                                                ", ".join(ips) or "هنوز رکورد %s ندارد" % rtype)
                        if zone_name:
                            line += "\n  دامنه: %s" % zone_name
                        for n in notes:
                            if "رکوردی با این نام" in n:
                                n += " (اولین اسکن خودش می‌سازدش)"
                            line += "\n  ⚠ %s" % n
                        lines.append(line)
                    except (CFError, NetError) as exc:
                        lines.append("%s: خطا — %s" % (key, exc))
                store.save()
            finally:
                console.hide_activity()
            self.main.refresh()
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

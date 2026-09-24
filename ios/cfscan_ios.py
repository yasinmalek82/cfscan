# -*- coding: utf-8 -*-
"""CF Scanner for iPhone - finds a clean Cloudflare address per carrier.

Runs inside Pythonista 3 on the iPhone. With the VPN off and the phone on one
carrier (MCI, Irancell, home Wi-Fi, ...), one tap:

1. re-checks the address the carrier's DNS record points at now,
2. if it is broken, scans Cloudflare addresses on this very connection
   (known-good ones and their /24 neighbours first, then random ones),
3. re-measures the fastest few with several attempts each (latency, jitter,
   loss, and a real WebSocket upgrade on the config's path when one is set),
4. points the carrier's DNS-only record (``mci.cdn.example.com``) at the
   winner through the Cloudflare API.

Several servers can be kept, each with its own CDN domain (SNI), path and
per-carrier records; one run can fix a carrier on every server. The panel's
hosts use the records as their address, so the panel is never touched.

Secrets: Cloudflare API tokens live in the iOS Keychain, never in the data
file. Everything else (servers, carriers, state, history) is kept in
``cfscan_ios_data.json`` next to this script. ``cfscan_ios_log.txt`` holds a
step log for bug reports; it never contains a token.

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
APP_VERSION = "2.0"

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


#: Scan and DNS settings shared by every server.
DEFAULT_SETTINGS = {
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

#: What one server (one CDN domain) is made of, besides its per-carrier records.
SERVER_DEFAULTS = {
    "name": "",
    "sni": "",              # CDN domain (orange cloud): SNI and Host header
    "path": "",             # WebSocket path of the config; empty = trace test only
    "port": 443,
    "tls": True,
    "zone_id": "",          # optional; looked up from the record name when empty
}

_ALL_DEFAULTS = dict(SERVER_DEFAULTS)
_ALL_DEFAULTS.update(DEFAULT_SETTINGS)

#: (minimum, maximum) for every numeric setting.
SETTING_LIMITS = {
    "port": (1, 65535), "ttl": (60, 86400), "ips_per_record": (1, 3),
    "candidates": (20, 5000), "workers": (1, 128), "timeout": (0.5, 10.0),
    "stop_after": (0, 1000), "verify_top": (1, 20), "verify_attempts": (2, 30),
    "max_loss_pct": (0, 50), "max_ping_ms": (50, 5000), "ip_version": (4, 6),
    "bad_ttl_hours": (0, 168),
}

#: ``prefix`` builds the suggested record: ``mtn`` + ``cdn.example.com``.
DEFAULT_CARRIERS = [
    {"id": "mci", "name": "همراه اول", "prefix": "mci"},
    {"id": "mtn", "name": "ایرانسل", "prefix": "mtn"},
    {"id": "home", "name": "اینترنت خانگی", "prefix": "home"},
]

HISTORY_LIMIT = 400
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

def normalise_host(value):
    """A bare hostname from a pasted value (``https://A.b.com/x`` -> ``a.b.com``)."""
    host = re.sub(r"[\s​-‏⁠﻿]", "", str(value or ""))
    host = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", host)
    host = host.split("/", 1)[0].split("?", 1)[0]
    if host.count(":") == 1:  # a port, not an IPv6 address
        host = host.split(":", 1)[0]
    return host.strip(".").lower()


def normalise_path(value):
    path = re.sub(r"[\s​-‏⁠﻿]", "", str(value or ""))
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
    if key == "sni":
        return normalise_host(value)
    if key == "path":
        return normalise_path(value)
    return str(value).strip()


def _slug(text, fallback):
    slug = re.sub(r"[^a-z0-9-]", "", str(text or "").lower())
    return slug or fallback


def normalise_server(raw, index=1):
    raw = raw if isinstance(raw, dict) else {}
    server = {"id": str(raw.get("id") or "s%d" % index)}
    for key, default in SERVER_DEFAULTS.items():
        try:
            server[key] = _coerce(key, raw.get(key, default))
        except (TypeError, ValueError):
            server[key] = default
    server["name"] = server["name"] or server["sni"] or "سرور %d" % index
    records = raw.get("records") if isinstance(raw.get("records"), dict) else {}
    server["records"] = {str(k): normalise_host(v) for k, v in records.items() if v}
    return server


def normalise_data(raw):
    """A complete version-2 document from whatever was stored.

    Version 1 (one CDN domain in the settings, carriers as ``profiles`` with
    one record each) becomes one server holding those records.
    """
    raw = raw if isinstance(raw, dict) else {}
    legacy = "servers" not in raw and "profiles" in raw
    raw_settings = raw.get("settings") if isinstance(raw.get("settings"), dict) else {}

    settings = dict(DEFAULT_SETTINGS)
    for key, value in raw_settings.items():
        if key in DEFAULT_SETTINGS:
            try:
                settings[key] = _coerce(key, value)
            except (TypeError, ValueError):
                pass

    source = raw.get("carriers") if not legacy else raw.get("profiles")
    carriers, seen = [], set()
    for c in source or copy.deepcopy(DEFAULT_CARRIERS):
        if not isinstance(c, dict) or not c.get("id") or str(c["id"]) in seen:
            continue
        cid = str(c["id"])
        seen.add(cid)
        default_prefix = cid if cid in ("mci", "mtn", "home") else ""
        carriers.append({"id": cid, "name": str(c.get("name") or cid),
                         "prefix": _slug(c.get("prefix", default_prefix), "")})

    state, memory, history = {}, {}, []
    raw_state = raw.get("state") if isinstance(raw.get("state"), dict) else {}
    if legacy:
        server = {k: raw_settings.get(k, v) for k, v in SERVER_DEFAULTS.items()}
        server["id"] = "s1"
        server["records"] = {str(p["id"]): p.get("record", "")
                             for p in raw.get("profiles") or [] if isinstance(p, dict) and p.get("id")}
        servers = [normalise_server(server, 1)]
        for cid, st in raw_state.items():
            if not isinstance(st, dict):
                continue
            memory[cid] = {"good": st.get("good") or {}, "bad": st.get("bad") or {}}
            state["s1|%s" % cid] = {k: v for k, v in st.items() if k not in ("good", "bad")}
        for h in raw.get("history") or []:
            if isinstance(h, dict):
                h = dict(h)
                h["server"] = "s1"
                h["carrier"] = h.pop("profile", "")
                history.append(h)
    else:
        servers, ids = [], set()
        for i, s in enumerate(raw.get("servers") or [], 1):
            server = normalise_server(s, i)
            if server["id"] not in ids:
                ids.add(server["id"])
                servers.append(server)
        state = {k: v for k, v in raw_state.items() if isinstance(v, dict)}
        raw_memory = raw.get("memory") if isinstance(raw.get("memory"), dict) else {}
        memory = {k: v for k, v in raw_memory.items() if isinstance(v, dict)}
        history = [h for h in raw.get("history") or [] if isinstance(h, dict)]

    ids = [s["id"] for s in servers]
    active = raw.get("active_server")
    return {
        "version": 2,
        "settings": settings,
        "servers": servers,
        "carriers": carriers,
        "active_server": active if active in ids else (ids[0] if ids else None),
        "state": state,
        "memory": memory,
        "history": history[-HISTORY_LIMIT:],
        "zones": raw.get("zones") if isinstance(raw.get("zones"), dict) else {},
        "ranges": raw.get("ranges") if isinstance(raw.get("ranges"), dict) else {},
    }


class Secrets:
    """Cloudflare tokens: iOS Keychain in Pythonista, memory elsewhere.

    ``sid`` None is the main token; a server may have its own for a domain
    in another Cloudflare account.
    """

    def __init__(self):
        self._memory = {}
        try:
            import keychain
        except ImportError:
            keychain = None
        self._keychain = keychain

    @staticmethod
    def _account(sid):
        return KEYCHAIN_ACCOUNT if not sid else "%s:%s" % (KEYCHAIN_ACCOUNT, sid)

    def get(self, sid=None):
        if self._keychain is None:
            return self._memory.get(self._account(sid), "")
        return self._keychain.get_password(KEYCHAIN_SERVICE, self._account(sid)) or ""

    def set(self, token, sid=None):
        token = (token or "").strip()
        account = self._account(sid)
        if self._keychain is None:
            self._memory[account] = token
        elif token:
            self._keychain.set_password(KEYCHAIN_SERVICE, account, token)
        else:
            try:
                self._keychain.delete_password(KEYCHAIN_SERVICE, account)
            except Exception:
                pass


class Store:
    """Servers, carriers, settings, state and history in one JSON file."""

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

    @property
    def active(self):
        sid = self.data.get("active_server")
        for s in self.servers:
            if s["id"] == sid:
                return s
        return self.servers[0] if self.servers else None

    def set_active(self, sid):
        with self.lock:
            self.server(sid)
            self.data["active_server"] = sid
            self.save()

    def save_server(self, sid, values, records=None):
        """Create (``sid`` None) or update a server; returns its id."""
        clean = {key: _coerce(key, value) for key, value in values.items()
                 if key in SERVER_DEFAULTS}
        clean_records = {cid: normalise_host(v) for cid, v in (records or {}).items()}
        with self.lock:
            if sid is None:
                n = len(self.servers) + 1
                ids = {s["id"] for s in self.servers}
                sid = "s%d" % n
                while sid in ids:
                    n += 1
                    sid = "s%d" % n
                server = normalise_server(dict(clean, id=sid), n)
                self.servers.append(server)
                if not self.data.get("active_server"):
                    self.data["active_server"] = sid
            else:
                server = self.server(sid)
                server.update(clean)
                server["name"] = server["name"] or server["sni"] or sid
            if records is not None:
                for cid, record in clean_records.items():
                    if record != server["records"].get(cid, ""):
                        self.data["state"].pop(self.key(sid, cid), None)
                    if record:
                        server["records"][cid] = record
                    else:
                        server["records"].pop(cid, None)
            self.save()
            return sid

    def delete_server(self, sid):
        with self.lock:
            self.data["servers"] = [s for s in self.servers if s["id"] != sid]
            for key in [k for k in self.data["state"] if k.startswith(sid + "|")]:
                del self.data["state"][key]
            if self.data.get("active_server") == sid:
                self.data["active_server"] = self.servers[0]["id"] if self.servers else None
            self.save()
        self.secrets.set("", sid)

    def record(self, sid, cid):
        return self.server(sid)["records"].get(cid, "")

    def suggest_record(self, sid, cid):
        """``<prefix>.<sni>``, e.g. ``mtn.cdn.example.com``."""
        server, carrier = self.server(sid), self.carrier(cid)
        if carrier.get("prefix") and server.get("sni"):
            return "%s.%s" % (carrier["prefix"], server["sni"])
        return ""

    def token_for(self, sid):
        return sanitize_token(self.secrets.get(sid) or self.secrets.get(None))

    # -- carriers ----------------------------------------------------------

    @property
    def carriers(self):
        return self.data["carriers"]

    def carrier(self, cid):
        for c in self.carriers:
            if c["id"] == cid:
                return c
        raise KeyError(cid)

    def save_carrier(self, cid, name, prefix):
        with self.lock:
            if cid is None:
                base = _slug(prefix, "") or "c%d" % int(time.time())
                cid, n = base, 1
                ids = {c["id"] for c in self.carriers}
                while cid in ids:
                    n += 1
                    cid = "%s%d" % (base, n)
                self.carriers.append({"id": cid, "name": name.strip() or cid,
                                      "prefix": _slug(prefix, "")})
            else:
                c = self.carrier(cid)
                c["name"] = name.strip() or c["name"]
                c["prefix"] = _slug(prefix, "")
            self.save()
            return cid

    def delete_carrier(self, cid):
        with self.lock:
            self.data["carriers"] = [c for c in self.carriers if c["id"] != cid]
            for s in self.servers:
                s["records"].pop(cid, None)
            for key in [k for k in self.data["state"] if k.endswith("|" + cid)]:
                del self.data["state"][key]
            self.data["memory"].pop(cid, None)
            self.save()

    # -- per server x carrier state and per carrier memory ------------------

    @staticmethod
    def key(sid, cid):
        return "%s|%s" % (sid, cid)

    def state(self, sid, cid):
        with self.lock:
            st = self.data["state"].setdefault(self.key(sid, cid), {})
            st.setdefault("current", [])
            st.setdefault("status", "unknown")
            return st

    def memory(self, cid):
        """Addresses that worked or failed on a carrier, shared by all servers."""
        with self.lock:
            mem = self.data["memory"].setdefault(cid, {})
            mem.setdefault("good", {})
            mem.setdefault("bad", {})
            return mem

    def remember_good(self, cid, ip, ping, colo):
        with self.lock:
            mem = self.memory(cid)
            mem["good"][ip] = {"ts": time.time(), "ping": ping, "colo": colo}
            mem["bad"].pop(ip, None)
            if len(mem["good"]) > GOOD_LIMIT:
                keep = sorted(mem["good"].items(), key=lambda kv: -kv[1].get("ts", 0))
                mem["good"] = dict(keep[:GOOD_LIMIT])

    def remember_bad(self, cid, ips, forget_good=False):
        with self.lock:
            mem = self.memory(cid)
            now = time.time()
            for ip in ips:
                mem["bad"][ip] = now
                if forget_good:
                    mem["good"].pop(ip, None)
            if len(mem["bad"]) > BAD_LIMIT:
                keep = sorted(mem["bad"].items(), key=lambda kv: -kv[1])
                mem["bad"] = dict(keep[:BAD_LIMIT])

    def clear_bad(self):
        with self.lock:
            for mem in self.data["memory"].values():
                mem["bad"] = {}
            self.save()

    # -- history -----------------------------------------------------------

    def add_history(self, sid, cid, kind, old=(), new=(), note=""):
        with self.lock:
            self.data["history"].append({"ts": time.time(), "server": sid, "carrier": cid,
                                         "kind": kind, "old": list(old), "new": list(new),
                                         "note": note})
            del self.data["history"][:-HISTORY_LIMIT]

    def history(self, sid=None, cid=None):
        items = [h for h in self.data["history"]
                 if (sid is None or h.get("server") == sid)
                 and (cid is None or h.get("carrier") == cid)]
        return list(reversed(items))

    def previous_ips(self, sid, cid):
        """The addresses the record had before its last change, if any."""
        for h in self.history(sid, cid):
            if h.get("kind") in ("apply", "manual", "rollback") and h.get("old"):
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
        """Servers, carriers and settings as JSON, without tokens or history."""
        return json.dumps({"app": "cfscan_ios", "version": 2, "settings": self.settings,
                           "servers": self.servers, "carriers": self.carriers},
                          ensure_ascii=False, indent=1)

    def import_json(self, text):
        raw = json.loads(text)
        if not isinstance(raw, dict) or raw.get("app") != "cfscan_ios":
            raise ValueError("not a CF Scanner export")
        merged = normalise_data({k: raw.get(k) for k in ("settings", "servers", "carriers",
                                                          "profiles") if k in raw})
        with self.lock:
            for key in ("settings", "servers", "carriers", "active_server"):
                self.data[key] = merged[key]
            if merged["state"]:
                self.data["state"].update(merged["state"])
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



def with_api(store, sid, via_ips, fn, api_factory=CloudflareAPI):
    """``fn(api)`` directly, or through a clean address if the API is blocked.

    Uses the server's own token when it has one, else the main token.
    """
    token = store.token_for(sid)
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


def with_zone(store, api, server, record, fn):
    """``fn(zone_id)`` for the zone ``record`` is in.

    The server's Zone ID, else the one remembered for this record, else a
    lookup. A wrong Zone ID (an Account ID pasted by mistake) or a stale
    remembered one falls back to the lookup.
    """
    configured = (server.get("zone_id") or "").strip()
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


def _record_or_fail(store, sid, cid):
    record = store.record(sid, cid)
    if not record:
        raise CFError("زیردامنهٔ «%s» برای سرور «%s» تنظیم نشده"
                      % (store.carrier(cid)["name"], store.server(sid)["name"]))
    return record


def read_record_ips(store, sid, cid, rtype, via_ips=(), api_factory=CloudflareAPI):
    record = _record_or_fail(store, sid, cid)
    server = store.server(sid)

    def fn(api):
        return with_zone(store, api, server, record,
                         lambda zone: [r["content"] for r in api.list_records(zone, record, rtype)])

    return with_api(store, sid, via_ips, fn, api_factory)[0]


def inspect_record(store, sid, cid, rtype, api_factory=CloudflareAPI):
    """(zone name, addresses, notes) for the Cloudflare check."""
    record = _record_or_fail(store, sid, cid)
    server = store.server(sid)

    def fn(api):
        def look(zone):
            ips, notes = api.inspect_record(zone, record, rtype)
            try:
                zone_name = api.zone_name(zone)
            except CFError:
                zone_name = ""
            return zone_name, ips, notes
        return with_zone(store, api, server, record, look)

    return with_api(store, sid, [], fn, api_factory)[0]


def apply_ips(store, sid, cid, ips, via_ips=(), kind="apply", note="", api_factory=CloudflareAPI):
    """Point the record of ``cid`` on server ``sid`` at ``ips``."""
    record = _record_or_fail(store, sid, cid)
    server = store.server(sid)
    if not ips:
        raise CFError("هیچ IP برای اعمال نیست")
    rtype = "AAAA" if ":" in ips[0] else "A"
    ttl = int(store.settings["ttl"])

    def fn(api):
        return with_zone(store, api, server, record,
                         lambda zone: api.sync_records(zone, record, ips, rtype, ttl))

    ops, via = with_api(store, sid, via_ips, fn, api_factory)
    with store.lock:
        st = store.state(sid, cid)
        old = list(st.get("current") or [])
        st["current"] = list(ips)
        st["status"] = "ok"
        st["checked_at"] = time.time()
        store.add_history(sid, cid, kind, old, ips, "via %s" % via if via else note)
        store.save()
    log("applied %s -> %s (%s)" % (record, ips, kind))
    return ops, via


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
    """One server x carrier run: check -> scan -> verify -> apply.

    ``mode``: ``auto`` scans only when the current address is broken,
    ``force`` scans anyway, ``check`` only re-checks the current address.
    """

    def __init__(self, store, sid, cid, events=None, mode="auto", context_factory=make_context,
                 api_factory=CloudflareAPI, candidates=None, rng=None,
                 probe_trace=trace_probe, probe_ws=ws_probe):
        self.store = store
        self.sid = sid
        self.cid = cid
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
        log("job start %s/%s mode=%s" % (self.sid, self.cid, self.mode))
        started = time.time()
        try:
            result = self._run()
        except (UserError, CFError, NetError, KeyError) as exc:
            result = {"kind": "error", "message": str(exc)}
        except Exception as exc:
            log("job crashed: %r" % (exc,))
            result = {"kind": "error", "message": "%s: %s" % (exc.__class__.__name__, exc)}
        result.setdefault("server", self.sid)
        result.setdefault("carrier", self.cid)
        result["elapsed"] = time.time() - started
        self.result = result
        self.running = False
        log("job end %s/%s: %s" % (self.sid, self.cid, result.get("kind")))
        self.events.finished(result)
        return result

    # -- the steps -------------------------------------------------------

    def _run(self):
        s = self.store.settings
        server = self.store.server(self.sid)
        record = self.store.record(self.sid, self.cid)
        target = Target.from_settings(server)
        if not target.sni:
            raise UserError("دامنهٔ CDN برای سرور «%s» خالی است" % server["name"])
        version = int(s["ip_version"])
        rtype = "AAAA" if version == 6 else "A"
        ctx = self.context_factory()
        use_ws = bool(target.path)
        has_token = bool(self.store.token_for(self.sid))
        result = {"kind": None, "server": self.sid, "carrier": self.cid, "record": record,
                  "current": [], "current_measure": [], "verified": [], "chosen": [],
                  "warning": "", "scanned": 0, "answered": 0, "errors": ""}

        # 1. the address the record has now
        self.events.step(0, "run")
        current = list(self.store.state(self.sid, self.cid).get("current") or [])
        if record and has_token:
            try:
                current = read_record_ips(self.store, self.sid, self.cid, rtype,
                                          api_factory=self.api_factory)
            except (CFError, NetError) as exc:
                self.events.note("خواندن رکورد از کلادفلر نشد: %s" % exc)
        current = [ip for ip in current if (":" in ip) == (version == 6)]
        result["current"] = current
        healthy = None
        if current:
            attempts = max(4, int(s["verify_attempts"]) // 2)
            ms = self._measure_many(current, target, ctx, attempts, use_ws)
            result["current_measure"] = ms
            healthy = all(is_healthy(m, s["max_loss_pct"], s["max_ping_ms"]) for m in ms)
            with self.store.lock:
                st = self.store.state(self.sid, self.cid)
                st.update(current=current, status="ok" if healthy else "bad",
                          checked_at=time.time(), ping=ms[0]["ping"],
                          detail=self._measure_text(ms[0]))
                if not healthy:
                    dead = [m["ip"] for m in ms if m["ok"] == 0]
                    self.store.remember_bad(self.cid, dead, forget_good=True)
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
            if self.mode == "check":
                self.store.add_history(self.sid, self.cid, "check", current, current,
                                       "سالم" if healthy else "خراب")
                self.store.save()
            return result

        # 2. fast pass over the candidates
        self.events.step(1, "run")
        mem = self.store.memory(self.cid)
        if self.fixed_candidates is not None:
            cands = list(self.fixed_candidates)
        else:
            cands = build_candidates(mem, int(s["candidates"]), version,
                                     self.store.ranges(version), rng=self.rng,
                                     bad_ttl_s=float(s["bad_ttl_hours"]) * 3600,
                                     exclude=current)
        started = time.time()
        answered, scanned, failed, errors = self._fast_pass(cands, target, ctx, s)
        result["scanned"], result["answered"] = scanned, len(answered)
        result["errors"] = error_summary(errors)
        locs = {r["loc"] for r in answered if r.get("loc")}
        if locs and "IR" not in locs:
            result["warning"] = ("به نظر VPN روشن است (موقعیت: %s). نتیجه مال این اینترنت نیست."
                                 % ", ".join(sorted(locs)))
            self.events.note(result["warning"])
        if answered:
            self.store.remember_bad(self.cid, failed)
        with self.store.lock:
            self.store.state(self.sid, self.cid)["last_scan"] = {
                "ts": time.time(), "scanned": scanned, "answered": len(answered),
                "seconds": round(time.time() - started, 1)}
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
            self.store.remember_good(self.cid, m["ip"], m["ping"], m["colo"])
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
        result["best"] = best
        self.events.step(2, "ok", "بهترین: %s  %s" % (best["ip"], self._measure_text(best)))

        # 4. the DNS record
        chosen = [m["ip"] for m in passing[:int(s["ips_per_record"])]]
        result["chosen"] = chosen
        result["via"] = [m["ip"] for m in passing]
        if current and sorted(current) == sorted(chosen):
            self.events.step(3, "ok", "رکورد همین IP را دارد")
            result["kind"] = "unchanged"
        elif not record or not has_token:
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
            ops, via = apply_ips(self.store, self.sid, self.cid, ips, result.get("via") or [],
                                 kind=kind, api_factory=self.api_factory)
        except (CFError, NetError) as exc:
            self.events.step(3, "fail", str(exc))
            result["kind"] = "apply_failed"
            result["message"] = str(exc)
            return False
        detail = "%s → %s" % (self.store.record(self.sid, self.cid), ", ".join(ips))
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
            return "پاسخ 404 گرفتیم: path این سرور با inbound یکی نیست."
        if verify and use_ws and any(code in joined for code in ("HTTP 52", "HTTP 50")):
            return "کلادفلر به سرور شما وصل نشد (خطای 5xx): سرور یا پورت را بررسی کنید."
        if "TLS" in joined or "reset" in joined:
            return "اتصال TLS قطع می‌شود؛ ممکن است SNI این سرور روی این اپراتور فیلتر باشد."
        if errors and all(e == "timeout" for e in errors):
            return "همه timeout شدند؛ اینترنت، حالت هواپیما یا روشن بودن VPN را بررسی کنید."
        return ""


RESULT_TEXT = {
    "healthy": "IP فعلی سالم است",
    "applied": "IP جدید اعمال شد",
    "unchanged": "بهترین IP همان قبلی است",
    "pending": "IP پیدا شد؛ «اعمال» را بزنید",
    "found": "IP پیدا شد (زیردامنه یا توکن تنظیم نشده)",
    "stopped": "متوقف شد",
    "broken": "IP فعلی خراب است",
    "unknown": "IP ثبت‌شده‌ای نیست",
    "nothing": "IP سالمی پیدا نشد",
    "apply_failed": "اعمال روی DNS نشد",
    "error": "خطا",
}
GOOD_KINDS = ("healthy", "applied", "unchanged", "pending", "found")


def result_line(result):
    """One Persian line for a finished run, for summaries and alerts."""
    kind = result.get("kind")
    text = RESULT_TEXT.get(kind, kind or "?")
    ips = result.get("chosen") or (result.get("current") if kind == "healthy" else [])
    if ips:
        text += ": " + ", ".join(ips)
    best = result.get("best")
    if best and best.get("ping") is not None and kind in ("applied", "pending", "unchanged", "found"):
        text += " · %.0fms %s" % (best["ping"], best.get("colo", ""))
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
ACCENT_BG = "#EEF2FC"
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

    def make_card(border=LINE, width=1):
        v = ui.View()
        v.background_color = CARD
        v.corner_radius = 18
        v.border_width = width
        v.border_color = border
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
        choice = dialogs.list_dialog(title, list(items))
        if choice is None:
            return None
        return list(items).index(choice)

    def text_field(key, title, value, kind="text"):
        return {"type": kind, "key": key, "title": title, "value": str(value),
                "autocorrection": False, "autocapitalization": ui.AUTOCAPITALIZE_NONE}

    STATUS_STYLE = {
        "ok": ("سالم", GOOD, GOOD_BG),
        "bad": ("قطع", BAD, BAD_BG),
        "unknown": ("بررسی نشده", NEUTRAL, NEUTRAL_BG),
        "unset": ("بدون زیردامنه", NEUTRAL, NEUTRAL_BG),
    }

    # ------------------------------------------------------------------ cards

    class CarrierCard(ui.View):
        HEIGHT = 172

        def __init__(self, app, sid, carrier):
            self.app = app
            self.sid = sid
            self.cid = carrier["id"]
            store = app.store
            record = store.record(sid, self.cid)
            st = store.state(sid, self.cid)
            status = st.get("status", "unknown") if record else "unset"
            text, fg, bg = STATUS_STYLE.get(status, STATUS_STYLE["unknown"])
            self.background_color = CARD
            self.corner_radius = 18
            self.border_width = 1.5 if status == "bad" else 1
            self.border_color = BAD if status == "bad" else LINE

            self.name_label = make_label(carrier["name"], 18, bold=True)
            self.record_label = make_label(record or "زیردامنه تنظیم نشده — «بیشتر» را بزنید",
                                           12, color=MUTED, mono=bool(record))
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
            last = st.get("last_scan")
            if last:
                info += " · اسکن: %d/%d در %.0f ثانیه" % (last["answered"], last["scanned"],
                                                         last["seconds"])
            self.info_label = make_label(info, 12, color=BAD if status == "bad" else MUTED)

            many = len(store.servers) > 1
            self.go = make_button("تست و اصلاح", self.tapped_go, primary=(status == "bad"),
                                  size=15)
            self.all = make_button("همه سرورها", self.tapped_all, size=14) if many else None
            self.more = make_button("بیشتر", self.tapped_more, size=14)
            for v in (self.name_label, self.record_label, self.pill, self.ip_label,
                      self.info_label, self.go, self.more, self.all):
                if v is not None:
                    self.add_subview(v)

        def layout(self):
            w = self.width
            self.pill.frame = (16, 16, 104, 26)
            self.name_label.frame = (128, 12, w - 144, 26)
            self.record_label.frame = (16, 44, w - 32, 18)
            self.ip_label.frame = (16, 70, w - 32, 22)
            self.info_label.frame = (16, 94, w - 32, 18)
            y, h = 124, 38
            if self.all is None:
                self.more.frame = (16, y, 80, h)
                self.go.frame = (104, y, w - 120, h)
            else:
                self.more.frame = (16, y, 70, h)
                self.all.frame = (94, y, 104, h)
                self.go.frame = (206, y, w - 222, h)

        def tapped_go(self, sender):
            self.app.start_scan([(self.sid, self.cid)], "auto")

        def tapped_all(self, sender):
            self.app.start_all_servers(self.cid)

        def tapped_more(self, sender):
            run_bg(self.app.carrier_menu, self.sid, self.cid)

    class MainView(ui.View):
        def __init__(self, app):
            self.app = app
            self.name = APP_NAME
            self.background_color = BG
            self.scroll = ui.ScrollView()
            self.scroll.always_bounce_vertical = True
            self.add_subview(self.scroll)

            self.server_card = make_card(border=ACCENT, width=1.5)
            self.server_caption = make_label("سرور فعال", 12, color=MUTED)
            self.server_name = make_label("", 20, bold=True)
            self.server_sni = make_label("", 12, color=MUTED, mono=True)
            self.server_btn = make_button("تغییر سرور", self.tapped_server, size=14)
            for v in (self.server_caption, self.server_name, self.server_sni, self.server_btn):
                self.server_card.add_subview(v)

            self.net_btn = ui.Button()
            self.net_btn.corner_radius = 14
            self.net_btn.font = ("<System-Bold>", 13)
            self.net_btn.action = lambda s: run_bg(self.app.check_connection)
            self.set_connection(None)

            self.empty = make_label("هنوز سروری ندارید. «افزودن سرور» را بزنید: دامنهٔ CDN، "
                                    "path و زیردامنهٔ هر اپراتور.", 15, color=MUTED, lines=4)
            self.empty_btn = make_button("افزودن سرور", lambda s: run_bg(self.app.edit_server, None),
                                         primary=True)
            self.footer = make_label("", 12, color=MUTED, align="center", lines=2)
            for v in (self.server_card, self.net_btn, self.empty, self.empty_btn, self.footer):
                self.scroll.add_subview(v)
            self.cards = []
            self.right_button_items = [
                ui.ButtonItem(title="ابزارها", action=lambda s: run_bg(self.app.open_tools)),
                ui.ButtonItem(title="تنظیمات", action=lambda s: run_bg(self.app.open_settings)),
            ]
            self.refresh()

        @on_main_thread
        def refresh(self):
            store = self.app.store
            for c in self.cards:
                self.scroll.remove_subview(c)
            server = store.active
            self.cards = []
            if server:
                self.cards = [CarrierCard(self.app, server["id"], c) for c in store.carriers]
                for c in self.cards:
                    self.scroll.add_subview(c)
                self.server_name.text = fa(server["name"])
                self.server_sni.text = "%s%s" % (server["sni"] or "(CDN domain?)",
                                                 "  " + server["path"] if server["path"] else "")
                count = len(store.servers)
                self.server_caption.text = fa("سرور فعال (%d از %d)" % (
                    [s["id"] for s in store.servers].index(server["id"]) + 1, count))
            self.server_card.hidden = server is None
            self.empty.hidden = self.empty_btn.hidden = server is not None
            s = store.settings
            if not store.secrets.get(None) and server and not store.secrets.get(server["id"]):
                self.footer.text = fa("توکن کلادفلر وارد نشده: «تنظیمات ← حساب کلادفلر».")
                self.footer.text_color = BAD
            else:
                self.footer.text = fa("IPv%d · %d کاندید · %s" % (
                    s["ip_version"], s["candidates"],
                    "اعمال خودکار" if s["auto_apply"] else "اعمال با تأیید"))
                self.footer.text_color = MUTED
            self.layout()

        @on_main_thread
        def set_connection(self, info):
            if info is None:
                text, fg, bg = "در حال بررسی اتصال…", NEUTRAL, NEUTRAL_BG
            elif not info["ok"]:
                text, fg, bg = "اینترنت در دسترس نیست (%s) — بزنید" % info["error"], BAD, BAD_BG
            elif info["loc"] and info["loc"] != "IR":
                text, fg, bg = "VPN روشن است (%s) — خاموشش کنید، بعد بزنید" % info["loc"], BAD, BAD_BG
            else:
                text, fg, bg = "✓ اینترنت ایران · %s · %s" % (info["ip"], info["colo"]), GOOD, GOOD_BG
            self.net_btn.title = fa(text)
            self.net_btn.tint_color = fg
            self.net_btn.background_color = bg

        def tapped_server(self, sender):
            run_bg(self.app.server_menu)

        def layout(self):
            w, h = self.width, self.height
            pad = 16
            inner = w - 2 * pad
            self.scroll.frame = (0, 0, w, h)
            y = 12
            if not self.server_card.hidden:
                self.server_card.frame = (pad, y, inner, 92)
                self.server_btn.frame = (12, 28, 104, 36)
                self.server_caption.frame = (124, 10, inner - 136, 18)
                self.server_name.frame = (124, 30, inner - 136, 28)
                self.server_sni.frame = (124, 60, inner - 136, 20)
                y += 104
            self.net_btn.frame = (pad, y, inner, 40)
            y += 52
            if not self.empty.hidden:
                self.empty.frame = (pad, y, inner, 90)
                self.empty_btn.frame = (pad, y + 96, inner, 48)
                y += 160
            for c in self.cards:
                c.frame = (pad, y, inner, CarrierCard.HEIGHT)
                y += CarrierCard.HEIGHT + 12
            self.footer.frame = (pad, y, inner, 40)
            y += 56
            self.scroll.content_size = (w, y)

    # ------------------------------------------------------------------ scan screen

    STEP_ICONS = {"wait": ("○", MUTED), "run": ("●", ACCENT), "ok": ("✓", GOOD),
                  "fail": ("✕", BAD), "skip": ("–", MUTED)}

    class ScanView(ui.View):
        """Runs one or more server x carrier jobs, one after the other.

        Implements the :class:`Events` methods the jobs call.
        """

        def __init__(self, app, targets, mode):
            self.app = app
            self.targets = list(targets)
            self.index = 0
            self.mode = mode
            self.summary = []
            self.rows = []
            self.result = None
            self.job = None
            self.started = time.time()
            carrier = app.store.carrier(self.targets[0][1])
            self.name = carrier["name"]
            self.background_color = BG

            self.scroll = ui.ScrollView()
            self.add_subview(self.scroll)
            self.batch_label = make_label("", 13, bold=True, color=ACCENT)
            self.server_label = make_label("", 16, bold=True)
            self.record_label = make_label("", 12, color=MUTED, mono=True)
            for v in (self.batch_label, self.server_label, self.record_label):
                self.scroll.add_subview(v)

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
            self.table_hint = make_label("روی هر ردیف بزنید تا همان IP را اعمال، کپی یا دوباره تست کنید.",
                                         12, color=MUTED, lines=2)
            self.table_hint.hidden = True
            for v in (self.outcome, self.notes, self.table_title, self.table, self.table_hint):
                self.scroll.add_subview(v)

            self.stop_btn = make_button("توقف", self.tapped_stop, color=BAD)
            self.apply_btn = make_button("اعمال روی DNS", self.tapped_apply, primary=True)
            self.copy_btn = make_button("کپی IP", self.tapped_copy)
            self.again_btn = make_button("اسکن دوباره", self.tapped_again)
            for v in (self.stop_btn, self.apply_btn, self.copy_btn, self.again_btn):
                self.add_subview(v)
            self.apply_btn.hidden = self.copy_btn.hidden = self.again_btn.hidden = True

        @property
        def batch(self):
            return len(self.targets) > 1

        @property
        def running(self):
            return self.job is not None and self.job.running

        def current_target(self):
            return self.targets[min(self.index, len(self.targets) - 1)]

        # -- running ------------------------------------------------------

        def start(self):
            console.set_idle_timer_disabled(True)
            self._begin(0)

        @on_main_thread
        def _begin(self, index):
            self.index = index
            sid, cid = self.targets[index]
            store = self.app.store
            server = store.server(sid)
            self.server_label.text = fa("سرور: %s" % server["name"])
            self.record_label.text = store.record(sid, cid) or server["sni"]
            self.batch_label.text = fa("سرور %d از %d" % (index + 1, len(self.targets))) \
                if self.batch else ""
            for icon, name, detail in self.step_views:
                icon.text, icon.text_color = STEP_ICONS["wait"]
                name.text_color = MUTED
                detail.text = ""
            self.fraction = 0.0
            self.counter.text = ""
            self.rows = []
            self.ds.items = []
            self.table_title.text = fa("بهترین‌ها تا این لحظه")
            self.job = ScanJob(store, sid, cid, events=self, mode=self.mode)
            self.layout()
            threading.Thread(target=self.job.run, name="job", daemon=True).start()

        def layout(self):
            w, h = self.width, self.height
            pad = 16
            inner = w - 2 * pad
            bottom = 76
            self.scroll.frame = (0, 0, w, h - bottom)
            y = 8
            if self.batch:
                self.batch_label.frame = (pad, y, inner, 20)
                y += 22
            self.server_label.frame = (pad, y, inner, 22)
            self.record_label.frame = (pad, y + 22, inner, 18)
            y += 48
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
            y += table_h + 6
            self.table_hint.frame = (pad, y, inner, 34)
            y += 44
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
            self.counter.text = fa("%d / %d بررسی شد · %d پاسخ · %d ثانیه" % (
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
            sid, cid = self.targets[self.index]
            if result.get("hint") or (result.get("kind") in ("error", "apply_failed")
                                      and result.get("message")):
                self.note(result.get("hint") or result["message"])
            if self.batch:
                self.summary.append((sid, result))
                if self.index + 1 < len(self.targets) and result.get("kind") != "stopped":
                    self._begin(self.index + 1)
                    return
            self._done()

        def _done(self):
            console.set_idle_timer_disabled(False)
            self.stop_btn.hidden = True
            self.again_btn.hidden = False
            store = self.app.store
            if self.batch:
                self.batch_label.text = fa("%d سرور بررسی شد" % len(self.summary))
                lines = []
                ok = 0
                for sid, r in self.summary:
                    ok += r.get("kind") in GOOD_KINDS
                    lines.append(fa("%s: %s" % (store.server(sid)["name"], result_line(r))))
                self.rows = []
                self.ds.items = lines
                self.ds.font = ("<System>", 13)
                self.table.row_height = 52
                self.table_title.text = fa("نتیجهٔ همهٔ سرورها")
                self.table_hint.hidden = True
                good = ok == len(self.summary)
                self._show_outcome("%d از %d سرور درست شد" % (ok, len(self.summary)), good)
                self.copy_btn.hidden = True
                self.apply_btn.hidden = True
            else:
                r = self.result or {}
                kind = r.get("kind")
                self.copy_btn.hidden = not (r.get("chosen") or r.get("verified"))
                self.apply_btn.hidden = kind not in ("pending", "apply_failed")
                self.table_hint.hidden = not r.get("verified")
                self._show_outcome(result_line(r), kind in GOOD_KINDS)
            seconds = time.time() - self.started
            console.hud_alert("تمام شد · %.0f ثانیه" % seconds, "success", 1.2)
            self.layout()
            self.app.main.refresh()

        def _show_outcome(self, text, good):
            self.outcome.text = fa(text)
            self.outcome.text_color = GOOD if good else BAD
            self.outcome.background_color = GOOD_BG if good else BAD_BG
            self.outcome.hidden = False

        # -- buttons ------------------------------------------------------

        def tapped_stop(self, sender):
            if self.job is not None:
                self.job.cancel()
            sender.enabled = False
            sender.title = "در حال توقف…"

        def tapped_again(self, sender):
            self.app.restart_scan(self.targets, "force")

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
            r = self.result or {}
            self._show_outcome(result_line(r), ok)
            console.hud_alert("اعمال شد" if ok else "اعمال نشد", "success" if ok else "error")
            self.layout()
            self.app.main.refresh()

        def row_tapped(self, ds):
            index = ds.selected_row
            if self.running or self.batch or index < 0 or index >= len(self.rows):
                return
            run_bg(self._row_menu, self.rows[index])

        def _row_menu(self, row):
            ip = row["ip"]
            sid, cid = self.current_target()
            store = self.app.store
            choice = pick(ip, ["اعمال همین IP روی رکورد", "کپی IP", "تست دوباره (۱۰ بار)"])
            if choice == 1:
                clipboard.set(ip)
                console.hud_alert("کپی شد")
            elif choice == 0:
                if alert("اعمال", "رکورد %s روی %s تنظیم شود؟" % (store.record(sid, cid), ip),
                         "اعمال") == 1:
                    self._apply_flow([ip])
            elif choice == 2:
                self.app.test_ip_flow(ip, sid, cid)

    class HistoryView(ui.View):
        def __init__(self, app, sid=None, cid=None):
            self.name = "تاریخچه"
            self.background_color = BG
            store = app.store
            servers = {s["id"]: s["name"] for s in store.servers}
            carriers = {c["id"]: c["name"] for c in store.carriers}
            kinds = {"apply": "تغییر", "manual": "دستی", "rollback": "برگشت", "check": "بررسی"}
            items = []
            for h in store.history(sid, cid):
                when = time.strftime("%m/%d %H:%M", time.localtime(h.get("ts", 0)))
                old = ",".join(h.get("old") or []) or "—"
                new = ",".join(h.get("new") or []) or "—"
                change = ("%s %s" % (new, h.get("note", "")) if h.get("kind") == "check"
                          else "%s → %s" % (old, new))
                items.append(fa("%s · %s · %s · %s · %s" % (
                    when, servers.get(h.get("server"), "?"), carriers.get(h.get("carrier"), "?"),
                    kinds.get(h.get("kind"), h.get("kind")), change)))
            self.table = ui.TableView()
            self.ds = ui.ListDataSource(items or [fa("هنوز چیزی ثبت نشده")])
            self.ds.font = ("<System>", 13)
            self.table.data_source = self.table.delegate = self.ds
            self.table.row_height = 52
            self.table.allows_selection = False
            self.add_subview(self.table)

        def layout(self):
            self.table.frame = (0, 0, self.width, self.height)

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
            if not self.store.servers or not self.store.secrets.get(None):
                run_bg(self.first_run)

        # -- navigation (main thread) ------------------------------------

        @on_main_thread
        def push(self, view_class, *args):
            """Build the view on the main thread, then show it."""
            self.nav.push_view(view_class(self, *args))

        @on_main_thread
        def start_scan(self, targets, mode):
            targets = [t for t in targets if self.store.server(t[0])]
            if not targets:
                return
            if self.active_scan is not None and self.active_scan.running:
                if self.active_scan.targets == targets:
                    self.nav.push_view(self.active_scan)
                else:
                    console.hud_alert("یک اسکن دیگر در حال اجراست", "error")
                return
            view = ScanView(self, targets, mode)
            self.active_scan = view
            self.nav.push_view(view)
            view.start()

        @on_main_thread
        def restart_scan(self, targets, mode):
            self.nav.pop_view()
            ui.delay(lambda: self.start_scan(targets, mode), 0.5)

        def start_all_servers(self, cid):
            targets = [(s["id"], cid) for s in self.store.servers if s["records"].get(cid)]
            if not targets:
                console.hud_alert("هیچ سروری برای این اپراتور زیردامنه ندارد", "error")
                return
            self.start_scan(targets, "auto")

        # -- flows (background threads) ----------------------------------

        def check_connection(self):
            self.main.set_connection(None)
            self.main.set_connection(connection_check())

        def first_run(self):
            alert("خوش آمدید",
                  "سه قدم:\n۱. توکن API کلادفلر\n۲. یک سرور: دامنهٔ CDN (SNI) و path\n"
                  "۳. زیردامنهٔ هر اپراتور برای آن سرور (پیشنهاد خودکار دارد)")
            if not self.store.secrets.get(None):
                self.edit_token(None)
            if not self.store.servers:
                self.edit_server(None)

        def open_settings(self):
            server = self.store.active
            items = ["حساب کلادفلر (توکن اصلی)", "تنظیمات اسکن و DNS",
                     "سرورها", "اپراتورها"]
            if server:
                items.insert(0, "ویرایش سرور «%s»" % server["name"])
            index = pick("تنظیمات", items)
            if index is None:
                return
            if server:
                index -= 1
            if index == -1:
                self.edit_server(server["id"])
            elif index == 0:
                self.edit_token(None)
            elif index == 1:
                self.edit_scan_settings()
            elif index == 2:
                self.manage_servers()
            elif index == 3:
                self.manage_carriers()

        def edit_token(self, sid):
            label = "توکن اصلی" if sid is None else "توکن جدا برای «%s»" % self.store.server(sid)["name"]
            has = bool(self.store.secrets.get(sid))
            fields = [{"type": "password", "key": "token",
                       "title": "API Token (%s)" % ("ذخیره شده" if has else "خالی"), "value": ""}]
            values = dialogs.form_dialog(label, sections=[(label, fields,
                "توکن فقط در Keychain آیفون ذخیره می‌شود. خالی = بدون تغییر، «-» = پاک کردن. "
                "دسترسی لازم: Zone → DNS → Edit (و بهتر است Zone → Zone → Read).")],
                done_button_title="ذخیره")
            if values is None:
                return
            raw = (values.get("token") or "").strip()
            if not raw:
                return
            if raw == "-":
                self.store.secrets.set("", sid)
                console.hud_alert("پاک شد")
            else:
                token = sanitize_token(raw)
                problem = token_problem(token)
                if problem:
                    alert("توکن", problem)
                    return
                self.store.secrets.set(token, sid)
                console.hud_alert("ذخیره شد")
                if sid or self.store.active:
                    self.test_cloudflare(sid)
            self.main.refresh()

        def edit_scan_settings(self):
            s = self.store.settings
            sections = [
                ("DNS", [
                    text_field("ttl", "TTL (ثانیه)", s["ttl"], "number"),
                    text_field("ips_per_record", "تعداد IP در رکورد (۱ تا ۳)", s["ips_per_record"], "number"),
                    {"type": "switch", "key": "auto_apply", "title": "اعمال خودکار بعد از تست",
                     "value": s["auto_apply"]},
                ], "با چند IP در رکورد، اگر یکی بسته شود کلاینت‌ها معمولاً بعدی را امتحان می‌کنند."),
                ("اسکن", [
                    text_field("candidates", "تعداد کاندید", s["candidates"], "number"),
                    text_field("workers", "تست همزمان", s["workers"], "number"),
                    text_field("timeout", "مهلت هر اتصال (ثانیه)", s["timeout"], "number"),
                    text_field("stop_after", "توقف بعد از N پاسخ (۰=همه)", s["stop_after"], "number"),
                    text_field("verify_top", "تعداد IP برای تأیید دقیق", s["verify_top"], "number"),
                    text_field("verify_attempts", "تلاش برای هر IP", s["verify_attempts"], "number"),
                    text_field("max_loss_pct", "حداکثر افت مجاز (٪)", s["max_loss_pct"], "number"),
                    text_field("max_ping_ms", "حداکثر پینگ سالم (ms)", s["max_ping_ms"], "number"),
                    text_field("colos", "فقط این دیتاسنترها (مثلاً FRA,AMS)", s["colos"]),
                    {"type": "switch", "key": "ip_version", "title": "IPv6 به جای IPv4",
                     "value": s["ip_version"] == 6},
                    text_field("bad_ttl_hours", "نادیده گرفتن IPهای بد (ساعت)", s["bad_ttl_hours"], "number"),
                ]),
            ]
            values = dialogs.form_dialog("تنظیمات اسکن", sections=sections, done_button_title="ذخیره")
            if values is None:
                return
            values["ip_version"] = 6 if values.get("ip_version") else 4
            try:
                self.store.update_settings(values)
            except ValueError as exc:
                alert("مقدار نامعتبر", str(exc))
                return self.edit_scan_settings()
            self.main.refresh()
            console.hud_alert("ذخیره شد")

        def edit_server(self, sid):
            store = self.store
            server = store.server(sid) if sid else dict(SERVER_DEFAULTS, records={})
            record_fields = []
            for c in store.carriers:
                value = server["records"].get(c["id"], "")
                record_fields.append(text_field("rec:" + c["id"], c["name"], value))
            sections = [
                ("سرور", [
                    text_field("name", "نام (مثلاً آلمان ۱)", server["name"]),
                    text_field("sni", "دامنهٔ CDN (SNI و Host)", server["sni"]),
                    text_field("path", "WebSocket path", server["path"]),
                    text_field("port", "پورت", server["port"], "number"),
                    {"type": "switch", "key": "tls", "title": "TLS", "value": server["tls"]},
                ], "همان مقادیری که در هاست‌های پنل برای این سرور است."),
                ("زیردامنهٔ هر اپراتور (ابر خاکستری)", record_fields,
                 "خالی بگذارید تا از الگوی پیشوند اپراتور + دامنهٔ CDN پیشنهاد شود، "
                 "مثلاً mtn.cdn.example.com."),
                ("کلادفلر (اختیاری)", [
                    text_field("zone_id", "Zone ID", server["zone_id"]),
                    {"type": "password", "key": "token",
                     "title": "توکن جدا (%s)" % ("دارد" if sid and store.secrets.get(sid)
                                                  else "از توکن اصلی"), "value": ""},
                ], "فقط اگر دامنهٔ این سرور در حساب کلادفلر دیگری است توکن جدا بدهید."),
            ]
            title = "ویرایش سرور" if sid else "سرور جدید"
            values = dialogs.form_dialog(title, sections=sections, done_button_title="ذخیره")
            if values is None:
                return
            records = {k[4:]: v for k, v in values.items() if k.startswith("rec:")}
            token = (values.pop("token", "") or "").strip()
            if not normalise_host(values.get("sni")):
                alert("دامنهٔ CDN", "دامنهٔ CDN (SNI) را وارد کنید.")
                return self.edit_server(sid)
            try:
                new_sid = store.save_server(sid, values, records)
            except ValueError as exc:
                alert("مقدار نامعتبر", str(exc))
                return self.edit_server(sid)
            missing = [c for c in store.carriers
                       if not store.record(new_sid, c["id"]) and store.suggest_record(new_sid, c["id"])]
            if missing:
                preview = "\n".join(store.suggest_record(new_sid, c["id"]) for c in missing)
                if alert("زیردامنه‌ها", "این‌ها ثبت شوند؟\n" + preview, "بله") == 1:
                    store.save_server(new_sid, {}, {c["id"]: store.suggest_record(new_sid, c["id"])
                                                    for c in missing})
            if token == "-":
                store.secrets.set("", new_sid)
            elif token:
                store.secrets.set(sanitize_token(token), new_sid)
            if sid is None:
                store.set_active(new_sid)
            self.main.refresh()
            console.hud_alert("ذخیره شد")
            if store.token_for(new_sid) and alert("تست", "اتصال به کلادفلر و رکوردها بررسی شود؟",
                                                   "بررسی") == 1:
                self.test_cloudflare(new_sid)

        def server_menu(self):
            store = self.store
            servers = store.servers
            active = store.active
            items = [("● " if active and s["id"] == active["id"] else "") + "%s — %s" % (s["name"], s["sni"])
                     for s in servers]
            items += ["+ سرور جدید", "مدیریت سرورها"]
            index = pick("سرور", items)
            if index is None:
                return
            if index < len(servers):
                store.set_active(servers[index]["id"])
                self.main.refresh()
            elif index == len(servers):
                self.edit_server(None)
            else:
                self.manage_servers()

        def manage_servers(self):
            store = self.store
            while True:
                servers = store.servers
                items = ["%s — %s" % (s["name"], s["sni"]) for s in servers] + ["+ سرور جدید"]
                index = pick("سرورها", items)
                if index is None:
                    break
                if index == len(servers):
                    self.edit_server(None)
                    continue
                sid = servers[index]["id"]
                action = pick(servers[index]["name"], ["فعال کردن", "ویرایش", "تکثیر (کپی)",
                                                      "توکن جدا", "حذف"])
                if action == 0:
                    store.set_active(sid)
                elif action == 1:
                    self.edit_server(sid)
                elif action == 2:
                    src = store.server(sid)
                    copy_values = {k: src[k] for k in SERVER_DEFAULTS}
                    copy_values["name"] = src["name"] + " (کپی)"
                    store.save_server(None, copy_values, {})
                    console.hud_alert("کپی شد؛ دامنه و زیردامنه‌ها را ویرایش کنید")
                elif action == 3:
                    self.edit_token(sid)
                elif action == 4:
                    if alert("حذف", "سرور «%s» حذف شود؟ رکوردهای DNS دست نمی‌خورند."
                             % servers[index]["name"], "حذف") == 1:
                        store.delete_server(sid)
            self.main.refresh()

        def manage_carriers(self):
            store = self.store
            while True:
                carriers = store.carriers
                items = ["%s — پیشوند %s" % (c["name"], c["prefix"] or "ندارد") for c in carriers]
                items.append("+ اپراتور جدید")
                index = pick("اپراتورها", items)
                if index is None:
                    break
                cid = None if index == len(carriers) else carriers[index]["id"]
                c = store.carrier(cid) if cid else {"name": "", "prefix": ""}
                fields = [text_field("name", "نام (مثلاً رایتل)", c["name"]),
                          text_field("prefix", "پیشوند زیردامنه (مثلاً rtl)", c["prefix"])]
                if cid:
                    fields.append({"type": "switch", "key": "delete", "title": "حذف این اپراتور",
                                   "value": False})
                values = dialogs.form_dialog("اپراتور", fields, done_button_title="ذخیره")
                if values is None:
                    continue
                if cid and values.get("delete"):
                    if alert("حذف", "«%s» از همهٔ سرورها حذف شود؟ رکوردهای DNS دست نمی‌خورند."
                             % c["name"], "حذف") == 1:
                        store.delete_carrier(cid)
                    continue
                store.save_carrier(cid, values.get("name", ""), values.get("prefix", ""))
            self.main.refresh()

        def carrier_menu(self, sid, cid):
            store = self.store
            carrier = store.carrier(cid)
            items = ["فقط بررسی IP فعلی", "اسکن کامل (حتی اگر سالم است)",
                     "اصلاح برای همهٔ سرورها", "تنظیم IP دستی", "برگرداندن IP قبلی",
                     "IPهای خوب ذخیره‌شده", "تاریخچه", "ویرایش زیردامنه"]
            index = pick("%s · %s" % (carrier["name"], store.server(sid)["name"]), items)
            if index == 0:
                self.start_scan([(sid, cid)], "check")
            elif index == 1:
                self.start_scan([(sid, cid)], "force")
            elif index == 2:
                self.start_all_servers(cid)
            elif index == 3:
                text = console.input_alert("IP دستی", "یک یا چند IP، با کاما جدا کنید", "", "اعمال")
                ips = [x.strip() for x in text.replace(" ", ",").split(",") if x.strip()]
                self._apply_manual(sid, cid, ips, "manual")
            elif index == 4:
                old = store.previous_ips(sid, cid)
                if not old:
                    alert("برگرداندن", "IP قبلی برای این رکورد ثبت نشده.")
                elif alert("برگرداندن", "رکورد به %s برگردد؟" % ", ".join(old), "برگردان") == 1:
                    self._apply_manual(sid, cid, old, "rollback")
            elif index == 5:
                self.good_list(sid, cid)
            elif index == 6:
                self.push(HistoryView, sid, cid)
            elif index == 7:
                current = store.record(sid, cid) or store.suggest_record(sid, cid)
                value = console.input_alert("زیردامنهٔ %s" % carrier["name"],
                                            "برای سرور «%s»" % store.server(sid)["name"],
                                            current, "ذخیره")
                store.save_server(sid, {}, {cid: value})
                self.main.refresh()

        def _apply_manual(self, sid, cid, ips, kind):
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
                apply_ips(self.store, sid, cid, ips, kind=kind)
            except (CFError, NetError) as exc:
                alert("اعمال نشد", str(exc))
                return
            finally:
                console.hide_activity()
            self.main.refresh()
            console.hud_alert("اعمال شد")

        def good_list(self, sid, cid):
            good = sorted(self.store.memory(cid)["good"].items(), key=lambda kv: -kv[1].get("ts", 0))
            if not good:
                alert("IPهای خوب", "هنوز IP خوبی برای این اپراتور ذخیره نشده.")
                return
            items = ["%s  %sms  %s  %s" % (ip, "%.0f" % g["ping"] if g.get("ping") else "?",
                                            g.get("colo", ""), ago(g.get("ts")))
                     for ip, g in good[:60]]
            index = pick("IPهای خوب %s" % self.store.carrier(cid)["name"], items)
            if index is None:
                return
            ip = good[index][0]
            if alert(ip, "دوباره تست شود یا مستقیم اعمال شود؟", "تست", "اعمال مستقیم") == 2:
                self._apply_manual(sid, cid, [ip], "manual")
            else:
                self.test_ip_flow(ip, sid, cid)

        def test_ip_flow(self, ip, sid=None, cid=None):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                alert("IP نامعتبر", ip)
                return
            store = self.store
            server = store.server(sid) if sid else store.active
            if not server or not server["sni"]:
                alert("سرور", "اول یک سرور با دامنهٔ CDN بسازید.")
                return
            s = store.settings
            target = Target.from_settings(server)
            console.show_activity()
            try:
                trace = trace_probe(ip, target, make_context(), float(s["timeout"]) + 1)
                m = measure(ip, target, make_context(), 10, float(s["timeout"]) + 1,
                            bool(target.path))
            finally:
                console.hide_activity()
            lines = ["سرور: %s" % server["name"],
                     "دیتاسنتر: %s" % (trace.get("colo") or "—"),
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
            if cid:
                store.remember_good(cid, ip, m["ping"], trace.get("colo", ""))
                store.save()
            targets = [c for c in store.carriers if server["records"].get(c["id"])]
            if not targets or alert(ip, "\n".join(lines), "اعمال روی یک اپراتور") != 1:
                return
            if cid is None:
                index = pick("روی کدام اپراتور؟", [c["name"] for c in targets])
                if index is None:
                    return
                cid = targets[index]["id"]
            self._apply_manual(server["id"], cid, [ip], "manual")

        def test_cloudflare(self, sid=None):
            store = self.store
            server = store.server(sid) if sid else store.active
            if server is None:
                alert("کلادفلر", "اول یک سرور بسازید.")
                return
            sid = server["id"]
            token = store.token_for(sid)
            problem = token_problem(token)
            if problem:
                alert("کلادفلر", problem)
                return
            console.show_activity()
            lines = ["سرور: %s" % server["name"],
                     "توکن: %s%s" % (token_fingerprint(token),
                                     " (جدا)" if store.secrets.get(sid) else "")]
            try:
                try:
                    info, via = with_api(store, sid, [], lambda api: api.verify_token())
                    kind = "توکن حساب" if (info or {}).get("kind") == "account" else "توکن کاربر"
                    lines.append("وضعیت: %s (%s)" % ((info or {}).get("status", "?"), kind))
                except (CFError, NetError) as exc:
                    lines.append("وضعیت: خطا (%s)" % exc)
                    alert("تست کلادفلر", "\n".join(lines))
                    return
                rtype = "AAAA" if store.settings["ip_version"] == 6 else "A"
                for c in store.carriers:
                    record = server["records"].get(c["id"])
                    if not record:
                        lines.append("%s: زیردامنه ندارد" % c["name"])
                        continue
                    try:
                        zone_name, ips, notes = inspect_record(store, sid, c["id"], rtype)
                        line = "%s (%s): %s" % (c["name"], record,
                                                ", ".join(ips) or "بدون رکورد %s" % rtype)
                        if zone_name:
                            line += "\n  دامنه: %s" % zone_name
                        for n in notes:
                            line += "\n  ⚠ %s" % n
                        lines.append(line)
                    except (CFError, NetError) as exc:
                        lines.append("%s (%s): خطا — %s" % (c["name"], record, exc))
                store.save()
            finally:
                console.hide_activity()
            alert("تست کلادفلر", "\n".join(lines))

        def open_tools(self):
            items = [
                "تاریخچهٔ تغییرات",
                "تست یک IP دلخواه",
                "تست اتصال به کلادفلر (سرور فعال)",
                "بررسی دوبارهٔ اتصال اینترنت",
                "به‌روزرسانی رنج IP کلادفلر",
                "پاک کردن حافظهٔ IPهای بد",
                "کپی همهٔ تنظیمات (بدون توکن)",
                "وارد کردن تنظیمات از کلیپ‌بورد",
                "کپی لاگ برای گزارش خطا",
            ]
            index = pick("ابزارها", items)
            if index == 0:
                self.push(HistoryView)
            elif index == 1:
                ip = console.input_alert("تست یک IP", "آدرس IP کلادفلر (با سرور فعال تست می‌شود)",
                                         "", "تست").strip()
                self.test_ip_flow(ip)
            elif index == 2:
                self.test_cloudflare()
            elif index == 3:
                self.check_connection()
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

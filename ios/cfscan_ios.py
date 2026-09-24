# -*- coding: utf-8 -*-
"""CF Scanner for iPhone - keeps each server's CDN address records clean.

Runs inside Pythonista 3 on the iPhone. Every CDN server (Germany, Turkey...)
has two DNS-only address records its CDN configs use as their address:

* ``record_mobile`` (``cdn1.germany.example.com``) for the mobile networks,
  MCI and Irancell, which can be tested any time,
* ``record_home`` (``cdn2.germany.example.com``, optional) for home
  internet, which can only be tested now and then.

Pick the server; the network is detected from the phone's ASN (Cloudflare's
``/meta``). "Scan" then, on this network only:

1. stops if the phone is not seen in Iran (VPN on),
2. re-measures the addresses the server's record for this network's group
   holds, as a client's "real delay" through the VLESS tunnel when the
   server's link is set; if they all pass, nothing changes,
3. otherwise scans Cloudflare addresses - first the ones working for this
   server on the group's other network, then the ones other servers found
   here, then known-good ones and their /24 neighbours, then random ones,
4. picks addresses that work here and never ones known to fail on the
   group's other network; ones not yet tested there are flagged,
5. writes the record through the Cloudflare API.

A mobile scan never touches the home record and a home scan never touches
the mobile one. Results are kept per server (address x network), because
the delay through Cloudflare to Germany is not the delay to Turkey.

Secrets: the Cloudflare API token and each server's VLESS uuid live in the
iOS Keychain, never in the data file ``cfscan_ios_data.json``.
``cfscan_ios_log.txt`` holds a step log for bug reports.

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
import uuid as uuid_module

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
APP_VERSION = "5.0"

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
    "zone_id": "",          # optional; looked up from the record name when empty
    "ttl": 60,
    "ips_per_record": 2,
    "auto_apply": True,
    "fresh_hours": 48,      # how long a result counts for the other network of a group
    "candidates": 500,
    "workers": 32,
    "timeout": 2.0,
    "stop_after": 25,       # stop the fast pass after this many answers (0 = all)
    "verify_top": 6,
    "verify_attempts": 6,
    "max_loss_pct": 0,
    "max_ping_ms": 1500,    # slowest config delay that still counts as healthy
    "min_gain_pct": 20,     # a forced scan replaces working addresses only when this much faster
    "colos": "",            # allowed datacentres, e.g. "FRA,AMS"; empty = any
    "ip_version": 4,
    "bad_ttl_hours": 6,
}

GROUPS = ("mobile", "home")
GROUP_NAMES = {"mobile": "موبایل", "home": "خانگی"}

#: A CDN server; its VLESS uuid is kept in the Keychain.
SERVER_DEFAULTS = {
    "name": "",
    "sni": "",              # CDN domain (orange cloud): SNI and Host header
    "host": "",             # Host header when it differs from the SNI
    "path": "",             # WebSocket path of the config
    "port": 443,
    "tls": True,
    "record_mobile": "",    # DNS-only address record for MCI / Irancell
    "record_home": "",      # optional DNS-only address record for home internet
}

_ALL_DEFAULTS = dict(SERVER_DEFAULTS)
_ALL_DEFAULTS.update(DEFAULT_SETTINGS)

#: (minimum, maximum) for every numeric setting.
SETTING_LIMITS = {
    "port": (1, 65535), "ttl": (60, 86400), "ips_per_record": (1, 3),
    "fresh_hours": (1, 168), "candidates": (20, 5000), "workers": (1, 128),
    "timeout": (0.5, 10.0), "stop_after": (0, 1000), "verify_top": (1, 20),
    "verify_attempts": (2, 30), "max_loss_pct": (0, 50), "max_ping_ms": (50, 5000),
    "min_gain_pct": (0, 90), "ip_version": (4, 6), "bad_ttl_hours": (0, 168),
}

DEFAULT_NETWORKS = [
    {"id": "mci", "name": "همراه اول", "group": "mobile", "asns": [197207]},
    {"id": "mtn", "name": "ایرانسل", "group": "mobile", "asns": [44244]},
    {"id": "home", "name": "خانگی", "group": "home", "asns": []},
]

#: Suggestions when an unknown ASN is seen: (name, group).
KNOWN_ASNS = {
    197207: ("همراه اول", "mobile"),
    44244: ("ایرانسل", "mobile"),
    57218: ("رایتل", "mobile"),
    58224: ("مخابرات", "home"),
    31549: ("شاتل", "home"),
    43754: ("آسیاتک", "home"),
    16322: ("پارس‌آنلاین", "home"),
    50810: ("مبین‌نت", "home"),
}

HISTORY_LIMIT = 400
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
    if key in ("sni", "host", "record_mobile", "record_home"):
        return normalise_host(value)
    if key == "path":
        return normalise_path(value)
    return str(value).strip()


def suggest_record(sni, prefix="cdn1"):
    """``cdn1.germany.example.com`` from the CDN domain ``germany.example.com``."""
    sni = normalise_host(sni)
    return "%s.%s" % (prefix, sni) if sni.count(".") >= 1 else ""


def slot_key(sid, group):
    """The key a server's record is stored under: ``s1:mobile`` or ``s1:home``."""
    return "%s:%s" % (sid, group)


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


def _network(raw):
    nid, name = str(raw["id"]), str(raw.get("name") or raw["id"])
    group = raw.get("group")
    if group not in GROUPS:
        known = [g for n, g in KNOWN_ASNS.values() if n == name]
        default = [n["group"] for n in DEFAULT_NETWORKS if n["id"] == nid]
        group = (default or known or ["home" if "خانگی" in name else "mobile"])[0]
    asns = raw.get("asns")
    if not isinstance(asns, list):
        asns = [a for n in DEFAULT_NETWORKS if n["id"] == nid for a in n["asns"]]
    return {"id": nid, "name": name, "group": group,
            "asns": [int(a) for a in asns if str(a).isdigit()]}


def _cell(raw):
    raw = raw if isinstance(raw, dict) else {}
    delay = raw.get("delay", raw.get("ping"))
    return {"ok": bool(raw.get("ok")), "delay": delay, "colo": raw.get("colo", "") or "",
            "ts": raw.get("ts", 0) or 0}


def normalise_data(raw):
    """A complete version-5 document from whatever was stored.

    Every older layout is migrated:

    * 1: one CDN domain in the settings, carriers as ``profiles``;
    * 2: servers with a record per carrier, per-carrier good/bad memory;
    * 3: one app-wide ``ip1``/``ip2`` record, one coverage table;
    * 4: ``record``/``record2`` per server, one coverage table.

    Records become ``record_mobile``/``record_home``; the one coverage table
    is copied to every server without its numbers (they were not taken
    through that server), keeping whether each address worked.
    """
    raw = raw if isinstance(raw, dict) else {}
    version = raw.get("version") or (1 if "profiles" in raw else 5)
    raw_settings = raw.get("settings") if isinstance(raw.get("settings"), dict) else {}

    settings = dict(DEFAULT_SETTINGS)
    for key, value in raw_settings.items():
        if key in DEFAULT_SETTINGS:
            try:
                settings[key] = _coerce(key, value)
            except (TypeError, ValueError):
                pass
    if version < 4 and raw_settings.get("max_ping_ms") in (800, "800"):
        settings["max_ping_ms"] = DEFAULT_SETTINGS["max_ping_ms"]  # was a TCP ping limit
    if version == 2 and not settings["zone_id"]:
        zones = [s.get("zone_id") for s in raw.get("servers") or []
                 if isinstance(s, dict) and s.get("zone_id")]
        settings["zone_id"] = str(zones[0]).strip() if zones else ""

    # servers
    if version == 1:
        server_list = [dict(raw_settings, id="s1")] if raw_settings.get("sni") else []
    else:
        server_list = [dict(s) for s in raw.get("servers") or [] if isinstance(s, dict)]
    for s in server_list:
        if version == 4:
            s.setdefault("record_mobile", s.get("record", ""))
            s.setdefault("record_home", s.get("record2", ""))
    if version == 3 and server_list:
        server_list[0].setdefault("record_mobile", raw_settings.get("ip1", ""))
        server_list[0].setdefault("record_home", raw_settings.get("ip2", ""))
    servers, ids = [], set()
    for i, s in enumerate(server_list, 1):
        server = _server(s, i)
        if server["id"] not in ids:
            ids.add(server["id"])
            servers.append(server)
    first = servers[0]["id"] if servers else None

    # networks
    net_list = {1: raw.get("profiles"), 2: raw.get("carriers")}.get(version, raw.get("networks"))
    networks, seen = [], set()
    for n in net_list or copy.deepcopy(DEFAULT_NETWORKS):
        if isinstance(n, dict) and n.get("id") and str(n["id"]) not in seen:
            seen.add(str(n["id"]))
            networks.append(_network(n))
    if not networks:
        networks = copy.deepcopy(DEFAULT_NETWORKS)

    # coverage: server -> address -> network -> cell
    matrix = {}
    if version >= 5:
        for sid, table in (raw.get("matrix") or {}).items():
            if sid in ids and isinstance(table, dict):
                matrix[sid] = {ip: {nid: _cell(c) for nid, c in cells.items()}
                               for ip, cells in table.items() if isinstance(cells, dict)}
    else:
        flat = {}
        if version in (3, 4):
            flat = {ip: cells for ip, cells in (raw.get("matrix") or {}).items()
                    if isinstance(cells, dict)}
        memory = {1: raw.get("state"), 2: raw.get("memory")}.get(version) or {}
        for nid, mem in memory.items():
            for ip, g in ((mem or {}).get("good") or {}).items() if isinstance(mem, dict) else ():
                g = g if isinstance(g, dict) else {}
                flat.setdefault(ip, {})[nid] = {"ok": True, "ts": g.get("ts", 0),
                                                "colo": g.get("colo", "")}
        for sid in ids:
            matrix[sid] = {ip: {nid: dict(_cell(c), delay=None) for nid, c in cells.items()}
                           for ip, cells in flat.items()}

    bad = {}
    for nid, ips in (raw.get("bad") or {}).items():
        if isinstance(ips, dict):
            bad[nid] = dict(ips)
    memory = {1: raw.get("state"), 2: raw.get("memory")}.get(version) or {}
    for nid, mem in memory.items():
        if isinstance(mem, dict) and isinstance(mem.get("bad"), dict):
            bad.setdefault(nid, {}).update(mem["bad"])

    # what the records point at, and the history of changes
    def new_key(key):
        if version >= 5:
            return key
        if version == 3 and first:
            return {"ip1": slot_key(first, "mobile"), "ip2": slot_key(first, "home")}.get(key)
        if version == 4:
            sid, _, second = str(key).partition(":")
            return slot_key(sid, "home" if second else "mobile")
        return None

    records = {}
    for key, entry in (raw.get("records") or {}).items():
        target = new_key(key)
        if target and isinstance(entry, dict):
            records[target] = {"ips": list(entry.get("ips") or []), "ts": entry.get("ts", 0)}
    history = []
    for h in raw.get("history") or []:
        if not isinstance(h, dict):
            continue
        h = dict(h)
        if version < 5:
            h["record"] = new_key(h.get("record")) or ""
        history.append(h)

    net_ids = [n["id"] for n in networks]
    return {
        "version": 5,
        "settings": settings,
        "servers": servers,
        "networks": networks,
        "server": raw.get("server") if raw.get("server") in ids else first,
        "network": raw.get("network") if raw.get("network") in net_ids else net_ids[0],
        "matrix": matrix,
        "bad": bad,
        "records": records,
        "history": history[-HISTORY_LIMIT:],
        "zones": raw.get("zones") if isinstance(raw.get("zones"), dict) else {},
        "ranges": raw.get("ranges") if isinstance(raw.get("ranges"), dict) else {},
    }


class Secrets:
    """Keychain items (the Cloudflare token, VLESS uuids); memory elsewhere."""

    def __init__(self):
        self._memory = {}
        try:
            import keychain
        except ImportError:
            keychain = None
        self._keychain = keychain

    def get(self, sid=None):
        return self.get_named(KEYCHAIN_ACCOUNT)

    def set(self, token, sid=None):
        self.set_named(KEYCHAIN_ACCOUNT, token)

    def get_named(self, name):
        if self._keychain is None:
            return self._memory.get(name, "")
        return self._keychain.get_password(KEYCHAIN_SERVICE, name) or ""

    def set_named(self, name, value):
        value = (value or "").strip()
        if self._keychain is None:
            self._memory[name] = value
        elif value:
            self._keychain.set_password(KEYCHAIN_SERVICE, name, value)
        else:
            try:
                self._keychain.delete_password(KEYCHAIN_SERVICE, name)
            except Exception:
                pass


class Store:
    """Servers, networks, settings, per-server coverage and history."""

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

    # -- secrets -----------------------------------------------------------

    @property
    def token(self):
        return sanitize_token(self.secrets.get())

    def uuid_for(self, sid):
        """The VLESS uuid of a server's CDN config (Keychain), or ''."""
        getter = getattr(self.secrets, "get_named", None)
        return getter("vless:%s" % sid) if getter else ""

    def set_uuid(self, sid, value):
        setter = getattr(self.secrets, "set_named", None)
        if setter:
            setter("vless:%s" % sid, value)

    def target(self, server):
        return Target.from_settings(server, self.uuid_for(server["id"]))

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
    def selected(self):
        for s in self.servers:
            if s["id"] == self.data.get("server"):
                return s
        return self.servers[0] if self.servers else None

    def select_server(self, sid):
        with self.lock:
            self.server(sid)
            self.data["server"] = sid
            self.save()

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
                self.data["matrix"].setdefault(sid, {})
                if not self.data.get("server"):
                    self.data["server"] = sid
            else:
                server = self.server(sid)
                for group in GROUPS:
                    field = "record_" + group
                    if field in clean and clean[field] != server[field]:
                        self.data["records"].pop(slot_key(sid, group), None)
                server.update(clean)
                server["name"] = server["name"] or server["sni"] or sid
            self.save()
            return sid

    def delete_server(self, sid):
        with self.lock:
            self.data["servers"] = [s for s in self.servers if s["id"] != sid]
            self.data["matrix"].pop(sid, None)
            for group in GROUPS:
                self.data["records"].pop(slot_key(sid, group), None)
            if self.data.get("server") == sid:
                self.data["server"] = self.servers[0]["id"] if self.servers else None
            self.save()
        self.set_uuid(sid, "")

    def slots(self, sid=None):
        """Configured records: ``(key, server, record name, group)``."""
        out = []
        for sv in self.servers:
            if sid is not None and sv["id"] != sid:
                continue
            for group in GROUPS:
                if sv.get("record_" + group):
                    out.append((slot_key(sv["id"], group), sv, sv["record_" + group], group))
        return out

    def slot_label(self, key):
        sid, _, group = str(key).partition(":")
        try:
            name = self.server(sid)["name"]
        except KeyError:
            return str(key)
        return "%s · %s" % (name, GROUP_NAMES.get(group, group))

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

    def group_networks(self, group):
        return [n["id"] for n in self.networks if n["group"] == group]

    def network_for_asn(self, asn):
        for n in self.networks:
            if asn in n["asns"]:
                return n
        return None

    def save_network(self, nid, name, group, asn=None):
        if group not in GROUPS:
            raise ValueError("group must be mobile or home")
        with self.lock:
            if nid is None:
                n = 1
                ids = {x["id"] for x in self.networks}
                while "n%d" % n in ids:
                    n += 1
                nid = "n%d" % n
                self.networks.append({"id": nid, "name": name.strip() or nid,
                                      "group": group, "asns": []})
            else:
                net = self.network(nid)
                net["name"] = name.strip() or net["name"]
                net["group"] = group
            if asn:
                for other in self.networks:
                    if asn in other["asns"]:
                        other["asns"].remove(asn)
                self.network(nid)["asns"].append(int(asn))
            self.save()
            return nid

    def delete_network(self, nid):
        with self.lock:
            if len(self.networks) <= 1:
                raise ValueError("at least one network is needed")
            self.data["networks"] = [n for n in self.networks if n["id"] != nid]
            for table in self.data["matrix"].values():
                for cells in table.values():
                    cells.pop(nid, None)
            self.data["bad"].pop(nid, None)
            if self.data["network"] == nid:
                self.data["network"] = self.networks[0]["id"]
            self.save()

    # -- coverage per server: address x network ------------------------------

    def cells(self, sid):
        return self.data["matrix"].setdefault(sid, {})

    def record_result(self, sid, ip, nid, ok, delay=None, colo="", ts=None):
        with self.lock:
            table = self.cells(sid)
            table.setdefault(ip, {})[nid] = {"ok": bool(ok), "delay": delay, "colo": colo or "",
                                             "ts": time.time() if ts is None else ts}
            if ok:
                self.data["bad"].get(nid, {}).pop(ip, None)
            if len(table) > MATRIX_LIMIT:
                newest = sorted(table.items(),
                                key=lambda kv: -max(c.get("ts", 0) for c in kv[1].values()))
                self.data["matrix"][sid] = dict(newest[:MATRIX_LIMIT])

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
            self.data["matrix"] = {s["id"]: {} for s in self.servers}
            self.save()

    # -- what the records point at ------------------------------------------

    def record_ips(self, key):
        return list((self.data["records"].get(key) or {}).get("ips") or [])

    def record_changed_at(self, key):
        return (self.data["records"].get(key) or {}).get("ts")

    def set_record_ips(self, key, ips):
        with self.lock:
            entry = self.data["records"].get(key) or {}
            if list(ips) != entry.get("ips"):
                entry = {"ips": list(ips), "ts": time.time()}
            self.data["records"][key] = entry

    # -- history -----------------------------------------------------------

    def add_history(self, record, old, new, network="", kind="apply", note=""):
        with self.lock:
            self.data["history"].append({"ts": time.time(), "record": record, "kind": kind,
                                         "network": network, "old": list(old),
                                         "new": list(new), "note": note})
            del self.data["history"][:-HISTORY_LIMIT]

    def history(self, sid=None):
        items = [h for h in self.data["history"]
                 if sid is None or str(h.get("record", "")).startswith(sid + ":")]
        return list(reversed(items))

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
        """Settings, servers and networks as JSON, without the token or uuids."""
        return json.dumps({"app": "cfscan_ios", "version": 5, "settings": self.settings,
                           "servers": self.servers, "networks": self.networks},
                          ensure_ascii=False, indent=1)

    def import_json(self, text):
        raw = json.loads(text)
        if not isinstance(raw, dict) or raw.get("app") != "cfscan_ios":
            raise ValueError("not a CF Scanner export")
        merged = normalise_data(raw)
        with self.lock:
            for key in ("settings", "servers", "networks", "server", "network"):
                self.data[key] = merged[key]
            for s in self.servers:
                self.data["matrix"].setdefault(s["id"], {})
            self.save()

# ---------------------------------------------------------------- probes

class Target:
    """What a probe connects as: the config's SNI, Host, path, port and TLS.

    With a VLESS ``uuid`` the WebSocket probe goes on through the tunnel,
    exactly like a client's "real delay" test.
    """

    def __init__(self, sni, path="", port=443, tls=True, host="", uuid=""):
        self.sni = normalise_host(sni)
        self.host = normalise_host(host) or self.sni
        self.path = normalise_path(path)
        self.port = int(port)
        self.tls = bool(tls)
        self.uuid = str(uuid or "").strip()

    @classmethod
    def from_settings(cls, s, uuid=""):
        return cls(s["sni"], s["path"], s["port"], s["tls"], s.get("host", ""), uuid)

    @property
    def kind(self):
        """What a successful probe proves: the config, the tunnel, or the edge."""
        if self.uuid:
            return "vless"
        return "ws" if self.path else "trace"


#: Where the "real delay" request goes, as in the clients (plain HTTP inside
#: the tunnel, so no second TLS handshake is timed).
DELAY_TEST_HOST = "www.gstatic.com"
DELAY_TEST_PATH = "/generate_204"


def parse_vless_link(link):
    """The parts of a ``vless://`` WebSocket config link, or ValueError."""
    link = re.sub(_INVISIBLE, "", str(link or ""))
    parts = urllib.parse.urlsplit(link)
    if parts.scheme.lower() != "vless" or "@" not in parts.netloc:
        raise ValueError("لینک باید با vless:// شروع شود")
    user, _, hostport = parts.netloc.rpartition("@")
    try:
        uuid_text = str(uuid_module.UUID(urllib.parse.unquote(user)))
    except ValueError:
        raise ValueError("UUID لینک نامعتبر است")
    query = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    kind = (query.get("type") or "tcp").lower()
    if kind not in ("ws", "httpupgrade"):
        raise ValueError("فقط کانفیگ WebSocket پشت CDN پشتیبانی می‌شود (type=%s)" % kind)
    if query.get("encryption", "none") not in ("", "none"):
        raise ValueError("encryption باید none باشد")
    try:
        port = parts.port or 443
    except ValueError:
        raise ValueError("پورت لینک نامعتبر است")
    host = normalise_host(query.get("host", ""))
    sni = normalise_host(query.get("sni", "")) or host or normalise_host(parts.hostname)
    path = urllib.parse.unquote(query.get("path", "/")).split("?", 1)[0]
    return {"uuid": uuid_text, "sni": sni, "host": host if host != sni else "",
            "path": normalise_path(path) or "/", "port": port,
            "tls": query.get("security", "none").lower() == "tls",
            "name": urllib.parse.unquote(parts.fragment or "")}


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
                   "Accept: */*\r\nConnection: close\r\n\r\n" % (target.host, USER_AGENT))
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


def ws_frame(payload, opcode=0x2):
    """One masked client WebSocket frame."""
    mask = os.urandom(4)
    n = len(payload)
    if n < 126:
        head = bytes([0x80 | opcode, 0x80 | n])
    elif n < 65536:
        head = bytes([0x80 | opcode, 0x80 | 126]) + n.to_bytes(2, "big")
    else:
        head = bytes([0x80 | opcode, 0x80 | 127]) + n.to_bytes(8, "big")
    return head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


class _WSReader:
    """Server frames from a socket, starting with bytes already read."""

    def __init__(self, sock, pending=b""):
        self.sock = sock
        self.buf = pending

    def _need(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionResetError("closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def frame(self):
        b0, b1 = self._need(2)
        n = b1 & 0x7F
        if n == 126:
            n = int.from_bytes(self._need(2), "big")
        elif n == 127:
            n = int.from_bytes(self._need(8), "big")
        mask = self._need(4) if b1 & 0x80 else None
        data = self._need(n)
        if mask:
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        return b0 & 0x0F, data


def vless_request(uuid_text, host, port, payload):
    """A VLESS request header (TCP to ``host:port``) followed by ``payload``."""
    addr = host.encode("ascii")
    return (b"\x00" + uuid_module.UUID(uuid_text).bytes + b"\x00\x01"
            + int(port).to_bytes(2, "big") + b"\x02" + bytes([len(addr)]) + addr + payload)


def _vless_exchange(sock, pending, target):
    """Send one HTTP request through the tunnel; the status it gets back."""
    request = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n"
               % (DELAY_TEST_PATH, DELAY_TEST_HOST, USER_AGENT)).encode("ascii")
    sock.sendall(ws_frame(vless_request(target.uuid, DELAY_TEST_HOST, 80, request)))
    reader = _WSReader(sock, pending)
    data, header_done = b"", False
    while True:
        opcode, payload = reader.frame()
        if opcode == 0x8:
            raise ConnectionResetError("closed by server")
        if opcode not in (0x0, 0x1, 0x2):
            continue
        data += payload
        if not header_done:
            if len(data) < 2 or len(data) < 2 + data[1]:
                continue
            data = data[2 + data[1]:]  # VLESS response header: version, addons
            header_done = True
        if b"\r\n" in data:
            return parse_status(data)


def ws_probe(ip, target, ctx, timeout):
    """A WebSocket upgrade on the config's path; ``101`` means the whole
    chain (Cloudflare, the server and Xray) answered.

    With a VLESS uuid on the target it goes on like a client's "real delay":
    one HTTP request through the tunnel, timed until its status line.
    """
    r = _blank_result(ip)
    sock = None
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    try:
        sock, start, r["tcp"] = _connect(ip, target, ctx, timeout)
        request = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
                   "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                   "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n"
                   % (target.path or "/", target.host, USER_AGENT, key))
        sock.sendall(request.encode("ascii"))
        data = _read(sock, until_head=True)
        r["status"] = parse_status(data)
        if r["status"] != 101:
            r["total"] = (time.perf_counter() - start) * 1000
            r["error"] = "HTTP %s" % r["status"] if r["status"] else "empty answer"
        elif not target.uuid:
            r["total"] = (time.perf_counter() - start) * 1000
            r["ok"] = True
        else:
            pending = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""
            status = _vless_exchange(sock, pending, target)
            r["total"] = (time.perf_counter() - start) * 1000
            r["status"] = status
            r["ok"] = status is not None and 200 <= status < 400
            if not r["ok"]:
                r["error"] = "tunnel HTTP %s" % status if status else "tunnel: no answer"
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
            probe_trace=trace_probe, probe_ws=ws_probe, warmup=False):
    """``attempts`` sequential probes of one address, summarised.

    ``delay`` is the median time of a whole probe - with a VLESS target the
    client's "real delay"; ``ping`` the median TCP connect. ``warmup``
    first makes one untimed probe: on a phone the first packets wake the
    radio and would count 50-200 ms that no later request pays.
    """
    tcp, total, errors = [], [], []
    colo = ""
    if warmup and not (cancel is not None and cancel.is_set()):
        (probe_ws if use_ws else probe_trace)(ip, target, ctx, timeout)
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
        "delay": statistics.median(total) if total else None,
        "jitter": successive_jitter_ms(total),
        "colo": colo, "errors": errors,
    }


def score(m):
    """Lower is better: config delay, twice the jitter, heavy loss penalty."""
    if m.get("delay") is None:
        return float("inf")
    return m["delay"] + 2 * (m.get("jitter") or 0) + 50 * m.get("loss", 100)


def is_healthy(m, max_loss, max_delay):
    return (m.get("ok", 0) > 0 and m.get("loss", 100) <= max_loss
            and m.get("delay") is not None and m["delay"] <= max_delay)


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
    """The DNS name behind a slot key (``s1:mobile`` -> the server's record)."""
    sid, _, group = str(key).partition(":")
    try:
        server = store.server(sid)
    except KeyError:
        raise CFError("سرور این رکورد دیگر وجود ندارد")
    name = server.get("record_" + group) or ""
    if not name:
        raise CFError("رکورد %s سرور «%s» تنظیم نشده" % (GROUP_NAMES.get(group, group),
                                                         server["name"]))
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
                 api_factory=CloudflareAPI):
    """Point the record of slot ``key`` at ``ips``; returns the route used."""
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
        store.set_record_ips(key, ips)
        store.add_history(key, old, ips, network, kind, "via %s" % via if via else "")
        store.save()
    log("applied %s -> %s" % (record, ips))
    return via


# ---------------------------------------------------------------- where the phone is

META_URL = "https://speed.cloudflare.com/meta"
TRACE_URL = "https://speed.cloudflare.com/cdn-cgi/trace"


def _fetch(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read(8192)


def detect_connection(timeout=6.0):
    """How Cloudflare sees this phone.

    ``{"ok", "asn", "org", "country", "ip", "colo", "error"}`` - from ``/meta``
    (which names the ASN), else from ``/cdn-cgi/trace`` without an ASN.
    ``country`` other than ``IR`` means the traffic leaves through a VPN.
    """
    try:
        meta = json.loads(_fetch(META_URL, timeout).decode("utf-8"))
        colo = meta.get("colo")
        if isinstance(colo, dict):
            colo = colo.get("iata") or ""
        asn = meta.get("asn")
        return {"ok": True, "asn": int(asn) if str(asn).isdigit() else None,
                "org": str(meta.get("asOrganization") or ""),
                "country": str(meta.get("country") or ""), "ip": str(meta.get("clientIp") or ""),
                "colo": str(colo or ""), "error": ""}
    except Exception as exc:
        first = describe_error(exc)
    try:
        info = parse_trace(b"\r\n\r\n" + _fetch(TRACE_URL, timeout))
        return {"ok": True, "asn": None, "org": "", "country": info.get("loc", ""),
                "ip": info.get("ip", ""), "colo": info.get("colo", ""), "error": ""}
    except Exception as exc:
        return {"ok": False, "asn": None, "org": "", "country": "", "ip": "", "colo": "",
                "error": describe_error(exc) or first}


# ---------------------------------------------------------------- choosing addresses

UNKNOWN = "unknown"


def cell_status(cell, now, window_s, since=None):
    """``ok``/``fail`` for a result measured recently enough, else ``unknown``."""
    if not cell:
        return UNKNOWN
    ts = cell.get("ts", 0)
    if (since is not None and ts < since) or now - ts >= window_s:
        return UNKNOWN
    return "ok" if cell.get("ok") else "fail"


def cell_text(cell, now, window_s):
    """``420`` for a recent pass, ``✕`` for a recent failure, ``؟`` otherwise."""
    status = cell_status(cell, now, window_s)
    if status == UNKNOWN:
        return "؟"
    if status == "fail":
        return "✕"
    return "%.0f" % cell["delay"] if cell.get("delay") is not None else "✓"


def choose_for_record(cells, nid, group_nets, now, window_s, count, current=(),
                      mode="auto", min_gain_pct=20, since=None, hints=None):
    """What a server's record for ``nid``'s group should hold.

    ``cells``: address -> network -> result, for this server only.

    * Only addresses measured OK on ``nid`` in this run (``since``) qualify.
    * Tier 1 also work (recently) on every other network of the group,
      tier 2 were not tested there lately; an address that recently FAILED
      on another network of the group is never chosen - it would break
      those customers.
    * Inside a tier: the lower worst delay across the group wins.
    * ``auto`` keeps current addresses that still work here and fills the
      gaps; ``force`` changes working ones only for ``min_gain_pct`` better.

    ``hints`` (address -> network -> ok/fail) fill what this server did not
    measure: whether an address is blocked on a network does not depend on
    the server, so other servers' results and the scan's failures count.

    Returns ``{"ips", "kind": "keep"|"change"|"conflict"|"none",
    "unverified": [networks], "conflict": [addresses], "tier": {ip: 1|2}}``.
    """
    others = [n for n in group_nets if n != nid]
    hints = hints or {}

    def status(ip, n, since_=None):
        own = cell_status((cells.get(ip) or {}).get(n), now, window_s, since_)
        if own != UNKNOWN or since_ is not None:
            return own
        return (hints.get(ip) or {}).get(n, UNKNOWN)

    def worst(ip):
        delays = []
        for n in [nid] + others:
            cell = (cells.get(ip) or {}).get(n)
            if cell and status(ip, n) == "ok" and cell.get("delay") is not None:
                delays.append(cell["delay"])
        return max(delays) if delays else float("inf")

    here = [ip for ip in cells if status(ip, nid, since) == "ok"]
    blocked = [ip for ip in here if any(status(ip, n) == "fail" for n in others)]
    tier1 = [ip for ip in here if ip not in blocked and all(status(ip, n) == "ok" for n in others)]
    tier2 = [ip for ip in here if ip not in blocked and ip not in tier1]
    ranked = sorted(tier1, key=worst) + sorted(tier2, key=worst)
    tiers = dict([(ip, 1) for ip in tier1] + [(ip, 2) for ip in tier2])

    keep = [ip for ip in current if ip in ranked]
    if mode == "force" and keep:
        best = ranked[:count]
        mean = lambda ips: sum(worst(ip) for ip in ips) / float(len(ips))  # noqa: E731
        if mean(best) <= mean(keep) * (1 - min_gain_pct / 100.0):
            chosen = best
        else:
            chosen = (keep + [ip for ip in ranked if ip not in keep])[:count]
    else:
        chosen = (keep + [ip for ip in ranked if ip not in keep])[:count]

    if not chosen:
        conflict = sorted(blocked, key=worst)[:count]
        return {"ips": [], "kind": "conflict" if conflict else "none", "unverified": [],
                "conflict": conflict, "tier": tiers}
    unverified = [n for n in others if any(status(ip, n) != "ok" for ip in chosen)]
    kind = "keep" if sorted(chosen) == sorted(current) else "change"
    return {"ips": chosen, "kind": kind, "unverified": unverified, "conflict": [], "tier": tiers}


def record_health(cells, ips, group_nets, now, window_s, hints=None):
    """Per network of the group: ``ok`` (every address works), ``fail`` (one
    fails) or ``unknown`` (not measured lately)."""
    out = {}
    hints = hints or {}

    def status(ip, n):
        own = cell_status((cells.get(ip) or {}).get(n), now, window_s)
        return own if own != UNKNOWN else (hints.get(ip) or {}).get(n, UNKNOWN)

    for n in group_nets:
        states = [status(ip, n) for ip in ips]
        if not ips or UNKNOWN in states and "fail" not in states:
            out[n] = UNKNOWN
        else:
            out[n] = "fail" if "fail" in states else "ok"
    return out


def network_hints(store, sid, ips, nets, now, window_s):
    """What other servers and failed scans say about ``ips`` on ``nets``.

    ``fail`` when the address did not answer on that network lately (it is
    blocked there for every server); ``ok`` when another server measured it
    working there.
    """
    bad_window = min(window_s, float(store.settings["bad_ttl_hours"]) * 3600 or window_s)
    hints = {}
    for ip in ips:
        for n in nets:
            ts = store.bad_for(n).get(ip)
            if ts and now - ts < bad_window:
                hints.setdefault(ip, {})[n] = "fail"
                continue
            for other, table in store.data["matrix"].items():
                if other != sid and cell_status((table.get(ip) or {}).get(n), now, window_s) == "ok":
                    hints.setdefault(ip, {})[n] = "ok"
                    break
    return hints


def relevant_networks(store, group):
    """The group's networks worth checking: known by ASN, or measured once.

    A network nobody ever tested (the default "home" before its first scan)
    would otherwise flag every address as unverified forever.
    """
    measured = set()
    for table in store.data["matrix"].values():
        for cells in table.values():
            measured.update(cells)
    return [n["id"] for n in store.networks
            if n["group"] == group and (n["asns"] or n["id"] in measured)]


# ---------------------------------------------------------------- scan engine

STEP_TITLES = ("بررسی رکورد روی این اینترنت", "اسکن", "اندازه‌گیری دقیق و انتخاب",
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
    """One server on one network: check its record -> scan -> choose -> apply.

    ``mode``: ``auto`` scans only when the record fails here, ``force``
    scans anyway (and changes working addresses only for a clear gain).
    """

    #: Addresses measured at the same time in the careful step. More would
    #: time the phone's CPU (Python threads, TLS) instead of the network.
    CALM_WORKERS = 3

    def __init__(self, store, sid, nid, events=None, mode="auto", context_factory=make_context,
                 api_factory=CloudflareAPI, candidates=None, rng=None,
                 probe_trace=trace_probe, probe_ws=ws_probe, now=None):
        self.store = store
        self.sid = sid
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
        log("job start %s/%s mode=%s" % (self.sid, self.nid, self.mode))
        started = time.time()
        try:
            result = self._run()
        except (UserError, CFError, NetError, KeyError) as exc:
            result = {"kind": "error", "message": str(exc)}
        except Exception as exc:
            log("job crashed: %r" % (exc,))
            result = {"kind": "error", "message": "%s: %s" % (exc.__class__.__name__, exc)}
        result.setdefault("server", self.sid)
        result.setdefault("network", self.nid)
        result["elapsed"] = time.time() - started
        self.result = result
        self.running = False
        log("job end %s/%s: %s" % (self.sid, self.nid, result.get("kind")))
        self.events.finished(result)
        return result

    # -- the steps -------------------------------------------------------

    def _run(self):
        store = self.store
        s = store.settings
        server = store.server(self.sid)
        network = store.network(self.nid)
        if not server.get("sni"):
            raise UserError("دامنهٔ CDN سرور «%s» خالی است" % server["name"])
        group = network["group"]
        group_nets = [n for n in relevant_networks(store, group) if n != self.nid] + [self.nid]
        key = slot_key(self.sid, group)
        record = server.get("record_" + group) or ""
        target = store.target(server)
        version = int(s["ip_version"])
        rtype = "AAAA" if version == 6 else "A"
        ctx = self.context_factory()
        use_ws = target.kind != "trace"
        has_token = bool(store.token)
        window = float(s["fresh_hours"]) * 3600
        count = int(s["ips_per_record"])
        run_started = self.clock()
        result = {"kind": None, "server": self.sid, "network": self.nid, "group": group,
                  "key": key, "record": record, "current": [], "ips": [], "verified": [],
                  "unverified": [], "conflict": [], "warning": "", "scanned": 0,
                  "answered": 0, "errors": "", "test": target.kind}
        if not record:
            self.events.note("رکورد %s برای «%s» تنظیم نشده؛ فقط اندازه‌گیری می‌شود."
                             % (GROUP_NAMES[group], server["name"]))
        if target.kind != "vless":
            self.events.note("لینک کانفیگ این سرور تنظیم نشده؛ عددها «تأخیر تا سرور» است، نه "
                             "تأخیر کامل کانفیگ.")

        # 1. what the record holds now, measured here
        self.events.step(0, "run")
        current = store.record_ips(key)
        if record and has_token:
            try:
                current = read_record(store, key, rtype, api_factory=self.api_factory)
                store.set_record_ips(key, current)
            except (CFError, NetError) as exc:
                self.events.note("خواندن رکورد از کلادفلر نشد: %s" % exc)
        current = [ip for ip in current if (":" in ip) == (version == 6)]
        result["current"] = current
        healthy = False
        if current:
            ms = self._measure_many(current, target, ctx, int(s["verify_attempts"]), use_ws)
            self._record(ms)
            store.save()
            healthy = all(self._ok(m) for m in ms)
            self.events.step(0, "ok" if healthy else "fail",
                             "  ".join(self._measure_text(m) for m in ms))
        else:
            self.events.step(0, "skip", "رکورد هنوز IP ندارد")
        if self.cancelled:
            return self._stopped(result)
        if healthy and self.mode == "auto":
            for i in (1, 2, 3):
                self.events.step(i, "skip")
            now = self.clock()
            health = record_health(store.cells(self.sid), current, group_nets, now, window,
                                   network_hints(store, self.sid, current, group_nets, now, window))
            result.update(kind="healthy", ips=current,
                          unverified=[n for n in group_nets if health[n] != "ok"])
            return result

        # 2. scan: what works for this server on the group's other network first
        self.events.step(1, "run")
        seeds = self._seeds(group_nets, window, current)
        if self.fixed_candidates is not None:
            cands = list(self.fixed_candidates)
        else:
            own = {ip: {"ts": c[self.nid].get("ts", 0)} for ip, c in store.cells(self.sid).items()
                   if (c.get(self.nid) or {}).get("ok")}
            cands = build_candidates({"good": own, "bad": store.bad_for(self.nid)},
                                     int(s["candidates"]), version, store.ranges(version),
                                     rng=self.rng, bad_ttl_s=float(s["bad_ttl_hours"]) * 3600,
                                     exclude=current, shared=seeds)
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
        for ip in failed:
            if ip in seeds:
                store.record_result(self.sid, ip, self.nid, False)
        if self.cancelled:
            store.save()
            return self._stopped(result)
        if not answered and not current:
            store.save()
            self.events.step(1, "fail", "هیچ IP پاسخ نداد (%s)" % result["errors"])
            result["kind"] = "nothing"
            result["hint"] = self._hint(errors, version)
            return result
        self.events.step(1, "ok" if answered else "fail",
                         "%d از %d پاسخ داد" % (len(answered), scanned))

        # 3. careful measure of the shortlist, then the rules
        self.events.step(2, "run")
        verify_top = int(s["verify_top"])
        top = sorted(answered, key=lambda r: r["tcp"])[:verify_top]
        seeded = [r for r in answered if r["ip"] in seeds and r not in top][:verify_top]
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
        now = self.clock()
        hints = network_hints(store, self.sid, list(store.cells(self.sid)),
                              [n for n in group_nets if n != self.nid], now, window)
        choice = choose_for_record(store.cells(self.sid), self.nid, group_nets, now,
                                   window, count, current, self.mode,
                                   float(s["min_gain_pct"]), since=run_started, hints=hints)
        result.update(ips=choice["ips"], unverified=choice["unverified"],
                      conflict=choice["conflict"], via=[m["ip"] for m in ms if m["ok"]])
        names = {n["id"]: n["name"] for n in store.networks}
        if choice["kind"] == "none":
            errs = [e for m in ms for e in m["errors"]]
            self.events.step(2, "fail", "هیچ IP سالمی پیدا نشد (%s)" % error_summary(errs))
            result["kind"] = "nothing"
            result["hint"] = self._hint(errs, version, verify=True, use_ws=use_ws)
            return result
        if choice["kind"] == "conflict":
            others = [names[n] for n in group_nets if n != self.nid]
            self.events.step(2, "fail", "IPهای سالم این اینترنت روی %s خراب‌اند: %s"
                             % ("، ".join(others), ", ".join(choice["conflict"])))
            result["kind"] = "conflict"
            return result
        detail = ", ".join(choice["ips"])
        if choice["unverified"]:
            detail += "\n⚠ روی %s هنوز تأیید نشده" % "، ".join(names[n] for n in choice["unverified"])
        self.events.step(2, "ok", detail)

        # 4. the record
        if choice["kind"] == "keep":
            self.events.step(3, "ok", "رکورد همین IPها را دارد")
            result["kind"] = "unchanged"
        elif not record:
            self.events.step(3, "skip", "رکورد %s تنظیم نشده" % GROUP_NAMES[group])
            result["kind"] = "found"
        elif not has_token:
            self.events.step(3, "skip", "توکن کلادفلر تنظیم نشده")
            result["kind"] = "found"
        elif not s["auto_apply"]:
            self.events.step(3, "wait", "منتظر تأیید شما")
            result["kind"] = "pending"
        else:
            self.apply(result)
        return result

    def apply(self, result=None, ips=None, kind="apply"):
        """Write the record; used by the job and by the screen's buttons.

        ``ips`` overrides the choice (the "apply anyway" of a conflict).
        """
        result = result if result is not None else (self.result or {})
        ips = list(ips if ips is not None else result.get("ips") or [])
        self.events.step(3, "run")
        try:
            apply_record(self.store, result["key"], ips, result.get("via") or [], self.nid,
                         kind=kind, api_factory=self.api_factory)
        except (CFError, NetError) as exc:
            self.events.step(3, "fail", str(exc))
            result["kind"] = "apply_failed"
            result["message"] = str(exc)
            return False
        self.events.step(3, "ok", "%s → %s" % (result.get("record"), ", ".join(ips)))
        result["kind"] = "applied"
        result["ips"] = ips
        return True

    # -- helpers ---------------------------------------------------------

    def _seeds(self, group_nets, window, current):
        """Addresses to try first here.

        1. working for this server on the group's other networks,
        2. working here for other servers,
        not measured here for this server lately.
        """
        now = self.clock()
        mine = self.store.cells(self.sid)
        out = []

        def fresh_here(ip):
            return cell_status((mine.get(ip) or {}).get(self.nid), now, window) != UNKNOWN

        others = [n for n in group_nets if n != self.nid]
        ranked = []
        for ip, cells in mine.items():
            oks = [cells[n] for n in others if cell_status(cells.get(n), now, window) == "ok"]
            if oks and not fresh_here(ip) and ip not in current:
                ranked.append((max(c.get("delay") or 0 for c in oks), ip))
        out += [ip for _, ip in sorted(ranked)]
        for sid, table in self.store.data["matrix"].items():
            if sid == self.sid:
                continue
            for ip, cells in table.items():
                if (cell_status(cells.get(self.nid), now, window) == "ok"
                        and ip not in out and not fresh_here(ip) and ip not in current):
                    out.append(ip)
        return out[:60]

    def _ok(self, m):
        s = self.store.settings
        return is_healthy(m, s["max_loss_pct"], s["max_ping_ms"])

    def _record(self, ms):
        for m in ms:
            self.store.record_result(self.sid, m["ip"], self.nid, self._ok(m), m.get("delay"),
                                     m.get("colo", ""))

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
                        top = sorted(answered, key=lambda x: x["tcp"])[:8]
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
        timeout = float(self.store.settings["timeout"]) + 2.0
        gate = threading.Semaphore(self.CALM_WORKERS)

        def one(i, ip):
            with gate:
                out[i] = measure(ip, target, ctx, attempts, timeout, use_ws,
                                 cancel=self.cancel_event, probe_trace=self.probe_trace,
                                 probe_ws=self.probe_ws, warmup=True)

        threads = [threading.Thread(target=one, args=(i, ip), name="verify-%d" % i, daemon=True)
                   for i, ip in enumerate(ips)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return [m for m in out if m is not None]

    @staticmethod
    def _measure_text(m):
        if m.get("delay") is None:
            return "%s: پاسخ نداد (%s)" % (m["ip"], error_summary(m.get("errors") or [], 1))
        return "%s %.0fms loss %.0f%%" % (m["ip"], m["delay"], m["loss"])

    @staticmethod
    def _stopped(result):
        result["kind"] = "stopped"
        return result

    @staticmethod
    def _hint(errors, version, verify=False, use_ws=False):
        joined = " ".join(errors)
        if version == 6 and ("unreachable" in joined.lower() or "No route" in joined):
            return "این اینترنت IPv6 ندارد؛ در تنظیمات پیشرفته IPv4 را انتخاب کنید."
        if verify and "tunnel" in joined:
            return ("تونل باز شد ولی درخواست داخلش جواب نگرفت: UUID لینک، فعال بودن کاربر یا "
                    "فیلتر شدن ترافیک بعد از اتصال را بررسی کنید.")
        if verify and use_ws and "HTTP 404" in joined:
            return "پاسخ 404: path سرور با inbound یکی نیست."
        if verify and use_ws and any(code in joined for code in ("HTTP 52", "HTTP 50")):
            return "کلادفلر به سرور وصل نشد (خطای 5xx): سرور یا پورت را بررسی کنید."
        if "TLS" in joined or "reset" in joined:
            return ("اتصال TLS قطع می‌شود؛ احتمالاً SNI دامنهٔ CDN روی این اینترنت فیلتر است. "
                    "دامنهٔ ذخیره را جایگزین کنید.")
        if errors and all(e == "timeout" for e in errors):
            return "همه timeout شدند؛ اینترنت، حالت هواپیما یا روشن بودن VPN را بررسی کنید."
        return ""


RESULT_TEXT = {
    "healthy": "رکورد روی این اینترنت سالم است",
    "applied": "رکورد به‌روز شد",
    "unchanged": "بهترین IPها همان قبلی‌اند",
    "pending": "IP پیدا شد؛ «اعمال» را بزنید",
    "found": "IP پیدا شد (رکورد یا توکن تنظیم نشده)",
    "conflict": "IP سالم این اینترنت روی اینترنت دیگر همین گروه خراب است",
    "stopped": "متوقف شد",
    "nothing": "IP سالمی پیدا نشد",
    "apply_failed": "اعمال روی DNS نشد",
    "error": "خطا",
}
GOOD_KINDS = ("healthy", "applied", "unchanged", "pending", "found")
TEST_LABEL = {"vless": "تأخیر کانفیگ", "ws": "تأخیر تا سرور", "trace": "تأخیر تا کلادفلر"}


def result_line(result, store=None):
    """A short Persian summary of a finished run."""
    kind = result.get("kind")
    text = RESULT_TEXT.get(kind, kind or "?")
    if kind in ("error", "apply_failed") and result.get("message"):
        text += " — " + result["message"]
    ips = result.get("ips") if kind in GOOD_KINDS else result.get("conflict")
    if ips:
        text += "\n" + ", ".join(ips)
    if store is not None and result.get("unverified") and kind in GOOD_KINDS:
        names = {n["id"]: n["name"] for n in store.networks}
        text += "\n⚠ روی %s تأیید نشده؛ با همان اینترنت اسکن کنید" % "، ".join(
            names.get(n, n) for n in result["unverified"])
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
    """A careful result: delay, its jitter, loss and datacentre."""
    if m.get("delay") is None:
        return "%-15s  FAIL" % m["ip"]
    return "%-15s %4.0fms ±%-3.0f %3.0f%% %s" % (m["ip"], m["delay"], m.get("jitter") or 0,
                                                 m["loss"], m.get("colo", ""))


def format_trace_row(r):
    """A fast-pass answer: only that it answered, and from where."""
    return "%-15s  ✓  %s" % (r["ip"], r.get("colo", ""))


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


def matrix_lines(store, sid):
    """The coverage table of one server, best first, for the tools list."""
    s = store.settings
    now = time.time()
    window = float(s["fresh_hours"]) * 3600
    cells = store.cells(sid)
    in_records = set()
    for key, _, _, _ in store.slots(sid):
        in_records.update(store.record_ips(key))
    rows = []
    for ip, by_net in cells.items():
        oks = [c.get("delay") or 0 for n, c in by_net.items()
               if cell_status(c, now, window) == "ok"]
        rows.append((-len(oks), max(oks) if oks else float("inf"), ip))
    lines = []
    for _, _, ip in sorted(rows):
        parts = ["%s %s" % (n["name"], cell_text(cells[ip].get(n["id"]), now, window))
                 for n in store.networks]
        lines.append(fa("%s%s · %s" % ("★ " if ip in in_records else "", ip, " · ".join(parts))))
    return lines


def history_lines(store, sid=None):
    names = {n["id"]: n["name"] for n in store.networks}
    kinds = {"apply": "", "manual": " (دستی)", "rollback": " (برگشت)", "forced": " (اجباری)"}
    lines = []
    for h in store.history(sid):
        when = time.strftime("%m/%d %H:%M", time.localtime(h.get("ts", 0)))
        old = ",".join(h.get("old") or []) or "—"
        new = ",".join(h.get("new") or []) or "—"
        where = names.get(h.get("network"), "")
        lines.append(fa("%s · %s%s · %s → %s%s" % (
            when, store.slot_label(h.get("record", "?")), kinds.get(h.get("kind"), ""),
            old, new, " · روی " + where if where else "")))
    return lines


def connection_text(info, network=None):
    """(text, state) for the network badge; state is ok, bad or wait."""
    if info is None:
        return "در حال تشخیص اینترنت…", "wait"
    if not info["ok"]:
        return "اینترنت در دسترس نیست (%s) — بزنید" % info["error"], "bad"
    if info["country"] and info["country"] != "IR":
        return "VPN روشن است (%s) — خاموشش کنید و بزنید" % info["country"], "bad"
    name = network["name"] if network else (info["org"] or "اینترنت ناشناخته")
    asn = " · AS%d" % info["asn"] if info.get("asn") else ""
    return "✓ %s%s · %s" % (name, asn, info["colo"]), "ok"


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

    def make_link(title, action):
        b = ui.Button()
        b.title = title
        b.font = ("<System-Bold>", 13)
        b.tint_color = ACCENT
        b.action = action
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

    STATE_COLORS = {"ok": (GOOD, GOOD_BG), "fail": (BAD, BAD_BG), UNKNOWN: (NEUTRAL, NEUTRAL_BG),
                    "bad": (BAD, BAD_BG), "wait": (NEUTRAL, NEUTRAL_BG)}

    # ------------------------------------------------------------------ record card

    class RecordCard(ui.View):
        """A server's record for one group: its addresses, per network."""

        ROW = 58

        def __init__(self, app, sid, group):
            self.app = app
            self.sid = sid
            self.group = group
            store = app.store
            server = store.server(sid)
            now = time.time()
            window = float(store.settings["fresh_hours"]) * 3600
            relevant = relevant_networks(store, group)
            nets = [n for n in store.networks if n["id"] in relevant]
            key = slot_key(sid, group)
            name = server.get("record_" + group)
            ips = store.record_ips(key) if name else []
            cells = store.cells(sid)
            self.background_color = CARD
            self.corner_radius = 18
            self.border_width = 1.5 if group == "mobile" and name else 1
            self.border_color = ACCENT if group == "mobile" and name else LINE

            self.heading = make_label(GROUP_NAMES[group], 16, bold=True)
            self.record = make_label(name or ("تنظیم نشده — در ویرایش سرور" if group == "mobile"
                                              else "اختیاری؛ در ویرایش سرور"),
                                     12, color=MUTED, mono=bool(name))
            for v in (self.heading, self.record):
                self.add_subview(v)
            self.rows = []
            for ip in ips:
                ip_label = make_label(ip, 15, mono=True, align="left")
                chips = []
                for n in nets:
                    cell = (cells.get(ip) or {}).get(n["id"])
                    fg, bg = STATE_COLORS[cell_status(cell, now, window)]
                    chip = make_label("%s %s" % (n["name"], cell_text(cell, now, window)), 12,
                                      bold=True, color=fg, align="center")
                    chip.background_color = bg
                    chip.corner_radius = 10
                    chips.append(chip)
                for v in [ip_label] + chips:
                    self.add_subview(v)
                self.rows.append((ip_label, chips))
            lines = []
            if name and ips:
                ids = [n["id"] for n in nets]
                health = record_health(cells, ips, ids, now, window,
                                       network_hints(store, sid, ips, ids, now, window))
                marks = {"ok": "✓", "fail": "✕ خراب", UNKNOWN: "⚠ تأیید نشده"}
                lines.append(" · ".join("%s %s" % (n["name"], marks[health[n["id"]]]) for n in nets))
                changed = store.record_changed_at(key)
                if changed:
                    lines.append("آخرین تغییر: %s" % ago(changed))
            elif name:
                lines.append("هنوز IP ندارد؛ روی %s اسکن کنید"
                             % (" یا ".join(n["name"] for n in nets) or "اینترنت " + GROUP_NAMES[group]))
            self.summary = make_label("\n".join(lines), 12, color=MUTED, lines=2)
            self.add_subview(self.summary)

        @property
        def height_needed(self):
            return 62 + len(self.rows) * self.ROW + (44 if self.summary.text else 8)

        def layout(self):
            w = self.width
            self.heading.frame = (16, 12, w - 32, 22)
            self.record.frame = (16, 34, w - 32, 18)
            y = 60
            for ip_label, chips in self.rows:
                ip_label.frame = (16, y, w - 32, 22)
                n = max(1, len(chips))
                gap = 6
                cw = (w - 32 - gap * (n - 1)) / n
                x = w - 16 - cw
                for chip in chips:
                    chip.frame = (x, y + 26, cw, 24)
                    x -= cw + gap
                y += self.ROW
            self.summary.frame = (16, y, w - 32, 36)

    # ------------------------------------------------------------------ main screen

    class MainView(ui.View):
        def __init__(self, app):
            self.app = app
            self.name = APP_NAME
            self.background_color = BG
            self.scroll = ui.ScrollView()
            self.scroll.always_bounce_vertical = True
            self.add_subview(self.scroll)

            self.servers = ui.SegmentedControl()
            self.servers.action = self.server_changed
            self.net_btn = ui.Button()
            self.net_btn.corner_radius = 14
            self.net_btn.font = ("<System-Bold>", 13)
            self.net_btn.action = lambda s: run_bg(self.app.detect, True)
            self.scan_btn = make_button("اسکن", self.tapped_scan, primary=True, size=18)
            self.scan_btn.corner_radius = 16
            self.force_btn = make_link("اسکن کامل، حتی اگر سالم است", self.tapped_force)
            self.all_btn = make_link("همهٔ سرورها روی این اینترنت", self.tapped_all)
            self.setup = make_label("", 13, color=BAD, lines=3)
            self.empty_btn = make_button("افزودن سرور (لینک vless کانفیگ CDN)",
                                         lambda s: run_bg(self.app.edit_server, None), primary=True)
            for v in (self.servers, self.net_btn, self.scan_btn, self.force_btn, self.all_btn,
                      self.setup, self.empty_btn):
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
            server = store.selected
            for c in self.cards:
                self.scroll.remove_subview(c)
            self.cards = []
            has = server is not None
            for v in (self.servers, self.scan_btn, self.force_btn):
                v.hidden = not has
            self.empty_btn.hidden = has
            self.all_btn.hidden = len(store.servers) < 2
            if has:
                self.servers.segments = [s["name"] for s in store.servers]
                self.servers.selected_index = [s["id"] for s in store.servers].index(server["id"])
                net = store.current_network
                self.scan_btn.title = "اسکن «%s» روی «%s»" % (server["name"], net["name"])
                self.cards = [RecordCard(self.app, server["id"], g) for g in GROUPS]
                for c in self.cards:
                    self.scroll.add_subview(c)
            problems = []
            if not store.token:
                problems.append("توکن کلادفلر (تنظیمات ← کلادفلر)")
            if server and not server.get("record_mobile"):
                problems.append("رکورد موبایل این سرور")
            if server and not store.uuid_for(server["id"]):
                problems.append("لینک کانفیگ این سرور، برای «تأخیر کانفیگ» واقعی")
            self.setup.text = fa("کامل کنید: %s" % "، ".join(problems)) if problems else ""
            self.setup.hidden = not problems
            self.layout()

        @on_main_thread
        def set_connection(self, info, network=None):
            text, state = connection_text(info, network)
            fg, bg = STATE_COLORS[state]
            self.net_btn.title = fa(text)
            self.net_btn.tint_color = fg
            self.net_btn.background_color = bg

        def server_changed(self, sender):
            self.app.store.select_server(self.app.store.servers[sender.selected_index]["id"])
            self.refresh()

        def tapped_scan(self, sender):
            run_bg(self.app.scan_flow, "auto", False)

        def tapped_force(self, sender):
            run_bg(self.app.scan_flow, "force", False)

        def tapped_all(self, sender):
            run_bg(self.app.scan_flow, "auto", True)

        def layout(self):
            w, h = self.width, self.height
            pad = 16
            inner = w - 2 * pad
            self.scroll.frame = (0, 0, w, h)
            y = 14
            if not self.servers.hidden:
                self.servers.frame = (pad, y, inner, 34)
                y += 46
            self.net_btn.frame = (pad, y, inner, 38)
            y += 50
            if not self.empty_btn.hidden:
                self.empty_btn.frame = (pad, y, inner, 56)
                y += 68
            if not self.scan_btn.hidden:
                self.scan_btn.frame = (pad, y, inner, 60)
                y += 64
                half = inner / 2.0
                self.force_btn.frame = (pad + half, y, half, 30)
                self.all_btn.frame = (pad, y, half, 30)
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
        """Runs one job per server on one network; implements :class:`Events`."""

        def __init__(self, app, sids, nid, mode):
            self.app = app
            self.sids = list(sids)
            self.nid = nid
            self.mode = mode
            self.index = 0
            self.summary = []
            self.rows = []
            self.result = None
            self.job = None
            self.started = time.time()
            store = app.store
            self.name = store.network(nid)["name"]
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

            self.outcome = make_label("", 15, bold=True, lines=4, align="center")
            self.outcome.corner_radius = 14
            self.outcome.hidden = True
            self.notes = make_label("", 13, color=WARN, lines=5)
            self.notes.background_color = WARN_BG
            self.notes.corner_radius = 12
            self.notes.hidden = True
            self.table_title = make_label("جواب‌داده‌ها", 14, bold=True)
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
            self.anyway_btn = make_button("اعمال با این وجود", self.tapped_anyway, color=BAD)
            self.done_btn = make_button("بازگشت", self.tapped_done)
            for v in (self.stop_btn, self.apply_btn, self.anyway_btn, self.done_btn):
                self.add_subview(v)
            self.apply_btn.hidden = self.anyway_btn.hidden = self.done_btn.hidden = True

        @property
        def batch(self):
            return len(self.sids) > 1

        @property
        def running(self):
            return self.job is not None and self.job.running

        def start(self):
            console.set_idle_timer_disabled(True)
            self._begin(0)

        @on_main_thread
        def _begin(self, index):
            self.index = index
            sid = self.sids[index]
            store = self.app.store
            server = store.server(sid)
            group = store.network(self.nid)["group"]
            self.server_label.text = fa("%s · %s" % (server["name"], GROUP_NAMES[group]))
            self.record_label.text = server.get("record_" + group) or server["sni"]
            self.batch_label.text = fa("سرور %d از %d" % (index + 1, len(self.sids))) \
                if self.batch else ""
            for icon, name, detail in self.step_views:
                icon.text, icon.text_color = STEP_ICONS["wait"]
                name.text_color = MUTED
                detail.text = ""
            self.fraction = 0.0
            self.counter.text = ""
            self.rows = []
            self.ds.items = []
            self.table_title.text = fa("جواب‌داده‌ها")
            self.job = ScanJob(store, sid, self.nid, events=self, mode=self.mode)
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
                detail.frame = (12, row_y + 24, inner - 56, 34)
                row_y += 62
            self.track.frame = (12, row_y + 2, inner - 24, 8)
            self.fill.frame = (0, 0, (inner - 24) * self.fraction, 8)
            self.counter.frame = (12, row_y + 14, inner - 24, 18)
            card_h = row_y + 40
            self.step_card.frame = (pad, y, inner, card_h)
            y += card_h + 12
            if not self.outcome.hidden:
                self.outcome.frame = (pad, y, inner, 92)
                y += 104
            if not self.notes.hidden:
                self.notes.frame = (pad, y, inner, 84)
                y += 96
            self.table_title.frame = (pad, y, inner, 22)
            y += 28
            table_h = max(3, len(self.ds.items)) * self.table.row_height
            self.table.frame = (pad, y, inner, table_h)
            y += table_h + 20
            self.scroll.content_size = (w, y)
            by = h - bottom + 12
            if self.stop_btn.hidden:
                visible = [b for b in (self.apply_btn, self.anyway_btn, self.done_btn)
                           if not b.hidden]
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
            if index == 2 and status == "run" and self.job is not None:
                label = TEST_LABEL[self.app.store.target(self.app.store.server(self.job.sid)).kind]
                self.table_title.text = fa("%s · نوسان · افت · دیتاسنتر" % label)

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
            kind = result.get("kind")
            if result.get("hint") or (kind in ("error", "apply_failed") and result.get("message")):
                self.note(result.get("hint") or result["message"])
            if self.batch:
                self.summary.append((self.sids[self.index], result))
                if self.index + 1 < len(self.sids) and kind != "stopped":
                    self._begin(self.index + 1)
                    return
            self._done()

        def _done(self):
            console.set_idle_timer_disabled(False)
            store = self.app.store
            self.stop_btn.hidden = True
            self.done_btn.hidden = False
            if self.batch:
                lines, good = [], 0
                for sid, r in self.summary:
                    good += r.get("kind") in GOOD_KINDS
                    lines.append(fa("%s: %s" % (store.server(sid)["name"],
                                                result_line(r, store).replace("\n", " · "))))
                self.rows = []
                self.ds.items = lines
                self.ds.font = ("<System>", 13)
                self.table.row_height = 60
                self.table_title.text = fa("نتیجهٔ همهٔ سرورها")
                self._show_outcome("%d از %d سرور درست است" % (good, len(self.summary)),
                                   good == len(self.summary))
            else:
                r = self.result or {}
                kind = r.get("kind")
                self.apply_btn.hidden = kind not in ("pending", "apply_failed")
                self.anyway_btn.hidden = kind != "conflict" or not r.get("record")
                self._show_outcome(result_line(r, store), kind in GOOD_KINDS)
            console.hud_alert("تمام شد · %.0f ثانیه" % (time.time() - self.started), "success", 1.2)
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

        def tapped_done(self, sender):
            self.app.nav.pop_view()

        def tapped_apply(self, sender):
            sender.enabled = False
            run_bg(self._apply_flow, None, "apply")

        def tapped_anyway(self, sender):
            r = self.result or {}
            names = [n["name"] for n in self.app.store.networks
                     if n["group"] == r.get("group") and n["id"] != self.nid]
            if alert("اعمال با این وجود",
                     "این IP روی %s کار نمی‌کند؛ مشتری‌های آن اینترنت قطع می‌شوند. ادامه؟"
                     % "، ".join(names), "اعمال") == 1:
                sender.enabled = False
                self._apply_flow(list(r.get("conflict") or []), "forced")

        def _apply_flow(self, ips, kind):
            ok = self.job.apply(self.result, ips, kind)
            self._after_apply(ok)

        @on_main_thread
        def _after_apply(self, ok):
            self.apply_btn.hidden = ok
            self.anyway_btn.hidden = True
            self.apply_btn.enabled = True
            self._show_outcome(result_line(self.result or {}, self.app.store), ok)
            self.layout()
            self.app.main.refresh()

        def row_tapped(self, ds):
            index = ds.selected_row
            if self.running or self.batch or index < 0 or index >= len(self.rows):
                return
            run_bg(self.app.address_menu, self.rows[index]["ip"], self.sids[0])

    class ListView(ui.View):
        """A titled, read-only list of lines."""

        def __init__(self, app, title, lines, row_height=52):
            self.name = title
            self.background_color = BG
            self.table = ui.TableView()
            self.ds = ui.ListDataSource(lines or [fa("هنوز چیزی ثبت نشده")])
            self.ds.font = ("<System>", 13)
            self.table.data_source = self.table.delegate = self.ds
            self.table.row_height = row_height
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
            self.connection = None

        def run(self):
            log("=== app start v%s ===" % APP_VERSION)
            enable_crash_trace()
            self.main = MainView(self)
            self.nav = ui.NavigationView(self.main)
            self.nav.present("fullscreen", hide_title_bar=False)
            if not self.store.servers or not self.store.token:
                run_bg(self.first_run)
            else:
                run_bg(self.detect, True)

        @on_main_thread
        def push_list(self, title, lines):
            self.nav.push_view(ListView(self, title, lines))

        @on_main_thread
        def open_scan(self, sids, nid, mode):
            if self.active_scan is not None and self.active_scan.running:
                self.nav.push_view(self.active_scan)
                return
            view = ScanView(self, sids, nid, mode)
            self.active_scan = view
            self.nav.push_view(view)
            view.start()

        # -- flows (background threads) ----------------------------------

        def detect(self, ask=True):
            """Where the phone is; picks (or asks for) the network. None when
            a scan must not run: no internet, or not seen in Iran."""
            self.main.set_connection(None)
            info = detect_connection()
            self.connection = info
            network = None
            if info["ok"] and (not info["country"] or info["country"] == "IR"):
                network = self.resolve_network(info, ask)
            self.main.set_connection(info, network)
            self.main.refresh()
            return network

        def resolve_network(self, info, ask=True):
            store = self.store
            asn = info.get("asn")
            if not asn:
                return store.current_network  # no ASN from Cloudflare: the manual choice
            known = store.network_for_asn(asn)
            if known:
                store.set_network(known["id"])
                return known
            if not ask:
                return None
            name, group = KNOWN_ASNS.get(asn, (info.get("org") or "AS%d" % asn, "home"))
            items = ["%s (%s)" % (n["name"], GROUP_NAMES[n["group"]]) for n in store.networks]
            items.append("+ اینترنت جدید: %s" % name)
            index = pick("این اینترنت کدام است؟ AS%d %s" % (asn, info.get("org") or ""), items)
            if index is None:
                return None
            if index < len(store.networks):
                nid = store.networks[index]["id"]
                store.save_network(nid, store.network(nid)["name"], store.network(nid)["group"], asn)
            else:
                name = console.input_alert("نام اینترنت", "", name, "ادامه").strip() or name
                g = pick("%s موبایل است یا خانگی؟" % name,
                         ["موبایل (همراه اول، ایرانسل…)", "خانگی (ADSL، فیبر، TD-LTE…)"])
                if g is None:
                    return None
                nid = store.save_network(None, name, GROUPS[g], asn)
            store.set_network(nid)
            return store.network(nid)

        def scan_flow(self, mode, every):
            store = self.store
            server = store.selected
            if server is None:
                return self.edit_server(None)
            network = self.detect(True)
            info = self.connection or {}
            if network is None:
                if not info.get("ok"):
                    alert("اینترنت", "اینترنت در دسترس نیست (%s)." % info.get("error", ""))
                elif info.get("country") and info["country"] != "IR":
                    alert("VPN روشن است", "کلادفلر این گوشی را در %s می‌بیند. VPN را خاموش کنید "
                                          "تا اسکن مال همین اینترنت باشد." % info["country"])
                return
            sids = [s["id"] for s in store.servers] if every else [server["id"]]
            self.open_scan(sids, network["id"], mode)

        def first_run(self):
            alert("خوش آمدید",
                  "۱. سرور: لینک vless کانفیگ CDN آن سرور را بچسبانید و رکورد موبایل "
                  "(مثلاً cdn1.germany…) را تأیید کنید.\n"
                  "۲. توکن کلادفلر.\n\n"
                  "بعد VPN را خاموش کنید، سرور را انتخاب کنید و «اسکن» را بزنید. اینترنت "
                  "(همراه اول، ایرانسل…) خودکار تشخیص داده می‌شود.")
            if not self.store.servers:
                self.edit_server(None)
            if not self.store.token:
                self.edit_token()
            self.detect(True)

        def open_settings(self):
            server = self.store.selected
            items = ["سرورها", "کلادفلر (توکن)", "اینترنت‌ها", "پیشرفته"]
            if server:
                items.insert(0, "ویرایش سرور «%s»" % server["name"])
            index = pick("تنظیمات", items)
            if index is None:
                return
            choice = items[index]
            if choice.startswith("ویرایش"):
                self.edit_server(server["id"])
            elif choice == "سرورها":
                self.manage_servers()
            elif choice.startswith("کلادفلر"):
                self.edit_token()
            elif choice == "اینترنت‌ها":
                self.manage_networks()
            else:
                self.edit_advanced()

        def edit_token(self):
            s = self.store.settings
            has = bool(self.store.token)
            sections = [("کلادفلر", [
                {"type": "password", "key": "token",
                 "title": "API Token (%s)" % ("ذخیره شده" if has else "خالی"), "value": ""},
                text_field("zone_id", "Zone ID (اختیاری)", s["zone_id"]),
            ], "توکن فقط در Keychain ذخیره می‌شود. خالی = بدون تغییر، «-» = پاک کردن. دسترسی: "
               "Zone → DNS → Edit و بهتر است Zone → Zone → Read."), ("رکوردها", [
                text_field("ips_per_record", "تعداد IP در هر رکورد (۱ تا ۳)", s["ips_per_record"], "number"),
                {"type": "switch", "key": "auto_apply", "title": "اعمال خودکار", "value": s["auto_apply"]},
            ], "هر IP رکورد باید روی اینترنت‌های همان گروه سالم باشد؛ کلاینت هر کدام را ممکن است بردارد.")]
            values = dialogs.form_dialog("کلادفلر", sections=sections, done_button_title="ذخیره")
            if values is None:
                return
            raw = (values.pop("token", "") or "").strip()
            try:
                self.store.update_settings(values)
            except ValueError as exc:
                alert("مقدار نامعتبر", str(exc))
                return self.edit_token()
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
            if raw and raw != "-" and self.store.servers:
                self.test_cloudflare()

        def edit_advanced(self):
            s = self.store.settings
            fields = [
                text_field("max_ping_ms", "حداکثر تأخیر کانفیگ سالم (ms)", s["max_ping_ms"], "number"),
                text_field("max_loss_pct", "حداکثر افت مجاز (٪)", s["max_loss_pct"], "number"),
                text_field("min_gain_pct", "اسکن کامل: حداقل بهبود برای تعویض (٪)", s["min_gain_pct"], "number"),
                text_field("fresh_hours", "اعتبار نتیجهٔ هر اینترنت (ساعت)", s["fresh_hours"], "number"),
                text_field("ttl", "TTL رکورد (ثانیه)", s["ttl"], "number"),
                text_field("candidates", "تعداد کاندید", s["candidates"], "number"),
                text_field("workers", "تست همزمان (اسکن سریع)", s["workers"], "number"),
                text_field("timeout", "مهلت هر اتصال (ثانیه)", s["timeout"], "number"),
                text_field("stop_after", "توقف بعد از N پاسخ (۰=همه)", s["stop_after"], "number"),
                text_field("verify_top", "تعداد IP برای اندازه‌گیری دقیق", s["verify_top"], "number"),
                text_field("verify_attempts", "تلاش برای هر IP", s["verify_attempts"], "number"),
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
            store = self.store
            server = store.server(sid) if sid else dict(SERVER_DEFAULTS)
            has_link = bool(sid and store.uuid_for(sid))
            clip = ""
            try:
                clip = (clipboard.get() or "").strip()
            except Exception:
                pass
            offer = clip if clip.lower().startswith("vless://") else ""
            link_title = "vless://… (%s)" % ("از کلیپ‌بورد" if offer else
                                             "ذخیره شده ✓" if has_link else "اینجا بچسبانید")
            sections = [
                ("کانفیگ CDN این سرور", [text_field("link", link_title, offer)],
                 "لینک کانفیگ CDN همین سرور را از پنل کپی کنید. دامنه، path و پورت از آن پر "
                 "می‌شوند و تست دقیقاً مثل «real delay» کلاینت‌ها انجام می‌شود. فقط UUID در "
                 "Keychain ذخیره می‌شود. خالی = بدون تغییر، «-» = حذف."),
                ("سرور", [
                    text_field("name", "نام (مثلاً آلمان)", server["name"]),
                    text_field("sni", "دامنهٔ CDN (SNI)", server["sni"]),
                    text_field("path", "WebSocket path", server["path"]),
                    text_field("port", "پورت", server["port"], "number"),
                    {"type": "switch", "key": "tls", "title": "TLS", "value": server["tls"]},
                ], "اگر لینک بدهید، این‌ها خودکار پر می‌شوند."),
                ("رکوردها (ابر خاکستری)", [
                    text_field("record_mobile", "موبایل (همراه اول، ایرانسل)", server["record_mobile"]),
                    text_field("record_home", "خانگی (اختیاری)", server["record_home"]),
                ], "address هاست CDN در پنل. موبایل خالی = cdn1.<دامنه>. خانگی را فقط وقتی "
                   "بگذارید که برای مشتری‌های خانگی یک کانفیگ CDN جدا دارید (مثلاً cdn2.<دامنه>)؛ "
                   "اسکن موبایل هیچ‌وقت به آن دست نمی‌زند."),
            ]
            if sid:
                sections.append(("", [{"type": "switch", "key": "delete", "title": "حذف این سرور",
                                       "value": False}]))
            values = dialogs.form_dialog("سرور CDN", sections=sections, done_button_title="ذخیره")
            if values is None:
                return
            if sid and values.get("delete"):
                if alert("حذف", "سرور «%s» حذف شود؟ رکوردهای DNS دست نمی‌خورند." % server["name"],
                         "حذف") == 1:
                    store.delete_server(sid)
                    self.main.refresh()
                return
            raw_link = (values.pop("link", "") or "").strip()
            uuid_value = None
            if raw_link == "-":
                uuid_value = ""
            elif raw_link:
                try:
                    parsed = parse_vless_link(raw_link)
                except ValueError as exc:
                    alert("لینک کانفیگ", str(exc))
                    return self.edit_server(sid)
                uuid_value = parsed["uuid"]
                for key in ("sni", "path", "port", "tls", "host"):
                    values[key] = parsed[key]
                if not (values.get("name") or "").strip() and parsed["name"]:
                    values["name"] = parsed["name"]
            sni = normalise_host(values.get("sni"))
            if not sni:
                alert("دامنهٔ CDN", "لینک کانفیگ یا دامنهٔ CDN را وارد کنید.")
                return self.edit_server(sid)
            if not normalise_host(values.get("record_mobile")):
                values["record_mobile"] = suggest_record(sni, "cdn1")
            for field in ("record_mobile", "record_home"):
                if normalise_host(values.get(field)) == sni:
                    alert("رکورد", "رکورد آدرس باید با دامنهٔ CDN فرق داشته باشد (رکورد خاکستری، "
                                   "دامنهٔ CDN نارنجی).")
                    return self.edit_server(sid)
            if (normalise_host(values.get("record_home"))
                    and normalise_host(values["record_home"]) == normalise_host(values["record_mobile"])):
                alert("رکورد", "رکورد خانگی باید با رکورد موبایل فرق داشته باشد.")
                return self.edit_server(sid)
            try:
                sid = store.save_server(sid, values)
            except ValueError as exc:
                alert("مقدار نامعتبر", str(exc))
                return self.edit_server(sid)
            if uuid_value is not None:
                store.set_uuid(sid, uuid_value)
            store.select_server(sid)
            self.main.refresh()
            console.hud_alert("ذخیره شد")

        def manage_servers(self):
            while True:
                servers = self.store.servers
                items = ["%s — %s%s" % (s["name"], s["record_mobile"] or "بدون رکورد",
                                        " · لینک ✓" if self.store.uuid_for(s["id"]) else "")
                         for s in servers]
                index = pick("سرورها", items + ["+ سرور جدید"])
                if index is None:
                    break
                self.edit_server(servers[index]["id"] if index < len(servers) else None)
            self.main.refresh()

        def manage_networks(self):
            store = self.store
            while True:
                networks = store.networks
                items = ["%s — %s%s" % (n["name"], GROUP_NAMES[n["group"]],
                                        " · " + ", ".join("AS%d" % a for a in n["asns"])
                                        if n["asns"] else "")
                         for n in networks]
                index = pick("اینترنت‌ها", items)
                if index is None:
                    break
                n = networks[index]
                values = dialogs.form_dialog(n["name"], [
                    text_field("name", "نام", n["name"]),
                    {"type": "switch", "key": "home", "title": "خانگی (نه موبایل)",
                     "value": n["group"] == "home"},
                    text_field("asns", "ASNها (با کاما)", ", ".join(str(a) for a in n["asns"])),
                    {"type": "switch", "key": "delete", "title": "حذف این اینترنت", "value": False},
                ], done_button_title="ذخیره")
                if values is None:
                    continue
                if values.get("delete"):
                    if alert("حذف", "«%s» و نتایجش حذف شود؟" % n["name"], "حذف") == 1:
                        try:
                            store.delete_network(n["id"])
                        except ValueError:
                            alert("حذف", "حداقل یک اینترنت لازم است.")
                    continue
                store.save_network(n["id"], values.get("name", ""),
                                   "home" if values.get("home") else "mobile")
                asns = [int(a) for a in re.findall(r"\d+", values.get("asns") or "")]
                with store.lock:
                    store.network(n["id"])["asns"] = asns
                    store.save()
            self.main.refresh()

        def open_tools(self):
            server = self.store.selected
            name = server["name"] if server else "—"
            items = [
                "جدول IPهای «%s»" % name,
                "تاریخچهٔ «%s»" % name,
                "تست یک IP روی «%s»" % name,
                "تنظیم دستی رکورد",
                "برگرداندن رکورد به IP قبلی",
                "تست اتصال به کلادفلر",
                "تشخیص دوبارهٔ اینترنت",
                "به‌روزرسانی رنج IP کلادفلر",
                "پاک کردن حافظهٔ IPها",
                "کپی تنظیمات (بدون توکن و UUID)",
                "وارد کردن تنظیمات از کلیپ‌بورد",
                "کپی لاگ برای گزارش خطا",
            ]
            index = pick("ابزارها", items)
            if index is None:
                return
            if index in (0, 1, 2, 3, 4) and server is None:
                alert("سرور", "اول یک سرور اضافه کنید.")
                return
            if index == 0:
                self.push_list("IPهای %s (★ = در رکورد)" % name, matrix_lines(self.store, server["id"]))
            elif index == 1:
                self.push_list("تاریخچهٔ %s" % name, history_lines(self.store, server["id"]))
            elif index == 2:
                ip = console.input_alert("تست یک IP", "آدرس IP کلادفلر", "", "تست").strip()
                self.test_ip(ip, server["id"])
            elif index == 3:
                key = self.pick_slot(server["id"])
                if key:
                    text = console.input_alert(record_name(self.store, key),
                                               "یک یا چند IP، با کاما جدا کنید", "", "اعمال")
                    self.apply_manual(key, [x.strip() for x in text.replace(" ", ",").split(",")
                                            if x.strip()])
            elif index == 4:
                key = self.pick_slot(server["id"])
                if key:
                    old = self.store.previous_ips(key)
                    if not old:
                        alert("برگرداندن", "IP قبلی ثبت نشده.")
                    elif alert("برگرداندن", "%s به %s برگردد؟" % (record_name(self.store, key),
                                                                 ", ".join(old)), "برگردان") == 1:
                        self.apply_manual(key, old, "rollback")
            elif index == 5:
                self.test_cloudflare()
            elif index == 6:
                self.detect(True)
            elif index == 7:
                self.refresh_ranges()
            elif index == 8:
                if alert("پاک کردن", "جدول IPها و حافظهٔ IPهای بد پاک شود؟", "پاک کن") == 1:
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
                console.hud_alert("وارد شد؛ لینک هر سرور را دوباره بدهید")
            elif index == 11:
                clipboard.set(read_log_tail(120))
                console.hud_alert("لاگ کپی شد")

        def pick_slot(self, sid):
            slots = self.store.slots(sid)
            if not slots:
                alert("رکورد", "این سرور رکوردی ندارد.")
                return None
            if len(slots) == 1:
                return slots[0][0]
            index = pick("کدام رکورد؟", ["%s — %s" % (GROUP_NAMES[g], name)
                                         for _, _, name, g in slots])
            return None if index is None else slots[index][0]

        def address_menu(self, ip, sid):
            slots = self.store.slots(sid)
            items = ["کپی IP", "تست دوباره (۱۰ بار)"] + \
                    ["گذاشتن روی رکورد %s" % GROUP_NAMES[g] for _, _, _, g in slots]
            index = pick(ip, items)
            if index is None:
                return
            if index == 0:
                clipboard.set(ip)
                console.hud_alert("کپی شد")
            elif index == 1:
                self.test_ip(ip, sid)
            else:
                key, _, name, _ = slots[index - 2]
                if alert(name, "%s فقط روی %s تنظیم شود؟" % (name, ip), "بله") == 1:
                    self.apply_manual(key, [ip])

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

        def test_ip(self, ip, sid):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                alert("IP نامعتبر", ip)
                return
            store = self.store
            server = store.server(sid)
            network = self.detect(True)
            if network is None:
                alert("اینترنت", "اول VPN را خاموش کنید و اینترنت را بررسی کنید.")
                return
            s = store.settings
            target = store.target(server)
            console.show_activity()
            try:
                trace = trace_probe(ip, target, make_context(), float(s["timeout"]) + 1)
                m = measure(ip, target, make_context(), 10, float(s["timeout"]) + 2,
                            target.kind != "trace", warmup=True)
            finally:
                console.hide_activity()
            ok = is_healthy(m, s["max_loss_pct"], s["max_ping_ms"])
            store.record_result(sid, ip, network["id"], ok, m["delay"], trace.get("colo", ""))
            store.save()
            self.main.refresh()
            lines = ["%s · %s" % (server["name"], network["name"]),
                     "نتیجه: %s" % ("سالم" if ok else "ناسالم"),
                     "%s: %s" % (TEST_LABEL[target.kind],
                                 "%.0f ms" % m["delay"] if m["delay"] is not None else "—"),
                     "پینگ TCP: %s" % ("%.0f ms" % m["ping"] if m["ping"] is not None else "—"),
                     "نوسان: %.0f · افت: %.0f%%" % (m["jitter"] or 0, m["loss"]),
                     "دیتاسنتر: %s" % (trace.get("colo") or "—")]
            if m["errors"]:
                lines.append("خطاها: %s" % error_summary(m["errors"]))
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
                if not store.slots():
                    lines.append("هیچ سروری رکورد ندارد.")
                for key, _, name, _ in store.slots():
                    try:
                        zone_name, ips, notes = inspect_record(store, key, rtype)
                        store.set_record_ips(key, ips)
                        line = "%s (%s): %s" % (store.slot_label(key), name,
                                                ", ".join(ips) or "هنوز رکورد %s ندارد" % rtype)
                        if zone_name:
                            line += "\n  دامنه: %s" % zone_name
                        for n in notes:
                            if "رکوردی با این نام" in n:
                                n += " (اولین اسکن خودش می‌سازدش)"
                            line += "\n  ⚠ %s" % n
                        lines.append(line)
                    except (CFError, NetError) as exc:
                        lines.append("%s: خطا — %s" % (store.slot_label(key), exc))
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

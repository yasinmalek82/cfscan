"""The iPhone app's engine (ios/cfscan_ios.py) without Pythonista.

The probes run against a real TLS server on 127.0.0.1 with a throwaway
certificate; the scan tests replace the probes and the Cloudflare API with
scripted fakes. Nothing here contacts a public network.
"""

from __future__ import annotations

import importlib.util
import json
import os
import random
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

_PATH = Path(__file__).resolve().parent.parent / "ios" / "cfscan_ios.py"
_spec = importlib.util.spec_from_file_location("cfscan_ios", _PATH)
app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(app)
# The app logs next to itself; keep test runs out of the source tree.
_LOG_DIR = tempfile.mkdtemp()
app.LOG_PATH = os.path.join(_LOG_DIR, "cfscan_ios_log.txt")


TEST_TOKEN = "Ab3dEf6hIj9lMn2pQr5tUv8xYz1bCd4fGh7jKl0n"



class MemorySecrets:
    def __init__(self, token=TEST_TOKEN):
        self.token = token
        self.named = {}

    def get(self, sid=None):
        return self.token

    def set(self, token, sid=None):
        self.token = token

    def get_named(self, name):
        return self.named.get(name, "")

    def set_named(self, name, value):
        self.named[name] = value


def make_store(tmp, token=TEST_TOKEN, record_home="", **settings):
    """Server ``s1`` (DE) with its mobile record; networks mci, mtn (mobile), home."""
    store = app.Store(os.path.join(tmp, "data.json"), secrets=MemorySecrets(token))
    base = {"auto_apply": True, "verify_attempts": 3, "verify_top": 4, "stop_after": 0,
            "timeout": 0.5, "ips_per_record": 1}
    base.update(settings)
    store.update_settings(base)
    store.save_server(None, {"name": "DE", "sni": "germany.example.test", "path": "/ws",
                             "record_mobile": "cdn1.germany.example.test",
                             "record_home": record_home})
    return store


def add_turkey(store):
    return store.save_server(None, {"name": "TR", "sni": "turkey.example.test", "path": "/tr",
                                    "record_mobile": "cdn1.turkey.example.test"})


# ------------------------------------------------------------------ storage

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_defaults_fill_a_missing_file(self):
        store = app.Store(os.path.join(self.tmp, "none.json"), secrets=MemorySecrets())
        self.assertEqual(store.servers, [])
        self.assertIsNone(store.selected)
        self.assertEqual([(n["id"], n["group"]) for n in store.networks],
                         [("mci", "mobile"), ("mtn", "mobile"), ("home", "home")])
        self.assertEqual(store.network_for_asn(44244)["id"], "mtn")
        self.assertEqual(store.group_networks("mobile"), ["mci", "mtn"])

    def test_servers_records_and_selection(self):
        store = make_store(self.tmp, record_home="cdn2.germany.example.test")
        tr = add_turkey(store)
        self.assertEqual(store.selected["id"], "s1")
        store.select_server(tr)
        self.assertEqual(store.selected["name"], "TR")
        self.assertEqual([(k, name, g) for k, _, name, g in store.slots()],
                         [("s1:mobile", "cdn1.germany.example.test", "mobile"),
                          ("s1:home", "cdn2.germany.example.test", "home"),
                          (tr + ":mobile", "cdn1.turkey.example.test", "mobile")])
        self.assertEqual(store.slot_label("s1:home"), "DE · خانگی")
        self.assertEqual(app.record_name(store, tr + ":mobile"), "cdn1.turkey.example.test")
        with self.assertRaises(app.CFError):
            app.record_name(store, tr + ":home")
        self.assertEqual(app.suggest_record("germany.example.com"), "cdn1.germany.example.com")
        store.set_record_ips(tr + ":mobile", ["1.1.1.1"])
        store.save_server(tr, {"record_mobile": "cdn9.turkey.example.test"})
        self.assertEqual(store.record_ips(tr + ":mobile"), [])  # renamed: old state dropped
        store.delete_server(tr)
        self.assertEqual(store.selected["id"], "s1")
        self.assertNotIn(tr, store.data["matrix"])

    def test_settings_round_trip_and_bad_values_change_nothing(self):
        store = make_store(self.tmp, workers="16")
        again = app.Store(store.path, secrets=MemorySecrets())
        self.assertEqual(again.settings["workers"], 16)
        with self.assertRaises(ValueError):
            again.update_settings({"workers": "8", "ttl": "5"})
        self.assertEqual(again.settings["workers"], 16)
        with self.assertRaises(ValueError):
            again.save_server("s1", {"port": "70000"})

    def test_networks_learn_their_asn_and_group(self):
        store = make_store(self.tmp)
        nid = store.save_network(None, "مخابرات", "home", asn=58224)
        self.assertEqual(store.network_for_asn(58224)["id"], nid)
        self.assertEqual(store.group_networks("home"), ["home", nid])
        store.save_network("home", "خانگی", "home", asn=58224)  # moved to another network
        self.assertEqual(store.network_for_asn(58224)["id"], "home")
        store.record_result("s1", "1.1.1.1", nid, True, 50)
        store.delete_network(nid)
        self.assertNotIn(nid, store.cells("s1")["1.1.1.1"])
        with self.assertRaises(ValueError):
            store.save_network(None, "x", "office")

    def test_results_are_kept_per_server(self):
        store = make_store(self.tmp)
        tr = add_turkey(store)
        store.remember_bad("mci", ["1.1.1.1"])
        store.record_result("s1", "1.1.1.1", "mci", True, 400, "FRA", ts=10)
        store.record_result(tr, "1.1.1.1", "mci", True, 250, "FRA", ts=10)
        self.assertEqual(store.cells("s1")["1.1.1.1"]["mci"]["delay"], 400)
        self.assertEqual(store.cells(tr)["1.1.1.1"]["mci"]["delay"], 250)
        self.assertNotIn("1.1.1.1", store.bad_for("mci"))

    def test_secrets_never_reach_the_data_file(self):
        store = make_store(self.tmp, token="secret-token-123")
        store.set_uuid("s1", VLESS_UUID)
        store.save()
        text = Path(store.path).read_text(encoding="utf-8")
        for secret in ("secret-token-123", VLESS_UUID):
            self.assertNotIn(secret, text)
            self.assertNotIn(secret, store.export_json())
        self.assertEqual(store.target(store.server("s1")).kind, "vless")
        store.delete_server("s1")
        self.assertEqual(store.uuid_for("s1"), "")

    def test_export_import(self):
        store = make_store(self.tmp, workers="20")
        store.save_network(None, "شاتل", "home", asn=31549)
        other = app.Store(os.path.join(self.tmp, "other.json"), secrets=MemorySecrets())
        other.import_json(store.export_json())
        self.assertEqual(other.servers[0]["record_mobile"], "cdn1.germany.example.test")
        self.assertEqual(other.network_for_asn(31549)["name"], "شاتل")
        self.assertEqual(other.settings["workers"], 20)
        with self.assertRaises(ValueError):
            other.import_json('{"hello": 1}')

    def test_version_four_is_migrated(self):
        v4 = {"version": 4, "settings": {"workers": 20},
              "servers": [{"id": "s1", "name": "DE", "sni": "germany.example.com",
                           "record": "cdn1.germany.example.com", "record2": "cdn2.germany.example.com"},
                          {"id": "s2", "name": "TR", "sni": "turkey.example.com",
                           "record": "cdn1.turkey.example.com"}],
              "networks": [{"id": "mci", "name": "همراه اول"}, {"id": "home", "name": "خانگی"},
                           {"id": "n1", "name": "رایتل"}],
              "matrix": {"1.1.1.1": {"mci": {"ok": True, "ping": 300, "ts": 5}}},
              "records": {"s1": {"ips": ["1.1.1.1"], "ts": 5}, "s1:2": {"ips": ["2.2.2.2"]}},
              "history": [{"ts": 1, "record": "s1:2", "old": [], "new": ["2.2.2.2"]}]}
        data = app.normalise_data(v4)
        self.assertEqual(data["version"], 5)
        de = data["servers"][0]
        self.assertEqual((de["record_mobile"], de["record_home"]),
                         ("cdn1.germany.example.com", "cdn2.germany.example.com"))
        self.assertEqual(data["records"]["s1:mobile"]["ips"], ["1.1.1.1"])
        self.assertEqual(data["records"]["s1:home"]["ips"], ["2.2.2.2"])
        self.assertEqual(data["history"][0]["record"], "s1:home")
        self.assertEqual([(n["id"], n["group"]) for n in data["networks"]],
                         [("mci", "mobile"), ("home", "home"), ("n1", "mobile")])
        self.assertEqual(data["networks"][0]["asns"], [197207])
        for sid in ("s1", "s2"):
            self.assertEqual(data["matrix"][sid]["1.1.1.1"]["mci"],
                             {"ok": True, "delay": None, "colo": "", "ts": 5})

    def test_version_three_and_one_are_migrated(self):
        v3 = {"version": 3, "settings": {"ip1": "cdn1.germany.example.com", "max_ping_ms": 800},
              "servers": [{"id": "s1", "name": "DE", "sni": "germany.example.com"}],
              "records": {"ip1": {"ips": ["1.1.1.1"], "ts": 5}}}
        data = app.normalise_data(v3)
        self.assertEqual(data["servers"][0]["record_mobile"], "cdn1.germany.example.com")
        self.assertEqual(data["records"]["s1:mobile"]["ips"], ["1.1.1.1"])
        self.assertEqual(data["settings"]["max_ping_ms"], 1500)
        v1 = {"version": 1, "settings": {"sni": "cdn.example.com", "path": "ws"},
              "profiles": [{"id": "mci", "name": "MCI"}],
              "state": {"mci": {"good": {"1.1.1.1": {"ts": 5, "ping": 40}}, "bad": {"9.9.9.9": 6}}}}
        data = app.normalise_data(v1)
        self.assertEqual(data["servers"][0]["path"], "/ws")
        self.assertTrue(data["matrix"]["s1"]["1.1.1.1"]["mci"]["ok"])
        self.assertEqual(data["bad"]["mci"], {"9.9.9.9": 6})

    def test_previous_ips_and_history_per_server(self):
        store = make_store(self.tmp)
        store.add_history("s1:mobile", ["1.1.1.1"], ["2.2.2.2"], "mci")
        store.add_history("s2:mobile", ["7.7.7.7"], ["8.8.8.8"], "mtn")
        self.assertEqual(store.previous_ips("s1:mobile"), ["1.1.1.1"])
        self.assertEqual(len(store.history("s1")), 1)


# ------------------------------------------------------------------ choosing

NOW = 1000000.0
DAY = 86400.0
RUN = NOW - 60  # this run started a minute ago


def cell(ok, delay=None, age=0):
    return {"ok": ok, "delay": delay, "colo": "", "ts": NOW - age}


class ChooseTests(unittest.TestCase):
    MOBILE = ["mci", "mtn"]

    def choose(self, cells, current=(), mode="auto", count=1, nid="mci"):
        return app.choose_for_record(cells, nid, self.MOBILE, NOW, DAY, count, current, mode,
                                     20, since=RUN)

    def test_an_address_working_on_both_carriers_wins(self):
        cells = {"A": {"mci": cell(True, 300), "mtn": cell(True, 500)},
                 "B": {"mci": cell(True, 200)},
                 "C": {"mci": cell(True, 100), "mtn": cell(False)}}
        choice = self.choose(cells)
        self.assertEqual((choice["ips"], choice["kind"], choice["unverified"]), (["A"], "change", []))
        self.assertEqual(choice["tier"], {"A": 1, "B": 2})

    def test_an_untested_carrier_is_flagged(self):
        choice = self.choose({"B": {"mci": cell(True, 200)}})
        self.assertEqual((choice["ips"], choice["unverified"]), (["B"], ["mtn"]))

    def test_known_bad_on_the_other_carrier_is_a_conflict(self):
        choice = self.choose({"C": {"mci": cell(True, 100), "mtn": cell(False)}})
        self.assertEqual((choice["ips"], choice["kind"], choice["conflict"]), ([], "conflict", ["C"]))

    def test_only_this_runs_measurements_qualify_here(self):
        choice = self.choose({"A": {"mci": cell(True, 100, age=3600), "mtn": cell(True, 90)}})
        self.assertEqual(choice["kind"], "none")

    def test_stale_results_elsewhere_count_as_unknown(self):
        choice = self.choose({"A": {"mci": cell(True, 100), "mtn": cell(False, age=3 * DAY)}})
        self.assertEqual((choice["ips"], choice["unverified"]), (["A"], ["mtn"]))

    def test_auto_keeps_working_addresses_and_fills_gaps(self):
        cells = {"OLD": {"mci": cell(True, 600), "mtn": cell(True, 600)},
                 "NEW": {"mci": cell(True, 100), "mtn": cell(True, 100)},
                 "DEAD": {"mci": cell(False)}}
        choice = self.choose(cells, current=["OLD", "DEAD"], count=2)
        self.assertEqual(choice["ips"], ["OLD", "NEW"])

    def test_a_scan_does_not_leave_a_slow_address_behind(self):
        cells = {"SLOW": {"mci": cell(True, 900), "mtn": cell(True, 900)},
                 "DEAD": {"mci": cell(False)},
                 "A": {"mci": cell(True, 100), "mtn": cell(True, 120)},
                 "B": {"mci": cell(True, 150), "mtn": cell(True, 140)}}
        choice = self.choose(cells, current=["SLOW", "DEAD"], count=2)
        self.assertEqual(sorted(choice["ips"]), ["A", "B"])

    def test_a_verified_address_is_not_swapped_for_an_unverified_one(self):
        cells = {"OLD": {"mci": cell(True, 600), "mtn": cell(True, 600)},
                 "NEW": {"mci": cell(True, 100)}}  # never tested on Irancell
        self.assertEqual(self.choose(cells, current=["OLD"])["ips"], ["OLD"])

    def test_force_changes_only_for_a_clear_gain(self):
        cells = {"OLD": {"mci": cell(True, 110), "mtn": cell(True, 110)},
                 "NEW": {"mci": cell(True, 100), "mtn": cell(True, 100)}}
        self.assertEqual(self.choose(cells, ["OLD"], "force")["kind"], "keep")
        cells["NEW"] = {"mci": cell(True, 50), "mtn": cell(True, 50)}
        self.assertEqual(self.choose(cells, ["OLD"], "force")["ips"], ["NEW"])

    def test_other_servers_and_failed_scans_fill_the_gaps(self):
        cells = {"A": {"mci": cell(True, 100)}, "B": {"mci": cell(True, 120)}}
        hints = {"A": {"mtn": "fail"}, "B": {"mtn": "ok"}}
        choice = app.choose_for_record(cells, "mci", self.MOBILE, NOW, DAY, 1, (), "auto", 20,
                                       since=RUN, hints=hints)
        self.assertEqual((choice["ips"], choice["unverified"]), (["B"], []))

    def test_record_health_per_network(self):
        cells = {"A": {"mci": cell(True, 100), "mtn": cell(False)}, "B": {"mci": cell(True, 90)}}
        self.assertEqual(app.record_health(cells, ["A", "B"], self.MOBILE, NOW, DAY),
                         {"mci": "ok", "mtn": "fail"})
        self.assertEqual(app.record_health(cells, ["B"], self.MOBILE, NOW, DAY),
                         {"mci": "ok", "mtn": "unknown"})
        self.assertEqual(app.cell_text(cells["A"]["mci"], NOW, DAY), "100")
        self.assertEqual(app.cell_text(cells["A"]["mtn"], NOW, DAY), "✕")
        self.assertEqual(app.cell_text(None, NOW, DAY), "؟")


# ------------------------------------------------------------------ pure helpers

class HelperTests(unittest.TestCase):
    def test_plan_sync_rewrites_before_it_deletes(self):
        existing = [{"id": "r1", "content": "1.1.1.1"}, {"id": "r2", "content": "2.2.2.2"},
                    {"id": "r3", "content": "3.3.3.3"}]
        self.assertEqual(app.plan_sync(existing, ["2.2.2.2", "9.9.9.9"]),
                         [("update", "r1", "9.9.9.9"), ("delete", "r3", "3.3.3.3")])
        self.assertEqual(app.plan_sync([], ["9.9.9.9"]), [("create", None, "9.9.9.9")])
        self.assertEqual(app.plan_sync(existing[:1], ["1.1.1.1"]), [])
        dup = [{"id": "a", "content": "1.1.1.1"}, {"id": "b", "content": "1.1.1.1"}]
        self.assertEqual(app.plan_sync(dup, ["1.1.1.1", "5.5.5.5"]), [("update", "b", "5.5.5.5")])

    def test_candidates_start_with_known_good_and_skip_recent_failures(self):
        now = 1000000.0
        state = {"good": {"104.16.5.10": {"ts": now - 10}, "104.17.9.9": {"ts": now - 5}},
                 "bad": {"104.16.5.11": now - 60, "104.16.5.12": now - 99999}}
        out = app.build_candidates(state, 60, 4, app.CF_RANGES_V4, rng=random.Random(3),
                                   now=now, bad_ttl_s=3600, exclude=["104.17.9.9"])
        self.assertEqual(out[0], "104.16.5.10")
        self.assertNotIn("104.17.9.9", out)
        self.assertNotIn("104.16.5.11", out)
        self.assertEqual(len(out), 60)
        self.assertEqual(len(set(out)), 60)
        neighbours = [ip for ip in out[1:9]]
        self.assertTrue(all(ip.startswith("104.16.5.") for ip in neighbours))
        for ip in out:
            last = int(ip.rsplit(".", 1)[1])
            self.assertNotIn(last, (0, 255))

    def test_ipv6_candidates_stay_ipv6(self):
        out = app.build_candidates({}, 20, 6, app.CF_RANGES_V6, rng=random.Random(1))
        self.assertEqual(len(out), 20)
        self.assertTrue(all(":" in ip for ip in out))

    def test_trace_and_status_parsing(self):
        raw = b"HTTP/1.1 200 OK\r\nServer: cloudflare\r\n\r\nfl=1\nip=5.6.7.8\ncolo=GYD\nloc=IR\n"
        self.assertEqual(app.parse_status(raw), 200)
        info = app.parse_trace(raw)
        self.assertEqual((info["colo"], info["loc"], info["ip"]), ("GYD", "IR", "5.6.7.8"))
        self.assertIsNone(app.parse_status(b"garbage"))

    def test_measure_summarises_attempts(self):
        answers = iter([
            {"ok": True, "tcp": 100.0, "total": 300.0, "colo": "FRA", "error": ""},
            {"ok": False, "tcp": None, "total": None, "colo": "", "error": "timeout"},
            {"ok": True, "tcp": 120.0, "total": 320.0, "colo": "FRA", "error": ""},
            {"ok": True, "tcp": 110.0, "total": 310.0, "colo": "FRA", "error": ""},
        ])
        m = app.measure("1.2.3.4", None, None, 4, 1, True, pause=0,
                        probe_ws=lambda *a: next(answers))
        self.assertEqual((m["ok"], m["attempts"], m["loss"]), (3, 4, 25.0))
        self.assertEqual(m["ping"], 110.0)
        self.assertEqual(m["delay"], 310.0)
        self.assertAlmostEqual(m["jitter"], 15.0)
        self.assertEqual(m["colo"], "FRA")
        self.assertFalse(app.is_healthy(m, 0, 800))
        self.assertTrue(app.is_healthy(m, 30, 800))
        self.assertFalse(app.is_healthy(m, 30, 300))
        self.assertLess(app.score({"delay": 100, "jitter": 1, "loss": 0}),
                        app.score({"delay": 90, "jitter": 1, "loss": 10}))

    def test_vless_links_are_parsed(self):
        link = ("vless://%s@cdn1.germany.example.com:2053?encryption=none&security=tls"
                "&sni=germany.example.com&type=ws&host=germany.example.com"
                "&path=%%2Fws%%3Fed%%3D2560#DE%%20%%F0%%9F%%9B%%A1" % VLESS_UUID)
        p = app.parse_vless_link(" " + link + "\u200f")
        self.assertEqual((p["uuid"], p["sni"], p["host"], p["path"], p["port"], p["tls"]),
                         (VLESS_UUID, "germany.example.com", "", "/ws", 2053, True))
        self.assertEqual(p["name"], "DE 🛡")
        for bad in ("vmess://abc", "vless://nouuid@x.com:443?type=ws",
                    "vless://%s@x.com:443?type=tcp&security=reality" % VLESS_UUID):
            with self.assertRaises(ValueError):
                app.parse_vless_link(bad)
        self.assertEqual(app.vless_request(VLESS_UUID, "a.b", 80, b"X")[:1], b"\x00")
        self.assertEqual(app.ws_frame(b"hi")[:2], bytes([0x82, 0x82]))

    def test_the_warmup_probe_is_not_counted(self):
        answers = iter([
            {"ok": True, "tcp": 250.0, "total": 900.0, "colo": "", "error": ""},
            {"ok": True, "tcp": 100.0, "total": 300.0, "colo": "", "error": ""},
            {"ok": True, "tcp": 100.0, "total": 310.0, "colo": "", "error": ""},
        ])
        m = app.measure("1.2.3.4", None, None, 2, 1, True, pause=0, warmup=True,
                        probe_ws=lambda *a: next(answers))
        self.assertEqual((m["attempts"], m["delay"]), (2, 305.0))

    def test_ago_and_colos(self):
        self.assertEqual(app.ago(0), "هرگز")
        self.assertEqual(app.ago(100, now=130), "همین الان")
        self.assertEqual(app.ago(0.5, now=7200.5), "2 ساعت پیش")
        self.assertEqual(app.parse_colos(" fra, AMS  muc"), {"FRA", "AMS", "MUC"})


class TokenTests(unittest.TestCase):
    def test_pasted_tokens_are_cleaned(self):
        tok = "cfat_" + "A1b2C3d4" * 5
        for pasted in (tok, " %s \n" % tok, "Bearer " + tok, '"%s"' % tok,
                       tok[:10] + "\u200b" + tok[10:], tok[:10] + "\u00a0" + tok[10:]):
            self.assertEqual(app.sanitize_token(pasted), tok, repr(pasted))

    def test_global_key_and_short_tokens_are_explained(self):
        self.assertIn("Global API Key", app.token_problem("0123456789abcdef0123456789abcdef01234"))
        self.assertIn("کوتاه", app.token_problem("abc"))
        self.assertEqual(app.token_problem("x" * 40), "")
        self.assertNotIn("A1b2C3d4" * 3, app.token_fingerprint("cfat_" + "A1b2C3d4" * 5))

    def test_an_account_token_verifies_under_its_account(self):
        calls = []

        class API(app.CloudflareAPI):
            def call(self, method, path, query=None, body=None):
                calls.append(path)
                if path == "/user/tokens/verify":
                    raise app.CFError("Invalid API Token (1000)", [1000])
                if path == "/zones":
                    return [{"id": "z1", "account": {"id": "acc1"}}]
                if path == "/accounts/acc1/tokens/verify":
                    return {"status": "active"}
                raise AssertionError(path)

        info = API("t").verify_token()
        self.assertEqual((info["status"], info["kind"]), ("active", "account"))
        self.assertEqual(calls, ["/user/tokens/verify", "/zones", "/accounts/acc1/tokens/verify"])

    def test_a_really_invalid_token_still_fails(self):
        class API(app.CloudflareAPI):
            def call(self, method, path, query=None, body=None):
                raise app.CFError("Invalid API Token (1000)", [1000])

        with self.assertRaises(app.CFError):
            API("t").verify_token()

    def test_other_refusals_are_not_retried(self):
        class API(app.CloudflareAPI):
            def call(self, method, path, query=None, body=None):
                if path != "/user/tokens/verify":
                    raise AssertionError(path)
                raise app.CFError("Cannot use the access token from location (9109)", [9109])

        with self.assertRaises(app.CFError) as ctx:
            API("t").verify_token()
        self.assertEqual(ctx.exception.codes, (9109,))


class ZoneTests(unittest.TestCase):
    """Zone lookup for records like mtn.cdn.example.com."""

    ZONES = [{"id": "z-ex", "name": "example.com", "account": {"id": "a1"}}]
    RECORDS = {"z-ex": [
        {"type": "A", "name": "mtn.cdn.example.com", "content": "1.1.1.1", "proxied": False},
        {"type": "A", "name": "mci.cdn.example.com", "content": "2.2.2.2", "proxied": True},
        {"type": "CNAME", "name": "mci.cdn.example.com", "content": "x.example.com"},
    ]}

    def api(self, name_filter=True, visible=True):
        test = self

        class API(app.CloudflareAPI):
            def call(self, method, path, query=None, body=None):
                query = query or {}
                if path == "/zones":
                    zones = test.ZONES if visible else []
                    if "name" in query:
                        return [z for z in zones if name_filter and z["name"] == query["name"]]
                    return zones
                if path.startswith("/zones/") and path.endswith("/dns_records"):
                    zone = path.split("/")[2]
                    if zone not in test.RECORDS:
                        raise app.CFError("Could not route (7003)", [7003])
                    out = test.RECORDS[zone]
                    if "name" in query:
                        out = [r for r in out if r["name"] == query["name"]]
                    if "type" in query:
                        out = [r for r in out if r["type"] == query["type"]]
                    return out
                if path.startswith("/zones/"):
                    return {"name": "example.com"}
                raise AssertionError(path)

        return API("t")

    def test_a_two_level_subdomain_finds_its_zone(self):
        self.assertEqual(self.api().find_zone("mtn.cdn.example.com"), "z-ex")

    def test_the_visible_zone_list_is_the_fallback(self):
        self.assertEqual(self.api(name_filter=False).find_zone("mtn.cdn.example.com"), "z-ex")

    def test_no_visible_zone_explains_the_missing_permission(self):
        with self.assertRaises(app.CFError) as ctx:
            self.api(visible=False).find_zone("mtn.cdn.example.com")
        self.assertIn("Zone ID", str(ctx.exception))

    def test_a_record_outside_every_zone_names_the_zones(self):
        with self.assertRaises(app.CFError) as ctx:
            self.api().find_zone("mtn.cdn")
        self.assertIn("example.com", str(ctx.exception))

    def test_a_wrong_zone_id_in_the_settings_falls_back_to_the_lookup(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        store = make_store(tmp, zone_id="0123456789abcdef0123456789abcdef")
        api = self.api()
        ips = app.with_zone(store, api, "mtn.cdn.example.com",
                            lambda zone: [r["content"] for r in
                                          api.list_records(zone, "mtn.cdn.example.com", "A")])
        self.assertEqual(ips, ["1.1.1.1"])
        self.assertEqual(store.zone_for("mtn.cdn.example.com"), "z-ex")

    def test_inspect_record_names_the_problems(self):
        api = self.api()
        self.assertEqual(api.inspect_record("z-ex", "mtn.cdn.example.com", "A"), (["1.1.1.1"], []))
        ips, notes = api.inspect_record("z-ex", "mci.cdn.example.com", "A")
        self.assertEqual(ips, ["2.2.2.2"])
        self.assertTrue(any("CNAME" in n for n in notes))
        self.assertTrue(any("نارنجی" in n for n in notes))
        ips, notes = api.inspect_record("z-ex", "mtn.example.com", "A")
        self.assertEqual(ips, [])
        self.assertIn("mtn.cdn.example.com", notes[0])

    def test_pasted_hostnames_are_cleaned(self):
        self.assertEqual(app.normalise_host(" https://MTN.cdn.Example.com:443/ws?x=1 "),
                         "mtn.cdn.example.com")
        self.assertEqual(app.normalise_host("mci.cdn.example.com.\u200f"), "mci.cdn.example.com")


# ------------------------------------------------------------------ real sockets

VLESS_UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"


class _TLSServer:
    """Answers /cdn-cgi/trace with 200 and the WebSocket path with 101.

    After the upgrade it acts as a tiny VLESS server: a request with the
    right uuid gets a VLESS response header and ``HTTP/1.1 204`` split over
    two server frames; a wrong uuid gets the connection closed.
    """

    def __init__(self, certfile, keyfile, ws_path="/ws"):
        self.ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ctx.load_cert_chain(certfile, keyfile)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.ws_path = ws_path
        self.hosts = []
        self.tunnel_requests = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            tls = self.ctx.wrap_socket(conn, server_side=True)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = tls.recv(4096)
                if not chunk:
                    return
                data += chunk
            head = data.decode("latin-1")
            path = head.split(" ", 2)[1]
            for line in head.split("\r\n"):
                if line.lower().startswith("host:"):
                    self.hosts.append(line.split(":", 1)[1].strip())
            if path == "/cdn-cgi/trace":
                body = b"fl=1\nip=5.6.7.8\ncolo=TST\nloc=IR\n"
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
            elif path == self.ws_path and "upgrade: websocket" in head.lower():
                tls.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n")
                self._vless(tls, data.split(b"\r\n\r\n", 1)[1])
            else:
                tls.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            tls.close()
        except (OSError, ssl.SSLError):
            pass

    @staticmethod
    def _frame(tls, pending):
        buf = pending

        def need(n):
            nonlocal buf
            while len(buf) < n:
                chunk = tls.recv(4096)
                if not chunk:
                    raise OSError("closed")
                buf += chunk
            out, buf = buf[:n], buf[n:]
            return out

        b0, b1 = need(2)
        n = b1 & 0x7F
        if n == 126:
            n = int.from_bytes(need(2), "big")
        mask = need(4)
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(need(n)))
        return b1 & 0x80, payload

    def _vless(self, tls, pending):
        tls.settimeout(2)
        try:
            masked, payload = self._frame(tls, pending)
        except OSError:
            return
        import uuid as uuid_mod
        version, user = payload[0], payload[1:17]
        addons = payload[17]
        rest = payload[18 + addons:]
        cmd, port = rest[0], int.from_bytes(rest[1:3], "big")
        atyp, alen = rest[3], rest[4]
        host = rest[5:5 + alen].decode()
        request = rest[5 + alen:]
        self.tunnel_requests.append((bool(masked), version, str(uuid_mod.UUID(bytes=user)),
                                     cmd, host, port, request))
        if str(uuid_mod.UUID(bytes=user)) != VLESS_UUID:
            return
        first = b"\x00\x00HTTP/1.1 2"
        second = b"04 No Content\r\n\r\n"
        tls.sendall(bytes([0x82, len(first)]) + first + bytes([0x80, len(second)]) + second)

    def close(self):
        self.sock.close()


@unittest.skipUnless(shutil.which("openssl"), "openssl is needed for a test certificate")
class ProbeSocketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.cert = os.path.join(cls.tmp, "cert.pem")
        cls.key = os.path.join(cls.tmp, "key.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", cls.key, "-out", cls.cert, "-days", "1",
                        "-subj", "/CN=cdn.example.test",
                        "-addext", "subjectAltName=DNS:cdn.example.test"],
                       check=True, capture_output=True)
        cls.server = _TLSServer(cls.cert, cls.key)

    @classmethod
    def tearDownClass(cls):
        cls.server.close()
        shutil.rmtree(cls.tmp)

    def client_ctx(self):
        ctx = ssl.create_default_context(cafile=self.cert)
        ctx.set_alpn_protocols(["http/1.1"])
        return ctx

    def target(self, path="/ws", sni="cdn.example.test"):
        return app.Target(sni, path, self.server.port, True)

    def test_trace_probe_reads_the_datacentre_with_our_sni(self):
        r = app.trace_probe("127.0.0.1", self.target(), self.client_ctx(), 3)
        self.assertTrue(r["ok"], r)
        self.assertEqual((r["colo"], r["loc"], r["client"]), ("TST", "IR", "5.6.7.8"))
        self.assertLessEqual(r["tcp"], r["total"])
        self.assertIn("cdn.example.test", self.server.hosts)

    def test_ws_probe_wants_101_on_the_config_path(self):
        self.assertTrue(app.ws_probe("127.0.0.1", self.target(), self.client_ctx(), 3)["ok"])
        wrong = app.ws_probe("127.0.0.1", self.target("/other"), self.client_ctx(), 3)
        self.assertFalse(wrong["ok"])
        self.assertEqual(wrong["error"], "HTTP 404")

    def test_a_vless_target_times_a_real_request_through_the_tunnel(self):
        target = app.Target("cdn.example.test", "/ws", self.server.port, True, uuid=VLESS_UUID)
        self.assertEqual(target.kind, "vless")
        r = app.ws_probe("127.0.0.1", target, self.client_ctx(), 3)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["status"], 204)
        masked, version, user, cmd, host, port, request = self.server.tunnel_requests[-1]
        self.assertTrue(masked)
        self.assertEqual((version, user, cmd, host, port),
                         (0, VLESS_UUID, 1, app.DELAY_TEST_HOST, 80))
        self.assertTrue(request.startswith(b"GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com"))

    def test_a_wrong_uuid_fails_after_the_upgrade(self):
        target = app.Target("cdn.example.test", "/ws", self.server.port, True,
                            uuid="00000000-0000-4000-8000-000000000000")
        r = app.ws_probe("127.0.0.1", target, self.client_ctx(), 3)
        self.assertFalse(r["ok"])
        self.assertIn(r["error"], ("reset", "timeout", "closed", "closed by server"))

    def test_a_certificate_for_another_name_is_a_tls_failure(self):
        r = app.trace_probe("127.0.0.1", self.target(sni="other.example.test"),
                            self.client_ctx(), 3)
        self.assertFalse(r["ok"])
        self.assertTrue(r["error"].startswith("TLS"), r["error"])

    def test_a_closed_port_fails_fast(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        r = app.trace_probe("127.0.0.1", app.Target("cdn.example.test", "", port),
                            self.client_ctx(), 2)
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "refused")


# ------------------------------------------------------------------ robustness

class RobustnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_a_dead_address_is_given_up_quickly(self):
        calls = []

        def dead(ip, target, ctx, timeout):
            calls.append(ip)
            return {"ip": ip, "ok": False, "tcp": None, "total": None, "error": "timeout"}

        m = app.measure("1.2.3.4", None, None, 6, 1, True, pause=0, warmup=True, probe_ws=dead)
        self.assertEqual(len(calls), 2)  # the warm-up and one attempt
        self.assertEqual((m["ok"], m["loss"], m["delay"]), (0, 100.0, None))

    def test_a_flaky_start_is_not_given_up(self):
        answers = iter([False, True, True, True])

        def flaky(ip, target, ctx, timeout):
            ok = next(answers)
            return {"ip": ip, "ok": ok, "tcp": 10.0 if ok else None,
                    "total": 30.0 if ok else None, "colo": "", "error": "" if ok else "reset"}

        m = app.measure("1.2.3.4", None, None, 3, 1, True, pause=0, warmup=True, probe_ws=flaky)
        self.assertEqual((m["ok"], m["attempts"]), (3, 4))

    def test_a_probe_that_raises_is_one_failure(self):
        def broken(ip, target, ctx, timeout):
            raise ValueError("bug")

        m = app.measure("1.2.3.4", None, None, 3, 1, False, pause=0, probe_trace=broken)
        self.assertEqual(m["errors"], ["ValueError", "ValueError"])

    def test_a_scan_survives_a_probe_that_raises(self):
        store = make_store(self.tmp)

        def probe(ip, target, ctx, timeout):
            if ip == "1.0.0.9":
                raise RuntimeError("bug")
            return scripted_probe({"1.0.0.2": (True, 100.0, "")})(ip, target, ctx, timeout)

        FakeAPI.records = {}
        FakeAPI.unreachable_direct = False
        job = app.ScanJob(store, "s1", "mci", context_factory=lambda: None, api_factory=FakeAPI,
                          candidates=["1.0.0.9", "1.0.0.2"], probe_trace=probe, probe_ws=probe)
        self.assertEqual(job.run()["kind"], "applied")

    def test_garbage_data_never_breaks_loading(self):
        rng = random.Random(7)
        atoms = [None, 0, -1, 3.5, "", "x", "1.1.1.1", True, [], {}, [1, "a"], {"a": 1}]

        def junk(depth=0):
            kind = rng.random()
            if depth > 3 or kind < 0.4:
                return rng.choice(atoms)
            if kind < 0.7:
                return [junk(depth + 1) for _ in range(rng.randrange(4))]
            keys = ["version", "settings", "servers", "networks", "matrix", "records", "history",
                    "bad", "profiles", "carriers", "state", "memory", "id", "sni", "record",
                    "ips", "ok", "asns", "group", "name", "zones", "ranges", "server", "network"]
            return {rng.choice(keys): junk(depth + 1) for _ in range(rng.randrange(6))}

        for _ in range(600):
            raw = junk()
            if isinstance(raw, dict) and rng.random() < 0.5:
                raw["version"] = rng.choice([1, 2, 3, 4, 5, "5", None])
            try:
                data = app.normalise_data(raw)
            except Exception as exc:  # the Store catches this, but it should not happen
                self.fail("normalise_data(%r) raised %r" % (raw, exc))
            self.assertEqual(data["version"], 5)
            json.dumps(data)

    def test_choice_rules_hold_for_random_tables(self):
        rng = random.Random(11)
        nets = ["mci", "mtn"]
        for _ in range(2000):
            cells = {}
            for i in range(rng.randrange(8)):
                ip = "10.0.0.%d" % i
                for n in nets:
                    if rng.random() < 0.7:
                        age = rng.choice([0, 30, 3600, 5 * DAY])
                        cells.setdefault(ip, {})[n] = cell(rng.random() < 0.6,
                                                           rng.choice([None, 80, 300, 900]), age)
            current = [ip for ip in cells if rng.random() < 0.3]
            count = rng.randrange(1, 4)
            mode = rng.choice(["auto", "force"])
            choice = app.choose_for_record(cells, "mci", nets, NOW, DAY, count, current, mode,
                                           20, since=RUN)
            here = [ip for ip in cells
                    if app.cell_status(cells[ip].get("mci"), NOW, DAY, RUN) == "ok"]
            failed_there = [ip for ip in cells
                            if app.cell_status(cells[ip].get("mtn"), NOW, DAY) == "fail"]
            self.assertLessEqual(len(choice["ips"]), count)
            self.assertEqual(len(set(choice["ips"])), len(choice["ips"]))
            for ip in choice["ips"]:
                self.assertIn(ip, here)
                self.assertNotIn(ip, failed_there)
            if choice["kind"] == "conflict":
                self.assertEqual(choice["ips"], [])
                self.assertTrue(set(choice["conflict"]) <= set(failed_there) & set(here))
            if choice["kind"] == "none":
                self.assertEqual([ip for ip in here if ip not in failed_there], [])
            # a working current address leaves only for a clearly faster one
            def worst(ip):
                delays = [c["delay"] for n, c in cells[ip].items()
                          if app.cell_status(c, NOW, DAY) == "ok" and c.get("delay") is not None]
                return max(delays) if delays else float("inf")

            kept = [ip for ip in current if ip in here and ip not in failed_there]
            newcomers = [ip for ip in choice["ips"] if ip not in current]
            dropped = [ip for ip in kept if ip not in choice["ips"]]
            if len(kept) <= count:
                self.assertLessEqual(len(dropped), len(newcomers))
                for ip in dropped:
                    self.assertTrue(any(worst(n) <= worst(ip) * 0.8 for n in newcomers),
                                    (ip, choice, cells))

    def test_many_threads_write_while_saving(self):
        store = make_store(self.tmp)
        errors = []

        def writer(k):
            try:
                for i in range(200):
                    store.record_result("s1", "10.%d.0.%d" % (k, i), "mci", i % 2 == 0, i)
                    store.remember_bad("mtn", ["10.%d.1.%d" % (k, i)])
                    if i % 20 == 0:
                        store.save()
                        store.cells_copy("s1")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(k,)) for k in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        again = app.Store(store.path, secrets=MemorySecrets())
        self.assertLessEqual(len(again.cells("s1")), app.MATRIX_LIMIT)

    def test_a_record_change_survives_a_restart(self):
        store = make_store(self.tmp)
        FakeAPI.records = {}
        FakeAPI.unreachable_direct = False
        job = app.ScanJob(store, "s1", "mci", context_factory=lambda: None, api_factory=FakeAPI,
                          candidates=["1.0.0.2"],
                          probe_trace=scripted_probe({"1.0.0.2": (True, 100.0, "")}),
                          probe_ws=scripted_probe({"1.0.0.2": (True, 100.0, "")}))
        job.run()
        again = app.Store(store.path, secrets=MemorySecrets())
        self.assertEqual(again.record_ips("s1:mobile"), ["1.0.0.2"])
        self.assertEqual(again.history()[0]["new"], ["1.0.0.2"])
        self.assertEqual(again.cells("s1")["1.0.0.2"]["mci"]["delay"], 100.0)

    def test_the_fast_pass_is_fast(self):
        store = make_store(self.tmp, candidates=2000, stop_after=0)
        table = {"10.%d.%d.1" % (i // 250, i % 250): (i % 7 == 0, 100.0 + i % 50, "")
                 for i in range(2000)}
        FakeAPI.records = {}
        FakeAPI.unreachable_direct = False
        job = app.ScanJob(store, "s1", "mci", context_factory=lambda: None, api_factory=FakeAPI,
                          candidates=list(table), probe_trace=scripted_probe(table),
                          probe_ws=scripted_probe(table))
        started = time.time()
        result = job.run()
        self.assertEqual(result["scanned"], 2000)
        self.assertLess(time.time() - started, 5.0)


class FrameTests(unittest.TestCase):
    class Sock:
        def __init__(self, chunks):
            self.chunks = list(chunks)

        def recv(self, n):
            return self.chunks.pop(0) if self.chunks else b""

    def test_long_and_split_frames(self):
        payload = bytes(range(256)) * 2
        frame = bytes([0x82, 126]) + len(payload).to_bytes(2, "big") + payload
        reader = app._WSReader(self.Sock([frame[:3], frame[3:100], frame[100:]]), b"")
        self.assertEqual(reader.frame(), (0x2, payload))
        big = b"x" * 70000
        frame = bytes([0x82, 127]) + len(big).to_bytes(8, "big") + big
        self.assertEqual(app._WSReader(self.Sock([frame]), b"").frame(), (0x2, big))

    def test_a_closed_connection_raises(self):
        with self.assertRaises(ConnectionResetError):
            app._WSReader(self.Sock([b"\x82"]), b"").frame()

    def test_vless_answer_split_across_frames(self):
        head = b"\x00\x02ab"  # version, 2 bytes of addons
        body = b"HTTP/1.1 204 No Content\r\n\r\n"
        frames = [bytes([0x82, 1]) + head[:1], bytes([0x80, 3]) + head[1:],
                  bytes([0x80, len(body)]) + body]

        class Sock(self.Sock):
            def sendall(self, data):
                pass

        target = app.Target("x.example", "/ws", 443, True, uuid=VLESS_UUID)
        self.assertEqual(app._vless_exchange(Sock(frames), b"", target), 204)
        closed = [bytes([0x88, 0])]
        with self.assertRaises(ConnectionResetError):
            app._vless_exchange(Sock(closed), b"", target)

    def test_client_frames_are_masked_and_sized(self):
        for n in (0, 125, 126, 65535, 65536):
            frame = app.ws_frame(b"a" * n)
            self.assertEqual(frame[0], 0x82)
            self.assertTrue(frame[1] & 0x80)
            header = {True: 2, False: 4 if n < 65536 else 10}[n < 126]
            self.assertEqual(len(frame), header + 4 + n)


# ------------------------------------------------------------------ the scan

class FakeAPI:
    """A Cloudflare stand-in keeping DNS records in a shared dict."""

    records = {}
    unreachable_direct = False
    down = False
    calls = []

    def __init__(self, token="", via_ip=None, **kw):
        self.token = token
        self.via_ip = via_ip

    def _check(self):
        FakeAPI.calls.append(self.via_ip)
        if FakeAPI.down:
            raise app.NetError("connection reset")
        if FakeAPI.unreachable_direct and self.via_ip is None:
            raise app.NetError("timeout")

    def find_zone(self, record):
        self._check()
        return "zone1"

    def list_records(self, zone, name, rtype):
        self._check()
        return [{"id": "r%d" % i, "content": ip}
                for i, ip in enumerate(FakeAPI.records.get((name, rtype), []))]

    def sync_records(self, zone, name, ips, rtype, ttl):
        self._check()
        FakeAPI.records[(name, rtype)] = list(ips)
        return [("sync", None, ip) for ip in ips]


def scripted_probe(table, loc="IR"):
    """A probe answering from ``table``: ip -> (ok, total_ms, colo)."""

    def probe(ip, target, ctx, timeout):
        ok, total, colo = table.get(ip, (False, None, ""))
        return {"ip": ip, "ok": ok, "tcp": total / 3 if ok else None,
                "total": total if ok else None, "status": 200 if ok else None,
                "colo": colo if ok else "", "loc": loc if ok else "", "client": "",
                "error": "" if ok else "timeout"}

    return probe


class RecordingEvents(app.Events):
    def __init__(self):
        self.steps = []
        self.details = {}
        self.notes = []
        self.progress_by_step = {}
        self.result = None

    def step(self, index, status, detail=""):
        self.steps.append((index, status))
        if detail:
            self.details[index] = detail

    def progress(self, done, total, found):
        running = [i for i, st in self.steps if st == "run"]
        if running:
            self.progress_by_step.setdefault(running[-1], []).append((done, total, found))

    def note(self, text):
        self.notes.append(text)

    def finished(self, result):
        self.result = result


DE = ("cdn1.germany.example.test", "A")
DE_HOME = ("cdn2.germany.example.test", "A")
TR = ("cdn1.turkey.example.test", "A")


class ScanJobTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        FakeAPI.records = {}
        FakeAPI.unreachable_direct = False
        FakeAPI.down = False
        FakeAPI.calls = []

    def job(self, store, nid, table, sid="s1", mode="auto", loc="IR", candidates=None,
            probe=None):
        probe = probe or scripted_probe(table, loc)
        return app.ScanJob(store, sid, nid, events=RecordingEvents(), mode=mode,
                           context_factory=lambda: None, api_factory=FakeAPI,
                           candidates=list(table) if candidates is None else candidates,
                           rng=random.Random(4), probe_trace=probe, probe_ws=probe)

    def test_first_scan_on_mci_fills_the_mobile_record(self):
        store = make_store(self.tmp)
        table = {"1.0.0.1": (True, 400.0, "GYD"), "1.0.0.2": (True, 150.0, "FRA"),
                 "1.0.0.3": (False, None, "")}
        job = self.job(store, "mci", table)
        result = job.run()
        self.assertEqual(result["kind"], "applied")
        self.assertEqual(FakeAPI.records[DE], ["1.0.0.2"])
        self.assertEqual(result["unverified"], ["mtn"])
        self.assertEqual(store.cells("s1")["1.0.0.2"]["mci"]["delay"], 150.0)
        self.assertIn("1.0.0.3", store.bad_for("mci"))
        self.assertEqual(store.history()[0]["record"], "s1:mobile")
        self.assertIn("ایرانسل", app.result_line(result, store))

    def test_irancell_then_confirms_or_replaces_it(self):
        store = make_store(self.tmp)
        self.job(store, "mci", {"1.0.0.1": (True, 300.0, ""), "1.0.0.2": (True, 150.0, "")}).run()
        # on Irancell the MCI winner fails; the other MCI address works on both
        mtn = {"1.0.0.1": (True, 200.0, ""), "1.0.0.2": (False, None, ""),
               "1.0.0.9": (True, 90.0, "")}
        seen = []

        def probe(ip, target, ctx, timeout):
            seen.append(ip)
            return scripted_probe(mtn)(ip, target, ctx, timeout)

        store.update_settings({"candidates": 20, "stop_after": 3})
        job = self.job(store, "mtn", mtn, candidates=None, probe=probe)
        job.fixed_candidates = None
        result = job.run()
        self.assertEqual(result["kind"], "applied")
        self.assertEqual(FakeAPI.records[DE], ["1.0.0.1"])  # works on both beats 1.0.0.9
        self.assertEqual(result["unverified"], [])
        scanned = [ip for ip in seen if ip != "1.0.0.2"]  # after re-checking the record
        self.assertEqual(scanned[0], "1.0.0.1")  # the MCI address was tried first

    def test_a_healthy_record_is_left_alone(self):
        store = make_store(self.tmp)
        FakeAPI.records[DE] = ["1.0.0.2"]
        result = self.job(store, "mtn", {"1.0.0.2": (True, 90.0, "")}, candidates=[]).run()
        self.assertEqual((result["kind"], result["scanned"]), ("healthy", 0))
        self.assertEqual(result["unverified"], ["mci"])

    def test_one_dead_address_of_two_triggers_a_scan(self):
        store = make_store(self.tmp, ips_per_record=2)
        FakeAPI.records[DE] = ["1.0.0.1", "1.0.0.2"]
        result = self.job(store, "mtn", {"1.0.0.1": (True, 90.0, ""), "1.0.0.2": (False, None, "")}).run()
        self.assertEqual(result["kind"], "applied")
        self.assertEqual(FakeAPI.records[DE], ["1.0.0.1"])

    def test_an_address_known_bad_on_irancell_is_not_used_on_mci(self):
        store = make_store(self.tmp)
        store.record_result("s1", "1.0.0.5", "mtn", False)
        job = self.job(store, "mci", {"1.0.0.5": (True, 50.0, "")})
        result = job.run()
        self.assertEqual((result["kind"], result["conflict"]), ("conflict", ["1.0.0.5"]))
        self.assertNotIn(DE, FakeAPI.records)
        self.assertTrue(job.apply(result, result["conflict"], "forced"))
        self.assertEqual(FakeAPI.records[DE], ["1.0.0.5"])
        self.assertEqual(store.history()[0]["kind"], "forced")

    def test_home_scans_only_touch_the_home_record(self):
        store = make_store(self.tmp, record_home="cdn2.germany.example.test")
        FakeAPI.records[DE] = ["1.0.0.1"]
        result = self.job(store, "home", {"1.0.0.1": (False, None, ""),
                                          "1.0.0.7": (True, 60.0, "")}).run()
        self.assertEqual(result["kind"], "applied")
        self.assertEqual(FakeAPI.records[DE_HOME], ["1.0.0.7"])
        self.assertEqual(FakeAPI.records[DE], ["1.0.0.1"])

    def test_mobile_scans_never_touch_the_home_record(self):
        store = make_store(self.tmp, record_home="cdn2.germany.example.test")
        FakeAPI.records[DE_HOME] = ["1.0.0.7"]
        self.job(store, "mci", {"1.0.0.2": (True, 100.0, ""), "1.0.0.7": (False, None, "")}).run()
        self.assertEqual(FakeAPI.records[DE_HOME], ["1.0.0.7"])
        self.assertEqual(FakeAPI.records[DE], ["1.0.0.2"])

    def test_without_a_home_record_a_home_scan_only_measures(self):
        store = make_store(self.tmp)
        job = self.job(store, "home", {"1.0.0.7": (True, 60.0, "")})
        result = job.run()
        self.assertEqual((result["kind"], result["ips"]), ("found", ["1.0.0.7"]))
        self.assertEqual(FakeAPI.records, {})
        self.assertTrue(any("خانگی" in n for n in job.events.notes))

    def test_each_server_measures_through_itself(self):
        store = make_store(self.tmp)
        tr = add_turkey(store)
        store.set_uuid(tr, VLESS_UUID)
        seen = []

        def probe(ip, target, ctx, timeout):
            seen.append((target.sni, target.kind))
            return scripted_probe({"1.0.0.2": (True, 100.0, "")})(ip, target, ctx, timeout)

        result = self.job(store, "mci", {"1.0.0.2": (True, 100.0, "")}, sid=tr, probe=probe).run()
        self.assertEqual(result["kind"], "applied")
        self.assertEqual(set(seen), {("turkey.example.test", "vless")})
        self.assertEqual(FakeAPI.records[TR], ["1.0.0.2"])
        self.assertNotIn(DE, FakeAPI.records)
        self.assertIn("1.0.0.2", store.cells(tr))
        self.assertNotIn("1.0.0.2", store.cells("s1"))

    def test_a_second_server_starts_from_what_the_first_found_here(self):
        store = make_store(self.tmp)
        tr = add_turkey(store)
        self.job(store, "mci", {"1.0.0.2": (True, 100.0, "")}).run()
        job = self.job(store, "mci", {}, sid=tr)
        self.assertEqual(job._seeds(["mci", "mtn"], DAY, []), ["1.0.0.2"])

    def test_an_address_blocked_on_irancell_is_not_given_to_another_server(self):
        store = make_store(self.tmp)
        tr = add_turkey(store)
        store.remember_bad("mtn", ["1.0.0.5"])            # timed out on Irancell (DE's scan)
        store.record_result("s1", "1.0.0.1", "mtn", True, 200)  # works there for DE
        table = {"1.0.0.5": (True, 50.0, ""), "1.0.0.1": (True, 300.0, "")}
        result = self.job(store, "mci", table, sid=tr).run()
        self.assertEqual(FakeAPI.records[TR], ["1.0.0.1"])
        self.assertEqual(result["unverified"], [])

    def test_a_network_never_tested_is_not_waited_for(self):
        store = make_store(self.tmp, record_home="cdn2.germany.example.test")
        nid = store.save_network(None, "مخابرات", "home", asn=58224)
        result = self.job(store, nid, {"1.0.0.7": (True, 60.0, "")}).run()
        self.assertEqual(result["kind"], "applied")
        self.assertEqual(result["unverified"], [])  # the default "home" was never measured
        self.assertEqual(app.relevant_networks(store, "home"), [nid])

    def test_manual_approval(self):
        store = make_store(self.tmp, auto_apply=False)
        job = self.job(store, "mci", {"1.0.0.2": (True, 100.0, "")})
        result = job.run()
        self.assertEqual(result["kind"], "pending")
        self.assertNotIn(DE, FakeAPI.records)
        self.assertTrue(job.apply(result))
        self.assertEqual(FakeAPI.records[DE], ["1.0.0.2"])

    def test_a_blocked_api_is_reached_through_a_clean_address(self):
        store = make_store(self.tmp)
        FakeAPI.unreachable_direct = True
        result = self.job(store, "mci", {"1.0.0.2": (True, 100.0, "")}).run()
        self.assertEqual(result["kind"], "applied")
        self.assertIn("1.0.0.2", FakeAPI.calls)

    def test_healthy_but_slow_looks_for_a_faster_address(self):
        store = make_store(self.tmp)
        FakeAPI.records[DE] = ["1.0.0.9"]
        table = {"1.0.0.9": (True, 900.0, ""), "1.0.0.2": (True, 300.0, "")}
        job = self.job(store, "mtn", table, candidates=["1.0.0.2"])
        result = job.run()
        self.assertIn((0, "slow"), job.events.steps)
        self.assertEqual((result["kind"], result["ips"]), ("applied", ["1.0.0.2"]))
        self.assertEqual(FakeAPI.records[DE], ["1.0.0.2"])
        self.assertIn("1.0.0.2 (300ms)", app.result_line(result, store))

    def test_slow_but_nothing_clearly_faster_keeps_the_address(self):
        store = make_store(self.tmp)
        FakeAPI.records[DE] = ["1.0.0.9"]
        table = {"1.0.0.9": (True, 900.0, ""), "1.0.0.2": (True, 800.0, "")}
        result = self.job(store, "mtn", table, candidates=["1.0.0.2"]).run()
        self.assertEqual((result["kind"], result["ips"], result["slow"]),
                         ("unchanged", ["1.0.0.9"], 900.0))
        line = app.result_line(result, store)
        self.assertIn("IP سریع‌تری", line)
        self.assertIn("1.0.0.9 (900ms)", line)
        self.assertEqual(FakeAPI.records[DE], ["1.0.0.9"])

    def test_a_fast_enough_record_is_not_scanned(self):
        for good_ms, kind in ((1000, "healthy"), (0, "healthy"), (500, "unchanged")):
            store = make_store(tempfile.mkdtemp(dir=self.tmp), good_ping_ms=good_ms)
            FakeAPI.records[DE] = ["1.0.0.9"]
            job = self.job(store, "mtn", {"1.0.0.9": (True, 900.0, "")}, candidates=[])
            self.assertEqual(job.run()["kind"], kind, good_ms)

    def test_every_long_step_reports_its_progress(self):
        store = make_store(self.tmp, stop_after=2)
        FakeAPI.records[DE] = ["1.0.0.9"]
        table = {"1.0.0.%d" % i: (True, 100.0 + i, "") for i in range(1, 30)}
        table["1.0.0.9"] = (False, None, "")
        job = self.job(store, "mci", table, candidates=[ip for ip in table if ip != "1.0.0.9"])
        job.store.update_settings({"workers": 1})
        result = job.run()
        self.assertEqual(result["kind"], "applied")
        progress = job.events.progress_by_step
        self.assertEqual(progress[0][-1], (1, 1, 0))       # the record's address, failed
        self.assertEqual(progress[1][-1][2], 2)            # enough answers
        done, total, good = progress[2][-1]
        self.assertEqual((done, total), (total, total))
        self.assertIn("کافی بود", job.events.details[1])
        self.assertIn("ms)", job.events.details[2])
        self.assertIn("✕", job.events.details[0])

    def test_cloudflare_down_keeps_the_choice_for_a_retry(self):
        store = make_store(self.tmp)
        store.set_record_ips("s1:mobile", ["1.0.0.9"])
        FakeAPI.down = True
        job = self.job(store, "mci", {"1.0.0.2": (True, 100.0, "")})
        result = job.run()
        self.assertEqual(result["kind"], "apply_failed")
        self.assertIn("connection reset", result["message"])
        self.assertTrue(any("خواندن رکورد" in n for n in job.events.notes))
        self.assertEqual(store.record_ips("s1:mobile"), ["1.0.0.9"])  # unchanged
        self.assertEqual(store.history(), [])
        FakeAPI.down = False
        self.assertTrue(job.apply(result))
        self.assertEqual(FakeAPI.records[DE], ["1.0.0.2"])
        self.assertEqual(store.record_ips("s1:mobile"), ["1.0.0.2"])
        self.assertEqual(store.history()[0]["old"], ["1.0.0.9"])

    def test_ipv6_scans_write_an_aaaa_record(self):
        store = make_store(self.tmp, ip_version=6)
        result = self.job(store, "mci", {"2606:4700::1": (True, 120.0, "FRA")}).run()
        self.assertEqual(result["kind"], "applied")
        self.assertEqual(FakeAPI.records[("cdn1.germany.example.test", "AAAA")],
                         ["2606:4700::1"])

    def test_nothing_answering_gives_a_hint_and_marks_nothing_bad(self):
        store = make_store(self.tmp)
        result = self.job(store, "mci", {}, candidates=["1.0.0.4"]).run()
        self.assertEqual(result["kind"], "nothing")
        self.assertIn("timeout", result["hint"])
        self.assertNotIn("1.0.0.4", store.bad_for("mci"))

    def test_a_foreign_location_warns_about_the_vpn(self):
        store = make_store(self.tmp)
        job = self.job(store, "mci", {"1.0.0.2": (True, 100.0, "")}, loc="DE")
        self.assertIn("VPN", job.run()["warning"])

    def test_without_a_token_the_scan_still_finds_addresses(self):
        store = make_store(self.tmp, token="")
        result = self.job(store, "mci", {"1.0.0.2": (True, 100.0, "")}).run()
        self.assertEqual((result["kind"], result["ips"]), ("found", ["1.0.0.2"]))

    def test_stop_applies_nothing(self):
        store = make_store(self.tmp)
        job = self.job(store, "mci", {"1.0.0.2": (True, 100.0, "")})
        job.cancel()
        self.assertEqual(job.run()["kind"], "stopped")
        self.assertEqual(FakeAPI.records, {})


class DetectTests(unittest.TestCase):
    def fetch(self, answers):
        def fake(url, timeout):
            answer = answers[url]
            if isinstance(answer, Exception):
                raise answer
            return answer
        return fake

    def test_meta_gives_the_asn(self):
        original = app._fetch
        try:
            app._fetch = self.fetch({app.META_URL: b'{"asn": 44244, "asOrganization": "Irancell", '
                                                  b'"country": "IR", "clientIp": "5.6.7.8", '
                                                  b'"colo": {"iata": "GYD"}}'})
            info = app.detect_connection()
            self.assertEqual((info["asn"], info["country"], info["colo"]), (44244, "IR", "GYD"))
            app._fetch = self.fetch({app.META_URL: b'{"asn": "AS197207", "country": "IR"}'})
            self.assertEqual(app.detect_connection()["asn"], 197207)
            self.assertEqual((app.parse_asn(44244), app.parse_asn("AS44244"), app.parse_asn(None)),
                             (44244, 44244, None))
            app._fetch = self.fetch({app.META_URL: socket.timeout(),
                                     app.TRACE_URL: b"ip=5.6.7.8\nloc=DE\ncolo=FRA\n"})
            info = app.detect_connection()
            self.assertEqual((info["ok"], info["asn"], info["country"]), (True, None, "DE"))
            app._fetch = self.fetch({app.META_URL: socket.timeout(), app.TRACE_URL: socket.timeout()})
            self.assertEqual(app.detect_connection()["error"], "timeout")
        finally:
            app._fetch = original


if __name__ == "__main__":
    unittest.main()

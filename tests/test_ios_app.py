"""The iPhone app's engine (ios/cfscan_ios.py) without Pythonista.

The probes run against a real TLS server on 127.0.0.1 with a throwaway
certificate; the scan tests replace the probes and the Cloudflare API with
scripted fakes. Nothing here contacts a public network.
"""

from __future__ import annotations

import importlib.util
import os
import random
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
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

    def get(self, sid=None):
        return self.token

    def set(self, token, sid=None):
        self.token = token


def make_store(tmp, token=TEST_TOKEN, sni="germany.example.test", path="/ws",
               record="cdn1.germany.example.test", record2="", **settings):
    """One CDN server ``s1`` with its address record; networks mci, mtn, home."""
    store = app.Store(os.path.join(tmp, "data.json"), secrets=MemorySecrets(token))
    base = {"auto_apply": True, "verify_attempts": 3, "verify_top": 4, "stop_after": 0,
            "timeout": 0.5, "ips_per_record": 1}
    base.update(settings)
    store.update_settings(base)
    store.save_server(None, {"name": "DE", "sni": sni, "path": path, "record": record,
                             "record2": record2})
    return store


# ------------------------------------------------------------------ storage

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_defaults_fill_a_missing_file(self):
        store = app.Store(os.path.join(self.tmp, "none.json"), secrets=MemorySecrets())
        self.assertEqual(store.servers, [])
        self.assertEqual([n["id"] for n in store.networks], ["mci", "mtn", "home"])
        self.assertEqual(store.current_network["id"], "mci")
        self.assertEqual(store.slots(), [])

    def test_each_server_has_its_own_record(self):
        store = make_store(self.tmp, record2="cdn2.germany.example.test")
        sid = store.save_server(None, {"name": "TR", "sni": "turkey.example.test",
                                       "record": "cdn1.turkey.example.test"})
        self.assertEqual([(k, name) for k, _, name, _ in store.slots()],
                         [("s1", "cdn1.germany.example.test"), ("s1:2", "cdn2.germany.example.test"),
                          (sid, "cdn1.turkey.example.test")])
        self.assertEqual(store.slot_label("s1:2"), "DE (دوم)")
        self.assertEqual(app.record_name(store, sid), "cdn1.turkey.example.test")
        self.assertEqual(app.suggest_record("germany.example.com"), "cdn1.germany.example.com")
        self.assertEqual(app.suggest_record("example.com", "cdn2"), "cdn2.example.com")
        self.assertEqual(app.suggest_record("localhost"), "")
        store.set_record_ips(sid, ["1.1.1.1"])
        store.delete_server(sid)
        self.assertNotIn(sid, store.data["records"])

    def test_settings_round_trip_and_bad_values_change_nothing(self):
        store = make_store(self.tmp, workers="16", record2="https://CDN2.germany.example.test/")
        again = app.Store(store.path, secrets=MemorySecrets())
        self.assertEqual(again.settings["workers"], 16)
        self.assertEqual(again.server("s1")["record2"], "cdn2.germany.example.test")
        with self.assertRaises(ValueError):
            again.update_settings({"workers": "8", "ttl": "5"})
        self.assertEqual(again.settings["workers"], 16)
        with self.assertRaises(ValueError):
            again.save_server("s1", {"port": "70000"})

    def test_networks_are_added_renamed_and_removed_with_their_results(self):
        store = make_store(self.tmp)
        nid = store.save_network(None, "رایتل")
        store.record_result("1.1.1.1", nid, True, 50)
        store.set_network(nid)
        store.save_network(nid, "Rightel")
        self.assertEqual(store.current_network["name"], "Rightel")
        store.delete_network(nid)
        self.assertNotIn(nid, store.matrix["1.1.1.1"])
        self.assertEqual(store.current_network["id"], "mci")
        for n in list(store.networks)[1:]:
            store.delete_network(n["id"])
        with self.assertRaises(ValueError):
            store.delete_network("mci")

    def test_results_are_kept_per_address_and_network(self):
        store = make_store(self.tmp)
        store.remember_bad("mci", ["1.1.1.1"])
        store.record_result("1.1.1.1", "mci", True, 50, "FRA", ts=10)
        store.record_result("1.1.1.1", "mtn", False, ts=11)
        self.assertEqual(store.matrix["1.1.1.1"]["mci"],
                         {"ok": True, "ping": 50, "colo": "FRA", "ts": 10})
        self.assertFalse(store.matrix["1.1.1.1"]["mtn"]["ok"])
        self.assertNotIn("1.1.1.1", store.bad_for("mci"))

    def test_the_token_is_never_written_to_the_data_file(self):
        store = make_store(self.tmp, token="secret-token-123")
        store.save()
        self.assertNotIn("secret-token-123", Path(store.path).read_text(encoding="utf-8"))
        self.assertNotIn("secret-token-123", store.export_json())

    def test_export_import_keeps_servers_networks_and_settings(self):
        store = make_store(self.tmp, workers="20")
        store.save_network(None, "شاتل")
        other = app.Store(os.path.join(self.tmp, "other.json"), secrets=MemorySecrets())
        other.import_json(store.export_json())
        self.assertEqual(other.servers[0]["sni"], "germany.example.test")
        self.assertEqual(other.servers[0]["record"], "cdn1.germany.example.test")
        self.assertEqual(other.settings["workers"], 20)
        self.assertEqual(other.networks[-1]["name"], "شاتل")
        with self.assertRaises(ValueError):
            other.import_json('{"hello": 1}')

    def test_version_one_data_is_migrated(self):
        v1 = {"version": 1,
              "settings": {"sni": "cdn.example.com", "path": "ws", "ttl": 120},
              "profiles": [{"id": "mci", "name": "MCI", "record": "mci.cdn.example.com"}],
              "state": {"mci": {"good": {"1.1.1.1": {"ts": 5, "ping": 40, "colo": "FRA"}},
                                "bad": {"9.9.9.9": 6}}}}
        data = app.normalise_data(v1)
        self.assertEqual(data["version"], 3)
        self.assertEqual((data["servers"][0]["sni"], data["servers"][0]["path"]),
                         ("cdn.example.com", "/ws"))
        self.assertEqual(data["networks"], [{"id": "mci", "name": "MCI"}])
        self.assertEqual(data["matrix"]["1.1.1.1"]["mci"],
                         {"ok": True, "ping": 40, "colo": "FRA", "ts": 5})
        self.assertEqual(data["bad"]["mci"], {"9.9.9.9": 6})
        self.assertEqual(data["settings"]["ttl"], 120)
        self.assertEqual(data["servers"][0]["record"], "")

    def test_version_three_single_record_moves_to_the_first_server(self):
        v3 = {"version": 3, "settings": {"ip1": "cdn1.germany.example.com", "ip2": ""},
              "servers": [{"id": "s1", "name": "DE", "sni": "germany.example.com"},
                          {"id": "s2", "name": "TR", "sni": "turkey.example.com"}],
              "records": {"ip1": {"ips": ["1.1.1.1"], "ts": 5}},
              "history": [{"ts": 1, "record": "ip1", "old": [], "new": ["1.1.1.1"]}]}
        data = app.normalise_data(v3)
        self.assertEqual(data["servers"][0]["record"], "cdn1.germany.example.com")
        self.assertEqual(data["servers"][1]["record"], "")
        self.assertEqual(data["records"]["s1"]["ips"], ["1.1.1.1"])
        self.assertEqual(data["history"][0]["record"], "s1")
        self.assertNotIn("ip1", data["settings"])

    def test_version_two_data_is_migrated(self):
        v2 = {"version": 2, "settings": {"workers": 20},
              "servers": [{"id": "s1", "name": "DE", "sni": "de.example.com", "path": "/a",
                           "zone_id": "z1", "records": {"mci": "mci.de.example.com"}},
                          {"id": "s2", "name": "TR", "sni": "tr.example.com"}],
              "carriers": [{"id": "mci", "name": "همراه اول", "prefix": "mci"},
                           {"id": "rtl", "name": "رایتل", "prefix": "rtl"}],
              "memory": {"rtl": {"good": {"2.2.2.2": {"ts": 7, "ping": 60}}}}}
        data = app.normalise_data(v2)
        self.assertEqual([s["sni"] for s in data["servers"]], ["de.example.com", "tr.example.com"])
        self.assertNotIn("records", data["servers"][0])
        self.assertEqual([n["id"] for n in data["networks"]], ["mci", "rtl"])
        self.assertTrue(data["matrix"]["2.2.2.2"]["rtl"]["ok"])
        self.assertEqual(data["settings"]["zone_id"], "z1")
        self.assertEqual(data["settings"]["workers"], 20)

    def test_previous_ips_come_from_the_record_history(self):
        store = make_store(self.tmp)
        store.add_history("s1", ["1.1.1.1"], ["2.2.2.2"], "mci")
        store.add_history("s1:2", ["7.7.7.7"], ["8.8.8.8"], "home")
        self.assertEqual(store.previous_ips("s1"), ["1.1.1.1"])
        self.assertEqual(store.previous_ips("s1:2"), ["7.7.7.7"])


# ------------------------------------------------------------------ coverage

NOW = 1000000.0
DAY = 86400.0


def cell(ok, ping=None, age=0):
    return {"ok": ok, "ping": ping, "colo": "", "ts": NOW - age}


class CoverageTests(unittest.TestCase):
    NETS = ["mci", "mtn", "home"]

    def test_an_address_working_everywhere_wins_by_its_worst_ping(self):
        matrix = {"A": {"mci": cell(True, 40), "mtn": cell(True, 200), "home": cell(True, 50)},
                  "B": {"mci": cell(True, 90), "mtn": cell(True, 100), "home": cell(True, 95)},
                  "C": {"mci": cell(True, 10), "mtn": cell(False)}}
        choice = app.choose_addresses(matrix, self.NETS, NOW, DAY, 2)
        self.assertEqual(choice["main"], ["B", "A"])
        self.assertEqual(choice["uncovered"], [])
        self.assertEqual(choice["second"], [])

    def test_a_network_no_common_address_reaches_goes_to_the_second_record(self):
        matrix = {"A": {"mci": cell(True, 40), "mtn": cell(True, 60), "home": cell(False)},
                  "H": {"mci": cell(False), "mtn": cell(False), "home": cell(True, 30)}}
        for scanned_on in ("mci", "home"):
            choice = app.choose_addresses(matrix, self.NETS, NOW, DAY, 2, must_work_on=scanned_on)
            self.assertEqual(choice["main"], ["A"])
            self.assertEqual(choice["covered"], ["mci", "mtn"])
            self.assertEqual(choice["uncovered"], ["home"])
            self.assertEqual(choice["second"], ["H"])

    def test_old_results_do_not_count(self):
        matrix = {"A": {"mci": cell(True, 40), "mtn": cell(False, age=3 * DAY)}}
        active = app.active_networks(matrix, self.NETS, NOW, DAY)
        self.assertEqual(active, ["mci"])
        self.assertEqual(app.choose_addresses(matrix, active, NOW, DAY, 1)["main"], ["A"])
        self.assertEqual(app.cell_text(matrix["A"]["mtn"], NOW, DAY), "؟")
        self.assertEqual(app.cell_text(matrix["A"]["mci"], NOW, DAY), "40")

    def test_equal_coverage_prefers_the_network_just_scanned(self):
        matrix = {"M": {"mci": cell(True, 10)}, "T": {"mtn": cell(True, 90)}}
        choice = app.choose_addresses(matrix, ["mci", "mtn"], NOW, DAY, 1, must_work_on="mtn")
        self.assertEqual(choice["main"], ["T"])
        self.assertEqual(choice["second"], ["M"])

    def test_seeds_are_addresses_working_elsewhere_not_yet_tried_here(self):
        matrix = {"A": {"mci": cell(True, 40)},
                  "B": {"mci": cell(True, 30), "mtn": cell(False)},
                  "C": {"mci": cell(False)}}
        self.assertEqual(app.seeds_for(matrix, "mtn", self.NETS, NOW, DAY), ["A"])

    def test_without_a_second_record_the_gaps_join_the_first(self):
        matrix = {"A": {"mci": cell(True, 40), "mtn": cell(True, 60), "home": cell(False)},
                  "B": {"mci": cell(True, 50), "mtn": cell(True, 70)},
                  "H": {"home": cell(True, 30)}}
        choice = app.choose_addresses(matrix, self.NETS, NOW, DAY, 2, merge_gaps=True)
        self.assertEqual(choice["main"], ["A", "H"])
        self.assertTrue(choice["merged"])
        self.assertEqual(choice["covered"], self.NETS)
        self.assertEqual(choice["second"], [])

    def test_nothing_measured_chooses_nothing(self):
        self.assertEqual(app.choose_addresses({}, self.NETS, NOW, DAY, 2)["main"], [])


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
        self.assertAlmostEqual(m["jitter"], 15.0)
        self.assertEqual(m["colo"], "FRA")
        self.assertFalse(app.is_healthy(m, 0, 800))
        self.assertTrue(app.is_healthy(m, 30, 800))
        self.assertLess(app.score({"total": 100, "jitter": 1, "loss": 0}),
                        app.score({"total": 90, "jitter": 1, "loss": 10}))

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

class _TLSServer:
    """Answers /cdn-cgi/trace with 200 and the WebSocket path with 101."""

    def __init__(self, certfile, keyfile, ws_path="/ws"):
        self.ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ctx.load_cert_chain(certfile, keyfile)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.ws_path = ws_path
        self.hosts = []
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
            else:
                tls.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            tls.close()
        except (OSError, ssl.SSLError):
            pass

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


# ------------------------------------------------------------------ the scan

class FakeAPI:
    """A Cloudflare stand-in keeping DNS records in a shared dict."""

    records = {}
    unreachable_direct = False
    calls = []

    def __init__(self, token="", via_ip=None, **kw):
        self.token = token
        self.via_ip = via_ip

    def _check(self):
        FakeAPI.calls.append(self.via_ip)
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
        self.notes = []
        self.result = None

    def step(self, index, status, detail=""):
        self.steps.append((index, status))

    def note(self, text):
        self.notes.append(text)

    def finished(self, result):
        self.result = result


IP1 = ("cdn1.germany.example.test", "A")
IP2 = ("cdn2.germany.example.test", "A")
TR1 = ("cdn1.turkey.example.test", "A")


class ScanJobTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        FakeAPI.records = {}
        FakeAPI.unreachable_direct = False
        FakeAPI.calls = []

    def job(self, store, nid, table, mode="auto", loc="IR", candidates=None, probe=None):
        probe = probe or scripted_probe(table, loc)
        return app.ScanJob(store, nid, events=RecordingEvents(), mode=mode,
                           context_factory=lambda: None, api_factory=FakeAPI,
                           candidates=list(table) if candidates is None else candidates,
                           probe_trace=probe, probe_ws=probe)

    def test_the_first_scan_fills_the_record_and_the_coverage_table(self):
        store = make_store(self.tmp)
        table = {"1.0.0.1": (True, 400.0, "GYD"), "1.0.0.2": (True, 150.0, "FRA"),
                 "1.0.0.3": (False, None, "")}
        job = self.job(store, "mci", table)
        result = job.run()
        self.assertEqual(result["kind"], "applied")
        self.assertEqual(FakeAPI.records[IP1], ["1.0.0.2"])
        self.assertEqual(store.record_ips("s1"), ["1.0.0.2"])
        self.assertTrue(store.matrix["1.0.0.2"]["mci"]["ok"])
        self.assertIn("1.0.0.3", store.bad_for("mci"))
        self.assertEqual(store.history()[0]["record"], "s1")
        self.assertEqual(store.history()[0]["network"], "mci")
        self.assertEqual(job.events.steps[0], (0, "run"))
        self.assertEqual(job.events.steps[-1], (3, "ok"))
        self.assertIn("1.0.0.2", app.result_line(result))

    def test_a_record_working_here_is_left_alone(self):
        store = make_store(self.tmp)
        FakeAPI.records[IP1] = ["1.0.0.2"]
        result = self.job(store, "mtn", {"1.0.0.2": (True, 90.0, "FRA")}, candidates=[]).run()
        self.assertEqual(result["kind"], "healthy")
        self.assertEqual(result["scanned"], 0)
        self.assertTrue(store.matrix["1.0.0.2"]["mtn"]["ok"])

    def test_a_second_network_keeps_the_address_that_works_on_both(self):
        store = make_store(self.tmp)
        self.job(store, "mci", {"1.0.0.1": (True, 300.0, "GYD"),
                                "1.0.0.2": (True, 150.0, "FRA")}).run()
        self.assertEqual(FakeAPI.records[IP1], ["1.0.0.2"])
        # on Irancell the MCI winner fails, the slower MCI address works
        mtn = {"1.0.0.1": (True, 200.0, "FRA"), "1.0.0.2": (False, None, ""),
               "1.0.0.9": (True, 90.0, "FRA")}
        seen = []

        def probe(ip, target, ctx, timeout):
            seen.append(ip)
            return scripted_probe(mtn)(ip, target, ctx, timeout)

        store.update_settings({"candidates": 20, "stop_after": 3})
        job = app.ScanJob(store, "mtn", events=RecordingEvents(), context_factory=lambda: None,
                          api_factory=FakeAPI, rng=random.Random(4),
                          probe_trace=probe, probe_ws=probe)
        job.fixed_candidates = None
        result = job.run()
        self.assertEqual(result["kind"], "applied")
        self.assertEqual(FakeAPI.records[IP1], ["1.0.0.1"])
        self.assertEqual(result["servers"]["s1"]["covered"], ["mci", "mtn"])
        scanned = [ip for ip in seen if ip != "1.0.0.2"]
        self.assertEqual(scanned[0], "1.0.0.1")  # the address from MCI came first
        self.assertFalse(store.matrix["1.0.0.2"]["mtn"]["ok"])

    def test_home_without_a_common_address_fills_the_second_record(self):
        store = make_store(self.tmp, record2="cdn2.germany.example.test")
        store.record_result("1.0.0.1", "mci", True, 80)
        store.record_result("1.0.0.1", "mtn", True, 90)
        store.set_record_ips("s1", ["1.0.0.1"])
        FakeAPI.records[IP1] = ["1.0.0.1"]
        home = {"1.0.0.1": (False, None, ""), "1.0.0.7": (True, 60.0, "FRA")}
        result = self.job(store, "home", home).run()
        self.assertEqual(result["kind"], "applied")
        self.assertEqual(FakeAPI.records[IP1], ["1.0.0.1"])
        self.assertEqual(FakeAPI.records[IP2], ["1.0.0.7"])
        self.assertEqual(result["servers"]["s1"]["uncovered"], ["home"])

    def test_the_next_home_scan_sees_the_second_record_as_healthy(self):
        store = make_store(self.tmp, record2="cdn2.germany.example.test")
        FakeAPI.records[IP1] = ["1.0.0.1"]
        FakeAPI.records[IP2] = ["1.0.0.7"]
        home = {"1.0.0.1": (False, None, ""), "1.0.0.7": (True, 60.0, "FRA")}
        self.assertEqual(self.job(store, "home", home, candidates=[]).run()["kind"], "healthy")

    def test_without_a_second_record_each_network_gets_its_own_address(self):
        store = make_store(self.tmp)
        store.record_result("1.0.0.1", "mci", True, 80)
        store.set_record_ips("s1", ["1.0.0.1"])
        FakeAPI.records[IP1] = ["1.0.0.1"]
        job = self.job(store, "home", {"1.0.0.1": (False, None, ""), "1.0.0.7": (True, 60.0, "")})
        result = job.run()
        self.assertEqual(result["kind"], "applied")
        self.assertEqual(sorted(FakeAPI.records[IP1]), ["1.0.0.1", "1.0.0.7"])
        self.assertEqual(result["servers"]["s1"]["covered"], ["mci", "home"])
        self.assertTrue(any("رکورد دوم" in n for n in job.events.notes))

    def test_one_dead_address_in_a_record_triggers_a_scan(self):
        store = make_store(self.tmp, ips_per_record=2)
        FakeAPI.records[IP1] = ["1.0.0.1", "1.0.0.2"]
        mtn = {"1.0.0.1": (True, 90.0, ""), "1.0.0.2": (False, None, "")}
        result = self.job(store, "mtn", mtn).run()
        self.assertNotEqual(result["kind"], "healthy")
        self.assertEqual(FakeAPI.records[IP1], ["1.0.0.1"])

    def test_a_merged_record_is_healthy_when_this_networks_address_works(self):
        store = make_store(self.tmp)
        store.record_result("1.0.0.1", "mci", True, 80)
        store.set_record_ips("s1", ["1.0.0.1"])
        FakeAPI.records[IP1] = ["1.0.0.1"]
        home = {"1.0.0.1": (False, None, ""), "1.0.0.7": (True, 60.0, "")}
        self.assertIn("s1", self.job(store, "home", home).run()["merged_slots"])
        self.assertTrue(store.record_merged("s1"))
        again = self.job(store, "home", home, candidates=[]).run()
        self.assertEqual(again["kind"], "healthy")

    def test_each_server_gets_the_best_address_it_accepts(self):
        store = make_store(self.tmp)
        tr = store.save_server(None, {"name": "TR", "sni": "turkey.example.test", "path": "/tr",
                                      "record": "cdn1.turkey.example.test"})
        table = {"1.0.0.1": (True, 300.0, ""), "1.0.0.2": (True, 100.0, "")}

        def probe(ip, target, ctx, timeout):
            if target.sni == "turkey.example.test" and ip == "1.0.0.2":
                return scripted_probe({})(ip, target, ctx, timeout)
            return scripted_probe(table)(ip, target, ctx, timeout)

        job = self.job(store, "mci", table, probe=probe)
        result = job.run()
        self.assertEqual(result["kind"], "applied")
        self.assertEqual(FakeAPI.records[IP1], ["1.0.0.2"])
        self.assertEqual(FakeAPI.records[TR1], ["1.0.0.1"])
        self.assertEqual(store.record_ips(tr), ["1.0.0.1"])
        self.assertTrue(any("1.0.0.2" in n and "TR" in n for n in job.events.notes))

    def test_one_server_not_served_here_triggers_a_scan(self):
        store = make_store(self.tmp)
        store.save_server(None, {"name": "TR", "sni": "turkey.example.test",
                                 "record": "cdn1.turkey.example.test"})
        FakeAPI.records[IP1] = ["1.0.0.1"]
        FakeAPI.records[TR1] = ["1.0.0.9"]
        table = {"1.0.0.1": (True, 100.0, ""), "1.0.0.9": (False, None, "")}
        result = self.job(store, "mci", table).run()
        self.assertEqual(result["kind"], "applied")
        self.assertEqual(FakeAPI.records[TR1], ["1.0.0.1"])
        self.assertEqual(result["changes"], {"s2": ["1.0.0.1"]})

    def test_a_server_without_a_record_is_measured_but_not_written(self):
        store = make_store(self.tmp, record="")
        result = self.job(store, "mci", {"1.0.0.2": (True, 100.0, "")}).run()
        self.assertEqual(result["kind"], "found")
        self.assertEqual(result["servers"]["s1"]["main"], ["1.0.0.2"])
        self.assertEqual(FakeAPI.records, {})

    def test_manual_approval(self):
        store = make_store(self.tmp, auto_apply=False, ips_per_record=2)
        job = self.job(store, "mci", {"1.0.0.1": (True, 300.0, ""), "1.0.0.2": (True, 100.0, "")})
        result = job.run()
        self.assertEqual(result["kind"], "pending")
        self.assertNotIn(IP1, FakeAPI.records)
        self.assertTrue(job.apply(result))
        self.assertEqual(FakeAPI.records[IP1], ["1.0.0.2", "1.0.0.1"])

    def test_a_blocked_api_is_reached_through_a_clean_address(self):
        store = make_store(self.tmp)
        FakeAPI.unreachable_direct = True
        result = self.job(store, "mci", {"1.0.0.2": (True, 100.0, "")}).run()
        self.assertEqual(result["kind"], "applied")
        self.assertIn("1.0.0.2", FakeAPI.calls)

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

    def test_no_server_is_a_clear_error(self):
        store = app.Store(os.path.join(self.tmp, "d.json"), secrets=MemorySecrets())
        result = self.job(store, "mci", {"1.0.0.2": (True, 100.0, "")}).run()
        self.assertEqual(result["kind"], "error")
        self.assertIn("CDN", result["message"])

    def test_without_a_token_the_scan_still_finds_addresses(self):
        store = make_store(self.tmp, token="")
        result = self.job(store, "mci", {"1.0.0.2": (True, 100.0, "")}).run()
        self.assertEqual((result["kind"], result["servers"]["s1"]["main"]), ("found", ["1.0.0.2"]))

    def test_cancel_stops_the_run(self):
        store = make_store(self.tmp)
        job = self.job(store, "mci", {"1.0.0.2": (True, 100.0, "")})
        job.cancel()
        self.assertEqual(job.run()["kind"], "stopped")

    def test_connection_check_reads_the_location(self):
        class Resp:
            def __init__(self, body):
                self.body = body

            def read(self, n=-1):
                return self.body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        original = app.urllib.request.urlopen
        try:
            app.urllib.request.urlopen = lambda req, timeout: Resp(b"ip=5.6.7.8\ncolo=GYD\nloc=IR\n")
            self.assertEqual(app.connection_check(), {"ok": True, "loc": "IR", "ip": "5.6.7.8",
                                                      "colo": "GYD", "error": ""})

            def fail(req, timeout):
                raise socket.timeout()

            app.urllib.request.urlopen = fail
            self.assertEqual(app.connection_check()["error"], "timeout")
        finally:
            app.urllib.request.urlopen = original


if __name__ == "__main__":
    unittest.main()

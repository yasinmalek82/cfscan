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
    """Tokens by server id; ``None`` is the main token."""

    def __init__(self, token=TEST_TOKEN):
        self.tokens = {None: token}

    def get(self, sid=None):
        return self.tokens.get(sid, "")

    def set(self, token, sid=None):
        self.tokens[sid] = token


def make_store(tmp, token=TEST_TOKEN, sni="cdn.example.test", path="/ws", **settings):
    """A store with one server ``s1`` whose MCI record is mci.example.test."""
    store = app.Store(os.path.join(tmp, "data.json"), secrets=MemorySecrets(token))
    base = {"auto_apply": True, "verify_attempts": 3, "verify_top": 3, "stop_after": 0,
            "timeout": 0.5}
    base.update(settings)
    store.update_settings(base)
    store.save_server(None, {"name": "DE", "sni": sni, "path": path},
                      {"mci": "mci.example.test"})
    return store


# ------------------------------------------------------------------ storage

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_defaults_fill_a_missing_file(self):
        store = app.Store(os.path.join(self.tmp, "none.json"), secrets=MemorySecrets())
        self.assertEqual(store.settings["ttl"], 60)
        self.assertEqual(store.servers, [])
        self.assertIsNone(store.active)
        self.assertEqual([c["id"] for c in store.carriers], ["mci", "mtn", "home"])

    def test_settings_round_trip_and_bad_values_change_nothing(self):
        store = make_store(self.tmp, workers="16", colos="fra, ams")
        again = app.Store(store.path, secrets=MemorySecrets())
        self.assertEqual(again.settings["workers"], 16)
        self.assertEqual(again.server("s1")["path"], "/ws")
        with self.assertRaises(ValueError):
            again.update_settings({"workers": "8", "ttl": "5"})
        self.assertEqual(again.settings["workers"], 16)
        with self.assertRaises(ValueError):
            again.save_server("s1", {"port": "70000"})
        self.assertEqual(again.server("s1")["port"], 443)

    def test_version_one_data_becomes_one_server(self):
        v1 = {"settings": {"sni": "CDN.Example.com", "path": "ws", "port": 2053, "ttl": 120,
                           "zone_id": "z"},
              "profiles": [{"id": "mci", "name": "MCI", "record": "mci.cdn.example.com"},
                           {"id": "mtn", "name": "MTN", "record": "mtn.cdn.example.com"}],
              "state": {"mci": {"current": ["1.1.1.1"], "status": "ok",
                                "good": {"1.1.1.1": {"ts": 5}}, "bad": {"9.9.9.9": 6}}},
              "history": [{"ts": 1, "profile": "mci", "kind": "apply", "old": [], "new": ["1.1.1.1"]}]}
        data = app.normalise_data(v1)
        self.assertEqual(data["version"], 2)
        server = data["servers"][0]
        self.assertEqual((server["id"], server["sni"], server["path"], server["port"],
                          server["zone_id"]), ("s1", "cdn.example.com", "/ws", 2053, "z"))
        self.assertEqual(server["records"], {"mci": "mci.cdn.example.com",
                                             "mtn": "mtn.cdn.example.com"})
        self.assertEqual(data["settings"]["ttl"], 120)
        self.assertEqual(data["state"]["s1|mci"]["current"], ["1.1.1.1"])
        self.assertIn("1.1.1.1", data["memory"]["mci"]["good"])
        self.assertEqual(data["history"][0]["server"], "s1")
        self.assertEqual(data["history"][0]["carrier"], "mci")
        self.assertEqual(data["active_server"], "s1")
        self.assertEqual([c["prefix"] for c in data["carriers"]], ["mci", "mtn"])

    def test_stored_garbage_is_ignored(self):
        data = app.normalise_data({"settings": {"ttl": 5, "workers": "x"},
                                   "servers": [{"id": "a", "port": "x", "sni": "A.B."},
                                               {"id": "a"}, "junk"],
                                   "carriers": [{"id": "c", "prefix": "R T!"}, {"id": "c"}]})
        self.assertEqual(data["settings"]["ttl"], 60)
        self.assertEqual(data["settings"]["workers"], 32)
        self.assertEqual([s["id"] for s in data["servers"]], ["a", "s3"])
        self.assertEqual((data["servers"][0]["port"], data["servers"][0]["sni"]), (443, "a.b"))
        self.assertEqual(data["carriers"], [{"id": "c", "name": "c", "prefix": "rt"}])

    def test_servers_are_added_suggested_switched_and_deleted(self):
        store = make_store(self.tmp)
        sid = store.save_server(None, {"name": "NL", "sni": "https://cdn2.example.org/"})
        self.assertEqual(sid, "s2")
        self.assertEqual(store.server(sid)["sni"], "cdn2.example.org")
        self.assertEqual(store.suggest_record(sid, "mtn"), "mtn.cdn2.example.org")
        self.assertEqual(store.active["id"], "s1")
        store.set_active(sid)
        self.assertEqual(store.active["id"], "s2")
        store.state(sid, "mci")["current"] = ["1.1.1.1"]
        store.secrets.set("per-server", sid)
        store.delete_server(sid)
        self.assertEqual(store.active["id"], "s1")
        self.assertNotIn("s2|mci", store.data["state"])
        self.assertEqual(store.secrets.get(sid), "")

    def test_changing_a_record_forgets_its_state(self):
        store = make_store(self.tmp)
        store.state("s1", "mci").update(current=["1.1.1.1"], status="ok")
        store.save_server("s1", {}, {"mci": "mci.example.test"})
        self.assertEqual(store.state("s1", "mci")["current"], ["1.1.1.1"])
        store.save_server("s1", {}, {"mci": "new.example.test"})
        self.assertEqual(store.state("s1", "mci")["current"], [])
        store.save_server("s1", {}, {"mci": ""})
        self.assertEqual(store.record("s1", "mci"), "")

    def test_carriers_can_be_added_and_removed_everywhere(self):
        store = make_store(self.tmp)
        cid = store.save_carrier(None, "رایتل", "RTL")
        self.assertEqual((cid, store.carrier(cid)["prefix"]), ("rtl", "rtl"))
        self.assertEqual(store.suggest_record("s1", cid), "rtl.cdn.example.test")
        store.save_server("s1", {}, {cid: "rtl.example.test"})
        store.remember_good(cid, "1.1.1.1", 50, "FRA")
        store.delete_carrier(cid)
        self.assertNotIn(cid, store.server("s1")["records"])
        self.assertNotIn(cid, store.data["memory"])

    def test_a_server_token_overrides_the_main_one(self):
        store = make_store(self.tmp)
        sid = store.save_server(None, {"sni": "cdn.other.test"})
        self.assertEqual(store.token_for(sid), TEST_TOKEN)
        store.secrets.set(" Bearer " + "Z" * 40 + " ", sid)
        self.assertEqual(store.token_for(sid), "Z" * 40)
        self.assertEqual(store.token_for("s1"), TEST_TOKEN)

    def test_the_token_is_never_written_to_the_data_file(self):
        store = make_store(self.tmp, token="secret-token-123")
        store.save()
        self.assertNotIn("secret-token-123", Path(store.path).read_text(encoding="utf-8"))
        self.assertNotIn("secret-token-123", store.export_json())

    def test_export_import_keeps_servers_carriers_and_settings(self):
        store = make_store(self.tmp, workers="20")
        store.save_server(None, {"sni": "cdn2.example.test"}, {"mtn": "mtn.cdn2.example.test"})
        other = app.Store(os.path.join(self.tmp, "other.json"), secrets=MemorySecrets())
        other.import_json(store.export_json())
        self.assertEqual([s["sni"] for s in other.servers], ["cdn.example.test", "cdn2.example.test"])
        self.assertEqual(other.record("s2", "mtn"), "mtn.cdn2.example.test")
        self.assertEqual(other.settings["workers"], 20)
        with self.assertRaises(ValueError):
            other.import_json('{"hello": 1}')

    def test_a_version_one_export_still_imports(self):
        other = app.Store(os.path.join(self.tmp, "other.json"), secrets=MemorySecrets())
        other.import_json('{"app": "cfscan_ios", "settings": {"sni": "cdn.x.test"}, '
                          '"profiles": [{"id": "mci", "name": "MCI", "record": "mci.x.test"}]}')
        self.assertEqual(other.record("s1", "mci"), "mci.x.test")

    def test_previous_ips_and_history_filters(self):
        store = make_store(self.tmp)
        store.add_history("s1", "mci", "apply", ["1.1.1.1"], ["2.2.2.2"])
        store.add_history("s1", "mci", "check", ["2.2.2.2"], ["2.2.2.2"])
        store.add_history("s2", "mci", "apply", ["7.7.7.7"], ["8.8.8.8"])
        self.assertEqual(store.previous_ips("s1", "mci"), ["1.1.1.1"])
        self.assertEqual(len(store.history("s1")), 2)
        self.assertEqual(len(store.history(cid="mci")), 3)

    def test_memory_is_shared_by_servers_of_a_carrier(self):
        store = make_store(self.tmp)
        store.remember_good("mci", "1.1.1.1", 50, "FRA")
        store.remember_bad("mci", ["1.1.1.1"], forget_good=True)
        self.assertNotIn("1.1.1.1", store.memory("mci")["good"])
        self.assertIn("1.1.1.1", store.memory("mci")["bad"])


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
        store = make_store(tmp)
        store.save_server("s1", {"zone_id": "0123456789abcdef0123456789abcdef"})
        api = self.api()
        ips = app.with_zone(store, api, store.server("s1"), "mtn.cdn.example.com",
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


class ScanJobTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        FakeAPI.records = {("mci.example.test", "A"): ["9.9.9.9"]}
        FakeAPI.unreachable_direct = False
        FakeAPI.calls = []
        self.table = {
            "9.9.9.9": (False, None, ""),       # the current, now blocked
            "1.0.0.1": (True, 400.0, "GYD"),
            "1.0.0.2": (True, 150.0, "FRA"),
            "1.0.0.3": (True, 250.0, "AMS"),
            "1.0.0.4": (False, None, ""),
        }

    def job(self, store, mode="auto", table=None, loc="IR"):
        probe = scripted_probe(self.table if table is None else table, loc)
        return app.ScanJob(store, "s1", "mci", events=RecordingEvents(), mode=mode,
                           context_factory=lambda: None, api_factory=FakeAPI,
                           candidates=["1.0.0.1", "1.0.0.2", "1.0.0.3", "1.0.0.4"],
                           probe_trace=probe, probe_ws=probe)

    def test_a_broken_record_is_replaced_by_the_best_verified_address(self):
        store = make_store(self.tmp)
        job = self.job(store)
        result = job.run()
        self.assertEqual(result["kind"], "applied")
        self.assertEqual(result["chosen"], ["1.0.0.2"])
        self.assertEqual(FakeAPI.records[("mci.example.test", "A")], ["1.0.0.2"])
        st = store.state("s1", "mci")
        self.assertEqual((st["status"], st["current"]), ("ok", ["1.0.0.2"]))
        mem = store.memory("mci")
        self.assertIn("1.0.0.2", mem["good"])
        self.assertIn("1.0.0.4", mem["bad"])
        self.assertIn("9.9.9.9", mem["bad"])
        self.assertEqual(store.previous_ips("s1", "mci"), ["9.9.9.9"])
        self.assertEqual(st["last_scan"]["scanned"], 4)
        self.assertIn("1.0.0.2", app.result_line(result))
        self.assertEqual(job.events.steps[-1], (3, "ok"))
        self.assertIs(job.events.result, result)

    def test_a_healthy_record_is_left_alone(self):
        store = make_store(self.tmp)
        FakeAPI.records[("mci.example.test", "A")] = ["1.0.0.3"]
        result = self.job(store).run()
        self.assertEqual(result["kind"], "healthy")
        self.assertEqual(FakeAPI.records[("mci.example.test", "A")], ["1.0.0.3"])
        self.assertEqual(result["scanned"], 0)

    def test_force_scans_even_when_healthy_and_can_find_the_same_address(self):
        store = make_store(self.tmp)
        FakeAPI.records[("mci.example.test", "A")] = ["1.0.0.2"]
        job = self.job(store, mode="force")
        job.fixed_candidates = ["1.0.0.2", "1.0.0.1"]
        result = job.run()
        self.assertEqual(result["kind"], "unchanged")

    def test_two_addresses_per_record_and_manual_approval(self):
        store = make_store(self.tmp, ips_per_record=2, auto_apply=False)
        job = self.job(store)
        result = job.run()
        self.assertEqual(result["kind"], "pending")
        self.assertEqual(result["chosen"], ["1.0.0.2", "1.0.0.3"])
        self.assertEqual(FakeAPI.records[("mci.example.test", "A")], ["9.9.9.9"])
        self.assertTrue(job.apply(result["chosen"], result))
        self.assertEqual(FakeAPI.records[("mci.example.test", "A")], ["1.0.0.2", "1.0.0.3"])

    def test_a_blocked_api_is_reached_through_a_clean_address(self):
        store = make_store(self.tmp)
        FakeAPI.unreachable_direct = True
        result = self.job(store).run()
        self.assertEqual(result["kind"], "applied")
        self.assertEqual(FakeAPI.records[("mci.example.test", "A")], ["1.0.0.2"])
        self.assertIn("1.0.0.2", FakeAPI.calls)

    def test_colour_filter_keeps_only_the_named_datacentres(self):
        store = make_store(self.tmp, colos="AMS")
        result = self.job(store).run()
        self.assertEqual(result["chosen"], ["1.0.0.3"])

    def test_nothing_answering_gives_a_hint_and_marks_nothing_bad(self):
        store = make_store(self.tmp)
        result = self.job(store, table={}).run()
        self.assertEqual(result["kind"], "nothing")
        self.assertIn("timeout", result["hint"])
        self.assertNotIn("1.0.0.4", store.memory("mci")["bad"])

    def test_a_foreign_location_warns_about_the_vpn(self):
        store = make_store(self.tmp)
        job = self.job(store, loc="DE")
        result = job.run()
        self.assertIn("VPN", result["warning"])
        self.assertTrue(job.events.notes)

    def test_missing_cdn_domain_is_a_clear_error(self):
        store = make_store(self.tmp)
        store.data["servers"][0]["sni"] = ""
        result = self.job(store).run()
        self.assertEqual(result["kind"], "error")
        self.assertIn("CDN", result["message"])

    def test_without_a_token_the_scan_still_finds_addresses(self):
        store = make_store(self.tmp, token="")
        result = self.job(store).run()
        self.assertEqual(result["kind"], "found")
        self.assertEqual(result["chosen"], ["1.0.0.2"])

    def test_each_server_is_probed_with_its_own_domain_and_token(self):
        store = make_store(self.tmp)
        sid = store.save_server(None, {"name": "NL", "sni": "cdn2.example.test", "path": "/x"},
                                {"mci": "mci.cdn2.example.test"})
        store.secrets.set("Q" * 40, sid)
        FakeAPI.records[("mci.cdn2.example.test", "A")] = ["9.9.9.9"]
        seen, tokens = [], []

        def probe(ip, target, ctx, timeout):
            seen.append((target.sni, target.path))
            return scripted_probe(self.table)(ip, target, ctx, timeout)

        class TokenAPI(FakeAPI):
            def __init__(self, token="", via_ip=None, **kw):
                tokens.append(token)
                super().__init__(token, via_ip)

        job = app.ScanJob(store, sid, "mci", events=RecordingEvents(),
                          context_factory=lambda: None, api_factory=TokenAPI,
                          candidates=["1.0.0.2"], probe_trace=probe, probe_ws=probe)
        self.assertEqual(job.run()["kind"], "applied")
        self.assertEqual(set(seen), {("cdn2.example.test", "/x")})
        self.assertEqual(set(tokens), {"Q" * 40})
        self.assertEqual(FakeAPI.records[("mci.cdn2.example.test", "A")], ["1.0.0.2"])
        self.assertEqual(FakeAPI.records[("mci.example.test", "A")], ["9.9.9.9"])

    def test_a_second_server_starts_from_what_the_first_found(self):
        store = make_store(self.tmp)
        self.job(store).run()
        sid = store.save_server(None, {"sni": "cdn2.example.test"}, {"mci": "mci.cdn2.example.test"})
        cands = app.build_candidates(store.memory("mci"), 10, 4, app.CF_RANGES_V4,
                                     rng=random.Random(1))
        self.assertIn(cands[0], ("1.0.0.2", "1.0.0.3", "1.0.0.1"))
        self.assertTrue(sid)

    def test_other_carriers_addresses_are_tried_early(self):
        store = make_store(self.tmp)
        store.state("s1", "mtn").update(current=["1.0.0.3"], status="ok")
        store.state("s1", "home").update(current=["5.5.5.5"], status="bad")
        store.remember_good("home", "1.0.0.9", 90, "FRA")
        store.remember_good("mci", "1.0.0.1", 90, "GYD")
        shared = store.shared_candidates("mci")
        self.assertEqual(list(shared), ["1.0.0.3", "1.0.0.9"])
        self.assertEqual(shared["1.0.0.3"], "ایرانسل")
        cands = app.build_candidates(store.memory("mci"), 30, 4, app.CF_RANGES_V4,
                                     rng=random.Random(2), shared=list(shared))
        self.assertEqual(cands[:3], ["1.0.0.1", "1.0.0.3", "1.0.0.9"])

    def test_a_scan_can_pick_the_address_another_carrier_found(self):
        store = make_store(self.tmp)
        store.state("s1", "mtn").update(current=["1.0.0.2"], status="ok")
        job = self.job(store)
        job.fixed_candidates = None
        job.store.update_settings({"candidates": 20, "stop_after": 2})
        result = job.run()
        self.assertEqual(result["chosen"], ["1.0.0.2"])
        self.assertEqual(result["shared_from"], "ایرانسل")

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

    def test_cancel_stops_the_run(self):
        store = make_store(self.tmp)
        job = self.job(store)
        job.cancel()
        self.assertEqual(job.run()["kind"], "stopped")


if __name__ == "__main__":
    unittest.main()

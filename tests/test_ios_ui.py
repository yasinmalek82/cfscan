"""The iPhone app's screens and flows, with Pythonista replaced by stand-ins.

``tests/fake_pythonista`` provides ``ui``, ``console``, ``dialogs``,
``clipboard`` and ``keychain`` with only what the app uses, so a wrong
attribute or a broken flow fails here instead of on the phone. Dialog and
alert answers are scripted; the network, the probes and Cloudflare are the
same fakes the engine tests use. Nothing contacts a public network.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
FAKES = ("ui", "console", "dialogs", "clipboard", "keychain")


def _load_app():
    """The app module imported against the stand-ins, without leaking them."""
    saved = {name: sys.modules.get(name) for name in FAKES}
    sys.path.insert(0, str(HERE / "fake_pythonista"))
    try:
        for name in FAKES:
            sys.modules.pop(name, None)
        fakes = {name: importlib.import_module(name) for name in FAKES}
        spec = importlib.util.spec_from_file_location("cfscan_ios_ui",
                                                      HERE.parent / "ios" / "cfscan_ios.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(HERE / "fake_pythonista"))
        for name, old in saved.items():
            if old is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old
    return module, fakes


app, fake = _load_app()
from tests import test_ios_app as engine  # noqa: E402  (the shared fakes)

LOG_DIR = tempfile.mkdtemp()
app.LOG_PATH = os.path.join(LOG_DIR, "log.txt")
TOKEN = "cfat_" + "A1b2C3d4" * 6
UUID = engine.VLESS_UUID
LINK = ("vless://%s@old.example.com:443?type=ws&security=tls&sni=germany.example.com"
        "&host=germany.example.com&path=%%2Fws#آلمان" % UUID)
MCI = {"ok": True, "asn": 197207, "org": "MCCI", "country": "IR", "ip": "5.6.7.8",
       "colo": "GYD", "error": ""}


class AppTestCase(unittest.TestCase):
    """A fresh app per test: store, fakes and network tables reset."""

    TABLES = {}

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        for name in ("console", "dialogs"):
            fake[name].ANSWERS[:] = []
            fake[name].LOG[:] = []
        fake["clipboard"].DATA[0] = ""
        fake["keychain"].STORE.clear()
        engine.FakeAPI.records = {}
        engine.FakeAPI.calls = []
        engine.FakeAPI.unreachable_direct = False
        engine.FakeAPI.down = False
        # the shared fakes raise the engine copy's errors; make them this copy's
        self.patch(engine.app, "NetError", app.NetError)
        self.conn = dict(MCI)
        self.tables = {"mci": {"1.0.0.1": (True, 300.0, "GYD"), "1.0.0.2": (True, 150.0, "FRA")},
                       "mtn": {"1.0.0.1": (True, 200.0, "FRA"), "1.0.0.2": (False, None, ""),
                               "1.0.0.9": (True, 90.0, "FRA")},
                       "home": {"1.0.0.7": (True, 60.0, "FRA")}}
        self.patch(app, "run_bg", lambda fn, *a: fn(*a))
        self.patch(app, "detect_connection", lambda timeout=6.0: dict(self.conn))
        fake_api = engine.FakeAPI
        fake_api.verify_token = lambda api: {"status": "active", "kind": "account"}
        fake_api.inspect_record = lambda api, z, n, t: (fake_api.records.get((n, t), []), [])
        fake_api.zone_name = lambda api, z: "example.com"
        for fn, defaults in ((app.with_api, (fake_api,)), (app.read_record, ((), fake_api)),
                             (app.inspect_record, (fake_api,)),
                             (app.apply_record, ((), "", "apply", fake_api))):
            self.patch(fn, "__defaults__", defaults)
        test = self
        real_job = app.ScanJob

        class Job(real_job):
            def __init__(self, store, sid, nid, **kw):
                table = test.tables.get(nid, {})
                probe = engine.scripted_probe(table)
                kw.update(context_factory=lambda: None, api_factory=fake_api,
                          candidates=list(table), probe_trace=probe, probe_ws=probe)
                real_job.__init__(self, store, sid, nid, **kw)

        self.patch(app, "ScanJob", Job)
        self.store = app.Store(os.path.join(self.tmp, "data.json"))
        self.store.update_settings({"verify_attempts": 3, "ips_per_record": 1})
        self.app = app.App(self.store)

    def patch(self, obj, name, value):
        old = getattr(obj, name)
        setattr(obj, name, value)
        self.addCleanup(setattr, obj, name, old)

    # helpers ---------------------------------------------------------------

    def answer(self, *dialog_answers, alerts=()):
        fake["dialogs"].ANSWERS[:] = list(dialog_answers)
        fake["console"].ANSWERS[:] = list(alerts)

    def ready(self):
        """A store with Germany (link + mobile record) and a token."""
        sid = self.store.save_server(None, {"name": "آلمان", "sni": "germany.example.com",
                                            "path": "/ws",
                                            "record_mobile": "cdn1.germany.example.com"})
        self.store.set_uuid(sid, UUID)
        self.store.secrets.set(TOKEN)
        self.start()
        return sid

    def start(self):
        self.app.run()
        self.main = self.app.main
        self.main.frame = (0, 0, 390, 760)
        self.main.layout()

    def scan(self, mode="auto", every=False):
        self.app.active_scan = None
        self.app.nav.pushed = []
        self.app.scan_flow(mode, every)
        if not self.app.nav.pushed:
            return None
        view = self.app.nav.pushed[-1]
        deadline = time.time() + 10
        while time.time() < deadline:
            done = view.result and not view.running
            if done and (not view.batch or len(view.summary) == len(view.sids)):
                break
            time.sleep(0.02)
        time.sleep(0.05)
        view.frame = (0, 0, 390, 760)
        view.layout()
        return view

    def alerts(self):
        return [entry for entry in fake["console"].LOG if entry[0] == "alert"]


class FirstRunTests(AppTestCase):
    def test_the_first_run_takes_the_link_from_the_clipboard(self):
        fake["clipboard"].DATA[0] = LINK
        self.answer({"link": LINK, "name": "", "sni": "", "path": "", "port": "443", "tls": True,
                     "record_mobile": "", "record_home": ""},
                    {"token": " Bearer %s " % TOKEN, "zone_id": "", "ips_per_record": "1",
                     "auto_apply": True})
        self.start()
        server = self.store.servers[0]
        self.assertEqual((server["name"], server["sni"], server["path"], server["record_mobile"]),
                         ("آلمان", "germany.example.com", "/ws", "cdn1.germany.example.com"))
        self.assertEqual(self.store.uuid_for(server["id"]), UUID)
        self.assertEqual(self.store.token, TOKEN)
        form = [f for sec in fake["dialogs"].LOG[0][3] for f in sec[1]]
        self.assertEqual(form[0]["value"], LINK)  # offered from the clipboard
        self.assertIn("همراه اول", self.main.net_btn.title)
        self.assertEqual(self.main.scan_btn.title, "اسکن «آلمان» روی «همراه اول»")
        self.assertTrue(self.main.setup.hidden)
        self.assertNotIn(UUID, Path(self.store.path).read_text(encoding="utf-8"))

    def test_a_bad_link_is_explained_and_the_form_comes_back(self):
        self.answer({"link": "vmess://x", "name": "", "sni": "", "path": "", "port": "443",
                     "tls": True, "record_mobile": "", "record_home": ""}, None)
        self.app.main = app.MainView(self.app)
        self.app.edit_server(None)
        self.assertEqual(self.alerts()[-1][1], "لینک کانفیگ")
        self.assertEqual(self.store.servers, [])

    def test_missing_pieces_are_listed_on_the_main_screen(self):
        self.store.save_server(None, {"name": "آلمان", "sni": "germany.example.com"})
        self.answer()
        self.start()
        self.assertFalse(self.main.setup.hidden)
        self.assertIn("توکن", self.main.setup.text)
        self.assertIn("لینک کانفیگ", self.main.setup.text)


class ScanFlowTests(AppTestCase):
    def test_mci_then_irancell(self):
        self.ready()
        view = self.scan()
        self.assertEqual(view.result["kind"], "applied")
        self.assertIn("ایرانسل تأیید نشده", view.outcome.text)
        self.assertEqual(self.main.cards[0].pill.text, "‏تأیید نشده")
        self.assertFalse(view.done_btn.hidden)
        self.assertTrue(view.stop_btn.hidden)
        self.conn.update(asn=44244, org="Irancell")
        view = self.scan()
        self.assertEqual((view.result["kind"], view.result["ips"]), ("applied", ["1.0.0.1"]))
        card = self.main.cards[0]
        card.frame = (0, 0, 358, card.height_needed)
        card.layout()
        chips = [chip.text for chip in card.rows[0][1]]
        self.assertEqual(chips, ["‏همراه اول 300", "‏ایرانسل 200"])
        self.assertIn("همراه اول ✓ · ایرانسل ✓", card.summary.text)
        self.assertEqual((card.state, card.pill.text), ("ok", "‏سالم"))
        self.assertEqual(self.main.cards[1].pill.text, "‏اختیاری")

    def test_a_card_says_when_its_address_is_broken(self):
        sid = self.ready()
        self.scan()
        ip = self.store.record_ips(app.slot_key(sid, "mobile"))[0]
        self.store.record_result(sid, ip, "mtn", False)
        self.main.refresh()
        card = self.main.cards[0]
        self.assertEqual((card.state, card.pill.text), ("fail", "‏خراب"))
        self.assertIn("ایرانسل ✕ خراب", card.summary.text)

    def test_vpn_on_stops_the_scan(self):
        self.ready()
        self.conn.update(country="DE", asn=None)
        self.assertIsNone(self.scan())
        self.assertEqual(self.alerts()[-1][1], "VPN روشن است")
        self.assertEqual(engine.FakeAPI.records, {})

    def test_no_internet_stops_the_scan(self):
        self.ready()
        self.conn.update(ok=False, error="timeout")
        self.assertIsNone(self.scan())
        self.assertEqual(self.alerts()[-1][1], "اینترنت")

    def test_an_unknown_home_network_is_named_once(self):
        self.ready()
        self.conn.update(asn=58224, org="TCI")
        self.tables["n1"] = {"1.0.0.7": (True, 60.0, "FRA")}
        self.answer("+ اینترنت جدید: مخابرات", 1, alerts=["مخابرات"])
        view = self.scan()
        self.assertEqual(self.store.current_network["name"], "مخابرات")
        self.assertEqual(self.store.current_network["group"], "home")
        self.assertEqual(view.result["kind"], "found")  # no home record: measured only
        self.answer()
        self.assertEqual(self.app.detect(True)["name"], "مخابرات")  # remembered

    def test_a_wrong_asn_is_moved_from_the_badge(self):
        self.ready()
        self.store.save_network("mtn", "ایرانسل", "mobile", asn=197207)
        self.app.detect(True)
        self.assertIn("ایرانسل", self.main.net_btn.title)
        self.answer("الان روی «همراه اول» هستم")
        self.app.network_menu()
        self.assertEqual(self.store.network_for_asn(197207)["id"], "mci")
        self.assertIn("همراه اول", self.main.net_btn.title)

    def test_no_asn_asks_instead_of_guessing(self):
        self.ready()
        self.conn.update(asn=None)
        self.answer(None)
        self.assertIsNone(self.scan())
        self.assertIn("تشخیص خودکار نشد", fake["dialogs"].LOG[-1][1])

    def test_conflict_needs_the_user(self):
        sid = self.ready()
        self.store.record_result(sid, "1.0.0.5", "mtn", False)
        self.tables["mci"] = {"1.0.0.5": (True, 50.0, "")}
        view = self.scan()
        self.assertEqual(view.result["kind"], "conflict")
        self.assertFalse(view.anyway_btn.hidden)
        self.assertEqual(engine.FakeAPI.records, {})
        self.answer(alerts=[1])
        view.tapped_anyway(view.anyway_btn)
        self.assertEqual(engine.FakeAPI.records[("cdn1.germany.example.com", "A")], ["1.0.0.5"])
        self.assertTrue(view.anyway_btn.hidden)

    def test_the_scan_screen_shows_each_step(self):
        self.ready()
        view = self.scan()
        icons = [icon.text for icon, _, _ in view.step_views]
        self.assertEqual(icons, ["–", "✓", "✓", "✓"])  # no record yet, scan, measure, DNS
        details = [d.text for _, _, d in view.step_views]
        self.assertIn("انتخاب: 1.0.0.2 (150ms)", details[2])
        self.assertIn("cdn1.germany.example.com", details[3])
        self.assertTrue(view.track.hidden and view.counter.hidden)  # nothing running
        self.assertRegex(view.clock_label.text, r"^\d+:\d\d$")
        self.assertIn("تأخیر کانفیگ", view.table_title.text)
        self.assertFalse(view.table.hidden)
        for i, (icon, name, detail) in enumerate(view.step_views[:-1]):
            below = view.step_views[i + 1][1]
            self.assertLessEqual(detail.y + detail.height, below.y)  # no overlapping text

    def test_a_running_step_has_its_own_progress_bar(self):
        self.ready()
        view = app.ScanView(self.app, [self.store.selected["id"]], "mci", "auto")
        view.frame = (0, 0, 390, 760)
        view.step(1, "run")
        view.progress(40, 200, 7)
        self.assertFalse(view.track.hidden)
        self.assertEqual(view.counter.text, "‏40 از 200 IP · 7 جواب داد")
        self.assertAlmostEqual(view.fill.width, view.track.width * 0.2)
        step_1 = view.step_views[1]
        self.assertGreater(view.track.y, step_1[2].y)
        self.assertLess(view.track.y, view.step_views[2][1].y)
        view.step(1, "ok", "7 از 200 IP جواب داد")
        self.assertTrue(view.track.hidden)
        view.phase_state[2] = "run"
        view.phase = 2
        view._tick()
        self.assertIn(view.step_views[2][0].text, app.SPINNER)

    def test_unhappy_with_a_healthy_delay_scan_anyway(self):
        sid = self.ready()
        self.store.update_settings({"good_ping_ms": 0})  # the wanted delay is off
        engine.FakeAPI.records[("cdn1.germany.example.com", "A")] = ["1.0.0.1"]
        view = self.scan()
        self.assertEqual(view.result["kind"], "healthy")
        self.assertIn("1.0.0.1 (300ms)", view.outcome.text)
        self.assertFalse(view.faster_btn.hidden)
        view.tapped_faster(view.faster_btn)
        deadline = time.time() + 10
        while (view.result is None or view.running) and time.time() < deadline:
            time.sleep(0.02)
        time.sleep(0.05)
        self.assertEqual(view.mode, "force")
        self.assertEqual((view.result["kind"], view.result["ips"]), ("applied", ["1.0.0.2"]))
        self.assertEqual(engine.FakeAPI.records[("cdn1.germany.example.com", "A")], ["1.0.0.2"])
        self.assertTrue(view.faster_btn.hidden)
        self.assertFalse(view.done_btn.hidden)
        self.assertEqual(self.store.record_ips(app.slot_key(sid, "mobile")), ["1.0.0.2"])

    def test_a_slow_address_is_marked_on_its_card(self):
        sid = self.ready()
        self.store.update_settings({"good_ping_ms": 250})
        self.scan()  # MCI: 1.0.0.2 at 150ms
        self.store.record_result(sid, "1.0.0.2", "mtn", True, 480.0)
        self.main.refresh()
        card = self.main.cards[0]
        self.assertEqual((card.state, card.pill.text), ("warn", "‏کُند"))
        chips = card.rows[0][1]
        self.assertEqual(chips[0].text_color, app.GOOD)   # MCI 150
        self.assertEqual(chips[1].text_color, app.WARN)   # Irancell 480
        self.assertIn("ایرانسل ✓ کُند", card.summary.text)

    def test_stopping_marks_the_running_step(self):
        self.ready()
        view = app.ScanView(self.app, [self.store.selected["id"]], "mci", "auto")
        view.frame = (0, 0, 390, 760)
        view.step(2, "run")
        view.finished({"kind": "stopped"})
        self.assertEqual(view.step_views[2][0].text, "–")
        self.assertEqual(view.step_views[2][2].text, "‏متوقف شد")
        self.assertFalse(view.done_btn.hidden)

    def test_manual_approval_button(self):
        self.ready()
        self.store.update_settings({"auto_apply": False})
        view = self.scan()
        self.assertEqual(view.result["kind"], "pending")
        self.assertEqual(view.step_views[3][0].text, "❚❚")
        self.assertFalse(view.apply_btn.hidden)
        view.tapped_apply(view.apply_btn)
        self.assertEqual(view.result["kind"], "applied")
        self.assertTrue(view.apply_btn.hidden)

    def test_a_failed_update_can_be_retried(self):
        self.ready()
        engine.FakeAPI.down = True
        view = self.scan()
        self.assertEqual(view.result["kind"], "apply_failed")
        self.assertFalse(view.apply_btn.hidden)
        self.assertIn("connection reset", view.notes.text)
        engine.FakeAPI.down = False
        view.tapped_apply(view.apply_btn)
        self.assertEqual(view.result["kind"], "applied")
        self.assertTrue(view.apply_btn.hidden)
        self.assertEqual(view.outcome.text_color, app.GOOD)

    def test_all_servers(self):
        self.ready()
        self.store.save_server(None, {"name": "ترکیه", "sni": "turkey.example.com", "path": "/tr",
                                      "record_mobile": "cdn1.turkey.example.com"})
        self.main.refresh()
        self.assertFalse(self.main.all_btn.hidden)
        view = self.scan(every=True)
        self.assertEqual([r["kind"] for _, r in view.summary], ["applied", "applied"])
        self.assertIn("2 از 2", view.outcome.text)
        self.assertEqual(len(view.ds.items), 2)

    def test_stop_in_the_middle_changes_nothing(self):
        self.ready()
        self.store.update_settings({"stop_after": 0})
        self.tables["mci"] = {"1.0.%d.%d" % (i // 250, i % 250 + 1): (True, 100.0 + i, "")
                              for i in range(400)}
        slow = engine.scripted_probe(self.tables["mci"])

        def probe(*args):
            time.sleep(0.01)
            return slow(*args)

        real_job = app.ScanJob

        class SlowJob(real_job):
            def __init__(job, store, sid, nid, **kw):
                real_job.__init__(job, store, sid, nid, **kw)
                job.probe_trace = job.probe_ws = probe

        self.patch(app, "ScanJob", SlowJob)
        self.app.active_scan = None
        self.app.nav.pushed = []
        self.app.scan_flow("auto", False)
        view = self.app.nav.pushed[-1]
        time.sleep(0.1)
        view.tapped_stop(view.stop_btn)
        self.assertFalse(view.stop_btn.enabled)
        deadline = time.time() + 10
        while view.running and time.time() < deadline:
            time.sleep(0.02)
        time.sleep(0.05)
        self.assertEqual(view.result["kind"], "stopped")
        self.assertEqual(engine.FakeAPI.records, {})
        self.assertLess(view.result["scanned"], 400)

    def test_tapping_a_result_row(self):
        self.ready()
        view = self.scan()
        view.ds.selected_row = 0
        self.answer("کپی IP")
        view.row_tapped(view.ds)
        self.assertEqual(fake["clipboard"].DATA[0], view.rows[0]["ip"])


class MenuTests(AppTestCase):
    def test_every_tool_opens_without_errors(self):
        sid = self.ready()
        self.scan()
        items = None
        # what each tool asks: an IP to test, IPs to set, a confirmation...
        alerts = {2: ["1.0.0.2", 1], 3: ["1.0.0.2"], 4: [1], 8: [1]}
        for index in range(12):
            fake["dialogs"].LOG[:] = []
            self.answer(index, alerts=alerts.get(index, [1]))
            self.app.open_tools()
            items = items or fake["dialogs"].LOG[0][2]
        self.assertEqual(len(items), 12)
        errors = [line for line in Path(app.LOG_PATH).read_text().splitlines()
                  if "failed" in line and "flow" in line]
        self.assertEqual(errors, [])
        self.assertTrue(self.store.history(sid))

    def test_every_settings_page_opens_and_cancels(self):
        self.ready()
        for index in range(5):
            self.answer(index, None, None)
            self.app.open_settings()
        self.assertEqual(self.store.servers[0]["name"], "آلمان")

    def test_networks_can_be_edited(self):
        self.ready()
        self.answer(2, {"name": "خانگی", "home": True, "asns": "58224, 31549", "delete": False}, None)
        self.app.manage_networks()
        self.assertEqual(self.store.network("home")["asns"], [58224, 31549])

    def test_server_edit_keeps_records_apart(self):
        sid = self.ready()
        self.answer({"link": "", "name": "آلمان", "sni": "germany.example.com", "path": "/ws",
                     "port": "443", "tls": True, "record_mobile": "cdn1.germany.example.com",
                     "record_home": "cdn1.germany.example.com", "delete": False}, None)
        self.app.edit_server(sid)
        self.assertEqual(self.alerts()[-1][1], "رکورد")
        self.assertEqual(self.store.server(sid)["record_home"], "")

    def test_export_and_import(self):
        self.ready()
        self.answer(9)
        self.app.open_tools()
        exported = fake["clipboard"].DATA[0]
        self.assertNotIn(UUID, exported)
        self.assertNotIn(TOKEN, exported)
        self.assertEqual(json.loads(exported)["servers"][0]["name"], "آلمان")
        fake["clipboard"].DATA[0] = "not json"
        self.answer(10)
        self.app.open_tools()
        self.assertEqual(self.alerts()[-1][1], "وارد نشد")


class LayoutTests(AppTestCase):
    def test_server_line_says_how_it_is_tested(self):
        sid = self.ready()
        self.assertIn("germany.example.com · تأخیر کانفیگ ✓", self.main.server_info.text)
        self.store.set_uuid(sid, "")
        self.main.refresh()
        self.assertIn("لینک کانفیگ را اضافه کنید", self.main.server_info.text)
        self.assertEqual(self.main.server_info.text_color, app.WARN)

    def test_a_manual_pick_shows_on_the_badge(self):
        text, state = app.connection_text(None, {"name": "خانگی"})
        self.assertEqual(state, "ok")
        self.assertIn("خانگی (انتخاب دستی)", text)

    def test_dark_mode_colours_every_screen(self):
        self.addCleanup(app.apply_theme, "light")
        self.patch(fake["ui"], "get_ui_style", lambda: "dark")
        self.ready()
        dark = app.PALETTES["dark"]
        self.assertEqual(app.THEME, "dark")
        self.assertEqual(self.main.background_color, dark["BG"])
        self.assertEqual(self.main.cards[0].background_color, dark["CARD"])
        self.assertEqual(self.main.scan_btn.tint_color, dark["ON_ACCENT"])
        view = self.scan()
        self.assertEqual(view.outcome.text_color, dark["GOOD"])
        self.assertEqual(view.track.background_color, dark["TRACK"])
        self.assertEqual(self.main.cards[0].pill.background_color, dark["WARN_BG"])

    def test_text_is_readable_in_both_themes(self):
        def luminance(hex_colour):
            channels = [int(hex_colour[i:i + 2], 16) / 255.0 for i in (1, 3, 5)]
            lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
            return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]

        def contrast(a, b):
            high, low = sorted((luminance(a), luminance(b)), reverse=True)
            return (high + 0.05) / (low + 0.05)

        pairs = [("INK", "BG"), ("INK", "CARD"), ("MUTED", "CARD"), ("MUTED", "BG"),
                 ("GOOD", "GOOD_BG"), ("BAD", "BAD_BG"), ("NEUTRAL", "NEUTRAL_BG"),
                 ("WARN", "WARN_BG"), ("ACCENT", "CARD"), ("ACCENT", "BG"),
                 ("ON_ACCENT", "ACCENT"), ("BAD", "CARD"), ("WARN", "BG")]
        for theme, palette in app.PALETTES.items():
            for fg, bg in pairs:
                ratio = contrast(palette[fg], palette[bg])
                self.assertGreaterEqual(ratio, 4.5, "%s: %s on %s is %.2f" % (theme, fg, bg, ratio))

    def test_every_palette_has_every_colour(self):
        light, dark = app.PALETTES["light"], app.PALETTES["dark"]
        self.assertEqual(set(light), set(dark))
        for palette in (light, dark):
            for value in palette.values():
                self.assertRegex(value, r"^#[0-9A-F]{6}$")

    def test_screens_fit_every_phone_width(self):
        sid = self.ready()
        self.store.save_server(None, {"name": "ترکیه", "sni": "turkey.example.com",
                                      "record_mobile": "cdn1.turkey.example.com",
                                      "record_home": "cdn2.turkey.example.com"})
        view = self.scan()
        for width in (320, 375, 390, 430):
            self.main.frame = (0, 0, width, 700)
            self.main.layout()
            for card in self.main.cards:
                card.frame = (0, 0, width - 32, card.height_needed)
                card.layout()
                for sub in card.subviews:
                    self.assertLessEqual(sub.x + sub.width, width - 32 + 0.5, sub)
            view.frame = (0, 0, width, 700)
            view.layout()
        self.assertTrue(self.store.selected["id"] == sid)


class RecoveryTests(unittest.TestCase):
    def test_a_broken_data_file_is_kept_aside(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        path = os.path.join(tmp, "data.json")
        Path(path).write_text("{ broken", encoding="utf-8")
        store = app.Store(path)
        self.assertEqual(store.servers, [])
        self.assertTrue(store.recovered.startswith(path + ".broken-"))
        self.assertEqual(Path(store.recovered).read_text(encoding="utf-8"), "{ broken")

    def test_odd_stored_values_do_not_stop_the_app(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        path = os.path.join(tmp, "data.json")
        Path(path).write_text(json.dumps({"version": 5, "servers": [{"id": 5, "port": "x"}],
                                          "networks": "nope", "matrix": {"5": {"1.1.1.1": 3}},
                                          "records": [], "history": {}}), encoding="utf-8")
        store = app.Store(path)
        self.assertEqual(store.servers[0]["port"], 443)
        self.assertEqual(len(store.networks), 3)

    def test_damaged_real_data_still_opens_every_screen(self):
        """A real data file with random values swapped for junk still opens."""
        import copy
        import random
        rng = random.Random(3)
        junk = [None, 0, -5, 2.5, "", "x", True, [], {}, [1, None], {"k": [2]}]
        base = {"version": 5,
                "settings": {"ttl": 60, "ips_per_record": 2},
                "servers": [{"id": "s1", "name": "آلمان", "sni": "germany.example.com",
                             "record_mobile": "cdn1.germany.example.com",
                             "record_home": "cdn2.germany.example.com"}],
                "networks": copy.deepcopy(app.DEFAULT_NETWORKS),
                "server": "s1", "network": "mci",
                "matrix": {"s1": {"1.0.0.1": {"mci": {"ok": True, "delay": 300, "colo": "FRA",
                                                      "ts": time.time()}}}},
                "bad": {"mtn": {"1.0.0.2": time.time()}},
                "records": {"s1:mobile": {"ips": ["1.0.0.1"], "ts": time.time()}},
                "history": [{"ts": time.time(), "record": "s1:mobile", "kind": "apply",
                             "network": "mci", "old": ["1.0.0.3"], "new": ["1.0.0.1"]}],
                "zones": {}, "ranges": {}}

        def leaves(node, path=()):
            items = node.items() if isinstance(node, dict) else enumerate(node)
            for key, value in items:
                if isinstance(value, (dict, list)) and value:
                    yield from leaves(value, path + (key,))
                yield path + (key,)

        paths = list(leaves(base))
        for _ in range(250):
            doc = copy.deepcopy(base)
            for where in rng.sample(paths, rng.randrange(1, 4)):
                node = doc
                try:
                    for key in where[:-1]:
                        node = node[key]
                    node[where[-1]] = copy.deepcopy(rng.choice(junk))
                except (KeyError, IndexError, TypeError):
                    continue
            tmp = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, tmp)
            path = os.path.join(tmp, "data.json")
            Path(path).write_text(json.dumps(doc), encoding="utf-8")
            try:
                store = app.Store(path)
                json.dumps(store.data)
                for server in store.servers:
                    app.matrix_lines(store, server["id"])
                    app.history_lines(store, server["id"])
                    for key, *_ in store.slots(server["id"]):
                        store.record_ips(key)
                        store.slot_label(key)
                main = app.MainView(app.App(store))
                main.frame = (0, 0, 375, 700)
                main.refresh()
                main.layout()
                store.save()
            except Exception as exc:
                self.fail("%r broke the app: %r" % (doc, exc))


if __name__ == "__main__":
    unittest.main()

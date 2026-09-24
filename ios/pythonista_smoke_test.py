"""Pythonista smoke test for the iPhone scanner.

Run this once inside Pythonista on the iPhone, with the VPN turned off, before
the full app is built. It answers three questions on the phone's own carrier:

1. Does Pythonista's ``ui`` module draw a Persian, right-to-left screen?
2. Can the phone open TCP + TLS to Cloudflare addresses with our own SNI,
   several at once, and how fast?
3. Is the Cloudflare API reachable without the VPN? (The full app changes the
   DNS record through it.)

Nothing is changed anywhere: the probes only read ``/cdn-cgi/trace`` and the
public ``/client/v4/ips`` endpoint.

If Pythonista closes while this runs, open ``smoke_log.txt`` (saved next to
this script): its last lines say which step was running. Setting ``USE_UI``
to ``False`` runs the same network test in the console, without any screen.
"""

import faulthandler
import ipaddress
import os
import random
import socket
import ssl
import threading
import time
import urllib.request

#: False runs the network test in the console only (no ui module at all).
USE_UI = True

try:
    import ui  # Pythonista only
except ImportError:  # lets the probes be tried on a computer
    ui = None

try:
    from objc_util import on_main_thread  # Pythonista only
except ImportError:
    def on_main_thread(fn):
        return fn

#: A few of Cloudflare's published IPv4 ranges; addresses are drawn at random.
SAMPLE_RANGES = (
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "162.159.0.0/16",
    "188.114.96.0/20",
)
PROBE_COUNT = 12
WORKERS = 6
TIMEOUT = 3.0
DEFAULT_SNI = "speed.cloudflare.com"
API_URL = "https://api.cloudflare.com/client/v4/ips"

try:
    _HERE = os.path.dirname(os.path.abspath(__file__))
except NameError:
    _HERE = os.getcwd()
LOG_PATH = os.path.join(_HERE, "smoke_log.txt")
_log_lock = threading.Lock()


def log(message):
    """Append one line to the log and flush it, so it survives a crash."""
    line = "%s [%s] %s\n" % (time.strftime("%H:%M:%S"),
                             threading.current_thread().name, message)
    with _log_lock:
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError:
            pass


def enable_crash_trace():
    """Ask Python to write a traceback into the log on a hard crash."""
    try:
        fh = open(LOG_PATH, "a", encoding="utf-8")
        faulthandler.enable(file=fh, all_threads=True)
    except Exception as exc:  # not every build allows it
        log("faulthandler unavailable: %r" % (exc,))


def random_addresses(count, rng=random):
    """``count`` random host addresses spread over :data:`SAMPLE_RANGES`."""
    nets = [ipaddress.ip_network(r) for r in SAMPLE_RANGES]
    picked = []
    for i in range(count):
        net = nets[i % len(nets)]
        offset = rng.randrange(1, net.num_addresses - 1)
        picked.append(str(net.network_address + offset))
    return picked


def probe(ip, sni, ctx, port=443, timeout=TIMEOUT):
    """TCP, TLS and one HTTP request to ``ip`` with ``sni`` as the hostname.

    Returns a dict with ``ok``, the milliseconds of each step, the HTTP status
    and the Cloudflare datacentre (``colo``) the address answered from.
    """
    result = {"ip": ip, "ok": False, "tcp": None, "tls": None,
              "status": None, "colo": "", "error": ""}
    try:
        start = time.perf_counter()
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            result["tcp"] = (time.perf_counter() - start) * 1000
            with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                result["tls"] = (time.perf_counter() - start) * 1000
                request = ("GET /cdn-cgi/trace HTTP/1.1\r\nHost: %s\r\n"
                           "Connection: close\r\n\r\n" % sni)
                tls.sendall(request.encode("ascii"))
                data = b""
                while len(data) < 8192:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    data += chunk
        text = data.decode("utf-8", "replace")
        first = text.split("\r\n", 1)[0].split()
        if len(first) >= 2 and first[1].isdigit():
            result["status"] = int(first[1])
        for line in text.splitlines():
            if line.startswith("colo="):
                result["colo"] = line[5:].strip()
        result["ok"] = result["status"] == 200
        if not result["ok"]:
            result["error"] = "HTTP %s" % result["status"]
    except socket.timeout:
        result["error"] = "timeout"
    except ssl.SSLError as exc:
        result["error"] = "TLS: %s" % (exc.reason or exc.__class__.__name__)
    except OSError as exc:
        result["error"] = exc.strerror or exc.__class__.__name__
    except Exception as exc:  # never let one address stop the test
        result["error"] = repr(exc)
    return result


def api_reachable(timeout=6.0):
    """True when the Cloudflare API answers on this connection."""
    try:
        with urllib.request.urlopen(API_URL, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def format_row(r):
    if r["ok"]:
        return "%-15s  %4.0f ms  %s" % (r["ip"], r["tls"], r["colo"])
    return "%-15s  FAIL  %s" % (r["ip"], r["error"])


def run_probes(sni, on_row=None):
    """Probe :data:`PROBE_COUNT` random addresses with plain worker threads."""
    ctx = ssl.create_default_context()  # built once, before any thread
    todo = random_addresses(PROBE_COUNT)
    rows = []
    lock = threading.Lock()

    def worker():
        while True:
            with lock:
                if not todo:
                    return
                ip = todo.pop()
            log("probe %s" % ip)
            r = probe(ip, sni, ctx)
            log("done  %s" % format_row(r))
            with lock:
                rows.append(r)
            if on_row:
                on_row(r)

    threads = [threading.Thread(target=worker, name="probe-%d" % i, daemon=True)
               for i in range(WORKERS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return rows


def console_main(sni=DEFAULT_SNI):
    log("console test start, sni=%s" % sni)
    began = time.perf_counter()
    rows = run_probes(sni, on_row=lambda r: print(format_row(r)))
    ok = sum(1 for r in rows if r["ok"])
    print("\n%d of %d answered in %.1f s" % (ok, len(rows), time.perf_counter() - began))
    api = api_reachable()
    print("Cloudflare API:", "reachable" if api else "NOT reachable")
    log("console test end: %d/%d ok, api=%s" % (ok, len(rows), api))


if ui is not None:

    INK = "#17181C"
    MUTED = "#5B5E66"
    ACCENT = "#1F4FD1"
    GOOD = "#17663F"
    BAD = "#A3261C"

    class SmokeTest(ui.View):
        """One screen. Every change to it happens on the main thread."""

        def __init__(self):
            self.background_color = "#F3F1EC"
            self.name = "CF Scanner test"

            self.heading = ui.Label()
            self.heading.text = "تست اولیه اسکنر"
            self.heading.font = ("<System-Bold>", 24)
            self.heading.text_color = INK
            self.heading.alignment = ui.ALIGN_RIGHT

            self.hint = ui.Label()
            self.hint.text = "VPN را خاموش کنید، بعد «شروع» را بزنید."
            self.hint.font = ("<System>", 14)
            self.hint.text_color = MUTED
            self.hint.alignment = ui.ALIGN_RIGHT
            self.hint.number_of_lines = 2

            self.sni = ui.TextField()
            self.sni.text = DEFAULT_SNI
            self.sni.font = ("Menlo", 14)
            self.sni.autocapitalization_type = ui.AUTOCAPITALIZE_NONE
            self.sni.autocorrection_type = False
            self.sni.spellchecking_type = False
            self.sni.placeholder = "SNI"

            self.button = ui.Button()
            self.button.title = "شروع"
            self.button.font = ("<System-Bold>", 17)
            self.button.background_color = ACCENT
            self.button.tint_color = "white"
            self.button.corner_radius = 12
            self.button.action = self.start

            self.card = ui.View()
            self.card.background_color = "white"
            self.card.corner_radius = 16
            self.card.border_width = 1
            self.card.border_color = "#E2DED6"

            self.status = ui.Label()
            self.status.text = ""
            self.status.font = ("<System-Bold>", 15)
            self.status.text_color = INK
            self.status.alignment = ui.ALIGN_RIGHT

            self.output = ui.TextView()
            self.output.editable = False
            self.output.font = ("Menlo", 13)
            self.output.text_color = INK
            self.output.background_color = "white"

            self.card.add_subview(self.status)
            self.card.add_subview(self.output)
            for v in (self.heading, self.hint, self.sni, self.button, self.card):
                self.add_subview(v)
            log("ui built")

        def layout(self):
            w, h = self.width, self.height
            pad = 20
            inner = w - 2 * pad
            self.heading.frame = (pad, 20, inner, 34)
            self.hint.frame = (pad, 56, inner, 40)
            self.sni.frame = (pad, 104, inner, 40)
            self.button.frame = (pad, 156, inner, 48)
            card_h = max(120, h - 240)
            self.card.frame = (pad, 220, inner, card_h)
            self.status.frame = (16, 12, inner - 32, 24)
            self.output.frame = (8, 44, inner - 16, card_h - 52)

        @on_main_thread
        def set_status(self, text, color=INK):
            self.status.text = text
            self.status.text_color = color

        @on_main_thread
        def append(self, line):
            self.output.text = self.output.text + line + "\n"

        @on_main_thread
        def set_busy(self, busy):
            self.button.enabled = not busy
            self.button.alpha = 0.5 if busy else 1.0

        def start(self, sender):
            sni = (self.sni.text or "").strip() or DEFAULT_SNI
            self.sni.end_editing()
            self.output.text = ""
            self.set_busy(True)
            log("start pressed, sni=%s" % sni)
            threading.Thread(target=self.run, args=(sni,), name="runner",
                             daemon=True).start()

        def run(self, sni):
            try:
                self.set_status("در حال تست %d آدرس..." % PROBE_COUNT)
                began = time.perf_counter()
                rows = run_probes(sni, on_row=lambda r: self.append(format_row(r)))
                took = time.perf_counter() - began
                ok = sum(1 for r in rows if r["ok"])
                self.append("")
                self.append("%d of %d answered in %.1f s" % (ok, len(rows), took))
                self.set_status("بررسی API کلادفلر...")
                log("checking api")
                api = api_reachable()
                self.append("Cloudflare API: %s" % ("reachable" if api else "NOT reachable"))
                self.set_status("تمام شد: %d از %d پاسخ داد" % (ok, len(rows)),
                                GOOD if ok else BAD)
                log("run end: %d/%d ok, api=%s" % (ok, len(rows), api))
            except Exception as exc:
                log("run failed: %r" % (exc,))
                self.append("ERROR: %r" % (exc,))
                self.set_status("خطا", BAD)
            finally:
                self.set_busy(False)


def main():
    log("=== start (USE_UI=%s, ui=%s) ===" % (USE_UI, ui is not None))
    enable_crash_trace()
    if USE_UI and ui is not None:
        view = SmokeTest()
        log("presenting")
        view.present("fullscreen")
        log("presented")
    else:
        console_main()


if __name__ == "__main__":
    main()

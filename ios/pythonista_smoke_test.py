"""Pythonista smoke test for the iPhone scanner.

Run this once inside Pythonista on the iPhone, with the VPN turned off, before
the full app is built. It answers three questions on the phone's own carrier:

1. Does Pythonista's ``ui`` module draw a Persian, right-to-left screen?
2. Can the phone open TCP + TLS to Cloudflare addresses with our own SNI,
   several at once, and how fast?
3. Is the Cloudflare API reachable without the VPN? (The full app changes the
   DNS record through it.)

Nothing is changed anywhere: the probes only read ``/cdn-cgi/trace`` and the
public ``/client/v4/ips`` endpoint, and nothing is stored.
"""

import ipaddress
import random
import socket
import ssl
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

try:
    import ui  # Pythonista only
except ImportError:  # pragma: no cover - lets the probes be tried elsewhere
    ui = None

#: A few of Cloudflare's published IPv4 ranges; addresses are drawn at random.
SAMPLE_RANGES = (
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "162.159.0.0/16",
    "188.114.96.0/20",
)
PROBE_COUNT = 12
WORKERS = 12
TIMEOUT = 3.0
DEFAULT_SNI = "speed.cloudflare.com"
API_URL = "https://api.cloudflare.com/client/v4/ips"


def random_addresses(count, rng=random):
    """``count`` random host addresses spread over :data:`SAMPLE_RANGES`."""
    nets = [ipaddress.ip_network(r) for r in SAMPLE_RANGES]
    picked = []
    for i in range(count):
        net = nets[i % len(nets)]
        offset = rng.randrange(1, net.num_addresses - 1)
        picked.append(str(net.network_address + offset))
    return picked


def probe(ip, sni, port=443, timeout=TIMEOUT):
    """TCP, TLS and one HTTP request to ``ip`` with ``sni`` as the hostname.

    Returns a dict with ``ok``, the milliseconds of each step, the HTTP status
    and the Cloudflare datacentre (``colo``) the address answered from.
    """
    result = {"ip": ip, "ok": False, "tcp": None, "tls": None,
              "status": None, "colo": "", "error": ""}
    ctx = ssl.create_default_context()
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
    """Probe :data:`PROBE_COUNT` random addresses; returns the result dicts."""
    rows = []
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for r in pool.map(lambda ip: probe(ip, sni), random_addresses(PROBE_COUNT)):
            rows.append(r)
            if on_row:
                on_row(r)
    return rows


if ui is not None:

    INK = "#17181C"
    MUTED = "#5B5E66"
    ACCENT = "#1F4FD1"
    GOOD = "#17663F"
    BAD = "#A3261C"

    class SmokeTest(ui.View):
        def __init__(self):
            self.background_color = "#F3F1EC"
            self.name = "CF Scanner test"

            self.title = ui.Label(text="تست اولیه اسکنر", font=("<System-Bold>", 24),
                                  text_color=INK, alignment=ui.ALIGN_RIGHT)
            self.hint = ui.Label(text="VPN را خاموش کنید، بعد «شروع» را بزنید.",
                                 font=("<System>", 14), text_color=MUTED,
                                 alignment=ui.ALIGN_RIGHT, number_of_lines=2)
            self.sni = ui.TextField(text=DEFAULT_SNI, font=("Menlo", 14),
                                    autocapitalization_type=ui.AUTOCAPITALIZE_NONE,
                                    autocorrection_type=False, spellchecking_type=False,
                                    clear_button_mode="while_editing")
            self.sni.placeholder = "SNI (مثلاً cdn.example.com)"

            self.button = ui.Button(title="شروع", font=("<System-Bold>", 17))
            self.button.background_color = ACCENT
            self.button.tint_color = "white"
            self.button.corner_radius = 12
            self.button.action = self.start

            self.card = ui.View(background_color="white", corner_radius=16,
                                border_width=1, border_color="#E2DED6")
            self.status = ui.Label(text="", font=("<System-Bold>", 15),
                                   text_color=INK, alignment=ui.ALIGN_RIGHT)
            self.output = ui.TextView(editable=False, font=("Menlo", 13),
                                      text_color=INK, background_color="white")
            self.card.add_subview(self.status)
            self.card.add_subview(self.output)

            for v in (self.title, self.hint, self.sni, self.button, self.card):
                self.add_subview(v)

        def layout(self):
            w, h = self.width, self.height
            pad = 20
            inner = w - 2 * pad
            self.title.frame = (pad, 20, inner, 34)
            self.hint.frame = (pad, 56, inner, 40)
            self.sni.frame = (pad, 104, inner, 40)
            self.button.frame = (pad, 156, inner, 48)
            self.card.frame = (pad, 220, inner, h - 240)
            self.status.frame = (16, 12, inner - 32, 24)
            self.output.frame = (8, 44, inner - 16, self.card.height - 52)

        def set_status(self, text, color=INK):
            def apply():
                self.status.text = text
                self.status.text_color = color
            ui.delay(apply, 0)

        def append(self, line):
            def apply():
                self.output.text += line + "\n"
            ui.delay(apply, 0)

        def start(self, sender):
            self.sni.end_editing()
            self.output.text = ""
            self.button.enabled = False
            self.run(self.sni.text.strip() or DEFAULT_SNI)

        @ui.in_background
        def run(self, sni):
            self.set_status("در حال تست %d آدرس..." % PROBE_COUNT)
            began = time.perf_counter()
            rows = run_probes(sni, on_row=lambda r: self.append(format_row(r)))
            took = time.perf_counter() - began
            ok = sum(1 for r in rows if r["ok"])
            self.append("")
            self.append("%d of %d answered in %.1f s" % (ok, len(rows), took))
            self.set_status("بررسی API کلادفلر...")
            api = api_reachable()
            self.append("Cloudflare API: %s" % ("reachable" if api else "NOT reachable"))
            color = GOOD if ok else BAD
            self.set_status("تمام شد: %d از %d پاسخ داد" % (ok, len(rows)), color)

            def done():
                self.button.enabled = True
            ui.delay(done, 0)


if __name__ == "__main__":
    if ui is not None:
        SmokeTest().present("fullscreen")
    else:
        for row in run_probes(DEFAULT_SNI):
            print(format_row(row))
        print("Cloudflare API:", "reachable" if api_reachable() else "NOT reachable")

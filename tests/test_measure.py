"""Jitter, upload and the cfst download pass.

Nothing here contacts a public network. Socket tests listen on 127.0.0.1, and
the scan tests replace both the scanner and the probe functions.
"""

from __future__ import annotations

import socket
import threading
import unittest
from unittest import mock

from cfscan.measure import (
    DEFAULT_DOWNLOAD_BYTES,
    DEFAULT_DOWNLOAD_URL,
    measure_jitter_ms,
    measure_upload_mbps,
    open_tcp,
    successive_jitter_ms,
)
from cfscan.runner import explain_zero_download
from cfscan.menu import quick_scan
from cfscan.parser import ScanResult

from tests.support import LOG_SUCCESS, Fixture, ScriptedSpawn


def _csv(rows):
    header = "IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码"
    lines = ["\ufeff" + header]
    for ip, latency, download in rows:
        lines.append(f"{ip},4,4,0.00,{latency:.2f},{download:.2f},FRA")
    return "\r\n".join(lines) + "\r\n"


class _MemorySocket:
    def __init__(self, response=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"):
        self.sent = b""
        self._buf = response

    def sendall(self, data):
        self.sent += data

    def recv(self, count):
        chunk = self._buf[:count]
        self._buf = self._buf[count:]
        return chunk

    def settimeout(self, _timeout):
        return None

    def close(self):
        return None


class JitterMathTests(unittest.TestCase):
    def test_mean_gap_between_samples(self):
        self.assertAlmostEqual(successive_jitter_ms([10, 12, 11, 15]), 7.0 / 3.0)

    def test_one_sample_is_not_a_measurement(self):
        self.assertIsNone(successive_jitter_ms([10]))
        self.assertIsNone(successive_jitter_ms([]))

    def test_measure_jitter_uses_the_injected_clock_and_direct_flag(self):
        schedule = [0.0, 0.010, 0.010, 0.030, 0.030, 0.040]
        seen = {}

        def clock():
            clock.n += 1
            return schedule[clock.n - 1]

        clock.n = 0

        def connect(ip, port, timeout, direct=False, environ=None):
            seen["direct"] = direct
            seen["ip"] = ip
            seen["port"] = port
            return _MemorySocket()

        jitter = measure_jitter_ms(
            "104.16.0.1", 2087, samples=3, direct=True, connect=connect, clock=clock)
        self.assertAlmostEqual(jitter, 10.0)
        self.assertTrue(seen["direct"])
        self.assertEqual(seen["ip"], "104.16.0.1")
        self.assertEqual(seen["port"], 2087)

    def test_a_failed_handshake_is_skipped(self):
        def connect(ip, port, timeout, direct=False, environ=None):
            raise OSError("timed out")

        self.assertIsNone(measure_jitter_ms(
            "104.16.0.1", 443, samples=4, connect=connect))


class DownloadDefaultTests(unittest.TestCase):
    def test_default_download_url_is_fifty_megabytes(self):
        self.assertEqual(DEFAULT_DOWNLOAD_BYTES, 50_000_000)
        self.assertEqual(
            DEFAULT_DOWNLOAD_URL,
            "https://speed.cloudflare.com/__down?bytes=50000000",
        )


class _RepeatingSocket:
    """Answers each finished POST with the next scripted response."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.sent = b""
        self._buf = b""
        self._need = None
        self._head = b""

    def sendall(self, data):
        self.sent += data
        if self._need is None:
            self._head += data
            if b"\r\n\r\n" not in self._head:
                return
            head, extra = self._head.split(b"\r\n\r\n", 1)
            self._head = b""
            length = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    length = int(line.split(b":", 1)[1].strip())
            self._need = length - len(extra)
            if self._need <= 0:
                self._queue()
                self._need = None
            return
        self._need -= len(data)
        if self._need <= 0:
            self._queue()
            self._need = None

    def _queue(self):
        if self.responses:
            self._buf += self.responses.pop(0)

    def recv(self, count):
        if not self._buf:
            return b""
        chunk = self._buf[:count]
        self._buf = self._buf[count:]
        return chunk

    def settimeout(self, _timeout):
        return None

    def close(self):
        return None


def _clock(schedule):
    values = iter(schedule)

    def clock():
        return next(values)

    return clock


_UPLOAD_OK = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"


class UploadTests(unittest.TestCase):
    def test_upload_posts_to_the_url_through_the_candidate_address(self):
        seen = {}

        def clock():
            clock.n += 1
            return clock.n * 100.0

        clock.n = 0

        def connect(ip, port, timeout, direct=False, environ=None):
            sock = _MemorySocket()
            seen["sock"] = sock
            seen["ip"] = ip
            seen["port"] = port
            seen["direct"] = direct
            return sock

        mbps = measure_upload_mbps(
            "104.16.0.1", "http://speed.cloudflare.com/__up",
            seconds=8, direct=True, connect=connect, clock=clock)
        self.assertIsNotNone(mbps)
        self.assertGreater(mbps, 0)
        self.assertEqual(seen["ip"], "104.16.0.1")
        self.assertEqual(seen["port"], 80)
        self.assertTrue(seen["direct"])
        sent = seen["sock"].sent
        self.assertIn(b"POST /__up HTTP/1.1", sent)
        self.assertIn(b"Host: speed.cloudflare.com", sent)
        self.assertNotIn(b"104.16.0.1", sent.split(b"\r\n\r\n", 1)[0])

    def test_a_rejected_upload_is_not_a_speed(self):
        def connect(ip, port, timeout, direct=False, environ=None):
            return _MemorySocket(b"HTTP/1.1 500 No\r\nContent-Length: 0\r\n\r\n")

        def clock():
            clock.n += 1
            return float(clock.n)

        clock.n = 0
        self.assertIsNone(measure_upload_mbps(
            "104.16.0.1", "http://example.test/up", seconds=1,
            connect=connect, clock=clock))

    def test_upload_reuses_one_connection_for_one_megabyte_posts(self):
        sock = _RepeatingSocket([_UPLOAD_OK, _UPLOAD_OK])
        seen = []
        wrapped = []

        def connect(ip, port, timeout, direct=False, environ=None):
            seen.append((ip, port, direct))
            return sock

        def wrap(raw, server_hostname, timeout):
            wrapped.append((raw, server_hostname, timeout))
            return raw

        # started, after post 1, before post 2, after post 2, elapsed
        with mock.patch("cfscan.measure._wrap_tls", side_effect=wrap):
            mbps = measure_upload_mbps(
                "104.16.0.1", "https://speed.cloudflare.com/__up",
                seconds=1, direct=True, connect=connect,
                clock=_clock([0.0, 0.4, 0.5, 1.0, 1.0]))
        self.assertAlmostEqual(mbps, 2.0)
        self.assertEqual(seen, [("104.16.0.1", 443, True)])
        self.assertEqual(wrapped, [(sock, "speed.cloudflare.com", 10)])
        self.assertEqual(sock.sent.count(b"POST /__up HTTP/1.1"), 2)
        self.assertEqual(sock.sent.count(b"Content-Length: 1048576"), 2)
        self.assertIn(b"Connection: keep-alive", sock.sent)
        self.assertIn(b"Host: speed.cloudflare.com", sock.sent)
        self.assertNotIn(b"Connection: close", sock.sent)

    def test_upload_opens_again_when_the_server_closes(self):
        closed = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        sockets = []

        def connect(ip, port, timeout, direct=False, environ=None):
            sock = _RepeatingSocket([closed])
            sockets.append(sock)
            return sock

        mbps = measure_upload_mbps(
            "104.16.0.1", "http://speed.cloudflare.com/__up",
            seconds=1, direct=False, connect=connect,
            clock=_clock([0.0, 0.4, 0.5, 1.0, 1.0]))
        self.assertAlmostEqual(mbps, 2.0)
        self.assertEqual(len(sockets), 2)
        posted = sum(sock.sent.count(b"POST /__up HTTP/1.1") for sock in sockets)
        self.assertEqual(posted, 2)

    def test_a_later_rejection_keeps_the_bytes_already_accepted(self):
        sock = _RepeatingSocket([
            _UPLOAD_OK,
            b"HTTP/1.1 500 No\r\nContent-Length: 0\r\n\r\n",
        ])

        def connect(ip, port, timeout, direct=False, environ=None):
            return sock

        mbps = measure_upload_mbps(
            "104.16.0.1", "http://speed.cloudflare.com/__up",
            seconds=8, connect=connect,
            clock=_clock([0.0, 0.2, 0.3, 1.0]))
        self.assertAlmostEqual(mbps, 1.0)

    def test_chunked_keep_alive_still_reuses_the_socket(self):
        chunked = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n0\r\n\r\n"
        )
        sock = _RepeatingSocket([chunked, chunked])
        calls = []

        def connect(ip, port, timeout, direct=False, environ=None):
            calls.append(ip)
            return sock

        mbps = measure_upload_mbps(
            "104.16.0.1", "http://speed.cloudflare.com/__up",
            seconds=1, connect=connect,
            clock=_clock([0.0, 0.4, 0.5, 1.0, 1.0]))
        self.assertAlmostEqual(mbps, 2.0)
        self.assertEqual(calls, ["104.16.0.1"])
        self.assertEqual(sock.sent.count(b"POST /__up HTTP/1.1"), 2)


class ProxySocketTests(unittest.TestCase):
    def test_direct_ignores_a_proxy_and_connects_to_the_address(self):
        target = socket.socket()
        target.bind(("127.0.0.1", 0))
        target.listen(1)
        target.settimeout(2)
        port = target.getsockname()[1]
        environ = {
            "HTTPS_PROXY": "http://127.0.0.1:1",
            "https_proxy": "http://127.0.0.1:1",
        }
        try:
            sock = open_tcp("127.0.0.1", port, timeout=1, direct=True, environ=environ)
            incoming, _addr = target.accept()
            sock.close()
            incoming.close()
        finally:
            target.close()

    def test_without_direct_an_http_proxy_receives_connect(self):
        seen = {}
        ready = threading.Event()

        def serve():
            srv = socket.socket()
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            seen["port"] = srv.getsockname()[1]
            ready.set()
            srv.settimeout(2)
            try:
                conn, _addr = srv.accept()
            except OSError:
                srv.close()
                return
            conn.settimeout(2)
            data = b""
            try:
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
            seen["request"] = data
            try:
                conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            except OSError:
                pass
            conn.close()
            srv.close()

        thread = threading.Thread(target=serve)
        thread.start()
        self.assertTrue(ready.wait(2))
        environ = {"HTTP_PROXY": f"http://127.0.0.1:{seen['port']}"}
        sock = open_tcp("104.16.0.1", 443, timeout=2, direct=False, environ=environ)
        sock.close()
        thread.join(2)
        self.assertIn(b"CONNECT 104.16.0.1:443", seen.get("request", b""))

    def test_socks5_proxy_is_asked_for_the_candidate_address(self):
        seen = {}
        ready = threading.Event()

        def serve():
            srv = socket.socket()
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            seen["port"] = srv.getsockname()[1]
            ready.set()
            srv.settimeout(2)
            try:
                conn, _addr = srv.accept()
            except OSError:
                srv.close()
                return
            conn.settimeout(2)
            try:
                seen["greeting"] = conn.recv(8)
                conn.sendall(bytes((0x05, 0x00)))
                seen["request"] = conn.recv(64)
                conn.sendall(bytes((0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0)))
            except OSError as error:
                seen["error"] = str(error)
            finally:
                conn.close()
                srv.close()

        thread = threading.Thread(target=serve)
        thread.start()
        self.assertTrue(ready.wait(2))
        environ = {"ALL_PROXY": f"socks5://127.0.0.1:{seen['port']}"}
        sock = open_tcp("104.16.0.1", 443, timeout=2, direct=False, environ=environ)
        sock.close()
        thread.join(2)
        self.assertEqual(seen.get("greeting"), bytes((0x05, 0x01, 0x00)))
        request = seen.get("request", b"")
        self.assertEqual(request[:4], bytes((0x05, 0x01, 0x00, 0x01)))
        self.assertEqual(request[4:8], socket.inet_aton("104.16.0.1"))
        self.assertEqual(int.from_bytes(request[8:10], "big"), 443)

    def test_no_proxy_star_skips_the_proxy(self):
        target = socket.socket()
        target.bind(("127.0.0.1", 0))
        target.listen(1)
        target.settimeout(2)
        port = target.getsockname()[1]
        environ = {
            "HTTP_PROXY": "http://127.0.0.1:1",
            "NO_PROXY": "*",
        }
        try:
            sock = open_tcp("127.0.0.1", port, timeout=1, direct=False, environ=environ)
            incoming, _addr = target.accept()
            sock.close()
            incoming.close()
        finally:
            target.close()


class ScanIntegrationTests(unittest.TestCase):
    def test_jitter_is_shown_and_prefers_the_steadier_address(self):
        csv_text = _csv([("104.21.0.1", 100.0, 0.0), ("104.21.0.2", 110.0, 0.0)])
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=csv_text)
        fixture = Fixture(answers=["y", "n"], spawn=spawn)
        self.addCleanup(fixture.close)
        fixture.session.probes = True
        fixture.session.verify_top_ips = False

        def fake(ip, port, samples=6, timeout=1.5, direct=False, environ=None,
                 connect=None, clock=None):
            fake.direct = direct
            return 25.0 if ip.endswith(".1") else 1.0

        with mock.patch("cfscan.menu.measure_jitter_ms", side_effect=fake):
            code = quick_scan(fixture.session, fixture.config)
        self.assertEqual(code, 0)
        text = fixture.text
        self.assertIn("Jitter", text)
        self.assertLess(text.index("104.21.0.2"), text.index("104.21.0.1"))
        self.assertIn("1.00 ms", text)
        self.assertFalse(fake.direct)

        fixture.out.seek(0)
        fixture.out.truncate(0)
        from cfscan.menu import show_last_results
        show_last_results(fixture.session, fixture.config)
        self.assertIn("Jitter", fixture.text)
        self.assertIn("1.00 ms", fixture.text)

    def test_direct_mode_is_handed_to_the_probe(self):
        csv_text = _csv([("104.21.0.1", 100.0, 0.0)])
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=csv_text)
        fixture = Fixture(answers=["y", "n"], spawn=spawn)
        self.addCleanup(fixture.close)
        fixture.session.probes = True
        fixture.session.direct = True
        fixture.session.verify_top_ips = False
        seen = {}

        def fake(ip, port, samples=6, timeout=1.5, direct=False, environ=None,
                 connect=None, clock=None):
            seen["direct"] = direct
            return 2.0

        with mock.patch("cfscan.menu.measure_jitter_ms", side_effect=fake):
            self.assertEqual(quick_scan(fixture.session, fixture.config), 0)
        self.assertTrue(seen["direct"])
        self.assertIn("ignore proxy", fixture.text)

    def test_download_pass_merges_speed_and_ranks_by_it(self):
        latency = _csv([("104.21.0.1", 100.0, 0.0), ("104.21.0.2", 180.0, 0.0)])
        downloaded = _csv([("104.21.0.1", 100.0, 2.0), ("104.21.0.2", 180.0, 20.0)])
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS,
                              csv_sequence=[latency, downloaded])
        fixture = Fixture(answers=["y", "n"], spawn=spawn)
        self.addCleanup(fixture.close)
        fixture.session.verify_top_ips = False
        profile = fixture.profile()
        profile["download_test"] = True
        profile["download_url"] = "https://speed.cloudflare.com/__down?bytes=200000000"
        profile["download_count"] = 2
        code = quick_scan(fixture.session, fixture.config)
        self.assertEqual(code, 0)
        self.assertEqual(len(spawn.calls), 2)
        second = spawn.calls[1]
        self.assertNotIn("-dd", second)
        self.assertNotIn("-httping", second)
        self.assertEqual(second[second.index("-tp") + 1], "443")
        self.assertIn("-dn", second)
        self.assertIn("speed.cloudflare.com", second[second.index("-url") + 1])
        text = fixture.text
        self.assertIn("Download", text)
        self.assertIn("20.00 MB/s", text)
        self.assertLess(text.index("104.21.0.2"), text.index("104.21.0.1"))
        self.assertIn("-debug", second)
        self.assertNotIn("HTTP 403", text)

    def test_download_pass_warns_when_the_log_shows_http_403(self):
        latency = _csv([("104.21.0.1", 100.0, 0.0)])
        downloaded = _csv([("104.21.0.1", 100.0, 0.0)])
        log = (
            "[调试] IP: 104.21.0.1, 下载测速终止，HTTP 状态码: 403, "
            "测速地址: https://speed.cloudflare.com/__down?bytes=200000000\n"
        )
        spawn = ScriptedSpawn(
            log_sequence=[LOG_SUCCESS, log],
            csv_sequence=[latency, downloaded],
        )
        fixture = Fixture(answers=["y", "n"], spawn=spawn)
        self.addCleanup(fixture.close)
        fixture.session.verify_top_ips = False
        profile = fixture.profile()
        profile["download_test"] = True
        profile["download_url"] = "https://speed.cloudflare.com/__down?bytes=200000000"
        code = quick_scan(fixture.session, fixture.config)
        self.assertEqual(code, 0)
        self.assertIn("-debug", spawn.calls[1])
        text = fixture.text
        self.assertIn("HTTP 403", text)
        self.assertIn("0.00 MB/s", text)
        self.assertIn(DEFAULT_DOWNLOAD_URL, text)
        self.assertIsNotNone(explain_zero_download(
            "HTTP status code: 403\n", {"104.21.0.1": 0.0},
            profile["download_url"]))
        self.assertIsNone(explain_zero_download(
            log, {"104.21.0.1": 12.0}, profile["download_url"]))

    def test_upload_column_uses_the_injected_probe(self):
        csv_text = _csv([("104.21.0.1", 100.0, 0.0)])
        spawn = ScriptedSpawn(log_text=LOG_SUCCESS, csv_text=csv_text)
        fixture = Fixture(answers=["y", "n"], spawn=spawn)
        self.addCleanup(fixture.close)
        fixture.session.probes = True
        fixture.session.verify_top_ips = False
        fixture.profile()["upload_test"] = True
        fixture.profile()["upload_url"] = "https://speed.cloudflare.com/__up"
        fixture.profile()["jitter_test"] = False

        def fake(ip, url, seconds=8, timeout=10, direct=False, environ=None,
                 connect=None, clock=None):
            self.assertEqual(ip, "104.21.0.1")
            self.assertIn("__up", url)
            return 4.5

        with mock.patch("cfscan.menu.measure_upload_mbps", side_effect=fake):
            self.assertEqual(quick_scan(fixture.session, fixture.config), 0)
        self.assertIn("Upload", fixture.text)
        self.assertIn("4.50 MB/s", fixture.text)


class TableTests(unittest.TestCase):
    def test_latency_only_table_does_not_grow_empty_columns(self):
        from cfscan.menu import _render_results_table
        from cfscan.ui import Console
        import io

        stream = io.StringIO()
        console = Console(out=stream, color=False)
        rows = [ScanResult("104.21.0.1", 4, 4, 0.0, 120.0)]
        _render_results_table(console, rows)
        text = stream.getvalue()
        self.assertIn("Latency", text)
        self.assertNotIn("Jitter", text)
        self.assertNotIn("Download", text)
        self.assertNotIn("Upload", text)

    def test_measured_columns_are_labelled(self):
        from cfscan.menu import _render_results_table
        from cfscan.ui import Console
        import io

        stream = io.StringIO()
        console = Console(out=stream, color=False)
        rows = [ScanResult("104.21.0.1", 4, 4, 0.0, 120.0, download_mbps=0.0,
                           jitter_ms=2.5, upload_mbps=1.25)]
        _render_results_table(console, rows, profile={"download_test": True})
        text = stream.getvalue()
        for header in ("Jitter", "Download", "Upload"):
            self.assertIn(header, text)
        self.assertIn("2.50 ms", text)
        self.assertIn("0.00 MB/s", text)
        self.assertIn("1.25 MB/s", text)


if __name__ == "__main__":
    unittest.main()

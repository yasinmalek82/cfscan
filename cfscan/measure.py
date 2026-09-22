"""Jitter and upload measurements that cfst v2.3.5 cannot report.

The scanner's CSV has average latency and, when its download test actually
ran, a download column. It has no jitter column and no upload flag, so both
are measured here, against the address cfst already found, after the scan.

Every probe takes the same ``direct`` choice as :func:`cfscan.runner.scanner_environment`:
``direct=True`` (``cfscan --direct``) opens a socket to that address and ignores
proxy variables, so a test of the real ISP does not ride a VPN proxy exported
in the shell. Otherwise an ``http(s)`` or ``socks5`` proxy in the environment
is used, which is what the scanner's own HTTP client would do.

Nothing here is started through a shell, and nothing is written down except
the numbers the caller asks to store.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import time
import urllib.parse

__all__ = [
    "DEFAULT_DOWNLOAD_URL",
    "DEFAULT_UPLOAD_URL",
    "measure_jitter_ms",
    "measure_upload_mbps",
    "open_tcp",
    "successive_jitter_ms",
]

#: A Cloudflare-cached body large enough for cfst's download test. cfst only
#: records a speed for HTTP 200, and a short body finishes early and shows up
#: as 0.00 MB/s. The profile's own test URL is usually that short body, so the
#: download pass uses this unless the profile names another file.
DEFAULT_DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=200000000"

#: Cloudflare's upload endpoint. The POST is sent through the candidate address
#: (SNI and Host stay this hostname) so the number describes that address.
DEFAULT_UPLOAD_URL = "https://speed.cloudflare.com/__up"

_UPLOAD_CHUNK = bytes(range(256)) * 256  # 64 KiB, not a long run of zeros
_MAX_UPLOAD_POSTS = 100000


def successive_jitter_ms(samples_ms):
    """Mean absolute gap between consecutive round-trip samples, in milliseconds.

    This is the fluctuation a latency number hides: 140 ms every time is not
    the same address as 140 ms that swings between 80 and 200. Fewer than two
    successful samples is "not measured", not a perfect zero.
    """
    if not samples_ms or len(samples_ms) < 2:
        return None
    gaps = [abs(float(samples_ms[index]) - float(samples_ms[index - 1]))
            for index in range(1, len(samples_ms))]
    return sum(gaps) / float(len(gaps))


def measure_jitter_ms(ip, port, samples=6, timeout=1.5, direct=False,
                      environ=None, connect=None, clock=None):
    """Jitter of TCP handshakes to ``ip:port``.

    A TCP connect is the privileged-free stand-in for ping: it needs no raw
    socket, and it times the path to that exact address rather than whatever
    DNS would pick. Failed attempts are skipped, the way a lost ping is.
    ``connect`` and ``clock`` exist so tests never open a real socket.
    """
    connect = connect or open_tcp
    clock = clock or time.perf_counter
    samples = max(2, int(samples))
    rtts = []
    for _ in range(samples):
        sock = None
        started = clock()
        try:
            sock = connect(ip, int(port), timeout, direct=direct, environ=environ)
        except OSError:
            continue
        else:
            rtts.append(max(0.0, (clock() - started) * 1000.0))
        finally:
            _close(sock)
    return successive_jitter_ms(rtts)


def measure_upload_mbps(ip, url, seconds=8, timeout=10, direct=False,
                        environ=None, connect=None, clock=None):
    """Upload throughput to ``url`` with the TCP connection pinned to ``ip``.

    Returns megabytes per second, or ``None`` when nothing could be sent.
    The URL's hostname is the HTTP Host and the TLS name; the socket still
    goes to ``ip``, on the URL's port. That is what makes the number belong
    to one Cloudflare address instead of to whichever edge DNS returns.
    """
    connect = connect or open_tcp
    clock = clock or time.perf_counter
    parts = urllib.parse.urlsplit(str(url or "").strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    host_header = parts.hostname
    if parts.port:
        name = parts.hostname
        if ":" in name:
            name = f"[{name}]"
        host_header = f"{name}:{parts.port}"

    seconds = max(0.1, float(seconds))
    total = 0
    attempts = 0
    started = clock()
    while attempts < _MAX_UPLOAD_POSTS:
        if attempts and (clock() - started) >= seconds:
            break
        sock = None
        try:
            sock = connect(ip, port, timeout, direct=direct, environ=environ)
            if parts.scheme == "https":
                sock = _wrap_tls(sock, parts.hostname, timeout)
            _post_body(sock, path, host_header, _UPLOAD_CHUNK)
        except OSError:
            if total <= 0:
                return None
            break
        else:
            total += len(_UPLOAD_CHUNK)
            attempts += 1
        finally:
            _close(sock)
        if (clock() - started) >= seconds:
            break
    elapsed = clock() - started
    if total <= 0 or elapsed <= 0:
        return None
    return total / elapsed / (1024.0 * 1024.0)


# --------------------------------------------------------------------------
# Connections
# --------------------------------------------------------------------------

def open_tcp(ip, port, timeout, direct=False, environ=None):
    """A TCP socket to ``ip:port``, through a proxy only when that is honest.

    ``direct=True`` never consults proxy variables. Otherwise the first of
    HTTPS_PROXY, HTTP_PROXY and ALL_PROXY is used, unless NO_PROXY says this
    address is excluded. SOCKS and HTTP proxies both end up connected to the
    given address, not to the proxy's own idea of the hostname.
    """
    timeout = float(timeout)
    if not direct and not _no_proxy(ip, environ):
        proxy = _proxy_endpoint(environ)
        if proxy is not None:
            return _connect_through_proxy(proxy, ip, int(port), timeout)
        if _proxy_is_set(environ):
            # A value we cannot speak (an unknown scheme) must not be silently
            # ignored: that would measure the raw ISP while claiming to follow
            # the shell's proxy.
            raise OSError("the proxy URL in the environment is not supported")
    sock = socket.create_connection((str(ip), int(port)), timeout=timeout)
    sock.settimeout(timeout)
    return sock


def _close(sock):
    if sock is None:
        return
    try:
        sock.close()
    except OSError:
        pass


def _wrap_tls(sock, server_hostname, timeout):
    wrapped = ssl.create_default_context().wrap_socket(
        sock, server_hostname=server_hostname)
    wrapped.settimeout(float(timeout))
    return wrapped


def _post_body(sock, path, host, payload):
    header = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: cfscan\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"Content-Length: {len(payload)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("ascii")
    sock.sendall(header)
    sock.sendall(payload)
    peek = _read_some(sock, 512)
    if not peek:
        return
    status = _http_status(peek)
    if status is not None and status >= 400:
        raise OSError(f"upload rejected with HTTP {status}")


def _http_status(peek):
    line = peek.split(b"\r\n", 1)[0]
    parts = line.split()
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/"):
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def _read_some(sock, limit):
    try:
        return sock.recv(limit)
    except OSError:
        return b""


def _recv_exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise OSError("the connection closed early")
        data += chunk
    return data


def _proxy_is_set(environ):
    environ = _environ(environ)
    for key in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY",
                "all_proxy", "ALL_PROXY"):
        if str(environ.get(key) or "").strip():
            return True
    return False


def _environ(environ):
    if environ is None:
        import os
        return os.environ
    return environ


def _no_proxy(ip, environ):
    environ = _environ(environ)
    raw = str(environ.get("NO_PROXY") or environ.get("no_proxy") or "")
    host = str(ip).strip().lower()
    for item in raw.split(","):
        item = item.strip().lower()
        if not item:
            continue
        if item == "*":
            return True
        if item == host:
            return True
        if item.startswith(".") and host.endswith(item):
            return True
    return False


def _proxy_endpoint(environ):
    """``(kind, host, port, username, password)`` or ``None``.

    ``kind`` is ``http``, ``https`` or ``socks5``. Userinfo is kept for the
    handshake and is never included in an error string by the callers.
    """
    environ = _environ(environ)
    raw = ""
    for key in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY",
                "all_proxy", "ALL_PROXY"):
        raw = str(environ.get(key) or "").strip()
        if raw:
            break
    if not raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    parts = urllib.parse.urlsplit(raw)
    scheme = (parts.scheme or "").lower()
    host = parts.hostname
    if not host:
        return None
    if scheme in ("socks5", "socks5h", "socks"):
        kind = "socks5"
        port = parts.port or 1080
    elif scheme == "https":
        kind = "https"
        port = parts.port or 443
    elif scheme == "http":
        kind = "http"
        port = parts.port or 80
    else:
        return None
    username = urllib.parse.unquote(parts.username) if parts.username else None
    password = urllib.parse.unquote(parts.password) if parts.password else None
    return (kind, host, int(port), username, password)


def _connect_through_proxy(proxy, ip, port, timeout):
    kind, host, proxy_port, username, password = proxy
    sock = socket.create_connection((host, proxy_port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        if kind == "https":
            sock = _wrap_tls(sock, host, timeout)
        if kind == "socks5":
            _socks5_connect(sock, ip, port, username, password)
        else:
            _http_connect(sock, ip, port, username, password)
    except BaseException:
        _close(sock)
        raise
    return sock


def _http_connect(sock, ip, port, username, password):
    authority = _authority(ip, port)
    lines = [
        f"CONNECT {authority} HTTP/1.1",
        f"Host: {authority}",
    ]
    if username is not None:
        import base64
        token = base64.b64encode(
            f"{username}:{password or ''}".encode("utf-8")).decode("ascii")
        lines.append(f"Proxy-Authorization: Basic {token}")
    lines.append("")
    lines.append("")
    sock.sendall("\r\n".join(lines).encode("ascii"))
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = sock.recv(512)
        if not chunk:
            break
        head += chunk
        if len(head) > 8192:
            break
    status = _http_status(head)
    if status != 200:
        raise OSError("the proxy refused the tunnel")


def _socks5_connect(sock, ip, port, username, password):
    if username is not None:
        sock.sendall(bytes((0x05, 0x02, 0x00, 0x02)))
    else:
        sock.sendall(bytes((0x05, 0x01, 0x00)))
    version, method = _recv_exact(sock, 2)
    if version != 0x05 or method == 0xFF:
        raise OSError("the proxy refused the handshake")
    if method == 0x02:
        user = (username or "").encode("utf-8")
        secret = (password or "").encode("utf-8")
        if len(user) > 255 or len(secret) > 255:
            raise OSError("the proxy login is too long")
        sock.sendall(bytes((0x01, len(user))) + user + bytes((len(secret),)) + secret)
        status = _recv_exact(sock, 2)
        if status[1] != 0x00:
            raise OSError("the proxy refused the login")
    elif method != 0x00:
        raise OSError("the proxy chose an unsupported login")
    request = bytes((0x05, 0x01, 0x00)) + _socks_address(ip, port)
    sock.sendall(request)
    head = _recv_exact(sock, 4)
    if head[1] != 0x00:
        raise OSError("the proxy could not reach the address")
    atyp = head[3]
    if atyp == 0x01:
        _recv_exact(sock, 6)
    elif atyp == 0x04:
        _recv_exact(sock, 18)
    elif atyp == 0x03:
        length = _recv_exact(sock, 1)[0]
        _recv_exact(sock, length + 2)
    else:
        raise OSError("the proxy returned an unexpected reply")


def _socks_address(ip, port):
    packed_port = int(port).to_bytes(2, "big")
    try:
        parsed = ipaddress.ip_address(str(ip))
    except ValueError:
        host = str(ip).encode("idna")
        return bytes((0x03, len(host))) + host + packed_port
    if parsed.version == 4:
        return bytes((0x01,)) + parsed.packed + packed_port
    return bytes((0x04,)) + parsed.packed + packed_port


def _authority(ip, port):
    text = str(ip)
    if ":" in text:
        return f"[{text}]:{int(port)}"
    return f"{text}:{int(port)}"

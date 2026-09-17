"""Refreshing the Cloudflare IP range files the scanner reads.

The lists that ship with the scanner are a snapshot: the one on this Mac was
written in January 2023, and Cloudflare has published ranges since. A range
that is missing from the file is simply never scanned, so the refresh is not
cosmetic - it decides which part of the edge can be found at all.

Cloudflare publishes both lists as plain text, one CIDR per line:

    https://www.cloudflare.com/ips-v4
    https://www.cloudflare.com/ips-v6

Everything downloaded is parsed with :mod:`ipaddress` before it is allowed near
the scanner: a file the scanner cannot parse aborts a whole run, so a bad
download must be rejected here rather than three minutes into a scan. The
previous file is kept next to the new one as ``<name>.previous``.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import ssl
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

__all__ = [
    "RangeError",
    "IPV4_URL",
    "IPV6_URL",
    "describe_file",
    "fetch_text",
    "install_ranges",
    "read_ranges",
    "merge_ranges",
    "parse_ranges",
    "url_for_version",
]

IPV4_URL = "https://www.cloudflare.com/ips-v4"
IPV6_URL = "https://www.cloudflare.com/ips-v6"

#: A published list is a few hundred bytes. Anything far larger is not the list
#: - a captive portal login page, say - and must not reach the scanner.
MAX_DOWNLOAD_BYTES = 256 * 1024

#: Fewer ranges than this means the answer was not the list either: the IPv4
#: list has held around fifteen entries for years.
MIN_RANGES = 5

DOWNLOAD_TIMEOUT = 20


class RangeError(Exception):
    """Raised when a range list could not be fetched or could not be trusted."""


def url_for_version(version):
    return IPV6_URL if int(version) == 6 else IPV4_URL


def parse_ranges(text, version):
    """Every CIDR range in ``text`` for one IP version, in the order given.

    Raises :class:`RangeError` when the text is not a usable range list, so a
    proxy's error page can never be written over a working file.
    """
    version = int(version)
    ranges = []
    wrong_version = 0
    for raw in str(text or "").splitlines():
        line = raw.strip().lstrip("﻿")
        if not line or line.startswith("#"):
            continue
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError:
            raise RangeError(
                f"The downloaded list is not a list of IP ranges ({line[:40]!r} "
                "is not one), so nothing was changed."
            )
        if network.version != version:
            wrong_version += 1
            continue
        text_form = str(network)
        if text_form not in ranges:
            ranges.append(text_form)
    if wrong_version and not ranges:
        raise RangeError(
            f"The downloaded list holds only IPv{6 if version == 4 else 4} "
            f"ranges, not the IPv{version} list that was asked for."
        )
    if len(ranges) < MIN_RANGES:
        raise RangeError(
            f"The downloaded list holds only {len(ranges)} range(s), which is "
            "too few to be Cloudflare's list. Nothing was changed."
        )
    return ranges


def fetch_text(url, timeout=DOWNLOAD_TIMEOUT, opener=None):
    """Download a published range list as text.

    ``opener`` is the single boundary tests replace; in production it is
    :func:`urllib.request.urlopen`, which honours this shell's proxy variables
    the same way the scanner does.
    """
    opener = opener or urllib.request.urlopen
    request = urllib.request.Request(url, headers={"User-Agent": "cfscan"})
    try:
        with opener(request, timeout=timeout) as response:
            raw = response.read(MAX_DOWNLOAD_BYTES + 1)
    except (urllib.error.URLError, ssl.SSLError, OSError) as error:
        raise RangeError(
            f"The list could not be downloaded from {url}: {error}. Check the "
            "connection (a VPN or proxy in this shell is used as well) and try "
            "again."
        )
    if len(raw) > MAX_DOWNLOAD_BYTES:
        raise RangeError(
            f"The answer from {url} is far larger than a range list, so it is "
            "not one. Nothing was changed."
        )
    return raw.decode("utf-8", errors="replace")


def describe_file(path):
    """``{"path", "exists", "ranges", "modified"}`` for a range file on disk."""
    path = Path(path)
    info = {"path": str(path), "exists": path.exists(), "ranges": 0,
            "modified": None}
    if not info["exists"]:
        return info
    try:
        info["modified"] = datetime.fromtimestamp(path.stat().st_mtime)
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return info
    count = 0
    for raw in text.splitlines():
        line = raw.strip().lstrip("﻿")
        if not line or line.startswith("#"):
            continue
        try:
            ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        count += 1
    info["ranges"] = count
    return info


def merge_ranges(existing, published):
    """The union of the file on disk and the published list, collapsed.

    A published list is not a superset of the file the scanner ships, and
    replacing one with the other loses addresses that demonstrably work.
    Measured on this Mac, both directions happen at once:

    * the shipped file carries ``104.16.0.0/12``, so it covers 104.28-104.31,
      which Cloudflare does not publish - and ``104.28.173.174`` answered a
      real scan from FRA in 140 ms;
    * the published list carries ``172.64.0.0/13``, so it covers 172.68-172.71,
      which the shipped file never had.

    So the two are merged rather than swapped. The cost of keeping a range
    Cloudflare no longer publishes is a little scanning time; the cost of
    dropping a live one is never finding the address behind it.

    Returns ``(ranges, {"before", "published", "after"})`` where each number is
    a count of addresses.
    """
    def networks(items):
        found = []
        for item in items:
            try:
                found.append(ipaddress.ip_network(str(item), strict=False))
            except ValueError:
                continue
        return found

    def size(nets):
        return sum(net.num_addresses for net in nets)

    mine = list(ipaddress.collapse_addresses(networks(existing)))
    theirs = list(ipaddress.collapse_addresses(networks(published)))
    merged = list(ipaddress.collapse_addresses(mine + theirs))
    return ([str(net) for net in merged],
            {"before": size(mine), "published": size(theirs),
             "after": size(merged)})


def read_ranges(path, version):
    """The ranges already on disk, or an empty list when there are none."""
    path = Path(path)
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    found = []
    for raw in text.splitlines():
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if network.version == int(version):
            found.append(str(network))
    return found


def install_ranges(path, ranges):
    """Write a validated range list, keeping the previous file beside it.

    Returns ``(path, backup_path_or_None)``. The file holds ranges and nothing
    else - no header comment - because the scanner parses every line as a range
    and aborts the run on one it cannot read.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = None
    if path.exists():
        backup = Path(str(path) + ".previous")
        try:
            shutil.copy2(str(path), str(backup))
        except OSError:
            backup = None
    payload = "\n".join(str(item) for item in ranges) + "\n"
    temporary = Path(str(path) + ".new")
    try:
        temporary.write_text(payload, encoding="utf-8")
        os.replace(str(temporary), str(path))
    except OSError as error:
        try:
            if temporary.exists():
                temporary.unlink()
        except OSError:  # pragma: no cover - nothing to do about it
            pass
        raise RangeError(f"The range file could not be written: {error}")
    return path, backup

"""Addresses a profile has already proven, so tomorrow costs seconds.

A full scan measures thousands of addresses to end up offering ten. The ten it
offered yesterday are still the best guess for today: Cloudflare's edge does
not reshuffle overnight, and re-measuring ten known addresses is one scanner
run of a few seconds instead of several minutes.

So every address that passes the strict check is remembered on its profile, and
menu 3 offers the list before it asks for an address to type. The record keeps
what the verdict was worth - when it was measured, from which datacentre, at
what latency - because a PASS from last month is a suggestion, not a promise.

Everything here is a pure function over the profile dictionary, so the
behaviour can be tested without a network and without a scanner.
"""

from __future__ import annotations

from datetime import datetime

__all__ = [
    "MAX_FAVOURITES",
    "entries_for",
    "forget",
    "format_age",
    "remember",
    "remember_many",
]

#: Enough to cover a scan's top ten twice over; beyond that the list stops
#: being something a person reads and the oldest entries are dropped.
MAX_FAVOURITES = 20


def _clean(entry):
    """One stored record, or None when it is not usable."""
    if not isinstance(entry, dict):
        return None
    address = str(entry.get("ip") or "").strip()
    if not address:
        return None
    record = {"ip": address}
    for key in ("colo", "when", "domain"):
        value = entry.get(key)
        if value:
            record[key] = str(value)
    for key in ("rtt_ms", "port"):
        value = entry.get(key)
        if value is None:
            continue
        try:
            record[key] = float(value) if key == "rtt_ms" else int(value)
        except (TypeError, ValueError):
            continue
    return record


def entries_for(profile):
    """The stored addresses of a profile, newest first, repaired if needed."""
    cleaned = []
    seen = set()
    for entry in (profile.get("favourites") or []):
        record = _clean(entry)
        if record is None or record["ip"] in seen:
            continue
        seen.add(record["ip"])
        cleaned.append(record)
    return cleaned[:MAX_FAVOURITES]


def remember(profile, ip, rtt_ms=None, colo=None, when=None):
    """Record one proven address on its profile, newest first.

    Re-proving an address moves it back to the front with fresh numbers rather
    than adding a second entry, so the list stays a set of addresses and not a
    log of attempts.
    """
    address = str(ip or "").strip()
    if not address:
        return entries_for(profile)
    record = {
        "ip": address,
        "when": (when or datetime.now()).isoformat(timespec="seconds"),
        "domain": str(profile.get("domain") or ""),
        "port": profile.get("port"),
    }
    if rtt_ms is not None:
        record["rtt_ms"] = rtt_ms
    if colo and str(colo).upper() not in ("N/A", "NA", "-", "UNKNOWN"):
        record["colo"] = str(colo)
    kept = [item for item in entries_for(profile) if item["ip"] != address]
    cleaned = _clean(record)
    profile["favourites"] = ([cleaned] + kept)[:MAX_FAVOURITES]
    return profile["favourites"]


def remember_many(profile, rows, when=None):
    """Record several proven addresses, fastest first.

    ``rows`` are parser results (anything with ``ip``, ``latency_ms`` and
    ``colo``). They are stored slowest first so the fastest ends up at the front
    of the list after each one is pushed on.
    """
    ordered = sorted(rows, key=lambda row: getattr(row, "latency_ms", 0.0) or 0.0,
                     reverse=True)
    for row in ordered:
        remember(profile, getattr(row, "ip", None),
                 rtt_ms=getattr(row, "latency_ms", None),
                 colo=getattr(row, "colo", None), when=when)
    return profile.get("favourites") or []


def forget(profile, ip):
    """Drop one address. Returns True when it was there."""
    address = str(ip or "").strip()
    kept = [item for item in entries_for(profile) if item["ip"] != address]
    removed = len(kept) != len(entries_for(profile))
    profile["favourites"] = kept
    return removed


def format_age(entry, now=None):
    """How old a record is, in words a person reads at a glance."""
    stamp = str(entry.get("when") or "")
    if not stamp:
        return "unknown"
    try:
        measured = datetime.fromisoformat(stamp)
    except ValueError:
        return "unknown"
    seconds = ((now or datetime.now()) - measured).total_seconds()
    if seconds < 0:
        return "just now"
    if seconds < 3600:
        return f"{int(seconds // 60)} min ago"
    if seconds < 86400:
        return f"{int(seconds // 3600)} h ago"
    return f"{int(seconds // 86400)} d ago"

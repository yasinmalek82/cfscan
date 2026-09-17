"""Which Cloudflare datacentres are actually fast on this line.

Geography does not decide this, and assuming it does is expensive. Measured on
one Iranian line across roughly six thousand rows: GYD (Baku, the nearest
datacentre of all) had a median of 232 ms and was the slowest of every European
colo, while FRA - some 3,000 km further away - had a median of 176 ms and the
fastest single address of the whole set at 134 ms. What decides the number is
the route the carrier takes, not the distance.

So the ranking is measured rather than reasoned about, and this module keeps
the running score: every scan contributes one summary row per datacentre, and
the scoreboard turns the accumulated summaries into an order and into a region
filter worth using.

Two things make that honest rather than merely convenient:

* **A score belongs to the line it was measured on.** A scan taken through a
  tunnel describes the tunnel's path, not this machine's own connection, and
  mixing the two produces a ranking that is true of neither. Every entry is
  therefore labelled with the line it came from, and the scoreboard says which
  line it is describing.
* **Filtering narrows what can be learned.** Once a filter is applied, later
  scans only ever see the datacentres it allows, so a colo that becomes good
  can never be discovered again. Entries record the filter they were taken
  under, and the scoreboard says when the picture has stopped refreshing.
"""

from __future__ import annotations

import statistics
import subprocess
from datetime import datetime

__all__ = [
    "MAX_HISTORY",
    "UNKNOWN_LINE",
    "describe_line",
    "entries_for",
    "line_label",
    "observe",
    "recommended_filter",
    "scoreboard",
    "summarise",
]

#: Scans kept per profile. Thirty covers weeks of use and keeps the
#: configuration file small; the oldest entry falls off the end.
MAX_HISTORY = 30

#: How many samples a datacentre needs before its score is treated as a
#: measurement rather than as an anecdote.
MIN_SAMPLES = 20

UNKNOWN_LINE = "unknown"

#: Interface names macOS gives to tunnels. A default route over one of these
#: means every measurement describes the path through that tunnel.
_TUNNEL_PREFIXES = ("utun", "ppp", "ipsec", "tun", "tap", "gpd", "wg")


def _route_default():
    """``(interface, gateway)`` of the default route, or ``(None, None)``."""
    try:
        completed = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None, None
    interface = gateway = None
    for raw in (completed.stdout or "").splitlines():
        line = raw.strip()
        if line.startswith("interface:"):
            interface = line.split(":", 1)[1].strip() or None
        elif line.startswith("gateway:"):
            gateway = line.split(":", 1)[1].strip() or None
    return interface, gateway


def describe_line(interface=None, gateway=None):
    """What this machine's traffic currently leaves through.

    Returns ``{"interface", "gateway", "tunnel", "label"}``. ``tunnel`` is the
    part that matters: when the default route is a tunnel, a scan measures the
    path through it, and the address it recommends is the best address *for
    that tunnel* rather than for this machine's own line.
    """
    if interface is None and gateway is None:
        interface, gateway = _route_default()
    name = str(interface or "")
    tunnel = any(name.startswith(prefix) for prefix in _TUNNEL_PREFIXES)
    return {
        "interface": name or None,
        "gateway": gateway or None,
        "tunnel": bool(tunnel),
        "label": line_label(name, gateway, tunnel),
    }


def line_label(interface, gateway=None, tunnel=None):
    """A short, stable name for one line, used to group measurements.

    Tunnels are grouped by the kind of interface rather than by its number:
    macOS hands out ``utun18`` today and ``utun11`` tomorrow for the same
    tunnel, and a score that resets on every reconnect would be worthless.
    """
    name = str(interface or "")
    if not name:
        return UNKNOWN_LINE
    if tunnel is None:
        tunnel = any(name.startswith(prefix) for prefix in _TUNNEL_PREFIXES)
    if tunnel:
        kind = next((prefix for prefix in _TUNNEL_PREFIXES
                     if name.startswith(prefix)), "tunnel")
        return f"tunnel:{kind}"
    if gateway:
        return f"direct:{name}:{gateway}"
    return f"direct:{name}"


def summarise(results):
    """One row per datacentre for a single scan.

    ``results`` are parser results. Rows whose datacentre is unknown are
    skipped rather than lumped together: the scanner reports no colo at all for
    some recipes, and a bucket of "unknown" would rank nothing.
    """
    buckets = {}
    for row in results:
        colo = str(getattr(row, "colo", "") or "").strip().upper()
        if not colo or colo in ("N/A", "NA", "-", "UNKNOWN"):
            continue
        latency = getattr(row, "latency_ms", None)
        if latency is None:
            continue
        bucket = buckets.setdefault(colo, {"latencies": [], "clean": 0})
        bucket["latencies"].append(float(latency))
        if getattr(row, "is_loss_free", False):
            bucket["clean"] += 1
    summary = {}
    for colo, bucket in buckets.items():
        values = sorted(bucket["latencies"])
        summary[colo] = {
            "n": len(values),
            "min": round(values[0], 2),
            "med": round(statistics.median(values), 2),
            "clean": bucket["clean"],
        }
    return summary


def entries_for(profile):
    """The stored scan summaries of a profile, oldest first, repaired."""
    kept = []
    for entry in (profile.get("edge_history") or []):
        if not isinstance(entry, dict):
            continue
        colos = entry.get("colos")
        if not isinstance(colos, dict) or not colos:
            continue
        clean = {}
        for colo, stats in colos.items():
            if not isinstance(stats, dict):
                continue
            try:
                clean[str(colo).upper()] = {
                    "n": int(stats.get("n") or 0),
                    "min": float(stats.get("min")),
                    "med": float(stats.get("med")),
                    "clean": int(stats.get("clean") or 0),
                }
            except (TypeError, ValueError):
                continue
        if not clean:
            continue
        kept.append({
            "when": str(entry.get("when") or ""),
            "line": str(entry.get("line") or UNKNOWN_LINE),
            "filter": str(entry.get("filter") or ""),
            "colos": clean,
        })
    return kept[-MAX_HISTORY:]


def observe(profile, results, line=None, colo_filter=None, when=None):
    """Record what one scan saw. Returns the summary that was stored.

    An empty summary is not stored: a scan that learned nothing about any
    datacentre should not push a useful entry off the end of the history.
    """
    summary = summarise(results)
    if not summary:
        return {}
    entry = {
        "when": (when or datetime.now()).isoformat(timespec="seconds"),
        "line": str((line or {}).get("label") if isinstance(line, dict)
                    else line or UNKNOWN_LINE),
        "filter": str(colo_filter or ""),
        "colos": summary,
    }
    history = entries_for(profile)
    history.append(entry)
    profile["edge_history"] = history[-MAX_HISTORY:]
    return summary


def scoreboard(profile, line=None, window=None):
    """Rank the datacentres this profile has measured, best first.

    ``line`` limits the ranking to one line's measurements, which is the whole
    point of recording the line in the first place. ``window`` limits it to the
    most recent N scans, for a line whose quality has changed.

    Returns ``(rows, meta)``. Each row carries ``colo``, ``best`` (the fastest
    address ever seen there), ``typical`` (the median of the per-scan medians),
    ``samples``, ``scans``, ``clean`` (the share of addresses that lost no
    packets) and ``trusted`` (whether there are enough samples to mean
    something). ``meta`` says which line and how much of the history was used,
    and whether recent scans were filtered.
    """
    history = entries_for(profile)
    if line:
        history = [entry for entry in history if entry["line"] == line]
    if window:
        history = history[-int(window):]

    merged = {}
    for entry in history:
        for colo, stats in entry["colos"].items():
            row = merged.setdefault(colo, {"colo": colo, "mins": [], "meds": [],
                                           "samples": 0, "scans": 0, "clean": 0})
            row["mins"].append(stats["min"])
            row["meds"].append(stats["med"])
            row["samples"] += stats["n"]
            row["scans"] += 1
            row["clean"] += stats["clean"]

    rows = []
    for row in merged.values():
        samples = row["samples"]
        rows.append({
            "colo": row["colo"],
            "best": min(row["mins"]),
            # A median of per-scan medians, not of every address: the per-scan
            # figure is what the history keeps, and it resists one bad scan.
            "typical": round(statistics.median(row["meds"]), 1),
            "samples": samples,
            "scans": row["scans"],
            "clean": (row["clean"] / samples) if samples else 0.0,
            "trusted": samples >= MIN_SAMPLES,
        })
    # Untrusted rows sort last whatever their number says: two lucky addresses
    # must not outrank a datacentre measured a thousand times.
    rows.sort(key=lambda item: (not item["trusted"], item["typical"], item["colo"]))

    recent = history[-5:]
    filtered = [entry for entry in recent if entry["filter"]]
    meta = {
        "line": line or "all lines",
        "scans": len(history),
        "colos": len(rows),
        # True when every recent scan was filtered, so the picture can no longer
        # refresh: the datacentres left out are simply never measured again.
        "stale": bool(recent) and len(filtered) == len(recent),
        "recent_filter": filtered[-1]["filter"] if filtered else "",
        "lines": sorted({entry["line"] for entry in entries_for(profile)}),
    }
    return rows, meta


def recommended_filter(rows, count=4, margin=1.35):
    """The datacentres worth keeping, as a region filter.

    Only trusted rows are offered. The list stops early when a datacentre is
    much slower than the best one - ``margin`` times its typical latency -
    because padding the filter with somewhere slow only spends scanning time on
    addresses that will not be chosen.
    """
    trusted = [row for row in rows if row["trusted"]]
    if not trusted:
        return []
    ceiling = trusted[0]["typical"] * float(margin)
    chosen = [row["colo"] for row in trusted[:int(count)]
              if row["typical"] <= ceiling]
    return chosen

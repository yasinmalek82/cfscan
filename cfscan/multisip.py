"""Joining the carrier rounds into an answer.

Input: the stored rounds of one multi-carrier session (see
:mod:`cfscan.vantages`). Output: which addresses work everywhere, which are
best per carrier, and - when nothing works everywhere - which address covers the
most carriers.

Everything here is a pure function over the stored measurements, so the report
can be rebuilt later from the session file and can be tested without a network.
Ranking a "works everywhere" list by **worst case** latency (min-max) is
deliberate: an address that is 150 ms on one carrier and 600 ms on another is
worse than one that is 200 ms on both, even though its average is lower.
"""

from __future__ import annotations

__all__ = [
    "best_per_line",
    "common_rows",
    "coverage_rows",
    "join_rounds",
    "recommendation",
    "report",
    "worst_case_rtt",
]

from .vantages import PASS


def _rtt_of(entry):
    try:
        return float(entry.get("rtt_ms"))
    except (TypeError, ValueError, AttributeError):
        return None


def join_rounds(session):
    """One row per address measured in the session, with a per-carrier column."""
    rounds = list(session.get("rounds") or [])
    total = len(rounds)
    rows = {}
    order = []
    for record in rounds:
        isp = str(record.get("isp") or "?")
        for entry in record.get("verified") or []:
            if not isinstance(entry, dict):
                continue
            address = str(entry.get("ip") or "")
            if not address:
                continue
            if address not in rows:
                rows[address] = {"ip": address, "per_isp": {}}
                order.append(address)
            rows[address]["per_isp"][isp] = {
                "verdict": str(entry.get("verdict") or "").upper(),
                "rtt_ms": _rtt_of(entry),
                "loss": entry.get("loss"),
                "colo": entry.get("colo"),
            }

    joined = []
    for address in order:
        row = rows[address]
        passing = [name for name, entry in row["per_isp"].items()
                   if entry["verdict"] == PASS]
        passing_rtts = [row["per_isp"][name]["rtt_ms"] for name in passing
                        if row["per_isp"][name]["rtt_ms"] is not None]
        all_rtts = [entry["rtt_ms"] for entry in row["per_isp"].values()
                    if entry["rtt_ms"] is not None]
        row["passing"] = passing
        row["covered"] = len(passing)
        row["total"] = total
        row["worst_rtt"] = max(passing_rtts) if passing_rtts else (
            max(all_rtts) if all_rtts else None)
        row["best_rtt"] = min(passing_rtts) if passing_rtts else (
            min(all_rtts) if all_rtts else None)
        if len(passing_rtts) > 1:
            row["spread"] = max(passing_rtts) - min(passing_rtts)
        else:
            row["spread"] = 0.0 if passing_rtts else None
        joined.append(row)
    return joined


def worst_case_rtt(row):
    value = row.get("worst_rtt")
    return value if value is not None else float("inf")


def _common_key(row):
    return (worst_case_rtt(row), row.get("spread") or 0.0, row["ip"])


def common_rows(rows, minimum=None):
    """Addresses that passed on every carrier, best worst-case first."""
    if not rows:
        return []
    total = minimum if minimum is not None else rows[0].get("total") or 0
    if total <= 0:
        return []
    return sorted([row for row in rows if row.get("covered") == total],
                  key=_common_key)


def coverage_rows(rows, minimum=None):
    """Addresses that passed somewhere but not everywhere.

    Sorted by how many carriers they cover (more is better), then by worst-case
    latency. This is what to show when the "works everywhere" list is empty.
    """
    if not rows:
        return []
    total = minimum if minimum is not None else rows[0].get("total") or 0
    partial = [row for row in rows
               if 0 < (row.get("covered") or 0) < max(total, 1)]
    return sorted(partial, key=lambda row: (-(row.get("covered") or 0),
                                            worst_case_rtt(row),
                                            row["ip"]))


def best_per_line(session):
    """The fastest verified address of each carrier, in measurement order."""
    best = []
    for record in session.get("rounds") or []:
        isp = str(record.get("isp") or "?")
        entries = [entry for entry in record.get("verified") or []
                   if isinstance(entry, dict) and entry.get("ip")]
        if not entries:
            best.append({"isp": isp, "ip": None, "reason": "nothing was verified"})
            continue
        passing = [entry for entry in entries
                   if str(entry.get("verdict") or "").upper() == PASS
                   and _rtt_of(entry) is not None]
        pool = passing or [entry for entry in entries if _rtt_of(entry) is not None]
        if not pool:
            best.append({"isp": isp, "ip": None, "reason": "no measurement"})
            continue
        winner = min(pool, key=lambda entry: (_rtt_of(entry), str(entry.get("ip"))))
        best.append({
            "isp": isp,
            "ip": str(winner.get("ip")),
            "rtt_ms": _rtt_of(winner),
            "loss": winner.get("loss"),
            "colo": winner.get("colo"),
            "verdict": str(winner.get("verdict") or "").upper(),
            "verified": bool(passing),
        })
    return best


def recommendation(session, rows=None, common=None, coverage=None):
    """What to actually use, and why. ``None`` when nothing passed anywhere.

    An address that passed on every measured carrier is the answer whenever one
    exists. With a single carrier measured - the state after one round of the
    wizard - that list *is* that carrier's passing addresses, so the wording says
    so instead of claiming it works on "all 1" carrier.
    """
    rows = join_rounds(session) if rows is None else rows
    total = len(session.get("rounds") or [])
    common = common_rows(rows, total) if common is None else common
    if common:
        best = common[0]
        if total < 2:
            reason = (f"verified on the only carrier measured; worst case "
                      f"{worst_case_rtt(best):.0f} ms")
        else:
            reason = (f"passed on all {total} carriers; worst case "
                      f"{worst_case_rtt(best):.0f} ms")
        return {"ip": best["ip"], "kind": "common", "reason": reason,
                "row": best}
    coverage = coverage_rows(rows, total) if coverage is None else coverage
    if coverage:
        best = coverage[0]
        return {
            "ip": best["ip"],
            "kind": "coverage",
            "reason": (f"no address passed on every carrier; this one passed on "
                       f"{best['covered']} of {total} ({', '.join(best['passing'])})"),
            "row": best,
        }
    # No address passed anywhere. best_per_line() still knows which carrier
    # measured something, but recommending an address that failed its strict
    # check would be worse than recommending nothing.
    return None


def report(session):
    """Everything the report screen needs, computed in one place."""
    rounds = list(session.get("rounds") or [])
    total = len(rounds)
    rows = join_rounds(session)
    common = common_rows(rows, total)
    coverage = coverage_rows(rows, total)
    return {
        "session": session,
        "total": total,
        "isps": [str(record.get("isp") or "?") for record in rounds],
        "rows": rows,
        "common": common,
        "coverage": coverage,
        "best_per_line": best_per_line(session),
        "recommendation": recommendation(session, rows=rows, common=common,
                                         coverage=coverage),
        "verified_addresses": len(rows),
    }

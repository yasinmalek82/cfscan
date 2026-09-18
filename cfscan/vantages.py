"""Per-carrier round records and the session that ties the rounds together.

A multi-carrier run has to survive a hotspot dropping or the laptop sleeping,
and the final report is built from stored measurements rather than from what is
still on screen. Every round is therefore appended to a session file as soon as
it finishes::

    ~/Documents/Cloudflare Scanner Results/multi-isp/<domain>/<session>.json

The file is written atomically (the same helper the configuration uses), so an
interrupted round can never leave a half written record behind.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .profiles import atomic_write_json, profile_slug

__all__ = [
    "SESSION_VERSION",
    "add_round",
    "drop_round",
    "isp_names",
    "latest_session",
    "list_sessions",
    "load_session",
    "measured_ip_list",
    "new_session",
    "replace_round",
    "round_for",
    "save_session",
    "session_slug",
    "sessions_dir",
    "verdict_of",
]

SESSION_VERSION = 1

PASS = "PASS"
FAIL = "FAIL"
DEAD = "DEAD"


def verdict_of(row, attempts):
    """The verdict for one measured address: PASS, FAIL or DEAD.

    PASS means every one of the ``attempts`` was answered with no loss at all.
    DEAD means the scanner wrote no row for it, so nothing came back.
    """
    if row is None:
        return DEAD
    received = int(getattr(row, "received", 0) or 0)
    sent = int(getattr(row, "sent", 0) or 0)
    loss = float(getattr(row, "loss", 1.0) or 0.0)
    if received >= attempts and sent >= attempts and loss <= 0.0:
        return PASS
    return FAIL


def new_session(profile, domain, port, pool_file, pool_sha, isps, when=None,
                scheme=None, http_status=None, pool_seed=None):
    """A session record: the recipe, the pool and the carriers to measure.

    The pool seed is kept here (and not in the pool file, which has to stay a
    plain address list for the scanner) so the very same candidates can be
    rebuilt later.
    """
    when = when or datetime.now()
    return {
        "version": SESSION_VERSION,
        "domain": str(domain),
        "port": int(port),
        "scheme": scheme or str(profile.get("scheme") or "https"),
        "http_status": (http_status if http_status is not None
                        else profile.get("http_status")),
        "profile": str(profile.get("name") or ""),
        "pool_file": str(pool_file) if pool_file else None,
        "pool_sha256": str(pool_sha or ""),
        "pool_seed": pool_seed if pool_seed is None else int(pool_seed),
        "isps": [str(item) for item in isps],
        "created": when.isoformat(timespec="seconds"),
        "rounds": [],
    }


def add_round(session, isp, verified, csv_path=None, log_path=None,
              access=None, when=None, scanned=0, replace=False):
    """Record one finished round. Returns the round record.

    ``replace=True`` puts the round where the same carrier's earlier round was,
    so re-measuring a carrier neither adds a second column nor reshuffles the
    order the carriers were first measured in.
    """
    when = when or datetime.now()
    record = {
        "isp": str(isp),
        "access": str(access) if access else None,
        "when": when.isoformat(timespec="seconds"),
        "scanned": int(scanned or 0),
        "csv": str(csv_path) if csv_path else None,
        "log": str(log_path) if log_path else None,
        "verified": list(verified or []),
    }
    if replace:
        replace_round(session, isp, record)
    else:
        session.setdefault("rounds", []).append(record)
    return record


def round_for(session, isp):
    """The round recorded for one carrier, or ``None``."""
    wanted = str(isp)
    for record in session.get("rounds") or []:
        if str(record.get("isp")) == wanted:
            return record
    return None


def drop_round(session, isp):
    """Remove one carrier's round, keeping the order of the others.

    Used before a carrier is measured again: one carrier gets one round, so a
    retry replaces the earlier measurement instead of showing up as a second
    column with the same name.
    """
    wanted = str(isp)
    rounds = session.get("rounds") or []
    for index, record in enumerate(rounds):
        if str(record.get("isp")) == wanted:
            return rounds.pop(index)
    return None


def replace_round(session, isp, record):
    """Put a newer measurement of a carrier where its old round was.

    The position is kept on purpose: the report columns follow the order the
    carriers were first measured in, so replacing a round does not reshuffle
    the table. Returns ``True`` when an earlier round was replaced.
    """
    wanted = str(isp)
    rounds = session.setdefault("rounds", [])
    for index, existing in enumerate(rounds):
        if str(existing.get("isp")) == wanted:
            rounds[index] = record
            return True
    rounds.append(record)
    return False


def isp_names(session):
    """The carriers measured so far, in the order they were measured."""
    return [str(item.get("isp")) for item in session.get("rounds") or []]


def measured_ip_list(session):
    """Every address that was verified in any round, in first-seen order.

    The next round verifies this list again, which is what makes the shared
    answers comparable: an address only counts as common when it was proven on
    each carrier.
    """
    seen = []
    for record in session.get("rounds") or []:
        for row in record.get("verified") or []:
            address = str((row or {}).get("ip") or "")
            if address and address not in seen:
                seen.append(address)
    return seen


def session_slug(domain, when=None):
    """``example-com-20260916-124530`` for a session.

    Seconds are part of the name so two sessions for one domain never land in
    the same file, even when they are started within the same minute.
    """
    label = profile_slug(str(domain) or "multi-isp")
    return f"{label}-{(when or datetime.now()).strftime('%Y%m%d-%H%M%S')}"


def sessions_dir(results_dir, domain=None):
    """Where multi-carrier sessions live (one folder per domain)."""
    base = Path(results_dir) / "multi-isp"
    if domain:
        base = base / profile_slug(str(domain))
    return base


def list_sessions(results_dir, domain=None):
    """Every stored session for a domain, newest last."""
    directory = sessions_dir(results_dir, domain) if domain else sessions_dir(results_dir)
    if not directory.is_dir():
        return []
    found = [item for item in directory.rglob("*.json") if item.is_file()]
    return sorted(found, key=lambda item: item.stat().st_mtime_ns)


def latest_session(results_dir, domain=None):
    """The newest session file, or None."""
    found = list_sessions(results_dir, domain)
    return found[-1] if found else None


def _free_path(directory, slug):
    """A session file name that is not taken by another session.

    The slug carries seconds, and two sessions for one domain can still be
    created inside the same second (a scripted round, or a round that is
    re-measured right away). Without this check the second session would land on
    the first one's file and destroy it silently, so a taken name gets a
    counter instead.
    """
    candidate = directory / f"{slug}.json"
    index = 2
    while candidate.exists():
        candidate = directory / f"{slug}-{index}.json"
        index += 1
    return candidate


def save_session(results_dir, session):
    """Write the session atomically, creating its folder when needed."""
    directory = sessions_dir(results_dir, session.get("domain"))
    directory.mkdir(parents=True, exist_ok=True)
    path = session.get("path")
    if path:
        path = Path(path)
    else:
        path = _free_path(directory,
                          session_slug(session.get("domain")))
    atomic_write_json(path, session)
    session["path"] = str(path)
    return path


def load_session(path):
    """Read a session file back."""
    import json

    with open(str(path), "r", encoding="utf-8") as handle:
        data = json.load(handle)
    data.setdefault("rounds", [])
    data["path"] = str(path)
    return data

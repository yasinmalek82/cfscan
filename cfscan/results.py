"""Result files: timestamped CSV names, the latest pointer and Finder.

Results live in::

    ~/Documents/Cloudflare Scanner Results/

Every file gets a fresh timestamped name, and the name is checked against the
directory before it is used, so an existing result is never overwritten. A
small pointer to the newest result is kept in the configuration file so
``cfscan`` can reopen it later.
"""

from __future__ import annotations

import subprocess
from datetime import datetime
from pathlib import Path

from .profiles import profile_slug, save_config

__all__ = [
    "ResultStore",
    "ensure_dir",
    "latest_result_path",
    "new_result_path",
    "open_in_finder",
    "timestamp_label",
]


def ensure_dir(path):
    """Create a directory (and its parents) if it does not exist yet."""
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def timestamp_label(when=None):
    """A filesystem friendly timestamp such as ``20260915-163501``."""
    return (when or datetime.now()).strftime("%Y%m%d-%H%M%S")


def _sequence_of(filename):
    """Sort helper: ``name-2.csv`` comes after ``name.csv`` when mtimes tie.

    Result names end in ``YYYYMMDD-HHMMSS``. That clock fragment is not a
    collision index. Only the extra ``-2``, ``-3``, ... added when that name
    was already taken counts, so a same-second file sorts after the first one.
    """
    stem = filename[:-4] if str(filename).lower().endswith(".csv") else str(filename)
    parts = stem.split("-")
    if (len(parts) >= 2
            and len(parts[-1]) == 6 and parts[-1].isdigit()
            and len(parts[-2]) == 8 and parts[-2].isdigit()):
        return 1
    if (len(parts) >= 3
            and parts[-1].isdigit()
            and len(parts[-2]) == 6 and parts[-2].isdigit()
            and len(parts[-3]) == 8 and parts[-3].isdigit()):
        return int(parts[-1])
    if len(parts) >= 2 and parts[-1].isdigit():
        return int(parts[-1])
    return 1


def _unique_path(directory, filename):
    """Return a path in ``directory`` that does not exist yet."""
    directory = Path(directory)
    candidate = directory / filename
    if not candidate.exists():
        return candidate
    if filename.lower().endswith(".csv"):
        stem, suffix = filename[:-4], ".csv"
    else:
        stem, suffix = filename, ""
    index = 2
    while True:
        candidate = directory / f"{stem}-{index}{suffix}"
        if not candidate.exists():
            return candidate
        index += 1


def new_result_path(results_dir, label, when=None):
    """A never-used result path for a label, inside ``results_dir``."""
    directory = ensure_dir(results_dir)
    safe_label = profile_slug(label)
    filename = f"cfscan-{safe_label}-{timestamp_label(when)}.csv"
    return _unique_path(directory, filename)


def latest_result_path(config, paths):
    """The newest known result file, or ``None`` when there is none."""
    pointer = (config or {}).get("last_result") or {}
    stored = pointer.get("csv")
    if stored and Path(stored).exists():
        return Path(stored)

    directory = Path(paths.results_dir)
    if not directory.is_dir():
        return None
    candidates = [item for item in directory.glob("*.csv") if item.is_file()]
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda item: (item.stat().st_mtime_ns, _sequence_of(item.name)),
    )


def open_in_finder(path):
    """Open a file or folder in Finder. Returns True on success."""
    try:
        completed = subprocess.run(
            ["open", str(path)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return False
    return getattr(completed, "returncode", 1) == 0


class ResultStore(object):
    """All result-file bookkeeping for one set of paths."""

    def __init__(self, paths):
        self.paths = paths

    @property
    def directory(self):
        return Path(self.paths.results_dir)

    def new_csv(self, label, when=None):
        """A fresh timestamped CSV path (never overwrites an existing file)."""
        return new_result_path(self.directory, label, when=when)

    def named_csv(self, filename, when=None):
        """A CSV path for a user supplied filename, made unique if needed."""
        directory = ensure_dir(self.directory)
        return _unique_path(directory, str(filename))

    def log_for(self, csv_path):
        """The raw scanner log that belongs to a result file."""
        csv_path = Path(csv_path)
        return csv_path.with_suffix(".log")

    def record_latest(self, config, csv_path, profile_name, recommended_ip=None,
                      when=None):
        """Save a pointer to the newest result inside the configuration."""
        csv_path = Path(csv_path)
        log_path = self.log_for(csv_path)
        config["last_result"] = {
            "csv": str(csv_path),
            "log": str(log_path) if log_path.exists() else None,
            "profile": profile_name,
            "recommended_ip": recommended_ip,
            "when": (when or datetime.now()).isoformat(timespec="seconds"),
        }
        save_config(self.paths, config)
        return config["last_result"]

    def latest(self, config):
        return latest_result_path(config, self.paths)

"""Configuration storage: profiles, paths and atomic writes.

Everything cfscan remembers lives in one JSON file::

    ~/.config/cfscan/config.json

The file is only ever written atomically (write to a temporary file in the
same directory, then ``os.replace``), it is created with mode 0600, and
unknown keys written by future versions are preserved untouched.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from pathlib import Path

__all__ = [
    "CONFIG_VERSION",
    "DEFAULT_CFST_PATH",
    "DEFAULT_DOMAIN",
    "DEFAULT_IPV4_FILE",
    "DEFAULT_IPV6_FILE",
    "DEFAULT_PROFILE_KEY",
    "PLACEHOLDER_DOMAINS",
    "is_placeholder",
    "DEFAULT_RECOMMENDED_IP",
    "Paths",
    "UnknownProfile",
    "atomic_write_json",
    "default_profile",
    "delete_profile",
    "find_cfst",
    "get_active",
    "ip_file_for",
    "load_config",
    "new_config",
    "profile_slug",
    "save_config",
    "set_active",
    "set_ip_version",
    "upsert_profile",
]

CONFIG_VERSION = 1

#: The profile a fresh installation starts with. It is a placeholder on purpose:
#: a scan measures thousands of addresses against whatever domain is configured,
#: so shipping a real one would point every installation of this tool at someone
#: else's server. cfscan says the profile is a placeholder until it is changed.
DEFAULT_DOMAIN = "example.com"
DEFAULT_PORT = 443
DEFAULT_HTTP_STATUS = 400
DEFAULT_RECOMMENDED_IP = None
DEFAULT_PROFILE_KEY = "example"

#: Domains that mean "nothing has been configured yet" rather than a target.
PLACEHOLDER_DOMAINS = ("example.com", "example.org", "example.net")

DEFAULT_CFST_PATH = "/opt/homebrew/bin/cfst"
DEFAULT_SHARE_DIR = str(Path.home() / ".local" / "share" / "cloudflare-speedtest")
DEFAULT_IPV4_FILE = str(Path(DEFAULT_SHARE_DIR) / "ip.txt")
DEFAULT_IPV6_FILE = str(Path(DEFAULT_SHARE_DIR) / "ipv6.txt")

_RESULTS_FOLDER_NAME = "Cloudflare Scanner Results"


class UnknownProfile(KeyError):
    """Raised when a profile name does not exist in the configuration."""

    def __str__(self):
        # KeyError would add quotes around the message; users should never see
        # Python's repr formatting in an error line.
        if not self.args:
            return "That profile does not exist."
        return str(self.args[0])


class Paths(object):
    """Where cfscan keeps its files."""

    def __init__(self, home=None):
        self.home = Path(home).expanduser() if home else Path.home()
        self.config_dir = self.home / ".config" / "cfscan"
        self.config_file = self.config_dir / "config.json"
        self.results_dir = self.home / "Documents" / _RESULTS_FOLDER_NAME


def find_cfst():
    """Return the path of the installed cfst binary."""
    found = shutil.which("cfst")
    if found:
        return found
    if os.path.exists(DEFAULT_CFST_PATH):
        return DEFAULT_CFST_PATH
    return DEFAULT_CFST_PATH


def default_profile(cfst_path=None):
    """The profile described in the project specification."""
    return {
        "name": DEFAULT_DOMAIN,
        "domain": DEFAULT_DOMAIN,
        "port": DEFAULT_PORT,
        # "httping" performs an HTTP(S) request, "tcp" is a plain TCP connect.
        "mode": "httping",
        # Scheme used to build the test URL. "https" performs a real TLS request;
        # "http" sends a plain request to the HTTPS port instead.
        "scheme": "https",
        "url_path": "/",
        "http_status": DEFAULT_HTTP_STATUS,
        # Cloudflare datacentres to keep, as IATA codes ("FRA,AMS"). Empty means
        # the whole edge, which is what a first scan should measure.
        "colo": "",
        "ip_version": 4,
        "ip_file": DEFAULT_IPV4_FILE,
        "ipv6_file": DEFAULT_IPV6_FILE,
        "attempts": 4,
        "concurrency": 200,
        "max_latency_ms": 1000,
        "max_loss": 0.25,
        "results_limit": 20,
        # How many of the best addresses cfscan shows and verifies. This is the
        # number the user actually sees; "results_limit" only reaches the
        # scanner's own console output, which cfscan hides.
        "top_ips": 10,
        "download_test": False,
        "recommended_ip": DEFAULT_RECOMMENDED_IP,
        "verify_attempts": 20,
        # Addresses this profile has proven, newest first (see menu 3).
        "favourites": [],
        # One summary per scan of which datacentres answered and how fast, used
        # to rank the edge locations from measurement rather than from a map
        # (see menu 12).
        "edge_history": [],
    }


def new_config(cfst_path=None):
    """A fresh configuration containing only the built in default profile."""
    return {
        "version": CONFIG_VERSION,
        "cfst_path": cfst_path or find_cfst(),
        "active_profile": DEFAULT_PROFILE_KEY,
        "profiles": {DEFAULT_PROFILE_KEY: default_profile()},
    }


def is_placeholder(profile):
    """True while a profile still points at the shipped placeholder domain.

    Everything downstream - the menu header, the scan flows - uses this to ask
    the user for their own domain instead of measuring ``example.com``, which
    no Cloudflare edge serves for them.
    """
    domain = str((profile or {}).get("domain") or "").strip().lower()
    return domain in PLACEHOLDER_DOMAINS


def ip_file_for(profile):
    """Return the IP range file matching the profile's IP version."""
    if int(profile.get("ip_version", 4)) == 6:
        return str(profile.get("ipv6_file") or DEFAULT_IPV6_FILE)
    return str(profile.get("ip_file") or DEFAULT_IPV4_FILE)


def set_ip_version(profile, version):
    """Switch a profile between IPv4 and IPv6, keeping both range files."""
    version = int(version)
    ipv4_file = profile.get("ipv4_file") or profile.get("ip_file") or DEFAULT_IPV4_FILE
    ipv6_file = profile.get("ipv6_file") or DEFAULT_IPV6_FILE
    profile["ipv4_file"] = ipv4_file
    profile["ipv6_file"] = ipv6_file
    profile["ip_version"] = version
    # The active range file is mirrored into "ip_file" so the stored profile
    # always shows which file the next scan will use.
    profile["ip_file"] = ipv6_file if version == 6 else ipv4_file
    return profile


# --------------------------------------------------------------------------
# Atomic writes
# --------------------------------------------------------------------------

def atomic_write_json(path, data):
    """Write JSON atomically, preserving the previous file if anything fails."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2, sort_keys=False) + "\n"
    handle = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(path.parent),
        prefix=path.name + ".",
        suffix=".tmp",
        delete=False,
    )
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(str(temporary), 0o600)
        os.replace(str(temporary), str(path))
    except BaseException:
        try:
            if temporary.exists():
                temporary.unlink()
        except OSError:
            pass
        raise
    return path


# --------------------------------------------------------------------------
# Loading / saving
# --------------------------------------------------------------------------

def _is_mapping(value):
    return isinstance(value, dict)


def _merge_profile(stored):
    """Fill in anything a stored profile is missing, without dropping extras."""
    merged = default_profile()
    merged.update(stored or {})
    # Re-apply the type/range fixes for values users can edit by hand.
    try:
        merged["port"] = int(merged.get("port", DEFAULT_PORT))
    except (TypeError, ValueError):
        merged["port"] = DEFAULT_PORT
    try:
        merged["ip_version"] = 6 if int(merged.get("ip_version", 4)) == 6 else 4
    except (TypeError, ValueError):
        merged["ip_version"] = 4
    if merged.get("mode") not in ("httping", "tcp"):
        merged["mode"] = "httping"
    if merged.get("scheme") not in ("http", "https"):
        merged["scheme"] = "https"
    if not isinstance(merged.get("colo"), str):
        merged["colo"] = ""
    if not isinstance(merged.get("favourites"), list):
        merged["favourites"] = []
    if not isinstance(merged.get("edge_history"), list):
        merged["edge_history"] = []
    return merged


def _backup_corrupt(path):
    index = 0
    while True:
        index += 1
        candidate = Path(str(path) + f".corrupt-{index}")
        if not candidate.exists():
            break
    try:
        shutil.copy2(str(path), str(candidate))
    except OSError:
        pass
    return candidate


def load_config(paths):
    """Load the configuration, creating or repairing it when necessary."""
    config_path = Path(paths.config_file)
    if not config_path.exists():
        config = new_config()
        save_config(paths, config)
        return config

    try:
        raw = config_path.read_text(encoding="utf-8")
    except OSError:
        return new_config()

    try:
        stored = json.loads(raw) if raw.strip() else {}
    except ValueError:
        _backup_corrupt(config_path)
        config = new_config()
        save_config(paths, config)
        return config

    if not _is_mapping(stored):
        _backup_corrupt(config_path)
        config = new_config()
        save_config(paths, config)
        return config

    config = stored
    config.setdefault("version", CONFIG_VERSION)
    config.setdefault("cfst_path", find_cfst())

    profiles = config.get("profiles")
    if not _is_mapping(profiles):
        profiles = {}
    repaired = {}
    for name, profile in profiles.items():
        if not _is_mapping(profile):
            continue
        repaired[str(name)] = _merge_profile(profile)
    # At least one profile always exists, so a broken file can never lock the
    # user out of the tool. It is only re-created when nothing else is left:
    # re-adding it beside the user's own profiles would resurrect a profile they
    # deleted on purpose, every single time the configuration was read.
    if not repaired:
        repaired[DEFAULT_PROFILE_KEY] = default_profile()
    config["profiles"] = repaired

    active = config.get("active_profile")
    if active not in repaired:
        config["active_profile"] = DEFAULT_PROFILE_KEY
    return config


def save_config(paths, config):
    """Persist the configuration atomically."""
    return atomic_write_json(Path(paths.config_file), config)


# --------------------------------------------------------------------------
# Profiles
# --------------------------------------------------------------------------

def get_active(config):
    """Return ``(name, profile)`` for the active profile."""
    name = config.get("active_profile")
    profiles = config.get("profiles", {})
    if name not in profiles:
        raise UnknownProfile(f"Unknown profile '{name}'. "
                             f"Available profiles: {', '.join(profiles) or 'none'}.")
    return name, profiles[name]


def set_active(config, name):
    """Make ``name`` the active profile."""
    if name not in config.get("profiles", {}):
        raise UnknownProfile(f"Unknown profile '{name}'. "
                             f"Available profiles: "
                             f"{', '.join(config.get('profiles') or {}) or 'none'}.")
    config["active_profile"] = name
    return name


def upsert_profile(config, name, values):
    """Add a profile or update an existing one, preserving other keys."""
    profiles = config.setdefault("profiles", {})
    if name in profiles:
        profiles[name].update(values or {})
    else:
        profiles[name] = _merge_profile(values)
    return profiles[name]


def delete_profile(config, name):
    """Delete a profile. Returns False when it did not exist."""
    profiles = config.setdefault("profiles", {})
    if name not in profiles:
        return False
    del profiles[name]
    if config.get("active_profile") == name:
        config["active_profile"] = (
            DEFAULT_PROFILE_KEY if DEFAULT_PROFILE_KEY in profiles
            else (sorted(profiles)[0] if profiles else DEFAULT_PROFILE_KEY)
        )
    return True


def profile_slug(name):
    """Turn a profile name into something safe for a filename."""
    text = str(name or "").strip().lower()
    text = text.replace("..", "-")
    text = re.sub(r"[^a-z0-9]+", "-", text)
    text = text.strip("-")
    if not text:
        text = "profile"
    return text[:60]

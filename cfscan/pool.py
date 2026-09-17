"""A frozen candidate list, so every carrier round measures the same addresses.

The scanner does not test every address of the ranges it is handed: it draws a
fresh sample on every run. Measured on the shipped range file - 1,524,480
addresses available, 5,955 tested per run, and two runs of the same profile
shared no address at all. A carrier comparison therefore needs a candidate list
that is chosen once and reused, which is what this module builds: a
deterministic sample spread over many /24 prefixes, with the seed stored in the
session record so the very same list can be rebuilt later.

The file handed to the scanner contains addresses and nothing else: the scanner
parses it as a CIDR list and aborts the run on any line it cannot parse.
"""

from __future__ import annotations

import hashlib
import ipaddress
import random
import secrets
from pathlib import Path

__all__ = [
    "DEFAULT_PER_PREFIX",
    "DEFAULT_POOL_SIZE",
    "POOL_VERSION",
    "new_pool",
    "pool_file_name",
    "pool_sha",
    "prefixes_in",
    "read_pool",
    "sample_addresses",
    "write_pool",
]

POOL_VERSION = 1

DEFAULT_POOL_SIZE = 2000
DEFAULT_PER_PREFIX = 8

# A /12 holds 4096 /24 prefixes; anything larger is sampled down instead of
# being enumerated, so a huge range file cannot make this module allocate a
# million strings.
MAX_PREFIXES = 8192


def prefixes_in(range_text):
    """Every /24 prefix covered by a range file, deduplicated and sorted.

    Lines may be CIDR ranges (what the Cloudflare list ships) or bare
    addresses. Unreadable lines are skipped: a candidate pool is a convenience,
    never a reason to refuse a scan.
    """
    prefixes = set()
    for raw in str(range_text or "").splitlines():
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue
        # Tolerate an inline comment after the range.
        for separator in ("#", "//", ","):
            if separator in line:
                line = line.split(separator, 1)[0].strip()
        if not line:
            continue
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if network.version != 4:
            continue
        if network.prefixlen >= 24:
            break_out = ipaddress.ip_network((int(network.network_address)
                                              & 0xFFFFFF00, 24))
            prefixes.add(str(break_out))
            continue
        count = 2 ** (24 - network.prefixlen)
        step = max(1, count // MAX_PREFIXES)
        for index in range(0, count, step):
            base = int(network.network_address) + (index << 8)
            prefixes.add(str(ipaddress.ip_network((base & 0xFFFFFF00, 24))))
            if len(prefixes) >= MAX_PREFIXES:
                break
        if len(prefixes) >= MAX_PREFIXES:
            break
    return sorted(prefixes)


def sample_addresses(prefixes, per_prefix=DEFAULT_PER_PREFIX, seed=None):
    """A deterministic sample inside the given prefixes.

    The seed decides everything, so the same seed always yields the same
    addresses - the point of the whole module. Host part 0 and 255 are avoided:
    the shipped Cloudflare ranges treat them as network/broadcast.
    """
    prefixes = list(prefixes)
    if not prefixes:
        return []
    per_prefix = max(1, int(per_prefix))
    generator = random.Random(seed)
    addresses = []
    for prefix in prefixes:
        network = ipaddress.ip_network(prefix, strict=False)
        base = int(network.network_address)
        hosts = sorted(generator.sample(range(1, 255), min(per_prefix, 254)))
        for host in hosts:
            addresses.append(str(ipaddress.ip_address(base + host)))
    return sorted(addresses, key=lambda item: int(ipaddress.ip_address(item)))


def pool_sha(addresses):
    """A stable fingerprint of a candidate list."""
    payload = "\n".join(sorted(str(item) for item in addresses))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def new_pool(range_text, size=DEFAULT_POOL_SIZE, per_prefix=DEFAULT_PER_PREFIX,
             seed=None):
    """Build a pool from a range file: ``{version, seed, addresses, sha256}``."""
    size = int(size)
    if size < 1:
        # Silently clamping this to one address produced a "pool" of a single
        # candidate, which is not a comparison - say so instead.
        raise ValueError(
            f"A candidate list needs at least one address, not {size}."
        )
    per_prefix = max(1, int(per_prefix))
    prefixes_needed = max(1, (size + per_prefix - 1) // per_prefix)
    available = prefixes_in(range_text)
    if not available:
        raise ValueError(
            "The IP range file does not contain any IPv4 range, so a candidate "
            "list cannot be built from it."
        )
    seed = int(seed) if seed is not None else secrets.randbelow(2 ** 31)
    if len(available) > prefixes_needed:
        chosen = sorted(random.Random(seed).sample(available, prefixes_needed))
    else:
        chosen = available
    addresses = sample_addresses(chosen, per_prefix=per_prefix, seed=seed)
    if len(addresses) > size:
        addresses = addresses[:size]
    return {
        "version": POOL_VERSION,
        "seed": seed,
        "per_prefix": per_prefix,
        "prefixes": len(chosen),
        "addresses": addresses,
        "sha256": pool_sha(addresses),
    }


def pool_file_name(pool):
    """``pool-3f9a2b7c1d4e5f60.txt`` for a pool, so identical pools collide."""
    return f"pool-{str(pool.get('sha256') or '')[:16]}.txt"


def write_pool(directory, pool):
    """Write a pool as one address per line, and nothing else. Returns the path.

    No comment lines: the scanner parses this file as a CIDR list and aborts the
    whole run on a line it cannot parse (measured: ``# cfscan candidate pool -\n
    200 addresses/128`` made a real run exit with code 1 and write no result at
    all). The seed and the fingerprint live in the session record and in the file
    name instead, so nothing is lost by keeping the file plain.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / pool_file_name(pool)
    lines = [str(item) for item in pool.get("addresses") or []]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def read_pool(path):
    """Read a pool file back into a list of addresses.

    Comment and blank lines are skipped, so a hand-written or older list is
    still readable (and the scanner's refusal to eat comments is healed before
    it ever sees the file).
    """
    addresses = []
    for raw in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        addresses.append(line)
    return addresses

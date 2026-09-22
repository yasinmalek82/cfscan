"""cfscan - a friendly wrapper around XIU2/CloudflareSpeedTest.

The package only wraps the existing scanner: it never replaces the scanning
engine, it builds safe argument lists for the ``cfst`` binary, and it keeps
its own configuration and results files.
"""

import os as _os

__version__ = "1.4.1"
__all__ = ["__version__", "source_note", "running_from_dev_link"]


def running_from_dev_link():
    """True when this package is being imported straight from a project folder.

    ``dev-link.sh`` writes a launcher that does exactly that, so an edit is live
    on the next run. The variable alone is not enough: a stale one left over
    from another checkout must not claim that *this* package is the linked one.
    """
    linked = _os.environ.get("CFSCAN_DEV_SOURCE")
    if not linked:
        return False
    package_dir = _os.path.dirname(_os.path.abspath(__file__))
    return _os.path.abspath(_os.path.join(linked, "cfscan")) == package_dir


def source_note():
    """Where this run imported the package from.

    Printing it turns "is my change live?" into something the reader can check
    instead of guess.
    """
    package_dir = _os.path.dirname(_os.path.abspath(__file__))
    if running_from_dev_link():
        return f"dev link: {package_dir} (edits are live)"
    return f"installed: {package_dir}"

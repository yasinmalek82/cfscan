"""cfscan - a friendly wrapper around XIU2/CloudflareSpeedTest.

The package only wraps the existing scanner: it never replaces the scanning
engine, it builds safe argument lists for the ``cfst`` binary, and it keeps
its own configuration and results files.
"""

__version__ = "1.1.0"
__all__ = ["__version__"]

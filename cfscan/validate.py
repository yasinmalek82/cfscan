"""Input validation for every value that reaches the scanner or the disk.

Rules of thumb used here:

* Numbers are parsed strictly, so ``"443a"`` or ``"1.5"`` never become a port.
* IP addresses are validated with :mod:`ipaddress`, never with a hand written
  regular expression.
* Anything that looks like a secret (UUID, password, private key, subscription
  link) is rejected outright: cfscan never asks for or stores secrets.
* Filenames may not contain path separators, shell metacharacters or control
  characters, so a value can never escape the results directory.
"""

from __future__ import annotations

import ipaddress
import re

__all__ = [
    "ValidationError",
    "assert_no_secrets",
    "validate_domain",
    "validate_float",
    "validate_http_status",
    "validate_colo",
    "validate_int",
    "validate_ip",
    "validate_ip_version",
    "validate_loss",
    "validate_output_filename",
    "validate_port",
    "validate_profile_name",
    "validate_url_scheme",
]


class ValidationError(ValueError):
    """Raised when a user supplied value is not acceptable."""


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------

_SECRET_MESSAGE = (
    "Invalid value: this looks like a secret (UUID, password, private key or "
    "subscription link). cfscan never asks for or stores secrets - please "
    "enter something else."
)

_SECRET_PATTERNS = (
    # UUIDs (tolerating a slightly short final group, which still means secret).
    re.compile(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{8,}\b",
        re.IGNORECASE,
    ),
    # Proxy / VPN share links and subscription links.
    re.compile(
        r"\b(vless|vmess|vless|trojan|ss|ssr|shadowsocks|hysteria2?|tuic|wireguard)"
        r"\s*://",
        re.IGNORECASE,
    ),
    re.compile(r"\b(subscription|subscribe|sub)\s*[:=]\s*\S+", re.IGNORECASE),
    # Credential assignments.
    re.compile(r"\b(password|passwd|pass|secret|token|apikey|api_key)\s*[:=]", re.IGNORECASE),
    re.compile(r"\b(uuid|guid|aid|psk)\s*[:=]", re.IGNORECASE),
    # Private keys.
    re.compile(r"-----BEGIN[ A-Z]*PRIVATE KEY-----"),
    re.compile(r"\bprivate[ _-]?key\b", re.IGNORECASE),
)


def assert_no_secrets(value):
    """Reject values that look like credentials or subscription links."""
    if value is None:
        return
    text = str(value)
    for pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            raise ValidationError(_SECRET_MESSAGE)


# --------------------------------------------------------------------------
# Hosts, addresses and ports
# --------------------------------------------------------------------------

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
_MAX_DOMAIN_LENGTH = 253
_MAX_LABEL_LENGTH = 63


def validate_domain(value):
    """Validate a domain name and return it in lower case."""
    assert_no_secrets(value)
    if not isinstance(value, str):
        raise ValidationError(f"Invalid domain: expected text, got {type(value).__name__}.")
    text = value.strip().rstrip(".").lower()
    if not text:
        raise ValidationError("Invalid domain: the value is empty.")
    if "://" in text or "/" in text or "@" in text:
        raise ValidationError(
            f"Invalid domain: {text!r} should be a plain hostname such as "
            "'gerr.yasin-ai-54.ir' (no scheme, no path)."
        )
    if len(text) > _MAX_DOMAIN_LENGTH:
        raise ValidationError("Invalid domain: the name is longer than 253 characters.")
    if " " in text or "\t" in text:
        raise ValidationError(f"Invalid domain: {text!r} contains a space.")
    try:
        ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        raise ValidationError(
            f"Invalid domain: {text!r} is an IP address, not a domain name."
        )
    labels = text.split(".")
    if len(labels) < 2:
        raise ValidationError(
            f"Invalid domain: {text!r} has no dot, so it cannot be a public domain."
        )
    for label in labels:
        if not label:
            raise ValidationError(f"Invalid domain: {text!r} contains an empty label.")
        if len(label) > _MAX_LABEL_LENGTH:
            raise ValidationError(
                f"Invalid domain: the label {label!r} is longer than 63 characters."
            )
        if not _LABEL_RE.match(label):
            raise ValidationError(
                f"Invalid domain: {text!r} contains an illegal character or a "
                "label that starts or ends with a hyphen."
            )
    return text


def validate_ip(value, version=None):
    """Validate an IP address with the standard library and return it."""
    assert_no_secrets(value)
    if not isinstance(value, str):
        raise ValidationError("Invalid IP address: expected text.")
    text = value.strip()
    if not text:
        raise ValidationError("Invalid IP address: the value is empty.")
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        raise ValidationError(
            f"Invalid IP address: {text!r} is not a valid IP address."
        )
    if version is not None and parsed.version != version:
        raise ValidationError(
            f"Invalid IP address: {text!r} is IPv{parsed.version} but IPv{version} is "
            f"configured here. Switch the IP version (menu 7) or enter an IPv{version} "
            "address."
        )
    return parsed


def validate_ip_version(value):
    """Return 4 or 6 for the accepted spellings of an IP version."""
    if isinstance(value, bool):
        raise ValidationError("Invalid IP version: expected 4 or 6.")
    if isinstance(value, int):
        normalised = value
    elif isinstance(value, str):
        text = value.strip().lower()
        normalised = {"4": 4, "v4": 4, "ipv4": 4, "6": 6, "v6": 6, "ipv6": 6}.get(text)
        if normalised is None:
            raise ValidationError(
                f"Invalid IP version: {value!r} is not IPv4 or IPv6."
            )
    else:
        raise ValidationError("Invalid IP version: expected 4 or 6.")
    if normalised not in (4, 6):
        raise ValidationError(f"Invalid IP version: {value!r} is not IPv4 or IPv6.")
    return normalised


def validate_port(value):
    """Return an integer port between 1 and 65535."""
    if isinstance(value, bool):
        raise ValidationError("Invalid port: expected a number between 1 and 65535.")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        text = value.strip()
        if not re.fullmatch(r"\d+", text):
            raise ValidationError(
                f"Invalid port: {value!r} is not a number between 1 and 65535."
            )
        number = int(text)
    else:
        raise ValidationError("Invalid port: expected a number between 1 and 65535.")
    if not 1 <= number <= 65535:
        raise ValidationError(
            f"Invalid port: {number} is outside the allowed range 1-65535."
        )
    return number


def validate_url_scheme(value):
    """Return 'http' or 'https'."""
    if not isinstance(value, str):
        raise ValidationError("Invalid scheme: expected 'http' or 'https'.")
    text = value.strip().lower()
    if text not in ("http", "https"):
        raise ValidationError(f"Invalid scheme: {value!r} is not 'http' or 'https'.")
    return text


# --------------------------------------------------------------------------
# Numbers
# --------------------------------------------------------------------------

def validate_int(value, minimum=None, maximum=None, field="value"):
    """Return a strictly parsed integer inside the given range."""
    if isinstance(value, bool):
        raise ValidationError(f"Invalid {field}: expected a whole number.")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        text = value.strip()
        if not re.fullmatch(r"[+-]?\d+", text):
            raise ValidationError(
                f"Invalid {field}: {value!r} is not a whole number."
            )
        number = int(text)
    else:
        raise ValidationError(f"Invalid {field}: {value!r} is not a whole number.")
    if minimum is not None and number < minimum:
        raise ValidationError(
            f"Invalid {field}: {number} is below the minimum of {minimum}."
        )
    if maximum is not None and number > maximum:
        raise ValidationError(
            f"Invalid {field}: {number} is above the maximum of {maximum}."
        )
    return number


def validate_float(value, minimum=None, maximum=None, field="value"):
    """Return a strictly parsed floating point number inside the given range."""
    if isinstance(value, bool):
        raise ValidationError(f"Invalid {field}: expected a number.")
    if isinstance(value, (int, float)):
        number = float(value)
    elif isinstance(value, str):
        text = value.strip()
        if not re.fullmatch(r"[+-]?(\d+\.?\d*|\.\d+)", text):
            raise ValidationError(f"Invalid {field}: {value!r} is not a number.")
        number = float(text)
    else:
        raise ValidationError(f"Invalid {field}: {value!r} is not a number.")
    if minimum is not None and number < minimum:
        raise ValidationError(
            f"Invalid {field}: {number} is below the minimum of {minimum}."
        )
    if maximum is not None and number > maximum:
        raise ValidationError(
            f"Invalid {field}: {number} is above the maximum of {maximum}."
        )
    return number


def validate_loss(value, field="maximum packet loss"):
    """Return a packet loss value as a fraction between 0.0 and 1.0.

    Accepts ``0.25``, ``25`` and ``25%`` for the same setting.
    """
    if isinstance(value, bool):
        raise ValidationError(f"Invalid {field}: expected a percentage or a fraction.")
    if isinstance(value, (int, float)):
        number = float(value)
        percent = number > 1
    elif isinstance(value, str):
        text = value.strip()
        percent = text.endswith("%")
        if percent:
            text = text[:-1].strip()
        if not re.fullmatch(r"[+-]?(\d+\.?\d*|\.\d+)", text):
            raise ValidationError(
                f"Invalid {field}: {value!r} is not a percentage such as 25%."
            )
        number = float(text)
        percent = percent or number > 1
    else:
        raise ValidationError(f"Invalid {field}: {value!r} is not a percentage.")
    fraction = number / 100.0 if percent else number
    if not 0.0 <= fraction <= 1.0:
        raise ValidationError(
            f"Invalid {field}: {value!r} must be between 0% and 100%."
        )
    return fraction


#: Cloudflare names a datacentre with the IATA code of its airport (FRA, AMS,
#: LHR); the scanner also accepts two letter country codes. Anything else is a
#: typo that would silently filter every address away.
_COLO_RE = re.compile(r"^[A-Z]{2,4}$")
MAX_COLO_CODES = 20


def validate_colo(value):
    """Validate a region filter and return it as the scanner wants it.

    Accepts ``"fra, ams"``, ``"FRA,AMS"`` and ``"FRA AMS"`` alike, and returns
    ``"FRA,AMS"``. An empty value (or "any"/"all"/"none") means no filter, which
    is the default: the whole edge is measured.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValidationError(
            "Invalid region filter: expected text such as 'FRA,AMS'."
        )
    text = value.strip()
    if not text or text.lower() in ("none", "any", "all", "-"):
        return ""
    assert_no_secrets(text)
    codes = []
    for raw in text.replace(" ", ",").split(","):
        code = raw.strip().upper()
        if not code:
            continue
        if not _COLO_RE.match(code):
            raise ValidationError(
                f"Invalid region filter: {code!r} is not a Cloudflare region "
                "code. Use the three letter airport code of a datacentre - FRA "
                "(Frankfurt), AMS (Amsterdam), LHR (London) - or a two letter "
                "country code such as DE, separated by commas."
            )
        if code not in codes:
            codes.append(code)
    if len(codes) > MAX_COLO_CODES:
        raise ValidationError(
            f"Invalid region filter: {len(codes)} region codes is more than a "
            f"filter needs (the maximum is {MAX_COLO_CODES})."
        )
    return ",".join(codes)


def validate_http_status(value):
    """Return an HTTP status code between 100 and 599."""
    return validate_int(value, minimum=100, maximum=599, field="HTTP status code")


# --------------------------------------------------------------------------
# Names on disk
# --------------------------------------------------------------------------

_UNSAFE_FILENAME_CHARS = set('\\/:*?"<>|;&$`\'()[]{}!~\t\n\r\x00')
# The '.csv' suffix is matched case-insensitively, because the check above
# accepts 'Report.CSV' as well and the two must not disagree.
_ALLOWED_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+-]*\.csv$", re.IGNORECASE)
_MAX_FILENAME_LENGTH = 120


def validate_output_filename(value):
    """Validate a bare CSV filename (never a path)."""
    if not isinstance(value, str):
        raise ValidationError("Invalid filename: expected text.")
    text = value.strip()
    if not text:
        raise ValidationError("Invalid filename: the value is empty.")
    assert_no_secrets(text)
    if len(text) > _MAX_FILENAME_LENGTH:
        raise ValidationError(
            f"Invalid filename: {len(text)} characters is too long "
            f"(maximum {_MAX_FILENAME_LENGTH})."
        )
    if any(character in _UNSAFE_FILENAME_CHARS for character in text):
        raise ValidationError(
            f"Invalid filename: {text!r} contains a character that is not allowed "
            "in a filename."
        )
    if not text.lower().endswith(".csv"):
        raise ValidationError(
            f"Invalid filename: {text!r} must end with '.csv'."
        )
    if not _ALLOWED_FILENAME_RE.match(text):
        raise ValidationError(
            f"Invalid filename: {text!r} may only use letters, digits, spaces, "
            "'-', '_', '+' and '.' and must not start with a dot."
        )
    return text


def validate_profile_name(value):
    """Validate the name of a saved profile."""
    if not isinstance(value, str):
        raise ValidationError("Invalid profile name: expected text.")
    text = value.strip()
    if not text:
        raise ValidationError("Invalid profile name: the value is empty.")
    assert_no_secrets(text)
    if len(text) > 60:
        raise ValidationError("Invalid profile name: keep it under 60 characters.")
    if any(character in text for character in "\\/\x00\n\r\t"):
        raise ValidationError(
            f"Invalid profile name: {text!r} must not contain slashes or control "
            "characters."
        )
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._+-]*", text):
        raise ValidationError(
            f"Invalid profile name: {text!r} may only use letters, digits, spaces, "
            "'-', '_', '+' and '.'."
        )
    return text

"""Parsing of the CSV files produced by XIU2/CloudflareSpeedTest.

The scanner writes a UTF-8 CSV with a byte order mark, CRLF line endings and a
Chinese header. It looks like this::

    IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码
    104.16.0.1,4,4,0.00,138.32,0.00,FRA

The last column (``地区码`` / colo) only exists in HTTPing mode. Parsing stays
tolerant: unknown headers fall back to positional columns, unreadable rows are
skipped with a warning, and the caller always receives a report instead of an
exception for anything that is merely unusual.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
from dataclasses import dataclass, field
from typing import List, Optional

__all__ = [
    "CsvError",
    "ParseReport",
    "ScanResult",
    "parse_csv_text",
    "parse_results_csv",
    "rank_results",
    "recommend",
]


class CsvError(Exception):
    """Raised when a result file cannot be read at all."""


# Header spellings seen in the wild (Chinese originals and English variants).
# Compared after lower-casing and removing all whitespace, so "IP 地址" and
# "IP Address" both resolve to the ip column.
_HEADER_KEYS = {
    "ip": ("ip", "ip地址", "ipaddress", "address"),
    "sent": ("已发送", "sent", "发送"),
    "received": ("已接收", "received", "接收", "recv"),
    "loss": ("丢包率", "loss", "packetloss", "丢包", "lossrate"),
    "latency": ("平均延迟", "latency", "avglatency", "平均延迟(ms)", "delay"),
    "download": ("下载速度(mb/s)", "下载速度", "download", "download(mb/s)",
                 "downloadspeed(mb/s)", "下载速度(mb/s)"),
    "colo": ("地区码", "colo", "colocode", "region", "datacenter"),
}

_PROGRESS_HEADER_CHARS = set("[]_-# ")


@dataclass(frozen=True)
class ScanResult:
    """One row of a scanner result file."""

    ip: str
    sent: int
    received: int
    loss: float
    latency_ms: float
    download_mbps: float = 0.0
    colo: Optional[str] = None

    @property
    def loss_percent(self) -> float:
        return round(self.loss * 100.0, 2)

    @property
    def has_colo(self) -> bool:
        return bool(self.colo) and self.colo.upper() not in ("N/A", "NA", "-", "UNKNOWN")

    @property
    def is_loss_free(self) -> bool:
        return self.loss <= 0.0 and self.received >= self.sent and self.sent > 0

    def latency_text(self) -> str:
        return f"{self.latency_ms:.2f} ms"

    def loss_text(self) -> str:
        return f"{self.loss_percent:.0f}%"

    def colo_text(self) -> str:
        return self.colo if self.has_colo else "-"


@dataclass
class ParseReport:
    """Outcome of parsing a result file."""

    results: List[ScanResult] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    header: List[str] = field(default_factory=list)
    used_positional_fallback: bool = False


# --------------------------------------------------------------------------
# Text helpers
# --------------------------------------------------------------------------

def _clean_cell(value: str) -> str:
    return (value or "").replace("\ufeff", "").strip()


def _normalise_header(value: str) -> str:
    text = _clean_cell(value).lower()
    text = text.replace("：", ":")
    return re.sub(r"\s+", "", text)


def _map_header(header_row: List[str]):
    """Return {field: column index} for a header row, or None if unusable."""
    mapping = {}
    for index, cell in enumerate(header_row):
        name = _normalise_header(cell)
        if not name:
            continue
        for key, spellings in _HEADER_KEYS.items():
            if key in mapping:
                continue
            if name in spellings:
                mapping[key] = index
                break
    if "ip" not in mapping:
        return None
    return mapping


def _looks_like_data_row(row: List[str]) -> bool:
    if not row:
        return False
    first = _clean_cell(row[0])
    try:
        ipaddress.ip_address(first)
    except ValueError:
        return False
    return True


def _looks_like_progress_row(row: List[str]) -> bool:
    """Progress bars leak into the log; make sure they never parse as data."""
    joined = "".join(_clean_cell(cell) for cell in row)
    if not joined:
        return False
    return set(joined) <= _PROGRESS_HEADER_CHARS


def _parse_int(value: str, default: int = 0) -> int:
    text = _clean_cell(value)
    if re.fullmatch(r"[+-]?\d+", text):
        return int(text)
    return default


def _parse_float(value: str, default: float = 0.0) -> float:
    text = _clean_cell(value)
    if text.endswith("%"):
        text = text[:-1].strip()
        if re.fullmatch(r"[+-]?(\d+\.?\d*|\.\d+)", text):
            return float(text) / 100.0
        return default
    if re.fullmatch(r"[+-]?(\d+\.?\d*|\.\d+)", text):
        return float(text)
    return default


def _parse_loss(value: str) -> float:
    text = _clean_cell(value)
    if not text:
        return 0.0
    percent = text.endswith("%")
    if percent:
        text = text[:-1].strip()
    if not re.fullmatch(r"[+-]?(\d+\.?\d*|\.\d+)", text):
        return 0.0
    number = float(text)
    if percent:
        return min(max(number / 100.0, 0.0), 1.0)
    # The scanner writes fractions (0.00 - 1.00); tolerate percentages too.
    if number > 1.0:
        return min(number / 100.0, 1.0)
    return max(number, 0.0)


def _parse_latency(value: str):
    """Latency in milliseconds, or None when the cell holds no number.

    An unreadable latency must not become ``0.0``: sorting would then put that
    row ahead of every measured address and the recommendation would hand the
    user an address that was never timed.
    """
    text = _clean_cell(value)
    if not text:
        # No measurement recorded in the column at all; keep the row as before.
        return 0.0
    text = re.sub(r"(?i)\s*ms$", "", text).strip()
    if re.fullmatch(r"[+-]?(\d+\.?\d*|\.\d+)", text):
        return float(text)
    return None


def _row_to_result(row: List[str], index) -> Optional[ScanResult]:
    if len(row) < 5:
        return None
    try:
        ip = str(ipaddress.ip_address(_clean_cell(row[index["ip"]])))
    except (ValueError, IndexError, KeyError):
        return None

    def cell(key):
        position = index.get(key)
        if position is None or position >= len(row):
            return ""
        return row[position]

    latency = _parse_latency(cell("latency"))
    if latency is None:
        # Treated like any other unreadable line, so the report can say so.
        return None

    colo = _clean_cell(cell("colo")) or None
    return ScanResult(
        ip=ip,
        sent=_parse_int(cell("sent")),
        received=_parse_int(cell("received")),
        loss=_parse_loss(cell("loss")),
        latency_ms=latency,
        download_mbps=_parse_float(cell("download")),
        colo=colo,
    )


# --------------------------------------------------------------------------
# Public parsing API
# --------------------------------------------------------------------------

def parse_csv_text(text: str) -> ParseReport:
    """Parse scanner CSV text, tolerating anything that is merely malformed."""
    report = ParseReport()
    if not text or not text.strip():
        report.warnings.append("The result file is empty, so there is nothing to show.")
        return report

    try:
        rows = list(csv.reader(io.StringIO(text)))
    except csv.Error as error:  # pragma: no cover - csv is very forgiving
        report.warnings.append(f"The result file could not be read: {error}")
        return report

    rows = [row for row in rows if any(_clean_cell(cell) for cell in row)]
    if not rows:
        report.warnings.append("The result file is empty, so there is nothing to show.")
        return report

    report.header = [_clean_cell(cell) for cell in rows[0]]
    mapping = _map_header(rows[0])
    body = rows[1:]

    if mapping is None:
        if _looks_like_data_row(rows[0]):
            # No usable header at all: treat every row as data, positionally.
            report.used_positional_fallback = True
            report.warnings.append(
                "The header of the result file was not recognised; columns were "
                "read by position (IP, sent, received, loss, latency, download, colo)."
            )
            mapping = {"ip": 0, "sent": 1, "received": 2, "loss": 3, "latency": 4,
                       "download": 5, "colo": 6}
            body = rows
        else:
            report.warnings.append(
                "The result file does not look like a CloudflareSpeedTest CSV."
            )
            return report

    skipped = 0
    for row in body:
        if _looks_like_progress_row(row):
            continue
        if not any(_clean_cell(cell) for cell in row):
            continue
        result = _row_to_result(row, mapping)
        if result is None:
            skipped += 1
            continue
        report.results.append(result)

    if skipped:
        report.warnings.append(
            f"Skipped {skipped} unreadable line(s) in the result file."
        )
    if not report.results:
        report.warnings.append("The result file does not contain any usable row.")
    return report


def parse_results_csv(path) -> ParseReport:
    """Read and parse a result file from disk."""
    import os

    path = str(path)
    if not os.path.exists(path):
        raise CsvError(f"Result file not found: {path}")
    if os.path.isdir(path):
        raise CsvError(f"Expected a result file but found a directory: {path}")
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as error:
        raise CsvError(f"The result file could not be read: {error}")

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")
    return parse_csv_text(text)


def rank_results(results: List[ScanResult]) -> List[ScanResult]:
    """Sort results the way a human ranks Cloudflare IPs."""
    return sorted(results, key=lambda item: (item.loss, item.latency_ms, item.ip))


def recommend(results: List[ScanResult], preferred_ip=None) -> Optional[ScanResult]:
    """Pick the IP to recommend.

    The verified IP stored in the profile wins when it is present in the scan
    results; otherwise the fastest loss free candidate is chosen.
    """
    if not results:
        return None
    if preferred_ip:
        for result in results:
            if result.ip == preferred_ip:
                return result
    loss_free = [item for item in results if item.is_loss_free]
    pool = loss_free or results
    return min(pool, key=lambda item: (item.latency_ms, item.loss))

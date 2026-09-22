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
from dataclasses import dataclass, field, replace
from typing import List, Optional

__all__ = [
    "CsvError",
    "JITTER_POINT_PER_MS",
    "LATENCY_POINT_PER_MS",
    "ParseReport",
    "SPEED_POINT_PER_MBPS",
    "ScanResult",
    "apply_measurements",
    "merge_verified_result",
    "parse_csv_text",
    "parse_results_csv",
    "rank_results",
    "recommend",
    "write_enriched_csv",
]

#: Points added for each MB/s of download and of upload. The two speeds weigh
#: the same, so a strong upload is not only a tie-break after download.
SPEED_POINT_PER_MBPS = 10.0

#: Penalty for each millisecond of jitter. 10 ms of jitter costs 1 point,
#: the same as 0.1 MB/s of speed or 20 ms of latency.
JITTER_POINT_PER_MS = 0.1

#: Penalty for each millisecond of average latency. It still matters, and a
#: small gap does not hide a real difference in speed or jitter: 20 ms costs
#: 1 point.
LATENCY_POINT_PER_MS = 0.05


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
    # Not written by cfst. cfscan adds them after its own jitter and upload
    # probes so "show last results" can rank the same way the scan did.
    "jitter": ("抖动(ms)", "抖动", "jitter", "jitter(ms)", "jitterms"),
    "upload": ("上传速度(mb/s)", "上传速度", "upload", "upload(mb/s)",
               "uploadspeed(mb/s)"),
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
    #: ``None`` means this row was not download-tested. ``0.0`` is a real
    #: measurement that transferred nothing. cfst's own CSV writes ``0.00``
    #: even when its download test is off, so a latency-only file stays ``0.0``.
    download_mbps: Optional[float] = 0.0
    colo: Optional[str] = None
    #: ``None`` means the probe did not run (or no sample came back). Zero is a
    #: real measurement: the round trip did not fluctuate.
    jitter_ms: Optional[float] = None
    #: ``None`` means upload was not measured. Zero is a failed or empty send.
    upload_mbps: Optional[float] = None

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

    def jitter_text(self) -> str:
        if self.jitter_ms is None:
            return "—"
        return f"{self.jitter_ms:.2f} ms"

    def download_text(self) -> str:
        if self.download_mbps is None:
            return "—"
        return f"{self.download_mbps:.2f} MB/s"

    def upload_text(self) -> str:
        if self.upload_mbps is None:
            return "—"
        return f"{self.upload_mbps:.2f} MB/s"


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


def _parse_optional_float(value: str):
    """A float, or ``None`` when the cell is empty or not a number.

    Used for columns cfscan itself adds. An empty cell must stay "not
    measured": treating it as ``0`` would rank an address that was never
    probed as perfectly stable, or as a failed upload.
    """
    text = _clean_cell(value)
    if not text or text in ("-", "n/a", "N/A"):
        return None
    if re.fullmatch(r"[+-]?(\d+\.?\d*|\.\d+)", text):
        return float(text)
    return None


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
    jitter = _parse_optional_float(cell("jitter")) if "jitter" in index else None
    upload = _parse_optional_float(cell("upload")) if "upload" in index else None
    if "download" in index:
        raw_download = _clean_cell(cell("download"))
        # An empty cell is "not in the download pass". cfst itself always
        # writes 0.00, including when the test is off, and that stays a zero.
        if not raw_download or raw_download in ("-", "—"):
            download = None
        else:
            download = _parse_float(raw_download)
    else:
        download = 0.0
    return ScanResult(
        ip=ip,
        sent=_parse_int(cell("sent")),
        received=_parse_int(cell("received")),
        loss=_parse_loss(cell("loss")),
        latency_ms=latency,
        download_mbps=download,
        colo=colo,
        jitter_ms=jitter,
        upload_mbps=upload,
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


def _quality_points(item, download, upload, jitter_measured, missing_jitter):
    """Higher is better. Loss is not part of the score; the caller sorts it first."""
    points = -float(item.latency_ms) * LATENCY_POINT_PER_MS
    if download:
        points += float(item.download_mbps or 0.0) * SPEED_POINT_PER_MBPS
    if upload and item.upload_mbps is not None:
        points += float(item.upload_mbps) * SPEED_POINT_PER_MBPS
    if jitter_measured:
        # A missing sample must not look perfectly stable. It is just worse
        # than the worst sample we actually have, so a much faster download
        # can still win.
        jitter = missing_jitter if item.jitter_ms is None else float(item.jitter_ms)
        points -= jitter * JITTER_POINT_PER_MS
    return points


def rank_results(results: List[ScanResult], download=None) -> List[ScanResult]:
    """Sort results the way a human ranks Cloudflare IPs.

    Lower packet loss always comes first, so a loss-free address beats every
    address that dropped packets, however fast that one was.

    When no row has a download speed, an upload sample or a jitter sample,
    the rest of the order is lower latency. That is the same order a
    latency-only file has always had.

    When any of those three was measured, download, upload and jitter are one
    score, not tie-breaks hidden behind a latency band (higher wins):

    * ``10`` points per MB/s of download (``0`` when that row was not tested)
    * ``10`` points per MB/s of upload (no credit when that row was not tested)
    * ``0.1`` points off per ms of jitter
    * ``0.05`` points off per ms of latency

    So 1 MB/s of either speed is worth 100 ms of jitter or 200 ms of latency,
    and upload weighs the same as download. Pass ``download=False`` to ignore
    download on purpose (choosing who to probe, before speed should matter).
    ``download=True`` counts the column even when every speed is ``0``.
    """
    rows = list(results)
    if download is None:
        download = any(float(item.download_mbps or 0.0) > 0.0 for item in rows)
    else:
        download = bool(download)
    upload = any(item.upload_mbps is not None for item in rows)
    jitter_measured = any(item.jitter_ms is not None for item in rows)
    if not download and not upload and not jitter_measured:
        return sorted(rows, key=lambda item: (float(item.loss), float(item.latency_ms), item.ip))

    samples = [float(item.jitter_ms) for item in rows if item.jitter_ms is not None]
    missing_jitter = (max(samples) + 1.0) if samples else 0.0

    def key(item):
        points = _quality_points(item, download, upload, jitter_measured, missing_jitter)
        return (float(item.loss), -points, item.ip)

    return sorted(rows, key=key)


def recommend(results: List[ScanResult], preferred_ip=None) -> Optional[ScanResult]:
    """Pick the IP to recommend.

    The verified IP stored in the profile wins when it is present in the scan
    results; otherwise the first row of :func:`rank_results` is chosen.
    """
    if not results:
        return None
    if preferred_ip:
        for result in results:
            if result.ip == preferred_ip:
                return result
    loss_free = [item for item in results if item.is_loss_free]
    pool = loss_free or list(results)
    return rank_results(pool)[0]


def merge_verified_result(measured, verified, attempts=0):
    """Copy a strict-check verdict onto a row that already has speed numbers.

    Latency, loss, sent, received and colo come from the check. Jitter,
    download and upload stay on ``measured``, because the check is a latency
    run and does not repeat those probes. ``verified`` missing means the
    address answered nothing: the speed numbers are kept and the row is marked
    as total loss so it cannot outrank an address the check actually passed.
    """
    if verified is None:
        sent = int(attempts) if int(attempts or 0) > 0 else measured.sent
        return replace(measured, sent=sent, received=0, loss=1.0)
    colo = verified.colo if verified.has_colo else measured.colo
    return replace(
        measured,
        sent=verified.sent,
        received=verified.received,
        loss=verified.loss,
        latency_ms=verified.latency_ms,
        colo=colo,
    )


def apply_measurements(results, download_by_ip=None, jitter_by_ip=None,
                       upload_by_ip=None, clear_other_downloads=False):
    """Return new rows with any extra measurements copied on by IP.

    A missing IP is left alone, unless ``clear_other_downloads`` is set: then
    every address that was not in the download pass becomes "not measured"
    (``None``) instead of keeping cfst's ``0.00``. A present IP is updated
    even when the value is ``0`` or ``None``, because that is a measurement,
    not "skip".
    """
    download_by_ip = {} if download_by_ip is None else download_by_ip
    jitter_by_ip = {} if jitter_by_ip is None else jitter_by_ip
    upload_by_ip = {} if upload_by_ip is None else upload_by_ip
    updated = []
    for item in results:
        changes = {}
        if item.ip in download_by_ip:
            changes["download_mbps"] = float(download_by_ip[item.ip] or 0.0)
        elif clear_other_downloads:
            changes["download_mbps"] = None
        if item.ip in jitter_by_ip:
            value = jitter_by_ip[item.ip]
            changes["jitter_ms"] = None if value is None else float(value)
        if item.ip in upload_by_ip:
            value = upload_by_ip[item.ip]
            changes["upload_mbps"] = None if value is None else float(value)
        updated.append(replace(item, **changes) if changes else item)
    return updated


def write_enriched_csv(path, results):
    """Rewrite a result file so jitter and upload survive "show last results".

    The scanner's own columns stay in front, in the same order, and the two
    cfscan columns are appended. Empty cells mean "not measured".
    """
    header = ["IP 地址", "已发送", "已接收", "丢包率", "平均延迟",
              "下载速度(MB/s)", "地区码", "抖动(ms)", "上传速度(MB/s)"]
    body = []
    for item in results:
        body.append([
            item.ip,
            str(int(item.sent)),
            str(int(item.received)),
            f"{float(item.loss):.2f}",
            f"{float(item.latency_ms):.2f}",
            "" if item.download_mbps is None else f"{float(item.download_mbps):.2f}",
            item.colo if item.colo else "N/A",
            "" if item.jitter_ms is None else f"{float(item.jitter_ms):.2f}",
            "" if item.upload_mbps is None else f"{float(item.upload_mbps):.2f}",
        ])
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(header)
    writer.writerows(body)
    text = "\ufeff" + buffer.getvalue()
    with open(str(path), "w", encoding="utf-8", newline="") as handle:
        handle.write(text)

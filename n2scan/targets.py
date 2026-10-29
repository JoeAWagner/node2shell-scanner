"""Load the list of targets to scan.

The list is expected to come from a spreadsheet you own (e.g. a Google Sheet
exported as CSV: File -> Download -> Comma-separated values). We deliberately
read a local file rather than reaching into Google directly, so the tool has
no standing access to your sheet and the input is easy to review before a run.

Accepted formats:
  * CSV / TSV with a header row. We look for a column named one of:
    url, host, hostname, target, address, site (case-insensitive).
  * A plain text file with one host/URL per line (no header).

Lines beginning with '#' are treated as comments and skipped.
"""

from __future__ import annotations

import csv
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

_URL_COLUMNS = ("url", "host", "hostname", "target", "address", "site")


@dataclass(frozen=True)
class Target:
    """A single thing to scan, plus any extra columns from the sheet."""

    raw: str
    url: str
    host: str
    scheme_explicit: bool = True
    meta: dict[str, str] = field(default_factory=dict)

    def candidate_urls(self) -> list[str]:
        """URLs to try, in order.

        When the sheet gave a bare host we try https first, then http, so a
        host that only speaks plain HTTP still gets scanned. When the sheet
        specified a scheme we honour it exactly.
        """
        if self.scheme_explicit:
            return [self.url]
        return [f"https://{self.host}", f"http://{self.host}"]


def _normalize(raw: str) -> tuple[str, str, bool]:
    """Return (url, host, scheme_explicit) for a raw cell value.

    Adds an https:// scheme if none is present so httpx has something to fetch,
    and reports whether the caller specified the scheme themselves.
    """
    value = raw.strip()
    if not value:
        raise ValueError("empty target")
    explicit = "://" in value
    if not explicit:
        value = "https://" + value
    parsed = urlparse(value)
    if not parsed.hostname:
        raise ValueError(f"could not parse a host out of {raw!r}")
    return value, parsed.hostname, explicit


def _looks_like_header(row: list[str]) -> bool:
    lowered = [c.strip().lower() for c in row]
    return any(col in lowered for col in _URL_COLUMNS)


def _url_column_index(header: list[str]) -> int:
    lowered = [c.strip().lower() for c in header]
    for col in _URL_COLUMNS:
        if col in lowered:
            return lowered.index(col)
    # Fall back to the first column.
    return 0


def load_targets(path: str | Path) -> list[Target]:
    """Parse a CSV/TSV/txt file into a de-duplicated list of Targets."""
    path = Path(path)
    text = path.read_text(encoding="utf-8-sig")  # tolerate a BOM from Sheets
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if not lines:
        return []

    delimiter = "\t" if (path.suffix.lower() == ".tsv" or "\t" in lines[0]) else ","
    rows = list(csv.reader(lines, delimiter=delimiter))

    header: list[str] | None = None
    col = 0
    if _looks_like_header(rows[0]):
        header = rows[0]
        col = _url_column_index(header)
        rows = rows[1:]

    seen: set[str] = set()
    targets: list[Target] = []
    for row in rows:
        if not row or col >= len(row):
            continue
        cell = row[col]
        if not cell.strip():
            continue
        try:
            url, host, explicit = _normalize(cell)
        except ValueError:
            continue
        if host in seen:
            continue
        seen.add(host)
        meta: dict[str, str] = {}
        if header:
            for i, name in enumerate(header):
                if i != col and i < len(row):
                    meta[name.strip()] = row[i].strip()
        targets.append(
            Target(raw=cell.strip(), url=url, host=host, scheme_explicit=explicit, meta=meta)
        )
    return targets


def is_private(host: str) -> bool:
    """True if host is an RFC1918 / loopback IP. Useful for a sanity guardrail."""
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False

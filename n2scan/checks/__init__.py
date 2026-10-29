"""Check registry.

Register new detectors here so the CLI can list and select them by name.
DEFAULT_CHECK_NAMES is what runs when the user doesn't pass --check; checks not
in it (e.g. brotli-reach, which issues a POST) are opt-in.
"""

from __future__ import annotations

from n2scan.checks.base import Check, Finding, Severity, Status
from n2scan.checks.brotli_reach import BrotliReachabilityCheck
from n2scan.checks.fingerprint import FingerprintCheck
from n2scan.checks.node2shell import Node2ShellCheck

ALL_CHECKS: dict[str, Check] = {
    c.name: c
    for c in (
        FingerprintCheck(),
        Node2ShellCheck(),
        BrotliReachabilityCheck(),
    )
}

# Run by default (non-destructive, no request bodies).
DEFAULT_CHECK_NAMES: tuple[str, ...] = ("fingerprint", "node2shell")

__all__ = [
    "ALL_CHECKS",
    "DEFAULT_CHECK_NAMES",
    "Check",
    "Finding",
    "Severity",
    "Status",
]

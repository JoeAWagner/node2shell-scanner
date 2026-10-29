"""Check registry.

Register new detectors here so the CLI can list and select them by name.
"""

from __future__ import annotations

from n2scan.checks.base import Check, Finding, Severity, Status
from n2scan.checks.fingerprint import FingerprintCheck
from n2scan.checks.node2shell import Node2ShellCheck

ALL_CHECKS: dict[str, Check] = {
    c.name: c
    for c in (
        FingerprintCheck(),
        Node2ShellCheck(),
    )
}

__all__ = ["ALL_CHECKS", "Check", "Finding", "Severity", "Status"]

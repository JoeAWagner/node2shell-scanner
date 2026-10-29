"""The Check interface.

A Check inspects one target and returns a Finding. Checks must be
*non-destructive detectors*: they send a probe and classify the response.
They must not attempt to execute attacker-controlled commands on the target,
establish a shell, modify data, or exfiltrate anything. The job of this tool
is to tell you which of your sites are exposed so you can remediate them, not
to exploit them.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from n2scan.targets import Target

if TYPE_CHECKING:
    from n2scan.fetch import Fetcher


class Severity(enum.StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Status(enum.StrEnum):
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


@dataclass
class Finding:
    target: str
    check: str
    status: Status
    severity: Severity = Severity.INFO
    # Short human-readable explanation of *why* we reached this status.
    evidence: str = ""
    # Anything structured worth keeping (status code, matched header, etc.).
    detail: dict = field(default_factory=dict)


class Check(Protocol):
    name: str
    description: str

    async def run(self, fetcher: "Fetcher", target: Target) -> Finding:
        ...

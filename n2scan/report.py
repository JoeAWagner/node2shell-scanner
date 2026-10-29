"""Turn findings into output: a console summary, CSV, or JSON.

The CSV is meant to drop straight back into a spreadsheet so you have a
patch-tracking column next to each host.
"""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from dataclasses import asdict
from io import StringIO

from n2scan.checks.base import Finding, Status


def to_json(findings: list[Finding]) -> str:
    return json.dumps([asdict(f) for f in findings], indent=2, default=str)


def to_csv(findings: list[Finding]) -> str:
    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow(["target", "check", "status", "severity", "evidence"])
    for f in findings:
        writer.writerow([f.target, f.check, f.status, f.severity, f.evidence])
    return buf.getvalue()


def print_summary(findings: list[Finding], stream=sys.stdout) -> None:
    by_status: Counter[str] = Counter(f.status for f in findings)
    vulnerable = [f for f in findings if f.status == Status.VULNERABLE]
    error_kinds: Counter[str] = Counter(
        f.detail.get("error_kind", "unknown") for f in findings if f.status == Status.ERROR
    )
    tls_unverified = {
        f.target for f in findings if f.detail.get("tls_verified") is False
    }

    print("\n=== n2scan summary ===", file=stream)
    for status in Status:
        if by_status.get(status):
            print(f"  {status:<16} {by_status[status]}", file=stream)

    if error_kinds:
        print("\n  Errors by kind:", file=stream)
        for kind, n in error_kinds.most_common():
            hint = "  (try --no-verify-tls)" if kind == "tls-verify" else ""
            print(f"    {kind:<14} {n}{hint}", file=stream)

    if tls_unverified:
        print(
            f"\n  {len(tls_unverified)} host(s) reached only with an untrusted cert "
            "(self-signed/expired/private CA).",
            file=stream,
        )

    if vulnerable:
        print("\n  Needs patching:", file=stream)
        for f in sorted(vulnerable, key=lambda x: x.target):
            print(f"    [{f.severity}] {f.target} ({f.check}) — {f.evidence}", file=stream)
    else:
        print("\n  No hosts flagged VULNERABLE by the enabled checks.", file=stream)
    print("", file=stream)

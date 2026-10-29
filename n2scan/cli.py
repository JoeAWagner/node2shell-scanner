"""Command-line entry point.

Example:
    n2scan targets.csv
    n2scan targets.csv --check fingerprint --format csv -o reports/scan.csv
    n2scan targets.csv --concurrency 20 --no-verify-tls
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from n2scan import __version__
from n2scan.checks import ALL_CHECKS
from n2scan.report import print_summary, to_csv, to_json
from n2scan.scanner import DEFAULT_CONCURRENCY, DEFAULT_TIMEOUT, scan
from n2scan.targets import load_targets


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="n2scan",
        description="Authorized detect-and-report scanner for SBU-owned web properties.",
    )
    p.add_argument(
        "targets",
        nargs="?",
        help="CSV/TSV/txt list of hosts (e.g. a Google Sheet exported as CSV)",
    )
    p.add_argument(
        "--check",
        action="append",
        choices=sorted(ALL_CHECKS),
        help="Check(s) to run. Repeatable. Default: all.",
    )
    p.add_argument("--format", choices=("summary", "json", "csv"), default="summary")
    p.add_argument("-o", "--output", help="Write the report here instead of stdout.")
    p.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument(
        "--no-verify-tls",
        action="store_true",
        help="Skip TLS verification (handy for internal hosts with private CAs).",
    )
    p.add_argument("--list-checks", action="store_true", help="List available checks and exit.")
    p.add_argument("--version", action="version", version=f"n2scan {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_checks:
        for name, check in sorted(ALL_CHECKS.items()):
            print(f"{name:<14} {check.description}")
        return 0

    if not args.targets:
        print("error: a targets file is required (or use --list-checks)", file=sys.stderr)
        return 2

    targets = load_targets(args.targets)
    if not targets:
        print(f"No targets parsed from {args.targets}", file=sys.stderr)
        return 2

    selected = [ALL_CHECKS[name] for name in (args.check or sorted(ALL_CHECKS))]
    print(
        f"Scanning {len(targets)} target(s) with {len(selected)} check(s): "
        f"{', '.join(c.name for c in selected)}",
        file=sys.stderr,
    )

    findings = asyncio.run(
        scan(
            targets,
            selected,
            concurrency=args.concurrency,
            timeout=args.timeout,
            verify_tls=not args.no_verify_tls,
        )
    )

    if args.format == "json":
        output = to_json(findings)
    elif args.format == "csv":
        output = to_csv(findings)
    else:
        output = None

    if output is not None:
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(output, encoding="utf-8")
            print(f"Wrote {args.format} report to {args.output}", file=sys.stderr)
        else:
            print(output)

    if args.format == "summary" or not args.output:
        print_summary(findings)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""`n2scan-ssh` — fan out `node --version` across a host list over SSH and
report CVE-2026-111497 patch status.

    n2scan-ssh hosts.csv
    n2scan-ssh hosts.csv --user secops -i ~/.ssh/fleet --concurrency 25
    n2scan-ssh hosts.csv --format csv -o reports/node-versions.csv

Uses your system `ssh`, so configure auth the usual way (keys, agent,
~/.ssh/config). BatchMode is on by default so a host never hangs on a prompt;
pass --ask to allow interactive auth.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from n2scan import __version__
from n2scan.report import print_summary, to_csv, to_json
from n2scan.ssh import SSHConfig, run_fanout
from n2scan.targets import load_targets


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="n2scan-ssh",
        description="Host-side CVE-2026-111497 patch sweep via SSH (`node --version`).",
    )
    p.add_argument("targets", nargs="?", help="CSV/TSV/txt list of hosts (same format as n2scan).")
    p.add_argument("--user", help="SSH username (else from ssh_config / current user).")
    p.add_argument("--port", type=int, help="SSH port.")
    p.add_argument("-i", "--identity", help="Identity file (private key).")
    p.add_argument("-o", "--ssh-option", action="append", default=[],
                   help="Extra `ssh -o` option, repeatable (e.g. -o StrictHostKeyChecking=accept-new).")
    p.add_argument("--concurrency", type=int, default=10)
    p.add_argument("--connect-timeout", type=int, default=10, help="ssh ConnectTimeout (s).")
    p.add_argument("--overall-timeout", type=int, default=30, help="Hard per-host timeout (s).")
    p.add_argument("--ask", action="store_true", help="Disable BatchMode (allow password prompts).")
    p.add_argument("--no-login-shell", action="store_true",
                   help="Don't wrap in `sh -lc` (skip sourcing profile/nvm PATH).")
    p.add_argument("--ssh-bin", default="ssh", help="Path to the ssh client.")
    p.add_argument("--format", choices=("summary", "json", "csv"), default="summary")
    p.add_argument("--output", help="Write the report here instead of stdout.")
    p.add_argument("--version", action="version", version=f"n2scan {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.targets:
        print("error: a hosts file is required", file=sys.stderr)
        return 2

    targets = load_targets(args.targets)
    if not targets:
        print(f"No hosts parsed from {args.targets}", file=sys.stderr)
        return 2

    cfg = SSHConfig(
        user=args.user,
        port=args.port,
        identity=args.identity,
        connect_timeout=args.connect_timeout,
        overall_timeout=args.overall_timeout,
        batch_mode=not args.ask,
        extra_opts=list(args.ssh_option),
        concurrency=args.concurrency,
        ssh_bin=args.ssh_bin,
        login_shell=not args.no_login_shell,
    )

    print(f"SSH-checking {len(targets)} host(s) with concurrency {cfg.concurrency}...",
          file=sys.stderr)
    findings = asyncio.run(run_fanout(targets, cfg))

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

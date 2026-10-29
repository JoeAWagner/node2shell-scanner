"""Local / host-side check for CVE-2026-111497.

This is the dependable answer to "does this host need patching?": read the
Node.js version actually installed and compare it to the fixed releases. Run
it on the host (or over your own SSH/config-management fan-out). It executes
`node --version` and nothing else — no network, no payloads.

    python -m n2scan.local              # check the node on PATH
    python -m n2scan.local /opt/node/bin/node
    python -m n2scan.local --version 24.22.0
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys

from n2scan.versions import FIXED, node_patch_status
from n2scan.checks.node2shell import CVE, FIXED_HINT


def installed_node_version(node_bin: str = "node") -> str | None:
    """Return the version string from `node --version`, or None if not found."""
    exe = shutil.which(node_bin) or (node_bin if "/" in node_bin else None)
    if not exe:
        return None
    try:
        out = subprocess.run(
            [exe, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    return out.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="n2scan.local",
        description=f"Host-side {CVE} (Node2Shell) patch check.",
    )
    p.add_argument("node_bin", nargs="?", default="node", help="node executable (default: on PATH)")
    p.add_argument("--version", help="Skip execution and evaluate this version string instead.")
    args = p.parse_args(argv)

    version = args.version or installed_node_version(args.node_bin)
    if not version:
        print(f"node not found ({args.node_bin!r}); nothing to evaluate", file=sys.stderr)
        return 2

    affected = node_patch_status(version)
    if affected is True:
        print(f"VULNERABLE: Node {version} is affected by {CVE} — {FIXED_HINT}")
        return 1
    if affected is False:
        print(f"OK: Node {version} is patched against {CVE}")
        return 0
    print(
        f"UNKNOWN: Node {version} major not recognized; fixed trains are "
        f"{', '.join('.'.join(map(str, v)) for v in FIXED.values())}"
    )
    return 3


if __name__ == "__main__":
    raise SystemExit(main())

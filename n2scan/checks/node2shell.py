"""node2shell detector for CVE-2026-111497 (Node2Shell / Brotli2Shell).

Non-destructive by design. The vulnerability is triggered by *malformed*
Brotli input, so a real exploit probe risks crashing the target process. This
check never sends malformed Brotli (or any payload). Instead it tries to read
the Node.js version the site leaks from response banners / error pages and
compares it to the fixed releases.

Remote version disclosure is uncommon, so expect a lot of INCONCLUSIVE: the
dependable check for your own fleet is reading the Node version on each host
(see n2scan.local). This check tells you what can be seen from outside without
touching the vulnerable code path.
"""

from __future__ import annotations

import httpx

from n2scan.checks.base import Check, Finding, Severity, Status
from n2scan.fetch import Fetcher, classify_error
from n2scan.targets import Target
from n2scan.versions import node_patch_status, parse_version

CVE = "CVE-2026-111497"
FIXED_HINT = "fixed in Node 22.23.4 / 24.22.1 / 26.12.1"

# Header values that might carry a version string worth inspecting.
_VERSION_HEADERS = ("x-powered-by", "server", "via", "x-runtime")


class Node2ShellCheck(Check):
    name = "node2shell"
    description = f"Detects {CVE} (Node2Shell) via leaked Node version; non-destructive."

    async def run(self, fetcher: Fetcher, target: Target) -> Finding:
        try:
            fr = await fetcher.get(target)
        except httpx.HTTPError as exc:
            return Finding(
                target=target.host,
                check=self.name,
                status=Status.ERROR,
                evidence=f"request failed ({classify_error(exc)}): {exc}",
                detail={"error_kind": classify_error(exc)},
            )
        resp = fr.response

        # Look for a "node/x.y.z" style banner in the usual headers.
        node_version: tuple[int, int, int] | None = None
        source = ""
        for header in _VERSION_HEADERS:
            value = resp.headers.get(header, "")
            if "node" in value.lower():
                ver = parse_version(value)
                if ver:
                    node_version, source = ver, f"{header}: {value}"
                    break

        detail = {
            "cve": CVE,
            "status_code": resp.status_code,
            "x_powered_by": resp.headers.get("x-powered-by", ""),
            "server": resp.headers.get("server", ""),
            "used_url": fr.used_url,
            "tls_verified": fr.tls_verified,
        }

        if node_version is None:
            return Finding(
                target=target.host,
                check=self.name,
                status=Status.INCONCLUSIVE,
                severity=Severity.INFO,
                evidence=(
                    "no Node version exposed over HTTP; confirm on the host with "
                    f"`node --version` ({FIXED_HINT})"
                ),
                detail=detail,
            )

        detail["node_version"] = ".".join(map(str, node_version))
        detail["version_source"] = source
        affected = node_patch_status(node_version)
        vstr = detail["node_version"]

        if affected is True:
            return Finding(
                target=target.host,
                check=self.name,
                status=Status.VULNERABLE,
                severity=Severity.CRITICAL,
                evidence=f"Node {vstr} is affected by {CVE} ({FIXED_HINT}); from {source}",
                detail=detail,
            )
        if affected is False:
            return Finding(
                target=target.host,
                check=self.name,
                status=Status.NOT_VULNERABLE,
                severity=Severity.INFO,
                evidence=f"Node {vstr} is at/after the fixed release for {CVE}; from {source}",
                detail=detail,
            )
        return Finding(
            target=target.host,
            check=self.name,
            status=Status.INCONCLUSIVE,
            severity=Severity.MEDIUM,
            evidence=f"Node {vstr} (major unrecognized); confirm patch level on host ({FIXED_HINT})",
            detail=detail,
        )

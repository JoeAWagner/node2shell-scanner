"""A benign fingerprint check.

Does a single GET and records what the server volunteers about itself
(status, Server / X-Powered-By headers, and whether its TLS cert validated).
This is passive reconnaissance of your own hosts — the kind of thing `curl -I`
shows — and is useful on its own for spotting Node/Express front doors and
hosts with self-signed or expired certificates.
"""

from __future__ import annotations

import httpx

from n2scan.checks.base import Check, Finding, Severity, Status
from n2scan.fetch import Fetcher, classify_error
from n2scan.targets import Target


class FingerprintCheck(Check):
    name = "fingerprint"
    description = "Records server/version banners and TLS trust from a benign GET."

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
        server = resp.headers.get("server", "")
        powered_by = resp.headers.get("x-powered-by", "")
        looks_node = "express" in powered_by.lower() or "node" in powered_by.lower()
        tls_note = "" if fr.tls_verified else " [TLS cert did not validate]"
        return Finding(
            target=target.host,
            check=self.name,
            status=Status.INCONCLUSIVE,
            severity=Severity.LOW if not fr.tls_verified else Severity.INFO,
            evidence=(
                f"HTTP {resp.status_code}; server={server or '-'}; "
                f"x-powered-by={powered_by or '-'}"
                + (" [node/express]" if looks_node else "")
                + tls_note
            ),
            detail={
                "status_code": resp.status_code,
                "server": server,
                "x_powered_by": powered_by,
                "final_url": str(resp.url),
                "used_url": fr.used_url,
                "tls_verified": fr.tls_verified,
            },
        )

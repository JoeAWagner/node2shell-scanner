"""A benign fingerprint check.

Does a single GET and records what the server volunteers about itself
(status, Server / X-Powered-By headers). This is passive reconnaissance of
your own hosts — the kind of thing `curl -I` shows — and is useful on its own
for spotting Node/Express front doors that may warrant the node2shell check.
"""

from __future__ import annotations

import httpx

from n2scan.checks.base import Check, Finding, Severity, Status
from n2scan.targets import Target


class FingerprintCheck(Check):
    name = "fingerprint"
    description = "Records server/version banners from a single benign GET."

    async def run(self, client: httpx.AsyncClient, target: Target) -> Finding:
        try:
            resp = await client.get(target.url)
        except httpx.HTTPError as exc:
            return Finding(
                target=target.host,
                check=self.name,
                status=Status.ERROR,
                evidence=f"request failed: {exc.__class__.__name__}: {exc}",
            )

        server = resp.headers.get("server", "")
        powered_by = resp.headers.get("x-powered-by", "")
        detail = {
            "status_code": resp.status_code,
            "server": server,
            "x_powered_by": powered_by,
            "final_url": str(resp.url),
        }
        looks_node = "express" in powered_by.lower() or "node" in powered_by.lower()
        return Finding(
            target=target.host,
            check=self.name,
            status=Status.INCONCLUSIVE,
            severity=Severity.INFO,
            evidence=(
                f"HTTP {resp.status_code}; server={server or '-'}; "
                f"x-powered-by={powered_by or '-'}"
                + (" [node/express]" if looks_node else "")
            ),
            detail=detail,
        )

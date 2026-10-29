"""Level-2 Brotli reachability probe for CVE-2026-111497 (opt-in).

This sends a **valid, well-formed** Brotli-compressed request body and infers
whether the host actually decodes Brotli request bodies — i.e. whether the
vulnerable decode path is part of its attack surface. It never sends malformed
Brotli, so it cannot trigger the out-of-bounds write (that is the exploit, and
is out of scope for this tool).

Important about what this can and can't tell you:

  * A positive result means "this host accepted a Brotli-encoded request body
    without rejecting the encoding" — attack surface is likely present. It does
    NOT mean the host is vulnerable; a patched host decodes Brotli perfectly
    well. Always confirm patch status with the Node binary version
    (n2scan.local / `node --version`).
  * Black-box detection of request-body decompression is inherently heuristic:
    a server that silently ignores the body looks the same as one that decodes
    it. We compare the Brotli request against an identity-encoded control to
    reduce (not eliminate) that ambiguity, and we report what we actually saw.

It issues a POST with a tiny body to the probe path (default "/"). POST can
have side effects on some apps, which is why this check is **off by default**
and the path is configurable.
"""

from __future__ import annotations

import httpx

from n2scan.checks.base import Check, Finding, Severity, Status
from n2scan.fetch import Fetcher, classify_error
from n2scan.targets import Target

CVE = "CVE-2026-111497"

# A valid, round-trip-verified Brotli stream of b"n2scan-brotli-reachability-probe".
# Embedded so this check needs no Brotli library and can only ever send
# well-formed data (generated with brotli.compress; see commit history).
_VALID_BROTLI = (
    b"\x1b\x1f\x00\xf8Eox^{\x9c\xdfHQ\xa2\x90\x8a$SQ\xf1\xb2\xd2i9cCw\xbe\x12\xeb\xb4\x80\xc5\x0bp"
)
_PLAINTEXT = b"n2scan-brotli-reachability-probe"

# Status codes that mean the server explicitly won't decode this body.
_REJECTS_ENCODING = {415}
_METHOD_BLOCKED = {405, 501}


class BrotliReachabilityCheck(Check):
    name = "brotli-reach"
    description = (
        f"[opt-in] Sends a VALID Brotli body to infer if the {CVE} decode path "
        "is reachable. Non-destructive; not proof of vulnerability."
    )

    def __init__(self, path: str = "/") -> None:
        self.path = path if path.startswith("/") else "/" + path

    def _probe_target(self, target: Target) -> Target:
        # Reuse the target's scheme-fallback machinery but aim at the probe path.
        base = target.url.rstrip("/")
        url = base + self.path
        return Target(
            raw=target.raw,
            url=url,
            host=target.host,
            scheme_explicit=target.scheme_explicit,
            meta=target.meta,
        )

    async def run(self, fetcher: Fetcher, target: Target) -> Finding:
        probe = self._probe_target(target)
        br_headers = {
            "Content-Encoding": "br",
            "Content-Type": "application/octet-stream",
        }
        try:
            br = await fetcher.get(probe, method="POST", content=_VALID_BROTLI, headers=br_headers)
            # Identity control: same decoded bytes, no Content-Encoding.
            control = await fetcher.get(
                probe,
                method="POST",
                content=_PLAINTEXT,
                headers={"Content-Type": "application/octet-stream"},
            )
        except httpx.HTTPError as exc:
            return Finding(
                target=target.host,
                check=self.name,
                status=Status.ERROR,
                evidence=f"probe failed ({classify_error(exc)}): {exc}",
                detail={"error_kind": classify_error(exc), "cve": CVE},
            )

        br_code = br.response.status_code
        ctrl_code = control.response.status_code
        detail = {
            "cve": CVE,
            "probe_url": br.used_url,
            "brotli_status": br_code,
            "control_status": ctrl_code,
            "tls_verified": br.tls_verified,
            "note": "reachability signal only; confirm patch via node --version",
        }

        # Explicit "I won't decode that" / method not usable here.
        if br_code in _REJECTS_ENCODING:
            return Finding(
                target=target.host, check=self.name, status=Status.INCONCLUSIVE,
                severity=Severity.INFO,
                evidence=f"host rejects Content-Encoding: br (HTTP {br_code}) — decode path not reached here",
                detail=detail,
            )
        if br_code in _METHOD_BLOCKED and ctrl_code in _METHOD_BLOCKED:
            return Finding(
                target=target.host, check=self.name, status=Status.INCONCLUSIVE,
                severity=Severity.INFO,
                evidence=f"POST not accepted at {self.path} (HTTP {br_code}); try a different --brotli-path",
                detail=detail,
            )

        # Brotli body errored where the identity control did not: the server
        # likely tried to process the encoded body. Suggestive of a decode path.
        if br_code >= 500 and ctrl_code < 500:
            return Finding(
                target=target.host, check=self.name, status=Status.INCONCLUSIVE,
                severity=Severity.MEDIUM,
                evidence=(
                    f"server errored on the Brotli body (HTTP {br_code}) but not the identity "
                    f"control (HTTP {ctrl_code}) — a decode path may be present; confirm with node --version"
                ),
                detail=detail,
            )

        # Brotli body accepted without complaint (and handled like the control):
        # the encoding wasn't rejected, so a decode path is plausibly reachable.
        if br_code < 400:
            return Finding(
                target=target.host, check=self.name, status=Status.INCONCLUSIVE,
                severity=Severity.MEDIUM,
                evidence=(
                    f"host accepted a Brotli-encoded body (HTTP {br_code}) — decode path plausibly "
                    "REACHABLE; this is attack surface, not proof. Confirm patch via node --version"
                ),
                detail=detail,
            )

        return Finding(
            target=target.host, check=self.name, status=Status.INCONCLUSIVE,
            severity=Severity.INFO,
            evidence=f"inconclusive (brotli HTTP {br_code}, control HTTP {ctrl_code})",
            detail=detail,
        )

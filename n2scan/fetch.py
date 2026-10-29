"""Shared fetch helper with sensible behaviour for an internal fleet.

Internal hosts routinely present self-signed or private-CA certificates. Strict
TLS verification then fails on every one of them, which is useless when you're
trying to find out their Node version. So the default behaviour here is:

  1. try the request with TLS verification on;
  2. if (and only if) that fails because the certificate didn't validate, retry
     the same URL with verification off and record `tls_verified=False`;
  3. if an https connection fails outright and the target had no explicit
     scheme, fall back to http://.

The cert never silently "passes" — a host reached only via step 2 is flagged,
so you still see which hosts have bad certs while getting the Node result.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from n2scan.targets import Target

# Substrings that mark a TLS trust/verification failure (as opposed to a
# genuine connection problem). httpx surfaces these wrapped in ConnectError.
_TLS_VERIFY_MARKERS = (
    "certificate_verify_failed",
    "certificate verify failed",
    "self-signed certificate",
    "self signed certificate",
    "unable to get local issuer",
    "unable to get issuer",
    "sslcertverificationerror",
    "certificate has expired",
    "hostname mismatch",
    "doesn't match",
)


def is_tls_verify_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(marker in msg for marker in _TLS_VERIFY_MARKERS)


def classify_error(exc: Exception) -> str:
    """Coarse, human-readable bucket for a failed request."""
    if isinstance(exc, (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.PoolTimeout, httpx.WriteTimeout)):
        return "timeout"
    if is_tls_verify_error(exc):
        return "tls-verify"
    if isinstance(exc, httpx.ConnectError):
        return "connect"
    return exc.__class__.__name__


@dataclass
class FetchResult:
    response: httpx.Response
    used_url: str
    tls_verified: bool


class Fetcher:
    """Wraps a verifying and a non-verifying client and applies the fallback."""

    def __init__(
        self,
        secure: httpx.AsyncClient,
        insecure: httpx.AsyncClient | None,
        *,
        verify_default: bool = True,
    ):
        self._secure = secure
        self._insecure = insecure
        self._verify_default = verify_default

    async def get(self, target: Target, method: str = "GET") -> FetchResult:
        last_exc: Exception | None = None
        for url in target.candidate_urls():
            # When verification is globally off, there's only the insecure client.
            if not self._verify_default and self._insecure is not None:
                try:
                    resp = await self._insecure.request(method, url)
                    return FetchResult(resp, url, tls_verified=False)
                except httpx.HTTPError as exc:
                    last_exc = exc
                    continue

            try:
                resp = await self._secure.request(method, url)
                return FetchResult(resp, url, tls_verified=True)
            except httpx.HTTPError as exc:
                last_exc = exc
                if is_tls_verify_error(exc) and self._insecure is not None:
                    try:
                        resp = await self._insecure.request(method, url)
                        return FetchResult(resp, url, tls_verified=False)
                    except httpx.HTTPError as exc2:
                        last_exc = exc2
                # non-TLS failure (e.g. https refused): try the next candidate
                continue

        assert last_exc is not None
        raise last_exc

"""Scan orchestration: run selected checks across all targets, concurrently.

Concurrency is bounded and there's a small per-host politeness so a sweep of
your own fleet doesn't look like (or turn into) a hammering. Everything here
is read-only HTTP from the checks' point of view.

Internal fleets commonly use self-signed / private-CA certs, so by default we
verify TLS but transparently retry a cert-verification failure without
verification (recording that it didn't validate) — see n2scan.http.Fetcher.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Iterable

import httpx

from n2scan.checks.base import Check, Finding, Status
from n2scan.http import Fetcher
from n2scan.targets import Target

DEFAULT_CONCURRENCY = 10
DEFAULT_TIMEOUT = 10.0
DEFAULT_USER_AGENT = "n2scan/0.1 (authorized internal scan; contact: secops@sbu)"


async def _scan_one(
    fetcher: Fetcher,
    semaphore: asyncio.Semaphore,
    target: Target,
    checks: list[Check],
) -> list[Finding]:
    findings: list[Finding] = []
    async with semaphore:
        for check in checks:
            try:
                findings.append(await check.run(fetcher, target))
            except Exception as exc:  # a check must never crash the whole run
                findings.append(
                    Finding(
                        target=target.host,
                        check=check.name,
                        status=Status.ERROR,
                        evidence=f"check raised {exc.__class__.__name__}: {exc}",
                    )
                )
    return findings


def _make_client(concurrency: int, timeout: float, user_agent: str, verify: bool) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        follow_redirects=True,
        timeout=timeout,
        headers={"User-Agent": user_agent},
        limits=httpx.Limits(max_connections=concurrency),
        verify=verify,
    )


async def scan(
    targets: Iterable[Target],
    checks: list[Check],
    *,
    concurrency: int = DEFAULT_CONCURRENCY,
    timeout: float = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
    verify_tls: bool = True,
) -> list[Finding]:
    semaphore = asyncio.Semaphore(concurrency)
    secure = _make_client(concurrency, timeout, user_agent, verify=verify_tls)
    # An insecure client is always available as the cert-failure fallback (and
    # is the only client when verification is globally disabled).
    insecure = _make_client(concurrency, timeout, user_agent, verify=False)
    fetcher = Fetcher(secure, insecure, verify_default=verify_tls)

    async with contextlib.AsyncExitStack() as stack:
        await stack.enter_async_context(secure)
        await stack.enter_async_context(insecure)
        tasks = [_scan_one(fetcher, semaphore, t, checks) for t in targets]
        results = await asyncio.gather(*tasks)
    return [f for group in results for f in group]

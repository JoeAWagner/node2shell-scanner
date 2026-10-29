"""Scan orchestration: run selected checks across all targets, concurrently.

Concurrency is bounded and there's a small per-host politeness so a sweep of
your own fleet doesn't look like (or turn into) a hammering. Everything here
is read-only HTTP from the checks' point of view.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable

import httpx

from n2scan.checks.base import Check, Finding, Status
from n2scan.targets import Target

DEFAULT_CONCURRENCY = 10
DEFAULT_TIMEOUT = 10.0
DEFAULT_USER_AGENT = "n2scan/0.1 (authorized internal scan; contact: secops@sbu)"


async def _scan_one(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    target: Target,
    checks: list[Check],
) -> list[Finding]:
    findings: list[Finding] = []
    async with semaphore:
        for check in checks:
            try:
                findings.append(await check.run(client, target))
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
    limits = httpx.Limits(max_connections=concurrency)
    headers = {"User-Agent": user_agent}
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=timeout,
        headers=headers,
        limits=limits,
        verify=verify_tls,
    ) as client:
        tasks = [_scan_one(client, semaphore, t, checks) for t in targets]
        results = await asyncio.gather(*tasks)
    return [f for group in results for f in group]

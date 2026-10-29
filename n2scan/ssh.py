"""SSH fan-out: read the real Node.js version on each host and compare it to
the CVE-2026-111497 fixed releases.

This is the dependable verdict for your own fleet. Remote HTTP scanning can
rarely see the Node version; reading it on the host can't be fooled. It runs
exactly one read-only command per host — `node --version` — over your system
`ssh`, so it uses your existing keys/agent/ssh_config and stores no credentials.

Non-destructive: it never installs, changes, or restarts anything.

Limitation (v1): it checks the `node` on the remote login PATH. A host with
several Node installs (nvm, containers, a service pinned to its own build) may
run a different binary than the default one; treat a clean result as "the
default node is patched," and confirm service-specific builds separately.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from n2scan.checks.base import Finding, Severity, Status
from n2scan.checks.node2shell import CVE, FIXED_HINT
from n2scan.targets import Target
from n2scan.versions import node_patch_status, parse_version

CHECK_NAME = "node2shell-ssh"
_NO_NODE = "__N2SCAN_NO_NODE__"

# Run under a login shell so nvm/profile PATH entries are picked up. Emits the
# version on its own line, or a sentinel if node isn't found. Read-only.
REMOTE_CMD = (
    f"command -v node >/dev/null 2>&1 && node --version || echo {_NO_NODE}"
)


@dataclass
class SSHConfig:
    user: str | None = None
    port: int | None = None
    identity: str | None = None
    connect_timeout: int = 10
    overall_timeout: int = 30
    batch_mode: bool = True
    extra_opts: list[str] = field(default_factory=list)
    concurrency: int = 10
    ssh_bin: str = "ssh"
    login_shell: bool = True


def build_ssh_argv(host: str, cfg: SSHConfig) -> list[str]:
    argv = [cfg.ssh_bin]
    if cfg.batch_mode:
        argv += ["-o", "BatchMode=yes"]
    argv += ["-o", f"ConnectTimeout={cfg.connect_timeout}"]
    if cfg.port:
        argv += ["-p", str(cfg.port)]
    if cfg.identity:
        argv += ["-i", cfg.identity]
    for opt in cfg.extra_opts:
        argv += ["-o", opt]
    dest = f"{cfg.user}@{host}" if cfg.user else host
    remote = f"sh -lc {_shquote(REMOTE_CMD)}" if cfg.login_shell else REMOTE_CMD
    argv += [dest, remote]
    return argv


def _shquote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


# Substrings that indicate an SSH/transport failure rather than a host answer.
_SSH_FAIL_MARKERS = (
    "permission denied",
    "connection refused",
    "connection timed out",
    "could not resolve",
    "no route to host",
    "host key verification failed",
    "operation timed out",
    "connection closed",
    "network is unreachable",
)


def classify_node_output(host: str, rc: int, stdout: str, stderr: str) -> Finding:
    """Turn one host's ssh result into a Finding. Pure, so it's unit-testable."""
    out = stdout.strip()
    err = stderr.strip()
    low_err = err.lower()

    # node present and reported a version?
    version = parse_version(out) if out and _NO_NODE not in out else None
    if version is not None:
        vstr = ".".join(map(str, version))
        detail = {"cve": CVE, "node_version": vstr, "host": host}
        affected = node_patch_status(version)
        if affected is True:
            return Finding(host, CHECK_NAME, Status.VULNERABLE, Severity.CRITICAL,
                           f"Node {vstr} is affected by {CVE} ({FIXED_HINT})", detail)
        if affected is False:
            return Finding(host, CHECK_NAME, Status.NOT_VULNERABLE, Severity.INFO,
                           f"Node {vstr} is patched against {CVE}", detail)
        return Finding(host, CHECK_NAME, Status.INCONCLUSIVE, Severity.MEDIUM,
                       f"Node {vstr} major unrecognized; confirm manually ({FIXED_HINT})", detail)

    # node explicitly not found on the host
    if _NO_NODE in out or (rc == 0 and not out):
        return Finding(host, CHECK_NAME, Status.INCONCLUSIVE, Severity.INFO,
                       "node not found on host (not a Node host, or not on login PATH)",
                       {"cve": CVE, "host": host, "node_version": None})

    # otherwise: an SSH/transport or shell failure
    kind = "ssh" if (rc == 255 or any(m in low_err for m in _SSH_FAIL_MARKERS)) else "remote"
    msg = err or out or f"exit code {rc}"
    return Finding(host, CHECK_NAME, Status.ERROR, Severity.INFO,
                   f"ssh/host error ({kind}): {msg}",
                   {"cve": CVE, "host": host, "error_kind": kind, "rc": rc})


async def check_host(host: str, cfg: SSHConfig, semaphore: asyncio.Semaphore) -> Finding:
    argv = build_ssh_argv(host, cfg)
    async with semaphore:
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            return Finding(host, CHECK_NAME, Status.ERROR, Severity.INFO,
                           f"ssh binary not found ({cfg.ssh_bin!r})",
                           {"error_kind": "ssh", "host": host})
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=cfg.overall_timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return Finding(host, CHECK_NAME, Status.ERROR, Severity.INFO,
                           f"ssh timed out after {cfg.overall_timeout}s",
                           {"error_kind": "timeout", "host": host})
    return classify_node_output(
        host, proc.returncode, out.decode(errors="replace"), err.decode(errors="replace")
    )


async def run_fanout(targets: list[Target], cfg: SSHConfig) -> list[Finding]:
    semaphore = asyncio.Semaphore(cfg.concurrency)
    tasks = [check_host(t.host, cfg, semaphore) for t in targets]
    return await asyncio.gather(*tasks)

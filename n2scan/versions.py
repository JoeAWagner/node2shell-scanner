"""Node.js version logic for CVE-2026-111497 (Node2Shell / Brotli2Shell).

The flaw is an out-of-bounds write in the Brotli decoder compiled into the
Node.js binary. Because it's in the binary (not an npm package), the fix is a
Node runtime upgrade. Fixed releases:

    22.x  ->  22.23.4
    24.x  ->  24.22.1
    26.x  ->  26.12.1

Anything at or above the fix *on its own major line* is patched. Majors with
no listed fix here (e.g. old/EOL lines) are treated as vulnerable-if-affected
and surfaced for manual confirmation rather than silently cleared.

Refs:
    https://www.rapid7.com/blog/post/etr-cve-2026-111497-critical-out-of-bounds-write-in-the-node-js-brotli-decoder/
    https://osv.dev/vulnerability/CVE-2026-111497
"""

from __future__ import annotations

import re

# major -> first fixed (major, minor, patch)
FIXED: dict[int, tuple[int, int, int]] = {
    22: (22, 23, 4),
    24: (24, 22, 1),
    26: (26, 12, 1),
}

# Majors known to contain the vulnerable decoder but with no clean fixed line
# (EOL etc.). Present => affected; upgrade to a supported fixed release.
KNOWN_AFFECTED_MAJORS = {23, 25}

_VERSION_RE = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")


def parse_version(text: str) -> tuple[int, int, int] | None:
    """Pull an (x, y, z) version tuple out of arbitrary text, if present."""
    m = _VERSION_RE.search(text)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def node_patch_status(version: str | tuple[int, int, int]) -> bool | None:
    """Is this Node version affected by CVE-2026-111497?

    Returns:
        True  -> affected (needs patching)
        False -> patched / not affected
        None  -> can't decide from this version alone (unknown major)
    """
    ver = parse_version(version) if isinstance(version, str) else version
    if ver is None:
        return None
    major = ver[0]
    if major in FIXED:
        return ver < FIXED[major]
    if major in KNOWN_AFFECTED_MAJORS:
        return True
    # Majors at/after the first fixed train (e.g. 27+) ship the fix; older
    # unlisted majors (<=21) are EOL and should be upgraded regardless.
    if major <= 21:
        return True
    return None

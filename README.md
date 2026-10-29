# n2scan

A small, **authorized** detect-and-report scanner for a list of web properties
you own (SBU infrastructure). You give it a list of hosts — e.g. a Google Sheet
exported as CSV — and it tells you **which ones look like they still need
patching** for a given issue. It does not exploit anything, bring anything
down, or open a shell: each check sends a benign probe and classifies the
response, and you act on the report.

> Scope: run this only against hosts your organization owns or is explicitly
> authorized to test. It is built for internal remediation tracking.

## Install

```bash
pip install -e .
```

## Usage

Export your Google Sheet as CSV (File → Download → Comma-separated values) with
a column named `url` or `host`, then:

```bash
# run every check, print a summary
n2scan targets.csv

# just the CVE check, write a spreadsheet-friendly report
n2scan targets.csv --check node2shell --format csv -o reports/scan.csv

# internal hosts behind a private CA
n2scan targets.csv --no-verify-tls
```

List what checks exist:

```bash
n2scan --list-checks
```

## Input formats

- **CSV/TSV with a header** — a column named one of `url, host, hostname,
  target, address, site` is used; other columns are carried through into the
  JSON report.
- **Plain text** — one host or URL per line. Lines starting with `#` are
  comments.

Bare hosts get `https://` added automatically. Targets are de-duplicated by host.

## Checks

| name | default | what it does |
|---|---|---|
| `fingerprint` | yes | Single benign GET; records `Server` / `X-Powered-By` banners and TLS trust. Flags Node/Express front doors. |
| `node2shell` | yes | Detects exposure to **CVE-2026-111497** by parsing a leaked Node version. Reads headers only — sends no Brotli. |
| `brotli-reach` | **opt-in** | Sends a **valid** Brotli request body to infer whether the Brotli *decode path* is reachable (attack surface). Never sends malformed data, so it can't trigger the bug. A positive is a prioritization signal, **not** proof of vulnerability — confirm with `node --version`. Issues a POST, so it's off by default. |

```bash
# opt in to the reachability probe (POSTs to / by default)
n2scan targets.csv --check node2shell --check brotli-reach
n2scan targets.csv --check brotli-reach --brotli-path /api/upload
```

### What actually confirms patch status

Because the fix is in the compiled Node binary, the only reliable vulnerable/patched
verdict comes from the version on the host:

```bash
python -m n2scan.local            # checks `node --version` vs the fixed releases
```

The remote checks (`node2shell`, `brotli-reach`) help you *find and prioritize* hosts;
`n2scan.local` gives the verdict.

Each finding has a status: `vulnerable`, `not_vulnerable`, `inconclusive`, or
`error`, plus the evidence behind it.

## Design rules for checks

Checks are **detectors only**. A check may observe (status codes, headers,
version banners, a benign no-op endpoint) but must never send a payload that
executes commands, writes files, changes data, or establishes a shell. The
purpose is to produce a patch list, not to exploit your own hosts.

## Development

```bash
pip install -e '.[dev]'
pytest
```

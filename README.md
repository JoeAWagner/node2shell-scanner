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

| name | what it does |
|---|---|
| `fingerprint` | Single benign GET; records `Server` / `X-Powered-By` banners. Flags Node/Express front doors. |
| `node2shell` | Detects exposure to **CVE-2026-111497** (see below). Non-destructive version/behaviour check. |

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

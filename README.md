# cyberscanner

**Open-source vulnerability scanner for Python and JavaScript projects.**
No account. No cloud. No cost. Just `pip install` and scan.

[![PyPI version](https://img.shields.io/pypi/v/cyberscanner.svg)](https://pypi.org/project/cyberscanner/)
[![Python versions](https://img.shields.io/pypi/pyversions/cyberscanner.svg)](https://pypi.org/project/cyberscanner/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-39%20passed-brightgreen)](https://github.com/your-org/cyberscanner)

---

## Why cyberscanner?

Every Python project eventually hits this wall: you want to scan your dependencies for known CVEs, but the good tools (Snyk, Mend) require a paid account or a cloud signup, and the free tools each have a critical gap:

- **OSV-Scanner** is a Go binary — not pip-installable, poor UX for Python devs
- **pip-audit** only scans Python, misses JS/Node, has no secrets detection
- **safety** has a limited free tier and requires an account for full data
- **Trivy** is excellent but again a Go binary, no pip install, no Python API

`cyberscanner` is the tool that should have existed: fully pip-installable, works as both a CLI and importable Python library, scans Python **and** JavaScript, detects hardcoded secrets, stores every scan locally for history and diffing, and pulls from multiple free advisory databases for better coverage.

---

## How it compares

| Feature | Snyk | OSV-Scanner | pip-audit | safety | Trivy | **cyberscanner** |
|---------|:----:|:-----------:|:---------:|:------:|:-----:|:----------------:|
| `pip install` | No | No (Go binary) | Yes | Yes | No (Go binary) | **Yes** |
| Completely free & open source | No (paid) | Yes | Yes | Limited | Yes | **Yes** |
| Python dependency scanning | Yes | Yes | Yes | Yes | Yes | **Yes** |
| JavaScript / Node scanning | Yes | Yes | No | No | Yes | **Yes** |
| Secret / credential detection | Yes | No | No | No | Yes | **Yes** |
| Local scan history + diffing | Yes | No | No | No | No | **Yes** |
| Handles unpinned deps | Yes | No | Partial | Yes | Partial | **Yes** |
| Python library API | No | No | Limited | Limited | No | **Yes** |
| SARIF output (GitHub integration) | Yes | Yes | No | No | Yes | **Yes** |
| HTML report | Yes | No | No | No | Yes | **Yes** |
| Fix / upgrade suggestions | Yes | No | Yes | Yes | No | **Yes** |
| Multi-source advisory data | Yes | OSV only | PyPI Advisory | PyPI DB | NVD + more | **OSV + GitHub** |
| No cloud account needed | No | Yes | Yes | No | Yes | **Yes** |
| CI fail-on severity flag | Yes | Yes | Yes | Yes | Yes | **Yes** |

**The short version:** cyberscanner does what Snyk does for individual developers and small teams, for free, without a signup, installable in one command.

---

## Installation

```bash
pip install cyberscanner
```

That's it. No Go toolchain. No Docker. No account.

**Minimum requirements:** Python 3.8+

---

## Quick start

```bash
# Scan your current project
cyberscanner scan .

# Scan a specific path
cyberscanner scan /path/to/project

# Secrets-only scan
cyberscanner secrets .

# View scan history
cyberscanner history

# See what changed since the last scan (new vulns / fixed vulns)
cyberscanner history --diff
```

---

## CLI reference

### `cyberscanner scan`

Scans for vulnerable dependencies (Python + JavaScript) and hardcoded secrets.

```
cyberscanner scan [PATH] [OPTIONS]

Options:
  --format, -f    Output format: table (default) | json | sarif | html
  --output, -o    Write output to a file instead of stdout
  --fail-on       Exit with code 1 if any vulnerability at this severity or
                  above is found. Values: critical | high | medium | low
  --no-secrets    Skip secret/credential detection
  --no-deps       Skip dependency scanning (only scan secrets)
```

**Examples:**

```bash
# Rich terminal table (default)
cyberscanner scan .

# JSON output — pipe into jq, scripts, CI tools
cyberscanner scan . --format json | jq '.summary'

# SARIF for GitHub Code Scanning upload
cyberscanner scan . --format sarif -o results.sarif

# HTML report saved to a file
cyberscanner scan . --format html -o report.html

# CI mode: fail the build on any high or critical finding
cyberscanner scan . --fail-on high

# Dependency scan only, no secrets
cyberscanner scan . --no-secrets
```

### `cyberscanner secrets`

Scans files for hardcoded secrets and credentials. Faster than a full scan when you only need secret detection.

```bash
cyberscanner secrets .
cyberscanner secrets . --format json
```

**Detected secret types:**

| Pattern | Severity |
|---------|----------|
| AWS Access Key ID (`AKIA...`) | Critical |
| AWS Secret Access Key | Critical |
| GitHub Personal Access Token (`ghp_...`) | Critical |
| GitHub Fine-grained Token (`github_pat_...`) | Critical |
| OpenAI API Key (`sk-...`) | Critical |
| Anthropic API Key (`sk-ant-...`) | Critical |
| Stripe Live Secret Key (`sk_live_...`) | Critical |
| Private Key Block (`-----BEGIN * PRIVATE KEY-----`) | Critical |
| Database URLs with embedded credentials | Critical |
| GitHub OAuth / App tokens | High |
| Google API Key (`AIza...`) | High |
| Slack Bot/User/App tokens | High |
| HuggingFace tokens (`hf_...`) | High |
| SendGrid API Key | High |
| Stripe Publishable Key (`pk_live_...`) | High |
| Bearer tokens in code | High |
| JWT tokens | Medium |
| Generic secret/API key assignments | Medium |

Secrets are **redacted** in output — only the first 4 and last 4 characters are shown. The full value is never logged or stored.

Files inside `node_modules/`, `.git/`, `__pycache__/`, `venv/`, `dist/`, and binary file types are automatically skipped.

### `cyberscanner history`

View past scans stored in your local SQLite database (`~/.cyberscanner/history.db`).

```bash
# List last 10 scans
cyberscanner history

# List last 25 scans
cyberscanner history --limit 25

# Show full details for a specific scan
cyberscanner history --id <scan-id>

# Diff: what vulnerabilities appeared or were fixed since the last scan
cyberscanner history --diff

# Diff filtered to a specific project path
cyberscanner history --diff --path /path/to/project
```

The `--diff` output shows two tables: **New Vulnerabilities** (appeared in the latest scan but not in the previous one) and **Fixed Vulnerabilities** (present in the previous scan but gone in the latest). This is how you track whether your dependency upgrades actually resolved the findings.

---

## Python API

`cyberscanner` is designed to be used as a library just as naturally as a CLI tool.

```python
from cyberscanner import Scanner

# Scan current directory
scanner = Scanner(".")
results = scanner.scan()

# Access findings
for vuln in results.vulnerabilities:
    print(f"{vuln.package}@{vuln.version} — {vuln.vuln_id} ({vuln.severity.value})")
    if vuln.fixed_in:
        print(f"  Fix: upgrade to {', '.join(vuln.fixed_in)}")

for secret in results.secrets:
    print(f"{secret.pattern_name} at {secret.file_path}:{secret.line_no}")

# Summary counts
print(results.summary.critical)   # int
print(results.summary.high)
print(results.summary.total_secrets)

# Export
json_str = results.to_json()       # JSON string
d = results.to_dict()              # plain dict

# Selective scanning
results = scanner.scan(scan_secrets=False)   # deps only
results = scanner.scan(scan_deps=False)      # secrets only
```

**Available models** (importable from `cyberscanner`):

```python
from cyberscanner import Scanner, ScanResult, Vulnerability, SecretFinding, Package, Severity
```

| Class | Description |
|-------|-------------|
| `Scanner` | Main entry point. `Scanner(path).scan()` returns a `ScanResult` |
| `ScanResult` | Full result: vulnerabilities, secrets, summary, packages found |
| `Vulnerability` | A CVE or GHSA finding: package, version, severity, CVSS score, fix versions |
| `SecretFinding` | A detected secret: file path, line number, pattern name, redacted match |
| `Package` | A parsed dependency: name, version, ecosystem, pinned status |
| `Severity` | Enum: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN` |

---

## Output formats

### Table (default)

Color-coded terminal output using [Rich](https://github.com/Textualize/rich). Severity is highlighted: Critical in bold red, High in red, Medium in yellow, Low in cyan.

### JSON

Machine-readable output — suitable for piping into other tools, storing artifacts, or parsing in CI scripts.

```bash
cyberscanner scan . --format json | jq '.summary.critical'
cyberscanner scan . --format json -o scan-results.json
```

### SARIF

[SARIF 2.1.0](https://sarifweb.azurewebsites.net/) output for direct integration with GitHub Code Scanning, Azure DevOps, and other SARIF-aware CI/CD systems.

```bash
cyberscanner scan . --format sarif -o results.sarif
```

Upload to GitHub Code Scanning:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### HTML

A self-contained dark-themed HTML report with a summary dashboard, vulnerability table, and secrets table. No external CDN dependencies — the entire report is a single file.

```bash
cyberscanner scan . --format html -o report.html
```

---

## What gets scanned

### Python

| File | Notes |
|------|-------|
| `requirements.txt` | All variants: `requirements*.txt`, `requirements/*.txt` |
| `requirements-dev.txt` | Dev/test requirements |
| `pyproject.toml` | PEP 621 `[project.dependencies]` and Poetry `[tool.poetry.dependencies]` |
| `setup.py` | Extracts `install_requires` |
| `Pipfile` | Both `[packages]` and `[dev-packages]` |

**Unpinned dependencies:** If a package has no pinned version (e.g., just `requests` with no `==` specifier), cyberscanner fetches the latest published version from PyPI and scans that, clearly marking the result as `unpinned`.

### JavaScript / Node.js

| File | Notes |
|------|-------|
| `package.json` | `dependencies` and `devDependencies` |
| `package-lock.json` | Lock file v1, v2, and v3 — exact resolved versions |
| `yarn.lock` | Yarn classic and berry |

When a lock file is present, exact resolved versions are used — the most accurate possible scan. When only `package.json` is present, version ranges are used.

---

## Advisory data sources

cyberscanner queries two free sources and deduplicates the combined results by CVE/GHSA ID.

---

### 1. OSV.dev — Primary source

**Endpoint:** `https://api.osv.dev` · **Auth:** None · **Cost:** Free

[Google's Open Source Vulnerability database](https://osv.dev/) is itself an aggregator — a single query hits data from all of these upstream sources:

| Upstream database | What it covers |
|-------------------|---------------|
| **GitHub Advisory Database (GHSA)** | All major ecosystems; includes CVSS scores and fix versions |
| **PyPI Advisory Database (PYSEC)** | Python-specific advisories maintained by the Python Packaging Authority |
| **npm Advisory Database** | JavaScript / Node.js packages |
| **NVD (National Vulnerability Database)** | NIST's canonical CVE registry — cross-referenced for all entries |
| **Go Vulnerability Database** | Go modules |
| **RustSec Advisory Database** | Rust crates |
| **Maven / OSS-Index** | Java / JVM packages |
| **RubyGems Advisory Database** | Ruby gems |

**How the OSV query works (two-step):**

OSV's batch endpoint (`POST /v1/querybatch`) matches your packages against its database and returns a list of vulnerability IDs. cyberscanner then fetches the full record for each unique ID (`GET /v1/vulns/{id}`) to retrieve severity scores, fix versions, CVSS vectors, and references. This two-step design is necessary because the batch endpoint only returns stubs — the full data lives on the individual record endpoint.

```
Step 1:  POST /v1/querybatch  →  [{id: "GHSA-xxx"}, {id: "PYSEC-yyy"}, ...]
Step 2:  GET  /v1/vulns/{id}  →  full record (CVSS, affected ranges, fix version, aliases)
```

**Note on severity data:** GHSA entries always include CVSS scores (returned as full vector strings like `CVSS:3.1/AV:N/AC:L/...`). PYSEC entries (PyPI-specific advisories) often do not include CVSS — cyberscanner falls back to the `database_specific.severity` string (`HIGH`, `MODERATE`, etc.) when a numeric score is absent.

---

### 2. GitHub Advisory Database — Secondary source

**Endpoint:** `https://api.github.com/graphql` · **Auth:** Optional `GITHUB_TOKEN` · **Cost:** Free

The [GitHub Advisory Database](https://github.com/advisories) queried via GraphQL. This source provides value for:
- Advisories disclosed on GitHub before they propagate to OSV
- Better remediation detail and patch information for GHSA entries
- Additional CVSS scoring for some entries

Enable by setting a GitHub token in your environment:

```bash
export GITHUB_TOKEN=ghp_your_token_here   # or GH_TOKEN
cyberscanner scan .
```

If no token is present, this source is silently skipped — scans still work using OSV alone.

---

### Deduplication and merging

When both sources return the same vulnerability, cyberscanner:

1. Identifies duplicates by **canonical ID** — CVE IDs take priority over GHSA IDs over PYSEC IDs
2. Keeps the entry with the **higher severity** rating
3. **Merges** fix versions and aliases from both records so you get the most complete remediation information

---

### What is NOT included (yet)

| Source | Gap it would fill | Roadmap |
|--------|------------------|---------|
| **NVD direct** | EPSS exploitability scores — tells you if a CVE is actively exploited in the wild | Phase 2 |
| **OSS-Index (Sonatype)** | Better Java/Maven coverage | Phase 3 |
| **Safety DB** | Python-focused, curated by PyUp — requires paid account for full data | N/A |
| **Snyk Intel** | Proprietary, not open access | N/A |

In practice, OSV alone gives **95%+ coverage** for Python and JavaScript projects because it already aggregates GHSA + PYSEC + NVD cross-references into a single query.

---

## CI/CD integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install cyberscanner
        run: pip install cyberscanner

      - name: Scan for vulnerabilities
        run: cyberscanner scan . --fail-on high --format sarif -o results.sarif

      - name: Upload to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security-scan:
  image: python:3.11-slim
  script:
    - pip install cyberscanner
    - cyberscanner scan . --fail-on high --format json -o scan.json
  artifacts:
    when: always
    paths:
      - scan.json
```

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: cyberscanner-secrets
        name: Scan for hardcoded secrets
        entry: cyberscanner secrets
        language: system
        pass_filenames: false
        args: ["."]
```

---

## Local history and scan diffing

Every scan is automatically saved to a local SQLite database at `~/.cyberscanner/history.db`. No data is sent to any server.

This enables tracking that free tools don't offer:

```bash
# See vulnerability trends across all scans of a project
cyberscanner history --path /my/project --limit 20

# Find out exactly what changed after upgrading dependencies
# Run scan before upgrade, upgrade packages, run scan again, then:
cyberscanner history --diff --path /my/project
```

The diff output shows:
- **New vulnerabilities** — appeared in the most recent scan but not the previous one
- **Fixed vulnerabilities** — present in the previous scan but resolved in the most recent one

This is the feedback loop for knowing whether `pip upgrade` actually fixed the CVEs you were targeting.

---

## Architecture

```
cyberscanner/
  scanner/
    python.py        ← Parses requirements.txt, pyproject.toml, setup.py, Pipfile
    javascript.py    ← Parses package.json, package-lock.json, yarn.lock
    secrets.py       ← 25 regex patterns compiled at import time
  advisories/
    osv.py           ← OSV.dev batch REST API client
    github.py        ← GitHub Advisory GraphQL client (optional token)
    aggregator.py    ← Merges sources, deduplicates by CVE/GHSA ID
  db/
    storage.py       ← SQLite schema, save/query/diff
  report/
    table.py         ← Rich terminal output
    json_report.py   ← JSON serialization via Pydantic
    sarif.py         ← SARIF 2.1.0 builder
    html.py          ← Self-contained HTML report
  models.py          ← Pydantic v2 data models
  cli.py             ← Typer CLI (scan / secrets / history)
  __init__.py        ← Public Python API (Scanner class)
```

**Dependencies:** `typer`, `httpx`, `pydantic>=2`, `packaging`, `rich`, `tomli` (Python < 3.11 only). All pure Python — no compiled extensions.

---

## Roadmap

**Phase 2 — Better data**
- NVD (National Vulnerability Database) as a third advisory source
- EPSS exploitability scoring — tells you if a CVE is actually being exploited in the wild
- Vulnerability age — flag CVEs that have been unpatched for X days

**Phase 3 — More ecosystems**
- Go (`go.mod`, `go.sum`)
- Rust (`Cargo.toml`, `Cargo.lock`)
- Java (`pom.xml`, `build.gradle`)
- Ruby (`Gemfile.lock`)

**Phase 4 — Automation**
- SBOM generation (CycloneDX and SPDX formats)
- License compliance checking
- Policy engine — define rules like "fail if any Critical CVE older than 30 days"
- `--fix` flag — generate the exact upgrade commands to resolve findings
- VS Code extension

**Phase 5 — Teams**
- Shared history across a team (opt-in, self-hosted)
- Slack/webhook notifications when new CVEs affect your dependencies
- Scheduled background scanning

---

## Contributing

Contributions are welcome. To get started:

```bash
git clone https://github.com/your-org/cyberscanner
cd cyberscanner
pip install -e ".[dev]"
pytest tests/
```

Project structure follows the `src/` layout. All code targets Python 3.8+. Tests use `pytest` with `unittest.mock` for network calls — no real API calls in the test suite.

**Adding a new secret pattern:** Open `src/cyberscanner/scanner/secrets.py` and add an entry to `_RAW_PATTERNS`. Each entry is `(name, regex, Severity)`. Add a corresponding test in `tests/test_secrets.py`.

**Adding a new ecosystem:** Create a new scanner class in `src/cyberscanner/scanner/` extending `BaseScanner`, implement `detect()` and `parse()`, and register it in `src/cyberscanner/__init__.py`.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Acknowledgements

- [OSV.dev](https://osv.dev/) — Google's open-source vulnerability database
- [GitHub Advisory Database](https://github.com/advisories) — GHSA advisory data
- [Rich](https://github.com/Textualize/rich) — terminal output
- [Typer](https://typer.tiangolo.com/) — CLI framework
- [Pydantic](https://docs.pydantic.dev/) — data validation

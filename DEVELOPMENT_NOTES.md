# cyberscanner — Development Recap

## Why we built this

Snyk costs money. The free alternatives each have a critical gap:
- **OSV-Scanner** — Go binary, not pip-installable, no Python API, no history
- **pip-audit** — Python only, no JS, no secrets, no history
- **safety** — limited free tier, requires account
- **Trivy** — Go binary, excellent but no pip install

**Goal:** A single `pip install` that covers Python + JS deps, secrets, history/diffing, and outputs SARIF/HTML — with no cloud account needed.

---

## What was built (v0.1.0)

### Core architecture
```
src/cyberscanner/
  __init__.py          Public Python API — Scanner class
  cli.py               Typer CLI: scan / secrets / history commands
  models.py            Pydantic v2 models: Vulnerability, SecretFinding, ScanResult
  scanner/
    python.py          requirements.txt, pyproject.toml, setup.py, Pipfile
    javascript.py      package.json, package-lock.json, yarn.lock
    secrets.py         25 regex patterns — AWS, GitHub, Stripe, OpenAI, DB URLs, JWTs...
  advisories/
    osv.py             OSV.dev two-step API client
    github.py          GitHub Advisory GraphQL (optional GITHUB_TOKEN)
    aggregator.py      Deduplicates by CVE/GHSA ID, merges severity + fix versions
  db/storage.py        SQLite at ~/.cyberscanner/history.db — save, query, diff
  report/
    table.py           Rich terminal table with severity colours
    json_report.py     JSON via Pydantic serialization
    sarif.py           SARIF 2.1.0 for GitHub Code Scanning
    html.py            Self-contained dark-themed HTML report
```

### Test suite
- `tests/` — 41 unit tests, fully mocked, no network, runs in ~1.3s
- `smoke_tests/` — 99 tests total: CLI subprocess, Python API, live OSV API, output format validation
  - Non-live: 51 tests, no network, runs in ~5s
  - Live: 48 tests, hits real OSV API, runs in ~50s

### CLI commands
```bash
cyberscanner scan .                         # full scan, Rich table
cyberscanner scan . --format json           # JSON to stdout
cyberscanner scan . --format sarif          # SARIF 2.1.0
cyberscanner scan . --format html -o r.html # HTML report
cyberscanner scan . --fail-on high          # CI mode, exit 1
cyberscanner secrets .                      # secrets only
cyberscanner history                        # past scans
cyberscanner history --diff                 # new vs fixed vulns
```

### Python API
```python
from cyberscanner import Scanner
results = Scanner(".").scan()
results.vulnerabilities    # list[Vulnerability]
results.secrets            # list[SecretFinding]
results.to_json()          # JSON string
results.to_dict()          # plain dict
```

---

## Key decisions

### OSV two-step API
OSV's batch endpoint (`POST /v1/querybatch`) now returns only `{id, modified}` stubs —
NOT the full vulnerability object. Full data (severity, CVSS, fix versions, affected ranges)
requires a second `GET /v1/vulns/{id}` call per unique CVE ID.

This was discovered during smoke testing when all severities returned as `UNKNOWN` and
all `fixed_in` arrays were empty. The original single-call implementation was rewritten
to do the two-step fetch, with deduplication so each unique vuln ID is fetched once.

### CVSS severity parsing
GHSA entries return severity as a full CVSS vector string:
`"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"` — NOT a bare score number.
The base score is not embedded in the vector; cyberscanner falls back to
`database_specific.severity` (string: "HIGH", "MODERATE", etc.) when no bare
numeric score is present. PYSEC entries (PyPI advisories) often have neither —
these return `Severity.UNKNOWN`.

### Windows cp1252 encoding
Three separate encoding issues on Windows (all fixed):
1. `✓` in terminal output → replaced with `[OK]`
2. `→` and `·` in table output → replaced with `->` and `|`
3. `print(out)` for JSON/SARIF output crashes on Unicode chars in OSV descriptions
   (e.g. `⁠` WORD JOINER in npm advisory text) → replaced with
   `sys.stdout.buffer.write(out.encode("utf-8"))`
4. Subprocess tests reading UTF-8 output through cp1252 pipe → fixed by passing
   `encoding="utf-8"` and `PYTHONUTF8=1` env var to subprocess.run()

### GitHub push protection
First push was blocked because test fixture files contain fake Stripe keys in
`sk_live_` format — GitHub's secret scanner correctly flagged them.
They were bypassed via GitHub's "mark as test" flow at:
`/security/secret-scanning/unblock-secret/...`
These are INTENTIONAL fake credentials for testing our own secret scanner.

---

## Advisory data sources

| Source | Type | Auth | What it provides |
|--------|------|------|-----------------|
| OSV.dev | Primary | None | Aggregates GHSA, PYSEC, npm advisories, NVD cross-refs, Go, Rust, Maven, Ruby |
| GitHub Advisory DB | Secondary | Optional `GITHUB_TOKEN` | GHSA entries with CVSS, sometimes newer than OSV |

**OSV aggregates these upstream databases:**
GHSA (GitHub) · PYSEC (PyPI) · npm Advisory · NVD · Go Vuln DB · RustSec · Maven · RubyGems

**Not yet included:** NVD direct (for EPSS scores), OSS-Index (Java), Safety DB (paid)

---

## Test count summary

| Suite | Count | Network | Time |
|-------|-------|---------|------|
| Unit tests (`tests/`) | 41 | No | ~1.3s |
| Smoke non-live (`smoke_tests/ -m "smoke and not live"`) | 51 | No | ~5s |
| Smoke live (`smoke_tests/ -m live`) | 48 | Yes (OSV API) | ~50s |
| **Total** | **140** | | |

---

## Build & publish

```bash
# Build
python -m build                        # creates dist/*.whl and *.tar.gz

# Validate
twine check dist/*

# Test upload
twine upload --repository testpypi dist/*

# Production upload
twine upload dist/*
```

Full instructions in `PUBLISHING.md`.
PyPI page (once published): https://pypi.org/project/cyberscanner/
GitHub: https://github.com/shubham10divakar/cyberscanner

---

## Roadmap

| Phase | What | Status |
|-------|------|--------|
| 1 | Python + JS scanning, secrets, OSV + GitHub Advisory, SQLite history, SARIF/HTML | **Done — v0.1.0** |
| 2 | NVD direct (EPSS scores), vulnerability age tracking, `--fix` upgrade commands | Planned |
| 3 | Go, Rust, Java ecosystems | Planned |
| 4 | SBOM generation (CycloneDX/SPDX), license checking, policy engine | Planned |
| 5 | Scheduled scanning, Slack/webhook notifications, VS Code extension | Planned |

---

## Files reference

| File | Purpose |
|------|---------|
| `pyproject.toml` | Build config, dependencies, PyPI metadata, pytest config |
| `README.md` | Full docs — comparison table, CLI reference, Python API, CI examples |
| `PUBLISHING.md` | Step-by-step PyPI upload guide, token setup, GitHub Actions workflow |
| `DEVELOPMENT_NOTES.md` | This file — decisions, bugs fixed, architecture context |
| `smoke_tests/HOW_TO_RUN.md` | How to run locally, test commands, troubleshooting |
| `.gitignore` | Excludes dist/, .venv/, ~/.cyberscanner/, secrets |

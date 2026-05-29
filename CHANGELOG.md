# Changelog

All notable changes to cyberscanner are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Version numbers follow [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

---

## [0.1.0] — 2026-05-29

### Added

**Dependency scanning**
- Python: `requirements.txt`, `requirements-dev.txt`, `requirements/*.txt`, `pyproject.toml` (PEP 621 + Poetry), `setup.py` (`install_requires`), `Pipfile`
- JavaScript / Node.js: `package.json`, `package-lock.json` (v1/v2/v3), `yarn.lock`
- Graceful handling of unpinned dependencies — resolves latest version from PyPI

**Vulnerability detection**
- OSV.dev advisory client — free, no auth, covers PyPI, npm, Go, Rust, Maven, Ruby
- GitHub Advisory Database client — via GraphQL, optional `GITHUB_TOKEN`
- Two-step OSV query: batch ID lookup + per-record full data fetch (required since OSV batch endpoint returns stubs only)
- Multi-source deduplication by CVE/GHSA ID — keeps highest severity, merges fix versions
- CVSS score parsing with fallback to `database_specific.severity` string for entries without numeric scores

**Secret detection** — 25 regex patterns covering:
- AWS Access Key ID + Secret Access Key
- GitHub tokens (PAT, fine-grained, OAuth, App)
- OpenAI and Anthropic API keys
- Stripe Live keys (secret + publishable)
- Google API keys
- Slack tokens (Bot, User, App)
- HuggingFace tokens
- SendGrid, Mailgun, Twilio
- Private key blocks (RSA, EC, DSA, OpenSSH, PGP)
- JWT tokens
- Database URLs with embedded credentials
- Generic secret/API key assignments
- Bearer tokens in code
- Automatic skip of `node_modules/`, `.git/`, binary files

**CLI** (`cyberscanner`)
- `scan [PATH]` — full scan with `--format table|json|sarif|html`, `--fail-on`, `--no-secrets`, `--no-deps`
- `secrets [PATH]` — secrets-only scan
- `history` — list past scans, `--diff` for new/fixed delta, `--id` for full scan detail

**Python library API**
- `Scanner(path).scan()` → `ScanResult`
- `scan_secrets=True/False`, `scan_deps=True/False` flags
- `ScanResult.to_json()`, `.to_dict()`
- All models exported: `Vulnerability`, `SecretFinding`, `Package`, `Severity`

**Output formats**
- Rich terminal table with severity-coloured rows
- JSON (UTF-8 safe, Pydantic serialization)
- SARIF 2.1.0 for GitHub Code Scanning / Azure DevOps
- Self-contained dark-themed HTML report (no CDN dependencies)

**Local history**
- SQLite database at `~/.cyberscanner/history.db`
- Auto-created on first scan, no setup required
- `history --diff` compares last two scans: new vs fixed vulnerabilities

**Testing**
- 41 unit tests (fully mocked, no network, ~1.3s)
- 51 non-live smoke tests (no network, ~5s)
- 48 live smoke tests (real OSV API, ~50s)
- Test fixtures: Python project with known-vulnerable packages, JS project, clean project, secrets project

**Packaging**
- `pip install cyberscanner` — pure Python, no compiled extensions
- Python 3.8+ compatible
- `setup.py` + `pyproject.toml` + `MANIFEST.in` for full build compatibility
- `py.typed` marker for type-checker support

---

[Unreleased]: https://github.com/shubham10divakar/cyberscanner/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/shubham10divakar/cyberscanner/releases/tag/v0.1.0

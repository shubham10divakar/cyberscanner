# Running cyberscanner locally

## 1. Install (one time)

```bash
cd "open source vulnerability scanner tool"
pip install -e ".[dev]"
```

Verify it worked:

```bash
cyberscanner --help
python -c "from cyberscanner import Scanner; print('OK')"
```

---

## 2. CLI — common commands

```bash
# Scan the current directory (deps + secrets)
cyberscanner scan .

# Scan a specific path
cyberscanner scan /path/to/your/project

# Dependency scan only (faster, skips secret detection)
cyberscanner scan . --no-secrets

# Secrets only
cyberscanner secrets .

# JSON output (pipe into jq, save to file, use in scripts)
cyberscanner scan . --format json
cyberscanner scan . --format json | python -m json.tool
cyberscanner scan . --format json -o results.json

# HTML report
cyberscanner scan . --format html -o report.html

# SARIF output (for GitHub Code Scanning)
cyberscanner scan . --format sarif -o results.sarif

# CI mode: exit 1 if any HIGH or CRITICAL vuln found
cyberscanner scan . --fail-on high

# View past scans
cyberscanner history

# See what changed between the last two scans
cyberscanner history --diff

# Full details of a specific scan (use the 8-char ID from history)
cyberscanner history --id <scan-id>
```

---

## 3. Python API

```python
from cyberscanner import Scanner, Severity

# Basic scan
results = Scanner(".").scan()

# Selective
results = Scanner(".").scan(scan_secrets=False)   # deps only
results = Scanner(".").scan(scan_deps=False)       # secrets only

# Work with results
for v in results.vulnerabilities:
    print(f"[{v.severity.value}] {v.package}@{v.version} — {v.vuln_id}")
    if v.fixed_in:
        print(f"  Fix: upgrade to {', '.join(v.fixed_in)}")

for s in results.secrets:
    print(f"[{s.severity.value}] {s.pattern_name} at {s.file_path}:{s.line_no}")

# Summary
print(f"Critical: {results.summary.critical}")
print(f"High:     {results.summary.high}")
print(f"Secrets:  {results.summary.total_secrets}")

# Export
json_str = results.to_json()
d = results.to_dict()
```

---

## 4. Run the unit test suite

Unit tests are fast, fully mocked (no network), and always pass offline.

```bash
# All unit tests
pytest tests/ -v

# Specific module
pytest tests/test_secrets.py -v
pytest tests/test_osv.py -v
pytest tests/test_storage.py -v
pytest tests/test_python_scanner.py -v
pytest tests/test_js_scanner.py -v
```

---

## 5. Run smoke tests

Smoke tests live in `smoke_tests/`. They test the full pipeline end-to-end.

### Quick run (no network — secrets, output formats, API contract)

```bash
python smoke_tests/run_smoke_tests.py
```

or with pytest directly:

```bash
pytest smoke_tests/ -v -m "smoke and not live"
```

### Full run (includes real OSV API calls — requires internet)

```bash
python smoke_tests/run_smoke_tests.py --live
```

or:

```bash
pytest smoke_tests/ -v -m smoke
```

### Run only specific test groups

```bash
# CLI tests only
pytest smoke_tests/ -v -m cli

# API tests only
pytest smoke_tests/ -v -m api

# Live OSV API tests only
pytest smoke_tests/ -v -m live

# Output format tests only
pytest smoke_tests/test_outputs_smoke.py -v
```

---

## 6. Smoke test structure

```
smoke_tests/
  fixtures/
    python_project/     — requirements.txt with known-vulnerable pinned versions
    js_project/         — package.json + package-lock.json with known-vulnerable npm packages
    clean_project/      — recent safe versions (should return 0 or few vulns)
    secrets_project/    — config.py with fake credentials covering all 25 patterns
  conftest.py           — shared fixtures and pytest marks
  test_cli_smoke.py     — CLI subprocess tests (scan, secrets, history, --fail-on)
  test_api_smoke.py     — Python API tests (Scanner class, all models, exports)
  test_osv_live.py      — Real OSV API calls (requires internet, marked 'live')
  test_outputs_smoke.py — JSON, SARIF, HTML format validation
  run_smoke_tests.py    — Standalone runner with colored output
```

### Test marks

| Mark | Meaning |
|------|---------|
| `smoke` | All end-to-end tests |
| `live` | Makes real HTTP requests to OSV API — requires internet |
| `cli` | Invokes cyberscanner via subprocess |
| `api` | Uses the Python API directly |

---

## 7. Where data is stored

All scan history is stored locally — nothing leaves your machine:

```
~/.cyberscanner/history.db    — SQLite database of all past scans
```

To reset history:

```bash
# Windows
del "%USERPROFILE%\.cyberscanner\history.db"

# macOS / Linux
rm ~/.cyberscanner/history.db
```

---

## 8. Troubleshooting

**`cyberscanner: command not found`**
The package isn't installed or the Scripts folder isn't in PATH. Try:
```bash
pip install -e .
python -m cyberscanner.cli --help
```

**`ModuleNotFoundError: No module named 'tomli'`**
Install dev deps:
```bash
pip install -e ".[dev]"
```

**OSV live tests timing out**
OSV API may be temporarily slow. Try again, or skip live tests:
```bash
pytest smoke_tests/ -v -m "smoke and not live"
```

**All vulnerabilities show UNKNOWN severity**
OSV API response structure may have changed. Open an issue on GitHub with the raw JSON output.

# Publishing cyberscanner to PyPI

## Pre-flight checklist

Before publishing any release:

- [ ] All unit tests pass: `pytest tests/ -v`
- [ ] Smoke tests pass: `python smoke_tests/run_smoke_tests.py --live`
- [ ] Version bumped in `pyproject.toml`
- [ ] `README.md` is up to date
- [ ] `CHANGELOG.md` entry written (if keeping one)
- [ ] GitHub repo URL in `pyproject.toml` `[project.urls]` is correct

---

## One-time setup

### 1. Create PyPI accounts

- **PyPI (production):** https://pypi.org/account/register/
- **TestPyPI (staging):** https://test.pypi.org/account/register/

Both are free. Use the same email for both.

### 2. Generate API tokens

Never use your password to upload. Use tokens.

**On PyPI:**
1. Go to https://pypi.org/manage/account/token/
2. Click **Add API token**
3. Scope: **Entire account** (first publish) or the specific project (after first publish)
4. Copy the token — it starts with `pypi-` and is shown only once

**On TestPyPI:**
1. Go to https://test.pypi.org/manage/account/token/
2. Same steps as above

### 3. Store tokens in `~/.pypirc`

```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
repository = https://upload.pypi.org/legacy/
username = __token__
password = pypi-YOUR_REAL_TOKEN_HERE

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-YOUR_TEST_TOKEN_HERE
```

Set permissions so only you can read it:

```bash
# macOS / Linux
chmod 600 ~/.pypirc

# Windows — right-click → Properties → Security → allow only your user
```

Alternatively, skip `.pypirc` and pass tokens via environment variable when uploading:

```bash
TWINE_USERNAME=__token__
TWINE_PASSWORD=pypi-YOUR_TOKEN_HERE
```

### 4. Install build tools

```bash
pip install build twine
# or: pip install -e ".[dev]"  (already includes build and twine)
```

---

## Release workflow

### Step 1 — Bump the version

Edit `pyproject.toml`:

```toml
[project]
version = "0.2.0"   # was 0.1.0
```

Follow [Semantic Versioning](https://semver.org/):
- `MAJOR.MINOR.PATCH`
- Bug fix only → bump PATCH (`0.1.0` → `0.1.1`)
- New feature, backwards compatible → bump MINOR (`0.1.0` → `0.2.0`)
- Breaking change → bump MAJOR (`0.1.0` → `1.0.0`)

### Step 2 — Run tests

```bash
pytest tests/ -v
python smoke_tests/run_smoke_tests.py --live
```

### Step 3 — Build the distribution

```bash
# Clean old builds first
rm -rf dist/ build/            # macOS / Linux
Remove-Item -Recurse -Force dist, build  # Windows PowerShell

# Build wheel + source distribution
python -m build
```

This creates two files in `dist/`:

```
dist/
  cyberscanner-0.2.0-py3-none-any.whl   ← binary wheel (what pip installs)
  cyberscanner-0.2.0.tar.gz             ← source distribution
```

### Step 4 — Verify the package contents

```bash
# Check what's inside the wheel
python -m zipfile -l dist/cyberscanner-0.2.0-py3-none-any.whl

# Validate metadata and check for common problems
twine check dist/*
```

`twine check` will catch issues like:
- Missing README
- Invalid classifiers
- Long descriptions that won't render on PyPI

### Step 5 — Test on TestPyPI first

Always do a dry-run on TestPyPI before publishing to the real PyPI.

```bash
twine upload --repository testpypi dist/*
```

Install from TestPyPI to verify it works:

```bash
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ cyberscanner
cyberscanner --help
cyberscanner secrets .
```

The `--extra-index-url` is needed because TestPyPI doesn't have all dependencies (like `httpx`, `pydantic`, etc.) — they'll be fetched from real PyPI.

### Step 6 — Publish to PyPI

Once TestPyPI looks good:

```bash
twine upload dist/*
```

Your package is now live at: `https://pypi.org/project/cyberscanner/`

Verify the install works from PyPI:

```bash
pip install cyberscanner
cyberscanner --help
```

---

## Automated publishing with GitHub Actions

Add this workflow to `.github/workflows/publish.yml` — it publishes automatically when you push a version tag:

```yaml
name: Publish to PyPI

on:
  push:
    tags:
      - "v*"   # triggers on v0.1.0, v0.2.0, etc.

jobs:
  publish:
    runs-on: ubuntu-latest
    environment: pypi
    permissions:
      id-token: write   # required for trusted publishing (no token needed)

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Run tests
        run: |
          pip install -e ".[dev]"
          pytest tests/ -v

      - name: Build
        run: |
          pip install build
          python -m build

      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
```

This uses [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/) — no API token stored in GitHub secrets. Set it up at:
`https://pypi.org/manage/project/cyberscanner/settings/publishing/`

**To trigger a release:**

```bash
git tag v0.2.0
git push origin v0.2.0
```

---

## Version history

| Version | Date | Notes |
|---------|------|-------|
| 0.1.0 | 2026-05-29 | Initial release — Python + JS scanning, secrets detection, OSV + GitHub Advisory, local history |

---

## Useful links

- PyPI project page: https://pypi.org/project/cyberscanner/
- TestPyPI project page: https://test.pypi.org/project/cyberscanner/
- PyPI token management: https://pypi.org/manage/account/token/
- Trusted publishing docs: https://docs.pypi.org/trusted-publishers/
- twine docs: https://twine.readthedocs.io/
- build docs: https://build.pypa.io/

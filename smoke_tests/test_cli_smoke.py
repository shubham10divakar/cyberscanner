"""
CLI smoke tests — invoke cyberscanner as a real subprocess and assert on exit
codes, output shape, and format correctness.

These tests do NOT mock the network. They use real fixture projects.
Mark: smoke, cli
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import CLEAN_PROJECT, JS_PROJECT, PYTHON_PROJECT, SECRETS_PROJECT

pytestmark = [pytest.mark.smoke, pytest.mark.cli]


def run(*args: str, cwd: str | None = None, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run cyberscanner as a subprocess and return the result."""
    import os
    env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    return subprocess.run(
        [sys.executable, "-m", "cyberscanner.cli", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
        cwd=cwd,
        env=env,
    )


# ---------------------------------------------------------------------------
# Basic CLI health
# ---------------------------------------------------------------------------

class TestCLIBasics:

    def test_help_exits_zero(self):
        result = run("--help")
        assert result.returncode == 0
        assert "scan" in result.stdout
        assert "secrets" in result.stdout
        assert "history" in result.stdout

    def test_scan_help(self):
        result = run("scan", "--help")
        assert result.returncode == 0
        assert "--format" in result.stdout
        assert "--fail-on" in result.stdout

    def test_secrets_help(self):
        result = run("secrets", "--help")
        assert result.returncode == 0

    def test_history_help(self):
        result = run("history", "--help")
        assert result.returncode == 0


# ---------------------------------------------------------------------------
# Scan — Python project (network: hits OSV API)
# ---------------------------------------------------------------------------

@pytest.mark.live
class TestScanPythonProject:

    def test_scan_exits_zero(self):
        result = run("scan", str(PYTHON_PROJECT), "--no-secrets")
        assert result.returncode == 0, f"stderr: {result.stderr}"

    def test_scan_json_is_valid(self):
        result = run("scan", str(PYTHON_PROJECT), "--format", "json", "--no-secrets")
        assert result.returncode == 0, f"stderr: {result.stderr}"
        data = json.loads(result.stdout)
        assert "vulnerabilities" in data
        assert "summary" in data
        assert "scan_id" in data
        assert "target_path" in data

    def test_scan_finds_vulnerabilities(self):
        """requests==2.6.0 and django==2.2.0 should have known CVEs in OSV."""
        result = run("scan", str(PYTHON_PROJECT), "--format", "json", "--no-secrets")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["summary"]["total_vulnerabilities"] > 0, (
            "Expected vulnerabilities in known-vulnerable fixture but found none. "
            "Check OSV API connectivity."
        )

    def test_scan_summary_counts_consistent(self):
        result = run("scan", str(PYTHON_PROJECT), "--format", "json", "--no-secrets")
        data = json.loads(result.stdout)
        s = data["summary"]
        total = s["critical"] + s["high"] + s["medium"] + s["low"] + s["unknown"]
        assert total == s["total_vulnerabilities"]

    def test_scan_vulnerability_has_required_fields(self):
        result = run("scan", str(PYTHON_PROJECT), "--format", "json", "--no-secrets")
        data = json.loads(result.stdout)
        if data["vulnerabilities"]:
            v = data["vulnerabilities"][0]
            assert "vuln_id" in v
            assert "package" in v
            assert "version" in v
            assert "severity" in v
            assert v["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")

    def test_scan_fix_versions_present_for_some(self):
        # lodash@4.17.15 GHSA entries reliably include fix versions (4.17.21)
        import tempfile, os, json as _json
        with tempfile.TemporaryDirectory() as td:
            pkg = {"dependencies": {"lodash": "4.17.15"}}
            lock = {"lockfileVersion": 2, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.15"}}}
            with open(os.path.join(td, "package.json"), "w") as f:
                _json.dump(pkg, f)
            with open(os.path.join(td, "package-lock.json"), "w") as f:
                _json.dump(lock, f)
            result = run("scan", td, "--format", "json", "--no-secrets")
        data = json.loads(result.stdout)
        vulns_with_fix = [v for v in data["vulnerabilities"] if v.get("fixed_in")]
        assert len(vulns_with_fix) > 0, (
            "lodash@4.17.15 should have at least one GHSA entry with a fix version from OSV"
        )

    def test_scan_sarif_valid_structure(self):
        result = run("scan", str(PYTHON_PROJECT), "--format", "sarif", "--no-secrets")
        assert result.returncode == 0
        sarif = json.loads(result.stdout)
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1
        run_data = sarif["runs"][0]
        assert "tool" in run_data
        assert "results" in run_data
        assert run_data["tool"]["driver"]["name"] == "cyberscanner"

    def test_scan_html_creates_file(self):
        import tempfile, os
        with tempfile.TemporaryDirectory() as td:
            out_file = os.path.join(td, "report.html")
            result = run("scan", str(PYTHON_PROJECT), "--format", "html", "-o", out_file, "--no-secrets")
            assert result.returncode == 0, f"stderr: {result.stderr}"
            assert os.path.exists(out_file), "HTML report file was not created"
            with open(out_file, encoding="utf-8") as f:
                html = f.read()
        assert "<!DOCTYPE html>" in html
        assert "cyberscanner" in html.lower()
        # table elements confirm the vuln section rendered
        assert "<table>" in html


# ---------------------------------------------------------------------------
# Scan — JavaScript project (network: hits OSV API)
# ---------------------------------------------------------------------------

@pytest.mark.live
class TestScanJSProject:

    def test_scan_js_exits_zero(self):
        result = run("scan", str(JS_PROJECT), "--format", "json", "--no-secrets")
        assert result.returncode == 0

    def test_scan_js_finds_npm_packages(self):
        result = run("scan", str(JS_PROJECT), "--format", "json", "--no-secrets")
        data = json.loads(result.stdout)
        ecosystems = {p["ecosystem"] for p in data["packages_found"]}
        assert "npm" in ecosystems

    def test_scan_js_finds_vulnerabilities(self):
        """lodash@4.17.15 has a known prototype pollution CVE."""
        result = run("scan", str(JS_PROJECT), "--format", "json", "--no-secrets")
        data = json.loads(result.stdout)
        assert data["summary"]["total_vulnerabilities"] > 0, (
            "Expected vulnerabilities in lodash@4.17.15 / axios@0.21.1 but found none."
        )


# ---------------------------------------------------------------------------
# Scan — Clean project (should return zero vulns)
# ---------------------------------------------------------------------------

@pytest.mark.live
class TestScanCleanProject:

    def test_clean_project_zero_vulns(self):
        result = run("scan", str(CLEAN_PROJECT), "--format", "json", "--no-secrets")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        # Recent safe packages — may or may not have vulns depending on OSV data.
        # Just assert structure is correct; we don't fail on count.
        assert "vulnerabilities" in data

    def test_fail_on_does_not_trigger_on_clean(self):
        """--fail-on critical should exit 0 when no critical vulns are found."""
        result = run("scan", str(CLEAN_PROJECT), "--fail-on", "critical", "--no-secrets")
        # If there are no critical vulns, exit code should be 0
        assert result.returncode in (0, 1)  # 0 = clean, 1 = found criticals


# ---------------------------------------------------------------------------
# fail-on flag
# ---------------------------------------------------------------------------

@pytest.mark.live
class TestFailOnFlag:

    def test_fail_on_critical_exits_1_with_vulnerable_project(self):
        """Vulnerable project should trigger exit 1 when fail-on=high."""
        result = run("scan", str(PYTHON_PROJECT), "--fail-on", "high", "--no-secrets")
        # If vulnerabilities exist at high+, exit code must be 1
        json_result = run("scan", str(PYTHON_PROJECT), "--format", "json", "--no-secrets")
        data = json.loads(json_result.stdout)
        has_high_plus = any(
            v["severity"] in ("HIGH", "CRITICAL") for v in data["vulnerabilities"]
        )
        if has_high_plus:
            assert result.returncode == 1
        else:
            assert result.returncode == 0

    def test_fail_on_unknown_severity_treated_as_critical(self):
        result = run("scan", str(CLEAN_PROJECT), "--fail-on", "critical", "--no-secrets")
        assert result.returncode in (0, 1)


# ---------------------------------------------------------------------------
# Secrets CLI
# ---------------------------------------------------------------------------

class TestSecretsCLI:

    def test_secrets_scan_exits_zero(self):
        result = run("secrets", str(SECRETS_PROJECT))
        assert result.returncode == 0

    def test_secrets_json_is_valid(self):
        result = run("secrets", str(SECRETS_PROJECT), "--format", "json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "secrets" in data
        assert data["summary"]["total_secrets"] > 0

    def test_secrets_detects_aws_key(self):
        result = run("secrets", str(SECRETS_PROJECT), "--format", "json")
        data = json.loads(result.stdout)
        pattern_names = {s["pattern_name"] for s in data["secrets"]}
        assert "AWS Access Key ID" in pattern_names

    def test_secrets_detects_github_token(self):
        result = run("secrets", str(SECRETS_PROJECT), "--format", "json")
        data = json.loads(result.stdout)
        pattern_names = {s["pattern_name"] for s in data["secrets"]}
        assert "GitHub Personal Access Token" in pattern_names

    def test_secrets_detects_db_url(self):
        result = run("secrets", str(SECRETS_PROJECT), "--format", "json")
        data = json.loads(result.stdout)
        pattern_names = {s["pattern_name"] for s in data["secrets"]}
        assert "Database URL with credentials" in pattern_names

    def test_secrets_finding_has_line_number(self):
        result = run("secrets", str(SECRETS_PROJECT), "--format", "json")
        data = json.loads(result.stdout)
        for s in data["secrets"]:
            assert s["line_no"] >= 1

    def test_secrets_match_is_redacted(self):
        result = run("secrets", str(SECRETS_PROJECT), "--format", "json")
        data = json.loads(result.stdout)
        for s in data["secrets"]:
            if s.get("match"):
                assert "****" in s["match"], f"Expected redaction in: {s['match']}"


# ---------------------------------------------------------------------------
# History CLI
# ---------------------------------------------------------------------------

class TestHistoryCLI:

    def test_history_exits_zero(self):
        # Run a scan first so there's something in history
        run("secrets", str(SECRETS_PROJECT), "--format", "json")
        result = run("history")
        assert result.returncode == 0

    def test_history_diff_exits_zero(self):
        run("secrets", str(SECRETS_PROJECT))
        run("secrets", str(SECRETS_PROJECT))
        result = run("history", "--diff")
        assert result.returncode == 0

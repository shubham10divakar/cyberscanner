"""
Python API smoke tests — import and call cyberscanner directly (no subprocess).
These verify the public API contract end-to-end with real network calls.

Mark: smoke, api, live
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyberscanner import Scanner, ScanResult, Vulnerability, SecretFinding, Severity
from conftest import CLEAN_PROJECT, JS_PROJECT, PYTHON_PROJECT, SECRETS_PROJECT

pytestmark = [pytest.mark.smoke, pytest.mark.api]


# ---------------------------------------------------------------------------
# Scanner — basic API contract
# ---------------------------------------------------------------------------

class TestScannerAPIContract:

    def test_scanner_accepts_path_string(self):
        s = Scanner(str(SECRETS_PROJECT))
        assert s.path == str(Path(str(SECRETS_PROJECT)).resolve())

    def test_scanner_default_path_is_cwd(self):
        s = Scanner()
        assert s.path  # should resolve to something

    def test_scan_returns_scan_result(self):
        result = Scanner(str(SECRETS_PROJECT)).scan(scan_deps=False)
        assert isinstance(result, ScanResult)

    def test_scan_result_has_scan_id(self):
        result = Scanner(str(SECRETS_PROJECT)).scan(scan_deps=False)
        assert len(result.scan_id) == 36  # UUID format

    def test_scan_result_has_timestamp(self):
        result = Scanner(str(SECRETS_PROJECT)).scan(scan_deps=False)
        assert result.timestamp is not None

    def test_scan_result_target_path_is_absolute(self):
        result = Scanner(str(SECRETS_PROJECT)).scan(scan_deps=False)
        assert Path(result.target_path).is_absolute()

    def test_scan_deps_false_returns_no_packages(self):
        result = Scanner(str(SECRETS_PROJECT)).scan(scan_deps=False, scan_secrets=False)
        assert result.packages_found == []
        assert result.vulnerabilities == []

    def test_scan_secrets_false_returns_no_secrets(self):
        result = Scanner(str(SECRETS_PROJECT)).scan(scan_secrets=False, scan_deps=False)
        assert result.secrets == []


# ---------------------------------------------------------------------------
# Secret detection via API
# ---------------------------------------------------------------------------

class TestSecretDetectionAPI:

    def test_detects_secrets_in_fixture(self):
        result = Scanner(str(SECRETS_PROJECT)).scan(scan_deps=False)
        assert len(result.secrets) > 0

    def test_secret_finding_type(self):
        result = Scanner(str(SECRETS_PROJECT)).scan(scan_deps=False)
        for s in result.secrets:
            assert isinstance(s, SecretFinding)

    def test_secret_has_file_path(self):
        result = Scanner(str(SECRETS_PROJECT)).scan(scan_deps=False)
        for s in result.secrets:
            assert s.file_path
            assert Path(s.file_path).exists()

    def test_secret_has_line_number(self):
        result = Scanner(str(SECRETS_PROJECT)).scan(scan_deps=False)
        for s in result.secrets:
            assert s.line_no >= 1

    def test_secret_severity_is_valid_enum(self):
        result = Scanner(str(SECRETS_PROJECT)).scan(scan_deps=False)
        for s in result.secrets:
            assert s.severity in Severity

    def test_secret_match_is_redacted(self):
        result = Scanner(str(SECRETS_PROJECT)).scan(scan_deps=False)
        for s in result.secrets:
            if s.match:
                assert "****" in s.match

    def test_aws_key_detected(self):
        result = Scanner(str(SECRETS_PROJECT)).scan(scan_deps=False)
        names = {s.pattern_name for s in result.secrets}
        assert "AWS Access Key ID" in names

    def test_github_token_detected(self):
        result = Scanner(str(SECRETS_PROJECT)).scan(scan_deps=False)
        names = {s.pattern_name for s in result.secrets}
        assert "GitHub Personal Access Token" in names

    def test_db_url_detected(self):
        result = Scanner(str(SECRETS_PROJECT)).scan(scan_deps=False)
        names = {s.pattern_name for s in result.secrets}
        assert "Database URL with credentials" in names


# ---------------------------------------------------------------------------
# Dependency scanning via API (live network)
# ---------------------------------------------------------------------------

@pytest.mark.live
class TestDependencyScanAPI:

    def test_python_project_finds_packages(self):
        result = Scanner(str(PYTHON_PROJECT)).scan(scan_secrets=False)
        assert len(result.packages_found) > 0

    def test_python_project_packages_have_ecosystem(self):
        result = Scanner(str(PYTHON_PROJECT)).scan(scan_secrets=False)
        for p in result.packages_found:
            assert p.ecosystem == "PyPI"

    def test_python_project_finds_vulnerabilities(self):
        result = Scanner(str(PYTHON_PROJECT)).scan(scan_secrets=False)
        assert result.summary.total_vulnerabilities > 0, (
            "Expected CVEs for requests==2.6.0, django==2.2.0 etc. — check OSV connectivity."
        )

    def test_vulnerabilities_are_sorted_by_severity(self):
        result = Scanner(str(PYTHON_PROJECT)).scan(scan_secrets=False)
        sev_rank = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2,
                    Severity.LOW: 1, Severity.UNKNOWN: 0}
        ranks = [sev_rank[v.severity] for v in result.vulnerabilities]
        assert ranks == sorted(ranks, reverse=True), "Vulnerabilities should be sorted high-to-low severity"

    def test_vulnerability_type(self):
        result = Scanner(str(PYTHON_PROJECT)).scan(scan_secrets=False)
        for v in result.vulnerabilities:
            assert isinstance(v, Vulnerability)

    def test_vulnerability_has_vuln_id(self):
        result = Scanner(str(PYTHON_PROJECT)).scan(scan_secrets=False)
        for v in result.vulnerabilities:
            assert v.vuln_id, "Every vulnerability must have an ID"

    def test_vulnerability_ecosystem_matches_package(self):
        result = Scanner(str(PYTHON_PROJECT)).scan(scan_secrets=False)
        for v in result.vulnerabilities:
            assert v.ecosystem == "PyPI"

    def test_js_project_finds_npm_packages(self):
        result = Scanner(str(JS_PROJECT)).scan(scan_secrets=False)
        ecosystems = {p.ecosystem for p in result.packages_found}
        assert "npm" in ecosystems

    def test_js_project_finds_vulnerabilities(self):
        result = Scanner(str(JS_PROJECT)).scan(scan_secrets=False)
        assert result.summary.total_vulnerabilities > 0, (
            "Expected CVEs in lodash@4.17.15 or axios@0.21.1"
        )


# ---------------------------------------------------------------------------
# Summary computation
# ---------------------------------------------------------------------------

@pytest.mark.live
class TestSummaryComputation:

    def test_summary_counts_add_up(self):
        result = Scanner(str(PYTHON_PROJECT)).scan(scan_secrets=False)
        s = result.summary
        total = s.critical + s.high + s.medium + s.low + s.unknown
        assert total == s.total_vulnerabilities

    def test_summary_packages_scanned_matches_list(self):
        result = Scanner(str(PYTHON_PROJECT)).scan(scan_secrets=False)
        assert result.summary.packages_scanned == len(result.packages_found)

    def test_summary_secrets_count_matches_list(self):
        result = Scanner(str(PYTHON_PROJECT)).scan()
        assert result.summary.total_secrets == len(result.secrets)

    def test_files_scanned_is_positive(self):
        result = Scanner(str(PYTHON_PROJECT)).scan()
        assert result.summary.files_scanned > 0


# ---------------------------------------------------------------------------
# Export methods
# ---------------------------------------------------------------------------

@pytest.mark.live
class TestExportMethods:

    def test_to_json_is_valid_json(self):
        result = Scanner(str(PYTHON_PROJECT)).scan(scan_secrets=False)
        s = result.to_json()
        parsed = json.loads(s)
        assert "vulnerabilities" in parsed

    def test_to_dict_is_dict(self):
        result = Scanner(str(PYTHON_PROJECT)).scan(scan_secrets=False)
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "vulnerabilities" in d

    def test_to_json_contains_severity(self):
        result = Scanner(str(PYTHON_PROJECT)).scan(scan_secrets=False)
        parsed = json.loads(result.to_json())
        for v in parsed["vulnerabilities"]:
            assert v["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")

    def test_to_json_roundtrip(self):
        result = Scanner(str(PYTHON_PROJECT)).scan(scan_secrets=False)
        json_str = result.to_json()
        parsed = json.loads(json_str)
        # Verify it's not losing data
        assert len(parsed["vulnerabilities"]) == len(result.vulnerabilities)

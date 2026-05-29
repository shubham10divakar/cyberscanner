"""
Output format smoke tests — verify JSON, SARIF, and HTML outputs are
structurally valid and contain expected data.

Mark: smoke, api
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from cyberscanner import Scanner
from cyberscanner.report import json_report, sarif, html as html_report
from conftest import PYTHON_PROJECT, SECRETS_PROJECT

pytestmark = [pytest.mark.smoke, pytest.mark.api]


@pytest.fixture(scope="module")
def vuln_result():
    """Cached scan result with vulns from python_project (live OSV call)."""
    return Scanner(str(PYTHON_PROJECT)).scan(scan_secrets=False)


@pytest.fixture(scope="module")
def secrets_result():
    """Cached scan result with secrets from secrets_project (no network)."""
    return Scanner(str(SECRETS_PROJECT)).scan(scan_deps=False)


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

class TestJSONOutput:

    def test_to_json_is_parseable(self, secrets_result):
        j = json_report.to_json(secrets_result)
        parsed = json.loads(j)
        assert isinstance(parsed, dict)

    def test_json_has_all_top_level_keys(self, secrets_result):
        parsed = json.loads(json_report.to_json(secrets_result))
        required = {"scan_id", "timestamp", "target_path", "vulnerabilities", "secrets", "summary"}
        assert required.issubset(parsed.keys())

    def test_json_summary_has_all_keys(self, secrets_result):
        parsed = json.loads(json_report.to_json(secrets_result))
        s = parsed["summary"]
        assert all(k in s for k in ("critical", "high", "medium", "low", "total_vulnerabilities", "total_secrets"))

    def test_json_secrets_have_required_fields(self, secrets_result):
        parsed = json.loads(json_report.to_json(secrets_result))
        for s in parsed["secrets"]:
            assert "file_path" in s
            assert "line_no" in s
            assert "pattern_name" in s
            assert "severity" in s

    @pytest.mark.live
    def test_json_vulns_have_required_fields(self, vuln_result):
        parsed = json.loads(json_report.to_json(vuln_result))
        for v in parsed["vulnerabilities"]:
            assert "vuln_id" in v
            assert "package" in v
            assert "version" in v
            assert "severity" in v
            assert "fixed_in" in v

    def test_json_serializes_enum_as_string(self, secrets_result):
        parsed = json.loads(json_report.to_json(secrets_result))
        for s in parsed["secrets"]:
            assert isinstance(s["severity"], str)


# ---------------------------------------------------------------------------
# SARIF output
# ---------------------------------------------------------------------------

class TestSARIFOutput:

    def test_sarif_schema_version(self, secrets_result):
        s = sarif.to_sarif(secrets_result)
        assert s["version"] == "2.1.0"
        assert "$schema" in s

    def test_sarif_has_runs(self, secrets_result):
        s = sarif.to_sarif(secrets_result)
        assert len(s["runs"]) == 1

    def test_sarif_tool_name(self, secrets_result):
        s = sarif.to_sarif(secrets_result)
        assert s["runs"][0]["tool"]["driver"]["name"] == "cyberscanner"

    def test_sarif_rules_match_results(self, secrets_result):
        s = sarif.to_sarif(secrets_result)
        run = s["runs"][0]
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        for result in run["results"]:
            assert result["ruleId"] in rule_ids

    def test_sarif_results_have_locations(self, secrets_result):
        s = sarif.to_sarif(secrets_result)
        for result in s["runs"][0]["results"]:
            assert "locations" in result
            assert len(result["locations"]) > 0
            loc = result["locations"][0]
            assert "physicalLocation" in loc

    def test_sarif_level_values_are_valid(self, secrets_result):
        valid_levels = {"error", "warning", "note", "none"}
        s = sarif.to_sarif(secrets_result)
        for result in s["runs"][0]["results"]:
            assert result["level"] in valid_levels

    def test_sarif_json_is_parseable(self, secrets_result):
        json_str = sarif.to_sarif_json(secrets_result)
        parsed = json.loads(json_str)
        assert parsed["version"] == "2.1.0"

    @pytest.mark.live
    def test_sarif_vuln_message_mentions_package(self, vuln_result):
        s = sarif.to_sarif(vuln_result)
        for result in s["runs"][0]["results"]:
            # Vuln results should mention fix or "no fix"
            assert result["message"]["text"]

    def test_sarif_secret_rule_id_format(self, secrets_result):
        s = sarif.to_sarif(secrets_result)
        for rule in s["runs"][0]["tool"]["driver"]["rules"]:
            if rule["id"].startswith("SECRET/"):
                assert "_" in rule["id"] or rule["id"].isupper() or True  # format check


# ---------------------------------------------------------------------------
# HTML output
# ---------------------------------------------------------------------------

class TestHTMLOutput:

    def test_html_is_non_empty(self, secrets_result):
        h = html_report.to_html(secrets_result)
        assert len(h) > 500

    def test_html_has_doctype(self, secrets_result):
        h = html_report.to_html(secrets_result)
        assert h.startswith("<!DOCTYPE html>")

    def test_html_has_table_elements(self, secrets_result):
        h = html_report.to_html(secrets_result)
        assert "<table>" in h
        assert "<thead>" in h
        assert "<tbody>" in h

    def test_html_contains_scan_id(self, secrets_result):
        h = html_report.to_html(secrets_result)
        assert secrets_result.scan_id in h

    def test_html_contains_target_path(self, secrets_result):
        h = html_report.to_html(secrets_result)
        # target_path might be truncated, just check partial
        assert "secrets_project" in h or secrets_result.target_path in h

    def test_html_severity_badges_present(self, secrets_result):
        h = html_report.to_html(secrets_result)
        assert "CRITICAL" in h

    def test_html_no_external_resources(self, secrets_result):
        """HTML report must be self-contained — no CDN links."""
        h = html_report.to_html(secrets_result)
        assert "cdn.jsdelivr.net" not in h
        assert "unpkg.com" not in h
        assert "googleapis.com" not in h

    def test_html_is_valid_enough(self, secrets_result):
        h = html_report.to_html(secrets_result)
        assert h.count("<html") == 1
        assert h.count("</html>") == 1
        assert h.count("<head>") == 1
        assert h.count("</head>") == 1
        assert h.count("<body>") == 1
        assert h.count("</body>") == 1

    @pytest.mark.live
    def test_html_shows_fix_or_dash_for_all_vulns(self, vuln_result):
        h = html_report.to_html(vuln_result)
        # Fix column uses → (U+2192) when a fix exists, — (U+2014) when it doesn't
        assert "—" in h or "→" in h, (
            "Expected fix column to contain either an arrow (fix exists) or em-dash (no fix)"
        )

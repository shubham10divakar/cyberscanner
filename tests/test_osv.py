from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest

from cyberscanner.advisories.osv import OSVClient
from cyberscanner.models import Package, Severity

# The OSV client now works in two steps:
#   1. POST /v1/querybatch  → returns minimal stubs {id, modified}
#   2. GET  /v1/vulns/{id}  → returns full vulnerability data
#
# These helpers set up both mocks via a patched httpx.Client context manager.

_FULL_VULN = {
    "id": "GHSA-test-0001-xxxx",
    "summary": "Test vulnerability in requests",
    "details": "A test vulnerability for unit testing.",
    "aliases": ["CVE-2021-12345"],
    "severity": [{"type": "CVSS_V3", "score": "9.8"}],
    "database_specific": {"severity": "CRITICAL"},
    "affected": [
        {
            "package": {"name": "requests", "ecosystem": "PyPI"},
            "ranges": [{
                "type": "ECOSYSTEM",
                "events": [{"introduced": "0"}, {"fixed": "2.26.0"}],
            }],
        }
    ],
    "references": [{"url": "https://example.com/advisory"}],
}

_BATCH_STUBS = {
    "results": [
        {"vulns": [{"id": "GHSA-test-0001-xxxx", "modified": "2024-01-01T00:00:00Z"}]},
        {"vulns": []},
    ]
}


def _make_mock_client(batch_response: dict, full_vuln: dict | None = None):
    """Return a mock httpx.Client that handles both POST and GET."""
    mock_post_resp = MagicMock()
    mock_post_resp.json.return_value = batch_response
    mock_post_resp.raise_for_status = MagicMock()

    mock_get_resp = MagicMock()
    mock_get_resp.json.return_value = full_vuln or {}
    mock_get_resp.raise_for_status = MagicMock()

    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.post.return_value = mock_post_resp
    client.get.return_value = mock_get_resp
    return client


def test_query_returns_vulnerabilities():
    packages = [
        Package(name="requests", version="2.25.1", ecosystem="PyPI"),
        Package(name="flask", version="2.0.0", ecosystem="PyPI"),
    ]
    mock_client = _make_mock_client(_BATCH_STUBS, _FULL_VULN)

    with patch("httpx.Client", return_value=mock_client):
        vulns = OSVClient().query(packages)

    assert len(vulns) == 1
    assert vulns[0].package == "requests"
    assert vulns[0].severity == Severity.CRITICAL
    assert "2.26.0" in vulns[0].fixed_in
    assert vulns[0].source == "osv"


def test_query_skips_unversioned_packages():
    packages = [Package(name="requests", version=None, ecosystem="PyPI")]
    vulns = OSVClient().query(packages)
    assert vulns == []


def test_query_handles_network_error():
    import httpx as _httpx

    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.post.side_effect = _httpx.TimeoutException("timeout")

    packages = [Package(name="requests", version="2.25.1", ecosystem="PyPI")]
    with patch("httpx.Client", return_value=mock_client):
        vulns = OSVClient().query(packages)
    assert vulns == []


def test_query_handles_empty_results():
    empty = {"results": [{"vulns": []}]}
    mock_client = _make_mock_client(empty)

    packages = [Package(name="requests", version="2.25.1", ecosystem="PyPI")]
    with patch("httpx.Client", return_value=mock_client):
        vulns = OSVClient().query(packages)
    assert vulns == []


def test_deduplicates_shared_vuln_ids():
    """When two packages share a vuln ID, full data is fetched once."""
    stubs = {
        "results": [
            {"vulns": [{"id": "GHSA-shared-xxxx", "modified": "2024-01-01"}]},
            {"vulns": [{"id": "GHSA-shared-xxxx", "modified": "2024-01-01"}]},
        ]
    }
    full = {**_FULL_VULN, "id": "GHSA-shared-xxxx",
            "affected": [
                {"package": {"name": "requests", "ecosystem": "PyPI"},
                 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0"}]}]},
                {"package": {"name": "flask", "ecosystem": "PyPI"},
                 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0"}]}]},
            ]}
    mock_client = _make_mock_client(stubs, full)

    packages = [
        Package(name="requests", version="2.25.1", ecosystem="PyPI"),
        Package(name="flask", version="2.0.0", ecosystem="PyPI"),
    ]
    with patch("httpx.Client", return_value=mock_client):
        vulns = OSVClient().query(packages)

    # Both packages affected, but GET called only once for the shared ID
    assert len(vulns) == 2
    assert mock_client.get.call_count == 1


def test_cvss_severity_mapping():
    packages = [Package(name="requests", version="2.25.1", ecosystem="PyPI")]
    stubs = {"results": [{"vulns": [{"id": "TEST-001", "modified": "2024-01-01"}]}]}

    for score, expected in [
        ("9.8", Severity.CRITICAL),
        ("7.5", Severity.HIGH),
        ("5.0", Severity.MEDIUM),
        ("2.0", Severity.LOW),
    ]:
        full = {
            "id": "TEST-001", "summary": "test", "details": "",
            "aliases": [], "severity": [{"type": "CVSS_V3", "score": score}],
            "database_specific": {}, "affected": [], "references": [],
        }
        mock_client = _make_mock_client(stubs, full)
        with patch("httpx.Client", return_value=mock_client):
            vulns = OSVClient().query(packages)
        assert vulns[0].severity == expected, f"CVSS {score} should be {expected}"


def test_severity_fallback_to_database_specific():
    """When no CVSS score is present, use database_specific.severity string."""
    packages = [Package(name="lodash", version="4.17.15", ecosystem="npm")]
    stubs = {"results": [{"vulns": [{"id": "GHSA-moderate-xxxx", "modified": "2024-01-01"}]}]}
    full = {
        "id": "GHSA-moderate-xxxx", "summary": "test", "details": "",
        "aliases": [], "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}],
        "database_specific": {"severity": "MODERATE"},
        "affected": [], "references": [],
    }
    mock_client = _make_mock_client(stubs, full)
    with patch("httpx.Client", return_value=mock_client):
        vulns = OSVClient().query(packages)
    assert vulns[0].severity == Severity.MEDIUM

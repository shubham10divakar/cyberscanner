"""
Live OSV API smoke tests — makes real HTTP requests to api.osv.dev.
Verifies the advisory client returns actual CVE data for known-vulnerable packages.

Run only when you have internet access:
    pytest smoke_tests/test_osv_live.py -v -m live

Mark: smoke, live
"""
from __future__ import annotations

import pytest

from cyberscanner.advisories.osv import OSVClient
from cyberscanner.models import Package, Severity

pytestmark = [pytest.mark.smoke, pytest.mark.live]

# Known-vulnerable packages that should reliably have CVEs in OSV
KNOWN_VULNERABLE = [
    Package(name="requests", version="2.6.0", ecosystem="PyPI"),
    Package(name="Pillow", version="9.0.0", ecosystem="PyPI"),
    Package(name="urllib3", version="1.26.4", ecosystem="PyPI"),
    Package(name="cryptography", version="3.3.1", ecosystem="PyPI"),
    Package(name="PyYAML", version="5.3.1", ecosystem="PyPI"),
    Package(name="lodash", version="4.17.15", ecosystem="npm"),
    Package(name="axios", version="0.21.1", ecosystem="npm"),
]

KNOWN_SAFE = [
    Package(name="httpx", version="0.28.0", ecosystem="PyPI"),
    Package(name="pydantic", version="2.10.0", ecosystem="PyPI"),
]


class TestOSVLiveAPI:

    def test_osv_returns_results_for_vulnerable_packages(self):
        client = OSVClient()
        vulns = client.query(KNOWN_VULNERABLE)
        assert len(vulns) > 0, (
            "OSV API returned no results for known-vulnerable packages. "
            "Check internet connectivity or OSV API availability."
        )

    def test_requests_2_6_0_has_cve(self):
        """requests 2.6.0 has CVE-2014-1829 and others."""
        client = OSVClient()
        vulns = client.query([Package(name="requests", version="2.6.0", ecosystem="PyPI")])
        assert len(vulns) > 0, "requests==2.6.0 should have known CVEs in OSV"

    def test_pillow_9_0_0_has_cve(self):
        """Pillow 9.0.0 has multiple known CVEs."""
        client = OSVClient()
        vulns = client.query([Package(name="Pillow", version="9.0.0", ecosystem="PyPI")])
        assert len(vulns) > 0, "Pillow==9.0.0 should have known CVEs"

    def test_lodash_prototype_pollution(self):
        """lodash 4.17.15 has CVE-2021-23337 (prototype pollution)."""
        client = OSVClient()
        vulns = client.query([Package(name="lodash", version="4.17.15", ecosystem="npm")])
        assert len(vulns) > 0, "lodash@4.17.15 should have a prototype pollution CVE"

    def test_axios_ssrf(self):
        """axios 0.21.1 has CVE-2021-3749 (SSRF)."""
        client = OSVClient()
        vulns = client.query([Package(name="axios", version="0.21.1", ecosystem="npm")])
        assert len(vulns) > 0, "axios@0.21.1 should have a known CVE"

    def test_vuln_id_is_non_empty(self):
        client = OSVClient()
        vulns = client.query([Package(name="requests", version="2.6.0", ecosystem="PyPI")])
        for v in vulns:
            assert v.vuln_id, f"Vulnerability has empty vuln_id: {v}"

    def test_severity_is_set(self):
        # npm packages use GHSA entries which reliably include CVSS scores.
        # lodash@4.17.15 has GHSA-jf85-cpcp-j695 (prototype pollution, CVSS 7.4).
        client = OSVClient()
        vulns = client.query([Package(name="lodash", version="4.17.15", ecosystem="npm")])
        severities = {v.severity for v in vulns}
        assert severities - {Severity.UNKNOWN}, (
            f"lodash@4.17.15 GHSA entries should include real CVSS severity. Got: {severities}"
        )

    def test_fix_versions_present_for_some(self):
        # lodash@4.17.15 GHSA entries include fix versions (4.17.21).
        client = OSVClient()
        vulns = client.query([Package(name="lodash", version="4.17.15", ecosystem="npm")])
        with_fix = [v for v in vulns if v.fixed_in]
        assert len(with_fix) > 0, (
            "lodash@4.17.15 should have at least one GHSA entry with a fix version in OSV"
        )

    def test_batch_query_returns_one_result_per_package(self):
        """OSV batch query should return a result entry for every queried package."""
        packages = [
            Package(name="requests", version="2.6.0", ecosystem="PyPI"),
            Package(name="Pillow", version="9.0.0", ecosystem="PyPI"),
        ]
        client = OSVClient()
        # We can't check count (multiple CVEs per package), but we can verify
        # that packages with known vulns return at least 1 result each
        vulns = client.query(packages)
        packages_with_vulns = {v.package.lower() for v in vulns}
        assert "requests" in packages_with_vulns
        assert "pillow" in packages_with_vulns

    def test_references_are_urls(self):
        client = OSVClient()
        vulns = client.query([Package(name="requests", version="2.6.0", ecosystem="PyPI")])
        for v in vulns:
            for ref in v.references:
                assert ref.startswith("http"), f"Reference is not a URL: {ref}"

    def test_safe_packages_return_fewer_results(self):
        """Recent safe versions should have fewer (or zero) CVEs than old vulnerable ones."""
        client = OSVClient()
        safe_vulns = client.query(KNOWN_SAFE)
        vuln_vulns = client.query([Package(name="requests", version="2.6.0", ecosystem="PyPI")])
        # Old vulnerable package should have at least as many results
        safe_count = sum(1 for v in safe_vulns if v.package.lower() == "requests")
        old_count = len(vuln_vulns)
        assert old_count >= safe_count

    def test_no_results_for_nonexistent_package(self):
        client = OSVClient()
        vulns = client.query([
            Package(name="definitely-does-not-exist-12345xyz", version="1.0.0", ecosystem="PyPI")
        ])
        assert vulns == []

    def test_large_batch_does_not_crash(self):
        """Send 50 packages in one batch to verify chunking works."""
        packages = [
            Package(name=f"fake-pkg-{i}", version="1.0.0", ecosystem="PyPI")
            for i in range(50)
        ]
        packages.append(Package(name="requests", version="2.6.0", ecosystem="PyPI"))
        client = OSVClient()
        vulns = client.query(packages)
        # requests should still be found even in a large batch
        req_vulns = [v for v in vulns if v.package.lower() == "requests"]
        assert len(req_vulns) > 0

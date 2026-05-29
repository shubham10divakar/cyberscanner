from __future__ import annotations

import os
from typing import List, Optional

import httpx

from ..models import Package, Severity, Vulnerability

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"

_ECOSYSTEM_MAP = {
    "PyPI": "PIP",
    "npm": "NPM",
    "Go": "GO",
    "Maven": "MAVEN",
    "RubyGems": "RUBYGEMS",
    "Rust": "RUST",
}

_GQL_QUERY = """
query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!, $first: Int!) {
  securityVulnerabilities(ecosystem: $ecosystem, package: $package, first: $first) {
    nodes {
      advisory {
        ghsaId
        summary
        description
        severity
        cvss { score }
        identifiers { type value }
        references { url }
      }
      firstPatchedVersion { identifier }
      vulnerableVersionRange
    }
  }
}
"""


def _ghsa_severity(s: str) -> Severity:
    return {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MODERATE": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }.get(s.upper(), Severity.UNKNOWN)


class GitHubAdvisoryClient:

    def __init__(self) -> None:
        self.token: Optional[str] = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    @property
    def available(self) -> bool:
        return bool(self.token)

    def query(self, packages: List[Package]) -> List[Vulnerability]:
        if not self.available:
            return []
        vulns: List[Vulnerability] = []
        for pkg in packages:
            if pkg.version:
                vulns.extend(self._query_package(pkg))
        return vulns

    def _query_package(self, pkg: Package) -> List[Vulnerability]:
        ecosystem = _ECOSYSTEM_MAP.get(pkg.ecosystem)
        if not ecosystem:
            return []

        try:
            resp = httpx.post(
                GITHUB_GRAPHQL_URL,
                json={
                    "query": _GQL_QUERY,
                    "variables": {"ecosystem": ecosystem, "package": pkg.name, "first": 20},
                },
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json",
                },
                timeout=15,
            )
            resp.raise_for_status()
        except (httpx.HTTPError, httpx.TimeoutException):
            return []

        nodes = (
            resp.json()
            .get("data", {})
            .get("securityVulnerabilities", {})
            .get("nodes", [])
        )

        vulns = []
        for node in nodes:
            advisory = node.get("advisory", {})
            ghsa_id = advisory.get("ghsaId", "")

            vuln_id = ghsa_id
            for ident in advisory.get("identifiers", []):
                if ident.get("type") == "CVE":
                    vuln_id = ident.get("value", ghsa_id)
                    break

            severity = _ghsa_severity(advisory.get("severity", ""))
            cvss_score = advisory.get("cvss", {}).get("score")
            patched = node.get("firstPatchedVersion") or {}
            fixed_in = [patched["identifier"]] if patched.get("identifier") else []
            refs = [r.get("url", "") for r in advisory.get("references", []) if r.get("url")]

            vulns.append(
                Vulnerability(
                    vuln_id=vuln_id,
                    package=pkg.name,
                    version=pkg.version or "unknown",
                    ecosystem=pkg.ecosystem,
                    severity=severity,
                    cvss_score=cvss_score,
                    title=advisory.get("summary", ""),
                    description=advisory.get("description", "")[:500],
                    fixed_in=fixed_in,
                    references=refs[:5],
                    source="github",
                    aliases=[ghsa_id] if vuln_id != ghsa_id else [],
                )
            )
        return vulns

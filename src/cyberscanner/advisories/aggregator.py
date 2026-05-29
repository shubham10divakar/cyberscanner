from __future__ import annotations

from typing import Dict, List

from ..models import Package, Severity, Vulnerability
from .github import GitHubAdvisoryClient
from .osv import OSVClient

_SEV_RANK: Dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.UNKNOWN: 0,
}


class AdvisoryAggregator:

    def __init__(self) -> None:
        self.osv = OSVClient()
        self.github = GitHubAdvisoryClient()

    def query(self, packages: List[Package]) -> List[Vulnerability]:
        osv_results = self.osv.query(packages)
        github_results = self.github.query(packages)
        return self._deduplicate(osv_results + github_results)

    def _canonical_id(self, v: Vulnerability) -> str:
        for alias in [v.vuln_id] + v.aliases:
            if alias.startswith("CVE-"):
                return alias
        return v.vuln_id

    def _deduplicate(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        merged: Dict[str, Vulnerability] = {}

        for v in vulns:
            key = f"{v.package.lower()}:{v.version}:{self._canonical_id(v)}"
            if key not in merged:
                merged[key] = v
            else:
                existing = merged[key]
                all_aliases = list(set(existing.aliases + v.aliases + [existing.vuln_id, v.vuln_id]))
                all_fixed = list(set(existing.fixed_in + v.fixed_in))
                if _SEV_RANK[v.severity] > _SEV_RANK[existing.severity]:
                    merged[key] = v.model_copy(update={"aliases": all_aliases, "fixed_in": all_fixed})
                else:
                    merged[key] = existing.model_copy(update={"aliases": all_aliases, "fixed_in": all_fixed})

        return sorted(
            merged.values(),
            key=lambda x: (_SEV_RANK[x.severity], x.package),
            reverse=True,
        )

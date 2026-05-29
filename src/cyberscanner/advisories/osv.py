from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

import httpx

from ..models import Package, Severity, Vulnerability

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
CHUNK_SIZE = 100


def _parse_severity(vuln_data: dict) -> Tuple[Severity, Optional[float]]:
    """
    OSV querybatch now returns minimal stubs; full data comes from /vulns/{id}.
    Full records have severity[] and database_specific.severity.
    """
    cvss_score: Optional[float] = None

    for sev_item in vuln_data.get("severity") or []:
        score_str = sev_item.get("score", "")
        # score may be a bare float ("7.5") or a full CVSS vector
        try:
            cvss_score = float(score_str)
            break
        except (ValueError, TypeError):
            pass
        # CVSS vector string — base score is NOT in the vector; skip numeric extraction
        # fall through to database_specific string instead

    # Determine severity from CVSS score if we have a number
    if cvss_score is not None:
        if cvss_score >= 9.0:
            return Severity.CRITICAL, cvss_score
        if cvss_score >= 7.0:
            return Severity.HIGH, cvss_score
        if cvss_score >= 4.0:
            return Severity.MEDIUM, cvss_score
        return Severity.LOW, cvss_score

    # Fall back to the severity string in database_specific (GitHub Advisory entries)
    db = vuln_data.get("database_specific") or {}
    sev_str = db.get("severity", "").upper()
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MODERATE": Severity.MEDIUM,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }
    return mapping.get(sev_str, Severity.UNKNOWN), cvss_score


def _extract_fixed_versions(vuln_data: dict, ecosystem: str, pkg_name: str) -> List[str]:
    fixed_in = []
    for affected in vuln_data.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem", "").lower() != ecosystem.lower():
            continue
        if pkg.get("name", "").lower() != pkg_name.lower():
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                fixed = event.get("fixed")
                if fixed:
                    fixed_in.append(fixed)
    return fixed_in


def _osv_to_vuln(vuln_data: dict, pkg: Package) -> Vulnerability:
    severity, cvss_score = _parse_severity(vuln_data)
    fixed_in = _extract_fixed_versions(vuln_data, pkg.ecosystem, pkg.name)
    refs = [r.get("url", "") for r in (vuln_data.get("references") or []) if r.get("url")]

    return Vulnerability(
        vuln_id=vuln_data.get("id", ""),
        package=pkg.name,
        version=pkg.version or "unknown",
        ecosystem=pkg.ecosystem,
        severity=severity,
        cvss_score=cvss_score,
        title=vuln_data.get("summary", ""),
        description=(vuln_data.get("details") or "")[:500],
        fixed_in=fixed_in,
        references=refs[:5],
        source="osv",
        aliases=vuln_data.get("aliases") or [],
    )


def _fetch_full_vuln(vuln_id: str, client: httpx.Client) -> Optional[dict]:
    """Fetch the full vulnerability record by ID."""
    try:
        resp = client.get(OSV_VULN_URL.format(id=vuln_id), timeout=15)
        resp.raise_for_status()
        return resp.json()
    except (httpx.HTTPError, httpx.TimeoutException):
        return None


class OSVClient:

    def query(self, packages: List[Package]) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        for i in range(0, len(packages), CHUNK_SIZE):
            vulns.extend(self._query_batch(packages[i : i + CHUNK_SIZE]))
        return vulns

    def _query_batch(self, packages: List[Package]) -> List[Vulnerability]:
        indexed = [(i, p) for i, p in enumerate(packages) if p.version]
        if not indexed:
            return []

        queries = [
            {"version": p.version, "package": {"name": p.name, "ecosystem": p.ecosystem}}
            for _, p in indexed
        ]

        try:
            with httpx.Client() as client:
                # Step 1 — get vuln IDs matched to each package
                resp = client.post(OSV_BATCH_URL, json={"queries": queries}, timeout=30)
                resp.raise_for_status()
                results = resp.json().get("results", [])

                # Collect (vuln_id, package) pairs and unique IDs to fetch
                pairs: List[Tuple[str, Package]] = []
                unique_ids: Dict[str, Optional[dict]] = {}

                for (_, pkg), result in zip(indexed, results):
                    for stub in result.get("vulns") or []:
                        vid = stub.get("id")
                        if vid:
                            pairs.append((vid, pkg))
                            if vid not in unique_ids:
                                unique_ids[vid] = None

                # Step 2 — fetch full details for each unique vuln ID
                for vid in list(unique_ids.keys()):
                    unique_ids[vid] = _fetch_full_vuln(vid, client)

        except (httpx.HTTPError, httpx.TimeoutException):
            return []

        # Step 3 — build Vulnerability objects
        vulns: List[Vulnerability] = []
        for vid, pkg in pairs:
            full = unique_ids.get(vid)
            if full:
                vulns.append(_osv_to_vuln(full, pkg))

        return vulns

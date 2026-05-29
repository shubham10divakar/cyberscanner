from __future__ import annotations

import json
from typing import Any, Dict, Set

from ..models import ScanResult, Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.UNKNOWN: "none",
}


def to_sarif(result: ScanResult) -> Dict[str, Any]:
    rules = []
    results = []
    rule_ids: Set[str] = set()

    for v in result.vulnerabilities:
        rid = v.vuln_id
        if rid not in rule_ids:
            rule_ids.add(rid)
            help_uri = (
                f"https://osv.dev/vulnerability/{rid}"
                if v.source == "osv"
                else f"https://github.com/advisories/{rid}"
            )
            rules.append({
                "id": rid,
                "name": f"Vulnerability/{rid}",
                "shortDescription": {"text": v.title or rid},
                "fullDescription": {"text": v.description or v.title or rid},
                "helpUri": help_uri,
                "properties": {
                    "security-severity": str(v.cvss_score or ""),
                    "tags": ["security", "dependency"],
                },
            })

        fix_msg = (
            "Fix: upgrade to " + ", ".join(v.fixed_in)
            if v.fixed_in
            else "No fix available yet."
        )
        results.append({
            "ruleId": rid,
            "level": _SARIF_LEVEL[v.severity],
            "message": {"text": f"{v.package}@{v.version} is affected by {rid}. {fix_msg}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": result.target_path},
                    "region": {"startLine": 1},
                }
            }],
        })

    for s in result.secrets:
        rid = "SECRET/" + s.pattern_name.upper().replace(" ", "_")
        if rid not in rule_ids:
            rule_ids.add(rid)
            rules.append({
                "id": rid,
                "name": f"Secret/{s.pattern_name}",
                "shortDescription": {"text": f"Hardcoded {s.pattern_name} detected"},
                "properties": {"tags": ["security", "secret"]},
            })
        results.append({
            "ruleId": rid,
            "level": _SARIF_LEVEL[s.severity],
            "message": {"text": f"Potential {s.pattern_name} found in source code"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": s.file_path},
                    "region": {"startLine": s.line_no},
                }
            }],
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "cyberscanner",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/your-org/cyberscanner",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }


def to_sarif_json(result: ScanResult) -> str:
    return json.dumps(to_sarif(result), indent=2)

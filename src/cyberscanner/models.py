from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class Package(BaseModel):
    name: str
    version: Optional[str] = None
    ecosystem: str  # "PyPI" | "npm"
    pinned: bool = True


class Vulnerability(BaseModel):
    vuln_id: str
    package: str
    version: str
    ecosystem: str
    severity: Severity = Severity.UNKNOWN
    cvss_score: Optional[float] = None
    title: str = ""
    description: str = ""
    fixed_in: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    source: str = "osv"
    aliases: List[str] = Field(default_factory=list)


class SecretFinding(BaseModel):
    file_path: str
    line_no: int
    pattern_name: str
    severity: Severity = Severity.HIGH
    snippet: str
    match: str = ""


class ScanSummary(BaseModel):
    total_vulnerabilities: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0
    total_secrets: int = 0
    packages_scanned: int = 0
    files_scanned: int = 0


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    target_path: str
    scan_type: str = "full"
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    secrets: List[SecretFinding] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    packages_found: List[Package] = Field(default_factory=list)

    def compute_summary(self) -> None:
        counts: Dict[Severity, int] = {s: 0 for s in Severity}
        for v in self.vulnerabilities:
            counts[v.severity] += 1
        self.summary = ScanSummary(
            total_vulnerabilities=len(self.vulnerabilities),
            critical=counts[Severity.CRITICAL],
            high=counts[Severity.HIGH],
            medium=counts[Severity.MEDIUM],
            low=counts[Severity.LOW],
            unknown=counts[Severity.UNKNOWN],
            total_secrets=len(self.secrets),
            packages_scanned=len(self.packages_found),
            files_scanned=self.summary.files_scanned,
        )

    def to_json(self) -> str:
        return self.model_dump_json(indent=2)

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")

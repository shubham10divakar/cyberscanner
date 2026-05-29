from __future__ import annotations

from pathlib import Path

from .models import Package, ScanResult, SecretFinding, Severity, Vulnerability
from .scanner.python import PythonScanner
from .scanner.javascript import JavaScriptScanner
from .scanner.secrets import SecretsScanner
from .advisories.aggregator import AdvisoryAggregator


class Scanner:
    """Main entry point — scan a project directory for vulnerabilities and secrets."""

    def __init__(self, path: str = ".") -> None:
        self.path = str(Path(path).resolve())

    def scan(self, scan_secrets: bool = True, scan_deps: bool = True) -> ScanResult:
        result = ScanResult(target_path=self.path)
        packages = []

        if scan_deps:
            py_scanner = PythonScanner()
            if py_scanner.detect(self.path):
                packages.extend(py_scanner.parse(self.path))

            js_scanner = JavaScriptScanner()
            if js_scanner.detect(self.path):
                packages.extend(js_scanner.parse(self.path))

            result.packages_found = packages

            if packages:
                result.vulnerabilities = AdvisoryAggregator().query(packages)

        if scan_secrets:
            result.secrets = SecretsScanner().scan(self.path)

        result.compute_summary()
        result.summary.files_scanned = sum(
            1 for p in Path(self.path).rglob("*") if p.is_file()
        )
        return result


__all__ = [
    "Scanner",
    "ScanResult",
    "Vulnerability",
    "SecretFinding",
    "Package",
    "Severity",
]

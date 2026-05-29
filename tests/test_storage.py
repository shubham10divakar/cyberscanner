from __future__ import annotations

from pathlib import Path

import pytest

from cyberscanner.db.storage import LocalStorage
from cyberscanner.models import Package, ScanResult, SecretFinding, Severity, Vulnerability


@pytest.fixture
def storage(tmp_path, monkeypatch):
    monkeypatch.setattr("cyberscanner.db.storage.DB_DIR", tmp_path)
    monkeypatch.setattr("cyberscanner.db.storage.DB_PATH", tmp_path / "history.db")
    return LocalStorage()


def _vuln(**kwargs) -> Vulnerability:
    defaults = dict(
        vuln_id="CVE-2021-12345",
        package="requests",
        version="2.25.1",
        ecosystem="PyPI",
        severity=Severity.HIGH,
        title="Test vuln",
        fixed_in=["2.26.0"],
    )
    defaults.update(kwargs)
    return Vulnerability(**defaults)


def _result(vulns=None, secrets=None, path="/test/project") -> ScanResult:
    result = ScanResult(target_path=path)
    result.vulnerabilities = vulns or [_vuln()]
    result.secrets = secrets or [
        SecretFinding(
            file_path="/test/project/config.py",
            line_no=5,
            pattern_name="AWS Access Key ID",
            severity=Severity.CRITICAL,
            snippet='AWS_KEY = "AKIA..."',
        )
    ]
    result.packages_found = [Package(name="requests", version="2.25.1", ecosystem="PyPI")]
    result.compute_summary()
    return result


def test_save_and_list(storage):
    r = _result()
    storage.save(r)
    scans = storage.list_scans()
    assert len(scans) == 1
    assert scans[0]["vuln_count"] == 1
    assert scans[0]["secret_count"] == 1


def test_list_most_recent_first(storage):
    r1, r2 = _result(), _result()
    storage.save(r1)
    storage.save(r2)
    scans = storage.list_scans()
    assert scans[0]["id"] == r2.scan_id


def test_get_scan_returns_full_details(storage):
    r = _result()
    storage.save(r)
    data = storage.get_scan(r.scan_id)
    assert data is not None
    assert len(data["vulnerabilities"]) == 1
    assert data["vulnerabilities"][0]["vuln_id"] == "CVE-2021-12345"
    assert len(data["secrets"]) == 1


def test_get_scan_returns_none_for_unknown_id(storage):
    assert storage.get_scan("nonexistent-id") is None


def test_diff_identifies_new_and_fixed(storage):
    old = _result(vulns=[_vuln(vuln_id="CVE-2021-OLD", package="requests")])
    new = _result(vulns=[_vuln(vuln_id="CVE-2022-NEW", package="flask")])
    storage.save(old)
    storage.save(new)

    appeared, fixed = storage.diff_last_two()
    appeared_ids = {v["vuln_id"] for v in appeared}
    fixed_ids = {v["vuln_id"] for v in fixed}
    assert "CVE-2022-NEW" in appeared_ids
    assert "CVE-2021-OLD" in fixed_ids


def test_diff_no_change(storage):
    r1 = _result(vulns=[_vuln(vuln_id="CVE-SAME")])
    r2 = _result(vulns=[_vuln(vuln_id="CVE-SAME")])
    storage.save(r1)
    storage.save(r2)
    appeared, fixed = storage.diff_last_two()
    assert appeared == []
    assert fixed == []


def test_diff_returns_empty_with_single_scan(storage):
    storage.save(_result())
    appeared, fixed = storage.diff_last_two()
    assert appeared == []
    assert fixed == []


def test_list_respects_limit(storage):
    for _ in range(5):
        storage.save(_result())
    assert len(storage.list_scans(limit=3)) == 3

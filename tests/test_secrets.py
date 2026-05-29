from __future__ import annotations

from pathlib import Path

import pytest

from cyberscanner.scanner.secrets import SecretsScanner
from cyberscanner.models import Severity

FIXTURES = Path(__file__).parent / "fixtures"


def _write(tmp_path: Path, name: str, content: str) -> Path:
    f = tmp_path / name
    f.write_text(content, encoding="utf-8")
    return f


def test_detect_aws_access_key(tmp_path):
    _write(tmp_path, "config.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLEKEY"\n')
    findings = SecretsScanner().scan(str(tmp_path))
    names = {f.pattern_name for f in findings}
    assert "AWS Access Key ID" in names


def test_detect_github_pat(tmp_path):
    _write(tmp_path, "deploy.sh", 'TOKEN="ghp_16C7e42F292c6912E7710c838347Ae178B4a"\n')
    findings = SecretsScanner().scan(str(tmp_path))
    names = {f.pattern_name for f in findings}
    assert "GitHub Personal Access Token" in names


def test_detect_private_key_block(tmp_path):
    _write(tmp_path, "key.pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIEo\n-----END RSA PRIVATE KEY-----\n")
    findings = SecretsScanner().scan(str(tmp_path))
    names = {f.pattern_name for f in findings}
    assert "Private Key Block" in names


def test_detect_database_url(tmp_path):
    _write(tmp_path, "settings.py", 'DB = "postgresql://user:mypassword@localhost/db"\n')
    findings = SecretsScanner().scan(str(tmp_path))
    names = {f.pattern_name for f in findings}
    assert "Database URL with credentials" in names


def test_detect_stripe_live_key(tmp_path):
    _write(tmp_path, "payments.py", 'STRIPE = "sk_live_51H7TestKeyValue12345678"\n')
    findings = SecretsScanner().scan(str(tmp_path))
    names = {f.pattern_name for f in findings}
    assert "Stripe Live Secret Key" in names


def test_skip_node_modules(tmp_path):
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    _write(nm, "index.js", 'const k = "AKIAIOSFODNN7EXAMPLEKEY";\n')
    _write(tmp_path, "clean.py", "x = 1\n")
    findings = SecretsScanner().scan(str(tmp_path))
    assert all("node_modules" not in f.file_path for f in findings)


def test_skip_binary_extensions(tmp_path):
    (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n")
    findings = SecretsScanner().scan(str(tmp_path))
    assert findings == []


def test_scan_single_file():
    findings = SecretsScanner().scan(str(FIXTURES / "secret_sample.py"))
    names = {f.pattern_name for f in findings}
    assert "AWS Access Key ID" in names
    assert "GitHub Personal Access Token" in names
    assert "Database URL with credentials" in names


def test_severity_levels(tmp_path):
    _write(tmp_path, "config.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLEKEY"\n')
    findings = SecretsScanner().scan(str(tmp_path))
    aws = next(f for f in findings if f.pattern_name == "AWS Access Key ID")
    assert aws.severity == Severity.CRITICAL


def test_redacted_match(tmp_path):
    _write(tmp_path, "config.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLEKEY"\n')
    findings = SecretsScanner().scan(str(tmp_path))
    aws = next(f for f in findings if f.pattern_name == "AWS Access Key ID")
    assert "****" in aws.match
    assert aws.match != aws.snippet


def test_line_number_reported(tmp_path):
    _write(tmp_path, "config.py", "x = 1\ny = 2\nTOKEN = \"ghp_16C7e42F292c6912E7710c838347Ae178B4a\"\n")
    findings = SecretsScanner().scan(str(tmp_path))
    gh = next(f for f in findings if f.pattern_name == "GitHub Personal Access Token")
    assert gh.line_no == 3

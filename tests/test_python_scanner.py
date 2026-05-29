from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from cyberscanner.scanner.python import PythonScanner

FIXTURES = Path(__file__).parent / "fixtures"


def test_detect_requirements_txt(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    assert PythonScanner().detect(str(tmp_path))


def test_detect_returns_false_on_empty_dir(tmp_path):
    assert not PythonScanner().detect(str(tmp_path))


def test_parse_pinned_versions(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.25.1\ndjango==2.2.0\n")
    packages = PythonScanner().parse(str(tmp_path))
    by_name = {p.name.lower(): p for p in packages}
    assert "requests" in by_name
    assert by_name["requests"].version == "2.25.1"
    assert by_name["requests"].pinned is True
    assert by_name["django"].version == "2.2.0"


def test_parse_skips_comments_and_flags(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# comment\n--index-url https://pypi.org\n-r other.txt\nrequests==2.25.1\n"
    )
    packages = PythonScanner().parse(str(tmp_path))
    assert len(packages) == 1
    assert packages[0].name.lower() == "requests"


def test_parse_unpinned_resolves_version(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests\n")
    with patch("cyberscanner.scanner.python._resolve_version", return_value="2.31.0"):
        packages = PythonScanner().parse(str(tmp_path))
    assert packages[0].pinned is False
    assert packages[0].version == "2.31.0"


def test_parse_pyproject_pep621(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["requests>=2.0", "flask==2.0.0"]\n'
    )
    with patch("cyberscanner.scanner.python._resolve_version", return_value="2.31.0"):
        packages = PythonScanner().parse(str(tmp_path))
    names = {p.name.lower() for p in packages}
    assert "flask" in names
    assert "requests" in names


def test_parse_setup_py(tmp_path):
    (tmp_path / "setup.py").write_text(
        'setup(install_requires=["requests>=2.0", "flask==2.0.0"])\n'
    )
    with patch("cyberscanner.scanner.python._resolve_version", return_value="99.0"):
        packages = PythonScanner().parse(str(tmp_path))
    names = {p.name.lower() for p in packages}
    assert "requests" in names
    assert "flask" in names


def test_parse_fixture_requirements():
    packages = PythonScanner().parse(str(FIXTURES))
    names = {p.name.lower() for p in packages}
    assert "requests" in names
    assert "django" in names


def test_deduplication_across_files(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.25.1\n")
    (tmp_path / "requirements-dev.txt").write_text("requests==2.25.1\n")
    packages = PythonScanner().parse(str(tmp_path))
    names = [p.name.lower() for p in packages]
    assert names.count("requests") == 1

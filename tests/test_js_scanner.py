from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyberscanner.scanner.javascript import JavaScriptScanner

FIXTURES = Path(__file__).parent / "fixtures"


def test_detect_with_package_json(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{}}')
    assert JavaScriptScanner().detect(str(tmp_path))


def test_detect_false_without_package_json(tmp_path):
    assert not JavaScriptScanner().detect(str(tmp_path))


def test_parse_package_json_only(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"lodash": "^4.17.15"},
        "devDependencies": {"jest": "^27.0.0"},
    }))
    packages = JavaScriptScanner().parse(str(tmp_path))
    names = {p.name for p in packages}
    assert "lodash" in names
    assert "jest" in names


def test_parse_with_lockfile_uses_exact_version(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"lodash": "^4.17.15"},
    }))
    lock = {
        "lockfileVersion": 2,
        "packages": {
            "": {},
            "node_modules/lodash": {"version": "4.17.21"},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    packages = JavaScriptScanner().parse(str(tmp_path))
    lodash = next(p for p in packages if p.name == "lodash")
    assert lodash.version == "4.17.21"
    assert lodash.pinned is True


def test_parse_lockfile_v1(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"express": "^4.17.1"}}))
    lock = {
        "lockfileVersion": 1,
        "dependencies": {"express": {"version": "4.17.3"}},
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    packages = JavaScriptScanner().parse(str(tmp_path))
    expr = next(p for p in packages if p.name == "express")
    assert expr.version == "4.17.3"


def test_parse_fixture_with_lockfile():
    packages = JavaScriptScanner().parse(str(FIXTURES))
    names = {p.name for p in packages}
    assert "lodash" in names
    assert "express" in names
    lodash = next(p for p in packages if p.name == "lodash")
    assert lodash.version == "4.17.15"
    assert lodash.pinned is True

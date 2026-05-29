"""Shared fixtures for smoke tests."""
from __future__ import annotations

from pathlib import Path

import pytest

SMOKE_DIR = Path(__file__).parent
FIXTURES = SMOKE_DIR / "fixtures"

PYTHON_PROJECT = FIXTURES / "python_project"
JS_PROJECT = FIXTURES / "js_project"
CLEAN_PROJECT = FIXTURES / "clean_project"
SECRETS_PROJECT = FIXTURES / "secrets_project"


def pytest_configure(config):
    config.addinivalue_line("markers", "smoke: end-to-end smoke tests (may make real network calls)")
    config.addinivalue_line("markers", "live: requires internet access to OSV / GitHub APIs")
    config.addinivalue_line("markers", "cli: tests that invoke the CLI via subprocess")
    config.addinivalue_line("markers", "api: tests that use the Python API directly")

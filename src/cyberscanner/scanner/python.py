from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import List, Optional, Set

import httpx
from packaging.requirements import InvalidRequirement, Requirement

from .base import BaseScanner
from ..models import Package


def _load_toml(path: str) -> dict:
    if sys.version_info >= (3, 11):
        import tomllib
        with open(path, "rb") as f:
            return tomllib.load(f)
    else:
        import tomli  # type: ignore[import]
        with open(path, "rb") as f:
            return tomli.load(f)


def _resolve_version(name: str) -> Optional[str]:
    """Fetch latest published version from PyPI for unpinned packages."""
    try:
        resp = httpx.get(f"https://pypi.org/pypi/{name}/json", timeout=10)
        if resp.status_code == 200:
            return resp.json()["info"]["version"]
    except Exception:
        pass
    return None


def _parse_req_string(req_str: str) -> Optional[Package]:
    try:
        req = Requirement(req_str)
        name = req.name
        version: Optional[str] = None
        pinned = False
        for spec in req.specifier:
            if spec.operator in ("==", "==="):
                version = spec.version
                pinned = True
                break
        if not version:
            version = _resolve_version(name)
        return Package(name=name, version=version, ecosystem="PyPI", pinned=pinned)
    except InvalidRequirement:
        return None


class PythonScanner(BaseScanner):

    _MANIFEST_NAMES = [
        "requirements.txt",
        "requirements-dev.txt",
        "requirements-test.txt",
        "requirements-prod.txt",
        "pyproject.toml",
        "setup.py",
        "Pipfile",
    ]

    def detect(self, path: str) -> bool:
        root = Path(path)
        for name in self._MANIFEST_NAMES:
            if (root / name).exists():
                return True
        req_dir = root / "requirements"
        if req_dir.is_dir() and any(req_dir.glob("*.txt")):
            return True
        return False

    def parse(self, path: str) -> List[Package]:
        root = Path(path)
        packages: List[Package] = []
        seen: Set[str] = set()

        for req_file in list(root.glob("requirements*.txt")) + list((root / "requirements").glob("*.txt") if (root / "requirements").is_dir() else []):
            packages.extend(self._parse_requirements_file(str(req_file), seen))

        ppt = root / "pyproject.toml"
        if ppt.exists():
            packages.extend(self._parse_pyproject(str(ppt), seen))

        sp = root / "setup.py"
        if sp.exists():
            packages.extend(self._parse_setup_py(str(sp), seen))

        pipfile = root / "Pipfile"
        if pipfile.exists():
            packages.extend(self._parse_pipfile(str(pipfile), seen))

        return packages

    def _parse_requirements_file(self, filepath: str, seen: Set[str]) -> List[Package]:
        packages = []
        try:
            with open(filepath, encoding="utf-8", errors="ignore") as f:
                for raw_line in f:
                    line = raw_line.strip()
                    if not line or line.startswith(("#", "-r", "-c", "--", "-e")):
                        continue
                    line = line.split("#")[0].strip()
                    if not line:
                        continue
                    pkg = _parse_req_string(line)
                    if pkg and pkg.name.lower() not in seen:
                        seen.add(pkg.name.lower())
                        packages.append(pkg)
        except (OSError, IOError):
            pass
        return packages

    def _parse_pyproject(self, filepath: str, seen: Set[str]) -> List[Package]:
        packages = []
        try:
            data = _load_toml(filepath)
        except Exception:
            return packages

        # PEP 621
        for dep in data.get("project", {}).get("dependencies", []):
            pkg = _parse_req_string(dep)
            if pkg and pkg.name.lower() not in seen:
                seen.add(pkg.name.lower())
                packages.append(pkg)

        # Poetry
        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        for name, spec in poetry_deps.items():
            if name.lower() in ("python", "pip") or name.lower() in seen:
                continue
            seen.add(name.lower())
            version: Optional[str] = None
            pinned = False
            if isinstance(spec, str) and spec != "*":
                clean = spec.lstrip("^~>=<! ")
                if clean and clean[0].isdigit():
                    version = clean.split(",")[0].strip()
                    pinned = "==" in spec
            elif isinstance(spec, dict):
                raw = spec.get("version", "")
                version = raw.lstrip("^~>=<! ") or None
            if not version:
                version = _resolve_version(name)
            packages.append(Package(name=name, version=version, ecosystem="PyPI", pinned=pinned))

        return packages

    def _parse_setup_py(self, filepath: str, seen: Set[str]) -> List[Package]:
        packages = []
        try:
            with open(filepath, encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except (OSError, IOError):
            return packages

        match = re.search(r"install_requires\s*=\s*\[([^\]]+)\]", content, re.DOTALL)
        if match:
            for req_str in re.findall(r'["\']([^"\']+)["\']', match.group(1)):
                pkg = _parse_req_string(req_str.strip())
                if pkg and pkg.name.lower() not in seen:
                    seen.add(pkg.name.lower())
                    packages.append(pkg)
        return packages

    def _parse_pipfile(self, filepath: str, seen: Set[str]) -> List[Package]:
        packages = []
        try:
            data = _load_toml(filepath)
        except Exception:
            return packages

        for section in ("packages", "dev-packages"):
            for name, spec in data.get(section, {}).items():
                if name.lower() in seen:
                    continue
                seen.add(name.lower())
                version: Optional[str] = None
                pinned = False
                if isinstance(spec, str) and spec != "*":
                    version = spec.lstrip("=><! ")
                    pinned = spec.startswith("==")
                if not version:
                    version = _resolve_version(name)
                packages.append(Package(name=name, version=version, ecosystem="PyPI", pinned=pinned))
        return packages

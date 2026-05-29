from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional

from .base import BaseScanner
from ..models import Package


class JavaScriptScanner(BaseScanner):

    def detect(self, path: str) -> bool:
        return (Path(path) / "package.json").exists()

    def parse(self, path: str) -> List[Package]:
        root = Path(path)
        locked: Dict[str, str] = {}

        lock = root / "package-lock.json"
        yarn = root / "yarn.lock"

        if lock.exists():
            locked = self._parse_lockfile(str(lock))
        elif yarn.exists():
            locked = self._parse_yarn_lock(str(yarn))

        pkg_json = root / "package.json"
        if pkg_json.exists():
            return self._parse_package_json(str(pkg_json), locked)
        return []

    def _parse_package_json(self, filepath: str, locked: Dict[str, str]) -> List[Package]:
        packages = []
        try:
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return packages

        all_deps: Dict[str, str] = {}
        all_deps.update(data.get("dependencies", {}))
        all_deps.update(data.get("devDependencies", {}))

        for name, version_spec in all_deps.items():
            exact = locked.get(name)
            if exact:
                packages.append(Package(name=name, version=exact, ecosystem="npm", pinned=True))
            else:
                clean = version_spec.lstrip("^~>=<! ")
                pinned = not any(c in version_spec for c in "^~><") and bool(clean) and clean[0].isdigit()
                packages.append(Package(name=name, version=clean or None, ecosystem="npm", pinned=pinned))

        return packages

    def _parse_lockfile(self, filepath: str) -> Dict[str, str]:
        locked: Dict[str, str] = {}
        try:
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return locked

        lock_version = data.get("lockfileVersion", 1)
        if lock_version >= 2:
            for pkg_path, info in data.get("packages", {}).items():
                if not pkg_path:
                    continue
                # Strip "node_modules/" prefix (Python 3.8 compatible)
                prefix = "node_modules/"
                name = pkg_path[len(prefix):] if pkg_path.startswith(prefix) else pkg_path
                locked[name] = info.get("version", "")
        else:
            for name, info in data.get("dependencies", {}).items():
                locked[name] = info.get("version", "")

        return locked

    def _parse_yarn_lock(self, filepath: str) -> Dict[str, str]:
        locked: Dict[str, str] = {}
        try:
            with open(filepath, encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except (OSError, IOError):
            return locked

        for block in re.split(r"\n\n+", content):
            lines = block.strip().splitlines()
            if not lines:
                continue
            header = lines[0].strip().rstrip(":")
            name_match = re.match(r'^"?(@?[^@"]+)@', header)
            if not name_match:
                continue
            name = name_match.group(1).strip()
            for line in lines[1:]:
                v_match = re.match(r'\s+version\s+"?([^"\s]+)"?', line)
                if v_match:
                    locked[name] = v_match.group(1)
                    break

        return locked

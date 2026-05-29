from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from ..models import ScanResult

DB_DIR = Path.home() / ".cyberscanner"
DB_PATH = DB_DIR / "history.db"

_CREATE_SCANS = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    target_path TEXT NOT NULL,
    scan_type TEXT NOT NULL DEFAULT 'full',
    packages_scanned INTEGER DEFAULT 0,
    vuln_count INTEGER DEFAULT 0,
    secret_count INTEGER DEFAULT 0
)
"""

_CREATE_VULNS = """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    package TEXT NOT NULL,
    version TEXT,
    vuln_id TEXT NOT NULL,
    severity TEXT,
    cvss_score REAL,
    fixed_in TEXT,
    title TEXT,
    source TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
)
"""

_CREATE_SECRETS = """
CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_no INTEGER,
    pattern_name TEXT,
    severity TEXT,
    snippet TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
)
"""


class LocalStorage:

    def __init__(self) -> None:
        DB_DIR.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(DB_PATH))
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        self._conn.execute(_CREATE_SCANS)
        self._conn.execute(_CREATE_VULNS)
        self._conn.execute(_CREATE_SECRETS)
        self._conn.commit()

    def save(self, result: ScanResult) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO scans (id, timestamp, target_path, scan_type, packages_scanned, vuln_count, secret_count) "
                "VALUES (?,?,?,?,?,?,?)",
                (
                    result.scan_id,
                    result.timestamp.isoformat(),
                    result.target_path,
                    result.scan_type,
                    result.summary.packages_scanned,
                    result.summary.total_vulnerabilities,
                    result.summary.total_secrets,
                ),
            )
            for v in result.vulnerabilities:
                self._conn.execute(
                    "INSERT INTO vulnerabilities (scan_id, package, version, vuln_id, severity, cvss_score, fixed_in, title, source) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        result.scan_id,
                        v.package,
                        v.version,
                        v.vuln_id,
                        v.severity.value,
                        v.cvss_score,
                        json.dumps(v.fixed_in),
                        v.title,
                        v.source,
                    ),
                )
            for s in result.secrets:
                self._conn.execute(
                    "INSERT INTO secrets (scan_id, file_path, line_no, pattern_name, severity, snippet) "
                    "VALUES (?,?,?,?,?,?)",
                    (
                        result.scan_id,
                        s.file_path,
                        s.line_no,
                        s.pattern_name,
                        s.severity.value,
                        s.snippet,
                    ),
                )

    def list_scans(self, limit: int = 20) -> List[dict]:
        rows = self._conn.execute(
            "SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_scan(self, scan_id: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if not row:
            return None
        scan = dict(row)
        scan["vulnerabilities"] = [
            dict(r)
            for r in self._conn.execute(
                "SELECT * FROM vulnerabilities WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        ]
        scan["secrets"] = [
            dict(r)
            for r in self._conn.execute(
                "SELECT * FROM secrets WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        ]
        return scan

    def diff_last_two(self, target_path: Optional[str] = None) -> Tuple[List[dict], List[dict]]:
        """Return (new_vulns, fixed_vulns) comparing the last two scans."""
        if target_path:
            rows = self._conn.execute(
                "SELECT id FROM scans WHERE target_path = ? ORDER BY timestamp DESC LIMIT 2",
                (target_path,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT id FROM scans ORDER BY timestamp DESC LIMIT 2"
            ).fetchall()

        if len(rows) < 2:
            return [], []

        new_id, old_id = rows[0]["id"], rows[1]["id"]

        def _keys(scan_id: str) -> Set[str]:
            return {
                r["vuln_id"] + "|" + r["package"]
                for r in self._conn.execute(
                    "SELECT vuln_id, package FROM vulnerabilities WHERE scan_id = ?", (scan_id,)
                ).fetchall()
            }

        new_keys = _keys(new_id)
        old_keys = _keys(old_id)
        appeared = new_keys - old_keys
        fixed_keys = old_keys - new_keys

        new_rows = [
            dict(r)
            for r in self._conn.execute(
                "SELECT * FROM vulnerabilities WHERE scan_id = ?", (new_id,)
            ).fetchall()
            if (r["vuln_id"] + "|" + r["package"]) in appeared
        ]
        fixed_rows = [
            dict(r)
            for r in self._conn.execute(
                "SELECT * FROM vulnerabilities WHERE scan_id = ?", (old_id,)
            ).fetchall()
            if (r["vuln_id"] + "|" + r["package"]) in fixed_keys
        ]
        return new_rows, fixed_rows

    def close(self) -> None:
        self._conn.close()

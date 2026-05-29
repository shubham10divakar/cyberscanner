from __future__ import annotations

import re
from pathlib import Path
from typing import List, Set, Tuple

from ..models import SecretFinding, Severity

SKIP_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".zip", ".tar", ".gz", ".bz2", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib",
    ".pyc", ".pyo", ".class",
    ".mp3", ".mp4", ".avi", ".mov",
    ".woff", ".woff2", ".ttf", ".eot",
}

SKIP_DIRS: Set[str] = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "env", "dist", "build", ".tox", ".pytest_cache",
    "site-packages", ".mypy_cache", ".ruff_cache",
}

# (name, pattern, severity)
_RAW_PATTERNS: List[Tuple[str, str, Severity]] = [
    ("AWS Access Key ID",           r"AKIA[0-9A-Z]{16}",                                                         Severity.CRITICAL),
    ("AWS Secret Access Key",       r"(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key[\s]*[=:\"']+\s*([A-Za-z0-9/+=]{40})", Severity.CRITICAL),
    ("GitHub Personal Access Token",r"ghp_[A-Za-z0-9]{36}",                                                      Severity.CRITICAL),
    ("GitHub Fine-grained Token",   r"github_pat_[A-Za-z0-9_]{82}",                                              Severity.CRITICAL),
    ("GitHub OAuth Token",          r"gho_[A-Za-z0-9]{36}",                                                      Severity.HIGH),
    ("GitHub App Token",            r"ghs_[A-Za-z0-9]{36}",                                                      Severity.HIGH),
    ("Stripe Live Secret Key",      r"sk_live_[A-Za-z0-9]{24,34}",                                               Severity.CRITICAL),
    ("Stripe Live Publishable Key", r"pk_live_[A-Za-z0-9]{24,34}",                                               Severity.HIGH),
    ("OpenAI API Key",              r"sk-[A-Za-z0-9]{48}",                                                        Severity.CRITICAL),
    ("OpenAI Project Key",          r"sk-proj-[A-Za-z0-9\-_]{50,}",                                              Severity.CRITICAL),
    ("Anthropic API Key",           r"sk-ant-[A-Za-z0-9\-_]{90,}",                                               Severity.CRITICAL),
    ("Google API Key",              r"AIza[0-9A-Za-z\-_]{35}",                                                    Severity.HIGH),
    ("Slack Bot Token",             r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}",                           Severity.HIGH),
    ("Slack User Token",            r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32}",             Severity.HIGH),
    ("Slack App Token",             r"xapp-\d-[A-Z0-9]{10,13}-\d{11,13}-[a-z0-9]{64}",                          Severity.HIGH),
    ("Twilio Auth Token",           r"SK[0-9a-fA-F]{32}",                                                         Severity.HIGH),
    ("SendGrid API Key",            r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",                              Severity.HIGH),
    ("Mailgun API Key",             r"key-[0-9a-zA-Z]{32}",                                                       Severity.HIGH),
    ("HuggingFace Token",           r"hf_[A-Za-z0-9]{34}",                                                        Severity.HIGH),
    ("Private Key Block",           r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",   Severity.CRITICAL),
    ("JWT Token",                   r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",   Severity.MEDIUM),
    ("Database URL with credentials", r"(?:mysql|postgresql|postgres|mongodb|redis|mssql)://[^:@\s]+:[^@\s]+@[^\s\"']+", Severity.CRITICAL),
    ("Generic Secret Assignment",   r'(?i)(?:secret|api[_\-]?key|auth[_\-]?token|access[_\-]?token|private[_\-]?key|password)\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{20,})["\']', Severity.MEDIUM),
    ("Bearer Token in code",        r'(?i)authorization["\']?\s*[=:]\s*["\']Bearer\s+([A-Za-z0-9\-._~+/]+=*)',  Severity.HIGH),
]

_COMPILED = [(name, re.compile(pattern), sev) for name, pattern, sev in _RAW_PATTERNS]


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def _should_skip(path: Path) -> bool:
    for part in path.parts:
        if part in SKIP_DIRS:
            return True
    return path.suffix.lower() in SKIP_EXTENSIONS


class SecretsScanner:

    def scan(self, path: str) -> List[SecretFinding]:
        root = Path(path)
        findings: List[SecretFinding] = []
        if root.is_file():
            findings.extend(self._scan_file(root))
        else:
            for fpath in root.rglob("*"):
                if fpath.is_file() and not _should_skip(fpath):
                    findings.extend(self._scan_file(fpath))
        return findings

    def _scan_file(self, fpath: Path) -> List[SecretFinding]:
        findings = []
        try:
            with open(fpath, encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except (OSError, IOError):
            return findings

        for lineno, line in enumerate(lines, 1):
            for pattern_name, regex, severity in _COMPILED:
                for match in regex.finditer(line):
                    val = match.group(0)
                    findings.append(SecretFinding(
                        file_path=str(fpath),
                        line_no=lineno,
                        pattern_name=pattern_name,
                        severity=severity,
                        snippet=line.rstrip()[:120],
                        match=_redact(val),
                    ))
        return findings

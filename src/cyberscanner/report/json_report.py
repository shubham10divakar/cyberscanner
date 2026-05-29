from __future__ import annotations

from ..models import ScanResult


def to_json(result: ScanResult, indent: int = 2) -> str:
    return result.to_json()

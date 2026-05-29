from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from ..models import Package


class BaseScanner(ABC):

    @abstractmethod
    def detect(self, path: str) -> bool:
        """Return True if this scanner finds relevant files at path."""
        ...

    @abstractmethod
    def parse(self, path: str) -> List[Package]:
        """Extract packages from project files at path."""
        ...

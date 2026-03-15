from __future__ import annotations

from abc import ABC, abstractmethod


class TimingSafeComparatorPort(ABC):
    @abstractmethod
    def equals(self, a: bytes, b: bytes) -> bool: ...

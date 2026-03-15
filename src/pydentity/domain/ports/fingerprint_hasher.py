from __future__ import annotations

from abc import ABC, abstractmethod


class FingerprintHasherPort(ABC):
    @abstractmethod
    def hash(self, raw: str) -> str: ...

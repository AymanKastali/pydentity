from __future__ import annotations

from abc import ABC, abstractmethod


class RawTokenGeneratorPort(ABC):
    @abstractmethod
    def generate(self) -> str: ...

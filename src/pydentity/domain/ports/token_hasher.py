from __future__ import annotations

from abc import ABC, abstractmethod


class TokenHasherPort(ABC):
    @abstractmethod
    def hash(self, raw_token: str) -> bytes: ...

    @abstractmethod
    def verify(self, candidate: str, stored: bytes) -> bool: ...

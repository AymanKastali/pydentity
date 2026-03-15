from __future__ import annotations

from abc import ABC, abstractmethod


class EmailValidatorPort(ABC):
    @abstractmethod
    def validate(self, local_part: str, domain: str) -> None: ...

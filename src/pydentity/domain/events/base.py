from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DomainEvent:
    @property
    def name(self) -> str:
        return self.__class__.__name__

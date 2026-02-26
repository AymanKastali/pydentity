from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime, timedelta

    from pydentity.domain.models.value_objects import PasswordResetToken


class ResetTokenGeneratorPort(ABC):
    @abstractmethod
    def generate(
        self, ttl: timedelta, now: datetime
    ) -> tuple[str, PasswordResetToken]: ...

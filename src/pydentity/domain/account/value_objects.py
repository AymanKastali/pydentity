import re
from dataclasses import dataclass
from enum import StrEnum, auto
from typing import ClassVar


class AccountStatus(StrEnum):
    PENDING_VERIFICATION = auto()
    ACTIVE = auto()
    SUSPENDED = auto()


@dataclass(frozen=True, slots=True)
class Email:
    _PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

    value: str

    def __post_init__(self) -> None:
        if len(self.value) > 254:
            raise ValueError(f"Email too long: {len(self.value)} chars")
        if not self._PATTERN.match(self.value):
            raise ValueError(f"Invalid email: {self.value}")


@dataclass(frozen=True, slots=True)
class HashedPassword:
    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise ValueError("Hashed password cannot be empty")


@dataclass(frozen=True, slots=True)
class VerificationToken:
    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise ValueError("Verification token cannot be empty")

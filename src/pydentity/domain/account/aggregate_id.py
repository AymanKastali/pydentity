from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class AccountId:
    value: UUID

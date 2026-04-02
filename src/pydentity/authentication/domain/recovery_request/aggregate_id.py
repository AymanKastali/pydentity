from dataclasses import dataclass
from uuid import UUID

from pydentity.shared_kernel import ValueObject


@dataclass(frozen=True, slots=True)
class RecoveryRequestId(ValueObject):
    value: UUID

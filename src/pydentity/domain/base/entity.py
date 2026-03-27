from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from uuid import UUID


class Entity:
    def __init__(self, entity_id: UUID) -> None:
        self._id = entity_id

    @property
    def id(self) -> UUID:
        return self._id

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

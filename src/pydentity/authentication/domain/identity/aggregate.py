from typing import TYPE_CHECKING

from pydentity.authentication.domain.identity.events import IdentityCreated
from pydentity.shared_kernel import AggregateRoot, IdentityId

if TYPE_CHECKING:
    from datetime import datetime


class Identity(AggregateRoot[IdentityId]):
    def __init__(self, identity_id: IdentityId) -> None:
        super().__init__(identity_id)

    # --- Creation ---

    @classmethod
    def create(cls, identity_id: IdentityId, now: datetime) -> Identity:
        identity = cls(identity_id=identity_id)
        identity.record_event(IdentityCreated(occurred_at=now, identity_id=identity_id))
        return identity

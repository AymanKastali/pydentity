from dataclasses import dataclass

from pydentity.shared_kernel import DomainEvent, IdentityId


@dataclass(frozen=True, slots=True)
class IdentityCreated(DomainEvent):
    identity_id: IdentityId

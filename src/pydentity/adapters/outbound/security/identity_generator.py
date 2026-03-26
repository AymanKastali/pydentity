from __future__ import annotations

from uuid import uuid7

from pydentity.domain.models.value_objects import DeviceId, SessionId, UserId
from pydentity.domain.ports.identity_generation import IdentityGeneratorPort


class UUIDIdentityGenerator(IdentityGeneratorPort):
    def new_user_id(self) -> UserId:
        return UserId(value=uuid7())

    def new_session_id(self) -> SessionId:
        return SessionId(value=uuid7())

    def new_device_id(self) -> DeviceId:
        return DeviceId(value=uuid7())

    def new_token_id(self) -> str:
        return str(uuid7())

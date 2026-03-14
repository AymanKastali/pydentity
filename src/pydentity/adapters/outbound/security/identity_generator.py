from __future__ import annotations

from ulid import ULID

from pydentity.domain.models.value_objects import DeviceId, SessionId, UserId
from pydentity.domain.ports.identity_generation import IdentityGeneratorPort


class UlidIdentityGenerator(IdentityGeneratorPort):
    def new_user_id(self) -> UserId:
        return UserId(value=str(ULID()))

    def new_session_id(self) -> SessionId:
        return SessionId(value=str(ULID()))

    def new_device_id(self) -> DeviceId:
        return DeviceId(value=str(ULID()))

    def new_token_id(self) -> str:
        return str(ULID())

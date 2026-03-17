"""Port for JWK key store operations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from pydentity.application.models.jwk import JWKKeyPair, JWKPublicKey


class JWKKeyStorePort(ABC):
    @abstractmethod
    def get_signing_key(self) -> JWKKeyPair: ...

    @abstractmethod
    def get_all_public_keys(self) -> Sequence[JWKPublicKey]: ...

    @abstractmethod
    def get_public_key(self, kid: str) -> JWKPublicKey | None: ...

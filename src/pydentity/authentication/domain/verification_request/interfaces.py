from abc import ABC, abstractmethod

from pydentity.authentication.domain.verification_request.value_objects import (
    HashedVerificationRequestToken,
    RawVerificationRequestToken,
)


class VerificationRequestTokenHasher(ABC):
    @abstractmethod
    def hash(
        self, token: RawVerificationRequestToken
    ) -> HashedVerificationRequestToken: ...


class VerificationRequestTokenVerifier(ABC):
    @abstractmethod
    def verify(
        self, token: RawVerificationRequestToken, hashed: HashedVerificationRequestToken
    ) -> bool: ...

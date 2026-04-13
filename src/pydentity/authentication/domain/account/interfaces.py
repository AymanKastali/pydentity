from abc import ABC, abstractmethod

from pydentity.authentication.domain.account.value_objects import (
    Email,
    HashedPassword,
    RawPassword,
)


class PasswordHasher(ABC):
    @abstractmethod
    def hash(self, password: RawPassword) -> HashedPassword: ...


class PasswordVerifier(ABC):
    @abstractmethod
    def verify(self, password: RawPassword, hashed: HashedPassword) -> bool: ...


class CompromisedPasswordChecker(ABC):
    @abstractmethod
    def is_compromised(self, password: RawPassword) -> bool: ...


class EmailVerifier(ABC):
    @abstractmethod
    def is_valid(self, email: Email) -> bool: ...

from abc import ABC, abstractmethod

from pydentity.authentication.domain.device.value_objects import (
    HashedDeviceFingerprint,
    RawDeviceFingerprint,
)


class DeviceFingerprintHasher(ABC):
    @abstractmethod
    def hash(self, fingerprint: RawDeviceFingerprint) -> HashedDeviceFingerprint: ...


class DeviceFingerprintVerifier(ABC):
    @abstractmethod
    def verify(
        self, fingerprint: RawDeviceFingerprint, hashed: HashedDeviceFingerprint
    ) -> bool: ...

from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.exceptions import EmptyValueError
from pydentity.domain.models.value_objects import DeviceFingerprint

if TYPE_CHECKING:
    from pydentity.domain.ports.fingerprint_hasher import FingerprintHasherPort


class DeviceFingerprintFactory:
    def __init__(self, *, fingerprint_hasher: FingerprintHasherPort) -> None:
        self._fingerprint_hasher = fingerprint_hasher

    def create(self, raw: str) -> DeviceFingerprint:
        stripped = raw.strip()
        if not stripped:
            raise EmptyValueError(field_name="DeviceFingerprint")
        return DeviceFingerprint(value=self._fingerprint_hasher.hash(stripped))

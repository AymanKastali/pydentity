from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.guards import verify_params
from pydentity.domain.models.value_objects import DeviceFingerprint

if TYPE_CHECKING:
    from pydentity.domain.ports.fingerprint_hasher import FingerprintHasherPort


class DeviceFingerprintFactory:
    def __init__(self, *, fingerprint_hasher: FingerprintHasherPort) -> None:
        self._fingerprint_hasher = fingerprint_hasher

    def create(self, raw: str) -> DeviceFingerprint:
        verify_params(fingerprint=(raw, str))
        return DeviceFingerprint(value=self._fingerprint_hasher.hash(raw.strip()))

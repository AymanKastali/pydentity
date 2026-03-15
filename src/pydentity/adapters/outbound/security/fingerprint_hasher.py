from __future__ import annotations

import hashlib

from pydentity.domain.ports.fingerprint_hasher import FingerprintHasherPort


class Sha256FingerprintHasher(FingerprintHasherPort):
    def hash(self, raw: str) -> str:
        return hashlib.sha256(raw.encode()).hexdigest()

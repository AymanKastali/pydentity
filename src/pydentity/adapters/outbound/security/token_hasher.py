from __future__ import annotations

import hashlib
import hmac

from pydentity.domain.ports.token_hasher import TokenHasherPort


class Sha256TokenHasher(TokenHasherPort):
    def hash(self, raw_token: str) -> bytes:
        return hashlib.sha256(raw_token.encode()).digest()

    def verify(self, candidate: str, stored: bytes) -> bool:
        candidate_hash = hashlib.sha256(candidate.encode()).digest()
        return hmac.compare_digest(candidate_hash, stored)

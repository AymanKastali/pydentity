import hashlib

from pydentity.application.services.token_hasher import TokenHasher


class SHA256TokenHasher(TokenHasher):
    def hash(self, raw_token: str) -> str:
        return hashlib.sha256(raw_token.encode()).hexdigest()

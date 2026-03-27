import secrets

from pydentity.application.services.token_generator import TokenGenerator


class SecureTokenGenerator(TokenGenerator):
    def generate(self) -> str:
        return secrets.token_urlsafe(32)

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
)

from pydentity.application.services.access_token_service import (
    AccessTokenService,
    TokenClaims,
)

if TYPE_CHECKING:
    from pydentity.application.services.clock import Clock


class JWTAccessTokenService(AccessTokenService):
    def __init__(
        self,
        private_key_path: str,
        clock: Clock,
        expire_minutes: int = 15,
    ) -> None:
        self._clock = clock
        self._expire_minutes = expire_minutes
        key_path = Path(private_key_path)
        if key_path.is_dir():
            pem_files = sorted(key_path.glob("*.pem"))
            if not pem_files:
                raise FileNotFoundError(f"No .pem files found in {key_path}")
            key_path = pem_files[-1]
        self._private_key = key_path.read_text()
        private_key_obj = load_pem_private_key(
            self._private_key.encode(), password=None
        )
        self._public_key = (
            private_key_obj.public_key()
            .public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )

    def create_access_token(self, account_id: str, email: str) -> str:
        now = self._clock.now()
        payload = {
            "sub": account_id,
            "email": email,
            "iat": now,
            "exp": now + timedelta(minutes=self._expire_minutes),
            "jti": str(uuid4()),
        }
        return jwt.encode(payload, self._private_key, algorithm="RS256")

    def verify_access_token(self, token: str) -> TokenClaims:
        payload = jwt.decode(token, self._public_key, algorithms=["RS256"])
        return TokenClaims(
            sub=payload["sub"],
            email=payload["email"],
            exp=datetime.fromtimestamp(payload["exp"], tz=UTC),
            jti=payload["jti"],
        )

"""HS256 JWT verifier backed by PyJWT."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import jwt

from pydentity.application.exceptions.app import InvalidTokenError
from pydentity.application.models.access_token_claims import AccessTokenClaims
from pydentity.application.ports.token_verifier import TokenVerifierPort
from pydentity.domain.models.value_objects import Permission, SessionId, UserId

if TYPE_CHECKING:
    from pydantic import SecretStr


class HmacSha256JwtVerifier(TokenVerifierPort):
    def __init__(self, *, secret: SecretStr) -> None:
        self._secret = secret.get_secret_value()

    async def verify(self, token: str) -> AccessTokenClaims:
        try:
            payload: dict[str, object] = jwt.decode(
                token,
                self._secret,
                algorithms=["HS256"],
                options={"require": ["iss", "sub", "sid", "iat", "exp", "jti"]},
            )
        except jwt.PyJWTError:
            raise InvalidTokenError from None

        raw_permissions = payload.get("permissions", [])
        if not isinstance(raw_permissions, list):
            raise InvalidTokenError

        iat = payload["iat"]
        exp = payload["exp"]
        if not isinstance(iat, int | float) or not isinstance(exp, int | float):
            raise InvalidTokenError

        return AccessTokenClaims(
            issuer=str(payload["iss"]),
            subject=UserId(value=str(payload["sub"])),
            session_id=SessionId(value=str(payload["sid"])),
            issued_at=datetime.fromtimestamp(int(iat), tz=UTC),
            expires_at=datetime.fromtimestamp(int(exp), tz=UTC),
            token_id=str(payload["jti"]),
            permissions=frozenset(
                Permission(resource=p.split(":")[0], action=p.split(":")[1])
                for p in raw_permissions
            ),
        )

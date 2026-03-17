"""RS256 JWT verifier backed by PyJWT."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import jwt

from pydentity.application.exceptions.app import InvalidTokenError
from pydentity.application.models.access_token_claims import AccessTokenClaims
from pydentity.application.ports.token_verifier import TokenVerifierPort
from pydentity.domain.models.value_objects import (
    Permission,
    RoleName,
    SessionId,
    UserId,
)

if TYPE_CHECKING:
    from pydentity.application.ports.jwk_key_store import JWKKeyStorePort


class RS256JWTVerifier(TokenVerifierPort):
    def __init__(
        self, *, key_store: JWKKeyStorePort, expected_audiences: frozenset[str]
    ) -> None:
        self._key_store = key_store
        self._expected_audiences = expected_audiences

    async def verify(self, token: str) -> AccessTokenClaims:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise InvalidTokenError from None

        kid = header.get("kid")
        if not isinstance(kid, str):
            raise InvalidTokenError

        public_key = self._key_store.get_public_key(kid)
        if public_key is None:
            raise InvalidTokenError

        try:
            payload: dict[str, object] = jwt.decode(
                token,
                public_key.public_key,
                algorithms=["RS256"],
                audience=sorted(self._expected_audiences),
                options={"require": ["iss", "sub", "sid", "iat", "exp", "jti", "aud"]},
            )
        except jwt.PyJWTError:
            raise InvalidTokenError from None

        raw_permissions = payload.get("permissions", [])
        if not isinstance(raw_permissions, list):
            raise InvalidTokenError

        raw_roles = payload.get("roles", [])
        if not isinstance(raw_roles, list):
            raise InvalidTokenError

        iat = payload["iat"]
        exp = payload["exp"]
        if not isinstance(iat, int | float) or not isinstance(exp, int | float):
            raise InvalidTokenError

        raw_audiences = payload.get("aud", [])
        if isinstance(raw_audiences, str):
            raw_audiences = [raw_audiences]
        if not isinstance(raw_audiences, list):
            raise InvalidTokenError

        return AccessTokenClaims(
            issuer=str(payload["iss"]),
            subject=UserId(value=str(payload["sub"])),
            session_id=SessionId(value=str(payload["sid"])),
            issued_at=datetime.fromtimestamp(int(iat), tz=UTC),
            expires_at=datetime.fromtimestamp(int(exp), tz=UTC),
            token_id=str(payload["jti"]),
            permissions=frozenset(Permission(value=p) for p in raw_permissions),
            roles=frozenset(RoleName(value=r) for r in raw_roles),
            audiences=frozenset(str(a) for a in raw_audiences),
        )

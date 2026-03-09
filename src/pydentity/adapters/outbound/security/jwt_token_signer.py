"""HS256 JWT signer backed by PyJWT."""

from __future__ import annotations

from typing import TYPE_CHECKING

import jwt

from pydentity.application.ports.token_signer import TokenSignerPort

if TYPE_CHECKING:
    from pydantic import SecretStr

    from pydentity.application.models.access_token_claims import AccessTokenClaims


class HmacSha256JwtSigner(TokenSignerPort):
    def __init__(self, *, secret: SecretStr) -> None:
        self._secret = secret.get_secret_value()

    async def sign(self, claims: AccessTokenClaims) -> str:
        payload: dict[str, object] = {
            "iss": claims.issuer,
            "sub": claims.subject.value,
            "sid": claims.session_id.value,
            "iat": int(claims.issued_at.timestamp()),
            "exp": int(claims.expires_at.timestamp()),
            "jti": claims.token_id,
            "permissions": sorted(
                f"{p.resource}:{p.action}" for p in claims.permissions
            ),
        }
        return jwt.encode(payload, self._secret, algorithm="HS256")

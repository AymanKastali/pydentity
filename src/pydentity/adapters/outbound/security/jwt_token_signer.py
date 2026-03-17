"""RS256 JWT signer backed by PyJWT."""

from __future__ import annotations

from typing import TYPE_CHECKING

import jwt

from pydentity.application.ports.token_signer import TokenSignerPort

if TYPE_CHECKING:
    from pydentity.application.models.access_token_claims import AccessTokenClaims
    from pydentity.application.ports.jwk_key_store import JWKKeyStorePort


class RS256JWTSigner(TokenSignerPort):
    def __init__(self, *, key_store: JWKKeyStorePort) -> None:
        self._key_store = key_store

    async def sign(self, claims: AccessTokenClaims) -> str:
        key_pair = self._key_store.get_signing_key()
        payload: dict[str, object] = {
            "iss": claims.issuer,
            "sub": claims.subject.value,
            "sid": claims.session_id.value,
            "iat": int(claims.issued_at.timestamp()),
            "exp": int(claims.expires_at.timestamp()),
            "jti": claims.token_id,
            "permissions": sorted(p.value for p in claims.permissions),
            "roles": sorted(r.value for r in claims.roles),
            "aud": sorted(claims.audiences),
        }
        return jwt.encode(
            payload,
            key_pair.private_key,
            algorithm="RS256",
            headers={"kid": key_pair.kid},
        )

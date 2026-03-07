"""Minimal HS256 JWT signer using only stdlib (hmac + hashlib)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import TYPE_CHECKING

from pydentity.application.ports.token_signer import TokenSignerPort

if TYPE_CHECKING:
    from pydantic import SecretStr

    from pydentity.application.models.access_token_claims import AccessTokenClaims


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


_HEADER = _b64url(b'{"alg":"HS256","typ":"JWT"}')


class HmacSha256JwtSigner(TokenSignerPort):
    def __init__(self, *, secret: SecretStr) -> None:
        self._secret = secret.get_secret_value().encode()

    async def sign(self, claims: AccessTokenClaims) -> str:
        payload = _b64url(
            json.dumps(
                {
                    "iss": claims.issuer,
                    "sub": claims.subject.value,
                    "sid": claims.session_id.value,
                    "iat": int(claims.issued_at.timestamp()),
                    "exp": int(claims.expires_at.timestamp()),
                    "jti": claims.token_id,
                    "permissions": sorted(
                        f"{p.resource}:{p.action}" for p in claims.permissions
                    ),
                },
                separators=(",", ":"),
            ).encode()
        )
        message = f"{_HEADER}.{payload}"
        sig = hmac.new(
            key=self._secret,
            msg=message.encode(),
            digestmod=hashlib.sha256,
        ).digest()
        return f"{message}.{_b64url(sig)}"

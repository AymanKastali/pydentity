from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.domain.models.value_objects import AccessTokenClaims, SessionId, UserId

if TYPE_CHECKING:
    from datetime import datetime

    from pydentity.domain.models.policies import TokenLifetimePolicy
    from pydentity.domain.models.value_objects import Permission


def assemble_access_token_claims(
    issuer: str,
    user_id: UserId,
    session_id: SessionId,
    now: datetime,
    policy: TokenLifetimePolicy,
    jti: str,
    permissions: frozenset[Permission],
) -> AccessTokenClaims:
    return AccessTokenClaims(
        issuer=issuer,
        subject=user_id,
        session_id=session_id,
        issued_at=now,
        expires_at=now + policy.access_token_ttl,
        jti=jti,
        permissions=permissions,
    )

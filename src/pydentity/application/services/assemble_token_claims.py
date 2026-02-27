from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.dtos.auth import AccessTokenClaims
from pydentity.domain.services.permission_collector import collect_permissions

if TYPE_CHECKING:
    from collections.abc import Iterable
    from datetime import datetime

    from pydentity.domain.models.role import Role
    from pydentity.domain.models.value_objects import (
        SessionId,
        TokenLifetimePolicy,
        UserId,
    )


def assemble_token_claims(
    *,
    issuer: str,
    subject: UserId,
    session_id: SessionId,
    issued_at: datetime,
    token_lifetime_policy: TokenLifetimePolicy,
    token_id: str,
    roles: Iterable[Role],
) -> AccessTokenClaims:
    permissions = collect_permissions(roles)
    return AccessTokenClaims(
        issuer=issuer,
        subject=subject,
        session_id=session_id,
        issued_at=issued_at,
        expires_at=issued_at + token_lifetime_policy.access_token_ttl,
        token_id=token_id,
        permissions=permissions,
    )

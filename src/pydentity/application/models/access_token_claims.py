from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pydentity.domain.models.role import Role

if TYPE_CHECKING:
    from collections.abc import Iterable
    from datetime import datetime

    from pydentity.domain.models.value_objects import (
        Permission,
        RoleName,
        SessionId,
        TokenLifetimePolicy,
        UserId,
    )


@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    issuer: str
    subject: UserId
    session_id: SessionId
    issued_at: datetime
    expires_at: datetime
    token_id: str
    permissions: frozenset[Permission]
    roles: frozenset[RoleName]

    def __post_init__(self) -> None:
        if not isinstance(self.issuer, str) or not self.issuer.strip():
            raise ValueError("AccessTokenClaims.issuer must be a non-empty string")
        if not isinstance(self.token_id, str) or not self.token_id.strip():
            raise ValueError("AccessTokenClaims.token_id must be a non-empty string")
        if self.expires_at <= self.issued_at:
            raise ValueError("AccessTokenClaims.expires_at must be after issued_at")

    @classmethod
    def create(
        cls,
        *,
        issuer: str,
        subject: UserId,
        session_id: SessionId,
        issued_at: datetime,
        token_lifetime_policy: TokenLifetimePolicy,
        token_id: str,
        roles: Iterable[Role],
    ) -> AccessTokenClaims:
        materialized_roles = tuple(roles)
        permissions = Role.collect_permissions(materialized_roles)
        role_names = Role.collect_role_names(materialized_roles)
        return AccessTokenClaims(
            issuer=issuer,
            subject=subject,
            session_id=session_id,
            issued_at=issued_at,
            expires_at=issued_at + token_lifetime_policy.access_token_ttl,
            token_id=token_id,
            permissions=permissions,
            roles=role_names,
        )

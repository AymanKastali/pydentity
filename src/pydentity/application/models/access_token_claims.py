from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pydentity.domain.exceptions import InvalidValueError
from pydentity.domain.guards import verify_params
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
        verify_params(issuer=(self.issuer, str), token_id=(self.token_id, str))
        if self.expires_at <= self.issued_at:
            raise InvalidValueError(
                field_name=f"{self.__class__.__name__}.expires_at",
                reason="must be after issued_at",
            )

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

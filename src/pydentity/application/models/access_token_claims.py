from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pydentity.domain.exceptions import EmptyValueError, InvalidValueError
from pydentity.domain.services.permission_collector import collect_permissions

if TYPE_CHECKING:
    from collections.abc import Iterable
    from datetime import datetime

    from pydentity.domain.models.role import Role
    from pydentity.domain.models.value_objects import (
        Permission,
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

    def __post_init__(self) -> None:
        if not self.issuer:
            raise EmptyValueError(field_name=f"{self.__class__.__name__}.issuer")
        if not self.token_id:
            raise EmptyValueError(field_name=f"{self.__class__.__name__}.token_id")
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

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from pydentity.adapters.container import Container, get_container
from pydentity.application.exceptions.app import InsufficientPermissionsError
from pydentity.domain.models.value_objects import Permission

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from pydentity.application.models.access_token_claims import AccessTokenClaims

_bearer = HTTPBearer()


async def get_current_claims(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(_bearer)],
    container: Annotated[Container, Depends(get_container)],
) -> AccessTokenClaims:
    return await container.token_verifier.verify(credentials.credentials)


require_authenticated = get_current_claims


def require_permissions(
    *permission_strings: str,
) -> Callable[..., Coroutine[Any, Any, AccessTokenClaims]]:
    required = frozenset(
        Permission(resource=p.split(":")[0], action=p.split(":")[1])
        for p in permission_strings
    )

    async def _check(
        claims: Annotated[AccessTokenClaims, Depends(get_current_claims)],
    ) -> AccessTokenClaims:
        if not required.issubset(claims.permissions):
            raise InsufficientPermissionsError
        return claims

    return _check

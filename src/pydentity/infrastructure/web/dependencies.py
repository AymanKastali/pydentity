from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from pydentity.infrastructure.container import Container

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

bearer_scheme = HTTPBearer()

_session_factory: async_sessionmaker[AsyncSession] | None = None
_container: Container | None = None


def set_session_factory(
    factory: async_sessionmaker[AsyncSession],
) -> None:
    global _session_factory  # noqa: PLW0603
    _session_factory = factory


def set_container(container: Container) -> None:
    global _container  # noqa: PLW0603
    _container = container


async def get_session() -> AsyncGenerator[AsyncSession]:
    if _session_factory is None:
        raise RuntimeError("Session factory not initialized")
    async with _session_factory() as session:
        yield session


def get_container(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Container:
    if _container is None:
        raise RuntimeError("Container not initialized")

    class RequestContainer(Container):
        def _get_session(self) -> AsyncSession:
            return session

    request_container = object.__new__(RequestContainer)
    request_container.__dict__.update(_container.__dict__)
    return request_container


def get_current_account_id(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
    container: Annotated[Container, Depends(get_container)],
) -> str:
    try:
        claims = container.access_token_service.verify_access_token(
            credentials.credentials
        )
        return claims.sub
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        ) from exc

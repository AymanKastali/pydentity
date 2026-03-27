from typing import TYPE_CHECKING

from pydentity.domain.base import DomainError

if TYPE_CHECKING:
    from uuid import UUID


class RefreshTokenNotFoundError(DomainError):
    def __init__(self) -> None:
        super().__init__("Refresh token not found")


class RefreshTokenExpiredError(DomainError):
    def __init__(self, token_id: UUID) -> None:
        super().__init__(f"Refresh token expired: {token_id}")
        self.token_id = token_id


class RefreshTokenRevokedError(DomainError):
    def __init__(self, token_id: UUID) -> None:
        super().__init__(f"Refresh token revoked: {token_id}")
        self.token_id = token_id

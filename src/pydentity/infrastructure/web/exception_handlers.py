from typing import TYPE_CHECKING

from fastapi.responses import JSONResponse

from pydentity.domain.account.errors import (
    AccountAlreadyExistsError,
    AccountNotActiveError,
    AccountNotFoundError,
    EmailAlreadyVerifiedError,
    InvalidCredentialsError,
    InvalidVerificationTokenError,
)
from pydentity.domain.base import DomainError
from pydentity.domain.refresh_token.errors import (
    RefreshTokenExpiredError,
    RefreshTokenNotFoundError,
    RefreshTokenRevokedError,
)

if TYPE_CHECKING:
    from fastapi import FastAPI, Request

ERROR_STATUS_MAP: dict[type[DomainError], int] = {
    AccountNotFoundError: 404,
    AccountAlreadyExistsError: 409,
    InvalidCredentialsError: 401,
    AccountNotActiveError: 403,
    EmailAlreadyVerifiedError: 409,
    InvalidVerificationTokenError: 400,
    RefreshTokenNotFoundError: 401,
    RefreshTokenExpiredError: 401,
    RefreshTokenRevokedError: 401,
}


def register_exception_handlers(application: FastAPI) -> None:
    @application.exception_handler(DomainError)
    async def domain_error_handler(_request: Request, exc: DomainError) -> JSONResponse:
        status_code = ERROR_STATUS_MAP.get(type(exc), 400)
        return JSONResponse(
            status_code=status_code,
            content={"detail": str(exc)},
        )

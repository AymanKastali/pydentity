from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import status
from fastapi.responses import JSONResponse

from pydentity.application.exceptions.app import (
    ApplicationError,
    EmailAlreadyRegisteredError,
    InvalidTokenError,
    RoleNotFoundError,
    UserNotFoundError,
)
from pydentity.domain.exceptions.domain import (
    AccountAlreadyActiveError,
    AccountAlreadyDeactivatedError,
    AccountDeactivatedError,
    AccountLockedError,
    AccountNotActiveError,
    DeviceAlreadyRegisteredError,
    DomainError,
    EmailAlreadyTakenError,
    EmailAlreadyVerifiedError,
    EmailUnchangedError,
    InvalidCredentialsError,
    PasswordPolicyViolationError,
    PasswordReuseError,
    PermissionAlreadyGrantedError,
    PermissionNotGrantedError,
    RoleAlreadyAssignedError,
    RoleAlreadyExistsError,
    RoleNotAssignedError,
    VerificationTokenExpiredError,
    VerificationTokenInvalidError,
    VerificationTokenNotIssuedError,
)

if TYPE_CHECKING:
    from fastapi import FastAPI, Request

_DOMAIN_STATUS_MAP: dict[type[DomainError], int] = {
    InvalidCredentialsError: status.HTTP_401_UNAUTHORIZED,
    AccountLockedError: status.HTTP_403_FORBIDDEN,
    AccountDeactivatedError: status.HTTP_403_FORBIDDEN,
    AccountNotActiveError: status.HTTP_403_FORBIDDEN,
    AccountAlreadyActiveError: status.HTTP_409_CONFLICT,
    AccountAlreadyDeactivatedError: status.HTTP_409_CONFLICT,
    EmailAlreadyTakenError: status.HTTP_409_CONFLICT,
    EmailAlreadyVerifiedError: status.HTTP_409_CONFLICT,
    RoleAlreadyAssignedError: status.HTTP_409_CONFLICT,
    RoleAlreadyExistsError: status.HTTP_409_CONFLICT,
    DeviceAlreadyRegisteredError: status.HTTP_409_CONFLICT,
    PermissionAlreadyGrantedError: status.HTTP_409_CONFLICT,
    EmailUnchangedError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    PasswordPolicyViolationError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    PasswordReuseError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    VerificationTokenExpiredError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    VerificationTokenInvalidError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    VerificationTokenNotIssuedError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    RoleNotAssignedError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    PermissionNotGrantedError: status.HTTP_422_UNPROCESSABLE_CONTENT,
}

_APP_STATUS_MAP: dict[type[ApplicationError], int] = {
    UserNotFoundError: status.HTTP_404_NOT_FOUND,
    RoleNotFoundError: status.HTTP_404_NOT_FOUND,
    EmailAlreadyRegisteredError: status.HTTP_409_CONFLICT,
    InvalidTokenError: status.HTTP_401_UNAUTHORIZED,
}


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(DomainError)
    async def domain_error_handler(request: Request, exc: DomainError) -> JSONResponse:
        status_code = _DOMAIN_STATUS_MAP.get(type(exc), status.HTTP_400_BAD_REQUEST)
        return JSONResponse(
            status_code=status_code,
            content={"detail": str(exc)},
        )

    @app.exception_handler(ApplicationError)
    async def application_error_handler(
        request: Request, exc: ApplicationError
    ) -> JSONResponse:
        status_code = _APP_STATUS_MAP.get(type(exc), status.HTTP_400_BAD_REQUEST)
        return JSONResponse(
            status_code=status_code,
            content={"detail": str(exc)},
        )

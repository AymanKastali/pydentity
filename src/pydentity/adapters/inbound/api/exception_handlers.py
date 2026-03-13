from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from fastapi import status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError

from pydentity.adapters.inbound.api.schemas.response import ErrorDetail, ErrorResponse
from pydentity.application.exceptions.app import (
    ApplicationError,
    DeviceNotFoundError,
    EmailAlreadyRegisteredError,
    InsufficientPermissionsError,
    InvalidTokenError,
    PersistenceConsistencyError,
    RoleNotFoundError,
    SessionNotFoundError,
    UserNotFoundError,
)
from pydentity.domain.exceptions.domain import (
    AccountAlreadyActiveError,
    AccountAlreadyDeactivatedError,
    AccountDeactivatedError,
    AccountLockedError,
    AccountNotActiveError,
    DeviceAlreadyRegisteredError,
    DeviceAlreadyRevokedError,
    DeviceAlreadyTrustedError,
    DeviceAlreadyUntrustedError,
    DeviceOwnershipError,
    DeviceRevokedError,
    DomainError,
    EmailAlreadyTakenError,
    EmailAlreadyVerifiedError,
    EmailUnchangedError,
    EmptyValueError,
    InvalidCredentialsError,
    InvalidEmailAddressError,
    InvalidPolicyValueError,
    InvalidValueError,
    PasswordPolicyViolationError,
    PasswordReuseError,
    PermissionAlreadyGrantedError,
    PermissionNotGrantedError,
    RefreshTokenReuseDetectedError,
    ResetTokenExpiredError,
    ResetTokenInvalidError,
    ResetTokenNotIssuedError,
    RoleAlreadyAssignedError,
    RoleAlreadyExistsError,
    RoleNotAssignedError,
    SessionAlreadyRevokedError,
    SessionExpiredError,
    SessionRevokedError,
    VerificationTokenExpiredError,
    VerificationTokenInvalidError,
    VerificationTokenNotIssuedError,
)

if TYPE_CHECKING:
    from fastapi import FastAPI, Request

_log = logging.getLogger(__name__)

_DOMAIN_STATUS_MAP: dict[type[DomainError], int] = {
    InvalidCredentialsError: status.HTTP_401_UNAUTHORIZED,
    SessionRevokedError: status.HTTP_401_UNAUTHORIZED,
    SessionExpiredError: status.HTTP_401_UNAUTHORIZED,
    RefreshTokenReuseDetectedError: status.HTTP_401_UNAUTHORIZED,
    AccountLockedError: status.HTTP_403_FORBIDDEN,
    AccountDeactivatedError: status.HTTP_403_FORBIDDEN,
    AccountNotActiveError: status.HTTP_403_FORBIDDEN,
    DeviceRevokedError: status.HTTP_403_FORBIDDEN,
    DeviceOwnershipError: status.HTTP_403_FORBIDDEN,
    AccountAlreadyActiveError: status.HTTP_409_CONFLICT,
    AccountAlreadyDeactivatedError: status.HTTP_409_CONFLICT,
    EmailAlreadyTakenError: status.HTTP_409_CONFLICT,
    EmailAlreadyVerifiedError: status.HTTP_409_CONFLICT,
    RoleAlreadyAssignedError: status.HTTP_409_CONFLICT,
    RoleAlreadyExistsError: status.HTTP_409_CONFLICT,
    DeviceAlreadyRegisteredError: status.HTTP_409_CONFLICT,
    DeviceAlreadyRevokedError: status.HTTP_409_CONFLICT,
    DeviceAlreadyTrustedError: status.HTTP_409_CONFLICT,
    DeviceAlreadyUntrustedError: status.HTTP_409_CONFLICT,
    SessionAlreadyRevokedError: status.HTTP_409_CONFLICT,
    PermissionAlreadyGrantedError: status.HTTP_409_CONFLICT,
    EmailUnchangedError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    PasswordPolicyViolationError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    PasswordReuseError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    VerificationTokenExpiredError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    VerificationTokenInvalidError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    VerificationTokenNotIssuedError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    ResetTokenExpiredError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    ResetTokenInvalidError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    ResetTokenNotIssuedError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    RoleNotAssignedError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    PermissionNotGrantedError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    EmptyValueError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    InvalidValueError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    InvalidEmailAddressError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    InvalidPolicyValueError: status.HTTP_422_UNPROCESSABLE_CONTENT,
}

_DOMAIN_CODE_MAP: dict[type[DomainError], str] = {
    InvalidCredentialsError: "INVALID_CREDENTIALS",
    SessionRevokedError: "SESSION_REVOKED",
    SessionExpiredError: "SESSION_EXPIRED",
    RefreshTokenReuseDetectedError: "REFRESH_TOKEN_REUSE_DETECTED",
    AccountLockedError: "ACCOUNT_LOCKED",
    AccountDeactivatedError: "ACCOUNT_DEACTIVATED",
    AccountNotActiveError: "ACCOUNT_NOT_ACTIVE",
    DeviceRevokedError: "DEVICE_REVOKED",
    DeviceOwnershipError: "DEVICE_OWNERSHIP_VIOLATION",
    AccountAlreadyActiveError: "ACCOUNT_ALREADY_ACTIVE",
    AccountAlreadyDeactivatedError: "ACCOUNT_ALREADY_DEACTIVATED",
    EmailAlreadyTakenError: "EMAIL_ALREADY_TAKEN",
    EmailAlreadyVerifiedError: "EMAIL_ALREADY_VERIFIED",
    RoleAlreadyAssignedError: "ROLE_ALREADY_ASSIGNED",
    RoleAlreadyExistsError: "ROLE_ALREADY_EXISTS",
    DeviceAlreadyRegisteredError: "DEVICE_ALREADY_REGISTERED",
    DeviceAlreadyRevokedError: "DEVICE_ALREADY_REVOKED",
    DeviceAlreadyTrustedError: "DEVICE_ALREADY_TRUSTED",
    DeviceAlreadyUntrustedError: "DEVICE_ALREADY_UNTRUSTED",
    SessionAlreadyRevokedError: "SESSION_ALREADY_REVOKED",
    PermissionAlreadyGrantedError: "PERMISSION_ALREADY_GRANTED",
    EmailUnchangedError: "EMAIL_UNCHANGED",
    PasswordPolicyViolationError: "PASSWORD_POLICY_VIOLATION",
    PasswordReuseError: "PASSWORD_REUSE",
    VerificationTokenExpiredError: "VERIFICATION_TOKEN_EXPIRED",
    VerificationTokenInvalidError: "VERIFICATION_TOKEN_INVALID",
    VerificationTokenNotIssuedError: "VERIFICATION_TOKEN_NOT_ISSUED",
    ResetTokenExpiredError: "RESET_TOKEN_EXPIRED",
    ResetTokenInvalidError: "RESET_TOKEN_INVALID",
    ResetTokenNotIssuedError: "RESET_TOKEN_NOT_ISSUED",
    RoleNotAssignedError: "ROLE_NOT_ASSIGNED",
    PermissionNotGrantedError: "PERMISSION_NOT_GRANTED",
    EmptyValueError: "EMPTY_VALUE",
    InvalidValueError: "INVALID_VALUE",
    InvalidEmailAddressError: "INVALID_EMAIL_ADDRESS",
    InvalidPolicyValueError: "INVALID_POLICY_VALUE",
}

_APP_STATUS_MAP: dict[type[ApplicationError], int] = {
    UserNotFoundError: status.HTTP_404_NOT_FOUND,
    RoleNotFoundError: status.HTTP_404_NOT_FOUND,
    SessionNotFoundError: status.HTTP_404_NOT_FOUND,
    DeviceNotFoundError: status.HTTP_404_NOT_FOUND,
    EmailAlreadyRegisteredError: status.HTTP_409_CONFLICT,
    InvalidTokenError: status.HTTP_401_UNAUTHORIZED,
    InsufficientPermissionsError: status.HTTP_403_FORBIDDEN,
    PersistenceConsistencyError: status.HTTP_500_INTERNAL_SERVER_ERROR,
}

_APP_CODE_MAP: dict[type[ApplicationError], str] = {
    UserNotFoundError: "USER_NOT_FOUND",
    RoleNotFoundError: "ROLE_NOT_FOUND",
    SessionNotFoundError: "SESSION_NOT_FOUND",
    DeviceNotFoundError: "DEVICE_NOT_FOUND",
    EmailAlreadyRegisteredError: "EMAIL_ALREADY_REGISTERED",
    InvalidTokenError: "INVALID_TOKEN",
    InsufficientPermissionsError: "INSUFFICIENT_PERMISSIONS",
    PersistenceConsistencyError: "PERSISTENCE_CONSISTENCY_ERROR",
}


def _error_response(code: str, message: str) -> dict[str, object]:
    return ErrorResponse(error=ErrorDetail(code=code, message=message)).model_dump()


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(DomainError)
    async def domain_error_handler(request: Request, exc: DomainError) -> JSONResponse:
        status_code = _DOMAIN_STATUS_MAP.get(type(exc), status.HTTP_400_BAD_REQUEST)
        return JSONResponse(
            status_code=status_code,
            content=_error_response(
                code=_DOMAIN_CODE_MAP.get(type(exc), "DOMAIN_ERROR"),
                message=str(exc),
            ),
        )

    @app.exception_handler(ApplicationError)
    async def application_error_handler(
        request: Request, exc: ApplicationError
    ) -> JSONResponse:
        status_code = _APP_STATUS_MAP.get(type(exc), status.HTTP_400_BAD_REQUEST)
        return JSONResponse(
            status_code=status_code,
            content=_error_response(
                code=_APP_CODE_MAP.get(type(exc), "APPLICATION_ERROR"),
                message=str(exc),
            ),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        message = "; ".join(
            f"{e['loc'][-1]}: {e['msg']}" if e.get("loc") else e["msg"]
            for e in exc.errors()
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=_error_response(code="VALIDATION_ERROR", message=message),
        )

    @app.exception_handler(IntegrityError)
    async def integrity_error_handler(
        request: Request, exc: IntegrityError
    ) -> JSONResponse:
        _log.warning("integrity error: %s", exc.orig)
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content=_error_response(
                code="CONFLICT",
                message="The request conflicts with existing data.",
            ),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        _log.exception("unhandled exception: %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=_error_response(
                code="INTERNAL_ERROR",
                message="An unexpected error occurred.",
            ),
        )

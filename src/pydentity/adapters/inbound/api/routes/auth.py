from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends

from pydentity.adapters.container import (
    get_authenticate_user,
    get_logout_user,
    get_refresh_access_token,
    get_register_user,
)
from pydentity.adapters.inbound.api.schemas.auth import (
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    RefreshRequest,
    RefreshResponse,
    RegisterRequest,
    RegisterResponse,
)
from pydentity.application.dtos.auth import (
    AuthenticateUserInput,
    LogoutUserInput,
    RefreshAccessTokenInput,
    RegisterUserInput,
)

if TYPE_CHECKING:
    from pydentity.application.use_cases.auth.authenticate_user import AuthenticateUser
    from pydentity.application.use_cases.auth.logout_user import LogoutUser
    from pydentity.application.use_cases.auth.refresh_access_token import (
        RefreshAccessToken,
    )
    from pydentity.application.use_cases.auth.register_user import RegisterUser

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", status_code=200)
async def register(
    body: RegisterRequest,
    use_case: RegisterUser = Depends(get_register_user),
) -> RegisterResponse:
    result = await use_case.execute(
        RegisterUserInput(email=body.email, password=body.password)
    )
    return RegisterResponse(email=result.email)


@router.post("/login", status_code=200)
async def login(
    body: LoginRequest,
    use_case: AuthenticateUser = Depends(get_authenticate_user),
) -> LoginResponse:
    result = await use_case.execute(
        AuthenticateUserInput(
            email=body.email,
            password=body.password,
            device_id=body.device_id,
            device_name=body.device_name,
            raw_fingerprint=body.raw_fingerprint,
            platform=body.platform,
        )
    )
    return LoginResponse(
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        user_id=result.user_id,
        session_id=result.session_id,
        device_id=result.device_id,
    )


@router.post("/refresh", status_code=200)
async def refresh(
    body: RefreshRequest,
    use_case: RefreshAccessToken = Depends(get_refresh_access_token),
) -> RefreshResponse:
    result = await use_case.execute(
        RefreshAccessTokenInput(
            refresh_token=body.refresh_token,
            session_id=body.session_id,
        )
    )
    return RefreshResponse(
        access_token=result.access_token,
        refresh_token=result.refresh_token,
    )


@router.post("/logout", status_code=204)
async def logout(
    body: LogoutRequest,
    use_case: LogoutUser = Depends(get_logout_user),
) -> None:
    await use_case.execute(LogoutUserInput(session_id=body.session_id))

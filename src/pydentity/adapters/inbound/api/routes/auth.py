from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated

from fastapi import APIRouter, Depends, Header

from pydentity.adapters.container import (
    get_authenticate_user,
    get_logout_user,
    get_refresh_access_token,
    get_register_user,
)
from pydentity.adapters.inbound.api.dependencies.auth import require_authenticated
from pydentity.adapters.inbound.api.schemas.auth import (
    LoginRequest,
    LoginResponse,
    RefreshRequest,
    RefreshResponse,
    RegisterRequest,
    RegisterResponse,
)
from pydentity.adapters.inbound.api.schemas.response import ApiResponse
from pydentity.adapters.inbound.api.user_agent_parser import parse_user_agent
from pydentity.application.dtos.auth import (
    AuthenticateUserInput,
    LogoutUserInput,
    RefreshAccessTokenInput,
    RegisterUserInput,
)
from pydentity.application.models.access_token_claims import AccessTokenClaims

if TYPE_CHECKING:
    from pydentity.application.use_cases.auth.authenticate_user import AuthenticateUser
    from pydentity.application.use_cases.auth.logout_user import LogoutUser
    from pydentity.application.use_cases.auth.refresh_access_token import (
        RefreshAccessToken,
    )
    from pydentity.application.use_cases.auth.register_user import RegisterUser

router = APIRouter(prefix="/auth", tags=["auth"])


@dataclass(frozen=True, slots=True)
class DeviceHeaders:
    device_name: str
    raw_fingerprint: str
    platform: str


def get_device_headers(
    raw_fingerprint: Annotated[
        str, Header(alias="X-Device-Fingerprint", min_length=1, max_length=255)
    ],
    user_agent: Annotated[str | None, Header(include_in_schema=False)] = None,
) -> DeviceHeaders:
    parsed = parse_user_agent(user_agent)
    return DeviceHeaders(
        device_name=parsed.device_name,
        raw_fingerprint=raw_fingerprint,
        platform=parsed.platform,
    )


@router.post("/register", status_code=201)
async def register(
    body: RegisterRequest,
    use_case: RegisterUser = Depends(get_register_user),
) -> ApiResponse[RegisterResponse]:
    result = await use_case.execute(
        RegisterUserInput(email=body.email, password=body.password)
    )
    return ApiResponse(data=RegisterResponse(email=result.email))


@router.post("/login", status_code=200)
async def login(
    body: LoginRequest,
    device: Annotated[DeviceHeaders, Depends(get_device_headers)],
    use_case: AuthenticateUser = Depends(get_authenticate_user),
) -> ApiResponse[LoginResponse]:
    result = await use_case.execute(
        AuthenticateUserInput(
            email=body.email,
            password=body.password,
            device_name=device.device_name,
            raw_fingerprint=device.raw_fingerprint,
            platform=device.platform,
        )
    )
    return ApiResponse(
        data=LoginResponse(
            access_token=result.access_token,
            refresh_token=result.refresh_token,
            user_id=result.user_id,
            session_id=result.session_id,
            device_id=result.device_id,
        )
    )


@router.post("/refresh", status_code=200)
async def refresh(
    body: RefreshRequest,
    use_case: RefreshAccessToken = Depends(get_refresh_access_token),
) -> ApiResponse[RefreshResponse]:
    result = await use_case.execute(
        RefreshAccessTokenInput(refresh_token=body.refresh_token)
    )
    return ApiResponse(
        data=RefreshResponse(
            access_token=result.access_token,
            refresh_token=result.refresh_token,
        )
    )


@router.post("/logout", status_code=204)
async def logout(
    claims: Annotated[AccessTokenClaims, Depends(require_authenticated)],
    use_case: LogoutUser = Depends(get_logout_user),
) -> None:
    await use_case.execute(LogoutUserInput(session_id=str(claims.session_id.value)))

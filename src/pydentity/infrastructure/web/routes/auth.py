from typing import Annotated

from fastapi import APIRouter, Depends, status

from pydentity.application.account.dtos import (
    GetCurrentAccountDTO,
    RegisterAccountDTO,
    VerifyEmailDTO,
)
from pydentity.application.auth.dtos import (
    AuthenticateDTO,
    LogoutDTO,
    RefreshDTO,
)
from pydentity.infrastructure.container import Container
from pydentity.infrastructure.web.dependencies import (
    get_container,
    get_current_account_id,
)
from pydentity.infrastructure.web.schemas import (
    AccountResponse,
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    RegisterResponse,
    TokenPairResponse,
    VerifyEmailRequest,
)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    body: RegisterRequest,
    container: Annotated[Container, Depends(get_container)],
) -> RegisterResponse:
    service = container.register_account_service()
    result = await service.execute(
        RegisterAccountDTO(email=body.email, password=body.password)
    )
    return RegisterResponse(
        id=result.id,
        email=result.email,
        status=result.status,
    )


@router.post("/verify-email", status_code=status.HTTP_200_OK)
async def verify_email(
    body: VerifyEmailRequest,
    container: Annotated[Container, Depends(get_container)],
) -> dict[str, str]:
    service = container.verify_email_service()
    await service.execute(VerifyEmailDTO(account_id=body.account_id, token=body.token))
    return {"detail": "Email verified"}


@router.post("/login", response_model=TokenPairResponse)
async def login(
    body: LoginRequest,
    container: Annotated[Container, Depends(get_container)],
) -> TokenPairResponse:
    service = container.authenticate_service()
    result = await service.execute(
        AuthenticateDTO(email=body.email, password=body.password)
    )
    return TokenPairResponse(
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        token_type=result.token_type,
        expires_in=result.expires_in,
    )


@router.post("/refresh", response_model=TokenPairResponse)
async def refresh(
    body: RefreshRequest,
    container: Annotated[Container, Depends(get_container)],
) -> TokenPairResponse:
    service = container.refresh_access_token_service()
    result = await service.execute(RefreshDTO(refresh_token=body.refresh_token))
    return TokenPairResponse(
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        token_type=result.token_type,
        expires_in=result.expires_in,
    )


@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(
    body: LogoutRequest,
    container: Annotated[Container, Depends(get_container)],
) -> dict[str, str]:
    service = container.logout_service()
    await service.execute(LogoutDTO(refresh_token=body.refresh_token))
    return {"detail": "Logged out"}


@router.get("/me", response_model=AccountResponse)
async def get_me(
    account_id: Annotated[str, Depends(get_current_account_id)],
    container: Annotated[Container, Depends(get_container)],
) -> AccountResponse:
    service = container.get_current_account_service()
    result = await service.execute(GetCurrentAccountDTO(account_id=account_id))
    return AccountResponse(
        id=result.id,
        email=result.email,
        status=result.status,
    )

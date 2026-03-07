from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends

from pydentity.adapters.container import (
    get_change_password,
    get_request_password_reset,
    get_reset_password,
)
from pydentity.adapters.inbound.api.schemas.password import (
    ChangePasswordRequest,
    RequestPasswordResetRequest,
    ResetPasswordRequest,
)
from pydentity.application.dtos.password import (
    ChangePasswordInput,
    RequestPasswordResetInput,
    ResetPasswordInput,
)

if TYPE_CHECKING:
    from pydentity.application.use_cases.password.change_password import ChangePassword
    from pydentity.application.use_cases.password.request_password_reset import (
        RequestPasswordReset,
    )
    from pydentity.application.use_cases.password.reset_password import ResetPassword

router = APIRouter(prefix="/password", tags=["password"])


@router.post("/reset-request", status_code=204)
async def request_password_reset(
    body: RequestPasswordResetRequest,
    use_case: RequestPasswordReset = Depends(get_request_password_reset),
) -> None:
    await use_case.execute(RequestPasswordResetInput(email=body.email))


@router.post("/reset", status_code=204)
async def reset_password(
    body: ResetPasswordRequest,
    use_case: ResetPassword = Depends(get_reset_password),
) -> None:
    await use_case.execute(
        ResetPasswordInput(
            user_id=body.user_id,
            token=body.token,
            new_password=body.new_password,
        )
    )


@router.post("/change", status_code=204)
async def change_password(
    body: ChangePasswordRequest,
    use_case: ChangePassword = Depends(get_change_password),
) -> None:
    await use_case.execute(
        ChangePasswordInput(
            user_id=body.user_id,
            current_password=body.current_password,
            new_password=body.new_password,
        )
    )

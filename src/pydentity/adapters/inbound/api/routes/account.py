from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from fastapi import APIRouter, Depends

from pydentity.adapters.container import (
    get_change_email,
    get_deactivate_user,
    get_reactivate_user,
    get_suspend_user,
)
from pydentity.adapters.inbound.api.dependencies.auth import (
    require_authenticated,
    require_permissions,
)
from pydentity.adapters.inbound.api.schemas.account import (
    ChangeEmailRequest,
    DeactivateUserRequest,
    ReactivateUserRequest,
    SuspendUserRequest,
)
from pydentity.application.dtos.account import (
    ChangeEmailInput,
    DeactivateUserInput,
    ReactivateUserInput,
    SuspendUserInput,
)
from pydentity.application.models.access_token_claims import AccessTokenClaims

if TYPE_CHECKING:
    from pydentity.application.use_cases.account.change_email import ChangeEmail
    from pydentity.application.use_cases.account.deactivate_user import DeactivateUser
    from pydentity.application.use_cases.account.reactivate_user import ReactivateUser
    from pydentity.application.use_cases.account.suspend_user import SuspendUser

router = APIRouter(prefix="/account", tags=["account"])


@router.patch("/email", status_code=204)
async def change_email(
    body: ChangeEmailRequest,
    claims: Annotated[AccessTokenClaims, Depends(require_authenticated)],
    use_case: ChangeEmail = Depends(get_change_email),
) -> None:
    await use_case.execute(
        ChangeEmailInput(user_id=claims.subject.value, new_email=body.new_email)
    )


@router.post("/suspend", status_code=204)
async def suspend_user(
    body: SuspendUserRequest,
    _claims: Annotated[AccessTokenClaims, Depends(require_permissions("users:manage"))],
    use_case: SuspendUser = Depends(get_suspend_user),
) -> None:
    await use_case.execute(SuspendUserInput(user_id=body.user_id, reason=body.reason))


@router.post("/reactivate", status_code=204)
async def reactivate_user(
    body: ReactivateUserRequest,
    _claims: Annotated[AccessTokenClaims, Depends(require_permissions("users:manage"))],
    use_case: ReactivateUser = Depends(get_reactivate_user),
) -> None:
    await use_case.execute(ReactivateUserInput(user_id=body.user_id))


@router.post("/deactivate", status_code=204)
async def deactivate_user(
    body: DeactivateUserRequest,
    _claims: Annotated[AccessTokenClaims, Depends(require_permissions("users:manage"))],
    use_case: DeactivateUser = Depends(get_deactivate_user),
) -> None:
    await use_case.execute(DeactivateUserInput(user_id=body.user_id))

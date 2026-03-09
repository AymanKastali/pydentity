from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends

from pydentity.adapters.container import (
    get_reissue_verification_token,
    get_verify_email,
)
from pydentity.adapters.inbound.api.schemas.email import (
    ResendVerificationRequest,
    VerifyEmailRequest,
)
from pydentity.application.dtos.email import (
    ReissueVerificationTokenInput,
    VerifyEmailInput,
)

if TYPE_CHECKING:
    from pydentity.application.use_cases.email.reissue_verification_token import (
        ReissueVerificationToken,
    )
    from pydentity.application.use_cases.email.verify_email import VerifyEmail

router = APIRouter(prefix="/email", tags=["email"])


@router.post("/verify", status_code=204)
async def verify_email(
    body: VerifyEmailRequest,
    use_case: VerifyEmail = Depends(get_verify_email),
) -> None:
    await use_case.execute(VerifyEmailInput(token=body.token))


@router.post("/resend-verification", status_code=204)
async def resend_verification(
    body: ResendVerificationRequest,
    use_case: ReissueVerificationToken = Depends(get_reissue_verification_token),
) -> None:
    await use_case.execute(ReissueVerificationTokenInput(user_id=body.user_id))

from pydentity.authentication.domain.verification_request.value_objects import (
    VerificationRequestStatus,
)
from pydentity.shared_kernel.building_blocks import DomainError


class VerificationRequestError(DomainError):
    pass


class VerificationRequestNotPendingError(VerificationRequestError):
    def __init__(self, current_status: VerificationRequestStatus) -> None:
        super().__init__(
            f"Verification request must be pending, but status is {current_status}."
        )


class VerificationRequestExpiredError(VerificationRequestError):
    def __init__(self) -> None:
        super().__init__("Verification request has expired.")


class InvalidVerificationTokenError(VerificationRequestError):
    def __init__(self) -> None:
        super().__init__("Verification token is invalid.")

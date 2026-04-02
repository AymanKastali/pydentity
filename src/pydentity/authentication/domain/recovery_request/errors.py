from pydentity.shared_kernel import DomainError


class RecoveryRequestNotPendingError(DomainError):
    def __init__(self) -> None:
        super().__init__("Recovery request is not pending.")


class RecoveryRequestNotVerifiedError(DomainError):
    def __init__(self) -> None:
        super().__init__("Recovery request is not verified.")


class RecoveryRequestAlreadyCompletedError(DomainError):
    def __init__(self) -> None:
        super().__init__("Recovery request is already completed.")


class RecoveryRequestAlreadyExpiredError(DomainError):
    def __init__(self) -> None:
        super().__init__("Recovery request is already expired.")


class RecoveryTokenExpiredError(DomainError):
    def __init__(self) -> None:
        super().__init__("Recovery token has expired.")

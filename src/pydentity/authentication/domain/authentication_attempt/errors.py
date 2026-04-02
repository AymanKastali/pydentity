from pydentity.shared_kernel import DomainError


class AttemptNotInProgressError(DomainError):
    def __init__(self) -> None:
        super().__init__("Authentication attempt is not in progress.")


class FactorNotRequiredError(DomainError):
    def __init__(self) -> None:
        super().__init__("The provided factor is not required for this attempt.")


class FactorAlreadyVerifiedError(DomainError):
    def __init__(self) -> None:
        super().__init__("The provided factor has already been verified.")


class AttemptExpiredError(DomainError):
    def __init__(self) -> None:
        super().__init__("Authentication attempt has expired.")


class AttemptNotExpiredError(DomainError):
    def __init__(self) -> None:
        super().__init__("Authentication attempt has not yet expired.")


class VerificationCodeAlreadyGeneratedError(DomainError):
    def __init__(self) -> None:
        super().__init__(
            "A verification code has already been generated for this attempt."
        )

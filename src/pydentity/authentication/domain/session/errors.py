from pydentity.shared_kernel import DomainError


class SessionAlreadyEndedError(DomainError):
    def __init__(self) -> None:
        super().__init__("Session has already ended.")


class RefreshTokenExpiredError(DomainError):
    def __init__(self) -> None:
        super().__init__("Refresh token has expired.")


class RefreshTokenRevokedError(DomainError):
    def __init__(self) -> None:
        super().__init__("Refresh token has been revoked.")

from pydentity.shared_kernel import DomainError


class DeviceAlreadyRevokedError(DomainError):
    def __init__(self) -> None:
        super().__init__("Device already revoked.")


class DeviceAlreadyExpiredError(DomainError):
    def __init__(self) -> None:
        super().__init__("Device already expired.")


class DeviceLimitExceededError(DomainError):
    def __init__(self) -> None:
        super().__init__("Trusted device limit exceeded.")

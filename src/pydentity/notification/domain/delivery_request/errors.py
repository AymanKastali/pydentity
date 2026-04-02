from pydentity.shared_kernel import DomainError


class DeliveryRequestAlreadySentError(DomainError):
    def __init__(self) -> None:
        super().__init__("Delivery request is already sent.")


class DeliveryRequestAlreadyFailedError(DomainError):
    def __init__(self) -> None:
        super().__init__("Delivery request has already permanently failed.")


class DeliveryRequestNotSensitiveError(DomainError):
    def __init__(self) -> None:
        super().__init__("Delivery request is not sensitive.")


class DeliveryRequestContentAlreadyPurgedError(DomainError):
    def __init__(self) -> None:
        super().__init__("Delivery request content is already purged.")

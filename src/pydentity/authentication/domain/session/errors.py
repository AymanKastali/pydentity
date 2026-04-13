from pydentity.authentication.domain.session.value_objects import SessionStatus
from pydentity.shared_kernel.building_blocks import DomainError


class SessionError(DomainError):
    pass


class SessionNotActiveError(SessionError):
    def __init__(self, current_status: SessionStatus) -> None:
        super().__init__(f"Session must be active, but status is {current_status}.")

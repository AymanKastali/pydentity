"""In-process synchronous event dispatcher.

Opens a fresh UoW per ``publish()`` call so that handlers needing a
``UserRepositoryPort`` see already-committed data from the originating
use case.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydentity.application.event_handlers.handlers import (
    OnAccountLocked,
    OnDeviceRegistered,
    OnDeviceRevoked,
    OnLoginFailed,
    OnLoginSucceeded,
    OnPasswordChanged,
    OnPasswordReset,
    OnPasswordResetRequested,
    OnRefreshTokenReused,
    OnRoleAssignedToUser,
    OnRoleRevokedFromUser,
    OnSessionTerminated,
    OnUserDeactivated,
    OnUserRegistered,
    OnUserSuspended,
    OnVerificationTokenIssued,
)
from pydentity.application.ports.event_publisher import DomainEventPublisherPort
from pydentity.domain.events.device_events import DeviceRegistered, DeviceRevoked
from pydentity.domain.events.session_events import RefreshTokenReused, SessionTerminated
from pydentity.domain.events.user_events import (
    AccountLocked,
    LoginFailed,
    LoginSucceeded,
    PasswordChanged,
    PasswordReset,
    PasswordResetRequested,
    RoleAssignedToUser,
    RoleRevokedFromUser,
    UserDeactivated,
    UserRegistered,
    UserSuspended,
    VerificationTokenIssued,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any

    from pydentity.adapters.outbound.persistence.postgres.unit_of_work import (
        SqlAlchemyUnitOfWork,
    )
    from pydentity.application.ports.audit_log import AuditLogPort
    from pydentity.application.ports.notification import NotificationPort
    from pydentity.domain.events.base import DomainEvent
    from pydentity.domain.ports.repositories import UserRepositoryPort


class InProcessEventPublisher(DomainEventPublisherPort):
    def __init__(
        self,
        *,
        uow_factory: Callable[[], SqlAlchemyUnitOfWork],
        notification: NotificationPort,
        audit_log: AuditLogPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._notification = notification
        self._audit_log = audit_log

    async def publish(self, events: list[DomainEvent]) -> None:
        if not events:
            return

        async with self._uow_factory() as uow:
            # The registry is built dynamically to inject the current UoW's repository
            registry = self._get_registry(uow.users)

            for event in events:
                handlers = registry.get(type(event), [])
                for handler in handlers:
                    await handler.handle(event)

    def _get_registry(
        self, user_repo: UserRepositoryPort
    ) -> dict[type[DomainEvent], list[Any]]:
        """The Central Registry: Maps Event Types to initialized Handlers."""
        # Short aliases for readability within the dictionary
        n, a, r = self._notification, self._audit_log, user_repo

        return {
            # Registration & Access
            UserRegistered: [OnUserRegistered(notification=n, audit_log=a)],
            VerificationTokenIssued: [
                OnVerificationTokenIssued(notification=n, audit_log=a)
            ],
            LoginSucceeded: [OnLoginSucceeded(audit_log=a)],
            LoginFailed: [OnLoginFailed(notification=n, audit_log=a)],
            # Account Security
            AccountLocked: [OnAccountLocked(notification=n, audit_log=a)],
            PasswordResetRequested: [
                OnPasswordResetRequested(user_repo=r, notification=n, audit_log=a)
            ],
            PasswordReset: [OnPasswordReset(notification=n, audit_log=a)],
            PasswordChanged: [OnPasswordChanged(notification=n, audit_log=a)],
            # Session & Device Management
            DeviceRegistered: [
                OnDeviceRegistered(user_repo=r, notification=n, audit_log=a)
            ],
            DeviceRevoked: [OnDeviceRevoked(user_repo=r, notification=n, audit_log=a)],
            SessionTerminated: [
                OnSessionTerminated(user_repo=r, notification=n, audit_log=a)
            ],
            RefreshTokenReused: [
                OnRefreshTokenReused(user_repo=r, notification=n, audit_log=a)
            ],
            # Administrative Actions
            UserSuspended: [OnUserSuspended(user_repo=r, notification=n, audit_log=a)],
            UserDeactivated: [
                OnUserDeactivated(user_repo=r, notification=n, audit_log=a)
            ],
            RoleAssignedToUser: [OnRoleAssignedToUser(audit_log=a)],
            RoleRevokedFromUser: [OnRoleRevokedFromUser(audit_log=a)],
        }

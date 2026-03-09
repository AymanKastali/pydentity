"""Background subscriber that listens on Redis pub/sub and dispatches
domain events through the existing handler registry.

Runs as an ``asyncio.Task`` inside the FastAPI lifespan.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import TYPE_CHECKING

from pydentity.adapters.outbound.events.serialization import deserialize_event
from pydentity.application.event_handlers.handlers import (
    OnAccountLocked,
    OnDeviceRegistered,
    OnDeviceRevoked,
    OnEmailVerified,
    OnLoginFailed,
    OnLoginSucceeded,
    OnPasswordChanged,
    OnPasswordReset,
    OnPasswordResetRequested,
    OnRefreshTokenReused,
    OnRoleAssignedToUser,
    OnRoleRevokedFromUser,
    OnSessionTerminated,
    OnUserActivated,
    OnUserDeactivated,
    OnUserRegistered,
    OnUserSuspended,
    OnVerificationTokenIssued,
)
from pydentity.domain.events.device_events import (
    DeviceRegistered,
    DeviceRevoked,
)
from pydentity.domain.events.session_events import (
    RefreshTokenReused,
    SessionTerminated,
)
from pydentity.domain.events.user_events import (
    AccountLocked,
    EmailVerified,
    LoginFailed,
    LoginSucceeded,
    PasswordChanged,
    PasswordReset,
    PasswordResetRequested,
    RoleAssignedToUser,
    RoleRevokedFromUser,
    UserActivated,
    UserDeactivated,
    UserRegistered,
    UserSuspended,
    VerificationTokenIssued,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any

    from redis.asyncio import Redis

    from pydentity.adapters.outbound.persistence.postgres.unit_of_work import (
        SqlAlchemyUnitOfWork,
    )
    from pydentity.application.ports.audit_log import AuditLogPort
    from pydentity.application.ports.notification import NotificationPort
    from pydentity.domain.events.base import DomainEvent
    from pydentity.domain.ports.repositories import UserRepositoryPort

_log = logging.getLogger("pydentity.events.subscriber")


class RedisEventSubscriber:
    def __init__(
        self,
        *,
        redis: Redis,
        channel: str,
        uow_factory: Callable[[], SqlAlchemyUnitOfWork],
        notification: NotificationPort,
        audit_log: AuditLogPort,
    ) -> None:
        self._redis = redis
        self._channel = channel
        self._uow_factory = uow_factory
        self._notification = notification
        self._audit_log = audit_log
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        """Subscribe and begin listening in a background task."""
        self._task = asyncio.create_task(self._listen(), name="redis-event-sub")
        _log.info("subscribed to %s", self._channel)

    async def stop(self) -> None:
        """Cancel the listener task gracefully."""
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
            _log.info("unsubscribed from %s", self._channel)

    async def _listen(self) -> None:
        pubsub = self._redis.pubsub()
        await pubsub.subscribe(self._channel)

        try:
            async for message in pubsub.listen():
                if message["type"] != "message":
                    continue
                try:
                    event = deserialize_event(message["data"])
                    await self._dispatch(event)
                except Exception:
                    _log.exception(
                        "failed to handle event from channel %s",
                        self._channel,
                    )
        finally:
            await pubsub.unsubscribe(self._channel)
            await pubsub.aclose()  # type: ignore[no-untyped-call]

    async def _dispatch(self, event: DomainEvent) -> None:
        """Build handlers with a fresh UoW and dispatch the event."""
        async with self._uow_factory() as uow:
            registry = self._get_registry(uow.users)
            handlers = registry.get(type(event), [])
            for handler in handlers:
                await handler.handle(event)

    def _get_registry(
        self, user_repo: UserRepositoryPort
    ) -> dict[type[DomainEvent], list[Any]]:
        """Mirrors InProcessEventPublisher._get_registry."""
        n, a, r = self._notification, self._audit_log, user_repo

        return {
            UserRegistered: [OnUserRegistered(notification=n, audit_log=a)],
            VerificationTokenIssued: [
                OnVerificationTokenIssued(notification=n, audit_log=a)
            ],
            UserActivated: [OnUserActivated(audit_log=a)],
            EmailVerified: [OnEmailVerified(user_repo=r, notification=n, audit_log=a)],
            LoginSucceeded: [OnLoginSucceeded(audit_log=a)],
            LoginFailed: [OnLoginFailed(notification=n, audit_log=a)],
            AccountLocked: [OnAccountLocked(notification=n, audit_log=a)],
            PasswordResetRequested: [
                OnPasswordResetRequested(user_repo=r, notification=n, audit_log=a)
            ],
            PasswordReset: [OnPasswordReset(notification=n, audit_log=a)],
            PasswordChanged: [OnPasswordChanged(notification=n, audit_log=a)],
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
            UserSuspended: [OnUserSuspended(user_repo=r, notification=n, audit_log=a)],
            UserDeactivated: [
                OnUserDeactivated(user_repo=r, notification=n, audit_log=a)
            ],
            RoleAssignedToUser: [OnRoleAssignedToUser(audit_log=a)],
            RoleRevokedFromUser: [OnRoleRevokedFromUser(audit_log=a)],
        }

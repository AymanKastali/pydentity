"""Background subscriber that listens on Redis pub/sub and dispatches
domain events through the existing handler registry.

Audit trail recording is cross-cutting — every event is automatically
persisted before dispatching to notification-only handlers.

Runs as an ``asyncio.Task`` inside the FastAPI lifespan.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import TYPE_CHECKING

from pydentity.adapters.outbound.events.serialization import deserialize_event
from pydentity.application.audit.registry import EXCLUDED_EVENTS, extract_audit_fields
from pydentity.application.event_handlers.handlers import (
    OnAccountLocked,
    OnEmailVerified,
    OnLoginFailed,
    OnPasswordChanged,
    OnPasswordReset,
    OnPasswordResetRequested,
    OnUserDeactivated,
    OnUserRegistered,
    OnUserSuspended,
    OnVerificationTokenIssued,
)
from pydentity.domain.events.user_events import (
    AccountLocked,
    EmailVerified,
    LoginFailed,
    PasswordChanged,
    PasswordReset,
    PasswordResetRequested,
    UserDeactivated,
    UserRegistered,
    UserSuspended,
    VerificationTokenIssued,
)

if TYPE_CHECKING:
    from typing import Any

    from redis.asyncio import Redis

    from pydentity.application.ports.audit_trail import AuditTrailPort
    from pydentity.application.ports.notification import NotificationPort
    from pydentity.domain.events.base import DomainEvent

_log = logging.getLogger("pydentity.events.subscriber")


class RedisEventSubscriber:
    def __init__(
        self,
        *,
        redis: Redis,
        channel: str,
        notification: NotificationPort,
        audit_trail: AuditTrailPort,
    ) -> None:
        self._redis = redis
        self._channel = channel
        self._notification = notification
        self._audit_trail = audit_trail
        self._task: asyncio.Task[None] | None = None
        self._registry = self._build_registry()

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
                    envelope = deserialize_event(message["data"])
                    event = envelope.event
                    context = envelope.context

                    # Cross-cutting audit trail
                    if type(event) not in EXCLUDED_EVENTS:
                        await self._record_audit(event, context)

                    # Dispatch to notification-only handlers
                    await self._dispatch(event)
                except Exception:
                    _log.exception(
                        "failed to handle event from channel %s",
                        self._channel,
                    )
        finally:
            await pubsub.unsubscribe(self._channel)
            await pubsub.aclose()  # type: ignore[no-untyped-call]

    async def _record_audit(self, event: DomainEvent, context: dict[str, str]) -> None:
        """Extract audit fields from the event and persist via audit trail."""
        fields = extract_audit_fields(event)
        await self._audit_trail.record(
            action=event.name,
            category=str(fields["category"]),
            actor_user_id=str(fields["actor_user_id"]),
            session_id=fields["session_id"],  # type: ignore[arg-type]
            device_id=fields["device_id"],  # type: ignore[arg-type]
            ip_address=context.get("ip_address"),
            trace_id=context.get("trace_id"),
            target_entity_type=fields["target_entity_type"],  # type: ignore[arg-type]
            target_entity_id=fields["target_entity_id"],  # type: ignore[arg-type]
            metadata=fields["metadata"],  # type: ignore[arg-type]
        )

    async def _dispatch(self, event: DomainEvent) -> None:
        """Dispatch the event to registered notification handlers."""
        handlers = self._registry.get(type(event), [])
        for handler in handlers:
            await handler.handle(event)

    def _build_registry(self) -> dict[type[DomainEvent], list[Any]]:
        n = self._notification

        return {
            UserRegistered: [OnUserRegistered(notification=n)],
            VerificationTokenIssued: [OnVerificationTokenIssued(notification=n)],
            EmailVerified: [OnEmailVerified(notification=n)],
            LoginFailed: [OnLoginFailed(notification=n)],
            AccountLocked: [OnAccountLocked(notification=n)],
            PasswordResetRequested: [OnPasswordResetRequested(notification=n)],
            PasswordReset: [OnPasswordReset(notification=n)],
            PasswordChanged: [OnPasswordChanged(notification=n)],
            UserSuspended: [OnUserSuspended(notification=n)],
            UserDeactivated: [OnUserDeactivated(notification=n)],
        }

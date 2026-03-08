"""Serialize / deserialize frozen-dataclass domain events to JSON.

Each event is encoded as ``{"type": "ClassName", "data": {...fields...}}``.
The ``datetime`` type is handled specially since it is not JSON-serializable
by default.
"""

from __future__ import annotations

import json
from dataclasses import asdict, fields
from datetime import datetime

from pydentity.domain.events.base import DomainEvent  # noqa: TC001
from pydentity.domain.events.device_events import (
    DeviceLastActiveBumped,
    DeviceRegistered,
    DeviceRevoked,
    DeviceTrusted,
    DeviceUntrusted,
)
from pydentity.domain.events.role_events import (
    PermissionAddedToRole,
    PermissionRemovedFromRole,
    RoleCreated,
    RoleDescriptionChanged,
    RoleRenamed,
)
from pydentity.domain.events.session_events import (
    RefreshTokenReused,
    RefreshTokenRotated,
    SessionEstablished,
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
    UserDeactivated,
    UserEmailChanged,
    UserReactivated,
    UserRegistered,
    UserSuspended,
    VerificationTokenIssued,
    VerificationTokenReissued,
)

_EVENT_REGISTRY: dict[str, type[DomainEvent]] = {
    # User events
    "UserRegistered": UserRegistered,
    "EmailVerified": EmailVerified,
    "VerificationTokenReissued": VerificationTokenReissued,
    "UserEmailChanged": UserEmailChanged,
    "PasswordChanged": PasswordChanged,
    "PasswordResetRequested": PasswordResetRequested,
    "PasswordReset": PasswordReset,
    "LoginFailed": LoginFailed,
    "LoginSucceeded": LoginSucceeded,
    "AccountLocked": AccountLocked,
    "UserSuspended": UserSuspended,
    "UserReactivated": UserReactivated,
    "UserDeactivated": UserDeactivated,
    "RoleAssignedToUser": RoleAssignedToUser,
    "RoleRevokedFromUser": RoleRevokedFromUser,
    "VerificationTokenIssued": VerificationTokenIssued,
    # Device events
    "DeviceRegistered": DeviceRegistered,
    "DeviceTrusted": DeviceTrusted,
    "DeviceUntrusted": DeviceUntrusted,
    "DeviceRevoked": DeviceRevoked,
    "DeviceLastActiveBumped": DeviceLastActiveBumped,
    # Session events
    "SessionEstablished": SessionEstablished,
    "RefreshTokenRotated": RefreshTokenRotated,
    "RefreshTokenReused": RefreshTokenReused,
    "SessionTerminated": SessionTerminated,
    # Role events
    "RoleCreated": RoleCreated,
    "RoleRenamed": RoleRenamed,
    "RoleDescriptionChanged": RoleDescriptionChanged,
    "PermissionAddedToRole": PermissionAddedToRole,
    "PermissionRemovedFromRole": PermissionRemovedFromRole,
}


def _default(obj: object) -> str:
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def serialize_event(event: DomainEvent) -> str:
    """Encode a domain event as a JSON string."""
    return json.dumps(
        {"type": event.name, "data": asdict(event)},
        default=_default,
    )


def deserialize_event(raw: str | bytes) -> DomainEvent:
    """Decode a JSON string back into a domain event instance."""
    payload = json.loads(raw)
    event_type_name: str = payload["type"]
    data: dict[str, object] = payload["data"]

    event_cls = _EVENT_REGISTRY.get(event_type_name)
    if event_cls is None:
        raise ValueError(f"Unknown event type: {event_type_name!r}")

    # Reconstruct datetime fields from ISO strings
    for f in fields(event_cls):
        if f.type == "datetime" and isinstance(data.get(f.name), str):
            data[f.name] = datetime.fromisoformat(data[f.name])  # type: ignore[arg-type]

    return event_cls(**data)

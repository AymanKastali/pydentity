"""Audit trail registry — maps domain events to categories and extracts
structured audit fields.

Pure mapping module: no I/O, no third-party imports.
"""

from __future__ import annotations

from dataclasses import asdict, fields
from enum import StrEnum, auto
from typing import TYPE_CHECKING

from pydentity.domain.events.device_events import (
    DeviceLastActiveBumped,
    DeviceMetadataUpdated,
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
    UserActivated,
    UserDeactivated,
    UserEmailChanged,
    UserReactivated,
    UserRegistered,
    UserSuspended,
    VerificationTokenIssued,
    VerificationTokenReissued,
)

if TYPE_CHECKING:
    from pydentity.domain.events.base import DomainEvent


class AuditCategory(StrEnum):
    # Events related to system integrity: failed logins, MFA,
    # password resets, or detected threats.
    SECURITY = auto()

    # Tracking user movement: successful logins, viewing sensitive records,
    # or session expirations.
    ACCESS = auto()

    # The "Audit Trail": records 'Before' and 'After' snapshots of
    # database row creations, updates, or deletes.
    DATA_CHANGE = auto()

    # High-level configuration: changing global system settings,
    # managing roles, or site-wide toggles.
    ADMIN = auto()


CATEGORY_MAP: dict[type[DomainEvent], str] = {
    # SECURITY
    LoginFailed: AuditCategory.SECURITY,
    AccountLocked: AuditCategory.SECURITY,
    RefreshTokenReused: AuditCategory.SECURITY,
    PasswordReset: AuditCategory.SECURITY,
    PasswordChanged: AuditCategory.SECURITY,
    PasswordResetRequested: AuditCategory.SECURITY,
    # ACCESS
    LoginSucceeded: AuditCategory.ACCESS,
    SessionEstablished: AuditCategory.ACCESS,
    SessionTerminated: AuditCategory.ACCESS,
    RefreshTokenRotated: AuditCategory.ACCESS,
    DeviceRegistered: AuditCategory.ACCESS,
    DeviceRevoked: AuditCategory.ACCESS,
    DeviceTrusted: AuditCategory.ACCESS,
    DeviceUntrusted: AuditCategory.ACCESS,
    DeviceMetadataUpdated: AuditCategory.DATA_CHANGE,
    # DATA_CHANGE
    UserEmailChanged: AuditCategory.DATA_CHANGE,
    EmailVerified: AuditCategory.DATA_CHANGE,
    UserRegistered: AuditCategory.DATA_CHANGE,
    UserActivated: AuditCategory.DATA_CHANGE,
    VerificationTokenReissued: AuditCategory.DATA_CHANGE,
    VerificationTokenIssued: AuditCategory.DATA_CHANGE,
    # ADMIN
    UserSuspended: AuditCategory.ADMIN,
    UserDeactivated: AuditCategory.ADMIN,
    UserReactivated: AuditCategory.ADMIN,
    RoleCreated: AuditCategory.ADMIN,
    RoleDescriptionChanged: AuditCategory.ADMIN,
    PermissionAddedToRole: AuditCategory.ADMIN,
    PermissionRemovedFromRole: AuditCategory.ADMIN,
    RoleAssignedToUser: AuditCategory.ADMIN,
    RoleRevokedFromUser: AuditCategory.ADMIN,
}

EXCLUDED_EVENTS: set[type[DomainEvent]] = {DeviceLastActiveBumped}

SENSITIVE_FIELDS: frozenset[str] = frozenset({"raw_token"})

TARGET_MAP: dict[type[DomainEvent], tuple[str, str]] = {
    # Session events
    SessionEstablished: ("Session", "session_id"),
    SessionTerminated: ("Session", "session_id"),
    RefreshTokenRotated: ("Session", "session_id"),
    RefreshTokenReused: ("Session", "session_id"),
    # Device events
    DeviceRegistered: ("Device", "device_id"),
    DeviceRevoked: ("Device", "device_id"),
    DeviceTrusted: ("Device", "device_id"),
    DeviceUntrusted: ("Device", "device_id"),
    DeviceMetadataUpdated: ("Device", "device_id"),
    # Role events
    RoleCreated: ("Role", "role_name"),
    RoleDescriptionChanged: ("Role", "role_name"),
    PermissionAddedToRole: ("Role", "role_name"),
    PermissionRemovedFromRole: ("Role", "role_name"),
    # User lifecycle events
    UserRegistered: ("User", "user_id"),
    UserActivated: ("User", "user_id"),
    UserSuspended: ("User", "user_id"),
    UserDeactivated: ("User", "user_id"),
    UserReactivated: ("User", "user_id"),
    EmailVerified: ("User", "user_id"),
    UserEmailChanged: ("User", "user_id"),
    PasswordChanged: ("User", "user_id"),
    PasswordReset: ("User", "user_id"),
    PasswordResetRequested: ("User", "user_id"),
    LoginFailed: ("User", "user_id"),
    LoginSucceeded: ("User", "user_id"),
    AccountLocked: ("User", "user_id"),
    VerificationTokenIssued: ("User", "user_id"),
    VerificationTokenReissued: ("User", "user_id"),
    RoleAssignedToUser: ("User", "user_id"),
    RoleRevokedFromUser: ("User", "user_id"),
}

# Fields extracted into dedicated columns — excluded from metadata JSONB.
_KNOWN_FIELDS: frozenset[str] = frozenset(
    {"user_id", "session_id", "device_id", "role_name"}
)


def extract_audit_fields(event: DomainEvent) -> dict[str, object]:
    """Extract structured audit fields from a domain event.

    Returns a dict with keys: ``actor_user_id``, ``session_id``, ``device_id``,
    ``target_entity_type``, ``target_entity_id``, ``category``, ``metadata``.
    """
    event_type = type(event)
    all_data = asdict(event)

    # Actor
    actor_user_id = all_data.get("user_id", "")

    # Dedicated columns
    session_id = all_data.get("session_id")
    device_id = all_data.get("device_id")

    # Target entity
    target_info = TARGET_MAP.get(event_type)
    target_entity_type: str | None = None
    target_entity_id: str | None = None
    if target_info is not None:
        target_entity_type, id_field = target_info
        target_entity_id = str(all_data.get(id_field, ""))

    # Category
    category = CATEGORY_MAP.get(event_type, AuditCategory.DATA_CHANGE)

    # Metadata: remaining fields minus known + sensitive
    exclude = _KNOWN_FIELDS | SENSITIVE_FIELDS
    metadata: dict[str, object] = {}
    for f in fields(event):
        if f.name not in exclude and all_data[f.name] is not None:
            metadata[f.name] = all_data[f.name]

    return {
        "actor_user_id": actor_user_id,
        "session_id": session_id,
        "device_id": device_id,
        "target_entity_type": target_entity_type,
        "target_entity_id": target_entity_id,
        "category": category,
        "metadata": metadata if metadata else None,
    }

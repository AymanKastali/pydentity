"""System permission constants and predefined role definitions.

This module defines all permissions as ``Permission`` value objects grouped
by resource, plus two role-level permission sets used for seeding.

Zero third-party imports — domain purity.
"""

from __future__ import annotations

from pydentity.domain.models.value_objects import Permission

# ── Role name constants ───────────────────────────────────────────────

SUPER_ADMIN_ROLE_NAME = "super_admin"
DEFAULT_ROLE_NAME = "user"

# ── Resource permissions ──────────────────────────────────────────────

# Users
USERS_READ = Permission(resource="users", action="read")
USERS_CREATE = Permission(resource="users", action="create")
USERS_UPDATE = Permission(resource="users", action="update")
USERS_DELETE = Permission(resource="users", action="delete")
USERS_SUSPEND = Permission(resource="users", action="suspend")
USERS_REACTIVATE = Permission(resource="users", action="reactivate")
USERS_DEACTIVATE = Permission(resource="users", action="deactivate")

# Roles
ROLES_READ = Permission(resource="roles", action="read")
ROLES_CREATE = Permission(resource="roles", action="create")
ROLES_UPDATE = Permission(resource="roles", action="update")
ROLES_DELETE = Permission(resource="roles", action="delete")
ROLES_ASSIGN = Permission(resource="roles", action="assign")
ROLES_REVOKE = Permission(resource="roles", action="revoke")

# Sessions
SESSIONS_READ = Permission(resource="sessions", action="read")
SESSIONS_REVOKE = Permission(resource="sessions", action="revoke")

# Devices
DEVICES_READ = Permission(resource="devices", action="read")

# ── Predefined role permission sets ───────────────────────────────────

SUPER_ADMIN_PERMISSIONS: frozenset[Permission] = frozenset(
    {
        USERS_READ,
        USERS_CREATE,
        USERS_UPDATE,
        USERS_DELETE,
        USERS_SUSPEND,
        USERS_REACTIVATE,
        USERS_DEACTIVATE,
        ROLES_READ,
        ROLES_CREATE,
        ROLES_UPDATE,
        ROLES_DELETE,
        ROLES_ASSIGN,
        ROLES_REVOKE,
        SESSIONS_READ,
        SESSIONS_REVOKE,
        DEVICES_READ,
    }
)

DEFAULT_USER_PERMISSIONS: frozenset[Permission] = frozenset(
    {
        USERS_READ,
    }
)

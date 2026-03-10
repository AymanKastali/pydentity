"""Permission registry — single source of truth for permission
constants and predefined role definitions.

Lives in the adapter layer because it defines operational policy
(which specific permissions exist and which roles get them),
not domain structure.
"""

from __future__ import annotations

from typing import ClassVar

from pydentity.domain.models.enums import Action, Resource
from pydentity.domain.models.value_objects import Permission

# ── Permission constants (grouped by resource) ──────────────────────────


class PermissionRegistry:
    # Users
    USERS_READ = Permission(resource=Resource.USERS, action=Action.READ)
    USERS_CREATE = Permission(resource=Resource.USERS, action=Action.CREATE)
    USERS_UPDATE = Permission(resource=Resource.USERS, action=Action.UPDATE)
    USERS_DELETE = Permission(resource=Resource.USERS, action=Action.DELETE)
    USERS_SUSPEND = Permission(resource=Resource.USERS, action=Action.SUSPEND)
    USERS_REACTIVATE = Permission(resource=Resource.USERS, action=Action.REACTIVATE)
    USERS_DEACTIVATE = Permission(resource=Resource.USERS, action=Action.DEACTIVATE)

    # Roles
    ROLES_READ = Permission(resource=Resource.ROLES, action=Action.READ)
    ROLES_CREATE = Permission(resource=Resource.ROLES, action=Action.CREATE)
    ROLES_UPDATE = Permission(resource=Resource.ROLES, action=Action.UPDATE)
    ROLES_DELETE = Permission(resource=Resource.ROLES, action=Action.DELETE)
    ROLES_ASSIGN = Permission(resource=Resource.ROLES, action=Action.ASSIGN)
    ROLES_REVOKE = Permission(resource=Resource.ROLES, action=Action.REVOKE)

    # Sessions
    SESSIONS_READ = Permission(resource=Resource.SESSIONS, action=Action.READ)
    SESSIONS_REVOKE = Permission(resource=Resource.SESSIONS, action=Action.REVOKE)

    # Devices
    DEVICES_READ = Permission(resource=Resource.DEVICES, action=Action.READ)

    # ── Predefined role permission sets ──────────────────────────────────

    SUPER_ADMIN: ClassVar[frozenset[Permission]] = frozenset(
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

    DEFAULT_USER: ClassVar[frozenset[Permission]] = frozenset(
        {
            USERS_READ,
        }
    )

    # ── Role name constants ──────────────────────────────────────────────

    SUPER_ADMIN_ROLE_NAME: ClassVar[str] = "SUPER_ADMIN"
    DEFAULT_ROLE_NAME: ClassVar[str] = "USER"

    # ── Predefined role definitions ──────────────────────────────────────

    PREDEFINED_ROLES: ClassVar[dict[str, tuple[str, frozenset[Permission]]]] = {
        SUPER_ADMIN_ROLE_NAME: ("Full system access", SUPER_ADMIN),
        DEFAULT_ROLE_NAME: ("Default role for registered users", DEFAULT_USER),
    }

    # ── Query helpers ────────────────────────────────────────────────────

    @classmethod
    def all_permissions(cls) -> frozenset[Permission]:
        return frozenset(v for v in vars(cls).values() if isinstance(v, Permission))

    @classmethod
    def for_resource(cls, resource: Resource) -> frozenset[Permission]:
        return frozenset(p for p in cls.all_permissions() if p.resource == resource)

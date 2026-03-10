"""Permission registry — single source of truth for permission
constants and predefined role definitions.

Lives in the adapter layer because it defines operational policy
(which specific permissions exist and which roles get them),
not domain structure.
"""

from __future__ import annotations

from typing import ClassVar

from pydentity.adapters.config.enums import Action, Resource
from pydentity.domain.models.value_objects import Permission

# ── Private helper ────────────────────────────────────────────────────


def _p(resource: Resource, action: Action) -> Permission:
    """Create a permission with validation.

    Private helper to ensure consistent permission creation and enable
    future validation rules (e.g., checking that action is valid for resource).

    Args:
        resource: The resource this permission applies to
        action: The action allowed on the resource

    Returns:
        A validated Permission instance

    Example:
        _p(Resource.USERS, Action.READ) -> Permission("users:read")
    """
    # Future validation could go here, e.g.:
    # if action == Action.SUSPEND and resource != Resource.USERS:
    #     raise ValueError(f"Action {action} is not valid for resource {resource}")

    return Permission(value=f"{resource}:{action}")


# ── Permission constants (grouped by resource) ──────────────────────────


class PermissionRegistry:
    # Users
    USERS_READ = _p(Resource.USERS, Action.READ)
    USERS_CREATE = _p(Resource.USERS, Action.CREATE)
    USERS_UPDATE = _p(Resource.USERS, Action.UPDATE)
    USERS_DELETE = _p(Resource.USERS, Action.DELETE)
    USERS_SUSPEND = _p(Resource.USERS, Action.SUSPEND)
    USERS_REACTIVATE = _p(Resource.USERS, Action.REACTIVATE)
    USERS_DEACTIVATE = _p(Resource.USERS, Action.DEACTIVATE)

    # Roles
    ROLES_READ = _p(Resource.ROLES, Action.READ)
    ROLES_CREATE = _p(Resource.ROLES, Action.CREATE)
    ROLES_UPDATE = _p(Resource.ROLES, Action.UPDATE)
    ROLES_DELETE = _p(Resource.ROLES, Action.DELETE)
    ROLES_ASSIGN = _p(Resource.ROLES, Action.ASSIGN)
    ROLES_REVOKE = _p(Resource.ROLES, Action.REVOKE)

    # Sessions
    SESSIONS_READ = _p(Resource.SESSIONS, Action.READ)
    SESSIONS_REVOKE = _p(Resource.SESSIONS, Action.REVOKE)

    # Devices
    DEVICES_READ = _p(Resource.DEVICES, Action.READ)

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
        return frozenset(
            p for p in cls.all_permissions() if p.value.startswith(f"{resource}:")
        )
